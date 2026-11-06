//! Strict RUXMSG outer frames and deterministic CBOR map validation.
//!
//! Frame decoding validates the bounded length before allocating the payload.
//! Payload validators additionally reject trailing bytes, duplicate keys,
//! unknown key shapes, and non-canonical map ordering.

use std::collections::HashSet;
use std::io::Cursor;

use ciborium::value::Value;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::protocol::{FrameLength, MAX_FRAME_SIZE, MessageType, ProtocolVersion};

pub const HEADER_SIZE: usize = 6;
/// An encoded frame is byte-bounded, but a CBOR value can still be nested
/// deeply enough to exhaust a thread stack.  The schemas in RUXMSG/1 need at
/// most two levels (an outer map and scalar values); leave modest room for
/// forward-compatible diagnostics while keeping hostile input stack-safe.
const MAX_CBOR_NESTING: usize = 32;

pub(crate) fn wipe_cbor_value(value: &mut Value) {
    match value {
        Value::Bytes(bytes) => bytes.zeroize(),
        Value::Text(text) => text.zeroize(),
        Value::Array(items) => {
            for item in items {
                wipe_cbor_value(item);
            }
        }
        Value::Map(entries) => {
            for (key, value) in entries {
                wipe_cbor_value(key);
                wipe_cbor_value(value);
            }
        }
        _ => {}
    }
}

pub(crate) fn wipe_cbor_entries(entries: &mut [(u64, Value)]) {
    for (_, value) in entries {
        wipe_cbor_value(value);
    }
}

fn check_length(message_type: MessageType, length: u32) -> Result<FrameLength> {
    if length > message_type.max_payload() {
        return Err(Error::InvalidFrameLength(length));
    }
    FrameLength::new(length)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub version: ProtocolVersion,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Creates a version-one frame after enforcing the maximum payload size.
    pub fn new(message_type: MessageType, payload: Vec<u8>) -> Result<Self> {
        check_length(
            message_type,
            payload
                .len()
                .try_into()
                .map_err(|_| Error::InvalidFrameLength(u32::MAX))?,
        )?;
        Ok(Self {
            version: ProtocolVersion::V1,
            message_type,
            payload,
        })
    }

    /// Encodes the six-byte header followed by the payload.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let length = check_length(
            self.message_type,
            self.payload
                .len()
                .try_into()
                .map_err(|_| Error::InvalidFrameLength(u32::MAX))?,
        )?;
        let mut output = Vec::with_capacity(HEADER_SIZE + self.payload.len());
        output.push(self.version as u8);
        output.push(self.message_type as u8);
        output.extend_from_slice(&length.get().to_be_bytes());
        output.extend_from_slice(&self.payload);
        Ok(output)
    }

    /// Validates version, type and per-type length from the header alone, so
    /// callers can do this before allocating the payload.
    pub fn parse_header(header: &[u8; HEADER_SIZE]) -> Result<(ProtocolVersion, MessageType, u32)> {
        let version = ProtocolVersion::try_from(header[0])?;
        let message_type = MessageType::try_from(header[1])?;
        let declared = u32::from_be_bytes(header[2..6].try_into().expect("four length bytes"));
        check_length(message_type, declared)?;
        Ok((version, message_type, declared))
    }

    /// Decodes one frame and returns the number of bytes consumed.
    pub fn decode(input: &[u8]) -> Result<(Self, usize)> {
        if input.len() < HEADER_SIZE {
            return Err(Error::TruncatedFrame);
        }
        let (version, message_type, declared) = Self::parse_header(
            input[..HEADER_SIZE]
                .try_into()
                .expect("header has six bytes"),
        )?;
        let total = HEADER_SIZE
            .checked_add(declared as usize)
            .ok_or(Error::InvalidFrameLength(declared))?;
        if input.len() < total {
            return Err(Error::TruncatedFrame);
        }
        let payload = input[HEADER_SIZE..total].to_vec();
        Ok((
            Self {
                version,
                message_type,
                payload,
            },
            total,
        ))
    }

    /// Verifies that the payload is one complete deterministic CBOR map.
    pub fn validate_cbor_map(&self) -> Result<Vec<(u64, Value)>> {
        Self::validate_cbor_map_payload(&self.payload)
    }

    pub(crate) fn validate_cbor_map_payload(payload: &[u8]) -> Result<Vec<(u64, Value)>> {
        if payload.len() > MAX_FRAME_SIZE as usize {
            return Err(Error::InvalidFrameLength(
                u32::try_from(payload.len()).unwrap_or(u32::MAX),
            ));
        }

        // `ciborium::Value` is recursive.  Do a non-recursive structural pass
        // before asking it to build a value tree so an otherwise small frame
        // cannot turn into an unbounded parser/serializer/wiper call stack.
        // This also rejects indefinite lengths before any deserialization
        // allocation occurs.
        validate_cbor_structure(payload)?;

        let mut cursor = Cursor::new(payload);
        let mut value: Value = ciborium::de::from_reader(&mut cursor)
            .map_err(|error| Error::Encoding(error.to_string()))?;

        if cursor.position() != payload.len() as u64 {
            wipe_cbor_value(&mut value);
            return Err(Error::NonCanonicalEncoding);
        }

        let Value::Map(mut entries) = value else {
            wipe_cbor_value(&mut value);
            return Err(Error::InvalidPayloadShape);
        };

        let mut keys = HashSet::with_capacity(entries.len());
        let mut canonical_entries = Vec::with_capacity(entries.len());

        let mut iter = entries.drain(..);
        while let Some((mut key, mut val)) = iter.next() {
            let Value::Integer(integer) = key else {
                wipe_cbor_value(&mut key);
                wipe_cbor_value(&mut val);
                for (mut k, mut v) in iter {
                    wipe_cbor_value(&mut k);
                    wipe_cbor_value(&mut v);
                }
                wipe_cbor_entries(&mut canonical_entries);
                return Err(Error::InvalidMapKey);
            };
            let Ok(key_u64) = u64::try_from(integer) else {
                wipe_cbor_value(&mut val);
                for (mut k, mut v) in iter {
                    wipe_cbor_value(&mut k);
                    wipe_cbor_value(&mut v);
                }
                wipe_cbor_entries(&mut canonical_entries);
                return Err(Error::InvalidMapKey);
            };
            if !keys.insert(key_u64) {
                wipe_cbor_value(&mut val);
                for (mut k, mut v) in iter {
                    wipe_cbor_value(&mut k);
                    wipe_cbor_value(&mut v);
                }
                wipe_cbor_entries(&mut canonical_entries);
                return Err(Error::DuplicateMapKey(key_u64));
            }
            canonical_entries.push((key_u64, val));
        }
        canonical_entries.sort_by_key(|(key, _)| *key);

        let mut canonical_value = Value::Map(
            canonical_entries
                .into_iter()
                .map(|(key, value)| (Value::Integer(key.into()), value))
                .collect(),
        );

        let mut canonical = Zeroizing::new(Vec::new());

        if let Err(error) = ciborium::ser::into_writer(&canonical_value, &mut *canonical) {
            wipe_cbor_value(&mut canonical_value);
            return Err(Error::Encoding(error.to_string()));
        }
        if canonical.as_slice() != payload {
            wipe_cbor_value(&mut canonical_value);
            return Err(Error::NonCanonicalEncoding);
        }

        let Value::Map(entries) = canonical_value else {
            return Err(Error::InvalidPayloadShape);
        };
        entries
            .into_iter()
            .map(|(key, value)| {
                let Value::Integer(key) = key else {
                    return Err(Error::InvalidMapKey);
                };
                Ok((u64::try_from(key).map_err(|_| Error::InvalidMapKey)?, value))
            })
            .collect()
    }
}

/// Validates CBOR item boundaries, definite lengths, shortest integer/length
/// encodings, and nesting depth without constructing recursive values.
///
/// RUXMSG only admits unsigned integers, byte/text strings, arrays and maps
/// at this layer; schema validation subsequently rejects types not used by a
/// particular payload.  Tags and simple/floating values have no RUXMSG use
/// and are rejected here.
fn validate_cbor_structure(payload: &[u8]) -> Result<()> {
    let mut position = 0usize;
    // Each entry is the number of items remaining in a container.  The root
    // is represented as a one-item synthetic container.
    let mut remaining = vec![1usize];

    while !remaining.is_empty() {
        while remaining.last().is_some_and(|count| *count == 0) {
            remaining.pop();
        }
        if remaining.is_empty() {
            break;
        }

        let count = remaining.last_mut().expect("non-empty after check");
        *count -= 1;

        let initial = *payload.get(position).ok_or(Error::TruncatedFrame)?;
        position += 1;
        let major = initial >> 5;
        let additional = initial & 0x1f;
        let value = read_cbor_argument(payload, &mut position, additional)?;

        match major {
            // Unsigned and negative integers are structurally safe.  The
            // typed schema rejects negative values wherever unsigned fields
            // are required.
            0 | 1 => {}
            2 | 3 => {
                let length = usize::try_from(value).map_err(|_| Error::NonCanonicalEncoding)?;
                let end = position
                    .checked_add(length)
                    .ok_or(Error::NonCanonicalEncoding)?;
                if end > payload.len() {
                    return Err(Error::TruncatedFrame);
                }
                position = end;
            }
            4 | 5 => {
                let items = if major == 4 {
                    value
                } else {
                    value.checked_mul(2).ok_or(Error::NonCanonicalEncoding)?
                };
                let items = usize::try_from(items).map_err(|_| Error::NonCanonicalEncoding)?;
                if items > 0 {
                    if remaining.len() >= MAX_CBOR_NESTING {
                        return Err(Error::NonCanonicalEncoding);
                    }
                    remaining.push(items);
                }
            }
            // Tags, simple values, floats, and break have no valid use in
            // any RUXMSG/1 schema.  Indefinite lengths are also rejected by
            // `read_cbor_argument`.
            _ => return Err(Error::NonCanonicalEncoding),
        }
    }

    if position == payload.len() {
        Ok(())
    } else {
        Err(Error::NonCanonicalEncoding)
    }
}

fn read_cbor_argument(payload: &[u8], position: &mut usize, additional: u8) -> Result<u64> {
    let bytes = match additional {
        0..=23 => return Ok(u64::from(additional)),
        24 => 1,
        25 => 2,
        26 => 4,
        27 => 8,
        // 28-30 are reserved and 31 denotes an indefinite-length item.
        _ => return Err(Error::NonCanonicalEncoding),
    };

    let end = position.checked_add(bytes).ok_or(Error::TruncatedFrame)?;
    let encoded = payload.get(*position..end).ok_or(Error::TruncatedFrame)?;
    *position = end;

    let value = encoded
        .iter()
        .fold(0u64, |value, byte| (value << 8) | u64::from(*byte));
    let shortest = match bytes {
        1 => value >= 24,
        2 => value > u64::from(u8::MAX),
        4 => value > u64::from(u16::MAX),
        8 => value > u64::from(u32::MAX),
        _ => false,
    };
    if shortest {
        Ok(value)
    } else {
        Err(Error::NonCanonicalEncoding)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip_preserves_next_frame_boundary() {
        let first = Frame::new(MessageType::Close, vec![0xa0])
            .unwrap()
            .encode()
            .unwrap();
        let second = Frame::new(MessageType::Data, vec![0xa0])
            .unwrap()
            .encode()
            .unwrap();
        let mut input = first.clone();
        input.extend_from_slice(&second);
        let (decoded, consumed) = Frame::decode(&input).unwrap();
        assert_eq!(decoded.encode().unwrap(), first);
        assert_eq!(consumed, first.len());
    }

    #[test]
    fn rejects_duplicate_or_non_integer_map_keys() {
        let duplicate = Frame::new(MessageType::Data, vec![0xa2, 0x00, 0x01, 0x00, 0x02]).unwrap();
        assert_eq!(
            duplicate.validate_cbor_map(),
            Err(Error::DuplicateMapKey(0))
        );
        let text_key = Frame::new(MessageType::Data, vec![0xa1, 0x61, b'x', 0x01]).unwrap();
        assert_eq!(text_key.validate_cbor_map(), Err(Error::InvalidMapKey));
    }

    #[test]
    fn rejects_unsorted_integer_map_keys() {
        let unsorted = Frame::new(MessageType::Data, vec![0xa2, 0x01, 0x01, 0x00, 0x02]).unwrap();
        assert_eq!(
            unsorted.validate_cbor_map(),
            Err(Error::NonCanonicalEncoding)
        );
    }

    #[test]
    fn rejects_indefinite_and_excessively_nested_cbor_before_value_decode() {
        // An indefinite map is forbidden by RUXMSG deterministic CBOR.
        assert_eq!(
            Frame::validate_cbor_map_payload(&[0xbf, 0xff]),
            Err(Error::NonCanonicalEncoding)
        );

        // A one-megabyte DATA frame can otherwise encode enough nested
        // containers to overflow the process stack in a recursive CBOR AST.
        let mut nested = vec![0x81; MAX_CBOR_NESTING + 1];
        nested.push(0x00);
        assert_eq!(
            Frame::validate_cbor_map_payload(&nested),
            Err(Error::NonCanonicalEncoding)
        );
    }
}
