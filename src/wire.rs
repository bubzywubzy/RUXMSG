//! Strict RUXMSG outer frames and deterministic CBOR map validation.
//!
//! Frame decoding validates the bounded length before allocating the payload.
//! Payload validators additionally reject trailing bytes, duplicate keys,
//! unknown key shapes, and non-canonical map ordering.

use std::collections::HashSet;
use std::io::Cursor;

use ciborium::value::Value;

use crate::error::{Error, Result};
use crate::protocol::{FrameLength, MAX_FRAME_SIZE, MessageType, ProtocolVersion};

const HEADER_SIZE: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub version: ProtocolVersion,
    pub message_type: MessageType,
    pub payload: Vec<u8>,
}

impl Frame {
    /// Creates a version-one frame after enforcing the maximum payload size.
    pub fn new(message_type: MessageType, payload: Vec<u8>) -> Result<Self> {
        FrameLength::new(
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
        let length = FrameLength::new(
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

    /// Decodes one frame and returns the number of bytes consumed.
    pub fn decode(input: &[u8]) -> Result<(Self, usize)> {
        if input.len() < HEADER_SIZE {
            return Err(Error::TruncatedFrame);
        }
        let version = ProtocolVersion::try_from(input[0])?;
        let message_type = MessageType::try_from(input[1])?;
        let declared = u32::from_be_bytes(input[2..6].try_into().expect("header has four bytes"));
        FrameLength::new(declared)?;
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
    pub fn validate_cbor_map(&self) -> Result<()> {
        let mut cursor = Cursor::new(self.payload.as_slice());
        let value: Value = ciborium::de::from_reader(&mut cursor)
            .map_err(|error| Error::Encoding(error.to_string()))?;
        if cursor.position() != self.payload.len() as u64 {
            return Err(Error::NonCanonicalEncoding);
        }
        let Value::Map(entries) = &value else {
            return Err(Error::InvalidPayloadShape);
        };
        let mut keys = HashSet::with_capacity(entries.len());
        let mut canonical_entries = Vec::with_capacity(entries.len());
        for (key, value) in entries {
            let Value::Integer(integer) = key else {
                return Err(Error::InvalidMapKey);
            };
            let key: u64 = (*integer).try_into().map_err(|_| Error::InvalidMapKey)?;
            if !keys.insert(key) {
                return Err(Error::DuplicateMapKey(key));
            }
            canonical_entries.push((key, value.clone()));
        }
        canonical_entries.sort_by_key(|(key, _)| *key);
        let canonical_value = Value::Map(
            canonical_entries
                .into_iter()
                .map(|(key, value)| (Value::Integer(key.into()), value))
                .collect(),
        );
        let mut canonical = Vec::new();
        ciborium::ser::into_writer(&canonical_value, &mut canonical)
            .map_err(|error| Error::Encoding(error.to_string()))?;
        if canonical != self.payload {
            return Err(Error::NonCanonicalEncoding);
        }
        Ok(())
    }

    /// Returns the maximum payload accepted by the frame layer.
    pub const fn max_payload_size() -> u32 {
        MAX_FRAME_SIZE
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
}
