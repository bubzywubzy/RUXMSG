//! CLOSE reasons and bounded, secret-free peer diagnostics.

use ciborium::value::Value;

use crate::error::{Error, Result};
use crate::protocol::{MessageType, SessionId};
use crate::wire::Frame;

const MAX_DETAIL_BYTES: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloseReason {
    Normal = 0,
    ProtocolError = 1,
    AuthenticationFailure = 2,
    IdentityChanged = 3,
    ResourceLimit = 4,
    Shutdown = 5,
}

impl TryFrom<u64> for CloseReason {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self> {
        match value {
            0 => Ok(Self::Normal),
            1 => Ok(Self::ProtocolError),
            2 => Ok(Self::AuthenticationFailure),
            3 => Ok(Self::IdentityChanged),
            4 => Ok(Self::ResourceLimit),
            5 => Ok(Self::Shutdown),
            _ => Err(Error::InvalidClosePayload),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosePayload {
    pub session_id: Option<SessionId>,
    pub reason: CloseReason,
    pub detail: Option<String>,
}

impl ClosePayload {
    /// Encodes a CLOSE frame. Details are bounded and must not contain secrets.
    pub fn encode(&self) -> Result<Frame> {
        if self
            .detail
            .as_ref()
            .is_some_and(|detail| detail.len() > MAX_DETAIL_BYTES)
        {
            return Err(Error::InvalidClosePayload);
        }
        let mut entries = vec![(uint(1), uint(self.reason as u8))];
        if let Some(session_id) = self.session_id {
            entries.push((uint(0), Value::Bytes(session_id.as_bytes().to_vec())));
        }
        if let Some(detail) = &self.detail {
            entries.push((uint(2), Value::Text(detail.clone())));
        }
        entries.sort_by_key(|(key, _)| match key {
            Value::Integer(value) => u64::try_from(*value).unwrap_or(u64::MAX),
            _ => u64::MAX,
        });
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut encoded)
            .map_err(|error| Error::Encoding(error.to_string()))?;
        Frame::new(MessageType::Close, encoded)
    }

    /// Decodes a CLOSE frame and rejects unknown, oversized, or malformed fields.
    pub fn decode(frame: &Frame) -> Result<Self> {
        if frame.message_type != MessageType::Close {
            return Err(Error::InvalidClosePayload);
        }
        frame.validate_cbor_map()?;
        let value: Value = ciborium::de::from_reader(frame.payload.as_slice())
            .map_err(|error| Error::Encoding(error.to_string()))?;
        let Value::Map(entries) = value else {
            return Err(Error::InvalidClosePayload);
        };
        if !(1..=3).contains(&entries.len()) {
            return Err(Error::InvalidClosePayload);
        }
        let mut fields: Vec<Option<Value>> = (0..3).map(|_| None).collect();
        for (key, value) in entries {
            let Value::Integer(key) = key else {
                return Err(Error::InvalidClosePayload);
            };
            let key = usize::try_from(key).map_err(|_| Error::InvalidClosePayload)?;
            if key >= fields.len() || fields[key].is_some() {
                return Err(Error::InvalidClosePayload);
            }
            fields[key] = Some(value);
        }
        let session_id = fields[0]
            .take()
            .map(|value| {
                let Value::Bytes(bytes) = value else {
                    return Err(Error::InvalidClosePayload);
                };
                let array: [u8; SessionId::LENGTH] =
                    bytes.try_into().map_err(|_| Error::InvalidClosePayload)?;
                Ok(SessionId::from_bytes(array))
            })
            .transpose()?;
        let reason = CloseReason::try_from(uint_value(
            fields[1].take().ok_or(Error::InvalidClosePayload)?,
        )?)?;
        let detail = fields[2]
            .take()
            .map(|value| {
                let Value::Text(text) = value else {
                    return Err(Error::InvalidClosePayload);
                };
                if text.len() > MAX_DETAIL_BYTES {
                    return Err(Error::InvalidClosePayload);
                }
                Ok(text)
            })
            .transpose()?;
        Ok(Self {
            session_id,
            reason,
            detail,
        })
    }
}

fn uint(value: impl Into<i128>) -> Value {
    Value::Integer((value.into() as u64).into())
}

fn uint_value(value: Value) -> Result<u64> {
    let Value::Integer(value) = value else {
        return Err(Error::InvalidClosePayload);
    };
    u64::try_from(value).map_err(|_| Error::InvalidClosePayload)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn close_payload_round_trips_with_optional_fields() {
        let payload = ClosePayload {
            session_id: Some(SessionId::from_bytes([7; 16])),
            reason: CloseReason::Shutdown,
            detail: Some("bye".to_string()),
        };
        let frame = payload.encode().unwrap();
        assert_eq!(ClosePayload::decode(&frame).unwrap(), payload);
    }

    #[test]
    fn close_payload_requires_only_the_reason_field() {
        let payload = ClosePayload {
            session_id: None,
            reason: CloseReason::Normal,
            detail: None,
        };
        let frame = payload.encode().unwrap();
        assert_eq!(ClosePayload::decode(&frame).unwrap(), payload);
    }

    #[test]
    fn close_payload_rejects_oversized_detail() {
        let payload = ClosePayload {
            session_id: None,
            reason: CloseReason::Normal,
            detail: Some("x".repeat(MAX_DETAIL_BYTES + 1)),
        };
        assert_eq!(payload.encode(), Err(Error::InvalidClosePayload));
    }
}
