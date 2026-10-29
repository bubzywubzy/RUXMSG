//! Deterministic encoding of the fields authenticated by a handshake.

use std::collections::BTreeMap;

use ciborium::value::Value;

use crate::error::{Error, Result};
use crate::identity::PeerIdentity;
use crate::protocol::{HandshakePurpose, ProtocolVersion, SessionId};

/// Inputs authenticated by the RUXMSG handshake transcript.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transcript {
    pub purpose: HandshakePurpose,
    pub cipher_suite: u64,
    pub initiator_identity: PeerIdentity,
    pub responder_identity: PeerIdentity,
    pub initiator_ephemeral: [u8; 32],
    pub responder_ephemeral: [u8; 32],
    pub initiator_nonce: [u8; 16],
    pub responder_nonce: [u8; 16],
    pub previous_session_id: Option<SessionId>,
}

impl Transcript {
    /// Encodes the transcript fields as deterministic CBOR for hashing.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut fields = BTreeMap::<u64, Value>::new();
        fields.insert(0, uint(ProtocolVersion::V1 as u8));
        fields.insert(1, uint(self.cipher_suite));
        fields.insert(2, uint(self.purpose as u8));
        fields.insert(3, uint(0u64));
        fields.insert(4, uint(1u64));
        if let Some(session_id) = self.previous_session_id {
            fields.insert(5, bytes(session_id.as_bytes()));
        }
        fields.insert(6, bytes(self.initiator_identity.as_bytes()));
        fields.insert(7, bytes(self.responder_identity.as_bytes()));
        fields.insert(8, bytes(&self.initiator_ephemeral));
        fields.insert(9, bytes(&self.responder_ephemeral));
        fields.insert(10, bytes(&self.initiator_nonce));
        fields.insert(11, bytes(&self.responder_nonce));

        let value = Value::Map(
            fields
                .into_iter()
                .map(|(key, value)| (uint(key), value))
                .collect(),
        );
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&value, &mut encoded)
            .map_err(|error| Error::Encoding(error.to_string()))?;
        Ok(encoded)
    }
}

pub(crate) fn uint(value: impl Into<i128>) -> Value {
    Value::Integer((value.into() as u64).into())
}

pub(crate) fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}

pub(crate) fn array_value<const N: usize>(value: Value, kind: &'static str) -> Result<[u8; N]> {
    let Value::Bytes(bytes) = value else {
        return Err(Error::InvalidLength {
            kind,
            expected: 0,
            actual: 0,
        });
    };

    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| Error::InvalidLength {
            kind,
            expected: N,
            actual: bytes.len(),
        })
}

pub(crate) fn map_into_fields(
    entries: Vec<(u64, Value)>,
    field_count: usize,
    invalid: impl Fn() -> Error,
) -> Result<Vec<Option<Value>>> {
    let mut fields: Vec<Option<Value>> = (0..field_count).map(|_| None).collect();

    for (key, value) in entries {
        let index = usize::try_from(key).map_err(|_| invalid())?;
        if index >= fields.len() || fields[index].is_some() {
            return Err(invalid());
        }
        fields[index] = Some(value);
    }

    Ok(fields)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn transcript_encoding_is_deterministic() {
        let identity = PeerIdentity::from_bytes([1; 32]);
        let transcript = Transcript {
            purpose: HandshakePurpose::Initial,
            cipher_suite: 1,
            initiator_identity: identity,
            responder_identity: PeerIdentity::from_bytes([2; 32]),
            initiator_ephemeral: [3; 32],
            responder_ephemeral: [4; 32],
            initiator_nonce: [5; 16],
            responder_nonce: [6; 16],
            previous_session_id: None,
        };

        assert_eq!(transcript.encode().unwrap(), transcript.encode().unwrap());
    }
}
