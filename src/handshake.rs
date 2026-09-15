//! Handshake payloads, transcript assembly, signatures, and confirmation.
//!
//! The handshake is deliberately split into an unsigned HELLO exchange, a
//! transcript-bound signature exchange, and session confirmation. Do not add
//! fields to these payloads without updating the normative wire specification.

use ciborium::value::Value;

use crate::crypto::{
    SessionKeys, derive_session_keys, transcript_hash, verify_confirmation,
    verify_transcript_signature,
};
use crate::encoding::Transcript;
use crate::error::{Error, Result};
use crate::identity::{PeerIdentity, TrustState};
use crate::protocol::{MessageType, SessionId};
use crate::wire::Frame;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakePurpose {
    Initial = 0,
    Rekey = 1,
}

impl TryFrom<u64> for HandshakePurpose {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self> {
        match value {
            0 => Ok(Self::Initial),
            1 => Ok(Self::Rekey),
            _ => Err(Error::InvalidHandshake),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HelloRole {
    Initiator = 0,
    Responder = 1,
}

impl TryFrom<u64> for HelloRole {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self> {
        match value {
            0 => Ok(Self::Initiator),
            1 => Ok(Self::Responder),
            _ => Err(Error::InvalidHandshake),
        }
    }
}

/// Stage-0 HELLO. Each peer sends only its own identity and fresh session inputs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelloPayload {
    pub cipher_suite: u64,
    pub purpose: HandshakePurpose,
    pub role: HelloRole,
    pub identity_public_key: PeerIdentity,
    pub ephemeral_public_key: [u8; 32],
    pub nonce: [u8; 16],
    pub previous_session_id: Option<SessionId>,
}

impl HelloPayload {
    /// Encodes a stage-0 HELLO as a HANDSHAKE or REKEY frame.
    pub fn encode(&self) -> Result<Frame> {
        if self.purpose == HandshakePurpose::Initial && self.previous_session_id.is_some()
            || self.purpose == HandshakePurpose::Rekey && self.previous_session_id.is_none()
        {
            return Err(Error::InvalidHandshake);
        }
        let mut entries = vec![
            (uint(0), uint(1u64)),
            (uint(1), uint(self.cipher_suite)),
            (uint(2), uint(self.purpose as u8)),
            (uint(3), uint(self.role as u8)),
            (uint(4), bytes(self.identity_public_key.as_bytes())),
            (uint(5), bytes(&self.ephemeral_public_key)),
            (uint(6), bytes(&self.nonce)),
        ];
        if let Some(session_id) = self.previous_session_id {
            entries.push((uint(7), bytes(session_id.as_bytes())));
        }
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut encoded)
            .map_err(|error| Error::Encoding(error.to_string()))?;
        Frame::new(message_type_for_purpose(self.purpose), encoded)
    }

    /// Decodes and strictly validates a stage-0 HELLO frame.
    pub fn decode(frame: &Frame) -> Result<Self> {
        if frame.message_type != MessageType::Handshake && frame.message_type != MessageType::Rekey
        {
            return Err(Error::InvalidHandshake);
        }
        frame.validate_cbor_map()?;
        let value: Value = ciborium::de::from_reader(frame.payload.as_slice())
            .map_err(|error| Error::Encoding(error.to_string()))?;
        let Value::Map(entries) = value else {
            return Err(Error::InvalidHandshake);
        };
        if !(7..=8).contains(&entries.len()) {
            return Err(Error::InvalidHandshake);
        }
        let mut fields: Vec<Option<Value>> = (0..8).map(|_| None).collect();
        for (key, value) in entries {
            let Value::Integer(key) = key else {
                return Err(Error::InvalidHandshake);
            };
            let key = usize::try_from(key).map_err(|_| Error::InvalidHandshake)?;
            if key >= fields.len() || fields[key].is_some() {
                return Err(Error::InvalidHandshake);
            }
            fields[key] = Some(value);
        }
        let protocol_version = uint_value(fields[0].take().ok_or(Error::InvalidHandshake)?)?;
        if protocol_version != 1 {
            return Err(Error::UnsupportedVersion(protocol_version as u8));
        }
        let payload = Self {
            cipher_suite: uint_value(fields[1].take().ok_or(Error::InvalidHandshake)?)?,
            purpose: HandshakePurpose::try_from(uint_value(
                fields[2].take().ok_or(Error::InvalidHandshake)?,
            )?)?,
            role: HelloRole::try_from(uint_value(
                fields[3].take().ok_or(Error::InvalidHandshake)?,
            )?)?,
            identity_public_key: identity_value(fields[4].take().ok_or(Error::InvalidHandshake)?)?,
            ephemeral_public_key: array_value(
                fields[5].take().ok_or(Error::InvalidHandshake)?,
                "ephemeral",
            )?,
            nonce: array_value(fields[6].take().ok_or(Error::InvalidHandshake)?, "nonce")?,
            previous_session_id: fields[7]
                .take()
                .map(|value| array_value(value, "session ID"))
                .transpose()?
                .map(SessionId::from_bytes),
        };
        if payload.purpose == HandshakePurpose::Initial && payload.previous_session_id.is_some()
            || payload.purpose == HandshakePurpose::Rekey && payload.previous_session_id.is_none()
        {
            return Err(Error::InvalidHandshake);
        }
        if frame.message_type != message_type_for_purpose(payload.purpose) {
            return Err(Error::InvalidHandshake);
        }
        Ok(payload)
    }
}

/// HELLO/HANDSHAKE frames for an initial session use `HANDSHAKE` (0x01);
/// rekey frames use the distinct `REKEY` (0x04) type per the wire registry.
fn message_type_for_purpose(purpose: HandshakePurpose) -> MessageType {
    match purpose {
        HandshakePurpose::Initial => MessageType::Handshake,
        HandshakePurpose::Rekey => MessageType::Rekey,
    }
}

pub fn transcript_from_hellos(
    initiator: &HelloPayload,
    responder: &HelloPayload,
) -> Result<Transcript> {
    if initiator.role != HelloRole::Initiator
        || responder.role != HelloRole::Responder
        || initiator.cipher_suite != responder.cipher_suite
        || initiator.purpose != responder.purpose
        || initiator.previous_session_id != responder.previous_session_id
    {
        return Err(Error::InvalidHandshake);
    }
    Ok(Transcript {
        handshake_type: initiator.purpose as u8,
        cipher_suite: initiator.cipher_suite,
        initiator_identity: initiator.identity_public_key,
        responder_identity: responder.identity_public_key,
        initiator_ephemeral: initiator.ephemeral_public_key,
        responder_ephemeral: responder.ephemeral_public_key,
        initiator_nonce: initiator.nonce,
        responder_nonce: responder.nonce,
        previous_session_id: initiator.previous_session_id,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HandshakeType {
    Initial = 0,
    Rekey = 1,
}

impl TryFrom<u64> for HandshakeType {
    type Error = Error;

    fn try_from(value: u64) -> Result<Self> {
        match value {
            0 => Ok(Self::Initial),
            1 => Ok(Self::Rekey),
            _ => Err(Error::InvalidHandshake),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakePayload {
    pub handshake_type: HandshakeType,
    pub stage: u8,
    pub cipher_suite: u64,
    pub initiator_identity: PeerIdentity,
    pub responder_identity: PeerIdentity,
    pub initiator_ephemeral: [u8; 32],
    pub responder_ephemeral: [u8; 32],
    pub initiator_nonce: [u8; 16],
    pub responder_nonce: [u8; 16],
    pub previous_session_id: Option<SessionId>,
    pub initiator_signature: [u8; 64],
    pub responder_signature: Option<[u8; 64]>,
}

impl HandshakePayload {
    /// Returns the transcript-bearing fields, excluding signatures.
    pub fn transcript(&self) -> Transcript {
        Transcript {
            handshake_type: self.handshake_type as u8,
            cipher_suite: self.cipher_suite,
            initiator_identity: self.initiator_identity,
            responder_identity: self.responder_identity,
            initiator_ephemeral: self.initiator_ephemeral,
            responder_ephemeral: self.responder_ephemeral,
            initiator_nonce: self.initiator_nonce,
            responder_nonce: self.responder_nonce,
            previous_session_id: self.previous_session_id,
        }
    }

    /// Encodes a signed handshake stage using the purpose-specific message type.
    pub fn encode(&self) -> Result<Frame> {
        if self.stage > 1 || (self.stage == 0 && self.responder_signature.is_some()) {
            return Err(Error::InvalidHandshake);
        }
        if self.handshake_type == HandshakeType::Initial && self.previous_session_id.is_some() {
            return Err(Error::InvalidHandshake);
        }
        if self.handshake_type == HandshakeType::Rekey && self.previous_session_id.is_none() {
            return Err(Error::InvalidHandshake);
        }
        let mut entries = vec![
            (uint(0), uint(self.handshake_type as u8)),
            (uint(1), uint(self.stage)),
            (uint(2), uint(self.cipher_suite)),
            (uint(3), bytes(self.initiator_identity.as_bytes())),
            (uint(4), bytes(self.responder_identity.as_bytes())),
            (uint(5), bytes(&self.initiator_ephemeral)),
            (uint(6), bytes(&self.responder_ephemeral)),
            (uint(7), bytes(&self.initiator_nonce)),
            (uint(8), bytes(&self.responder_nonce)),
            (uint(10), bytes(&self.initiator_signature)),
        ];
        if let Some(session_id) = self.previous_session_id {
            entries.push((uint(9), bytes(session_id.as_bytes())));
        }
        if let Some(signature) = self.responder_signature {
            entries.push((uint(11), bytes(&signature)));
        }
        entries.sort_by_key(|(key, _)| match key {
            Value::Integer(value) => u64::try_from(*value).unwrap_or(u64::MAX),
            _ => u64::MAX,
        });
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&Value::Map(entries), &mut encoded)
            .map_err(|error| Error::Encoding(error.to_string()))?;
        Frame::new(
            message_type_for_handshake_type(self.handshake_type),
            encoded,
        )
    }

    /// Decodes and strictly validates a signed handshake stage.
    pub fn decode(frame: &Frame) -> Result<Self> {
        if frame.message_type != MessageType::Handshake && frame.message_type != MessageType::Rekey
        {
            return Err(Error::InvalidHandshake);
        }
        frame.validate_cbor_map()?;
        let value: Value = ciborium::de::from_reader(frame.payload.as_slice())
            .map_err(|error| Error::Encoding(error.to_string()))?;
        let Value::Map(entries) = value else {
            return Err(Error::InvalidHandshake);
        };
        let mut fields: Vec<Option<Value>> = (0..12).map(|_| None).collect();
        for (key, value) in entries {
            let Value::Integer(key) = key else {
                return Err(Error::InvalidHandshake);
            };
            let key = usize::try_from(key).map_err(|_| Error::InvalidHandshake)?;
            if key >= fields.len() || fields[key].is_some() {
                return Err(Error::InvalidHandshake);
            }
            fields[key] = Some(value);
        }
        let handshake_type = HandshakeType::try_from(uint_value(
            fields[0].take().ok_or(Error::InvalidHandshake)?,
        )?)?;
        let stage = u8::try_from(uint_value(
            fields[1].take().ok_or(Error::InvalidHandshake)?,
        )?)
        .map_err(|_| Error::InvalidHandshake)?;
        let cipher_suite = uint_value(fields[2].take().ok_or(Error::InvalidHandshake)?)?;
        let initiator_identity = identity_value(fields[3].take().ok_or(Error::InvalidHandshake)?)?;
        let responder_identity = identity_value(fields[4].take().ok_or(Error::InvalidHandshake)?)?;
        let initiator_ephemeral = array_value(
            fields[5].take().ok_or(Error::InvalidHandshake)?,
            "ephemeral",
        )?;
        let responder_ephemeral = array_value(
            fields[6].take().ok_or(Error::InvalidHandshake)?,
            "ephemeral",
        )?;
        let initiator_nonce =
            array_value(fields[7].take().ok_or(Error::InvalidHandshake)?, "nonce")?;
        let responder_nonce =
            array_value(fields[8].take().ok_or(Error::InvalidHandshake)?, "nonce")?;
        let previous_session_id = fields[9]
            .take()
            .map(|value| array_value(value, "session ID"))
            .transpose()?
            .map(SessionId::from_bytes);
        let initiator_signature = array_value(
            fields[10].take().ok_or(Error::InvalidHandshake)?,
            "signature",
        )?;
        let responder_signature = fields[11]
            .take()
            .map(|value| array_value(value, "signature"))
            .transpose()?;
        let payload = Self {
            handshake_type,
            stage,
            cipher_suite,
            initiator_identity,
            responder_identity,
            initiator_ephemeral,
            responder_ephemeral,
            initiator_nonce,
            responder_nonce,
            previous_session_id,
            initiator_signature,
            responder_signature,
        };
        if payload.stage > 1
            || (payload.stage == 1 && payload.responder_signature.is_none())
            || (payload.stage == 0 && payload.responder_signature.is_some())
        {
            return Err(Error::InvalidHandshake);
        }
        if payload.handshake_type == HandshakeType::Initial && payload.previous_session_id.is_some()
        {
            return Err(Error::InvalidHandshake);
        }
        if payload.handshake_type == HandshakeType::Rekey && payload.previous_session_id.is_none() {
            return Err(Error::InvalidHandshake);
        }
        if frame.message_type != message_type_for_handshake_type(payload.handshake_type) {
            return Err(Error::InvalidHandshake);
        }
        Ok(payload)
    }
}

/// Signed HANDSHAKE frames mirror the same HANDSHAKE-vs-REKEY split as HELLO.
fn message_type_for_handshake_type(handshake_type: HandshakeType) -> MessageType {
    match handshake_type {
        HandshakeType::Initial => MessageType::Handshake,
        HandshakeType::Rekey => MessageType::Rekey,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionConfirmPayload {
    pub session_id: SessionId,
    pub role: u8,
    pub confirmation: [u8; 32],
}

impl SessionConfirmPayload {
    /// Encodes the role-specific confirmation MAC and session identifier.
    pub fn encode(&self) -> Result<Frame> {
        if self.role > 1 {
            return Err(Error::InvalidHandshake);
        }
        let value = Value::Map(vec![
            (uint(0), bytes(self.session_id.as_bytes())),
            (uint(1), uint(self.role)),
            (uint(2), bytes(&self.confirmation)),
        ]);
        let mut encoded = Vec::new();
        ciborium::ser::into_writer(&value, &mut encoded)
            .map_err(|error| Error::Encoding(error.to_string()))?;
        Frame::new(MessageType::SessionConfirm, encoded)
    }

    /// Decodes a confirmation payload without accepting it as valid yet.
    pub fn decode(frame: &Frame) -> Result<Self> {
        if frame.message_type != MessageType::SessionConfirm {
            return Err(Error::ConfirmationInvalid);
        }
        frame.validate_cbor_map()?;
        let value: Value = ciborium::de::from_reader(frame.payload.as_slice())
            .map_err(|error| Error::Encoding(error.to_string()))?;
        let Value::Map(entries) = value else {
            return Err(Error::ConfirmationInvalid);
        };
        if entries.len() != 3 {
            return Err(Error::ConfirmationInvalid);
        }
        let mut fields: Vec<Option<Value>> = (0..3).map(|_| None).collect();
        for (key, value) in entries {
            let Value::Integer(key) = key else {
                return Err(Error::ConfirmationInvalid);
            };
            let key = usize::try_from(key).map_err(|_| Error::ConfirmationInvalid)?;
            if key >= fields.len() || fields[key].is_some() {
                return Err(Error::ConfirmationInvalid);
            }
            fields[key] = Some(value);
        }
        Ok(Self {
            session_id: SessionId::from_bytes(array_value(
                fields[0].take().ok_or(Error::ConfirmationInvalid)?,
                "session ID",
            )?),
            role: u8::try_from(uint_value(
                fields[1].take().ok_or(Error::ConfirmationInvalid)?,
            )?)
            .map_err(|_| Error::ConfirmationInvalid)?,
            confirmation: array_value(
                fields[2].take().ok_or(Error::ConfirmationInvalid)?,
                "confirmation",
            )?,
        })
    }

    /// Verifies the session ID, role, and confirmation MAC against derived keys.
    pub fn verify(&self, keys: &SessionKeys, hash: &[u8; 32]) -> Result<()> {
        if self.session_id != keys.session_id || self.role > 1 {
            return Err(Error::ConfirmationInvalid);
        }
        verify_confirmation(
            &keys.confirmation_key,
            hash,
            &self.confirmation,
            self.role == 0,
        )
    }
}

/// Verifies a responder-oriented handshake using the default role context.
pub fn verify_handshake(
    payload: &HandshakePayload,
    shared_secret: &[u8; 32],
    sas_approved: bool,
    trusted_identity: Option<(PeerIdentity, TrustState)>,
) -> Result<(SessionKeys, [u8; 32])> {
    verify_handshake_for_role(
        payload,
        shared_secret,
        sas_approved,
        trusted_identity,
        HelloRole::Responder,
    )
}

/// Verifies signatures, SAS/trust policy, and derives candidate session keys.
pub fn verify_handshake_for_role(
    payload: &HandshakePayload,
    shared_secret: &[u8; 32],
    sas_approved: bool,
    trusted_identity: Option<(PeerIdentity, TrustState)>,
    local_role: HelloRole,
) -> Result<(SessionKeys, [u8; 32])> {
    if !sas_approved && trusted_identity.is_none() {
        return Err(Error::SasRejected);
    }
    if let Some((identity, state)) = trusted_identity {
        let expected_peer = match local_role {
            HelloRole::Initiator => payload.responder_identity,
            HelloRole::Responder => payload.initiator_identity,
        };
        if state != TrustState::Trusted || identity != expected_peer {
            return Err(Error::IdentityMismatch);
        }
    }
    let transcript_hash = transcript_hash(&payload.transcript().encode()?);
    verify_transcript_signature(
        &payload.initiator_identity,
        &transcript_hash,
        &payload.initiator_signature,
        true,
    )?;
    if let Some(signature) = payload.responder_signature {
        verify_transcript_signature(
            &payload.responder_identity,
            &transcript_hash,
            &signature,
            false,
        )?;
    } else if payload.stage != 0 {
        return Err(Error::InvalidHandshake);
    }
    Ok((
        derive_session_keys(shared_secret, &transcript_hash)?,
        transcript_hash,
    ))
}

/// Applies the raw-public-key tie-break for simultaneous rekey attempts.
pub fn local_identity_wins_rekey_glare(
    local: &PeerIdentity,
    remote_initiator: &PeerIdentity,
) -> bool {
    local.as_bytes() > remote_initiator.as_bytes()
}

fn uint(value: impl Into<i128>) -> Value {
    Value::Integer((value.into() as u64).into())
}
fn bytes(value: &[u8]) -> Value {
    Value::Bytes(value.to_vec())
}
fn uint_value(value: Value) -> Result<u64> {
    let Value::Integer(value) = value else {
        return Err(Error::InvalidHandshake);
    };
    u64::try_from(value).map_err(|_| Error::InvalidHandshake)
}
fn bytes_value(value: Value, kind: &'static str) -> Result<Vec<u8>> {
    let Value::Bytes(value) = value else {
        return Err(Error::InvalidLength {
            kind,
            expected: 0,
            actual: 0,
        });
    };
    Ok(value)
}
fn array_value<const N: usize>(value: Value, kind: &'static str) -> Result<[u8; N]> {
    let bytes = bytes_value(value, kind)?;
    bytes
        .try_into()
        .map_err(|bytes: Vec<u8>| Error::InvalidLength {
            kind,
            expected: N,
            actual: bytes.len(),
        })
}
fn identity_value(value: Value) -> Result<PeerIdentity> {
    Ok(PeerIdentity::from_bytes(array_value(value, "identity")?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::IdentityKeypair;

    #[test]
    fn symmetric_hellos_form_a_transcript_after_both_arrive() {
        let initiator = HelloPayload {
            cipher_suite: 1,
            purpose: HandshakePurpose::Initial,
            role: HelloRole::Initiator,
            identity_public_key: PeerIdentity::from_bytes([1; 32]),
            ephemeral_public_key: [2; 32],
            nonce: [3; 16],
            previous_session_id: None,
        };
        let responder = HelloPayload {
            cipher_suite: 1,
            purpose: HandshakePurpose::Initial,
            role: HelloRole::Responder,
            identity_public_key: PeerIdentity::from_bytes([4; 32]),
            ephemeral_public_key: [5; 32],
            nonce: [6; 16],
            previous_session_id: None,
        };
        let decoded_initiator = HelloPayload::decode(&initiator.encode().unwrap()).unwrap();
        let decoded_responder = HelloPayload::decode(&responder.encode().unwrap()).unwrap();
        let transcript = transcript_from_hellos(&decoded_initiator, &decoded_responder).unwrap();
        assert_eq!(transcript.initiator_ephemeral, [2; 32]);
        assert_eq!(transcript.responder_nonce, [6; 16]);
    }

    #[test]
    fn signed_handshake_round_trips_and_verifies() {
        let initiator = IdentityKeypair::from_bytes(&[1; 32]);
        let responder = IdentityKeypair::from_bytes(&[2; 32]);
        let mut payload = HandshakePayload {
            handshake_type: HandshakeType::Initial,
            stage: 0,
            cipher_suite: 1,
            initiator_identity: initiator.identity(),
            responder_identity: responder.identity(),
            initiator_ephemeral: [3; 32],
            responder_ephemeral: [4; 32],
            initiator_nonce: [5; 16],
            responder_nonce: [6; 16],
            previous_session_id: None,
            initiator_signature: [0; 64],
            responder_signature: None,
        };
        let hash = transcript_hash(&payload.transcript().encode().unwrap());
        payload.initiator_signature = initiator.sign_transcript(&hash, true);
        let frame = payload.encode().unwrap();
        let decoded = HandshakePayload::decode(&frame).unwrap();
        verify_handshake(&decoded, &[7; 32], true, None).unwrap();
    }

    #[test]
    fn first_contact_requires_sas_and_trusted_identity_must_match() {
        let initiator = IdentityKeypair::from_bytes(&[1; 32]);
        let responder = IdentityKeypair::from_bytes(&[2; 32]);
        let mut payload = HandshakePayload {
            handshake_type: HandshakeType::Initial,
            stage: 0,
            cipher_suite: 1,
            initiator_identity: initiator.identity(),
            responder_identity: responder.identity(),
            initiator_ephemeral: [3; 32],
            responder_ephemeral: [4; 32],
            initiator_nonce: [5; 16],
            responder_nonce: [6; 16],
            previous_session_id: None,
            initiator_signature: [0; 64],
            responder_signature: None,
        };
        let hash = transcript_hash(&payload.transcript().encode().unwrap());
        payload.initiator_signature = initiator.sign_transcript(&hash, true);
        assert!(matches!(
            verify_handshake(&payload, &[7; 32], false, None),
            Err(Error::SasRejected)
        ));
        assert!(matches!(
            verify_handshake(
                &payload,
                &[7; 32],
                true,
                Some((PeerIdentity::from_bytes([9; 32]), TrustState::Trusted)),
            ),
            Err(Error::IdentityMismatch)
        ));
    }

    #[test]
    fn rekey_glare_uses_unsigned_raw_key_ordering() {
        assert!(local_identity_wins_rekey_glare(
            &PeerIdentity::from_bytes([2; 32]),
            &PeerIdentity::from_bytes([1; 32]),
        ));
        assert!(!local_identity_wins_rekey_glare(
            &PeerIdentity::from_bytes([1; 32]),
            &PeerIdentity::from_bytes([2; 32]),
        ));
    }

    #[test]
    fn rekey_hello_and_handshake_frames_use_the_rekey_wire_type() {
        let rekey_hello = HelloPayload {
            cipher_suite: 1,
            purpose: HandshakePurpose::Rekey,
            role: HelloRole::Initiator,
            identity_public_key: PeerIdentity::from_bytes([1; 32]),
            ephemeral_public_key: [2; 32],
            nonce: [3; 16],
            previous_session_id: Some(SessionId::from_bytes([9; 16])),
        };
        let frame = rekey_hello.encode().unwrap();
        assert_eq!(frame.message_type, MessageType::Rekey);
        assert_eq!(HelloPayload::decode(&frame).unwrap(), rekey_hello);

        let mut wrong_type_frame = frame.clone();
        wrong_type_frame.message_type = MessageType::Handshake;
        assert_eq!(
            HelloPayload::decode(&wrong_type_frame),
            Err(Error::InvalidHandshake)
        );

        let initiator = IdentityKeypair::from_bytes(&[1; 32]);
        let responder = IdentityKeypair::from_bytes(&[2; 32]);
        let mut payload = HandshakePayload {
            handshake_type: HandshakeType::Rekey,
            stage: 0,
            cipher_suite: 1,
            initiator_identity: initiator.identity(),
            responder_identity: responder.identity(),
            initiator_ephemeral: [3; 32],
            responder_ephemeral: [4; 32],
            initiator_nonce: [5; 16],
            responder_nonce: [6; 16],
            previous_session_id: Some(SessionId::from_bytes([9; 16])),
            initiator_signature: [0; 64],
            responder_signature: None,
        };
        let hash = transcript_hash(&payload.transcript().encode().unwrap());
        payload.initiator_signature = initiator.sign_transcript(&hash, true);
        let frame = payload.encode().unwrap();
        assert_eq!(frame.message_type, MessageType::Rekey);
        assert_eq!(HandshakePayload::decode(&frame).unwrap(), payload);
    }
}
