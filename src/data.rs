//! Authenticated DATA payloads, deterministic padding, and directional ratchets.
//!
//! DATA content is encrypted before padding is inspected by the receiver.
//! Counters and replay state are session-local and must never be persisted or
//! reset while a session remains active.

use std::fmt;

use ciborium::value::Value;

use crate::crypto::{decrypt_message, derive_message_key, encrypt_message, message_nonce};
use crate::error::{Error, Result};
use crate::protocol::{
    DEFAULT_PADDING_QUANTUM, DirectionId, MAX_FRAME_SIZE, MessageType, SessionId,
};
use crate::ratchet::{ReceivingChain, ReplayWindow};
use crate::wire::Frame;

const AEAD_TAG_SIZE: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPayload {
    pub session_id: SessionId,
    pub direction_id: DirectionId,
    pub message_counter: u64,
    pub ciphertext: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPlaintext {
    pub content: Vec<u8>,
    pub padding: Vec<u8>,
}

impl DataPlaintext {
    /// Builds zero padding so the encoded plaintext plus its AEAD tag reaches
    /// the configured padding quantum.
    pub fn padded(content: &[u8]) -> Result<Self> {
        let mut padding_len = 0usize;
        loop {
            let candidate = Self {
                content: content.to_vec(),
                padding: vec![0; padding_len],
            };
            let encoded = candidate.encode()?;
            let target = encoded
                .len()
                .checked_add(AEAD_TAG_SIZE)
                .ok_or(Error::DataTooLarge)?;
            let rounded = target.div_ceil(DEFAULT_PADDING_QUANTUM) * DEFAULT_PADDING_QUANTUM;
            let next = rounded
                .checked_sub(AEAD_TAG_SIZE)
                .and_then(|size| size.checked_sub(encoded.len() - padding_len))
                .ok_or(Error::DataTooLarge)?;
            if next == padding_len {
                return Ok(candidate);
            }
            padding_len = next;
            if padding_len > MAX_FRAME_SIZE as usize {
                return Err(Error::DataTooLarge);
            }
        }
    }

    /// Encodes the authenticated plaintext map as deterministic CBOR.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let value = Value::Map(vec![
            (uint(0u64), Value::Bytes(self.content.clone())),
            (uint(1u64), Value::Bytes(self.padding.clone())),
        ]);
        let mut output = Vec::new();
        ciborium::ser::into_writer(&value, &mut output)
            .map_err(|error| Error::Encoding(error.to_string()))?;
        Ok(output)
    }

    /// Decodes and validates content/padding after AEAD authentication.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        Frame::new(MessageType::Data, bytes.to_vec())?.validate_cbor_map()?;
        let value: Value =
            ciborium::de::from_reader(bytes).map_err(|error| Error::Encoding(error.to_string()))?;
        let Value::Map(entries) = value else {
            return Err(Error::InvalidDataPayload);
        };
        if entries.len() != 2 {
            return Err(Error::InvalidDataPayload);
        }
        let mut content = None;
        let mut padding = None;
        for (key, value) in entries {
            let Value::Integer(key) = key else {
                return Err(Error::InvalidDataPayload);
            };
            match u64::try_from(key).map_err(|_| Error::InvalidDataPayload)? {
                0 => content = Some(bytes_value(value)?),
                1 => padding = Some(bytes_value(value)?),
                _ => return Err(Error::InvalidDataPayload),
            }
        }
        let padding = padding.ok_or(Error::InvalidDataPayload)?;
        if padding.iter().any(|byte| *byte != 0) {
            return Err(Error::InvalidPadding);
        }
        Ok(Self {
            content: content.ok_or(Error::InvalidDataPayload)?,
            padding,
        })
    }
}

pub struct DataSender {
    session_id: SessionId,
    direction: DirectionId,
    chain_key: [u8; 32],
    counter: u64,
}

impl fmt::Debug for DataSender {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataSender")
            .field("session_id", &self.session_id)
            .field("direction", &self.direction)
            .field("counter", &self.counter)
            .finish_non_exhaustive()
    }
}

impl DataSender {
    /// Creates a sender whose first message uses counter zero.
    pub fn new(session_id: SessionId, direction: DirectionId, chain_key: [u8; 32]) -> Self {
        Self {
            session_id,
            direction,
            chain_key,
            counter: 0,
        }
    }

    /// Encrypts one message and advances the directional chain and counter.
    pub fn encrypt(&mut self, content: &[u8]) -> Result<Frame> {
        let counter = self.counter;
        let plaintext = DataPlaintext::padded(content)?.encode()?;
        let (message_key, next_chain) = derive_message_key(&self.chain_key, self.direction);
        let aad = data_aad(self.session_id, self.direction, counter)?;
        let ciphertext = encrypt_message(
            &message_key,
            &message_nonce(self.direction, counter),
            &aad,
            &plaintext,
        )?;
        self.chain_key = next_chain;
        self.counter = self.counter.checked_add(1).ok_or(Error::CounterOverflow)?;
        encode_payload(DataPayload {
            session_id: self.session_id,
            direction_id: self.direction,
            message_counter: counter,
            ciphertext,
        })
    }
}

pub struct DataReceiver {
    session_id: SessionId,
    chain: ReceivingChain,
    replay: ReplayWindow,
}

impl fmt::Debug for DataReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataReceiver")
            .field("session_id", &self.session_id)
            .finish_non_exhaustive()
    }
}

impl DataReceiver {
    /// Creates a receiver with an empty replay window and receiving chain.
    pub fn new(session_id: SessionId, direction: DirectionId, chain_key: [u8; 32]) -> Self {
        Self {
            session_id,
            chain: ReceivingChain::new(chain_key, direction),
            replay: ReplayWindow::new(),
        }
    }

    /// Authenticates, replay-checks, decrypts, and returns one DATA message.
    pub fn decrypt(&mut self, frame: &Frame) -> Result<Vec<u8>> {
        if frame.message_type != MessageType::Data {
            return Err(Error::InvalidDataPayload);
        }
        let payload = decode_payload(&frame.payload)?;
        if payload.session_id != self.session_id {
            return Err(Error::InvalidDataPayload);
        }
        if self.replay.classify(payload.message_counter) != crate::ratchet::ReplayStatus::New {
            return Err(Error::ReplayRejected);
        }
        let message_key = self.chain.message_key(payload.message_counter)?;
        let aad = data_aad(
            self.session_id,
            payload.direction_id,
            payload.message_counter,
        )?;
        let plaintext = decrypt_message(
            &message_key,
            &message_nonce(payload.direction_id, payload.message_counter),
            &aad,
            &payload.ciphertext,
        )?;
        let decoded = DataPlaintext::decode(&plaintext)?;
        self.replay.accept(payload.message_counter)?;
        Ok(decoded.content)
    }
}

fn encode_payload(payload: DataPayload) -> Result<Frame> {
    let value = Value::Map(vec![
        (
            uint(0u64),
            Value::Bytes(payload.session_id.as_bytes().to_vec()),
        ),
        (uint(1u64), uint(payload.direction_id as u32)),
        (uint(2u64), uint(payload.message_counter)),
        (uint(3u64), Value::Bytes(payload.ciphertext)),
    ]);
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&value, &mut encoded)
        .map_err(|error| Error::Encoding(error.to_string()))?;
    Frame::new(MessageType::Data, encoded)
}

fn decode_payload(bytes: &[u8]) -> Result<DataPayload> {
    Frame::new(MessageType::Data, bytes.to_vec())?.validate_cbor_map()?;
    let value: Value =
        ciborium::de::from_reader(bytes).map_err(|error| Error::Encoding(error.to_string()))?;
    let Value::Map(entries) = value else {
        return Err(Error::InvalidDataPayload);
    };
    if entries.len() != 4 {
        return Err(Error::InvalidDataPayload);
    }
    let mut session_id = None;
    let mut direction_id = None;
    let mut counter = None;
    let mut ciphertext = None;
    for (key, value) in entries {
        let Value::Integer(key) = key else {
            return Err(Error::InvalidDataPayload);
        };
        match u64::try_from(key).map_err(|_| Error::InvalidDataPayload)? {
            0 => {
                let bytes = bytes_value(value)?;
                session_id = Some(SessionId::from_bytes(
                    bytes.try_into().map_err(|_| Error::InvalidDataPayload)?,
                ));
            }
            1 => {
                let raw =
                    u32::try_from(uint_value(value)?).map_err(|_| Error::InvalidDataPayload)?;
                direction_id = Some(DirectionId::try_from(raw)?);
            }
            2 => counter = Some(uint_value(value)?),
            3 => ciphertext = Some(bytes_value(value)?),
            _ => return Err(Error::InvalidDataPayload),
        }
    }
    let ciphertext = ciphertext.ok_or(Error::InvalidDataPayload)?;
    if ciphertext.len() < AEAD_TAG_SIZE {
        return Err(Error::InvalidDataPayload);
    }
    Ok(DataPayload {
        session_id: session_id.ok_or(Error::InvalidDataPayload)?,
        direction_id: direction_id.ok_or(Error::InvalidDataPayload)?,
        message_counter: counter.ok_or(Error::InvalidDataPayload)?,
        ciphertext,
    })
}

fn data_aad(session_id: SessionId, direction: DirectionId, counter: u64) -> Result<Vec<u8>> {
    let value = Value::Map(vec![
        (uint(0u64), uint(1u64)),
        (uint(1u64), Value::Bytes(session_id.as_bytes().to_vec())),
        (uint(2u64), uint(MessageType::Data as u8)),
        (uint(3u64), uint(direction as u32)),
        (uint(4u64), uint(counter)),
    ]);
    let mut encoded = Vec::new();
    ciborium::ser::into_writer(&value, &mut encoded)
        .map_err(|error| Error::Encoding(error.to_string()))?;
    Ok(encoded)
}

fn uint(value: impl Into<u64>) -> Value {
    Value::Integer(value.into().into())
}

fn uint_value(value: Value) -> Result<u64> {
    let Value::Integer(value) = value else {
        return Err(Error::InvalidDataPayload);
    };
    u64::try_from(value).map_err(|_| Error::InvalidDataPayload)
}

fn bytes_value(value: Value) -> Result<Vec<u8>> {
    let Value::Bytes(value) = value else {
        return Err(Error::InvalidDataPayload);
    };
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authenticated_data_round_trip_and_replay_rejection() {
        let id = SessionId::from_bytes([4; 16]);
        let mut sender = DataSender::new(id, DirectionId::InitiatorToResponder, [9; 32]);
        let mut receiver = DataReceiver::new(id, DirectionId::InitiatorToResponder, [9; 32]);
        let frame = sender.encrypt(b"hello").unwrap();
        assert_eq!(receiver.decrypt(&frame).unwrap(), b"hello");
        assert_eq!(receiver.decrypt(&frame), Err(Error::ReplayRejected));
    }

    #[test]
    fn tampered_ciphertext_and_padding_are_rejected() {
        let id = SessionId::from_bytes([5; 16]);
        let mut sender = DataSender::new(id, DirectionId::ResponderToInitiator, [8; 32]);
        let mut receiver = DataReceiver::new(id, DirectionId::ResponderToInitiator, [8; 32]);
        let mut frame = sender.encrypt(b"secret").unwrap();
        *frame.payload.last_mut().unwrap() ^= 1;
        assert_eq!(receiver.decrypt(&frame), Err(Error::AeadFailure));
    }

    #[test]
    fn padding_accounts_for_serialized_structure_and_tag() {
        let plaintext = DataPlaintext::padded(&[7; 31]).unwrap();
        let encoded = plaintext.encode().unwrap();
        assert_eq!((encoded.len() + AEAD_TAG_SIZE) % DEFAULT_PADDING_QUANTUM, 0);
        assert!(plaintext.padding.iter().all(|byte| *byte == 0));
    }
}
