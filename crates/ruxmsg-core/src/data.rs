//! Authenticated DATA payloads, deterministic padding, and directional ratchets.
//!
//! DATA content is encrypted before padding is inspected by the receiver.
//! Counters and replay state are session-local and must never be persisted or
//! reset while a session remains active.

use std::fmt;

use ciborium::value::Value;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::crypto::{decrypt_message, derive_message_key, encrypt_message, message_nonce};
use crate::encoding::uint;
use crate::error::{Error, Result};
use crate::protocol::{
    DEFAULT_PADDING_QUANTUM, DirectionId, MAX_CONTENT, MAX_FRAME_SIZE, MessageType, SessionId,
};
use crate::ratchet::{ReceivingChain, ReplayStatus, ReplayWindow};
use crate::wire::Frame;

const AEAD_TAG_SIZE: usize = 16;

struct WipeCborBytes(Value);

impl Drop for WipeCborBytes {
    fn drop(&mut self) {
        if let Value::Map(entries) = &mut self.0 {
            for (_, value) in entries {
                if let Value::Bytes(bytes) = value {
                    bytes.zeroize();
                }
            }
        }
    }
}

const fn bstr_header_len(length: usize) -> usize {
    match length {
        0..=23 => 1,
        24..=255 => 2,
        256..=65535 => 3,
        _ => 5,
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataPayload {
    pub session_id: SessionId,
    pub direction_id: DirectionId,
    pub message_counter: u64,
    pub ciphertext: Vec<u8>,
}

#[derive(PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct DataPlaintext {
    pub content: Vec<u8>,
    pub padding: Vec<u8>,
}

impl DataPlaintext {
    /// Builds zero padding so the encoded plaintext plus its AEAD tag reaches
    /// the configured padding quantum.
    /// The CBOR header of the padding byte string grows with its length, so
    /// searching upward finds the smallest padding that lands on the quantum.
    pub fn padded(content: &[u8]) -> Result<Self> {
        if content.len() > MAX_CONTENT {
            return Err(Error::DataTooLarge);
        }

        // Encode size excluding padding bytes and the padding header.
        let fixed = Self {
            content: content.to_vec(),
            padding: Vec::new(),
        }
        .encode()?
        .len()
            - bstr_header_len(0);

        let mut padding_len = 0usize;

        loop {
            let total = fixed + bstr_header_len(padding_len) + padding_len + AEAD_TAG_SIZE;

            if total.is_multiple_of(DEFAULT_PADDING_QUANTUM) {
                break;
            }

            padding_len += 1;

            if padding_len > MAX_FRAME_SIZE as usize {
                return Err(Error::DataTooLarge);
            }
        }

        Ok(Self {
            content: content.to_vec(),
            padding: vec![0; padding_len],
        })
    }

    /// Encodes the authenticated plaintext map as deterministic CBOR.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        let value = WipeCborBytes(Value::Map(vec![
            (uint(0u64), Value::Bytes(self.content.clone())),
            (uint(1u64), Value::Bytes(self.padding.clone())),
        ]));

        let mut output = Zeroizing::new(Vec::new());

        ciborium::ser::into_writer(&value.0, &mut *output)
            .map_err(|error| Error::Encoding(error.to_string()))?;

        Ok(output)
    }

    /// Decodes and validates content/padding after AEAD authentication.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let entries = Frame::validate_cbor_map_payload(bytes)?;

        if entries.len() != 2 {
            return Err(Error::InvalidDataPayload);
        }

        let mut content = None;
        let mut padding = None;

        for (key, value) in entries {
            match key {
                0 => content = Some(bytes_value(value)?),
                1 => padding = Some(bytes_value(value)?),
                _ => return Err(Error::InvalidDataPayload),
            }
        }

        let padding = padding.map(Zeroizing::new);
        let content = content.map(Zeroizing::new);
        let mut padding = padding.ok_or(Error::InvalidDataPayload)?;
        let mut content = content.ok_or(Error::InvalidDataPayload)?;
        if content.len() > MAX_CONTENT {
            return Err(Error::DataTooLarge);
        }

        if padding.iter().any(|byte| *byte != 0) {
            return Err(Error::InvalidPadding);
        }
        Ok(Self {
            content: std::mem::take(&mut *content),
            padding: std::mem::take(&mut *padding),
        })
    }
}

impl fmt::Debug for DataPlaintext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataPlaintext")
            .field("content", &"REDACTED")
            .field("padding_len", &self.padding.len())
            .finish()
    }
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct DataSender {
    #[zeroize(skip)]
    session_id: SessionId,
    #[zeroize(skip)]
    direction: DirectionId,
    chain_key: Zeroizing<[u8; 32]>,
    #[zeroize(skip)]
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
            chain_key: Zeroizing::new(chain_key),
            counter: 0,
        }
    }

    /// Encrypts one message and advances the directional chain and counter.
    pub fn encrypt(&mut self, content: &[u8]) -> Result<Frame> {
        let counter = self.counter;

        if content.len() > MAX_CONTENT {
            return Err(Error::DataTooLarge);
        }

        // 1. Check counter limits BEFORE doing any work or mutating state
        let next_counter = counter.checked_add(1).ok_or(Error::CounterOverflow)?;

        // 2. Prepare plaintext
        let plaintext = DataPlaintext::padded(content)?.encode()?;

        // 3. Derive key (does not mutate self.chain_key yet)
        let (message_key, next_chain) = derive_message_key(&self.chain_key, self.direction);

        // 4. Encrypt
        let aad = data_aad(self.session_id, self.direction, counter)?;

        let ciphertext = encrypt_message(
            &message_key,
            &message_nonce(self.direction, counter),
            &aad,
            &plaintext,
        )?;

        // 5. Commit chain and counter only after everything succeeds
        self.chain_key = next_chain;
        self.counter = next_counter;

        // 6. Return frame
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
    direction: DirectionId,
}

impl fmt::Debug for DataReceiver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DataReceiver")
            .field("session_id", &self.session_id)
            .field("direction", &self.direction)
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
            direction,
        }
    }

    /// Authenticates, replay-checks, decrypts, validates, and returns one
    /// DATA message.
    ///
    /// Message-key consumption is committed only after AEAD authentication
    /// and plaintext validation both succeed.
    pub fn decrypt(&mut self, frame: &Frame) -> Result<Zeroizing<Vec<u8>>> {
        if frame.message_type != MessageType::Data {
            return Err(Error::InvalidDataPayload);
        }

        let payload = decode_payload(&frame.payload)?;

        if payload.session_id != self.session_id {
            return Err(Error::InvalidDataPayload);
        }

        // The directional chain is fixed for the lifetime of this receiver.
        // Reject mismatched directions before touching ratchet state.
        if payload.direction_id != self.direction {
            return Err(Error::InvalidDataPayload);
        }

        if self.replay.classify(payload.message_counter) != ReplayStatus::New {
            return Err(Error::ReplayRejected);
        }

        // PREPARE:
        // Derive or retrieve the key without consuming it. If authentication
        // fails, the key remains available for a later legitimate frame.
        let message_key = self.chain.prepare_message_key(payload.message_counter)?;

        let aad = data_aad(
            self.session_id,
            payload.direction_id,
            payload.message_counter,
        )?;

        // AUTHENTICATE:
        // Any failure here leaves the prepared message key untouched.
        let plaintext = Zeroizing::new(decrypt_message(
            &message_key,
            &message_nonce(payload.direction_id, payload.message_counter),
            &aad,
            &payload.ciphertext,
        )?);

        // VALIDATE:
        // Do not consume the message key until the authenticated plaintext
        // also satisfies the DATA payload format and padding requirements.
        let mut decoded = DataPlaintext::decode(&plaintext)?;

        // COMMIT:
        // This is the first point at which the message key is consumed.
        self.chain.commit_message_key(payload.message_counter)?;

        // REPLAY COMMIT:
        // Only authenticated and structurally valid messages enter the replay
        // window.
        self.replay.accept(payload.message_counter)?;

        Ok(Zeroizing::new(std::mem::take(&mut decoded.content)))
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
    let entries = Frame::validate_cbor_map_payload(bytes)?;

    if entries.len() != 4 {
        return Err(Error::InvalidDataPayload);
    }

    let mut session_id = None;
    let mut direction_id = None;
    let mut counter = None;
    let mut ciphertext = None;

    for (key, value) in entries {
        match key {
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

            2 => {
                counter = Some(uint_value(value)?);
            }

            3 => {
                ciphertext = Some(bytes_value(value)?);
            }

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

        assert_eq!(receiver.decrypt(&frame).unwrap().as_slice(), b"hello");
        assert_eq!(receiver.decrypt(&frame), Err(Error::ReplayRejected));
    }

    #[test]
    fn tampered_ciphertext_does_not_consume_message_key() {
        let id = SessionId::from_bytes([5; 16]);

        let mut sender = DataSender::new(id, DirectionId::ResponderToInitiator, [8; 32]);

        let mut receiver = DataReceiver::new(id, DirectionId::ResponderToInitiator, [8; 32]);

        let mut tampered = sender.encrypt(b"secret").unwrap();

        *tampered.payload.last_mut().unwrap() ^= 0x01;

        assert_eq!(receiver.decrypt(&tampered), Err(Error::AeadFailure));

        // The same legitimate frame/counter must remain decryptable after
        // the forged frame failed authentication.
        let valid = sender.encrypt(b"secret").unwrap();

        assert_eq!(receiver.decrypt(&valid).unwrap().as_slice(), b"secret");
    }

    #[test]
    fn future_tampered_message_does_not_consume_target_key() {
        let id = SessionId::from_bytes([6; 16]);

        let mut sender = DataSender::new(id, DirectionId::ResponderToInitiator, [8; 32]);

        let mut receiver = DataReceiver::new(id, DirectionId::ResponderToInitiator, [8; 32]);

        let mut frames = Vec::new();

        for _ in 0..6 {
            frames.push(sender.encrypt(b"secret").unwrap());
        }

        let mut tampered = frames[5].clone();

        *tampered.payload.last_mut().unwrap() ^= 0x01;

        assert_eq!(receiver.decrypt(&tampered), Err(Error::AeadFailure));

        // Counter 5 was prepared and its key must still be available.
        assert_eq!(receiver.decrypt(&frames[5]).unwrap().as_slice(), b"secret");
    }

    #[test]
    fn wrong_direction_is_rejected_before_ratchet_use() {
        let id = SessionId::from_bytes([7; 16]);

        let mut sender = DataSender::new(id, DirectionId::ResponderToInitiator, [8; 32]);

        let mut receiver = DataReceiver::new(id, DirectionId::InitiatorToResponder, [8; 32]);

        let frame = sender.encrypt(b"secret").unwrap();

        assert_eq!(receiver.decrypt(&frame), Err(Error::InvalidDataPayload));
    }

    #[test]
    fn receiver_rejects_authenticated_content_over_the_limit() {
        let id = SessionId::from_bytes([7; 16]);
        let direction = DirectionId::InitiatorToResponder;
        let chain_key = [8; 32];
        let (message_key, _) = derive_message_key(&chain_key, direction);
        let plaintext = DataPlaintext {
            content: vec![0x41; MAX_CONTENT + 1],
            padding: Vec::new(),
        }
        .encode()
        .unwrap();
        let aad = data_aad(id, direction, 0).unwrap();
        let ciphertext =
            encrypt_message(&message_key, &message_nonce(direction, 0), &aad, &plaintext).unwrap();
        let frame = encode_payload(DataPayload {
            session_id: id,
            direction_id: direction,
            message_counter: 0,
            ciphertext,
        })
        .unwrap();
        let mut receiver = DataReceiver::new(id, direction, chain_key);

        assert_eq!(receiver.decrypt(&frame), Err(Error::DataTooLarge));
    }

    #[test]
    fn padding_accounts_for_serialized_structure_and_tag() {
        let plaintext = DataPlaintext::padded(&[7; 31]).unwrap();

        let encoded = plaintext.encode().unwrap();

        assert!((encoded.len() + AEAD_TAG_SIZE).is_multiple_of(DEFAULT_PADDING_QUANTUM));

        assert!(plaintext.padding.iter().all(|byte| *byte == 0));
    }
}
#[cfg(test)]
mod padding_tests {
    use super::*;

    /// Brute-force oracle: the smallest padding whose ciphertext is aligned.
    fn minimal_total(content: &[u8]) -> usize {
        (0..)
            .map(|padding_len| {
                DataPlaintext {
                    content: content.to_vec(),
                    padding: vec![0; padding_len],
                }
                .encode()
                .unwrap()
                .len()
                    + AEAD_TAG_SIZE
            })
            .find(|total| total.is_multiple_of(DEFAULT_PADDING_QUANTUM))
            .unwrap()
    }

    #[test]
    fn padding_is_the_minimal_aligned_size() {
        for length in (0..=700).chain([4_000, 65_535, MAX_CONTENT]) {
            let content = vec![0x42; length];
            let padded = DataPlaintext::padded(&content).unwrap();
            let total = padded.encode().unwrap().len() + AEAD_TAG_SIZE;

            assert_eq!(total, minimal_total(&content), "content length {length}");
        }
    }

    #[test]
    fn oversized_content_is_rejected_by_padded() {
        assert_eq!(
            DataPlaintext::padded(&vec![0; MAX_CONTENT + 1]),
            Err(Error::DataTooLarge)
        );
    }
}
