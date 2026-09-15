//! Cryptographic building blocks used by the RUXMSG handshake and DATA layers.
//!
//! These functions compose reviewed primitives; they do not define a general
//! purpose cryptographic API. Callers must preserve the protocol's domains,
//! directions, counters, and key lifetimes described in `protocol-spec.md`.

use std::fmt;

use bip39::Language;
use chacha20poly1305::{
    ChaCha20Poly1305, Key, KeyInit, Nonce,
    aead::{Aead, Payload},
};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};
use crate::identity::PeerIdentity;
use crate::protocol::{DirectionId, SessionId};

const HASH_DOMAIN: &[u8] = b"RUXMSG/1/TRANSCRIPT";
const INITIATOR_SIGNATURE_DOMAIN: &[u8] = b"RUXMSG/1/initiator";
const RESPONDER_SIGNATURE_DOMAIN: &[u8] = b"RUXMSG/1/responder";
const INITIATOR_CONFIRM_DOMAIN: &[u8] = b"RUXMSG/1/confirm/I";
const RESPONDER_CONFIRM_DOMAIN: &[u8] = b"RUXMSG/1/confirm/R";
const ZERO_SALT: [u8; 32] = [0; 32];

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct IdentityKeypair {
    secret: [u8; 32],
}

impl fmt::Debug for IdentityKeypair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("IdentityKeypair(REDACTED)")
    }
}

impl IdentityKeypair {
    /// Generates a fresh persistent Ed25519 identity seed.
    pub fn generate() -> Self {
        let signing_key = SigningKey::generate(&mut OsRng);
        Self {
            secret: signing_key.to_bytes(),
        }
    }

    /// Restores an identity from its 32-byte Ed25519 seed.
    ///
    /// The input is secret material and must come only from protected storage.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self { secret: *bytes }
    }

    /// Exposes the raw seed so it can be sealed into persistent storage; callers
    /// must not log, transmit, or otherwise expose the returned bytes.
    pub const fn to_bytes(&self) -> [u8; 32] {
        self.secret
    }

    /// Returns the persistent public identity corresponding to this keypair.
    pub fn identity(&self) -> PeerIdentity {
        PeerIdentity::from_bytes(
            SigningKey::from_bytes(&self.secret)
                .verifying_key()
                .to_bytes(),
        )
    }

    /// Signs a transcript hash with the role-specific RUXMSG domain.
    pub fn sign_transcript(&self, transcript_hash: &[u8; 32], initiator: bool) -> [u8; 64] {
        let domain = if initiator {
            INITIATOR_SIGNATURE_DOMAIN
        } else {
            RESPONDER_SIGNATURE_DOMAIN
        };
        let mut input = Vec::with_capacity(domain.len() + transcript_hash.len());
        input.extend_from_slice(domain);
        input.extend_from_slice(transcript_hash);
        SigningKey::from_bytes(&self.secret).sign(&input).to_bytes()
    }
}

pub fn verify_transcript_signature(
    identity: &PeerIdentity,
    transcript_hash: &[u8; 32],
    signature: &[u8; 64],
    initiator: bool,
) -> Result<()> {
    let verifying_key =
        VerifyingKey::from_bytes(identity.as_bytes()).map_err(|_| Error::InvalidIdentityKey)?;
    let domain = if initiator {
        INITIATOR_SIGNATURE_DOMAIN
    } else {
        RESPONDER_SIGNATURE_DOMAIN
    };
    let mut input = Vec::with_capacity(domain.len() + transcript_hash.len());
    input.extend_from_slice(domain);
    input.extend_from_slice(transcript_hash);
    let signature = ed25519_dalek::Signature::from_bytes(signature);
    verifying_key
        .verify(&input, &signature)
        .map_err(|_| Error::SignatureInvalid)
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct EphemeralKeypair {
    secret: [u8; 32],
    public: [u8; 32],
}

impl fmt::Debug for EphemeralKeypair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EphemeralKeypair(REDACTED)")
    }
}

impl EphemeralKeypair {
    /// Generates a fresh X25519 ephemeral keypair for one session.
    pub fn generate() -> Self {
        let secret = StaticSecret::random_from_rng(OsRng);
        let public = X25519PublicKey::from(&secret);
        Self {
            secret: secret.to_bytes(),
            public: public.to_bytes(),
        }
    }

    /// Restores an ephemeral keypair from its 32-byte X25519 private key.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let secret = StaticSecret::from(*bytes);
        let public = X25519PublicKey::from(&secret);
        Self {
            secret: *bytes,
            public: public.to_bytes(),
        }
    }

    /// Returns the public half safe to include in a HELLO.
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// Performs X25519 agreement and rejects an all-zero shared secret.
    pub fn shared_secret(&self, remote_public: &[u8; 32]) -> Result<[u8; 32]> {
        let secret = StaticSecret::from(self.secret);
        let shared = secret.diffie_hellman(&X25519PublicKey::from(*remote_public));
        if shared.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(Error::AllZeroSharedSecret);
        }
        Ok(shared.to_bytes())
    }
}

/// Hashes deterministic transcript bytes with the RUXMSG domain and length.
pub fn transcript_hash(transcript: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(HASH_DOMAIN);
    hasher.update((transcript.len() as u32).to_be_bytes());
    hasher.update(transcript);
    hasher.finalize().into()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SasIndices {
    pub first: u16,
    pub second: u16,
    pub third: u16,
}

/// Extracts three MSB-first 11-bit dictionary indices from a transcript hash.
pub fn sas_indices(transcript_hash: &[u8; 32]) -> SasIndices {
    let packed = (u64::from(transcript_hash[0]) << 25)
        | (u64::from(transcript_hash[1]) << 17)
        | (u64::from(transcript_hash[2]) << 9)
        | (u64::from(transcript_hash[3]) << 1)
        | u64::from(transcript_hash[4] >> 7);
    SasIndices {
        first: ((packed >> 22) & 0x7ff) as u16,
        second: ((packed >> 11) & 0x7ff) as u16,
        third: (packed & 0x7ff) as u16,
    }
}

/// Renders the transcript hash as the three-word BIP-0039 SAS dictionary value.
pub fn sas_words(transcript_hash: &[u8; 32]) -> [&'static str; 3] {
    let indices = sas_indices(transcript_hash);
    let words = Language::English.word_list();
    [
        words[indices.first as usize],
        words[indices.second as usize],
        words[indices.third as usize],
    ]
}

#[derive(Debug, Zeroize, ZeroizeOnDrop)]
pub struct SessionKeys {
    pub root_key: [u8; 32],
    pub initiator_to_responder: [u8; 32],
    pub responder_to_initiator: [u8; 32],
    #[zeroize(skip)]
    pub session_id: SessionId,
    pub confirmation_key: [u8; 32],
}

/// Derives the root, directional, confirmation, and session-ID values.
pub fn derive_session_keys(
    shared_secret: &[u8; 32],
    transcript_hash: &[u8; 32],
) -> Result<SessionKeys> {
    let hkdf = Hkdf::<Sha256>::new(Some(transcript_hash), shared_secret);
    let mut root_key = [0; 32];
    let mut initiator_to_responder = [0; 32];
    let mut responder_to_initiator = [0; 32];
    let mut session_id = [0; 16];
    let mut confirmation_key = [0; 32];
    hkdf.expand(b"RUXMSG/1/root", &mut root_key)
        .map_err(|_| Error::KeyDerivation)?;
    hkdf.expand(b"RUXMSG/1/I-to-R", &mut initiator_to_responder)
        .map_err(|_| Error::KeyDerivation)?;
    hkdf.expand(b"RUXMSG/1/R-to-I", &mut responder_to_initiator)
        .map_err(|_| Error::KeyDerivation)?;
    hkdf.expand(b"RUXMSG/1/session-id", &mut session_id)
        .map_err(|_| Error::KeyDerivation)?;
    hkdf.expand(b"RUXMSG/1/session-confirm", &mut confirmation_key)
        .map_err(|_| Error::KeyDerivation)?;
    Ok(SessionKeys {
        root_key,
        initiator_to_responder,
        responder_to_initiator,
        session_id: SessionId::from_bytes(session_id),
        confirmation_key,
    })
}

/// Computes the role-specific confirmation MAC over the transcript hash.
pub fn confirmation_mac(key: &[u8; 32], transcript_hash: &[u8; 32], initiator: bool) -> [u8; 32] {
    let domain = if initiator {
        INITIATOR_CONFIRM_DOMAIN
    } else {
        RESPONDER_CONFIRM_DOMAIN
    };
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts 32-byte keys");
    mac.update(domain);
    mac.update(transcript_hash);
    mac.finalize().into_bytes().into()
}

pub fn verify_confirmation(
    key: &[u8; 32],
    transcript_hash: &[u8; 32],
    expected: &[u8; 32],
    initiator: bool,
) -> Result<()> {
    let actual = confirmation_mac(key, transcript_hash, initiator);
    if actual.as_slice().ct_eq(expected.as_slice()).into() {
        Ok(())
    } else {
        Err(Error::ConfirmationInvalid)
    }
}

/// Derives one message key and the next chain key for a direction.
pub fn derive_message_key(chain_key: &[u8; 32], direction: DirectionId) -> ([u8; 32], [u8; 32]) {
    let hkdf = Hkdf::<Sha256>::new(Some(&ZERO_SALT), chain_key);
    let direction_bytes = (direction as u32).to_be_bytes();
    let mut message_key = [0; 32];
    let mut next_chain_key = [0; 32];
    let mut message_info = b"RUXMSG/1/message-key".to_vec();
    message_info.extend_from_slice(&direction_bytes);
    let mut chain_info = b"RUXMSG/1/chain-key".to_vec();
    chain_info.extend_from_slice(&direction_bytes);
    hkdf.expand(&message_info, &mut message_key)
        .expect("fixed HKDF output");
    hkdf.expand(&chain_info, &mut next_chain_key)
        .expect("fixed HKDF output");
    (message_key, next_chain_key)
}

/// Builds the protocol nonce as big-endian direction ID plus counter.
pub fn message_nonce(direction: DirectionId, counter: u64) -> [u8; 12] {
    let mut nonce = [0; 12];
    nonce[..4].copy_from_slice(&(direction as u32).to_be_bytes());
    nonce[4..].copy_from_slice(&counter.to_be_bytes());
    nonce
}

/// Encrypts plaintext with ChaCha20-Poly1305 and authenticates `aad`.
pub fn encrypt_message(
    message_key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new(Key::from_slice(message_key))
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::AeadFailure)
}

/// Authenticates and decrypts ChaCha20-Poly1305 ciphertext.
pub fn decrypt_message(
    message_key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>> {
    ChaCha20Poly1305::new(Key::from_slice(message_key))
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| Error::AeadFailure)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sas_extraction_is_msb_first() {
        let mut hash = [0; 32];
        hash[..5].copy_from_slice(&[0xff, 0x00, 0xaa, 0x55, 0x80]);
        let indices = sas_indices(&hash);
        assert_eq!(indices.first, 0x7f8);
        assert_eq!(indices.second, 0x02a);
        assert_eq!(indices.third, 0x4ab);
        assert_eq!(sas_words(&[0; 32]), ["abandon", "abandon", "abandon"]);
    }

    #[test]
    fn message_round_trip_authenticates_aad() {
        let key = [7; 32];
        let nonce = message_nonce(DirectionId::InitiatorToResponder, 0);
        let ciphertext = encrypt_message(&key, &nonce, b"aad", b"message").unwrap();
        assert_eq!(
            decrypt_message(&key, &nonce, b"aad", &ciphertext).unwrap(),
            b"message"
        );
        assert_eq!(
            decrypt_message(&key, &nonce, b"changed", &ciphertext),
            Err(Error::AeadFailure)
        );
    }

    #[test]
    fn identity_signatures_bind_the_transcript_hash_and_role() {
        let identity = IdentityKeypair::from_bytes(&[9; 32]);
        let transcript_hash = [8; 32];
        let signature = identity.sign_transcript(&transcript_hash, true);

        verify_transcript_signature(&identity.identity(), &transcript_hash, &signature, true)
            .unwrap();
        assert_eq!(
            verify_transcript_signature(&identity.identity(), &[7; 32], &signature, true,),
            Err(Error::SignatureInvalid)
        );
    }

    #[test]
    fn ephemeral_keypairs_derive_the_same_shared_secret() {
        let first = EphemeralKeypair::generate();
        let second = EphemeralKeypair::generate();
        assert_eq!(
            first.shared_secret(&second.public_key()).unwrap(),
            second.shared_secret(&first.public_key()).unwrap()
        );
    }
}
