//! Persistent peer identities and application-level trust records.
//!
//! A [`PeerIdentity`] is a public Ed25519 identity, not a network address.
//! Receiving one does not itself change a peer's [`TrustState`].

use crate::error::{Error, Result};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity([u8; 32]);

impl PeerIdentity {
    pub const LENGTH: usize = 32;

    /// Creates an identity from exactly 32 public-key bytes.
    pub fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Parses an identity while rejecting every length other than 32 bytes.
    pub fn try_from_slice(bytes: &[u8]) -> Result<Self> {
        let array: [u8; Self::LENGTH] = bytes.try_into().map_err(|_| Error::InvalidLength {
            kind: "peer identity",
            expected: Self::LENGTH,
            actual: bytes.len(),
        })?;
        Ok(Self(array))
    }

    /// Borrows the public-key bytes.
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TrustState {
    Unknown,
    Trusted,
    Revoked,
    Replaced,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    pub identity: PeerIdentity,
    pub display_name: Option<String>,
    pub trust_state: TrustState,
}

impl PeerRecord {
    /// Creates an untrusted record for an identity.
    pub fn new(identity: PeerIdentity) -> Self {
        Self {
            identity,
            display_name: None,
            trust_state: TrustState::Unknown,
        }
    }
}
