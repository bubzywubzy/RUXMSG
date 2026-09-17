//! Public peer identity representation.
//!
//! A `PeerIdentity` is a public Ed25519 identity. It is not a network
//! address, trust record, or persistent peer entry.
//!
//! Receiving a peer identity never changes persistent local state.

use crate::error::{Error, Result};

/// A peer's 32-byte Ed25519 public identity.
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
