//! RUXMSG/1 protocol registries, bounds, and fixed-size identifiers.
//!
//! Values in this module are wire-level contracts. Changing them requires a
//! protocol decision, specification update, vectors, and interoperability review.

use crate::error::{Error, Result};

pub const MAX_FRAME_SIZE: u32 = 1_048_576;
pub const REPLAY_WINDOW_SIZE: u8 = 64;
pub const MAX_SKIPPED_KEYS: u8 = 64;
pub const DEFAULT_PADDING_QUANTUM: usize = 256;
pub const REKEY_DRAIN_TIMEOUT_SECS: u64 = 15;
pub const REKEY_INTERVAL_SECS: u64 = 24 * 60 * 60;
pub const REKEY_MESSAGE_LIMIT: u64 = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum ProtocolVersion {
    V1 = 0x01,
}

impl TryFrom<u8> for ProtocolVersion {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::V1),
            other => Err(Error::UnsupportedVersion(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MessageType {
    Handshake = 0x01,
    SessionConfirm = 0x02,
    Data = 0x03,
    Rekey = 0x04,
    Close = 0x05,
}

impl TryFrom<u8> for MessageType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            0x01 => Ok(Self::Handshake),
            0x02 => Ok(Self::SessionConfirm),
            0x03 => Ok(Self::Data),
            0x04 => Ok(Self::Rekey),
            0x05 => Ok(Self::Close),
            other => Err(Error::UnknownMessageType(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum DirectionId {
    InitiatorToResponder = 0x0000_0001,
    ResponderToInitiator = 0x0000_0002,
}

impl TryFrom<u32> for DirectionId {
    type Error = Error;

    fn try_from(value: u32) -> Result<Self> {
        match value {
            0x0000_0001 => Ok(Self::InitiatorToResponder),
            0x0000_0002 => Ok(Self::ResponderToInitiator),
            other => Err(Error::InvalidDirection(other)),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameLength(u32);

impl FrameLength {
    /// Validates a payload length against the one-megabyte protocol limit.
    pub fn new(value: u32) -> Result<Self> {
        if value <= MAX_FRAME_SIZE {
            Ok(Self(value))
        } else {
            Err(Error::InvalidFrameLength(value))
        }
    }

    /// Returns the validated payload length in bytes.
    pub const fn get(self) -> u32 {
        self.0
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct SessionId([u8; 16]);

impl SessionId {
    pub const LENGTH: usize = 16;

    /// Creates an identifier from its protocol-length byte representation.
    pub fn from_bytes(bytes: [u8; Self::LENGTH]) -> Self {
        Self(bytes)
    }

    /// Borrows the raw identifier bytes without exposing a mutable view.
    pub const fn as_bytes(&self) -> &[u8; Self::LENGTH] {
        &self.0
    }
}

impl std::fmt::Debug for SessionId {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_tuple("SessionId")
            .field(&hex_prefix(&self.0))
            .finish()
    }
}

fn hex_prefix(bytes: &[u8]) -> String {
    bytes
        .iter()
        .take(4)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_frames_before_use() {
        assert_eq!(
            FrameLength::new(MAX_FRAME_SIZE + 1),
            Err(Error::InvalidFrameLength(MAX_FRAME_SIZE + 1))
        );
    }

    #[test]
    fn accepts_only_registered_values() {
        assert_eq!(ProtocolVersion::try_from(1), Ok(ProtocolVersion::V1));
        assert_eq!(MessageType::try_from(5), Ok(MessageType::Close));
        assert_eq!(DirectionId::try_from(3), Err(Error::InvalidDirection(3)));
    }
}
