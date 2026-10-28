use thiserror::Error;

/// Errors shared by the protocol foundation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum Error {
    #[error("unsupported protocol version: {0:#04x}")]
    UnsupportedVersion(u8),

    #[error("unknown message type: {0:#04x}")]
    UnknownMessageType(u8),

    #[error("invalid frame payload length: {0} bytes")]
    InvalidFrameLength(u32),

    #[error("invalid direction identifier: {0:#010x}")]
    InvalidDirection(u32),

    #[error("invalid fixed-size value for {kind}: expected {expected} bytes, got {actual}")]
    InvalidLength {
        kind: &'static str,
        expected: usize,
        actual: usize,
    },

    #[error("trust-store operation failed: {0}")]
    Storage(String),

    #[error("invalid Ed25519 identity key")]
    InvalidIdentityKey,

    #[error("all-zero X25519 shared secret")]
    AllZeroSharedSecret,

    #[error("invalid Ed25519 signature")]
    SignatureInvalid,

    #[error("invalid session confirmation")]
    ConfirmationInvalid,

    #[error("key derivation failed")]
    KeyDerivation,

    #[error("AEAD operation failed")]
    AeadFailure,

    #[error("deterministic encoding failed: {0}")]
    Encoding(String),

    #[error("truncated frame")]
    TruncatedFrame,

    #[error("invalid CBOR payload shape")]
    InvalidPayloadShape,

    #[error("invalid CBOR map key")]
    InvalidMapKey,

    #[error("duplicate CBOR map key: {0}")]
    DuplicateMapKey(u64),

    #[error("non-canonical encoding")]
    NonCanonicalEncoding,

    #[error("replayed or out-of-window message")]
    ReplayRejected,

    #[error("message key unavailable for counter {0}")]
    MessageKeyUnavailable(u64),

    #[error("skipped-message-key limit exceeded")]
    SkippedKeyLimit,

    #[error("message counter overflow")]
    CounterOverflow,

    #[error("invalid session state transition")]
    InvalidStateTransition,

    #[error("transport is closed")]
    TransportClosed,

    #[error("transport I/O failed: {0}")]
    Transport(String),

    #[error("transport read timed out")]
    TransportTimeout,

    #[error("unexpected trailing frame bytes")]
    TrailingFrameBytes,

    #[error("invalid DATA payload")]
    InvalidDataPayload,

    #[error("invalid DATA padding")]
    InvalidPadding,

    #[error("DATA payload exceeds the configured limit")]
    DataTooLarge,

    #[error("invalid handshake payload")]
    InvalidHandshake,

    #[error("invalid CLOSE payload")]
    InvalidClosePayload,

    #[error("short authentication string was not approved")]
    SasRejected,

    #[error("peer identity does not match the trusted identity")]
    IdentityMismatch,
}

pub type Result<T> = std::result::Result<T, Error>;
