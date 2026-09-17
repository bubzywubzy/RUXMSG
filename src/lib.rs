#![doc = include_str!("../docs/library.md")]
#![doc = "\nSee also the [architecture guide](../docs/architecture.md), [security model](../docs/security-model.md), and [normative protocol specification](../protocol-spec.md)."]

pub mod close;
pub mod connection;
pub mod crypto;
pub mod data;
pub mod encoding;
pub mod engine;
pub mod error;
pub mod handshake;
pub mod identity;
pub mod manager;
pub mod protocol;
pub mod ratchet;
pub mod session;
pub mod storage;
pub mod transport;
pub mod wire;

pub use error::{Error, Result};
pub use identity::PeerIdentity;
pub use protocol::{DirectionId, FrameLength, MessageType, ProtocolVersion, SessionId};
