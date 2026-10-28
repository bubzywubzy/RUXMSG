#![doc = include_str!("../../../docs/library.md")]
#![doc = "\nSee also the [architecture guide](../../../docs/architecture.md), [security model](../../../docs/security-model.md), and [normative protocol specification](../../../docs/protocol-spec.md)."]

pub mod close;
pub mod crypto;
pub mod data;
pub mod display;
pub mod encoding;
pub mod error;
pub mod handshake;
pub mod identity;
pub mod machine;
pub mod protocol;
pub mod ratchet;
pub mod storage;
pub mod wire;

pub use error::{Error, Result};
pub use identity::PeerIdentity;
pub use protocol::{DirectionId, FrameLength, MessageType, ProtocolVersion, SessionId};
