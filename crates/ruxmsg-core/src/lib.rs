#![doc = r#"
# RUXMSG library

`ruxmsg-core` is the protocol core for RUXMSG/1, a volatile, two-party
end-to-end encrypted messaging protocol.

The crate contains no I/O. It handles typed protocol constants, strict frame
handling, deterministic handshake transcript encoding, Ed25519 signatures,
X25519 key agreement, SAS rendering, HKDF key derivation, confirmation MACs,
directional ratchets, authenticated and padded DATA messages, bounded replay
and skipped-key state, and the sans-IO [`machine::Engine`] that ties everything
together.

The protocol core does not open sockets, spawn threads, manage clocks, or
depend on an asynchronous runtime. The caller drives the state machine by
providing inputs and processing the effects it returns.

## Recommended entry points

- [`machine::Engine`] consumes a [`machine::Input`] and returns ordered
  [`machine::Effect`]s. It has no clock, socket, thread, runtime, or callback.
  Deadlines are expressed as effects, and expiration is delivered as an input.
- `ruxmsg-net` drives an `Engine` over a Tokio byte stream. It owns the
  networking layer, timers, queues, and listener, and is the driver used by
  the terminal client.
- [`storage`] persists exactly one thing: the local identity seed, through a
  `SecretStore` supplied by the caller. The client's operating-system
  credential-store adapter lives in `ruxmsg-cli`.
- [`display::sanitize_for_display`] neutralizes control and bidirectional
  formatting characters in peer-provided text before it is rendered.

## Typical lifecycle

1. Load or generate the persistent identity using
   [`storage::IdentityKeyStore`].
2. Create an [`machine::Engine`] with the transport role, identity, and an
   `Entropy` source, then feed it [`machine::Input::Start`]. The dialing side
   is the initiator.
3. Execute each returned effect in order. Write frames, arm or cancel
   deadlines, deliver messages, and surface notifications as directed by
   the engine.
4. When the engine returns `Effect::RequestSas`, display the three SAS words
   and the peer's fingerprint. Only provide `Input::SasDecision(true)` after
   both people have compared the words over an independent channel.
   This verification is required on **every connection**; the protocol does
   not remember previously approved peers.
5. Feed received frames through `Input::FrameReceived`, expired deadlines
   through `Input::Timeout`, and transport loss through
   `Input::TransportClosed`. After a `CloseTransport` effect, the engine
   ignores further input.
6. Rekeying does not require another SAS comparison, but the peer identities
   must remain consistent with the active session. When the connection ends,
   the session and its keys are destroyed.

The [architecture guide](../../../docs/architecture.md) explains component
ownership and the driver contract. The [security model](../../../SECURITY.md)
describes the security assumptions and what callers must and must not persist
or display.

## Important boundaries

- **Persistence:** The storage abstraction holds the identity seed only.
  Do not use it to persist session keys, ratchet state, peer identities,
  trust state, or message history.
- **Volatility:** Session keys, ephemeral private keys, chain keys, replay
  windows, skipped message keys, and counters are memory-only and bound to
  the connection.
- **Trust:** Receiving a public key does not establish trust. SAS verification
  is required to authenticate a first-contact peer, and it must be repeated
  for every connection.
- **Display:** Application data received from a peer is untrusted. Sanitize
  it before rendering it in a terminal.
- **Drivers:** A driver must process effects in order, must not treat a
  partially written frame as though it were never sent, and must bound every
  queue it introduces. `ruxmsg-net` is the reference driver.

## Status

Independent interoperability testing and security review have not been
completed. Tests of the underlying cryptographic primitives do not establish
that the complete protocol is secure.

**Do not treat `ruxmsg-core` as production-secure until it has undergone
independent security review.**

See the [conformance matrix](../../../docs/conformance-matrix.md) for
implementation and test status.
"#]

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
