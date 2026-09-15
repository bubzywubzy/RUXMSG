# RUXMSG library

This crate is the Phase 5 conformance foundation for RUXMSG/1. It provides typed protocol constants, deterministic handshake transcript encoding, Ed25519 signatures, X25519 ephemeral agreement, transcript hashing, SAS rendering, HKDF key derivation, confirmation MACs, directional ratchet derivation, message nonces, ChaCha20-Poly1305 helpers, strict outer-frame handling, authenticated DATA payloads with padding, bounded replay/skipped-key state, lifecycle transitions, and in-memory/framed transport abstractions.

## Recommended entry points

- [`connection::PeerConnection`](../src/connection.rs) is the high-level synchronous connection facade.
- [`engine`](../src/engine.rs) establishes an authenticated session over any [`transport::Transport`](../src/transport.rs).
- [`manager::SessionManager`](../src/manager.rs) owns active and draining session state.
- [`transport::InMemoryTransport`](../src/transport.rs) is useful for deterministic tests.
- [`transport::FramedTransport`](../src/transport.rs) adapts a readable/writable stream to the wire framing layer.
- [`storage`](../src/storage.rs) defines the persistence boundary for identity and trust records.

## Typical lifecycle

1. Load or generate the persistent identity.
2. Establish a fresh session with `engine` or `PeerConnection`.
3. Compare the SAS through an independent channel on first contact.
4. Send and receive application bytes through the connection facade.
5. Rekey and drain the predecessor when the session policy requires it.
6. Close the connection and destroy in-memory session state.

The [architecture guide](architecture.md) explains ownership and data flow. The [security model](security-model.md) explains what callers may persist or expose.

## Important boundaries

Session keys, ephemeral private keys, ratchet state, replay windows, and skipped keys are in-memory state. The storage traits are for persistent identity and trust records; they must not be used to persist active session state.

The crate includes a synchronous two-peer handshake engine and rekey/session primitives. The CLI is currently a one-connection TCP client. Independent interoperability, production transport integration, complete trusted-peer reuse, a multi-peer client, and independent security review remain incomplete. Do not treat the crate as production-secure messaging software solely because its individual primitives have tests.
