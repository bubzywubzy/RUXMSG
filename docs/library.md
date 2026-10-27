# RUXMSG library

This crate is the conformance foundation for RUXMSG/1, a volatile two-party end-to-end encrypted messaging protocol. It provides typed protocol constants, deterministic handshake transcript encoding, Ed25519 signatures, X25519 agreement, transcript hashing, SAS rendering, HKDF key derivation, confirmation MACs, directional ratchets, message nonces, ChaCha20-Poly1305 helpers, strict frame handling, authenticated padded DATA, bounded replay and skipped-key state, session lifecycle and rekey primitives, and in-memory and framed transport abstractions.

## Recommended entry points

- [`connection::PeerConnection`](../src/connection.rs) is the high-level synchronous facade for one transport. For TCP, `split_tcp()` yields independent reader and writer halves.
- [`engine`](../src/engine.rs) establishes an authenticated session over any [`transport::Transport`](../src/transport.rs).
- [`manager::SessionManager`](../src/manager.rs) owns the active session and any draining predecessor.
- [`transport::InMemoryTransport`](../src/transport.rs) gives deterministic two-peer tests.
- [`transport::FramedTransport`](../src/transport.rs) adapts a readable/writable stream to the frame layer.
- [`storage`](../src/storage.rs) persists exactly one thing: the local identity seed.

## Typical lifecycle

1. Load or generate the persistent identity (`storage::IdentityKeyStore`).
2. Establish a fresh session over a connection with `engine` or `PeerConnection`, supplying a SAS-approval callback.
3. Present the three-word SAS and the peer fingerprint to the user; return `true` only after both people have compared them over an independent channel. This happens on **every** connection; the library remembers nothing.
4. Send and receive application bytes through the facade.
5. Rekey when the session policy requires it. Rekey does not use SAS; it must present the same identities as the active session.
6. Close, or lose the connection. The session and all its keys are destroyed; a new connection is a new handshake.

The [architecture guide](architecture.md) explains ownership and data flow. The [security model](security-model.md) explains what callers must and must not persist or display.

## Important boundaries

- **Persistence.** The storage traits hold the identity seed only. They must not be used for session keys, ratchet state, peer identities, trust state or history.
- **Volatility.** Session keys, ephemeral private keys, chains, replay windows, skipped keys and counters are memory-only and connection-bound.
- **Trust.** Receiving a public key confers no trust. The SAS callback is the only authentication of a first-contact peer, and it is required each time.
- **Display.** Application bytes from a peer are untrusted; sanitize control characters before rendering them to a terminal.
- **Threads.** Only one method that mutates session state may run at a time on a `PeerConnection`. Use the split TCP API for concurrent reading and writing.

## Status

The crate contains a synchronous two-peer handshake engine and session, rekey and drain primitives. Some RUXMSG/1 specification 1.1 requirements are not yet implemented, including the handshake commitment, rekey identity continuity, per-type limits and timeouts, and key zeroization on all chain state. See the [conformance matrix](conformance-matrix.md). Independent interoperability and security review have not been done, so do not treat the crate as production-secure because its individual primitives have tests.
