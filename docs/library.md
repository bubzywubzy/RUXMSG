# RUXMSG library

`ruxmsg-core` is the protocol core for RUXMSG/1, a volatile two-party end-to-end encrypted messaging protocol. It contains no I/O: typed protocol constants, strict frame handling, deterministic handshake transcript encoding, Ed25519 signatures, X25519 agreement, SAS rendering, HKDF key derivation, confirmation MACs, directional ratchets, authenticated padded DATA, bounded replay and skipped-key state, and the sans-IO [`machine::Engine`] that ties them together.

## Recommended entry points

- [`machine::Engine`] consumes an [`machine::Input`] and returns ordered [`machine::Effect`]s. It has no clock, socket, thread, runtime or callback; deadlines are effects and expiry is an input.
- `ruxmsg-net` drives an `Engine` over any Tokio byte stream, owns the timers, queues and listener, and is what the client uses.
- [`storage`] persists exactly one thing: the local identity seed, through a `SecretStore` you provide. The client's keyring adapter lives in `ruxmsg-cli`.
- [`display::sanitize_for_display`] neutralizes control and bidirectional characters in peer text.

## Typical lifecycle

1. Load or generate the persistent identity (`storage::IdentityKeyStore`).
2. Create an `Engine` with the transport role (the dialing side is the initiator), the identity and an `Entropy` source, then feed it `Input::Start`.
3. Execute each returned `Effect` in order: write frames, arm and cancel deadlines, deliver messages, and surface notifications.
4. On `Effect::RequestSas`, show the three words and the peer fingerprint, and answer with `Input::SasDecision(true)` only after both people compared them over an independent channel. This happens on **every** connection; nothing is remembered.
5. Feed received frames as `Input::FrameReceived`, expiry as `Input::Timeout`, and loss of the transport as `Input::TransportClosed`. After a `CloseTransport` effect the engine ignores all input.
6. A rekey needs no SAS; it must present the same identities as the active session. When the connection ends the session and its keys are destroyed.

The [architecture guide](architecture.md) explains ownership and the driver contract. The [security model](security-model.md) explains what callers must and must not persist or display.

## Important boundaries

- **Persistence.** The storage trait holds the identity seed only. It must not be used for session keys, ratchet state, peer identities, trust state or history.
- **Volatility.** Session keys, ephemeral private keys, chains, replay windows, skipped keys and counters are memory-only and connection-bound.
- **Trust.** Receiving a public key confers no trust. The SAS decision is the only authentication of a first-contact peer, and it is required each time.
- **Display.** Application bytes from a peer are untrusted; sanitize them before rendering to a terminal.
- **Drivers.** A driver must apply effects in order, must never treat a partially written frame as unsent, and must bound every queue it adds. `ruxmsg-net` is the reference driver.

## Status

Independent interoperability and security review have not been done, so do not treat the crate as production-secure because its primitives have tests. See the [conformance matrix](conformance-matrix.md).
