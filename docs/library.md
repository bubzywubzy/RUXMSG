# RUXMSG Library

RUXMSG is a Rust implementation of the RUXMSG/1 protocol and its supporting session machinery. The crate provides the protocol's wire representation, authenticated handshake, cryptographic session establishment, encrypted DATA handling, ratcheting, replay protection, session lifecycle management, and synchronous transport abstractions.

The library is designed around explicit security boundaries: the protocol implementation owns active cryptographic state in memory, while persistent local identity material is handled through the storage abstraction. Application code is responsible for deciding how higher-level contacts, conversations, and application data should be managed.

## Recommended entry points

* [`connection::PeerConnection`](../src/connection.rs) — high-level synchronous connection facade for establishing sessions, sending and receiving application bytes, rekeying, and closing connections.

* [`engine`](../src/engine.rs) — synchronous handshake engine that establishes an authenticated session over a transport.

* [`manager::SessionManager`](../src/manager.rs) — manages active session state and the transition between current and draining sessions during rekey.

* [`transport::Transport`](../src/transport.rs) — transport abstraction used by the handshake and connection layers.

* [`transport::InMemoryTransport`](../src/transport.rs) — deterministic in-memory transport useful for tests and protocol exercises.

* [`transport::FramedTransport`](../src/transport.rs) — adapts a `Read + Write` stream to the RUXMSG outer framing layer.

* [`storage`](../src/storage.rs) — persistence boundary for the local Ed25519 identity and its credential-store integration.

The storage layer does **not** currently implement persistent trusted-peer records or persistent SAS approvals.

## Protocol lifecycle

A typical library-level session follows this sequence:

1. Load the local persistent Ed25519 identity, or generate it when no identity exists.
2. Establish a fresh session using the handshake engine or [`PeerConnection`].
3. Perform SAS verification for the newly established authenticated session.
4. Exchange application bytes through the connection facade.
5. Derive and activate new session state when rekeying is required.
6. Drain the predecessor session according to the session lifecycle rules.
7. Close the connection and release active session state.

A process restart does not restore active cryptographic sessions. Session keys, ephemeral private keys, ratchet state, replay windows, skipped-key state, and related session state remain in memory only. A new process therefore establishes a fresh cryptographic session.

See [`docs/architecture.md`](architecture.md) for ownership and data flow.

## Cryptographic and protocol components

The crate contains the implementation components required by RUXMSG/1, including:

* typed protocol versions and message types;
* strict outer-frame encoding and decoding;
* canonical CBOR protocol encoding;
* deterministic handshake transcript construction;
* Ed25519 identity signatures;
* fresh X25519 ephemeral key agreement;
* transcript hashing;
* human-readable short authentication string (SAS) rendering;
* HKDF-SHA-256 session-key derivation;
* session confirmation MACs;
* directional ratchet and message-key derivation;
* deterministic message nonce construction;
* ChaCha20-Poly1305 authenticated encryption;
* authenticated DATA payload construction and validation;
* deterministic DATA padding;
* bounded replay-window state;
* bounded skipped-key state;
* session lifecycle transitions;
* candidate-session rekeying and predecessor draining;
* in-memory and framed stream transports.

These components are composed by the higher-level connection and session layers rather than exposed as an independent claim of security when considered in isolation.

## Persistence boundary

Persistent and ephemeral state are deliberately separated.

### Persistent

The current implementation persists the local Ed25519 identity through the storage/credential-store abstraction.

### In memory

The following remain process-local:

* ephemeral X25519 private keys;
* established session keys;
* directional ratchet state;
* message keys;
* counters;
* replay windows;
* skipped message keys;
* active session state;
* draining predecessor sessions.

The current implementation does **not** persist:

* trusted-peer records;
* SAS approval state;
* active sessions;
* ratchet state;
* message keys;
* conversation history.

Consequently, callers must not assume that a previously verified peer automatically bypasses SAS verification after a restart.

## Transport model

The protocol does not require a particular network provider.

The transport layer separates protocol logic from byte-stream delivery. `InMemoryTransport` supports deterministic local testing, while `FramedTransport<S>` can adapt a synchronous readable/writable stream such as a TCP connection.

The transport provides connectivity; it does not establish cryptographic identity or trust.

For example, TCP or an overlay such as Tailscale may provide reachability between peers, while RUXMSG performs its own authenticated handshake and session establishment above that transport.

## Connection model

[`PeerConnection<T>`](../src/connection.rs) is the primary synchronous facade for applications that want to work with an established peer connection without directly managing the lower-level handshake, session manager, ratchet, and framing components.

The connection layer handles operations including:

* session establishment;
* application DATA transmission;
* authenticated DATA reception;
* session inspection;
* rekeying;
* predecessor draining;
* connection closure.

For TCP use cases, the library also provides a split reader/rekey and writer/close interface so application code can separate inbound and outbound processing while retaining the session-management boundaries defined by the connection layer.

## Verification and testing

The repository contains deterministic conformance vectors and integration tests covering major protocol and session behaviors.

Relevant areas include:

* handshake establishment;
* transcript and cryptographic vectors;
* SAS behavior;
* DATA encryption/decryption;
* replay and out-of-order handling;
* skipped-key limits;
* session lifecycle;
* rekey and predecessor draining;
* framing and transport behavior;
* TCP split behavior;
* restart and persistent identity behavior.

The implementation also has fuzzing infrastructure for protocol parsers and stateful components.

Passing these tests demonstrates that the tested implementation satisfies those test cases. It does not constitute an independent security audit, formal verification, or proof of interoperability with unrelated implementations.

See [`docs/conformance-matrix.md`](conformance-matrix.md) for the current implementation and verification status.

## Relationship to the CLI

The `ruxmsg` binary is a client built on top of this library.

The current CLI is a **line-oriented, multi-session REPL**. It can maintain multiple peer/session handles within one process, select peers by label, exchange messages, inspect sessions and fingerprints, and manage listener/outbound connection operations.

The CLI should not be treated as a separate protocol implementation. Protocol behavior belongs to the library and its underlying modules.

See [`docs/cli.md`](cli.md) for the current command set and terminal behavior.

## Current scope

The library currently provides the core synchronous protocol and session implementation. The following are outside the current implemented scope or remain incomplete:

* persistent trusted-peer records;
* persistent SAS approvals and automatic trust reuse;
* persistent conversation/message history;
* offline message delivery;
* independent third-party interoperability;
* production deployment hardening beyond the currently tested implementation;
* independent security audit.

These limitations are intentional boundaries of the current implementation and should not be hidden behind the existence of working cryptographic primitives or passing tests.

## Design principle

RUXMSG keeps security-sensitive state explicit.

The protocol layer is responsible for:

* defining and enforcing wire semantics;
* authenticating peers;
* deriving session keys;
* maintaining ratchet state;
* enforcing replay and skipped-key bounds;
* controlling session transitions.

Higher-level applications remain responsible for:

* presenting and interpreting user-facing trust decisions;
* deciding how application data is stored;
* managing contacts and conversations;
* determining how long application-level information should persist.

This separation prevents application persistence and UI behavior from being mistaken for protocol-level security state.
