# RUXMSG

**Terminal-native peer-to-peer encrypted messaging in Rust.**

RUXMSG is a Rust protocol library and terminal client for peer-to-peer encrypted messaging. It establishes authenticated sessions directly between peers without requiring a central server.

The protocol treats the underlying network as untrusted. TCP provides transport and reachability; cryptographic identity and session security are provided by RUXMSG itself.

## Current status

RUXMSG is an **experimental protocol implementation**, not a production-ready messenger.

The current implementation provides:

* Persistent local **Ed25519 identities**;
* Profile-scoped identity management in the terminal client;
* Ephemeral **X25519** session establishment;
* Transcript-bound Ed25519 authentication;
* Short Authentication String (**SAS**) verification during first contact;
* Session-confirmation MACs;
* **HKDF-SHA-256** session and directional key derivation;
* **ChaCha20-Poly1305** authenticated message encryption;
* Deterministic message padding;
* Replay protection;
* Bounded out-of-order delivery;
* Skipped-key limits;
* Session lifecycle management;
* Rekey and drain primitives;
* Generic transport abstractions;
* In-memory transports for testing;
* Length-delimited framed transports over `Read + Write`;
* TCP listener and connector support;
* A line-oriented **multi-session terminal REPL**;
* Deterministic integration and conformance tests;
* Fuzzing infrastructure.

The current implementation **does not** provide:

* Persistent trusted-peer records;
* Persistent SAS approvals or automatic SAS bypass;
* Message history or persistent conversations;
* A central server or directory;
* An anonymity or metadata-protection layer;
* Independent interoperability implementations;
* An independent cryptographic/security audit.

The CLI currently performs SAS verification for each newly established connection. A peer being verified during one connection does not automatically become a persisted trusted peer.

## How it works

RUXMSG separates network reachability from cryptographic identity.

| Layer          | Mechanism                                 | Purpose                                        |
| -------------- | ----------------------------------------- | ---------------------------------------------- |
| Transport      | TCP or another `Transport` implementation | Move bytes between peers                       |
| Identity       | Ed25519                                   | Authenticate a persistent peer identity        |
| Handshake      | X25519 + transcript authentication        | Establish a fresh session                      |
| Key derivation | HKDF-SHA-256                              | Derive session and directional keys            |
| Authentication | SAS + transcript signatures               | Detect peer impersonation during first contact |
| Messages       | ChaCha20-Poly1305                         | Authenticate and encrypt DATA                  |
| Ratchet        | Session key evolution                     | Limit reuse of individual message keys         |
| Framing        | Versioned length-delimited frames         | Bound and validate wire messages               |

The network itself is not treated as an identity system.

For example, **Tailscale can provide reachability**, but a Tailscale identity is not used as the cryptographic identity of an RUXMSG peer.

## First contact

A connection performs a cryptographic handshake before application DATA is accepted.

At a high level:

1. The peers exchange handshake information.
2. Each side creates an ephemeral X25519 key.
3. The handshake transcript is constructed.
4. The transcript is hashed.
5. Each peer authenticates the transcript using its persistent Ed25519 identity.
6. Both sides derive fresh session material with HKDF-SHA-256.
7. The peers derive and display a short authentication string.
8. The users compare the SAS through an independent channel.
9. Session confirmation completes the handshake.
10. Encrypted DATA can then be exchanged.

The SAS is important because possession of a persistent Ed25519 identity alone does not give a user a safe way to know that they are communicating with the intended human on first contact.

If the independently compared SAS values do not match, the connection should be aborted.

## Terminal client

The `ruxmsg` binary is currently a **line-oriented multi-session REPL**.

Start it with:

```text
ruxmsg
```

A persistent identity profile can be selected with:

```text
ruxmsg --profile alice
```

Inside the REPL, the current command set includes:

```text
profile init <name>
profile use <name>
profile list

start [--addr <addr>]
stop
connect <addr>

peers
use <label>
msg <label> <text>
close <label>

fingerprint [label]
session <label>

tailscale status
tailscale up
tailscale ip

help
quit
```

The client can maintain multiple active peer sessions rather than operating as a single one-shot connection.

For example, a typical local test can use two terminal processes:

**Terminal A**

```text
ruxmsg --profile alice
```

Then:

```text
profile init alice
start --addr 127.0.0.1:4443
```

**Terminal B**

```text
ruxmsg --profile bob
```

Then:

```text
profile init bob
connect 127.0.0.1:4443
```

The exact interactive flow and available commands are documented in the [CLI guide](docs/cli.md).

## Identity persistence

RUXMSG persists the **local Ed25519 identity seed** through an operating-system credential store abstraction.

The application does not use a plaintext identity file as its normal persistence mechanism.

The underlying credential-store implementation is provided through the Rust `keyring` ecosystem, allowing the platform's native credential infrastructure to be used where supported.

Current identity persistence is intentionally separate from session state.

The following are **not** persisted by the current implementation:

* Active sessions;
* Ephemeral X25519 keys;
* Ratchet state;
* Message keys;
* Peer session state;
* SAS approval state;
* Trusted-peer records;
* Message history.

Restarting RUXMSG therefore creates new sessions rather than restoring previous cryptographic session state.

## Protocol and wire format

RUXMSG uses a versioned binary frame format.

A frame consists of:

```text
+---------+---------+----------------+-------------------+
| Version |  Type   | Payload Length |      Payload      |
+---------+---------+----------------+-------------------+
| 1 byte  | 1 byte  |    4 bytes     | N bytes           |
+---------+---------+----------------+-------------------+
```

Payloads use canonical CBOR encoding.

The implementation performs strict frame-length and encoding validation rather than treating the network as a trusted byte stream.

Cryptographic authentication data is bound to the protocol's defined transcript and associated-data encoding.

The normative protocol behavior is defined in the [protocol specification](docs/protocol-spec.md).

## Security properties

The current protocol is designed to provide:

### Peer authentication

Persistent Ed25519 identities authenticate the handshake transcript.

### Forward secrecy for sessions

Session establishment uses fresh ephemeral X25519 key material rather than directly using the long-term identity key as a session key.

### Authenticated encryption

Application DATA is protected with ChaCha20-Poly1305.

### Key separation

HKDF-SHA-256 derives separate session and directional cryptographic material rather than reusing a single undifferentiated key.

### Replay protection

The session layer tracks message/key state so previously accepted DATA cannot simply be replayed as new messages.

### Reordering tolerance

The ratchet permits bounded out-of-order message processing while limiting the amount of skipped key material retained.

### Transcript authentication

The handshake authenticates the negotiated session context rather than authenticating an isolated public key exchange.

These properties describe the intended and implemented protocol behavior. They should not be interpreted as a claim that the implementation has received an independent security audit.

## Security boundary

RUXMSG does **not** attempt to solve every security problem surrounding messaging.

In particular, it does not currently provide:

* Anonymity;
* Traffic-analysis resistance;
* Metadata confidentiality;
* Protection against endpoint compromise;
* Protection against a malicious or compromised operating system;
* Secure deletion guarantees;
* A trusted directory or global identity authority;
* Automatic proof that a displayed identity belongs to a particular human;
* Protection against users incorrectly accepting a mismatched SAS.

The complete threat model and operational assumptions are documented in the [security model](docs/security-model.md).

## Transport architecture

The protocol is separated from the underlying byte transport.

The core transport abstraction allows protocol code to operate over different implementations rather than directly depending on TCP.

Current transport components include:

* `InMemoryTransport` for deterministic testing;
* `FramedTransport<S>` for `Read + Write` streams;
* `Demuxer<T>` for routing framed traffic;
* TCP client/listener support in the terminal application.

This separation is intentional: the protocol should not need to know whether bytes arrived through TCP, an in-memory test transport, or another future transport implementation.

Tailscale is therefore optional. It can be used to make peers reachable without exposing RUXMSG directly to the public Internet, but it does not replace RUXMSG authentication.

## Platform support

The core Rust library is designed around cross-platform Rust APIs rather than platform-specific networking primitives.

The intended platform model is:

| Component                   | Linux     | macOS         | Windows       |
| --------------------------- | --------- | ------------- | ------------- |
| Core protocol library       | Supported | Supported     | Supported     |
| TCP transport               | Supported | Supported     | Supported     |
| In-memory transport         | Supported | Supported     | Supported     |
| Identity credential storage | Supported | Supported     | Supported     |
| Terminal client             | Supported | Supported     | Supported     |
| Tailscale integration       | Optional  | Optional      | Optional      |
| Automated CI validation     | Yes       | Not currently | Not currently |

The repository currently publishes automated CI validation on Linux. macOS and Windows support is based on the cross-platform Rust implementation and dependencies, but those platforms are not currently exercised by the repository's CI matrix.

Tailscale is an external optional dependency. RUXMSG itself does not require Tailscale.

## Repository layout

```text
src/
├── bin/ruxmsg.rs       Terminal REPL
├── close.rs            Session close/drain behavior
├── connection.rs       Connection/session coordination
├── crypto.rs           Cryptographic primitives and helpers
├── data.rs             DATA message handling
├── encoding.rs         Encoding helpers
├── engine.rs           Handshake engine
├── error.rs            Error types
├── handshake.rs        Handshake structures and processing
├── identity.rs         Local and peer identity types
├── manager.rs          Session management
├── protocol.rs         Protocol-level definitions
├── ratchet.rs          Message-key evolution
├── session.rs          Session state and lifecycle
├── storage.rs          Persistent identity storage boundary
├── transport.rs        Transport abstractions
└── wire.rs             Frame encoding/decoding

tests/
├── conformance.rs
├── connection.rs
├── handshake.rs
├── rekey.rs
├── restart.rs
├── tcp_split.rs
└── transport.rs
```

The repository also contains fuzzing infrastructure for exercising protocol and parsing boundaries.

## Documentation

The documentation is divided by purpose:

* [Protocol specification](docs/protocol-spec.md) — normative protocol, wire-format, encoding, and security requirements.
* [Protocol reference](docs/protocol-reference.md) — implementation-oriented field and encoding reference.
* [Conformance matrix](docs/conformance-matrix.md) — implementation and test status.
* [Architecture guide](docs/architecture.md) — non-normative explanation of the implementation structure and data flow.
* [Security model](docs/security-model.md) — threat model, security boundaries, and operational assumptions.
* [CLI guide](docs/cli.md) — terminal client, profiles, sessions, and usage.
* [Library guide](docs/library.md) — library API and integration information.
* [Contributor guide](docs/contributing.md) — development, testing, fuzzing, and protocol-change workflow.
* [Protocol decisions](docs/decisions.md) — recorded protocol decisions and their rationale.

## Building

RUXMSG is a Cargo project.

Build it with:

```bash
cargo build
```

For an optimized build:

```bash
cargo build --release
```

Run the terminal client with:

```bash
cargo run --bin ruxmsg
```

Or, after installation/building:

```bash
ruxmsg
```

The repository's declared minimum Rust version is **1.88**.

## Testing

The project uses Rust's standard testing and verification tooling.

Run the complete test suite with:

```bash
cargo test
```

Format the repository with:

```bash
cargo fmt --check
```

Run Clippy with:

```bash
cargo clippy --all-targets --all-features -- -D warnings
```

Generate API documentation with:

```bash
cargo doc --no-deps
```

The integration tests cover areas including:

* Handshake behavior;
* Connection behavior;
* Transport framing;
* TCP stream splitting;
* Session restart behavior;
* Rekey/session lifecycle behavior;
* Protocol conformance.

Fuzzing infrastructure is also included for testing parsing and protocol boundaries.

## Development status

RUXMSG is intentionally being developed from the protocol and security boundaries outward rather than starting as a feature-complete messaging application.

Current work is concentrated around the protocol implementation, session machinery, persistence boundaries, deterministic testing, and the terminal client.

Planned or incomplete areas include:

* Trusted-peer persistence;
* Persistent SAS approval and trusted-peer reuse;
* Broader transport implementations;
* Independent interoperability testing;
* More extensive cross-platform CI;
* Production hardening;
* Independent security review;
* Persistent conversations/message history;
* A more complete user-facing messaging client.

Until these areas are addressed, RUXMSG should be treated as an **experimental encrypted messaging protocol implementation**, not as a drop-in replacement for an audited production messenger.

## Design principle

RUXMSG deliberately keeps the cryptographic protocol, transport, persistence, and terminal interface as separate boundaries.

The goal is not to hide the protocol behind a large application framework. The goal is to make the security-critical behavior explicit, testable, and inspectable.

The normative protocol specification is the authority for protocol behavior. The implementation, tests, and supporting documentation should remain consistent with that specification.

## License

See the repository's license file for the applicable license terms.