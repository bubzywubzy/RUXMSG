# RUXMSG

Terminal-native peer-to-peer encrypted messaging

RUXMSG is a Rust protocol library and terminal client for communication between explicitly trusted peers. It does not require a central server and treats the underlying network—TCP, Tailscale, or another reachable transport—as hostile.

## What exists today

The repository is not a finished production messenger. It currently provides:

- Ed25519 persistent identities;
- X25519 ephemeral session establishment;
- transcript-bound signatures, SAS verification, and confirmation MACs;
- HKDF-SHA-256 session and directional key derivation;
- ChaCha20-Poly1305 authenticated DATA with deterministic padding;
- replay protection, bounded reordering, and skipped-key limits;
- session lifecycle and rekey/drain primitives;
- in-memory and framed transport abstractions;
- a synchronous two-peer handshake engine;
- a small one-connection TCP terminal client;
- deterministic integration tests and fuzzing infrastructure.

Rekey integration, trusted-peer reuse in the CLI, independent interoperability, production transport integration, independent security review, and a complete multi-peer client remain unfinished or unverified.

## Quick start

Build the project with Cargo, then run one peer as a listener and another as a connector:

```text
ruxmsg --profile alice listen --addr 127.0.0.1:4443
ruxmsg --profile bob connect 127.0.0.1:4443
```

On first contact, compare the displayed three-word SAS through an independent channel. Abort if it does not match. See the [CLI guide](docs/cli.md) for profiles, credential storage, and troubleshooting.

## Security boundary

RUXMSG separates reachability from identity:

| Layer | Responsibility |
| --- | --- |
| Network | TCP/Tailscale provides reachability only |
| Identity | Ed25519 identifies the persistent peer |
| Session | X25519 and HKDF establish fresh session keys |
| Messages | Ratchets and ChaCha20-Poly1305 protect DATA |

RUXMSG does not provide anonymity, metadata confidentiality, deniability, or protection from a compromised endpoint. The complete threat model is in the [security guide](docs/security-model.md).

## Documentation

The documents have distinct authority and audiences:

- [Protocol specification](docs/protocol-spec.md) — authoritative normative wire and security contract.
- [Protocol reference](docs/protocol-reference.md) — implementation-facing field and encoding index.
- [Conformance matrix](docs/conformance-matrix.md) — implementation, test, and readiness status.
- [Architecture guide](docs/architecture.md) — non-normative module and data-flow explanation.
- [Security model](docs/security-model.md) — threat model and operational guidance.
- [CLI guide](docs/cli.md) — installation, profiles, first contact, and current limitations.
- [Library guide](docs/library.md) — crate-level API documentation.
- [Contributor guide](docs/contributing.md) — development, testing, fuzzing, and protocol-change workflow.
- [Protocol decisions](docs/decisions.md) — recorded wire-level decisions and rationale.

## Building and testing

The standard Rust checks are formatting, compilation, unit/integration tests, Clippy, and generated API documentation. See [Contributing](docs/contributing.md) for the complete workflow and [Conformance](docs/conformance-matrix.md) for the evidence behind each implementation claim.

Before claiming interoperability, an implementation must satisfy the deterministic vectors and rejection rules in the normative specification, especially SAS bit boundaries, canonical CBOR, exact AAD encoding, and padding overhead. RUXMSG is not production-secure until it receives independent security review.
