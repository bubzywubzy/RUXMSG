# RUXMSG/1 conformance matrix

This matrix connects the normative requirements to implementation and tests. It is a status document, not a second specification. The [protocol specification](../protocol-spec.md) controls when wording differs.

Status meanings:

- **Implemented and tested** — code exists and repository tests exercise the behavior.
- **Implemented, integration incomplete** — primitives exist, but the complete product workflow is incomplete.
- **Infrastructure only** — targets or abstractions exist without a recorded complete validation result.
- **Planned** — not yet implemented or not yet suitable for interoperability claims.

| Area | Implementation | Evidence | Status |
| --- | --- | --- | --- |
| Version, message registry, frame length limits | `src/protocol.rs`, `src/wire.rs` | `tests/transport.rs`, module tests | Implemented and tested |
| Outer framing and truncation handling | `src/wire.rs`, `src/transport.rs` | `tests/transport.rs` | Implemented and tested |
| Deterministic transcript encoding | `src/encoding.rs`, `src/handshake.rs` | `tests/conformance.rs`, `tests/handshake.rs` | Implemented and tested |
| Ed25519 identity signatures | `src/crypto.rs`, `src/handshake.rs` | `tests/handshake.rs`, crypto tests | Implemented and tested |
| X25519 ephemeral agreement and all-zero rejection | `src/crypto.rs` | crypto and handshake tests | Implemented and tested |
| SAS word derivation | `src/crypto.rs` | `tests/conformance.rs` | Implemented and tested |
| HKDF session and directional keys | `src/crypto.rs` | `tests/handshake.rs`, crypto tests | Implemented and tested |
| Session confirmation | `src/crypto.rs`, `src/handshake.rs`, `src/engine.rs` | `tests/handshake.rs` | Implemented and tested |
| Authenticated DATA and canonical padding | `src/data.rs`, `src/crypto.rs` | `tests/conformance.rs`, data tests | Implemented and tested |
| Replay window and skipped-key bounds | `src/ratchet.rs`, `src/data.rs` | ratchet/data tests | Implemented and tested |
| Session lifecycle | `src/session.rs`, `src/manager.rs` | `tests/rekey.rs`, restart tests | Implemented and tested |
| Rekey candidate and drain behavior | `src/connection.rs`, `src/manager.rs` | `tests/connection.rs`, `tests/rekey.rs` | Implemented and tested |
| In-memory transport | `src/transport.rs` | handshake and integration tests | Implemented and tested |
| Framed stream transport | `src/transport.rs` | `tests/transport.rs`, `tests/tcp_split.rs` | Implemented and tested |
| Split TCP reader/writer concurrency | `src/connection.rs` | `tests/tcp_split.rs` | Implemented and tested |
| Identity and sealed trust persistence | `src/storage.rs` | `tests/restart.rs`, `tests/conformance.rs` | Implemented and tested |
| Trusted-peer reuse in the CLI | `src/bin/ruxmsg.rs` | `src/bin/ruxmsg.rs`, `tests/restart.rs` | Implemented and tested |
| Process restart with fresh session | `src/session.rs`, storage modules | `tests/restart.rs`, `tests/conformance.rs` | Implemented and tested |
| Fuzzing targets | `fuzz/fuzz_targets/` | committed corpus and targets | Infrastructure only |
| Independent implementation interoperability | external to repository | none recorded | Planned |
| Independent security review | external to repository | none recorded | Planned |
| Complete multi-peer production CLI | `src/bin/ruxmsg.rs` | current one-connection client | Planned |

## Test evidence notes

The deterministic vectors in `tests/conformance.rs` are especially important for transcript domain separation, SAS bit boundaries, and nonce byte order. Handshake tests use two peers and verify both perspectives derive the same transcript and session identifier. Rekey tests verify that an old session becomes receive-only during the drain interval and that a new session becomes active.

Fuzz targets are valuable defensive infrastructure, but the presence of a target or corpus directory is not a claim that a particular fuzzing duration, coverage level, or security result has been achieved.

## Review rule

A row should only be promoted to “production-ready” after complete integration coverage, interoperability evidence where applicable, and independent security review. This repository currently makes no such general production-readiness claim.
