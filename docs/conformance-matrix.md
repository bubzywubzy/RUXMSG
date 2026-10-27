# RUXMSG/1 conformance matrix

This matrix connects normative requirements to implementation and tests. It is a status document, not a second specification. The [protocol specification](protocol-spec.md) (1.1 draft) controls where wording differs.

Status meanings:

- **Implemented and tested**: code exists and repository tests exercise it.
- **Implemented, gap**: code exists but does not fully meet spec 1.1; the gap is stated.
- **Planned**: required by spec 1.1, not yet implemented.
- **Infrastructure only**: targets or abstractions exist without a recorded validation result.
- **Unverified**: cannot be confirmed from the repository alone.
- **External**: needs work outside this repository.

## Wire and encoding

| Area | Implementation | Evidence | Status |
| --- | --- | --- | --- |
| Version, message registry, 1 MiB limit | `src/protocol.rs`, `src/wire.rs` | `tests/conformance.rs`, `tests/transport.rs` | Implemented and tested |
| Per-type payload limits (spec §4.3) | none | none | Planned |
| Outer framing, truncation | `src/wire.rs`, `src/transport.rs` | `tests/transport.rs`, `tests/conformance.rs` | Implemented and tested |
| Strict deterministic CBOR (duplicate, unknown, unsorted, trailing) | `src/wire.rs` | `tests/conformance.rs` | Implemented and tested |
| `cipher_suite` must equal 1 in HELLO and AUTH | `src/handshake.rs` | none | Implemented, gap: value is not checked |
| Reserved message types rejected | `src/protocol.rs` | `tests/conformance.rs` | Implemented and tested |

## Handshake and authentication

| Area | Implementation | Evidence | Status |
| --- | --- | --- | --- |
| COMMIT before HELLO (D-012) | none | none | Planned |
| Symmetric HELLO and transcript from both HELLOs | `src/handshake.rs`, `src/encoding.rs` | `tests/conformance.rs`, `tests/handshake.rs` | Implemented and tested |
| AUTH fields checked against locally built transcript | `src/engine.rs`, `src/handshake.rs` | none | Implemented, gap: AUTH contents are hashed, not compared |
| Ed25519 identity signatures | `src/crypto.rs`, `src/handshake.rs` | `tests/conformance.rs`, crypto tests | Implemented and tested |
| Strict Ed25519 verification | `src/crypto.rs` | none | Implemented, gap: non-strict `verify` |
| X25519 agreement, all-zero rejection | `src/crypto.rs` | `tests/conformance.rs` | Implemented and tested |
| SAS derivation and bit boundaries | `src/crypto.rs` | `tests/conformance.rs` | Implemented and tested |
| SAS dictionary hash | `bip39` crate | `tests/conformance.rs` | Implemented and tested |
| SAS required on every initial handshake | `src/engine.rs` | `tests/conformance.rs` | Implemented and tested |
| Typed SAS approval (`yes` + Enter), fingerprint display, timeout | `src/bin/ruxmsg.rs` | none | Planned (single keypress today) |
| HKDF key schedule, session ID, confirmation | `src/crypto.rs`, `src/handshake.rs`, `src/engine.rs` | `tests/handshake.rs`, `tests/conformance.rs` | Implemented and tested |

## Messages

| Area | Implementation | Evidence | Status |
| --- | --- | --- | --- |
| DATA schema, AAD, nonce | `src/data.rs`, `src/crypto.rs` | `tests/conformance.rs` | Implemented and tested |
| Padding measured on ciphertext (D-014) | `src/data.rs` | `tests/conformance.rs` | Implemented and tested |
| Max content size (`MAX_CONTENT`, D-016) | none | none | Planned |
| Prepare/authenticate/commit receive path | `src/data.rs`, `src/ratchet.rs` | `tests/conformance.rs`, data tests | Implemented and tested |
| Replay window, skipped keys, key-cache bound | `src/ratchet.rs` | `tests/conformance.rs` | Implemented and tested (real ceiling is 128 keys, per spec §7.7) |
| Directional separation | `src/manager.rs`, `src/data.rs` | `tests/conformance.rs` | Implemented and tested |

## Sessions and rekey

| Area | Implementation | Evidence | Status |
| --- | --- | --- | --- |
| Lifecycle states and DATA permissions | `src/session.rs` | `tests/conformance.rs` | Implemented and tested |
| Session bound to one connection (D-013) | `src/bin/ruxmsg.rs` | none | Implemented, gap: behavior exists in the client but no test asserts it |
| Rekey candidate promotion and drain | `src/manager.rs`, `src/connection.rs` | `tests/rekey.rs`, `tests/connection.rs` | Implemented and tested |
| Rekey without SAS, identity continuity (D-015) | `src/connection.rs`, `src/manager.rs` | none | Planned (rekey currently prompts SAS and does not compare identities) |
| Failed rekey returns session to ACTIVE | `src/manager.rs` | none | Planned (session stays in REKEYING) |
| Peer-initiated rekey handled by reader loop | `src/connection.rs` | none | Planned |
| Automatic rekey trigger (24 h / 1,000,000) | `src/session.rs` | none | Implemented, gap: `rekey_due` is never called |
| Rekey glare tie-break on collision | `src/handshake.rs` | `tests/conformance.rs` | Implemented, gap: role fixed by key today, not resolved on collision |
| DATA buffered during rekey handshake | `src/transport.rs` | `tests/connection.rs` | Implemented and tested |

## Control frames and limits

| Area | Implementation | Evidence | Status |
| --- | --- | --- | --- |
| CLOSE schema and reasons | `src/close.rs` | `tests/conformance.rs` | Implemented and tested |
| CLOSE session-ID matching, unauthenticated labeling (D-017) | `src/connection.rs`, `src/bin/ruxmsg.rs` | none | Planned |
| Handshake timeouts, unauthenticated-handshake cap (D-016) | none | none | Planned |

## Volatile state and key hygiene

| Area | Implementation | Evidence | Status |
| --- | --- | --- | --- |
| Identity seed only persisted | `src/storage.rs` | storage tests (fake store) | Implemented and tested |
| Real OS credential store persists across restarts | `Cargo.toml`, `src/storage.rs` | none | Unverified: `keyring` features and backend not confirmed |
| No trust store, address book, history | whole crate | code review | Implemented |
| Fresh session after restart | `src/session.rs` | `tests/restart.rs` | Implemented and tested |
| Initial chain keys and root key not retained | `src/manager.rs` | none | Implemented, gap: `SessionKeys` kept in `ManagedSession` |
| Chain, message and cached keys zeroized | `src/data.rs`, `src/ratchet.rs` | none | Implemented, gap: not zeroized on drop |
| Terminal display sanitization of peer text | `src/bin/ruxmsg.rs` | none | Planned |

## Transport and client

| Area | Implementation | Evidence | Status |
| --- | --- | --- | --- |
| In-memory and framed transports | `src/transport.rs` | `tests/transport.rs` | Implemented and tested |
| Split TCP reader/writer | `src/connection.rs` | `tests/tcp_split.rs` | Implemented and tested |
| Multi-session REPL and chat view | `src/bin/ruxmsg.rs` | manual | Implemented (no automated tests) |
| Loopback/tailnet default bind | `src/bin/ruxmsg.rs` | none | Planned |
| Tailscale helper commands | `src/bin/ruxmsg.rs` | manual | Implemented (no automated tests) |

## Evidence quality

| Area | Status |
| --- | --- |
| Hex known-answer vectors (spec §12.1) | Planned: current tests assert properties, not fixed hex values |
| Fuzz targets (close, DATA decrypt, CBOR, frame, handshake, lifecycle) | Infrastructure only: `fuzz/corpus/` is git-ignored, so no corpus or run results are recorded |
| Independent implementation interoperability | External |
| Independent security review | External |

## Test evidence notes

`tests/conformance.rs` is important for SAS bit boundaries, transcript determinism, nonce byte order, padding and replay behavior, but most of it checks properties rather than published hex values. Handshake tests use two peers and check both derive the same transcript and session ID. Rekey tests check that an old session becomes receive-only during drain and that the new session becomes active.

Blocking two-peer tests must start the peer thread before the blocking handshake on the main thread.

## Review rule

A row is promoted to production-ready only after full integration coverage, interoperability evidence where applicable, and independent security review. The repository makes no general production-readiness claim.
