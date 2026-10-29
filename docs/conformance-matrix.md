# RUXMSG/1 conformance matrix

This matrix connects normative requirements to implementation and tests. It is a status document, not a second specification. The [protocol specification](protocol-spec.md) (1.1 draft) controls where wording differs.

Paths are relative to `crates/`. `core` is `ruxmsg-core`, `net` is `ruxmsg-net`, `cli` is `ruxmsg-cli`.

Status meanings:

- **Implemented and tested**: code exists and repository tests exercise it.
- **Implemented, gap**: code exists but is not fully covered or does not fully meet spec 1.1; the gap is stated.
- **Planned**: required by spec 1.1, not yet implemented.
- **Infrastructure only**: targets or abstractions exist without a recorded validation result.
- **Unverified**: cannot be confirmed from the repository alone.
- **External**: needs work outside this repository.

## Wire and encoding

| Area | Implementation | Evidence | Status |
| --- | --- | --- | --- |
| Version, message registry, 1 MiB limit | `core/src/protocol.rs`, `core/src/wire.rs` | `core/tests/conformance.rs`, `core/tests/limits.rs` | Implemented and tested |
| Per-type payload limits (§4.3), checked from the header | `core/src/protocol.rs`, `core/src/wire.rs`, `net/src/lib.rs` | `core/tests/limits.rs`, `net/tests/net.rs` | Implemented and tested |
| Outer framing, truncation, partial reads | `core/src/wire.rs`, `net/src/lib.rs` (`FrameDecoder`) | `core/tests/conformance.rs`, `net/tests/net.rs`, `fuzz/fuzz_targets/frame_stream.rs` | Implemented and tested; incremental decoder fuzz target added |
| Strict deterministic CBOR (duplicate, unknown, unsorted, trailing) | `core/src/wire.rs` | `core/tests/conformance.rs` | Implemented and tested |
| `cipher_suite` must equal 1 in COMMIT, HELLO and AUTH | `core/src/handshake.rs` | unit tests in `handshake.rs` | Implemented and tested |
| Reserved message types rejected | `core/src/protocol.rs` | `core/tests/conformance.rs` | Implemented and tested |
| Unsupported version closed without a protocol response | `net/src/lib.rs` | `net/tests/net.rs` | Implemented and tested |

## Handshake and authentication

| Area | Implementation | Evidence | Status |
| --- | --- | --- | --- |
| COMMIT before HELLO (D-012), ordering and forbidden transitions | `core/src/machine.rs` | `core/tests/engine.rs` | Implemented and tested |
| Reveal checked against the commitment in constant time | `core/src/machine.rs` | `core/tests/engine.rs` | Implemented and tested |
| HELLO rules: role, suite, purpose, previous session, own identity/ephemeral | `core/src/machine.rs` | `core/tests/engine.rs` | Implemented and tested |
| Symmetric HELLO and transcript from both HELLOs | `core/src/handshake.rs`, `core/src/encoding.rs` | `core/tests/conformance.rs` | Implemented and tested |
| AUTH fields checked against the locally built transcript; stage checks | `core/src/handshake.rs`, `core/src/machine.rs` | `core/tests/engine.rs` (replayed AUTH) | Implemented and tested |
| Reflected CONFIRM rejected (role checked) | `core/src/handshake.rs` | none | Implemented, gap: no test feeds a reflected confirmation |
| Ed25519 signatures, strict verification | `core/src/crypto.rs` | `core/tests/conformance.rs` | Implemented, gap: no test for a non-canonical signature or small-order key |
| X25519 agreement, all-zero rejection | `core/src/crypto.rs` | `core/tests/conformance.rs` | Implemented and tested |
| SAS derivation and bit boundaries | `core/src/crypto.rs` | `core/tests/conformance.rs` | Implemented and tested |
| SAS dictionary hash | `bip39` crate | `core/tests/conformance.rs` | Implemented and tested |
| SAS required on every initial handshake; rejection sends no signature | `core/src/machine.rs` | `core/tests/engine.rs`, `net/tests/net.rs` | Implemented and tested |
| Typed SAS approval (`yes` + Enter), fingerprint display, countdown | `cli/src/repl.rs`, `cli/src/tui.rs` | unit test of the approval rule; manual pty run | Implemented; input handling in the REPL and modal is not automated |
| Unknown REPL input is never sent as a message | `cli/src/commands.rs`, `cli/src/repl.rs` | `cli/src/commands.rs` unit tests | Implemented and tested |
| HKDF key schedule, session ID, confirmation | `core/src/crypto.rs`, `core/src/handshake.rs` | `core/tests/conformance.rs`, `core/tests/engine.rs` | Implemented and tested |

## Messages

| Area | Implementation | Evidence | Status |
| --- | --- | --- | --- |
| DATA schema, AAD, nonce | `core/src/data.rs`, `core/src/crypto.rs` | `core/tests/conformance.rs` | Implemented and tested |
| Padding measured on ciphertext (D-014) | `core/src/data.rs` | `core/tests/conformance.rs` | Implemented and tested |
| `MAX_CONTENT` (D-016), sender and receiver | `core/src/data.rs`, `core/src/machine.rs` | `core/tests/limits.rs`, unit tests in `core/src/data.rs` | Implemented and tested |
| Prepare/authenticate/commit receive path | `core/src/data.rs`, `core/src/ratchet.rs` | `core/tests/conformance.rs`, unit tests | Implemented and tested |
| Replay window, skipped keys, key-cache bound | `core/src/ratchet.rs` | `core/tests/conformance.rs`, `core/tests/engine.rs` | Implemented and tested (real ceiling is 128 keys, per spec §7.7) |
| Directional separation | `core/src/machine.rs`, `core/src/data.rs` | `core/tests/conformance.rs` | Implemented and tested |
| Malformed DATA ends the session; replay and AEAD failures drop the frame | `core/src/machine.rs` | `core/tests/engine.rs` | Implemented and tested |

## Sessions and rekey

| Area | Implementation | Evidence | Status |
| --- | --- | --- | --- |
| Lifecycle and DATA permissions | `core/src/machine.rs` | `core/tests/engine.rs` | Implemented and tested |
| Session bound to one connection (D-013) | `core/src/machine.rs`, `net/src/lib.rs` | `core/tests/engine.rs`, `net/tests/net.rs` | Implemented and tested |
| Rekey without SAS; identity continuity (D-015) | `core/src/machine.rs` | `core/tests/engine.rs` | Implemented and tested |
| Failed or timed-out rekey returns to ACTIVE; retry after a pause | `core/src/machine.rs` | `core/tests/engine.rs` | Implemented and tested |
| Late rekey frames dropped within a bounded grace; rejected commits warn after three consecutive failures (D-019) | `core/src/machine.rs` | `core/tests/engine.rs` | Implemented and tested |
| Peer-initiated rekey | `core/src/machine.rs` | `core/tests/engine.rs`, `net/tests/net.rs` | Implemented and tested |
| Automatic rekey trigger: 24 h timer and message count | `core/src/machine.rs` | `core/tests/engine.rs` (timer and count triggers) | Implemented and tested |
| Rekey glare tie-break | `core/src/machine.rs` | `core/tests/engine.rs` | Implemented and tested |
| DATA during a rekey; drain window | `core/src/machine.rs` | `core/tests/engine.rs` | Implemented and tested |

## Control frames and limits

| Area | Implementation | Evidence | Status |
| --- | --- | --- | --- |
| CLOSE schema and reasons | `core/src/close.rs` | `core/tests/conformance.rs` | Implemented and tested |
| CLOSE session-ID matching; unauthenticated cause | `core/src/machine.rs` | `core/tests/engine.rs` | Implemented and tested |
| CLOSE shown as unauthenticated | `cli/src/app.rs` | manual | Implemented (text only; no automated test) |
| Handshake timeouts: 15 s frame, 120 s SAS, 180 s total (§11) | `core/src/machine.rs` | `core/tests/engine.rs`, `net/tests/net.rs` | Implemented and tested; the frame and SAS interaction is an interpretation, see [architecture](architecture.md) |
| Cap of 4 unauthenticated handshakes | `net/src/lib.rs` | `net/tests/net.rs` | Implemented and tested |
| Bounded queues, cancel-safe reads, partial-write policy | `net/src/lib.rs` | `net/tests/net.rs` | Implemented and tested |
| Listener survives transient accept errors | `net/src/lib.rs` | none | Implemented, gap: untested |

## Volatile state and key hygiene

| Area | Implementation | Evidence | Status |
| --- | --- | --- | --- |
| Identity seed only persisted | `core/src/storage.rs`, `cli/src/keyring_store.rs` | storage unit tests (fake store) | Implemented and tested |
| Seed saved is read back and compared (§10.1) | `core/src/storage.rs` | storage unit test (forgetful store) | Implemented and tested; cannot prove persistence across a restart |
| Real OS credential store persists across restarts | `cli/Cargo.toml`, `cli/src/keyring_store.rs` | manual (profile reloaded across runs on Linux Secret Service) | Unverified on other platforms |
| No trust store, address book, history | whole workspace | code review | Implemented |
| Initial chain keys and root key not retained | `core/src/machine.rs` | none | Implemented (the derived `SessionKeys` is dropped and zeroized after the ratchets exist); no test inspects it |
| Chain, message and cached keys zeroized | `core/src/data.rs`, `core/src/ratchet.rs` | none | Implemented (`Zeroizing`); not asserted by a test |
| Key types have redacted `Debug` | `core/src/crypto.rs`, `core/src/machine.rs`, `net/src/lib.rs` | `core/tests/engine.rs`, `net/tests/net.rs` (canary) | Implemented and tested for engine and net events |
| Terminal display sanitization of peer text | `core/src/display.rs`, `cli/src/app.rs` | unit tests | Implemented and tested |
| Bounded scrollback, zeroized on eviction and drop | `cli/src/scrollback.rs` | unit tests (bounds only) | Implemented; zeroization not asserted |
| Exit wipe, core-dump hardening | `cli/src/hardening.rs` | manual (pty run) | Implemented; no `mlock`, so secrets can reach swap |
| Config is read-only, strict, never echoes content | `cli/src/config.rs` | `cli/tests/config.rs`, fuzz target | Implemented and tested |

## Evidence quality

| Area | Status |
| --- | --- |
| Hex known-answer vectors (spec §12.1) | Planned: current tests assert properties, not fixed hex values |
| Fuzz targets (close, DATA decrypt, CBOR, frame/stream, handshake incl. COMMIT, ratchet, engine inputs, config) | CI is configured to compile all targets and run 100-execution smoke campaigns; `fuzz/corpus/` remains git-ignored, and no campaign results are recorded in this repository |
| Independent implementation interoperability | External |
| Independent security review | External |

## Test evidence notes

`core/tests/engine.rs` is the main behavioural suite. It drives two engines over a simulator with a virtual clock, so every timeout and ordering case is deterministic and nothing can hang. `core/tests/conformance.rs` covers SAS bit boundaries, transcript determinism, nonce byte order, padding and replay, mostly as properties rather than published hex values. `net/tests/net.rs` runs real handshakes over pipes and loopback TCP, with injected write failures and paused-time timeouts.

## Review rule

A row is promoted to production-ready only after full integration coverage, interoperability evidence where applicable, and independent security review. The repository makes no general production-readiness claim.
