# Contributing to RUXMSG

RUXMSG is a security-sensitive Rust protocol implementation. Small changes can affect wire compatibility, cryptographic state, persistence behavior, or session lifecycle semantics. Contributions should therefore be narrowly scoped, explicit about intent, and validated against the complete repository test and tooling set.

## Repository layout

* `src/` — library modules and the `ruxmsg` terminal client
* `src/bin/ruxmsg.rs` — line-oriented multi-session CLI
* `tests/` — integration, transport, restart, rekey, and conformance tests
* `fuzz/` — fuzzing crate, targets, and committed corpus inputs
* `protocol-spec.md` — normative protocol specification
* `docs/protocol-reference.md` — implementation-facing protocol and wire reference
* `docs/conformance-matrix.md` — implementation and verification coverage
* `docs/architecture.md` — current implementation architecture
* `docs/cli.md` — current terminal client behavior
* `docs/decisions.md` — recorded protocol and architectural decisions

## Toolchain and checks

The crate uses **Rust 1.88 or newer** and the **2024 edition**, as declared in `Cargo.toml`.

Before opening a change, run the relevant focused checks while developing and the complete validation set before submission:

```bash
cargo fmt --all -- --check
cargo check --all-targets
cargo test --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo doc --no-deps
```

If the repository's supported commands or CI configuration change, follow the current repository configuration rather than relying on this document as a substitute for it.

The crate denies unsafe Rust and enables strict Clippy checking. Do not weaken lint settings merely to make a change compile or pass CI. If a lint exposes a legitimate design issue, fix the underlying issue or document the narrowly justified exception.

Documentation is part of the implementation surface. Examples must remain consistent with the current public API, protocol behavior, and line-oriented CLI.

## Testing expectations

Use focused tests during development, then run the complete workspace validation before submitting a change.

Important existing coverage includes:

* `tests/conformance.rs` — deterministic protocol, transcript, SAS, cryptographic, and encoding vectors;
* `tests/handshake.rs` — two-peer handshake establishment and authentication behavior;
* `tests/connection.rs` — connection-level DATA handling, interleaving, and rekey behavior;
* `tests/rekey.rs` — session replacement, predecessor draining, and rekey lifecycle behavior;
* `tests/restart.rs` — persistent identity behavior across restart boundaries;
* `tests/tcp_split.rs` — TCP framing and split reader/writer behavior;
* `tests/transport.rs` — transport and framing behavior.

The test suite also covers protocol rejection behavior, replay and skipped-key handling, canonical encoding, and other security-sensitive invariants where applicable.

### Blocking test behavior

Some integration tests use blocking transports and two peer threads. When constructing a two-peer blocking test, ensure the peer thread is started before invoking the corresponding blocking operation on the main thread.

Starting both blocking operations serially can deadlock the test because the first peer may wait for input that only the second peer can produce.

## Protocol changes

Treat protocol behavior as an explicit compatibility boundary.

Do not silently change:

* wire values;
* message types;
* field meanings;
* frame-length rules;
* canonical encoding requirements;
* cryptographic domains or transcript inputs;
* key-derivation inputs;
* nonce or counter construction;
* rejection conditions;
* session lifecycle transitions;
* rekey or drain semantics.

A change to any of these may affect interoperability or security even when the resulting source-level change is small.

For a protocol change:

1. update the normative `protocol-spec.md`;
2. update `docs/protocol-reference.md`;
3. update `docs/conformance-matrix.md`;
4. update affected deterministic vectors;
5. update implementation and integration tests;
6. evaluate compatibility with existing peers and persisted identities;
7. verify both accepted and rejected inputs;
8. document the security and interoperability consequences;
9. record the decision in `docs/decisions.md` when it represents a new or changed protocol/architectural decision.

The normative specification is authoritative. Implementation-facing and explanatory documentation must describe the specification and implementation accurately; they must not introduce a competing protocol definition.

## Identity and persistence

The current persistence boundary is intentionally narrow.

RUXMSG persists the local Ed25519 identity through the configured OS credential-store abstraction. Active cryptographic sessions, ratchet state, message keys, and session state are not restored across process restarts.

The current implementation does **not** provide persistent trusted-peer records or persistent SAS approvals. Do not document or implement assumptions that a previously verified peer will automatically bypass SAS verification unless the trust model is explicitly changed and implemented.

Changes involving identity or persistence require particular care because they can alter authentication semantics or create unintended secret-storage behavior.

## Fuzzing

Fuzzing infrastructure is located under `fuzz/`.

Current fuzz targets exercise areas including:

* close-message decoding;
* DATA decryption;
* CBOR payload handling;
* frame decoding;
* handshake decoding;
* session lifecycle behavior.

Committed corpus inputs provide useful regression and exploration cases. They do **not** establish that fuzzing has been exhaustively completed, nor do they constitute evidence of production readiness or security assurance.

Run the repository's fuzzing tooling when making changes to fuzzed components. When fuzzing identifies a meaningful crash, invariant violation, parser discrepancy, or security-relevant regression:

* preserve a minimal reproducing input where appropriate;
* add a regression test when practical;
* update the relevant corpus or fuzz target if useful;
* document the finding and its resolution in the associated issue or change description.

## Security-sensitive review

Review security-sensitive changes more aggressively than ordinary refactors.

Pay particular attention to changes involving:

* identity generation and storage;
* transcript construction;
* signature verification;
* SAS calculation or presentation;
* X25519 key agreement;
* HKDF inputs and domain separation;
* session confirmation;
* AEAD keys and nonces;
* message counters;
* replay windows;
* skipped-key handling;
* rekey and predecessor draining;
* canonical encoding;
* frame-length validation;
* error handling;
* logging and diagnostic output.

Never place private keys, persistent secret material, live-session SAS values, or other sensitive credentials in logs, test output, documentation, fixtures, or committed corpus files.

Avoid introducing state reuse across sessions. In particular, verify that ephemeral key material, nonces, counters, ratchet state, and derived keys retain their required lifecycle boundaries.

Error messages should provide enough information to diagnose protocol failures without unnecessarily disclosing cryptographic material, authentication state, or other sensitive information.

## CLI changes

The terminal client is a line-oriented, multi-session REPL rather than a one-shot connection command.

Changes to `src/bin/ruxmsg.rs` should preserve the distinction between:

* local profile selection;
* listener lifecycle;
* outbound connection creation;
* multiple simultaneous peer handles;
* per-peer message routing;
* session inspection;
* fingerprint display;
* connection closure;
* optional Tailscale convenience commands.

CLI documentation in `docs/cli.md` must be updated when command names, arguments, output semantics, or session behavior change.

Do not document persistent contact management, automatic trust enrollment, message history, offline delivery, or other functionality unless it actually exists in the implementation.

## Cross-platform changes

The core library is designed around platform-neutral Rust abstractions such as `Read`/`Write` transports and standard TCP. Platform-specific behavior primarily enters through facilities such as OS credential storage and the terminal/client environment.

The current CI configuration should be treated as the authoritative statement of what is automatically tested. Do not claim that a platform is independently tested merely because the code is theoretically portable.

Changes to credential storage, networking, terminal behavior, or other platform-sensitive components should be reviewed for differences between Linux, macOS, and Windows where relevant.

## Documentation synchronization

Documentation should describe the repository as it exists, not as it is intended to exist.

When implementation behavior changes, review at least the documentation directly associated with that behavior:

* protocol changes → `protocol-spec.md`, `docs/protocol-reference.md`, `docs/conformance-matrix.md`, and `docs/decisions.md`;
* architecture changes → `docs/architecture.md`;
* CLI changes → `docs/cli.md`;
* testing or verification changes → `docs/conformance-matrix.md`;
* persistence changes → architecture, CLI, and conformance documentation.

Remove obsolete behavior from documentation rather than leaving historical descriptions that appear to be current.

## Incomplete functionality

RUXMSG is an evolving protocol and implementation. When behavior is intentionally incomplete, experimental, or integration-limited, state that explicitly.

Do not infer security assurance from:

* a passing unit test;
* successful local interoperability;
* deterministic cryptographic vectors;
* fuzz corpus contents;
* successful compilation;
* a clean Clippy run.

Likewise, successful operation through TCP or Tailscale demonstrates connectivity, not cryptographic anonymity, metadata protection, or protection from a compromised endpoint.

No contributor should describe an implementation as independently audited, production-ready, interoperable with unrelated implementations, or secure against a particular threat model unless the corresponding evidence exists and the claim is appropriately scoped.

## Before submitting a change

At minimum:

1. Keep the change narrowly scoped.
2. Update affected documentation.
3. Run formatting and compilation checks.
4. Run focused tests for the changed subsystem.
5. Run the complete test suite.
6. Run Clippy with warnings treated as errors.
7. Generate documentation and verify examples.
8. Run relevant fuzz targets when parser/protocol/state-machine behavior changes.
9. Review the diff for accidental secret disclosure or state reuse.
10. For protocol changes, update the normative specification, conformance material, vectors, tests, and recorded decisions before considering the change complete.

The objective is not merely to make the code compile. Every change should leave the implementation, specification, tests, and documentation describing the same system.
