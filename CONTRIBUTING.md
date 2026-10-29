# Contributing to RUXMSG

RUXMSG is a security-sensitive Rust protocol implementation. Small changes can alter wire compatibility or security properties, so document intent and run the complete validation set.

## Repository layout

- `crates/ruxmsg-core/`: protocol core (sans-IO engine, wire, crypto); tests in `tests/`
- `crates/ruxmsg-net/`: Tokio driver; tests in `tests/`
- `crates/ruxmsg-cli/`: the `ruxmsg` binary, config loader and keyring adapter; tests in `tests/`
- `fuzz/`: fuzz crate and targets
- `docs/protocol-spec.md`: normative specification, including the decision log (Appendix B)
- `docs/conformance-matrix.md`: implementation and test status
- `docs/architecture.md`, `docs/library.md`, `docs/cli.md`, `docs/security-model.md`: explanatory guides

## Toolchain and checks

The workspace `Cargo.toml` declares Rust 1.88 and edition 2024 (the fuzz crate uses edition 2021). On Linux you need `pkg-config` and `libdbus-1-dev` for the credential store. CI runs, in order:

```text
cargo fmt --all -- --check
cargo check --workspace --all-targets
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features
```

Also build rustdoc before opening a change. Documentation examples must match the public API and the CLI source.

The workspace forbids unsafe Rust and denies Clippy's `all` and `correctness` groups. Do not weaken these settings to make a change pass.

## Scope

RUXMSG/1 is volatile two-party messaging. Do not add groups, anonymity features, relaying, offline delivery, a trust store, an address book, message history, logging of peer data, or session resumption to RUXMSG/1. Those belong to RUXMSG/2 or need a new decision. Persisting anything beyond the identity seed requires a decision that supersedes D-018.

## Testing expectations

Use focused tests while developing, then run the full suite. Existing coverage includes:

- transcript, SAS, nonce, padding, replay and frame-limit checks in `crates/ruxmsg-core/tests/conformance.rs` and `limits.rs`;
- the engine, driven by a two-node simulator with a virtual clock, in `crates/ruxmsg-core/tests/engine.rs`: handshake ordering and replay, every timeout, rekey, glare, CLOSE rules and bounded output;
- the Tokio driver over pipes and loopback TCP in `crates/ruxmsg-net/tests/net.rs`: partial and stalled writes, queue bounds, the handshake cap, timeouts under paused time;
- the config loader in `crates/ruxmsg-cli/tests/config.rs`.

Engine tests must never block: the simulator's peer returns `TransportClosed` when its script runs out, so a missing frame fails fast instead of hanging.

**Known-answer vectors.** Spec §12.1 requires fixed hex vectors for every derived value. Current tests mostly assert properties. New cryptographic code must add hex vectors, ideally cross-checked against an independent implementation, and keep them beside the tests that use them.

New security behavior needs tests for both the accepting and rejecting paths: for example, a commitment that does not match, AUTH fields that differ from the local transcript, a rekey from a different identity, and a failed authentication that must not consume a message key.

## Protocol changes

Do not change a wire value, field, length rule, canonical encoding rule, cryptographic domain, rejection rule, limit or lifecycle invariant without first updating the specification and recording the decision.

1. update `docs/protocol-spec.md` and record the decision in its Appendix B;
2. update the conformance matrix and known-answer vectors;
3. update the implementation and tests;
4. update the explanatory guides that describe the behavior;
5. consider backward compatibility and rejection behavior;
6. document the security and interoperability impact.

The specification is authoritative. Explanatory documents must link to it rather than redefine it.

## Fuzzing

Fuzz targets live in `fuzz/fuzz_targets/` (a separate workspace) and cover CLOSE decoding, DATA decryption, CBOR payloads, frame decoding, handshake decoding including COMMIT, the receiving ratchet, arbitrary engine input sequences, and the config parser. `fuzz/corpus/` and `fuzz/artifacts/` are git-ignored, so corpora are local. Run fuzzing with `cargo fuzz` from `fuzz/` (it needs a nightly toolchain) and record meaningful findings in the change description. When you change a decoder, the engine or the config schema, extend or add the matching target.

A target existing does not prove fuzzing was run or that any result was achieved.

## Security-sensitive review

Never put private keys, test secrets meant for real use, or SAS values from a live session in logs or documentation. Review changes to identity, transcript construction, commitment, key derivation, nonce construction, counters, replay windows, key erasure, storage, display of peer text, and error messages for accidental disclosure or state reuse.

When behavior is intentionally incomplete, say so in the conformance matrix. A passing test for a primitive is not evidence of production readiness or interoperability.
