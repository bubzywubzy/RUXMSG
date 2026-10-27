# Contributing to RUXMSG

RUXMSG is a security-sensitive Rust protocol implementation. Small changes can alter wire compatibility or security properties, so document intent and run the complete validation set.

## Repository layout

- `src/`: library modules and the `ruxmsg` binary (`src/bin/ruxmsg.rs`)
- `tests/`: integration and conformance tests
- `fuzz/`: fuzz crate and targets
- `docs/protocol-spec.md`: normative specification
- `docs/protocol-reference.md`: implementation-facing wire reference
- `docs/conformance-matrix.md`: implementation and test status
- `docs/decisions.md`: closed decisions and rationale
- `docs/test-vectors.md`: hex known-answer vectors (planned; see below)

## Toolchain and checks

`Cargo.toml` declares Rust 1.88 and edition 2024 (the fuzz crate uses edition 2021). On Linux you need `pkg-config` and `libdbus-1-dev` for the credential store. CI runs, in order:

```text
cargo fmt --all -- --check
cargo check --all-targets
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets --all-features
```

Also build rustdoc before opening a change. Documentation examples must match the public API and the CLI source.

The crate forbids unsafe Rust and denies Clippy's `all` and `correctness` groups. Do not weaken these settings to make a change pass.

## Scope

RUXMSG/1 is volatile two-party messaging. Do not add groups, anonymity features, relaying, offline delivery, a trust store, an address book, message history, logging of peer data, or session resumption to RUXMSG/1. Those belong to RUXMSG/2 or need a new decision. Persisting anything beyond the identity seed requires a decision that supersedes D-018.

## Testing expectations

Use focused tests while developing, then run the full suite. Existing coverage includes:

- transcript, SAS, nonce, padding, replay and frame-limit checks in `tests/conformance.rs`;
- two-peer handshake in `tests/handshake.rs`;
- interleaved DATA and rekey in `tests/connection.rs`;
- session replacement and drain in `tests/rekey.rs`;
- restart behavior in `tests/restart.rs`;
- framed transport and split reader/writer in `tests/transport.rs` and `tests/tcp_split.rs`.

Blocking two-peer tests must start the peer thread before invoking the blocking handshake on the main thread, or each side waits forever.

**Known-answer vectors.** Spec §12.1 requires fixed hex vectors for every derived value. Current tests mostly assert properties. New cryptographic code must add hex vectors, ideally cross-checked against an independent implementation, and record them in `docs/test-vectors.md`.

New security behavior needs tests for both the accepting and rejecting paths: for example, a commitment that does not match, AUTH fields that differ from the local transcript, a rekey from a different identity, and a failed authentication that must not consume a message key.

## Protocol changes

Do not change a wire value, field, length rule, canonical encoding rule, cryptographic domain, rejection rule, limit or lifecycle invariant without first updating the specification and recording the decision.

1. update `docs/protocol-spec.md` (and its Appendix B);
2. add the decision to `docs/decisions.md`;
3. update `docs/protocol-reference.md`;
4. update the conformance matrix and known-answer vectors;
5. update the implementation and tests;
6. consider backward compatibility and rejection behavior;
7. document the security and interoperability impact.

The specification is authoritative. Explanatory documents must link to it rather than redefine it.

## Fuzzing

Fuzz targets live in `fuzz/fuzz_targets/` and cover CLOSE decoding, DATA decryption, CBOR payloads, frame decoding, handshake decoding, and session lifecycle. `fuzz/corpus/` and `fuzz/artifacts/` are git-ignored, so corpora are local. Run fuzzing with the fuzz crate tooling and record meaningful findings in the change description. Add targets for COMMIT and AUTH decoding and the rekey state machine when those change.

A target existing does not prove fuzzing was run or that any result was achieved.

## Security-sensitive review

Never put private keys, test secrets meant for real use, or SAS values from a live session in logs or documentation. Review changes to identity, transcript construction, commitment, key derivation, nonce construction, counters, replay windows, key erasure, storage, display of peer text, and error messages for accidental disclosure or state reuse.

When behavior is intentionally incomplete, say so in the conformance matrix. A passing test for a primitive is not evidence of production readiness or interoperability.
