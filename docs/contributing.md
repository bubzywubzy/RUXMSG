# Contributing to RUXMSG

RUXMSG is a security-sensitive Rust protocol implementation. Small-looking changes can alter wire compatibility or security properties, so contributors should document intent and run the complete validation set.

## Repository layout

- `src/` — library modules and the `ruxmsg` binary
- `tests/` — integration and conformance tests
- `fuzz/` — fuzz crate, targets, corpus, and artifacts
- `protocol-spec.md` — normative protocol specification
- `docs/protocol-reference.md` — implementation-facing wire reference
- `docs/conformance-matrix.md` — implementation and test coverage
- `docs/decisions.md` — closed protocol decisions and rationale

## Toolchain and checks

The crate declares Rust 1.85 and edition 2024 in `Cargo.toml`. Before opening a change, run formatting, compilation, tests, Clippy, and documentation generation. Documentation examples must remain consistent with the public API and CLI source.

The project denies unsafe Rust and denies Clippy's `all` and `correctness` lint groups. Do not weaken these settings to make a change pass.

## Testing expectations

Use focused tests while developing, then run the complete workspace suite. Important existing coverage includes:

- deterministic transcript, SAS, and nonce vectors in `tests/conformance.rs`;
- two-peer handshake completion in `tests/handshake.rs`;
- interleaved DATA and rekey behavior in `tests/connection.rs`;
- session replacement and drain behavior in `tests/rekey.rs`;
- restart and persistence behavior in `tests/restart.rs`;
- framed transport and split reader/writer behavior in `tests/tcp_split.rs` and `tests/transport.rs`.

Blocking two-peer tests must start the peer thread before invoking the blocking handshake on the main thread. Otherwise each side can wait for the other indefinitely.

## Protocol changes

Do not change a wire value, field, length rule, canonical encoding rule, cryptographic domain, rejection rule, or lifecycle invariant without first updating the normative specification and recording the decision in `docs/decisions.md`.

For protocol changes:

1. update `protocol-spec.md`;
2. update `docs/protocol-reference.md`;
3. update the conformance matrix and deterministic vectors;
4. update implementation and integration tests;
5. consider backward compatibility and rejection behavior;
6. document the security and interoperability impact.

The specification is authoritative. Explanatory documents must link back to it rather than silently redefining it.

## Fuzzing

Fuzz targets live under `fuzz/fuzz_targets/` and cover close decoding, DATA decryption, CBOR payloads, frame decoding, handshake decoding, and session lifecycle behavior. Corpus files are committed under `fuzz/corpus/`.

Run fuzzing with the repository's fuzz crate tooling when available, and record meaningful findings or regressions in the relevant issue/change description. Existing corpus files demonstrate coverage inputs; they do not by themselves prove that fuzzing has completed or that the implementation is production-ready.

## Security-sensitive review

Never include private keys, test secrets intended for real use, or SAS values from a live session in logs or documentation. Review changes to identity, transcript construction, key derivation, nonce construction, counters, replay windows, storage, and error messages for accidental disclosure or state reuse.

When behavior is intentionally incomplete, say so explicitly. A passing unit test for a primitive is not evidence of production readiness or independent interoperability.
