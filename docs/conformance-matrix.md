# RUXMSG/1 conformance matrix

This matrix connects the normative requirements of RUXMSG/1 to the current implementation and repository test coverage.

It is a **status and evidence document**, not a second protocol specification. When wording differs between this document and the [protocol specification](protocol-spec.md), the protocol specification is authoritative.

## Status meanings

* **Implemented and tested** — implementation exists and repository tests exercise the relevant behavior.
* **Implemented, integration incomplete** — implementation primitives exist, but the complete workflow or product integration is incomplete.
* **Infrastructure only** — supporting infrastructure exists, but the repository does not establish a complete conformance result.
* **Planned** — not currently implemented or not currently sufficient for an interoperability claim.

---

## Protocol conformance

| Area                                     | Implementation                                       | Evidence                                     | Status                     |
| ---------------------------------------- | ---------------------------------------------------- | -------------------------------------------- | -------------------------- |
| Version, message types, and frame limits | `src/protocol.rs`, `src/wire.rs`                     | `tests/transport.rs`, module tests           | **Implemented and tested** |
| Outer framing and truncation handling    | `src/wire.rs`, `src/transport.rs`                    | `tests/transport.rs`                         | **Implemented and tested** |
| Deterministic transcript encoding        | `src/encoding.rs`, `src/handshake.rs`                | `tests/conformance.rs`, `tests/handshake.rs` | **Implemented and tested** |
| Ed25519 identity authentication          | `src/crypto.rs`, `src/handshake.rs`                  | `tests/handshake.rs`, crypto tests           | **Implemented and tested** |
| X25519 ephemeral key agreement           | `src/crypto.rs`                                      | crypto and handshake tests                   | **Implemented and tested** |
| X25519 all-zero shared-secret rejection  | `src/crypto.rs`                                      | crypto and handshake tests                   | **Implemented and tested** |
| SAS derivation                           | `src/crypto.rs`                                      | `tests/conformance.rs`                       | **Implemented and tested** |
| HKDF-SHA-256 session derivation          | `src/crypto.rs`                                      | `tests/handshake.rs`, crypto tests           | **Implemented and tested** |
| Directional key derivation               | `src/crypto.rs`                                      | `tests/handshake.rs`, crypto tests           | **Implemented and tested** |
| Session confirmation                     | `src/crypto.rs`, `src/handshake.rs`, `src/engine.rs` | `tests/handshake.rs`                         | **Implemented and tested** |
| Authenticated DATA                       | `src/data.rs`, `src/crypto.rs`                       | DATA and conformance tests                   | **Implemented and tested** |
| Canonical DATA padding                   | `src/data.rs`                                        | DATA and conformance tests                   | **Implemented and tested** |
| Replay protection                        | `src/ratchet.rs`, `src/data.rs`                      | ratchet/DATA tests                           | **Implemented and tested** |
| Bounded out-of-order delivery            | `src/ratchet.rs`, `src/data.rs`                      | ratchet/DATA tests                           | **Implemented and tested** |
| Skipped-key limits                       | `src/ratchet.rs`                                     | ratchet/DATA tests                           | **Implemented and tested** |
| Session lifecycle                        | `src/session.rs`, `src/manager.rs`                   | `tests/rekey.rs`, `tests/restart.rs`         | **Implemented and tested** |
| Rekey candidate handling                 | `src/connection.rs`, `src/manager.rs`                | `tests/connection.rs`, `tests/rekey.rs`      | **Implemented and tested** |
| Rekey drain behavior                     | `src/connection.rs`, `src/manager.rs`                | `tests/rekey.rs`                             | **Implemented and tested** |
| In-memory transport                      | `src/transport.rs`                                   | handshake and integration tests              | **Implemented and tested** |
| Framed stream transport                  | `src/transport.rs`                                   | `tests/transport.rs`, `tests/tcp_split.rs`   | **Implemented and tested** |
| TCP stream splitting                     | `src/connection.rs`                                  | `tests/tcp_split.rs`                         | **Implemented and tested** |

---

## Identity and persistence

The current persistence boundary is intentionally smaller than the earlier planned trust-store design.

| Area                                 | Implementation                      | Evidence                     | Status                                  |
| ------------------------------------ | ----------------------------------- | ---------------------------- | --------------------------------------- |
| Persistent local Ed25519 identity    | `src/identity.rs`, `src/storage.rs` | restart/integration coverage | **Implemented and tested**              |
| OS credential-store integration      | `src/storage.rs`                    | storage/integration behavior | **Implemented, integration incomplete** |
| Persistent trusted-peer records      | —                                   | none                         | **Planned**                             |
| Persistent SAS approvals             | —                                   | none                         | **Planned**                             |
| Automatic trusted-peer SAS bypass    | —                                   | none                         | **Planned**                             |
| Persistent session state             | —                                   | none                         | **Not implemented by design**           |
| Persistent ratchet/message-key state | —                                   | none                         | **Not implemented by design**           |
| Persistent message history           | —                                   | none                         | **Planned**                             |

The current implementation persists the local identity required to maintain a stable cryptographic identity across process restarts.

It does **not** persist trusted-peer records or SAS approvals.

A successful SAS verification therefore applies to the connection being established. The current CLI does not automatically remember that verification for a future connection.

---

## Session restart behavior

| Area                                      | Implementation                      | Evidence                                   | Status                        |
| ----------------------------------------- | ----------------------------------- | ------------------------------------------ | ----------------------------- |
| Identity survives process restart         | `src/identity.rs`, `src/storage.rs` | `tests/restart.rs`                         | **Implemented and tested**    |
| Active session remains in memory only     | `src/session.rs`, `src/manager.rs`  | `tests/restart.rs`                         | **Implemented and tested**    |
| Fresh handshake after restart             | `src/engine.rs`, `src/session.rs`   | `tests/restart.rs`, `tests/conformance.rs` | **Implemented and tested**    |
| Session keys restored after restart       | —                                   | none                                       | **Not implemented by design** |
| Ratchet state restored after restart      | —                                   | none                                       | **Not implemented by design** |
| Trusted-peer state restored after restart | —                                   | none                                       | **Planned**                   |

Restarting the process therefore preserves the local identity but requires a new cryptographic session.

---

## CLI conformance

The CLI has evolved into a multi-session REPL. The matrix therefore distinguishes the currently implemented client functionality from future application features.

| Area                                | Implementation      | Evidence                        | Status                     |
| ----------------------------------- | ------------------- | ------------------------------- | -------------------------- |
| Profile selection                   | `src/bin/ruxmsg.rs` | CLI implementation              | **Implemented**            |
| Profile initialization              | `src/bin/ruxmsg.rs` | CLI implementation              | **Implemented**            |
| Profile listing                     | `src/bin/ruxmsg.rs` | CLI implementation              | **Implemented**            |
| TCP listener                        | `src/bin/ruxmsg.rs` | CLI implementation              | **Implemented and tested** |
| TCP outbound connection             | `src/bin/ruxmsg.rs` | CLI implementation              | **Implemented and tested** |
| Multiple simultaneous peer sessions | `src/bin/ruxmsg.rs` | current peer/session management | **Implemented**            |
| Peer listing                        | `src/bin/ruxmsg.rs` | CLI implementation              | **Implemented**            |
| Peer selection                      | `src/bin/ruxmsg.rs` | CLI implementation              | **Implemented**            |
| Targeted message sending            | `src/bin/ruxmsg.rs` | CLI implementation              | **Implemented**            |
| Peer/session inspection             | `src/bin/ruxmsg.rs` | CLI implementation              | **Implemented**            |
| Peer fingerprint display            | `src/bin/ruxmsg.rs` | CLI implementation              | **Implemented**            |
| Explicit session close              | `src/bin/ruxmsg.rs` | CLI implementation              | **Implemented**            |
| Tailscale convenience commands      | `src/bin/ruxmsg.rs` | CLI implementation              | **Implemented**            |
| Persistent trusted-peer enrollment  | —                   | none                            | **Planned**                |
| Automatic SAS bypass                | —                   | none                            | **Planned**                |
| Persistent conversation history     | —                   | none                            | **Planned**                |
| Offline messaging                   | —                   | none                            | **Planned**                |
| Complete production messaging UI    | —                   | none                            | **Planned**                |

The current CLI should therefore not be described as a one-connection client. A single process can maintain multiple active peer sessions.

The CLI is nevertheless still a small protocol-oriented terminal client rather than a complete production messaging application.

---

## Transport and networking

| Area                               | Implementation                           | Evidence                        | Status                                  |
| ---------------------------------- | ---------------------------------------- | ------------------------------- | --------------------------------------- |
| Generic `Transport` abstraction    | `src/transport.rs`                       | transport/integration tests     | **Implemented and tested**              |
| In-memory transport                | `src/transport.rs`                       | handshake/integration tests     | **Implemented and tested**              |
| Generic framed stream transport    | `src/transport.rs`                       | `tests/transport.rs`            | **Implemented and tested**              |
| TCP client/listener path           | `src/bin/ruxmsg.rs`, `src/connection.rs` | connection/TCP tests            | **Implemented and tested**              |
| Tailscale reachability integration | `src/bin/ruxmsg.rs`                      | CLI implementation              | **Implemented, integration incomplete** |
| Additional production transports   | `src/transport.rs` abstraction           | no additional shipped transport | **Planned**                             |
| Central relay/server               | —                                        | none                            | **Not part of current architecture**    |

Tailscale is an optional reachability mechanism. It is not used as the cryptographic identity or authentication authority for a RUXMSG peer.

---

## Testing and verification infrastructure

| Area                                        | Implementation             | Evidence                               | Status                     |
| ------------------------------------------- | -------------------------- | -------------------------------------- | -------------------------- |
| Deterministic protocol vectors              | `tests/conformance.rs`     | committed test vectors                 | **Implemented and tested** |
| Handshake integration testing               | `tests/handshake.rs`       | two-peer handshake tests               | **Implemented and tested** |
| Connection integration testing              | `tests/connection.rs`      | connection tests                       | **Implemented and tested** |
| Rekey testing                               | `tests/rekey.rs`           | rekey/drain tests                      | **Implemented and tested** |
| Restart testing                             | `tests/restart.rs`         | restart behavior tests                 | **Implemented and tested** |
| TCP stream-splitting tests                  | `tests/tcp_split.rs`       | TCP split tests                        | **Implemented and tested** |
| Transport tests                             | `tests/transport.rs`       | transport/framing tests                | **Implemented and tested** |
| Fuzzing targets                             | `fuzz/fuzz_targets/`       | committed targets/corpus               | **Infrastructure only**    |
| Independent interoperability implementation | external                   | no independent implementation recorded | **Planned**                |
| Independent security audit                  | external                   | no independent review recorded         | **Planned**                |
| Cross-platform CI matrix                    | `.github/workflows/ci.yml` | current Linux CI                       | **Infrastructure only**    |

The repository's test suite provides evidence for implementation behavior, but passing repository tests is not equivalent to independent interoperability validation or a security audit.

---

## Conformance vectors

The deterministic conformance tests are particularly important for protocol behavior that must remain byte-for-byte compatible between implementations.

Relevant coverage includes:

* transcript construction;
* transcript domain separation;
* SAS derivation and bit boundaries;
* nonce construction and byte ordering;
* canonical encoding;
* DATA authentication;
* padding behavior;
* protocol rejection rules.

These tests are intended to prevent accidental changes to protocol behavior during implementation changes.

A passing local test suite does not by itself demonstrate interoperability with an independent implementation.

---

## Rekey evidence

The rekey tests exercise the transition between an active session and its predecessor.

The expected lifecycle is:

```text
Current session
      │
      │ rekey
      ▼
New active session
      │
      │
      └──── old session becomes draining
                         │
                         ▼
                  drain interval
                         │
                         ▼
                    old session
                      expires
```

The tests verify the relevant session transition and ensure that the old session does not remain an unrestricted source of new DATA after the transition.

---

## Fuzzing evidence

The repository contains fuzzing targets for protocol and parsing boundaries.

Fuzz infrastructure establishes that a target can be exercised by a fuzzing engine. It does **not** establish:

* a particular number of executed cases;
* a specific coverage percentage;
* absence of vulnerabilities;
* absence of crashes outside the tested corpus;
* production security.

Fuzzing status should therefore remain separate from protocol conformance status.

---

## Interoperability status

RUXMSG currently has repository-local implementation and conformance tests, but no independent implementation is recorded as interoperating with the current protocol.

Accordingly, the project should not claim interoperability solely from:

```text
implementation ↔ implementation
```

tests within the same repository.

An interoperability claim requires at least one independently implemented protocol participant and evidence that the implementation follows the normative wire and cryptographic requirements.

---

## Security-review status

No independent cryptographic or security audit is currently recorded for the repository.

The implementation contains explicit security boundaries and extensive deterministic testing, but those facts do not substitute for independent review.

A future production-readiness assessment should consider at least:

* independent protocol review;
* cryptographic implementation review;
* parser and wire-format review;
* state-machine review;
* concurrency review;
* memory-safety review;
* interoperability testing;
* platform-specific credential-store review;
* adversarial testing of malformed and reordered input.

---

## Current overall status

The repository currently has a substantial protocol implementation and test foundation.

The implementation status can be summarized as:

```text
Protocol primitives          Implemented
Handshake                    Implemented
Session establishment        Implemented
Authenticated DATA           Implemented
Ratchet/replay handling      Implemented
Rekey/drain machinery        Implemented
Transport abstraction        Implemented
TCP client                   Implemented
Multi-session REPL           Implemented
Local identity persistence   Implemented
Trusted-peer persistence     Not implemented
Persistent conversations     Not implemented
Independent interoperability Not demonstrated
Independent security review  Not performed
```

This is a description of implementation state, not a production-readiness rating.

---

## Review rule

Conformance status and production readiness are separate questions.

A protocol feature may be implemented and tested without the overall product being suitable for production use.

Before making a production-security or interoperability claim, the relevant behavior should have:

1. complete repository-level integration coverage;
2. deterministic conformance evidence where applicable;
3. independent interoperability evidence where applicable;
4. appropriate adversarial testing;
5. independent security review.

The current repository does not make a general production-readiness claim.
