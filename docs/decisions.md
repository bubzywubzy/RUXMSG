# RUXMSG/1 decisions

These decisions close wire-level and product-boundary questions. Normative wording is in the [specification](protocol-spec.md); Appendix B there mirrors this index. A decision may not be changed without updating the specification, the [protocol reference](protocol-reference.md), the [conformance matrix](conformance-matrix.md), and the tests.

## Decision index

| IDs | Area | Introduced |
| --- | --- | --- |
| D-001 to D-003 | Version, registry, strict schemas | spec 1.0 |
| D-004 to D-006 | Handshake, AAD/nonce, padding | spec 1.0 (D-006 amended by D-014) |
| D-007 to D-009 | Errors, state safety, implementation gate | spec 1.0 |
| D-010 to D-011 | SAS artifact, symmetric HELLO | spec 1.0 |
| D-012 | Handshake commitment | spec 1.1 |
| D-013 | Session bound to one connection | spec 1.1 |
| D-014 | Padding on ciphertext | spec 1.1 |
| D-015 | Rekey by identity continuity | spec 1.1 |
| D-016 | Limits and timeouts | spec 1.1 |
| D-017 | Unauthenticated CLOSE | spec 1.1 |
| D-018 | No trust store | spec 1.1 |

Remaining product work is tracked in the [conformance matrix](conformance-matrix.md) and must not be inferred from the existence of a low-level implementation.

## D-001: Version target

The wire protocol is `RUXMSG/1`. The normative baseline is specification 1.1. RUXMSG/2 (groups, anonymity features, offline delivery) will be a new protocol version, not an extension of this one.

## D-002: Message registry

Fixed IDs: `0x01` HANDSHAKE, `0x02` SESSION_CONFIRM, `0x03` DATA, `0x04` REKEY, `0x05` CLOSE. All other values are reserved and rejected in v1.

## D-003: Strict schemas

Base messages are deterministic CBOR maps with unsigned integer keys, definite lengths, no duplicate or unknown keys. Extensions require a new protocol version or a separately registered message type.

## D-004: Handshake transport

HANDSHAKE frames carry the initial-handshake stages and REKEY frames carry the same stages for a rekey. The AUTH stage carries the initiator signature (stage 0) and both signatures (stage 1). The transcript excludes signatures. A rekey requires a previous session ID.

## D-005: AAD and nonce

DATA AAD is canonical CBOR of version, session ID, message type, direction ID and counter. The nonce is BE32 direction ID followed by BE64 counter.

## D-006: Padding (amended by D-014)

Default quantum 256 bytes, padding of zero bytes, recalculated over the complete canonical plaintext map including CBOR overhead, validated only after AEAD authentication. The measurement basis was changed by D-014.

## D-007: Errors

Errors are not a wire message type. A peer may receive CLOSE with a reason; local diagnostics stay secret-free and bounded.

## D-008: State safety

A failed candidate handshake or rekey never invalidates the active session. Process exit destroys all cryptographic state. (Transport reconnect behavior is superseded by D-013.)

## D-009: Implementation gate

No Rust implementation was written until the protocol passed a two-pass wire-completeness review. Subsequent work remains subject to conformance tests and explicit decisions.

## D-010: SAS dictionary artifact

The SAS dictionary is the 2048-word LF-delimited lowercase ASCII BIP-0039 English list at `https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt`, pinned SHA-256 `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`. Implementations verify it before use.

## D-011: Symmetric HELLO exchange

Each peer sends a HELLO with only its own values, and the transcript is built after both arrive. This removed the earlier sequencing contradiction. D-012 now orders the exchange.

## D-012: Handshake commitment

**Decision.** The initiator sends COMMIT, `SHA-256("RUXMSG/1/COMMIT" || BE32(L) || P)` over its exact HELLO payload, before it sees any responder value. The responder sends its HELLO next; the initiator then reveals its HELLO; the responder verifies the commitment.

**Why.** The SAS has 33 bits. With plain HELLOs an active attacker can delay one side, read the other side's values, and grind its own nonce (about 2^33 hashes) until both connections display the same SAS. Since SAS is the only authentication, this defeats it. Committing first forces the attacker to fix its values before it knows the values they must match, leaving a 1-in-2^33 chance per attempt.

**Cost.** One extra frame per handshake. The same sequence is used for rekey for uniformity.

## D-013: Session bound to one connection

**Decision.** A session lives exactly as long as its transport connection. Loss of the connection ends the session and destroys its state. Reconnecting is a new handshake and a new SAS. There is no resumption.

**Why.** The product is volatile and requires SAS on every connection. Resumption would need a resume message, retained state, and counter and nonce continuity across connections. Connection-bound sessions make nonce reuse across connections impossible by construction. Supersedes the transport-reconnect preservation rule of spec 1.0.

## D-014: Padding measured on ciphertext

**Decision.** The padding quantum applies to the ciphertext: padding is chosen so the canonical plaintext map plus the 16-byte AEAD tag is a multiple of 256 bytes.

**Why.** It matches the implemented and tested behavior and pads what an observer actually sees. Amends D-006.

## D-015: Rekey by identity continuity

**Decision.** A rekey does not use SAS. The candidate must name the active session as `previous_session_id`, present the same local and remote identity keys that authenticated the active session, and carry valid signatures over the locally computed transcript. Otherwise it is discarded and the active session continues.

**Why.** Prompting a human every 24 hours is unworkable, and an attacker who was not already authenticated cannot produce the required signatures. A failed rekey returns the old session to ACTIVE.

## D-016: Limits and timeouts

**Decision.** Per-type payload limits (HANDSHAKE/REKEY 1,024, SESSION_CONFIRM 128, CLOSE 256, DATA 1 MiB), `MAX_CONTENT` 65,536 bytes per message, handshake frame timeout 15 s, SAS decision timeout 120 s, total handshake deadline 180 s, and at most 4 concurrent unauthenticated handshakes per listener. Defaults; implementations may be stricter.

**Why.** Unauthenticated peers should not be able to make a listener wait forever or allocate a megabyte per connection.

## D-017: CLOSE is unauthenticated in V1

**Decision.** CLOSE is a plaintext control frame. A CLOSE with an unknown session ID is ignored, a CLOSE naming the draining session closes only that session, and UIs report it as "peer closed (unauthenticated)".

**Why.** An attacker able to inject a CLOSE could also reset the TCP connection, so authentication would add little in V1. Authenticated close can be reconsidered for RUXMSG/2.

## D-018: No trust store

**Decision.** RUXMSG/1 persists only the local Ed25519 identity seed. It stores no peer identities, addresses, trust state, approvals, history or logs, and never skips the SAS based on remembered identity. Profile names are not enumerated.

**Why.** Keeps the product volatile and the attack surface small. Users may still compare peer fingerprints out of band.
