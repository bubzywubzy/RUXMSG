# RUXMSG/1 Phase 0 Decisions

These decisions close wire-level gaps in the original working draft. The normative wording is in [`../protocol-spec.md`](../protocol-spec.md), Appendix E.

## Decision index

| IDs | Area |
| --- | --- |
| D-001–D-003 | Version, registry, and strict schemas |
| D-004–D-006 | Handshake, AAD/nonce, and padding |
| D-007–D-009 | Errors, lifecycle, and implementation gate |
| D-010–D-011 | SAS artifact and symmetric HELLO exchange |

These are closed wire-level decisions. Remaining product work is tracked in the [conformance matrix](conformance-matrix.md) and must not be inferred from the existence of a low-level implementation.

## D-001: Version target

The wire protocol remains `RUXMSG/1`. The implementation baseline is normative version 1.0; the former working-draft designation is no longer the compatibility target.

## D-002: Message registry

The base message IDs are fixed: `0x01` HANDSHAKE, `0x02` SESSION_CONFIRM, `0x03` DATA, `0x04` REKEY, and `0x05` CLOSE. All other values are reserved in v1.

## D-003: Strict schemas

Base messages use deterministic CBOR maps with unsigned integer keys. Definite lengths are mandatory. Duplicate and unknown keys are rejected. Extensions require a new protocol version or separately registered message type.

## D-004: Handshake transport

HANDSHAKE stage 0 carries the initiator signature and stage 1 carries both signatures. The transcript excludes signatures. REKEY reuses the handshake field contract with a mandatory previous session ID.

## D-005: AAD and nonce

DATA AAD is canonical CBOR containing version, session ID, message type, direction ID, and counter. The nonce is the 12-byte big-endian direction ID plus counter.

## D-006: Padding

The default padding quantum is 256 bytes. Padding is recalculated using the complete canonical plaintext map, including CBOR overhead, and is validated only after AEAD authentication.

## D-007: Errors

Errors are not a separate message type. A peer may receive a CLOSE reason, while local diagnostics remain secret-free and bounded.

## D-008: State safety

Failed candidate handshakes and rekeys never invalidate the active session. Transport reconnect preserves cryptographic state; process restart destroys it.

## D-009: Implementation gate

No Rust implementation was added until the protocol and reference document passed a two-pass wire-completeness review. That gate is approved; subsequent work remains subject to conformance tests and explicit protocol decisions.

## D-010: SAS dictionary artifact

The SAS dictionary is the 2048-word LF-delimited lowercase ASCII artifact at `https://raw.githubusercontent.com/bitcoin/bips/master/bip-0039/english.txt`. Its pinned SHA-256 is `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`. Implementations must verify the artifact before using it.

## D-011: Symmetric HELLO exchange

Stage 0 is a symmetric HELLO. Each peer sends protocol version, cipher suite, handshake purpose, role, its own persistent identity public key, its own fresh X25519 ephemeral public key, its own fresh 128-bit nonce, and the previous session ID when rekeying. The complete transcript is constructed only after both HELLOs arrive. This removes the prior sequencing contradiction without treating transport identity as authentication.
