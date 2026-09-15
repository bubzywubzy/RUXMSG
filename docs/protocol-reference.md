# RUXMSG/1 Protocol Reference

This document is an implementation-facing index of the normative wire contract. The authoritative specification is [`../protocol-spec.md`](../protocol-spec.md), especially **Appendix E — Normative Wire Contract**. If this document differs from the specification, `protocol-spec.md` controls and this document must be corrected before implementation begins.

Use this reference when implementing or reviewing a frame, payload, rejection rule, or cryptographic encoding. Use the [architecture guide](architecture.md) for module/data-flow context and the [conformance matrix](conformance-matrix.md) for implementation and test status. This document does not imply that every protocol feature is integrated into the current CLI.

## Version and registry

- Protocol version byte: `0x01`
- ASCII protocol identifier: `RUXMSG/1`
- Maximum CBOR payload: `1,048,576` bytes
- Unknown versions and message types: reject

| Type byte | Message |
| ---: | --- |
| `0x01` | `HANDSHAKE` |
| `0x02` | `SESSION_CONFIRM` |
| `0x03` | `DATA` |
| `0x04` | `REKEY` |
| `0x05` | `CLOSE` |

`0x00` and `0x06`–`0xff` are reserved.

The sole cipher suite is `0x01`: Ed25519, X25519, SHA-256, HKDF-SHA-256, HMAC-SHA-256, and ChaCha20-Poly1305.

## Frame

```text
version:       1 byte, exactly 0x01
type:          1 byte, registry value
payload_length:4 bytes, unsigned big-endian
payload:       payload_length bytes, one definite-length CBOR map
```

The declared length must be validated before allocation and must not exceed 1 MiB. Truncation, trailing payload bytes, malformed CBOR, duplicate keys, unknown keys, and non-canonical encoding are rejected.

## Payload schemas

All keys are unsigned integers and all maps use RFC 8949 deterministic encoding. Base messages reject unknown keys.

### `HANDSHAKE` (`0x01`)

The first HANDSHAKE payload from each peer is a symmetric `HELLO`:

| Key | Field | Encoding |
| ---: | --- | --- |
| 0 | `protocol_version` | uint: `1` |
| 1 | `cipher_suite` | uint: `1` |
| 2 | `handshake_purpose` | uint: `0` initial, `1` rekey |
| 3 | `role` | uint: `0` initiator, `1` responder |
| 4 | `identity_public_key` | 32-byte bstr |
| 5 | `ephemeral_public_key` | 32-byte bstr |
| 6 | `nonce` | 16-byte bstr |
| 7 | `previous_session_id` | absent for initial; 16-byte bstr for rekey |

The initiator and responder each send one HELLO containing only their own fields. Both peers construct the transcript after both HELLOs arrive. The later authenticated signature stage uses the transcript and carries signatures separately; signatures are not part of HELLO.

### `SESSION_CONFIRM` (`0x02`)

| Key | Field | Encoding |
| ---: | --- | --- |
| 0 | `session_id` | 16-byte bstr |
| 1 | `role` | uint: `0` initiator or `1` responder |
| 2 | `confirmation` | 32-byte bstr |

### `DATA` (`0x03`)

| Key | Field | Encoding |
| ---: | --- | --- |
| 0 | `session_id` | 16-byte bstr |
| 1 | `direction_id` | uint: `1` or `2` |
| 2 | `message_counter` | uint64 |
| 3 | `ciphertext` | bstr, at least 16 bytes including the AEAD tag |

The authenticated plaintext is exactly `{0: content-bstr, 1: padding-bstr}`. Padding is all zero bytes and is calculated against the complete canonical plaintext map using the 256-byte quantum. Padding is inspected only after AEAD authentication.

The AAD is the canonical CBOR encoding of `{0: 1, 1: session_id, 2: 3, 3: direction_id, 4: message_counter}`. The nonce is `BE32(direction_id) || BE64(message_counter)`.

### `REKEY` (`0x04`)

`REKEY` uses the `HANDSHAKE` fields and encodings with `handshake_type=1`; `previous_session_id` is required. The candidate session is not active until confirmation succeeds. Simultaneous rekeys are resolved by unsigned lexicographic comparison of the raw initiator Ed25519 public keys.

### `CLOSE` (`0x05`)

| Key | Field | Encoding |
| ---: | --- | --- |
| 0 | `session_id` | optional 16-byte bstr |
| 1 | `reason` | uint: `0` normal, `1` protocol error, `2` authentication failure, `3` identity changed, `4` resource limit, `5` shutdown |
| 2 | `detail` | optional UTF-8 text, at most 128 bytes |

Diagnostics never carry secrets or application plaintext.

## Security-sensitive encodings

- Transcript hash: `SHA-256(ASCII("RUXMSG/1/TRANSCRIPT") || BE32(transcript_length) || transcript)`.
- Signature input: ASCII domain (`RUXMSG/1/initiator` or `RUXMSG/1/responder`) followed by the 32-byte transcript hash.
- Confirmation input: ASCII domain (`RUXMSG/1/confirm/I` or `RUXMSG/1/confirm/R`) followed by the transcript hash.
- Direction IDs: `0x00000001` initiator-to-responder; `0x00000002` responder-to-initiator.
- Message counters: unsigned 64-bit big-endian in nonces and AAD.

## Rejection rules

Reject unsupported versions/types, malformed or non-canonical CBOR, duplicate/unknown keys, invalid lengths, invalid signatures or confirmations, SAS rejection, identity changes, replayed/out-of-window counters, skipped-key gaps over 64, invalid padding, counter overflow, and resource-limit violations. Errors are local outcomes; peer notification uses `CLOSE` without secret-bearing diagnostics.

## Implementation status

The wire contract has passed the repository's protocol-design gate and is implemented in the conformance foundation to the extent shown in the [conformance matrix](conformance-matrix.md). Passing primitive or integration tests does not establish independent interoperability or production readiness. Those require complete product integration and external review.
