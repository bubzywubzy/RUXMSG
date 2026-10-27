# RUXMSG/1 protocol reference

Implementation-facing index of the wire contract. The authoritative source is the [specification](protocol-spec.md) (1.1 draft). If this document differs, the specification controls and this file must be corrected. Use the [architecture guide](architecture.md) for module context and the [conformance matrix](conformance-matrix.md) for implementation status. Items marked **(1.1)** are new in spec 1.1 and may not be implemented yet.

## Version and registries

- Protocol version byte: `0x01`; ASCII name `RUXMSG/1`.
- Version negotiation: none. Any other version: close the transport, no response.
- Cipher suite `0x01` only: Ed25519, X25519, SHA-256, HKDF-SHA-256, HMAC-SHA-256, ChaCha20-Poly1305.

| Type | Message | Used for |
| ---: | --- | --- |
| `0x01` | HANDSHAKE | COMMIT, HELLO, AUTH of an **initial** handshake |
| `0x02` | SESSION_CONFIRM | confirmation, initial or rekey |
| `0x03` | DATA | encrypted application data |
| `0x04` | REKEY | COMMIT, HELLO, AUTH of a **rekey** handshake |
| `0x05` | CLOSE | shutdown |

`0x00` and `0x06`-`0xff` are reserved and rejected.

## Frame

```text
version:        1 byte, exactly 0x01
type:           1 byte, registry value
payload_length: 4 bytes, unsigned big-endian
payload:        payload_length bytes, one definite-length deterministic CBOR map
```

Validate version, type and length before allocating. Reject truncation, trailing payload bytes, malformed or non-canonical CBOR, duplicate, unknown or non-integer keys, and wrong types or lengths.

## Limits and constants

| Constant | Value |
| --- | ---: |
| Max payload (any frame) | 1,048,576 |
| Max payload HANDSHAKE / REKEY **(1.1)** | 1,024 |
| Max payload SESSION_CONFIRM **(1.1)** | 128 |
| Max payload CLOSE **(1.1)** | 256 |
| `MAX_CONTENT` per DATA message **(1.1)** | 65,536 |
| Padding quantum (ciphertext, incl. tag) | 256 |
| Replay window | 64 |
| `MAX_SKIPPED_KEYS` (cache ceiling 128) | 64 |
| Rekey interval / message count | 24 h / 1,000,000 |
| `REKEY_DRAIN_TIMEOUT` | 15 s |
| Handshake frame read timeout **(1.1)** | 15 s |
| SAS decision timeout **(1.1)** | 120 s |
| Total handshake deadline **(1.1)** | 180 s |
| Concurrent unauthenticated handshakes **(1.1)** | 4 |

## Payload schemas

All keys are unsigned integers; all maps are deterministic CBOR; unknown keys are rejected.

Common types: identity, ephemeral, transcript hash, MAC, commitment = 32-byte bstr; nonce, session ID = 16-byte bstr; signature = 64-byte bstr.

### COMMIT **(1.1)** (HANDSHAKE or REKEY)

| Key | Field | Encoding |
| ---: | --- | --- |
| 0 | `protocol_version` | uint `1` |
| 1 | `cipher_suite` | uint `1` |
| 2 | `handshake_purpose` | uint `0` initial, `1` rekey |
| 3 | `commitment` | 32-byte bstr |
| 4 | `previous_session_id` | absent for initial; 16-byte bstr for rekey |

`commitment = SHA-256("RUXMSG/1/COMMIT" || BE32(L) || P)` where `P` is the exact payload bytes of the initiator HELLO and `L = len(P)`.

### HELLO (HANDSHAKE or REKEY)

| Key | Field | Encoding |
| ---: | --- | --- |
| 0 | `protocol_version` | uint `1` |
| 1 | `cipher_suite` | uint `1` |
| 2 | `handshake_purpose` | uint `0` initial, `1` rekey |
| 3 | `role` | uint `0` initiator, `1` responder |
| 4 | `identity_public_key` | 32-byte bstr |
| 5 | `ephemeral_public_key` | 32-byte bstr |
| 6 | `nonce` | 16-byte bstr |
| 7 | `previous_session_id` | absent for initial; 16-byte bstr for rekey |

Order: initiator COMMIT, responder HELLO, initiator HELLO (revealing the commitment). Each HELLO carries only its sender's values. The frame type must match the purpose (HANDSHAKE for `0`, REKEY for `1`).

### Transcript (never sent; hashed)

| Key | Field |
| ---: | --- |
| 0 | `protocol_version` (1) |
| 1 | `cipher_suite` (1) |
| 2 | `handshake_type` (0 or 1) |
| 3 | `initiator_role` (0) |
| 4 | `responder_role` (1) |
| 5 | `previous_session_id` (rekey only) |
| 6 | `initiator_identity` |
| 7 | `responder_identity` |
| 8 | `initiator_ephemeral` |
| 9 | `responder_ephemeral` |
| 10 | `initiator_nonce` |
| 11 | `responder_nonce` |

### AUTH (HANDSHAKE or REKEY)

| Key | Field | Encoding |
| ---: | --- | --- |
| 0 | `handshake_type` | uint `0` or `1` |
| 1 | `stage` | uint `0` initiator, `1` responder |
| 2 | `cipher_suite` | uint `1` |
| 3 | `initiator_identity` | 32-byte bstr |
| 4 | `responder_identity` | 32-byte bstr |
| 5 | `initiator_ephemeral` | 32-byte bstr |
| 6 | `responder_ephemeral` | 32-byte bstr |
| 7 | `initiator_nonce` | 16-byte bstr |
| 8 | `responder_nonce` | 16-byte bstr |
| 9 | `previous_session_id` | rekey only |
| 10 | `initiator_signature` | 64-byte bstr, required |
| 11 | `responder_signature` | 64-byte bstr, stage 1 only |

Echoed fields must equal the receiver's locally built transcript **(1.1)**. Stage 0 has no responder signature; stage 1 requires it.

### SESSION_CONFIRM

| Key | Field | Encoding |
| ---: | --- | --- |
| 0 | `session_id` | 16-byte bstr |
| 1 | `role` | uint `0` initiator, `1` responder |
| 2 | `confirmation` | 32-byte bstr |

### DATA

| Key | Field | Encoding |
| ---: | --- | --- |
| 0 | `session_id` | 16-byte bstr |
| 1 | `direction_id` | uint `1` or `2`, must match the sender's role |
| 2 | `message_counter` | uint64 |
| 3 | `ciphertext` | bstr, at least 16 bytes (includes tag) |

Plaintext is exactly `{0: content, 1: padding}`; padding is all `0x00`. Padding is chosen so `len(plaintext map) + 16` is a multiple of 256 (D-014), recomputing the CBOR overhead of the padding field until stable. Padding is inspected only after AEAD authentication.

AAD is the canonical CBOR of `{0: 1, 1: session_id, 2: 3, 3: direction_id, 4: message_counter}`. Nonce is `BE32(direction_id) || BE64(message_counter)`.

### CLOSE

| Key | Field | Encoding |
| ---: | --- | --- |
| 0 | `session_id` | optional 16-byte bstr; required when a session exists |
| 1 | `reason` | uint `0` normal, `1` protocol error, `2` authentication failure, `3` identity changed, `4` resource limit, `5` shutdown |
| 2 | `detail` | optional UTF-8 text, at most 128 bytes |

CLOSE is unauthenticated (D-017). Ignore a CLOSE naming an unknown session. Diagnostics never carry secrets or plaintext.

## Security-sensitive encodings

- Transcript hash: `SHA-256("RUXMSG/1/TRANSCRIPT" || BE32(len(T)) || T)`.
- Signature input: `"RUXMSG/1/initiator"` or `"RUXMSG/1/responder"` followed by the 32-byte transcript hash.
- Confirmation input: `"RUXMSG/1/confirm/I"` or `"RUXMSG/1/confirm/R"` followed by the transcript hash, under HMAC-SHA-256 with the confirmation key.
- Key schedule: `HKDF-Extract(salt = TranscriptHash, IKM = DH)`; expand labels `RUXMSG/1/root`, `I-to-R`, `R-to-I`, `session-id` (16 bytes), `session-confirm`.
- Message keys: `HKDF-Extract(salt = 32 zero bytes, IKM = CK)`; expand `"RUXMSG/1/message-key" || BE32(direction)` and `"RUXMSG/1/chain-key" || BE32(direction)`.
- Direction IDs: `1` initiator to responder, `2` responder to initiator.
- SAS: first 33 bits of the transcript hash, MSB first, as three 11-bit indices into the BIP-0039 English word list.

## Rejection rules

Reject: unsupported version or type, malformed or non-canonical CBOR, duplicate or unknown keys, invalid lengths, `cipher_suite` other than 1, commitment mismatch, AUTH not matching the local transcript, invalid signature or confirmation, SAS rejection, rekey with the wrong previous session or a changed identity, replayed or out-of-window counters, gaps over 64 or a full key cache, invalid padding, counter overflow, DATA before ACTIVE, and resource-limit violations. Errors are local outcomes; peers are notified with CLOSE and no secret-bearing detail.

## Implementation status

See the [conformance matrix](conformance-matrix.md). Passing primitive or integration tests does not establish independent interoperability or production readiness.
