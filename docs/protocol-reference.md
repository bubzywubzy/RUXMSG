# RUXMSG/1 Protocol Reference

This document is an implementation-facing reference for the RUXMSG/1 wire contract. The normative protocol specification is authoritative. If an implementation detail described here conflicts with the normative specification, the specification controls and this document must be corrected.

Use this reference when implementing or reviewing:

* frame construction and parsing;
* message-type registries;
* payload encoding;
* canonical CBOR requirements;
* cryptographic transcript inputs;
* authenticated DATA;
* rejection behavior;
* session and rekey semantics.

Use [`docs/architecture.md`](architecture.md) for implementation ownership and data flow, and [`docs/conformance-matrix.md`](conformance-matrix.md) for implementation and test status.

This document describes the protocol independently of the terminal client. A protocol feature being defined or implemented in the library does not imply that it is exposed through the current CLI.

## Version and Registry

The current protocol version is:

```text
Protocol version: 0x01
Protocol identifier: RUXMSG/1
```

The outer frame accepts payloads up to:

```text
MAX_FRAME_SIZE = 1,048,576 bytes
```

The message-type registry is:

| Type byte | Message           |
| --------: | ----------------- |
|    `0x01` | `HANDSHAKE`       |
|    `0x02` | `SESSION_CONFIRM` |
|    `0x03` | `DATA`            |
|    `0x04` | `REKEY`           |
|    `0x05` | `CLOSE`           |

`0x00` and `0x06`–`0xff` are currently unassigned and are rejected by the implementation.

The direction registry is:

| Direction ID | Meaning               |
| -----------: | --------------------- |
| `0x00000001` | Initiator → responder |
| `0x00000002` | Responder → initiator |

Unknown protocol versions, message types, and direction identifiers are rejected.

The current implementation also defines these protocol/session bounds:

| Parameter                       |                Value |
| ------------------------------- | -------------------: |
| Maximum frame payload           |    `1,048,576` bytes |
| Replay window                   |        `64` counters |
| Maximum skipped keys            |                 `64` |
| Default padding quantum         |          `256` bytes |
| Rekey interval                  |           `24 hours` |
| Rekey message limit             | `1,000,000` messages |
| Rekey predecessor drain timeout |         `15 seconds` |

These constants are implementation-level protocol/session contracts and should not be changed casually.

## Outer Frame

Every RUXMSG frame has a six-byte header followed by the declared payload:

```text
version:        1 byte
message_type:   1 byte
payload_length: 4 bytes, unsigned big-endian
payload:        payload_length bytes
```

The current implementation represents the frame as:

```text
+--------+------+----------------+----------------------+
| version| type | payload_length | payload              |
| 1 byte | 1 B  | 4 B, BE        | N bytes              |
+--------+------+----------------+----------------------+
```

`payload_length` is validated before the payload is accepted. Values greater than `1,048,576` bytes are rejected.

A frame decoder also rejects a truncated frame. The decoder returns the number of bytes consumed, allowing a complete frame to be separated from subsequent bytes in a stream.

The frame layer does not itself interpret the payload schema. Message-specific validation occurs above the outer framing layer.

## CBOR Encoding

RUXMSG protocol payloads use CBOR maps with unsigned integer keys.

The implementation's generic frame validator requires:

* the complete payload to decode successfully;
* exactly one complete CBOR value;
* the value to be a map;
* every map key to be an unsigned integer;
* no duplicate integer keys;
* canonical map ordering;
* no trailing bytes after the CBOR value.

The validator reconstructs the canonical integer-key map and compares its encoded representation against the received payload. A mismatch is rejected as non-canonical encoding.

Message-specific validators additionally enforce:

* required fields;
* permitted fields;
* field types;
* fixed byte-string lengths;
* numeric ranges;
* message-specific invariants.

Unknown fields are rejected by the corresponding message schema.

## HANDSHAKE — `0x01`

`HANDSHAKE` carries the protocol handshake `HELLO`.

The current HELLO structure contains the following fields:

| Key | Field                  | Encoding                                                    |
| --: | ---------------------- | ----------------------------------------------------------- |
| `0` | `protocol_version`     | unsigned integer                                            |
| `1` | `cipher_suite`         | unsigned integer                                            |
| `2` | `handshake_purpose`    | unsigned integer                                            |
| `3` | `role`                 | unsigned integer                                            |
| `4` | `identity_public_key`  | 32-byte byte string                                         |
| `5` | `ephemeral_public_key` | 32-byte byte string                                         |
| `6` | `nonce`                | 16-byte byte string                                         |
| `7` | `previous_session_id`  | absent for initial handshake; 16-byte byte string for rekey |

The protocol version is currently `1`.

The cipher-suite identifier is currently `1`.

`handshake_purpose` distinguishes:

```text
0 = initial session
1 = rekey
```

`role` distinguishes:

```text
0 = initiator
1 = responder
```

Each peer contributes its own HELLO. The peers construct the authenticated transcript from the handshake material after the required HELLO messages have been received.

The handshake uses ephemeral X25519 key agreement and authenticates the resulting transcript with the persistent Ed25519 identity.

Signatures are not part of the HELLO fields themselves; they are generated and verified as part of the authenticated handshake procedure.

For a rekey handshake, `previous_session_id` identifies the session being replaced.

## SESSION_CONFIRM — `0x02`

`SESSION_CONFIRM` confirms that both peers derived the same session state.

| Key | Field          | Encoding                                       |
| --: | -------------- | ---------------------------------------------- |
| `0` | `session_id`   | 16-byte byte string                            |
| `1` | `role`         | unsigned integer: `0` initiator, `1` responder |
| `2` | `confirmation` | 32-byte byte string                            |

The confirmation value is derived from session cryptographic material and the authenticated transcript. A confirmation failure prevents the candidate session from becoming established.

## DATA — `0x03`

Authenticated application data is carried in `DATA` messages.

| Key | Field             | Encoding                                       |
| --: | ----------------- | ---------------------------------------------- |
| `0` | `session_id`      | 16-byte byte string                            |
| `1` | `direction_id`    | unsigned integer                               |
| `2` | `message_counter` | unsigned 64-bit integer                        |
| `3` | `ciphertext`      | byte string containing ciphertext and AEAD tag |

The direction identifier is:

```text
0x00000001 = initiator → responder
0x00000002 = responder → initiator
```

The message counter is monotonically consumed by the directional ratchet and participates in authenticated encryption.

### Authenticated plaintext

The plaintext authenticated by the DATA AEAD layer is a canonical CBOR map containing:

```text
{
    0: content-bstr,
    1: padding-bstr
}
```

`content` contains the application bytes.

`padding` contains zero-valued bytes used to place the canonical plaintext into the protocol's configured padding quantum.

Padding is validated only after successful AEAD authentication. Unauthenticated ciphertext must not be interpreted as valid content or padding.

### AAD

The associated authenticated data contains the canonical encoding of the DATA header fields required by the protocol, including:

```text
version
session_id
message_type
direction_id
message_counter
```

The AAD binds the ciphertext to its protocol context, session, direction, and counter.

### Nonce

The DATA nonce is constructed from the direction identifier and message counter:

```text
BE32(direction_id) || BE64(message_counter)
```

The resulting value is 12 bytes, matching the ChaCha20-Poly1305 nonce size.

Nonce construction must remain deterministic and unique within the applicable key domain.

## REKEY — `0x04`

`REKEY` establishes a candidate replacement session.

Its handshake material uses the same HELLO field structure as the handshake path, with:

```text
handshake_purpose = 1
previous_session_id = existing session ID
```

`previous_session_id` is therefore required for a rekey.

A candidate session does not immediately replace the active session. It must complete authentication and session confirmation first.

Once confirmation succeeds, the session manager promotes the candidate and transitions the predecessor into its draining state according to the session lifecycle rules.

### Simultaneous rekey

If both peers initiate a rekey concurrently, the implementation resolves the competing candidates using an unsigned lexicographic comparison of the raw initiator Ed25519 public keys.

The comparison is performed on the public-key bytes themselves, not on their textual representation.

## CLOSE — `0x05`

`CLOSE` terminates or rejects a protocol/session interaction.

| Key | Field        | Encoding                                     |
| --: | ------------ | -------------------------------------------- |
| `0` | `session_id` | optional 16-byte byte string                 |
| `1` | `reason`     | unsigned integer                             |
| `2` | `detail`     | optional UTF-8 text, bounded by the protocol |

Current reason values are:

| Value | Meaning                |
| ----: | ---------------------- |
|   `0` | normal                 |
|   `1` | protocol error         |
|   `2` | authentication failure |
|   `3` | identity changed       |
|   `4` | resource limit         |
|   `5` | shutdown               |

Diagnostic details must not contain private keys, session keys, SAS values, application plaintext, or other secret material.

## Cryptographic Domains and Encodings

Security-sensitive byte construction is part of the protocol contract.

### Transcript hash

The transcript hash is domain-separated using the RUXMSG/1 transcript domain and includes the encoded transcript length:

```text
SHA-256(
    ASCII("RUXMSG/1/TRANSCRIPT") ||
    BE32(transcript_length) ||
    transcript
)
```

The transcript itself is constructed deterministically from the protocol handshake material.

### Identity signatures

The authenticated signature input consists of a role-specific domain followed by the 32-byte transcript hash:

```text
ASCII("RUXMSG/1/initiator") || transcript_hash
```

or:

```text
ASCII("RUXMSG/1/responder") || transcript_hash
```

The persistent identity algorithm is Ed25519.

### Session confirmation

Confirmation MAC input is role-separated:

```text
ASCII("RUXMSG/1/confirm/I") || transcript_hash
```

or:

```text
ASCII("RUXMSG/1/confirm/R") || transcript_hash
```

The confirmation result is 32 bytes.

### Key agreement and derivation

Session establishment uses:

* Ed25519 for persistent identity authentication;
* X25519 for ephemeral key agreement;
* SHA-256 for hashing;
* HKDF-SHA-256 for key derivation;
* HMAC-SHA-256 for confirmation/authentication material;
* ChaCha20-Poly1305 for DATA encryption.

Cryptographic domain strings, ordering, transcript construction, and KDF inputs are protocol values. Changes require a protocol decision and corresponding specification, vector, and test updates.

## Counters, Replay, and Skipped Keys

The protocol maintains bounded directional message state.

The current implementation defines:

```text
REPLAY_WINDOW_SIZE = 64
MAX_SKIPPED_KEYS   = 64
```

Receivers therefore do not maintain an unbounded set of historical message keys.

Inputs that fall outside the permitted replay window, repeat an already-consumed counter, or require a skipped-key gap beyond the configured bound are rejected.

Counter arithmetic must not wrap. Counter overflow is a protocol/state error rather than an opportunity to reuse nonce material.

## Padding

The default DATA padding quantum is:

```text
256 bytes
```

Padding is calculated against the complete canonical plaintext representation rather than against the application content alone.

Padding bytes are required to be zero.

Because padding is encrypted and authenticated together with the content, receivers inspect padding only after successful AEAD verification.

## Rejection Rules

Implementations must reject inputs that violate the applicable protocol invariants.

Important rejection classes include:

* unsupported protocol versions;
* unknown message types;
* invalid direction identifiers;
* oversized frames;
* truncated frames;
* malformed CBOR;
* trailing CBOR bytes;
* non-map payloads;
* non-integer map keys;
* duplicate map keys;
* non-canonical map encoding;
* unknown message fields;
* invalid field lengths;
* invalid field values;
* invalid signatures;
* failed session confirmation;
* rejected SAS verification;
* unexpected identity changes;
* replayed message counters;
* counters outside the permitted replay window;
* skipped-key gaps beyond the configured limit;
* invalid authenticated padding;
* counter exhaustion/overflow;
* resource-limit violations;
* invalid session lifecycle transitions.

A protocol error is handled locally by the implementation. Where the protocol requires peer notification, the implementation may send `CLOSE`; diagnostic information must remain non-secret.

## Session and Rekey Semantics

A successful handshake creates a fresh cryptographic session.

Active session state includes the directional ratchet and associated message-processing state. This state is process-local.

Rekeying creates a candidate session first. The candidate becomes active only after the required authentication and confirmation steps succeed.

The predecessor may remain temporarily available for draining according to the session manager's lifecycle policy. The current implementation bounds this drain period using the configured rekey drain timeout.

A process restart does not restore an active cryptographic session or its ratchet state. A new process establishes a new session.

## Implementation Boundary

The protocol reference describes the wire and cryptographic contract. It does not define:

* terminal UI behavior;
* peer labels;
* local profile management;
* message history;
* contact databases;
* offline delivery;
* Tailscale command behavior;
* application-level persistence.

Those concerns belong to the library/application layers rather than the RUXMSG/1 wire contract.

## Conformance Status

The protocol implementation and its verification status are tracked separately in [`docs/conformance-matrix.md`](conformance-matrix.md).

The repository contains deterministic vectors and integration tests for significant protocol and cryptographic behavior. Fuzzing infrastructure also exercises protocol parsing and session-state paths.

Passing repository tests demonstrates conformance to the tested cases. It does not by itself establish:

* independent interoperability with unrelated implementations;
* formal verification;
* resistance to every possible implementation flaw;
* an independent security audit;
* production readiness.

The protocol specification, implementation, tests, and conformance documentation should remain synchronized. Any change to a wire value, encoding rule, cryptographic input, rejection rule, or lifecycle invariant must be treated as a protocol change rather than an ordinary internal refactor.
