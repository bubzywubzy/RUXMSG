# RUXMSG/1 — Volatile Peer-to-Peer Encrypted Messaging

**Protocol:** RUXMSG/1
**Specification version:** 1.1 (draft, supersedes 1.0)
**Status:** Normative. Items marked **[CLOSED]** are new in 1.1 and need owner confirmation (see Appendix B). The reference implementation already follows them; see the conformance matrix.
**Scope:** Two-party, direct, end-to-end encrypted, volatile messaging. Groups, anonymity features and offline delivery are RUXMSG/2 (Appendix C) and are **not** part of this document.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119.

---

## 1. Purpose, Scope, and Security Model

### 1.1 What RUXMSG/1 is

RUXMSG/1 is a terminal-oriented protocol for two peers who reach each other directly over a reliable byte stream (TCP, typically over Tailscale). It provides:

- application-layer end-to-end encryption with no server;
- a persistent Ed25519 identity per profile;
- human-verified authentication (SAS) of **every** connection;
- a fresh X25519 session per connection, with automatic rekeying;
- per-message symmetric ratcheting, replay protection and bounded reordering;
- deterministic wire encoding and bounded resource use.

### 1.2 RUXMSG/1 scope table

| Capability | RUXMSG/1 | RUXMSG/2 |
| --- | :---: | :---: |
| Two-party direct E2EE messaging | ✅ | ✅ |
| Persistent identity keypair (stable fingerprint) | ✅ | ✅ |
| SAS verification on every connection | ✅ | ✅ |
| Rekeying with in-session identity continuity | ✅ | ✅ |
| Groups / multi-party | ❌ | planned |
| Anonymity / metadata-protection features | ❌ | planned |
| Store-and-forward / peer-assisted offline delivery | ❌ | planned |
| Session resumption | ❌ | undecided |

### 1.3 Volatile by definition

RUXMSG/1 persists **exactly one** item: the local Ed25519 identity seed, held in the operating-system credential store. All of the following are volatile and MUST NOT be written to disk, logs, or any credential store:

peer identities and fingerprints, peer addresses, trust or approval state, SAS approvals, session IDs, ephemeral keys, chain and message keys, skipped keys, replay state, counters, message plaintext and history, and profile-enumeration metadata.

A process exit, crash, or transport loss ends the session (see §6). A new connection is a new handshake with a new SAS.

### 1.4 Network model

The transport is untrusted. It may observe, capture, replay, reorder, duplicate, drop, modify, inject, delay, or terminate traffic. RUXMSG security MUST NOT depend on the transport. A Tailscale IP, hostname, username, or device name MUST NOT be treated as evidence of peer identity.

### 1.5 Non-goals

RUXMSG/1 does not provide anonymity, metadata confidentiality, traffic-analysis resistance, deniability, post-compromise recovery beyond periodic rekeying, protection from a compromised endpoint, or recovery of a lost identity key.

---

## 2. Cryptographic Suite

| Function | Algorithm |
| --- | --- |
| Persistent identity / signatures | Ed25519 |
| Ephemeral key agreement | X25519 |
| Hash | SHA-256 |
| KDF | HKDF-SHA-256 |
| Confirmation | HMAC-SHA-256 |
| Message AEAD | ChaCha20-Poly1305 |
| Structured encoding | Deterministic CBOR (RFC 8949 §4.2) |
| SAS dictionary | BIP-0039 English word list |

Cipher suite `0x01` is the only suite. Implementations MUST use reviewed libraries and MUST NOT implement primitives themselves.

- **Identity keys** MUST NOT be reused as X25519 keys.
- **X25519**: a fresh keypair per handshake; an all-zero shared secret MUST be rejected.
- **Ed25519 verification** SHOULD use strict verification (reject non-canonical signatures and small-order keys).
- **HKDF labels** all begin with the domain `RUXMSG/1/`.

---

## 3. Identity and Authentication Model

### 3.1 Identity

A RUXMSG identity is one 32-byte Ed25519 public key. Its private seed never leaves the installation.

### 3.2 Fingerprint

The fingerprint of an identity is the lowercase hexadecimal encoding of its 32-byte public key (64 characters). UIs MAY group characters for readability but MUST NOT truncate the value where it is used for verification.

### 3.3 No trust store

RUXMSG/1 defines no trust store. Receiving a public key confers no trust, and a previously seen identity confers no exemption from verification. Therefore:

1. **Every** connection, initial or after a restart or disconnect, requires SAS approval by **both** users.
2. Implementations MUST NOT skip the SAS based on remembered identity, address, or prior approval.
3. Implementations SHOULD display the peer's full fingerprint at every connection so users can additionally compare it against a fingerprint they already know.

The SAS is computed over a transcript that contains both identity keys (§5.4). An approved SAS therefore authenticates the peer's identity for that session, provided the commitment step in §5.2 is followed.

### 3.4 Identity continuity within a session

After a session is established, the peer identity is fixed for that session and for every rekey of it (§8). A rekey that presents a different identity MUST be discarded.

---

## 4. Wire Format

### 4.1 Frame

| Offset | Size | Field | Encoding |
| ---: | ---: | --- | --- |
| 0 | 1 | Version | `0x01` |
| 1 | 1 | Type | registry value (§4.2) |
| 2 | 4 | PayloadLength | unsigned big-endian |
| 6 | N | Payload | one definite-length deterministic CBOR map |

A receiver MUST validate version, type and length **before** allocating or reading the payload, MUST read exactly N bytes, MUST reject EOF before N bytes, and MUST reject trailing bytes inside the payload. Any malformed, truncated, or oversized frame terminates the candidate session or the session.

### 4.2 Registries

| Type | Name | Used for |
| ---: | --- | --- |
| `0x01` | HANDSHAKE | COMMIT, HELLO, AUTH of an **initial** handshake |
| `0x02` | SESSION_CONFIRM | confirmation of an initial or rekey candidate |
| `0x03` | DATA | encrypted application data |
| `0x04` | REKEY | COMMIT, HELLO, AUTH of a **rekey** handshake |
| `0x05` | CLOSE | session/connection shutdown |
| `0x00`, `0x06`–`0xff` | reserved | MUST be rejected |

Version `0x01` is the only version; there is no negotiation. A receiver of any other version MUST close the transport without a protocol response and MUST NOT downgrade.

### 4.3 Size limits

The absolute maximum payload is 1 MiB (1,048,576 bytes). **[CLOSED]** Per-type limits apply, checked from the type byte before allocation:

| Type | Max payload |
| --- | ---: |
| HANDSHAKE, REKEY | 1,024 bytes |
| SESSION_CONFIRM | 128 bytes |
| CLOSE | 256 bytes |
| DATA | 1,048,576 bytes |

DATA frames MUST NOT be accepted before the session is ACTIVE (or REKEYING/DRAINING). Application content per DATA message is limited to `MAX_CONTENT = 65,536` bytes **[CLOSED]**; senders MUST split larger messages.

### 4.4 Deterministic CBOR

All payloads are CBOR maps with unsigned-integer keys in shortest form, sorted per RFC 8949 deterministic ordering. Receivers MUST use definite lengths, and MUST reject: malformed CBOR, duplicate keys, unknown keys, non-integer keys, trailing bytes, non-shortest integers, missing required keys, and wrong value types or lengths. No extension keys exist in RUXMSG/1.

### 4.5 Fixed-size types

| Type | Encoding |
| --- | --- |
| IdentityPublicKey, EphemeralPublicKey, TranscriptHash, ConfirmationMAC, Commitment | byte string, 32 bytes |
| Nonce, SessionID | byte string, 16 bytes |
| Signature | byte string, 64 bytes |
| Ciphertext | byte string, ≥ 16 bytes (final 16 are the AEAD tag) |

---

## 5. Handshake

The same handshake runs for an initial session and for a rekey. It differs in `handshake_purpose`, in the frame type used (HANDSHAKE vs REKEY), and in how the peer is authenticated (SAS vs identity continuity, §8).

### 5.1 Message flow

```text
Initiator                                   Responder
   | -- COMMIT (H(initiator HELLO)) ------->  |
   | <------------------- HELLO (responder) -- |
   | -- HELLO (initiator, reveals commit) --> |   responder verifies commitment
   |        both build transcript, hash, SAS   |
   |        both users compare SAS; approve    |
   | -- AUTH stage 0 (Sig_I) ---------------> |   responder verifies Sig_I
   | <----------- AUTH stage 1 (Sig_I,Sig_R) -- |   initiator verifies Sig_R
   | -- SESSION_CONFIRM (role 0) ------------> |
   | <----------------- SESSION_CONFIRM (1) -- |
                       ACTIVE
```

### 5.2 COMMIT **[CLOSED — D-012]**

A SAS is only 33 bits. If a man-in-the-middle can choose its handshake values after seeing the other side's values, it can grind nonces offline until the SAS on both of its connections matches, and the human check then proves nothing. To prevent this, the initiator commits before it sees any responder value.

The initiator first sends COMMIT:

| Key | Field | Type | Required |
| ---: | --- | --- | --- |
| 0 | protocol_version | uint, 1 | yes |
| 1 | cipher_suite | uint, 1 | yes |
| 2 | handshake_purpose | uint, 0 initial / 1 rekey | yes |
| 3 | commitment | 32 bytes | yes |
| 4 | previous_session_id | SessionID | rekey only |

`commitment = SHA-256("RUXMSG/1/COMMIT" || BE32(L) || P)` where `P` is the exact payload bytes of the initiator HELLO that will be sent in step 3 and `L` is its length.

The responder MUST NOT send its HELLO until it has a valid COMMIT. The initiator MUST NOT send its HELLO until it has received the responder HELLO. The responder MUST verify that the revealed initiator HELLO hashes to the commitment (constant-time compare) and that `protocol_version`, `cipher_suite`, `handshake_purpose`, and `previous_session_id` match the COMMIT. Failure aborts the handshake.

### 5.3 HELLO

Each peer sends one HELLO containing only its own values.

| Key | Field | Type | Required |
| ---: | --- | --- | --- |
| 0 | protocol_version | uint, 1 | yes |
| 1 | cipher_suite | uint, 1 | yes |
| 2 | handshake_purpose | uint, 0 initial / 1 rekey | yes |
| 3 | role | uint, 0 initiator / 1 responder | yes |
| 4 | identity_public_key | IdentityPublicKey | yes |
| 5 | ephemeral_public_key | EphemeralPublicKey | yes |
| 6 | nonce | Nonce (fresh CSPRNG) | yes |
| 7 | previous_session_id | SessionID | rekey only |

Receivers MUST reject `cipher_suite ≠ 1`, `protocol_version ≠ 1`, an unexpected role, a HELLO whose purpose disagrees with the frame type, and a `previous_session_id` present for an initial or absent for a rekey. The two HELLOs MUST agree on version, suite, purpose and previous session ID. A peer MUST reject a HELLO carrying its own identity key or a replay of its own HELLO.

### 5.4 Transcript

The transcript is the deterministic CBOR map below, built by both peers only after both HELLOs are available. It contains no signatures.

| Key | Field |
| ---: | --- |
| 0 | protocol_version (1) |
| 1 | cipher_suite (1) |
| 2 | handshake_type (0 initial / 1 rekey) |
| 3 | initiator_role (0) |
| 4 | responder_role (1) |
| 5 | previous_session_id (rekey only; absent otherwise) |
| 6 | initiator_identity |
| 7 | responder_identity |
| 8 | initiator_ephemeral |
| 9 | responder_ephemeral |
| 10 | initiator_nonce |
| 11 | responder_nonce |

```text
TranscriptHash = SHA-256("RUXMSG/1/TRANSCRIPT" || BE32(len(T)) || T)
```

### 5.5 SAS

The SAS dictionary is the exact 2048-word BIP-0039 English list (`english.txt`, LF-delimited lowercase ASCII, SHA-256 `2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`), verified before use. Only the ordered list is used; the BIP-0039 checksum and mnemonic procedure are not.

Let `H = TranscriptHash`. Take its first 33 bits, most-significant-bit first, as three 11-bit indices:

```text
S  = (H[0] << 25) | (H[1] << 17) | (H[2] << 9) | (H[3] << 1) | (H[4] >> 7)
W0 = (S >> 22) & 0x7ff     W1 = (S >> 11) & 0x7ff     W2 = S & 0x7ff
SAS = WORD[W0] WORD[W1] WORD[W2]
```

There is no modulo; the words are indexed directly. An incorrect session matches with probability 2⁻³³, **provided COMMIT (§5.2) is honored**.

### 5.6 SAS approval (initial handshakes)

Both users MUST compare the SAS through an independent human channel and MUST both approve. The implementation:

- MUST label the value as a Short Authentication String and show the peer fingerprint and which connection it belongs to;
- MUST require a deliberate affirmative action, such as typing `yes` and pressing Enter. A single stray keypress MUST NOT approve;
- MUST treat any other input, a timeout (§11), or a closed connection as rejection;
- on rejection MUST abort, destroy all candidate state, and send no signature.

Rekey handshakes do **not** use SAS (§8).

### 5.7 AUTH

After approval each peer authenticates the transcript.

```text
Sig_I = Ed25519.Sign(IdentityPriv_I, "RUXMSG/1/initiator" || TranscriptHash)
Sig_R = Ed25519.Sign(IdentityPriv_R, "RUXMSG/1/responder" || TranscriptHash)
```

AUTH payload keys:

| Key | Field | Notes |
| ---: | --- | --- |
| 0 | handshake_type | 0 / 1 |
| 1 | stage | 0 = initiator AUTH, 1 = responder AUTH |
| 2 | cipher_suite | 1 |
| 3 | initiator_identity | |
| 4 | responder_identity | |
| 5 | initiator_ephemeral | |
| 6 | responder_ephemeral | |
| 7 | initiator_nonce | |
| 8 | responder_nonce | |
| 9 | previous_session_id | rekey only |
| 10 | initiator_signature | required |
| 11 | responder_signature | stage 1 only |

Receivers MUST rebuild the transcript **from the HELLOs they exchanged themselves** and MUST reject an AUTH whose echoed fields (keys 0, 2–9) differ from it in any way. Signatures are verified over the locally computed TranscriptHash, never over a hash derived solely from AUTH contents. The responder MUST verify Sig_I before sending its own signature.

### 5.8 Key schedule

```text
PRK = HKDF-Extract(salt = TranscriptHash, IKM = DH)
RootKey              = Expand(PRK, "RUXMSG/1/root", 32)
InitiatorToResponder = Expand(PRK, "RUXMSG/1/I-to-R", 32)
ResponderToInitiator = Expand(PRK, "RUXMSG/1/R-to-I", 32)
SessionID            = Expand(PRK, "RUXMSG/1/session-id", 16)
ConfirmationKey      = Expand(PRK, "RUXMSG/1/session-confirm", 32)
```

RootKey is reserved and MUST NOT encrypt messages. Directional keys MUST NOT be interchanged.

### 5.9 SESSION_CONFIRM

| Key | Field | Type |
| ---: | --- | --- |
| 0 | session_id | SessionID |
| 1 | role | uint, 0 initiator / 1 responder |
| 2 | confirmation | ConfirmationMAC |

```text
Confirm_I = HMAC-SHA-256(ConfirmationKey, "RUXMSG/1/confirm/I" || TranscriptHash)
Confirm_R = HMAC-SHA-256(ConfirmationKey, "RUXMSG/1/confirm/R" || TranscriptHash)
```

Confirmations are verified in constant time. An unknown session ID, wrong role, wrong length, or bad MAC fails the candidate without touching any active session. The session becomes ACTIVE only after both confirmations verify.

---

## 6. Session Lifecycle

### 6.1 States

`HANDSHAKING`, `ACTIVE`, `REKEYING`, `DRAINING`, `CLOSED`.

- ACTIVE and REKEYING sessions may send and receive DATA.
- DRAINING sessions may receive eligible in-flight DATA and MUST NOT originate DATA.
- Exactly one session is ever the sending session.

### 6.2 Process exit

All session state is destroyed on exit or crash. The identity seed persists; nothing else does. DATA for a destroyed or unknown session ID MUST be rejected.

### 6.3 Transport loss **[CLOSED — D-013]**

In RUXMSG/1 a session is bound to exactly one transport connection. When the connection ends for any reason, the session moves to CLOSED and its state is destroyed. Reconnecting is a new handshake with a new SAS. No resumption mechanism exists in RUXMSG/1. This removes the need for any counter or nonce continuity across connections: state is never carried over, so nonce reuse across connections is impossible by construction.

### 6.4 Transition table

See Appendix A.

---

## 7. Message Protection

### 7.1 Chains and keys

Each direction has an independent chain. For chain key `CK_n`:

```text
PRK_n  = HKDF-Extract(salt = 32 zero bytes, IKM = CK_n)
MK_n   = HKDF-Expand(PRK_n, "RUXMSG/1/message-key" || BE32(DirectionID), 32)
CK_n+1 = HKDF-Expand(PRK_n, "RUXMSG/1/chain-key"   || BE32(DirectionID), 32)
```

A message key MUST NOT be reused. Previous chain keys and used message keys MUST be erased (§10.2).

### 7.2 Counters and nonces

Counters are unsigned 64-bit per direction, starting at 0. Direction IDs: `1` initiator→responder, `2` responder→initiator. The 96-bit nonce is `BE32(DirectionID) || BE64(counter)`. A sender MUST initiate or complete rekeying before sending a DATA frame with counter u64::MAX. u64::MAX is therefore not a valid DATA message counter.

### 7.3 DATA payload and AAD

| Key | Field | Type |
| ---: | --- | --- |
| 0 | session_id | SessionID |
| 1 | direction_id | uint, 1 or 2 (MUST match sender's role) |
| 2 | message_counter | uint64 |
| 3 | ciphertext | Ciphertext |

AAD is the canonical CBOR of `{0: 1, 1: session_id, 2: 3, 3: direction_id, 4: message_counter}` (version, session ID, DATA type, direction, counter).

### 7.4 Plaintext and padding **[amended — D-014]**

The AEAD plaintext is exactly `{0: content (bstr), 1: padding (bstr)}`. Padding is all `0x00`. The default quantum is 256 bytes and is measured on the **ciphertext**: the sender chooses the smallest padding length such that `len(canonical plaintext map) + 16` (AEAD tag) is a multiple of 256, recomputing the CBOR overhead of the padding field until stable. Content larger than `MAX_CONTENT` or a plaintext that would exceed the frame limit MUST be rejected by the sender.

Padding is inspected only after AEAD authentication.

### 7.5 Receive procedure

A receiver MUST perform these steps in order and MUST NOT mutate ratchet or replay state before step 7:

1. Validate the frame and DATA map (§4).
2. Require `session_id` to match a receiving session and `direction_id` to equal that receiver's fixed direction.
3. Classify the counter against the replay window; reject duplicates and out-of-window counters.
4. **Prepare** the message key: derive skipped keys within the bounds of §7.7 and cache them, and cache the target key without consuming it.
5. AEAD-decrypt with the prepared key. Failure leaves all cached keys intact and marks nothing accepted.
6. Parse the plaintext map, require both keys exactly once, verify every padding byte is `0x00`.
7. **Commit**: consume the message key and record the counter in the replay window.
8. Deliver the content once.

### 7.6 Replay window

64 messages per direction. Bit 0 is the highest accepted counter, bit 63 is highest − 63. Duplicates and counters ≥ 64 below the highest MUST be rejected.

### 7.7 Skipped and prepared keys

`MAX_SKIPPED_KEYS = 64`. Limits the number of intermediate keys derived before the requested target key. The target key itself is not counted against this limit. A frame is rejected if its counter is more than 64 ahead of the next expected counter, or if the key cache already holds 64 or more keys. Consequently the cache never exceeds 128 keys. No attacker-supplied counter may cause unbounded CPU, memory, derivation, or state growth. Unauthenticated frames can advance derivation only within this bound.

### 7.8 Ordering

The cryptographic layer authenticates each message and rejects duplicates; it does not guarantee delivery order. Ordered delivery is an application concern (TCP already provides it in practice).

---

## 8. Rekeying

### 8.1 Triggers

A rekey begins at the first of: 24 hours since ACTIVE; 1,000,000 DATA messages sent by the local peer or accepted from the remote peer; or an explicit request. Either peer may initiate.

### 8.2 Authentication by identity continuity **[CLOSED — D-015]**

A rekey uses the §5 handshake with `handshake_purpose = 1`, frame type REKEY, and a required `previous_session_id`. It does **not** require SAS. Instead the receiver MUST verify all of the following, and MUST discard the candidate on any failure:

1. `previous_session_id` equals the current ACTIVE session's ID;
2. the remote identity key equals the identity authenticated in the current session;
3. the local identity key is unchanged;
4. both signatures verify over the locally computed transcript.

A rekey never changes the peer identity. An on-path attacker who was not already authenticated cannot produce these signatures.

### 8.3 Candidate, promotion and drain

The candidate stays non-active until both SESSION_CONFIRM messages verify. Then the candidate becomes ACTIVE and the old session becomes DRAINING for `REKEY_DRAIN_TIMEOUT = 15 s`, after which it MUST be destroyed with all keys, replay state and metadata. During the handshake the old session keeps sending and receiving; DATA and CLOSE frames that arrive between handshake frames MUST be buffered and processed, not dropped.

### 8.4 Failed rekey

A failed or timed-out candidate is discarded; the old session returns to ACTIVE and remains usable. A failed rekey MUST NOT prevent a later rekey attempt.

### 8.5 Glare

If both peers send a rekey COMMIT for the same `previous_session_id`, compare the two raw 32-byte identity keys as unsigned lexicographic byte strings. The greater key remains initiator and ignores the competing COMMIT; the lesser abandons its attempt, discards its commitment and ephemeral, and answers as responder with a fresh HELLO. Display names, hostnames, Tailscale addresses and fingerprint strings MUST NOT be used. No second candidate may be created, and queued application DATA is not lost.

---

## 9. CLOSE and Errors

### 9.1 CLOSE payload

| Key | Field | Type | Required |
| ---: | --- | --- | --- |
| 0 | session_id | SessionID | when a session exists |
| 1 | reason | uint | yes |
| 2 | detail | UTF-8 text, ≤ 128 bytes | no |

Reasons: `0` normal, `1` protocol_error, `2` authentication_failed, `3` identity_changed, `4` resource_limit, `5` shutdown. Unknown reasons are rejected. `detail` is diagnostic only, MUST NOT contain secrets or plaintext, and MUST NOT be required for interoperability.

### 9.2 CLOSE is unauthenticated **[CLOSED — D-017]**

In RUXMSG/1, CLOSE is a plaintext control frame and carries no authentication. An on-path attacker who can forge CLOSE could equally reset the TCP connection, so it gains no new capability. Nevertheless:

- a CLOSE naming a session ID that does not match a current session MUST be ignored;
- a CLOSE naming the DRAINING session closes only that session;
- UIs MUST present a received CLOSE as "peer closed (unauthenticated)" and MUST NOT present it as proof the peer chose to leave.

### 9.3 Errors

Errors are local outcomes, not a message type. Protocol errors: unsupported version or type, malformed frame, non-canonical or duplicate/unknown-key CBOR, missing or invalid field, invalid signature or confirmation, commitment mismatch, SAS rejection, identity mismatch, invalid state, replay, out-of-window counter, skipped-key limit, counter overflow, invalid padding, and resource-limit violations. Peer notification uses CLOSE without secret-bearing diagnostics.

---

## 10. Volatile State, Memory Hygiene, and Display Safety

### 10.1 Persistence

Only the Ed25519 identity seed persists, in the OS credential store per profile. Implementations MUST verify at startup or first use that the credential store is a real persistent backend and not an in-memory fallback, and MUST fail with a clear error otherwise.

### 10.2 Erasure

Because RUXMSG/1 claims symmetric message forward secrecy:

- after the send and receive ratchets are initialized, the implementation MUST NOT retain the initial directional chain keys or RootKey;
- chain keys, message keys, cached skipped keys and ephemeral private keys MUST be zeroized when replaced, consumed, or destroyed;
- key-bearing types MUST NOT implement `Debug`/logging that prints secret material.

### 10.3 Display safety

Peer-supplied text is untrusted. Before rendering to a terminal, implementations MUST neutralize or escape Unicode control characters (category Cc, including ESC and C1 controls, except newline and tab) and bidirectional override/isolate characters (U+202A–U+202E, U+2066–U+2069). Invalid UTF-8 MUST be handled without panic.

---

## 11. Transport and Resource Limits

RUXMSG requires a reliable ordered byte stream. TCP is the reference transport; Tailscale supplies reachability only. Implementations SHOULD bind listeners to loopback or a tailnet address by default rather than all interfaces.

Implementations MUST enforce the following. Defaults are **[CLOSED]**:

| Limit | Default |
| --- | ---: |
| Per-frame read timeout during handshake | 15 s |
| SAS decision timeout | 120 s |
| Total handshake deadline | 180 s |
| Concurrent unauthenticated handshakes per listener | 4 |
| Per-type payload limits | §4.3 |
| Max application content per message | 65,536 bytes |

Handshake state for a connection that exceeds a limit MUST be destroyed and the connection closed.

---

## 12. Conformance and Testing

### 12.1 Known-answer test vectors

The implementation MUST ship deterministic hex vectors (not merely property assertions) for: Ed25519 identity keys; X25519 ephemerals and shared secret; nonces; COMMIT and HELLO payload bytes; canonical transcript and TranscriptHash; SAS source bits, W0–W2 and words; signatures; HKDF PRK, RootKey, directional keys, SessionID; confirmation MACs; chain keys, message keys, next chain keys; nonce; AAD; plaintext; padding; ciphertext and tag. SAS vectors MUST cross the byte boundaries H[0]→H[1], H[1]→H[2], H[2]→H[3] and H[3]→H[4]. Two independent implementations MUST agree on every value.

### 12.2 Required behavioral tests

Identity generation; all-zero X25519 rejection; COMMIT/reveal mismatch; grind-resistance ordering (responder HELLO cannot precede COMMIT); transcript determinism; AUTH-versus-local-transcript mismatch; unsupported cipher suite; SAS extraction; SAS rejection; signature failure; HKDF derivation; confirmation; message-key derivation and chain advance; nonce construction; AEAD failure and AAD tampering; tamper-does-not-consume-key; replay and window sliding; reordering; skipped-key limit and cache ceiling; frame-size and per-type limits; malformed and duplicate-key CBOR; identity mismatch on rekey; wrong `previous_session_id`; process restart; transport loss ends session; normal, failed, and repeated rekey; simultaneous rekey and tie-break; drain timeout; DATA buffered during rekey; padding generation, CBOR overhead, authentication, and non-zero rejection; CLOSE with unknown session ID; handshake timeouts.

### 12.3 Fuzzing

Frame, CBOR, COMMIT/HELLO/AUTH, CLOSE, DATA decrypt, counter and replay handling, skipped-key handling, and the rekey state machine MUST be fuzzed. Malformed input MUST NOT cause unbounded allocation or work.

### 12.4 Independent review

RUXMSG/1 MUST NOT be described as production-secure solely because it uses established primitives. Before serious deployment it SHOULD receive independent review of handshake composition (including the commitment step), transcript binding, SAS construction, key schedule, ratchet, replay and skipped-key handling, rekey state machine, CBOR schemas, padding, memory erasure, and concurrency.

---

## Appendix A — State transition table

| Current state | Event | Result |
| --- | --- | --- |
| HANDSHAKING | both SESSION_CONFIRM verify | ACTIVE |
| HANDSHAKING | any authentication, commitment, SAS, schema, limit or timeout failure | candidate destroyed; CLOSED |
| ACTIVE | valid DATA | deliver once after §7.5 |
| ACTIVE | rekey trigger or valid rekey COMMIT | REKEYING (still sends and receives) |
| ACTIVE / REKEYING | transport loss | CLOSED; state destroyed |
| REKEYING | candidate confirmed | new session ACTIVE; old DRAINING |
| REKEYING | candidate fails or times out | candidate discarded; old session ACTIVE |
| DRAINING | eligible in-flight DATA | receive only |
| DRAINING | 15 s timeout | CLOSED; state destroyed |
| any non-CLOSED | CLOSE with matching session ID | that session CLOSED |
| any | process exit | all state destroyed |

## Appendix B — Decision log

| ID | Decision | Status |
| --- | --- | --- |
| D-001–D-011 | Version, registry, schemas, handshake transport, AAD/nonce, errors, lifecycle, SAS dictionary, symmetric HELLO (from spec 1.0) | **CLOSED** |
| D-012 | Initiator COMMIT before HELLO exchange to make the SAS grind-resistant | **CLOSED** |
| D-013 | A session is bound to one transport connection; reconnect = new handshake and SAS | **CLOSED** (consistent with "SAS every connection") |
| D-014 | Padding quantum measured on ciphertext (plaintext + 16-byte tag), matching the current code | **CLOSED** (amends D-006) |
| D-015 | Rekey authenticated by identity continuity, no SAS | **CLOSED** |
| D-016 | Per-type frame limits, `MAX_CONTENT`, handshake timeouts, unauthenticated-handshake cap | **CLOSED** (values are defaults) |
| D-017 | CLOSE is unauthenticated in V1 | **CLOSED** |
| D-018 | No trust store, no address book, SAS on every connection; only the identity seed persists | **CLOSED** (owner decision) |

## Appendix C — RUXMSG/2 roadmap (non-normative)

RUXMSG/2 will be a new protocol version (`0x02`), not an extension of RUXMSG/1; a V1 peer rejects a version-`0x02` frame per §4.2. Planned areas:

- **Groups**: multi-party sessions and membership. *Design to be filled in.*
- **Anonymity features**: metadata and identity protection. *Design to be filled in from the earlier design discussion.*
- **Peer-assisted offline delivery**: authorised peers hold encrypted envelopes in volatile RAM and forward when the recipient returns. *Design to be filled in.*

RUXMSG/1 leaves room for these through the version byte, the cipher-suite registry, the message-type registry, and separation of identity from session keys. Nothing in this appendix is normative for RUXMSG/1.

## Appendix D — Changes from 1.0

- Re-scoped to volatile two-party P2P; groups and anonymity moved to V2.
- Removed trust states, trusted-peer reuse, and identity-change UI that presumed a trust store; replaced with SAS on every connection.
- Added COMMIT step and grind-resistance rationale (D-012).
- Rewrote transcript section; fixed the inconsistent key numbering in old Appendix E.4.
- Added the previously undefined AUTH payload schema.
- Fixed the corrupted rows in the old state-transition table.
- Clarified that REKEY frames carry all rekey stages.
- Replaced transport-reconnect preservation with connection-bound sessions (D-013).
- Rekey authenticated by identity continuity; failed rekey returns to ACTIVE (D-015).
- Added per-type limits, timeouts, message-size limit, CLOSE semantics, erasure requirements, and display-safety requirements.
- Padding measured on ciphertext (D-014).
- Merged Appendix E into the main body.

*End of RUXMSG/1 specification 1.1 (draft).*
