# Security Policy and Threat Model

This document defines the vulnerability reporting process and the security boundary of RUXMSG/1. The [protocol specification](docs/protocol-spec.md) is authoritative for wire behavior and normative cryptographic requirements.

## Reporting a Vulnerability

Do **not** open a public GitHub issue for suspected security vulnerabilities.

Please report vulnerabilities privately via [GitHub Security Advisories](https://github.com/bubzywubzy/RUXMSG/security/advisories/new). Include:
- Affected crate(s) (`ruxmsg-core`, `ruxmsg-net`, or `ruxmsg-cli`) and version/commit.
- A minimal reproduction, test case, or fuzzer input (`fuzz/`).
- The impact (e.g., transcript forgery, key-cache exhaustion, terminal escape injection, or panic/DoS).

---

## Threat Model

The underlying network is assumed to be hostile. An attacker may observe, capture, replay, reorder, duplicate, drop, modify, inject, or delay frames, and may reset or terminate the TCP connection at any time. IP addresses, DNS names, Tailscale device names, and OS usernames are **not** cryptographic identities.

RUXMSG/1 protects application messages with:
- **Persistent identity:** One 32-byte Ed25519 identity seed per profile, stored only in the OS credential store.
- **Ephemeral forward secrecy:** A fresh X25519 key agreement per connection and per rekey.
- **Grind-resistant human authentication:** A committed handshake (`COMMIT` -> `HELLO` -> reveal) verified via a 3-word BIP-0039 Short Authentication String (SAS) on **every** connection.
- **Mutual authentication:** Role-separated Ed25519 signatures over the locally reconstructed deterministic CBOR transcript, followed by role-separated HMAC-SHA-256 confirmation MACs.
- **Symmetric ratcheting & AEAD:** HKDF-SHA-256 directional chains (`InitiatorToResponder = 1`, `ResponderToInitiator = 2`) encrypting messages with ChaCha20-Poly1305 and 256-byte quantum ciphertext padding.
- **Prepare-Authenticate-Commit receive path:** Unauthenticated or tampered `DATA` frames never consume a message key or advance the 64-message replay window.

## Authentication: SAS on Every Connection

RUXMSG has no trust store or address book. A peer is never trusted because it presented a key previously. On **every** connection:

1. The initiator sends `COMMIT`, containing `SHA-256("RUXMSG/1/COMMIT" || BE32(len) || initiator_hello_bytes)`.
2. The responder replies with its `HELLO`.
3. The initiator reveals its `HELLO`. The responder verifies the payload against the commitment in constant time (`subtle::ConstantTimeEq`).
4. Both sides construct the canonical CBOR transcript from the two `HELLO` frames and display the 3-word SAS (first 33 bits of `TranscriptHash`) alongside the peer's 64-character hex fingerprint.
5. Both users compare the three words over an independent channel and type `yes` + Enter within 120 seconds.
6. Only after local SAS approval does a peer sign the transcript hash and derive session keys.

**Why `COMMIT` matters:** Because a 3-word SAS has 33 bits of entropy, an active MITM who could wait to see the responder's `HELLO` before choosing its own `HELLO` could grind nonces offline in $O(2^{33})$ work to match the SAS on both legs. Binding the initiator to its exact `HELLO` bytes prior to seeing the responder's `HELLO` reduces an attacker's success probability to $2^{-33}$ per live connection.

## Identity Continuity Across Rekeys

Once a session is `ACTIVE`, the peer's `PeerIdentity` is pinned for the life of that TCP connection. Either peer may trigger an in-session rekey (at 24 hours, 1,000,000 messages, or manually via `rekey` / `Ctrl-R`). Rekeys use `MessageType::Rekey` and do **not** prompt for a new SAS; instead, the engine enforces that `previous_session_id` matches the active session and that both `IdentityPublicKey` values are identical to the active session's identities. Simultaneous rekeys (glare) are resolved deterministically by comparing raw 32-byte public keys in unsigned lexicographic order.

### Accepted residual: unauthenticated rekey control frames (D-019)

Rekey COMMITs cannot be authenticated until the candidate handshake binds them. A transport attacker can therefore inject repeated rekey attempts or delay legitimate traffic. Invalid and wrong-session COMMITs are dropped without closing the active session; after three consecutive rejections the client displays a warning, with further warnings suppressed until a valid attempt. After abandoning a candidate, the engine discards at most eight late REKEY or SESSION_CONFIRM frames. These are bounded mitigations, not cryptographic authentication or availability protection.

## What RUXMSG/1 Does Not Provide

- **Anonymity or metadata hiding:** IP endpoints, connection timing, and coarse message volume remain visible to network observers (payloads are padded to 256-byte multiples).
- **Deniability:** Handshake transcripts are signed with long-term Ed25519 identity keys.
- **Compromised endpoint protection:** Malware running as your OS user can read terminal buffers, keystrokes, or your OS keyring.
- **Authenticated `CLOSE`:** `CLOSE` is an unauthenticated plaintext control frame (an on-path attacker capable of injecting `CLOSE` can already send a TCP `RST`). The client always displays peer closes as `peer closed (unauthenticated, <reason>)` and ignores `CLOSE` frames with unknown session IDs.

## Volatile State, Memory Hygiene, and Process Hardening

- **Persistence boundary:** Only the 32-byte Ed25519 seed is stored in the OS credential store (`ruxmsg-<profile>` / `identity`). On save, `IdentityKeyStore` reads the secret back and verifies it in constant time to reject no-op/forgetful backends.
- **Zeroization:** `IdentityKeypair`, `EphemeralKeypair`, shared secrets, `SessionKeys`, chain keys, prepared message keys, decrypted plaintext, input buffers (`MAX_CONTENT + 4`), and scrollback entries are zeroized on drop or eviction; keypair and ratchet types are not clonable.
- **Redacted `Debug`:** `IdentityKeypair`, `EphemeralKeypair`, `SessionKeys`, `DataPlaintext`, `ReceivingChain`, Engine `Input`/`Effect`, and `ruxmsg-net` `ConnEvent`/`NetEvent` redact secret material and message plaintext.
- **Display sanitization:** Peer bytes are sanitized on ingestion via `sanitize_for_display` (escaping Unicode `Cc` control characters and bidi overrides `U+202A..=U+202E`, `U+2066..=U+2069` as `\u{xxxx}`) and tabs (`\t`) are expanded to spaces before storing in scrollback.
- **Process hardening (`ruxmsg-cli`):**
  - Runs on a single-threaded Tokio runtime (`current_thread`) to prevent secret copies across worker thread stacks.
  - Disables core dumps (`RLIMIT_CORE = 0` on Unix) and marks the process non-dumpable (`PR_SET_DUMPABLE = 0` on Linux).
  - Installs a panic hook and signal handlers (`SIGTERM`, `SIGHUP`, `SIGINT`) that send `CloseReason::Shutdown`, drop and zeroize all scrollbacks, restore the terminal, and emit ANSI screen + scrollback clear (`\x1b[2J\x1b[3J\x1b[H`) if any session or SAS was displayed.
  - **Known limitation:** Memory locking (`mlock` / `VirtualLock`) is not yet implemented, so OS swap could retain pages.

## Resource Bounds

Every untrusted input is strictly bounded prior to allocation or state mutation:

- **Frame headers:** Checked in 6 bytes. Max payloads: `HANDSHAKE` / `REKEY` = 1,024 B; `SESSION_CONFIRM` = 128 B; `CLOSE` = 256 B (`detail` ≤ 128 B UTF-8); `DATA` = 1 MiB. Both endpoints enforce the 64 KiB application-content limit.
- **Ratchet & Replay:** 64-message sliding replay bitmap; max 64 skipped keys per derivation gap; hard ceiling of 128 prepared keys in `ReceivingChain`, including target keys.
- **Timeouts:** 15 s TCP connect/write timeout; 15 s per-frame handshake read timeout (paused during the human SAS window); 120 s SAS decision timeout; 180 s total handshake/rekey timeout; 15 s old-session drain window; 30 s backoff before retrying a failed rekey; at most eight late rekey frames discarded per abandoned candidate.
- **Concurrency & Queues:** Max 4 concurrent unauthenticated inbound handshakes (`Semaphore`); max 4 queued SAS prompts; bounded MPSC channels (64 message, 8 control, 256 net events); scrollback capped at 1,000 entries and 256 KiB per peer (64 KiB per entry).
- **Config loader:** Max 16 KiB, UTF-8, `O_NOFOLLOW | O_NONBLOCK` (refuses symlinks and FIFOs), must be a regular file owned by the 

current UID and not group/world-writable (`mode & 0o022 == 0`), `deny_unknown_fields`, and never echoes file contents in error messages.