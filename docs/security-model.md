# RUXMSG security model

This guide summarizes the security boundary of RUXMSG/1. The [protocol specification](protocol-spec.md) is authoritative; this document is not a substitute for its normative requirements.

## Threat model

The underlying network is hostile. An attacker may observe, capture, replay, reorder, duplicate, drop, modify, inject or delay frames, and may terminate the connection. Addresses, hostnames, Tailscale identities and usernames are not cryptographic identity.

RUXMSG protects accepted application messages with:

- a persistent Ed25519 identity per profile;
- a fresh X25519 session per connection;
- a committed, human-verified handshake (SAS) on every connection;
- transcript-bound Ed25519 signatures and confirmation MACs;
- HKDF-SHA-256 key separation and directional symmetric ratchets;
- ChaCha20-Poly1305 with padding;
- replay protection, bounded reordering, and strict frame and resource limits.

## Authentication: the SAS on every connection

RUXMSG has no trust store. A peer is never trusted because it sent a key or because you approved it before. On **every** connection:

1. the peers exchange a commitment, then HELLOs containing identity keys, ephemeral keys and nonces;
2. each side hashes the transcript, which contains both identity keys and both ephemeral keys, and shows a three-word SAS;
3. the two people compare the words over an independent channel and both approve;
4. only then are transcript signatures exchanged and keys derived.

Because the SAS covers the identities, an approved SAS authenticates who you are talking to for that session.

**Why the commitment matters.** The SAS carries 33 bits, so an attacker needs about 2³³ tries to fake one. If the attacker can choose its handshake values after seeing yours, it can perform those tries offline and make both of its connections display identical words. The initiator therefore commits to its HELLO before seeing the responder's; the attacker must then fix its values first and has a 1 in 2³³ chance per attempt. This requirement (D-012) is implemented in the engine, which sends nothing but COMMIT before it has the responder's HELLO and refuses to continue if the reveal does not match.

The SAS is typed, not clicked: approval needs the word `yes` and Enter, so a stray key cannot approve. It expires after 120 seconds and counts as a rejection.

**Verifying well.** Use a channel that is not the RUXMSG connection. If you already know the peer's fingerprint, check it as well. Reject on any difference. Never approve because the address or Tailscale name looks right.

## Identity within a session

Once a session exists, its peer identity is fixed. A rekey must present the same identities and name the active session as predecessor, or it is discarded. Rekeying therefore needs no new SAS and cannot be used to swap the peer.

## What RUXMSG does not provide

- anonymity;
- metadata confidentiality or traffic-analysis resistance (sizes are padded to 256-byte steps, but timing, endpoints, and the fact of communication are observable);
- deniability;
- protection from a compromised endpoint or malware controlling it;
- recovery of a lost identity key;
- post-compromise recovery beyond periodic rekeying (no full Double Ratchet);
- authenticated close: a CLOSE frame is unauthenticated (see below).

## CLOSE is unauthenticated

CLOSE is a plaintext control frame. Anyone who can inject into the connection could also reset the TCP stream, so this adds no new capability, but the client shows a received CLOSE as "peer closed (unauthenticated)" and ignores a CLOSE naming a session it does not have.

## Volatile state and key handling

Only the identity seed persists, in the OS credential store. Session keys, ephemeral private keys, chains, message keys, skipped keys, replay windows, counters, peer identities and messages exist only in memory and vanish when the connection or process ends.

Requirements (spec §10):

- after the ratchets are initialized, the initial directional chain keys and root key must not be kept, otherwise a later memory compromise could recompute every earlier message key;
- chain keys, message keys, cached skipped keys and ephemeral secrets are zeroized when replaced or dropped;
- secret-bearing types never print their contents;
- the credential store must be a real persistent backend, not an in-memory fallback.

`IdentityKeypair::to_bytes` exists for controlled persistence only. Treat its output as secret and do not copy or log it.

## Display safety

Text from a peer is untrusted input to your terminal. Control characters (including ESC and C1 controls) and bidirectional override characters must be escaped or removed before display, or a peer can move the cursor, overwrite earlier lines, or spoof the interface. The client escapes these characters when a message arrives, so they appear as visible `\u{..}` sequences; the escaped text is what is stored and drawn.

## Resource limits

Everything an unauthenticated peer can influence is bounded:

- frames: a 1 MiB absolute cap, and small per-type caps (1,024 bytes for handshake frames, 128 for SESSION_CONFIRM, 256 for CLOSE) enforced from the header before any payload is read; message content is limited to 64 KiB;
- a 64-message replay window, at most 64 skipped keys per gap and a hard key-cache ceiling of 128;
- time: 15 seconds per handshake frame, 120 seconds for the SAS decision and 180 seconds for a whole handshake, with a drain window of 15 seconds after a rekey;
- concurrency: at most four unauthenticated inbound handshakes per listener and four pending SAS requests;
- memory: every queue in the network layer and the client is bounded, and a write that stalls for 15 seconds ends the connection.

A frame that is malformed, truncated or oversized ends the session. An authentication or replay failure on a DATA frame drops only that frame.

## Local state and its limits

Messages are kept only in a bounded in-memory scrollback per conversation. Buffers holding keys, plaintext and scrollback are zeroized when replaced, evicted or dropped. On exit, on SIGTERM, SIGHUP or SIGINT, and on a panic, the client closes its sessions, drops all conversation state, restores the terminal and clears the screen and its scrollback. Core dumps are disabled and the process is marked non-dumpable where the operating system allows it.

This narrows what a later local reader can recover; it does not defeat a live compromise. It cannot cover `SIGKILL` or power loss, memory the OS has already swapped out (memory is not locked), the terminal emulator's own buffers, or copies a compromised process makes while running.

## Configuration file

The optional config file is the one input the client reads from a user-writable place. It is read-only, global (not tied to a profile), size-limited, schema-closed and never interpolated or executed. The loader refuses symlinks and files that another user could write, and its errors never quote the file. It can change appearance and navigation keys only; it cannot rebind Enter, typing, Ctrl-C, Ctrl-D or anything in the SAS prompt.

## Operational guidance

1. Compare the SAS through an independent channel every time.
2. Confirm the words belong to the connection you just made.
3. Protect the OS account and credential store that hold your identity.
4. Treat an unexpected peer fingerprint as a security event.
5. Keep the default loopback listener, or bind a tailnet address, rather than all interfaces; the client warns if you bind every interface.
6. Keep dependencies updated.
7. Obtain independent security review before relying on RUXMSG for anything serious.

## Implementation status

The protocol core is a sans-IO state machine with deterministic tests, and the Tokio driver has fault-injection tests. Remaining gaps are listed in the [conformance matrix](conformance-matrix.md): published known-answer vectors, recorded fuzzing runs, memory locking, and automated tests for zeroization and the exit wipe. No independent review or interoperability testing has been done.
