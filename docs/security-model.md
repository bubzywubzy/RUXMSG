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

**Why the commitment matters.** The SAS carries 33 bits, so an attacker needs about 2³³ tries to fake one. If the attacker can choose its handshake values after seeing yours, it can perform those tries offline and make both of its connections display identical words. The initiator therefore commits to its HELLO before seeing the responder's; the attacker must then fix its values first and has a 1 in 2³³ chance per attempt. This requirement (D-012) is in spec 1.1 and is not yet implemented.

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

Text from a peer is untrusted input to your terminal. Control characters (including ESC and C1 controls) and bidirectional override characters must be escaped or removed before display, or a peer can move the cursor, overwrite earlier lines, or spoof the interface. *Not yet implemented in the client.*

## Resource limits

Frames, handshakes and caches are bounded: a 1 MiB absolute frame cap (spec 1.1 adds small per-type caps for handshake and control frames), a 64-message replay window, at most 64 skipped keys per gap with a hard cache ceiling of 128, handshake timeouts, and a cap on concurrent unauthenticated handshakes. Timeouts, per-type caps and the handshake cap are planned.

## Operational guidance

1. Compare the SAS through an independent channel every time.
2. Confirm the words belong to the connection you just made.
3. Protect the OS account and credential store that hold your identity.
4. Treat an unexpected peer fingerprint as a security event.
5. Bind listeners to loopback or a tailnet address rather than all interfaces.
6. Keep dependencies updated.
7. Obtain independent security review before relying on RUXMSG for anything serious.

## Implementation status

The repository is a working conformance foundation with deterministic tests and fuzz targets, not a finished production messenger. Items required by spec 1.1 but not yet built are listed in the [conformance matrix](conformance-matrix.md). No independent review or interoperability testing has been done.
