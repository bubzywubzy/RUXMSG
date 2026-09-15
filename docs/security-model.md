# RUXMSG security model

This guide summarizes the security boundary. The [protocol specification](../protocol-spec.md) is authoritative; this document must not be used as a substitute for the normative requirements.

## Threat model

RUXMSG assumes the underlying network is hostile. An attacker may observe, capture, replay, reorder, duplicate, drop, modify, inject, or delay frames and may disconnect the transport. Network addresses, hostnames, Tailscale identities, and usernames are not cryptographic identity.

RUXMSG protects accepted application messages with:

- persistent Ed25519 peer identities;
- fresh X25519 session agreement;
- transcript-bound signatures and confirmation MACs;
- HKDF-SHA-256 key separation;
- directional symmetric ratchets;
- ChaCha20-Poly1305 authenticated encryption;
- replay and bounded reordering checks;
- strict frame and payload resource limits.

## First contact

Both peers exchange identity and fresh session inputs, then independently calculate the transcript hash and its three-word Short Authentication String (SAS). Users must compare the SAS over an independent channel. A mismatch means the handshake must be rejected and the candidate session destroyed.

A peer is not trusted merely because it sent a public key. Trust enrollment is an explicit application decision after authentication succeeds.

## What the protocol does not provide

RUXMSG does not claim:

- anonymity;
- metadata confidentiality or traffic-analysis resistance;
- deniability;
- protection from a compromised endpoint;
- protection from malware controlling an endpoint;
- automatic recovery of lost identity keys;
- complete post-compromise security;
- cryptographic trust in the transport network.

Message sizes, timing, connection endpoints, and the existence of communication may remain observable.

## Restart and reconnect

Session key material is not persisted. After a process exits or loses memory, a new X25519 session and transcript are required. The long-term Ed25519 identity may remain the same.

A transport disconnect is not equivalent to a process restart. A future reconnect implementation must preserve the existing cryptographic session or explicitly establish a new one according to the protocol; it must never reset counters or reuse a nonce.

## Key handling

Private identity seeds, ephemeral private keys, chain keys, message keys, and skipped keys must not be logged or transmitted. The storage layer keeps the identity seed in an OS credential store and stores trusted-peer records in an AEAD-sealed file whose sealing key is also held by the credential store.

The current `IdentityKeypair::to_bytes` API exists for controlled persistence only. Callers must treat the returned bytes as secret material and avoid copying, logging, or retaining them unnecessarily.

## Operational guidance

1. Verify the SAS using a channel independent of the network connection.
2. Confirm the displayed words are associated with the intended peer and current connection.
3. Protect the operating-system account and credential store that hold the identity.
4. Back up identity material only through a deliberate, protected operational process.
5. Treat a changed identity as a security event; do not blindly replace a trusted key.
6. Keep the implementation and dependencies updated and obtain independent security review before production deployment.

## Implementation status

The repository contains a conformance foundation with deterministic tests and fuzz targets. It is not a completed production messaging system. In particular, the CLI currently supports one TCP connection, trusted-peer reuse is not yet fully wired into the CLI flow, independent interoperability has not been established, and production deployment has not received an independent security audit.
