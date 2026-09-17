# RUXMSG Security Model

This document describes the security boundary of the current RUXMSG implementation. The [normative protocol specification](../protocol-spec.md) is authoritative and takes precedence over this document.

This guide explains what the protocol is designed to protect, what assumptions it makes, what remains outside its security boundary, and where implementation limitations currently exist.

## Threat Model

RUXMSG treats the underlying network as hostile.

An attacker controlling or observing the network may:

* observe traffic;
* capture frames;
* replay frames;
* reorder frames;
* duplicate frames;
* drop frames;
* modify frames;
* inject frames;
* delay delivery;
* terminate connections;
* provide malformed protocol data.

Network reachability does not establish cryptographic identity.

The following are therefore **not** themselves cryptographic identities:

* IP addresses;
* TCP endpoints;
* hostnames;
* usernames;
* Tailscale identities;
* network location.

RUXMSG establishes peer identity through its own authenticated handshake.

## Security Properties

The protocol uses several independent mechanisms to establish and protect a session:

* persistent Ed25519 identities for peer authentication;
* fresh X25519 ephemeral key agreement for session establishment;
* transcript-bound identity signatures;
* transcript-bound session confirmation;
* HKDF-SHA-256 key derivation;
* directional ratchet state;
* ChaCha20-Poly1305 authenticated encryption;
* message counters and replay-window enforcement;
* bounded skipped-key state;
* strict frame-length validation;
* canonical CBOR validation;
* bounded protocol resources.

These mechanisms are composed as one protocol. The presence of an individual cryptographic primitive does not imply that the overall implementation satisfies every desired security property.

## Identity and Authentication

Each local profile has an Ed25519 identity that can persist across process restarts.

During session establishment, peers exchange their identity public keys together with fresh ephemeral session material. The handshake transcript binds the relevant inputs together, and the identity keys authenticate that transcript.

The persistent identity therefore provides continuity of cryptographic identity across sessions.

The identity itself is distinct from network reachability. Connecting to a particular address does not prove that the remote peer owns a particular RUXMSG identity.

## First Contact and SAS Verification

A newly established session produces a Short Authentication String (SAS) derived from the authenticated handshake transcript.

The intended first-contact procedure is:

1. establish the handshake;
2. display the SAS to both participants;
3. compare the SAS through a channel independent of the RUXMSG network connection;
4. reject the session if the values do not match;
5. continue using the session only after successful verification.

The independent comparison is important because the network connection itself is the channel whose authenticity is being established.

A matching SAS provides an application-level mechanism for detecting an active man-in-the-middle during initial authentication.

A peer sending a valid-looking public key does not, by itself, establish that the key belongs to the intended human or organization.

## Trust and Persistence Boundary

The current implementation intentionally has a narrow persistence boundary.

Persistent local identity material is stored through the storage/credential-store abstraction.

The implementation does **not currently persist**:

* trusted-peer records;
* SAS approval state;
* automatic trusted-peer enrollment;
* active session keys;
* ratchet state;
* replay windows;
* skipped message keys;
* message history.

Consequently, the current implementation does not provide persistent trust reuse in which a previously verified peer automatically bypasses SAS verification.

Trust management above the protocol identity layer remains an application concern until a persistent trust model is explicitly implemented.

## Session Security

Session cryptographic material is ephemeral.

The following state is process-local:

* X25519 ephemeral private keys;
* established session keys;
* directional chain state;
* message keys;
* message counters;
* replay windows;
* skipped keys;
* candidate rekey sessions;
* draining predecessor sessions.

A process restart therefore destroys active session state.

A subsequent connection establishes a fresh X25519 agreement and authenticated transcript, even if the same persistent Ed25519 identity is used.

This separation prevents active session state from silently becoming persistent identity state.

## Rekeying

RUXMSG supports replacement of an established session through a candidate rekey session.

The candidate is authenticated and confirmed before it becomes the active session. The predecessor can remain temporarily available for draining according to the session lifecycle rules.

Rekeying must preserve the protocol's key, counter, and nonce-uniqueness invariants.

In particular:

* counters must not be reset in a way that causes nonce reuse under the same key;
* session keys must not be reused across unrelated sessions;
* failed candidates must not become active;
* predecessor state must be bounded and eventually destroyed.

The implementation defines bounded rekey behavior, including a maximum predecessor drain period.

## Replay and Reordering

Authenticated DATA messages contain a directional message counter.

The receiver maintains bounded replay/reordering state rather than accepting an unlimited history.

The current implementation defines:

```text id="l3jz3e"
Replay window:       64 counters
Maximum skipped keys: 64
```

Messages that violate the applicable counter, replay-window, or skipped-key constraints are rejected.

These limits also provide resource bounds against attackers attempting to force unbounded receiver state.

## Cryptographic Protection of DATA

Application DATA is protected with ChaCha20-Poly1305.

The authenticated context includes protocol/session information and the directional message counter. The nonce is deterministically constructed from the direction identifier and message counter.

The authenticated plaintext contains both application content and protocol padding.

Padding is validated only after successful authentication. Unauthenticated ciphertext must never be interpreted as trusted application data.

The cryptographic design depends on correct nonce uniqueness, key separation, transcript binding, and state-machine enforcement. These properties must therefore be preserved when modifying the implementation.

## What RUXMSG Does Not Provide

RUXMSG does not claim to provide:

* anonymity;
* metadata confidentiality;
* traffic-analysis resistance;
* deniability;
* protection against a compromised endpoint;
* protection against malware controlling an endpoint;
* recovery from loss or compromise of the persistent identity without an external recovery mechanism;
* complete post-compromise security;
* cryptographic trust in the underlying transport network;
* protection against a malicious or compromised operating system.

In particular, network observers may still be able to determine:

* that communication is occurring;
* when connections are established;
* which network endpoints communicate;
* approximate message sizes;
* packet timing and traffic patterns;
* connection duration.

Encryption of application content does not make these metadata properties disappear.

## Endpoint Security

RUXMSG cannot protect secrets after the endpoint itself is compromised.

An attacker with sufficient access to a running process, operating-system account, credential store, memory, terminal, or endpoint may be able to obtain information that the protocol cannot hide.

The security of the persistent Ed25519 identity therefore also depends on protection of the operating-system account and the credential-storage mechanism.

The protocol does not attempt to turn an untrusted endpoint into a trusted one.

## Key Handling

Private cryptographic material must be treated as secret.

This includes:

* persistent identity seeds;
* X25519 ephemeral private keys;
* session keys;
* directional chain keys;
* message keys;
* skipped message keys;
* other derived secret material.

Such material must not be:

* logged;
* printed to the terminal;
* transmitted as diagnostics;
* committed to the repository;
* included in documentation;
* retained unnecessarily.

The storage layer is responsible for the persistence boundary around the local identity. Active session state must remain ephemeral.

Where an API intentionally exposes identity key material for controlled persistence or interoperability operations, callers are responsible for treating the returned bytes as secret material and minimizing copying and retention.

## Restart and Reconnect

A process restart destroys active session cryptographic state.

After restart:

```text id="o9p8e1"
persistent Ed25519 identity
          │
          ▼
fresh X25519 agreement
          │
          ▼
fresh authenticated transcript
          │
          ▼
fresh session
```

The long-term identity may remain unchanged while the session cryptographic state is completely new.

A transport disconnect is not itself permission to reset counters or reuse session cryptographic material.

Any future reconnect mechanism must either:

1. explicitly establish a new authenticated session; or
2. implement a protocol-defined session-resumption mechanism with its own security and nonce/counter requirements.

It must never achieve reconnection by blindly resetting session state.

## Transport Security Boundary

TCP and other transports provide byte delivery and connectivity. They are not the source of RUXMSG peer authentication.

Tailscale may be used as an optional connectivity mechanism, but Tailscale membership is not substituted for RUXMSG identity authentication.

A secure network does not eliminate the need for RUXMSG's authenticated handshake, and an untrusted network does not invalidate the protocol's cryptographic identity model.

## Operational Guidance

For current deployments and testing:

1. **Verify the SAS on first contact** using an independent communication channel.
2. **Confirm the intended peer identity** rather than relying only on an address or hostname.
3. **Protect the operating-system account and credential store** containing the persistent identity.
4. **Treat identity changes as security events.** Do not automatically replace an unexpected identity.
5. **Protect identity backups** if an operational backup procedure is used.
6. **Do not expose cryptographic secrets in logs or diagnostics.**
7. **Keep dependencies and the Rust toolchain maintained.**
8. **Run the repository's tests and relevant fuzz targets after security-sensitive changes.**
9. **Obtain independent security review before treating the implementation as suitable for high-assurance or production deployment.**

## Current Implementation Status

The repository contains a substantial protocol and session implementation with deterministic conformance tests, integration tests, restart coverage, rekey coverage, transport tests, and fuzzing infrastructure.

The current implementation should nevertheless be understood within its actual scope.

In particular:

* persistent local identity is implemented;
* active session state remains in memory;
* fresh sessions are established after restart;
* persistent trusted-peer records are not implemented;
* persistent SAS approvals are not implemented;
* automatic trusted-peer SAS bypass is not implemented;
* message history is not implemented;
* offline delivery is not implemented;
* independent interoperability has not been established;
* the implementation has not received an independent security audit.

The `ruxmsg` CLI is currently a **line-oriented multi-session REPL** rather than the earlier one-connection client model. It can maintain multiple peer/session handles within a process, but that does not constitute persistent contact or trust management.

Passing protocol vectors, integration tests, or fuzzing cases demonstrates behavior covered by those tests. It is not equivalent to a security proof, independent audit, or guarantee that no implementation vulnerabilities exist.

## Security Claim Boundary

The appropriate security claim is therefore deliberately narrow:

> RUXMSG implements an authenticated, encrypted peer-to-peer session protocol intended to operate over an untrusted network, with explicit identity, session, framing, replay, and resource boundaries.

That claim should not be expanded into guarantees that the current implementation does not establish.

Changes to identity handling, transcript construction, cryptographic derivation, nonce construction, replay state, persistence, session transitions, or error handling should be treated as security-sensitive changes and reviewed accordingly.
