# RUXMSG

Volatile, terminal-native, peer-to-peer end-to-end encrypted messaging.

RUXMSG is a Rust protocol library and terminal client for two people who talk directly to each other. There is no server. The network (TCP, Tailscale, anything reachable) is treated as hostile and provides reachability only. Identity, authentication, confidentiality, integrity and replay protection all happen above the transport.

## RUXMSG/1 and RUXMSG/2

| Capability | RUXMSG/1 (this repo) | RUXMSG/2 |
| --- | :---: | :---: |
| Two-party direct E2EE messaging | ✅ | ✅ |
| Persistent identity keypair (stable fingerprint) | ✅ | ✅ |
| SAS verification on every connection | ✅ | ✅ |
| Automatic rekeying | ✅ | ✅ |
| Groups | ❌ | planned |
| Anonymity features | ❌ | planned |
| Peer-assisted offline delivery | ❌ | planned |

**Volatile means volatile.** The only thing RUXMSG writes to disk is your identity seed, kept in the operating-system credential store. There is no trust store, no address book, no message history, no logs. Every connection is a fresh handshake, and both people compare a three-word Short Authentication String (SAS) every time.

## Status

The protocol is specified in [RUXMSG/1 specification 1.1 (draft)](docs/protocol-spec.md). The library and client implement most of it. Some 1.1 requirements are not yet implemented (notably the handshake COMMIT step, rekey identity continuity, per-type limits and timeouts, and terminal-output sanitization). The [conformance matrix](docs/conformance-matrix.md) tracks exactly what is done, what is planned, and what is unverified. RUXMSG is not production-secure until it has had independent security review.

## Quick start

Build with Cargo, then run the client. It is an interactive prompt (REPL).

Peer A (listens):

```text
$ ruxmsg
ruxmsg> profile init alice
ruxmsg> start --addr 127.0.0.1:4443
```

Peer B (connects):

```text
$ ruxmsg
ruxmsg> profile init bob
ruxmsg> connect 127.0.0.1:4443
```

Both sides then see a three-word SAS. Read it to each other over a channel that is **not** this connection (a call, in person). Approve only if the words match exactly and the peer fingerprint is the one you expect. Then use `chat` to open the chat view, or `msg <label> <text>`. Type `help` for every command.

To load an existing profile at launch: `ruxmsg --profile alice`. See the [CLI guide](docs/cli.md) for commands, profiles, Tailscale helpers, and troubleshooting.

## Security boundary

| Layer | Responsibility |
| --- | --- |
| Network | TCP/Tailscale provides reachability only |
| Identity | Ed25519 identifies the peer; verified by SAS on every connection |
| Session | X25519 + HKDF-SHA-256 establish fresh keys per connection; committed handshake resists SAS grinding |
| Messages | Directional ratchets + ChaCha20-Poly1305, padded, replay-protected |

RUXMSG does not provide anonymity, metadata confidentiality, deniability, or protection from a compromised endpoint. See the [security model](docs/security-model.md).

## Documentation

| Document | Authority and audience |
| --- | --- |
| [Protocol specification](docs/protocol-spec.md) | Normative wire and security contract |
| [Protocol reference](docs/protocol-reference.md) | Implementation-facing field and encoding index |
| [Conformance matrix](docs/conformance-matrix.md) | What is implemented, tested, planned, or unverified |
| [Protocol decisions](docs/decisions.md) | Closed wire-level decisions and rationale |
| [Architecture](docs/architecture.md) | Non-normative module, thread and data-flow guide |
| [Security model](docs/security-model.md) | Threat model and operational guidance |
| [CLI guide](docs/cli.md) | Using the terminal client |
| [Library guide](docs/library.md) | Crate API overview |
| [Contributing](docs/contributing.md) | Development, testing, fuzzing, protocol-change workflow |

If any document disagrees with the specification, the specification controls.

## Building and testing

Standard Rust checks: formatting, compilation, tests, Clippy, and rustdoc. The Linux build needs `pkg-config` and `libdbus-1-dev` for the credential store. See [Contributing](docs/contributing.md) for the full workflow.

## License

Apache-2.0.
