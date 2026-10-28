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

The protocol is specified in [RUXMSG/1 specification 1.1 (draft)](docs/protocol-spec.md). The reference implementation covers the handshake COMMIT step, rekey with identity continuity and glare resolution, per-type frame limits, handshake timeouts and a cap on unauthenticated handshakes, display sanitization of peer text, and typed SAS approval. Still open: published known-answer vectors, recorded fuzzing runs, memory locking, and independent interoperability and security review. The [conformance matrix](docs/conformance-matrix.md) tracks exactly what is implemented, tested, planned or unverified. RUXMSG is not production-secure until it has had independent security review.

## Workspace

| Crate | Role |
| --- | --- |
| `ruxmsg-core` | Protocol core: a sans-IO state machine, wire format, cryptography. No sockets, threads, clocks or runtime. |
| `ruxmsg-net` | Tokio driver: frame decoding, deadlines, bounded queues, listener. |
| `ruxmsg-cli` | The `ruxmsg` terminal client: REPL, conversation view, read-only config, keyring adapter. |

## Quick start

Build with Cargo, then run the client. It is an interactive prompt (REPL).

Peer A (listens; the default is loopback only, use a tailnet address to be reachable):

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

Both sides then see a three-word SAS. Read it to each other over a channel that is **not** this connection (a call, in person). Approve only if the words match exactly and the peer fingerprint is the one you expect, by typing `yes` and pressing Enter; anything else rejects. Then use `chat` to open the conversation view, or `msg <label> <text>`. Type `help` for every command.

To load an existing profile at launch: `ruxmsg --profile alice`. Appearance and key bindings can be set in an optional read-only config file. See the [CLI guide](docs/cli.md) for commands, profiles, configuration, Tailscale helpers, and troubleshooting.

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
| [Protocol specification](docs/protocol-spec.md) | Normative wire and security contract, including the decision log (Appendix B) |
| [Conformance matrix](docs/conformance-matrix.md) | What is implemented, tested, planned, or unverified |
| [Architecture](docs/architecture.md) | Non-normative crate, engine, runtime and data-flow guide |
| [Security model](docs/security-model.md) | Threat model and operational guidance |
| [CLI guide](docs/cli.md) | Using the terminal client |
| [Library guide](docs/library.md) | `ruxmsg-core` API overview |
| [Contributing](docs/contributing.md) | Layout, testing, fuzzing, protocol-change workflow |

If any document disagrees with the specification, the specification controls.

## Building and testing

```text
cargo build --workspace
cargo clippy --workspace --all-targets
cargo test --workspace
```

The Linux build needs `pkg-config` and `libdbus-1-dev` for the credential store. See [Contributing](docs/contributing.md) for the full workflow.

## License

Apache-2.0.
