# RUXMSG

**Volatile, terminal-native, peer-to-peer end-to-end encrypted messaging.**

RUXMSG is a Rust protocol library and terminal client built for two people to communicate directly, without relying on a central server. It works over TCP, Tailscale, or any other reachable byte stream. The network is treated as hostile and is responsible for reachability only. Identity, authentication, confidentiality, message integrity, and replay protection are handled by RUXMSG above the transport layer.

The goal is simple: keep the protocol separate from the network, keep persistent data to a minimum, and make security properties explicit rather than relying on the transport to provide them.

## RUXMSG/1 and RUXMSG/2

RUXMSG/1 is the protocol implemented in this repository. RUXMSG/2 is the planned next version, with additional capabilities built on top of the existing design.

| Capability | RUXMSG/1 (current) | RUXMSG/2 |
|---|:---:|:---:|
| Direct, two-party E2EE messaging | Yes | Yes |
| Persistent identity and stable fingerprint | Yes | Yes |
| SAS verification on every connection | Yes | Yes |
| Automatic and manual in-session rekeying | Yes | Yes |
| Group messaging | No | Planned |
| Anonymity features | No | Planned |
| Peer-assisted offline delivery | No | Planned |

RUXMSG/2 features are planned, not implemented or guaranteed. The current focus is on the protocol, its implementation, and getting the security properties right before expanding the feature set.

## Volatile means volatile

RUXMSG is designed to avoid retaining conversation data after use. The only application data intended to persist is the 32-byte Ed25519 identity seed, stored through the operating system's credential store.

There is no application-level trust store, address book, message history, or logging system. Every connection starts with a fresh handshake, and both peers compare a three-word Short Authentication String (SAS) to verify the connection.

Your identity persists, but each connection establishes fresh session keys. The SAS must be checked on every connection, not just the first time you talk to someone.

This describes RUXMSG's intended persistence model; it is not a guarantee that the operating system, terminal, crash reporter, or other external software never retains related data.

## Current status

The protocol is specified in [RUXMSG/1 specification 1.1](docs/protocol-spec.md).

The implementation includes:

- A committed handshake using the `COMMIT` step.
- Rekeying with identity continuity and glare resolution.
- Per-frame-type size limits and handshake deadlines.
- Limits on unauthenticated handshakes.
- Terminal display sanitization and process hardening.
- Typed SAS approval, requiring explicit user confirmation.
- A sans-IO protocol core separated from the Tokio networking layer.

The [conformance matrix](docs/conformance-matrix.md) tracks protocol requirements against implementation and test coverage.

There is still work to do. Outstanding items include published hexadecimal known-answer test vectors, recorded fuzzing corpora and runs, `mlock` memory locking, and an independent security review.

**RUXMSG has not undergone an independent security review and should not be considered production-secure.** Implemented features and passing tests are not substitutes for independent cryptographic and protocol analysis.

## Workspace structure

RUXMSG is split into three crates, keeping the protocol, networking, and terminal client separate.

| Crate | Responsibility |
|---|---|
| `ruxmsg-core` | The protocol core. Contains the sans-IO state machine (`Engine`), wire format, CBOR validation, and cryptographic operations. It does not depend on sockets, threads, clocks, or an async runtime. |
| `ruxmsg-net` | The Tokio networking layer. Handles incremental frame decoding, deadlines, bounded queues, incoming connections, and the handshake semaphore. |
| `ruxmsg-cli` | The `ruxmsg` terminal client. Handles the raw-mode REPL, Ratatui conversation view, read-only configuration, OS credential-store integration, and process hardening. |

The separation is intentional: the protocol state machine should not need to know which transport carries its messages, and the network driver should not redefine protocol security rules.

## Installation and quick start

You can build and install a locked release binary using the included installation scripts, or build the workspace directly with Cargo.

### Install

Run the appropriate script from the repository root.

**Linux / macOS**

```bash
./scripts/install.sh
```

**Windows (PowerShell)**

```powershell
.\scripts\install.ps1
```

These scripts build from the checked-out source with Cargo using the committed lockfile; they do not download release binaries. Rust/Cargo and the platform's native build dependencies are required.

On Linux and macOS, set `INSTALL_DIR=/path` to choose another installation directory. On Windows, use `-InstallDir <path>` or set `RUXMSG_INSTALL_DIR`. The default is `/usr/local/bin` on Linux/macOS and `%LOCALAPPDATA%\Programs\RUXMSG` on Windows. The installer does not change `PATH`; use the printed executable path or add the chosen directory yourself.

Use `./scripts/install.sh --check` or `./scripts/install.ps1 -Check` to validate prerequisites and paths without building. `--dry-run` / `-DryRun` previews the planned build and install without changing files. Both installers also support `--help` / `-Help`.

On Linux, building the credential-store integration requires `pkg-config` and the D-Bus development libraries (`libdbus-1-dev` on Debian-based systems). Other distributions may package these dependencies under different names.

### Start a session

RUXMSG uses an interactive terminal client. The following example shows two peers establishing a direct connection.

**Peer A — listen**

```text
$ ruxmsg
ruxmsg> profile init alice
ruxmsg> start --addr 127.0.0.1:4443
```

The listener defaults to loopback at `127.0.0.1:4443`. Loopback is only reachable from the same machine, so use an appropriate reachable address when connecting from another device. For a Tailscale connection, this will generally be the listener's Tailscale IP.

**Peer B — connect**

```text
$ ruxmsg
ruxmsg> profile init bob
ruxmsg> connect 127.0.0.1:4443
```

Replace the loopback address with Peer A's reachable address when connecting across devices.

### Verify the connection

Both peers display a three-word SAS and the other peer's 64-character hexadecimal fingerprint.

1. Compare the three SAS words over an independent channel, such as an in-person conversation or voice call.
2. Approve the connection only if the words match exactly.
3. Type `yes` and press Enter to approve. Any other response rejects the connection.

Do not verify the SAS through the same connection you're trying to authenticate. An independent comparison is what helps detect an active man-in-the-middle attack.

After approval, open the full-screen conversation interface:

```text
ruxmsg> chat peer1
```

Or send a message directly from the REPL:

```text
ruxmsg> msg peer1 Hello
```

Here, `peer1` represents the peer identifier exposed by the running client. Use the actual identifier shown by your session.

To load an existing profile when starting the client:

```bash
ruxmsg --profile alice
```

For the full command list, configuration options, Tailscale helpers, and uninstallation instructions, see the [CLI guide](docs/cli.md).

## Security model

RUXMSG assumes the transport can be observed, manipulated, interrupted, or controlled by an attacker. The transport provides a byte stream; it does not establish trust between peers.

| Layer | Mechanism | Responsibility |
|---|---|---|
| Network | TCP, Tailscale, or another reachable byte stream | Connectivity only. The transport is not trusted to provide end-to-end security. |
| Identity | Ed25519 | Establishes peer identity, with verification through SAS comparison on every connection. |
| Session establishment | X25519 and HKDF-SHA-256 | Establishes fresh session keys for each connection. The `COMMIT` step is designed to prevent SAS grinding. |
| Message protection | Directional HKDF ratchets and ChaCha20-Poly1305 | Provides authenticated encryption with directional key evolution. |
| Padding and replay protection | 256-byte padding and a 64-message replay window | Reduces message-length granularity and rejects messages that fall within the replay window and have already been accepted. |

These mechanisms address different parts of the protocol. Encryption alone does not authenticate the intended peer, and a successful connection does not eliminate the need to verify the SAS.

Padding does not hide all traffic patterns, and replay protection is not a substitute for transport-level availability. Neither prevents an attacker from dropping, delaying, or disrupting traffic.

For the complete threat model, security assumptions, non-goals, operational guidance, and vulnerability reporting policy, see [SECURITY.md](SECURITY.md).

## Documentation

| Document | Purpose |
|---|---|
| [Security policy](SECURITY.md) | Threat model, local security considerations, operational guidance, and vulnerability reporting. |
| [Protocol specification](docs/protocol-spec.md) | Normative wire format and cryptographic contract, including the decision log in Appendix B. |
| [Conformance matrix](docs/conformance-matrix.md) | Requirement-by-requirement implementation and test status. |
| [Architecture and library guide](docs/architecture.md) | Crate boundaries, the sans-IO `Engine` contract, Tokio driver, and client runtime. |
| [CLI guide](docs/cli.md) | Client commands, profiles, configuration, Tailscale helpers, and uninstallation. |
| [Contributing](docs/contributing.md) | Toolchain setup, testing, fuzzing, and the protocol-change workflow. |

## Contributing

RUXMSG is a protocol project first and a messaging client second. Changes to wire formats, cryptographic operations, handshake state, replay handling, or session lifecycle can affect the security of the entire system.

Before changing protocol behavior, review the specification, architecture guide, and conformance matrix. Keep the implementation aligned with the normative specification, add tests for new behavior and failure paths, and document any changes to protocol assumptions.

Security issues should be reported according to the instructions in [SECURITY.md](SECURITY.md).

## License

See the repository's license file for licensing terms.
