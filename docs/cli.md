# RUXMSG command-line client

The `ruxmsg` binary is the terminal client for RUXMSG.

It provides a line-oriented REPL for managing local identity profiles, starting a TCP listener, establishing multiple peer connections, inspecting sessions, and exchanging encrypted messages.

The client is intentionally small. It exercises the RUXMSG protocol and session machinery directly rather than providing a full-featured messaging application.

---

## Build and run

Build the project with Cargo:

```bash
cargo build
```

Run the client:

```bash
cargo run --bin ruxmsg
```

After building, the binary can also be invoked directly:

```text
ruxmsg
```

A profile can be selected when starting the client:

```text
ruxmsg --profile alice
```

The profile name determines which persistent local identity is used by that process.

---

## Starting the client

With no arguments, `ruxmsg` starts its interactive REPL.

```text
$ ruxmsg

RUXMSG
>
```

The available commands can be displayed with:

```text
help
```

The client currently supports:

```text
profile init <name>
profile use <name>
profile list

start [--addr <addr>]
stop
connect <addr>

peers
use <label>
msg <label> <text>
close <label>

fingerprint [label]
session <label>

tailscale status
tailscale up
tailscale ip

help
quit
```

The exact prompt and informational output may change as the terminal client develops.

---

## Profiles

Profiles provide separate local identity contexts.

Create a profile with:

```text
profile init alice
```

Create another:

```text
profile init bob
```

List available profiles:

```text
profile list
```

Switch the active profile:

```text
profile use alice
```

A profile's local Ed25519 identity is persisted through the operating-system credential-store abstraction.

The identity is generated when the profile first needs one and remains stable across application restarts.

Profile selection is an application-level feature. It does not change the RUXMSG protocol or cryptographic algorithms.

---

## Local identity persistence

The current implementation persists the **local Ed25519 identity seed**.

The storage layer uses the `keyring` dependency to access an operating-system credential store.

The current implementation does **not** persist:

* trusted-peer records;
* SAS approvals;
* active sessions;
* ratchet state;
* message keys;
* replay windows;
* message history.

There is currently no `trust.sealed` file or persistent trusted-peer database.

This means that a profile preserves the local cryptographic identity, but it does not preserve an authenticated session or a decision to automatically trust a peer on a future connection.

### Credential-store requirements

Credential-store behavior depends on the host operating system and its available credential infrastructure.

On Linux, the default keyring backend uses the Secret Service interface. A working Secret Service provider may therefore be required for identity persistence.

The identity seed should be treated as sensitive key material. Do not expose or manually copy it unless you understand the consequences.

---

## Starting a listener

Start a TCP listener with:

```text
start
```

The default listen address is determined by the current CLI implementation.

An explicit address can be supplied with:

```text
start --addr 127.0.0.1:4443
```

For a listener reachable by another host, use an address appropriate to the network interface and firewall configuration.

The listener can accept multiple incoming connections. Each accepted connection is represented as a peer session in the REPL.

Stop the listener with:

```text
stop
```

Stopping the listener prevents new incoming connections. It is separate from closing already-established peer sessions.

---

## Connecting to a peer

Connect to a TCP listener with:

```text
connect 127.0.0.1:4443
```

For another host:

```text
connect 192.168.0.10:4443
```

The address is only used for network reachability. It is not the peer's cryptographic identity.

A connection establishes a fresh RUXMSG session through the protocol handshake before application DATA is exchanged.

---

## First-contact verification

During session establishment, the handshake derives a short authentication string (SAS).

The terminal client presents the SAS to the user.

Compare the displayed value with the peer through an **independent channel**.

For example, the users could compare the values verbally or through another communication channel.

The connection should only be approved when:

1. both peers are communicating with the intended person/device;
2. the SAS values match exactly;
3. the user has independently verified the comparison.

A mismatch must be treated as a failed authentication event.

Do **not** substitute any of the following for SAS verification:

* IP address;
* hostname;
* DNS name;
* Tailscale address;
* Tailscale device name;
* physical network location.

Those values describe reachability or network identity, not the RUXMSG cryptographic identity.

---

## Multiple peer sessions

The current client is a **multi-session REPL**.

A single process can maintain multiple peer connections simultaneously.

Use:

```text
peers
```

to display the currently known peer/session labels.

A peer can then be selected with:

```text
use <label>
```

Messages can be sent explicitly to a peer with:

```text
msg <label> hello
```

This means the CLI does not require one process per connection.

Conceptually:

```text
ruxmsg
 │
 ├── peer-a
 │     └── RUXMSG session
 │
 ├── peer-b
 │     └── RUXMSG session
 │
 └── peer-c
       └── RUXMSG session
```

The current client is still intentionally minimal. It does not provide persistent conversations, message history, contact management, or a graphical conversation interface.

---

## Sending messages

Send application text to a specific peer with:

```text
msg <label> <text>
```

For example:

```text
msg alice hello from bob
```

The CLI passes the application data to the established RUXMSG session.

The session layer handles encryption, authentication, message-key management, and protocol framing.

The terminal client does not implement a separate encryption scheme on top of the protocol.

---

## Selecting a peer

The `use` command selects a peer for commands that operate on the current session:

```text
use alice
```

The currently selected peer can then be inspected or interacted with using the applicable session commands.

The explicit peer label can still be used with commands such as:

```text
msg alice hello
close alice
session alice
```

This allows the REPL to work with several simultaneous sessions without requiring separate terminal processes.

---

## Inspecting sessions

Inspect a session with:

```text
session <label>
```

This exposes session-level information provided by the current client.

It is intended primarily for observing the state of the protocol implementation while developing and testing RUXMSG.

The command does not expose private cryptographic key material.

---

## Inspecting fingerprints

Display the local or peer identity fingerprint with:

```text
fingerprint
```

A specific peer can be selected with:

```text
fingerprint <label>
```

Fingerprints are useful for identifying the cryptographic identity associated with a peer.

A fingerprint should not be treated as proof that an identity belongs to a particular human unless it has been independently verified.

The SAS comparison remains part of the first-contact authentication workflow.

---

## Closing a peer session

Close a specific session with:

```text
close <label>
```

A protocol `CLOSE` is used to terminate the RUXMSG session.

Closing a session removes its active cryptographic state from the running client.

The local persistent identity remains available to the profile.

The client does not persist the closed session's ratchet state for later resumption.

---

## Restart behavior

Restarting `ruxmsg` does not restore existing cryptographic sessions.

For example:

```text
Process A                         Process B
   │                                │
   │──── fresh handshake ──────────►│
   │                                │
   │──── encrypted session ────────►│
   │                                │
   X process exits                  │
                                    │
   │                                │
   │──── new handshake ────────────►│
   │                                │
   │──── new encrypted session ────►│
```

The local Ed25519 identity can survive the restart because it is persistent.

Session-specific state does not:

* X25519 ephemeral keys;
* session keys;
* ratchet chains;
* message keys;
* replay state;
* skipped keys;
* active session state.

A reconnect therefore establishes a new cryptographic session.

---

## Tailscale

Tailscale is optional.

The CLI provides commands for interacting with the local Tailscale installation:

```text
tailscale status
tailscale up
tailscale ip
```

These commands are convenience functionality for network reachability.

A Tailscale address can be used as a connection target:

```text
connect 100.x.y.z:<port>
```

The Tailscale identity is not used as the RUXMSG peer identity.

The protocol still performs its own authenticated handshake and SAS verification.

The security model is therefore:

```text
Tailscale
    │
    └── makes the peer reachable

RUXMSG
    │
    ├── identifies the peer with Ed25519
    ├── establishes a fresh X25519 session
    ├── authenticates the handshake transcript
    ├── verifies SAS
    └── encrypts application DATA
```

RUXMSG itself does not require Tailscale.

---

## Troubleshooting

### Credential-store errors

If profile initialization or identity loading fails, verify that the host's credential-store infrastructure is available to the current user session.

On Linux, check that a Secret Service provider is running and accessible.

The problem is with local identity persistence rather than the RUXMSG network protocol.

---

### Connection refused

If:

```text
connect 127.0.0.1:4443
```

fails with a connection-refused error:

1. Verify that the other peer has run `start`.
2. Verify the listener address and port.
3. Verify that the target address is reachable.
4. Check local and network firewalls.
5. If using Tailscale, verify that the target peer is reachable through Tailscale.

---

### SAS mismatch

If the SAS values do not match:

**abort the connection.**

Do not approve the connection and do not attempt to make the values match by retrying blindly.

Verify that both users are comparing the SAS generated by the same handshake and that they are communicating with the intended peers.

---

### Handshake failure after restart

A restart requires a new handshake.

This is expected because active session and ratchet state are held in memory.

The persistent profile identity should remain stable, but the session itself is new.

---

### Unexpected fingerprint

If a peer's fingerprint is unexpected:

1. Do not assume the network address is sufficient evidence.
2. Do not automatically accept the new identity.
3. Compare the identity/fingerprint with an independently known value.
4. Perform the SAS verification required by the protocol.

The current implementation does not maintain a persistent trusted-peer database that automatically remembers previous approvals.

---

## Current limitations

The terminal client is deliberately smaller than a production messaging application.

The current implementation does not yet provide:

* persistent trusted-peer records;
* automatic SAS bypass for previously verified peers;
* contact/address-book management;
* persistent message history;
* persistent conversations;
* offline message delivery;
* a central peer directory;
* asynchronous network infrastructure;
* production transport integrations beyond the currently exposed TCP path;
* a complete user-facing messaging interface.

The client is primarily a usable terminal front end for exercising the RUXMSG protocol implementation.

---

## Relationship to the library

The CLI is a consumer of the RUXMSG library.

The major boundaries are:

```text
ruxmsg CLI
    │
    ▼
PeerConnection
    │
    ├── Handshake
    ├── Session management
    ├── Ratchet
    ├── DATA protection
    └── Close/rekey
    │
    ▼
Transport
    │
    ▼
TCP
```

The CLI does not define the wire protocol.

Protocol behavior is defined by the [protocol specification](protocol-spec.md), while the implementation structure is described in the [architecture guide](architecture.md).

---

## Related documentation

* [Architecture](architecture.md) — implementation structure and data flow.
* [Security model](security-model.md) — threat model and security boundaries.
* [Protocol specification](protocol-spec.md) — normative protocol and wire requirements.
* [Protocol reference](protocol-reference.md) — implementation-facing protocol reference.
* [Conformance matrix](conformance-matrix.md) — implementation and testing status.
* [Library guide](library.md) — library API and integration.
