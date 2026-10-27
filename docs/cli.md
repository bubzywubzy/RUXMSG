# RUXMSG command-line client

`ruxmsg` is an interactive terminal client for volatile peer-to-peer messaging. It has two frontends that share one set of live sessions: a line-oriented **REPL** for control, and a **chat view** (Ratatui) for conversation. Press Esc in the chat view to return to the REPL; the network session stays alive.

Nothing about your peers, sessions, or messages is saved. The only persistent item is your identity seed.

## Launching

```text
ruxmsg                      # start with no identity loaded
ruxmsg --profile alice      # load an existing profile at startup
```

If `--profile` names a profile that does not exist, the client says so; create it with `profile init alice`.

## Profiles and identity

A profile is one Ed25519 identity. Its 32-byte seed is stored in the operating-system credential store under the service `ruxmsg-<profile>`, account `identity`. There is no trust file, address book, or profile registry.

| Command | Effect |
| --- | --- |
| `profile init <name>` | Create a new identity and make it active. Fails if the profile exists. |
| `profile use <name>` | Load an existing identity. |
| `profile list` | Not supported: RUXMSG keeps no registry of profiles. Remember your profile names. |
| `fingerprint` | Show your own fingerprint (64 hex characters, the raw public key). |
| `fingerprint <label>` | Show a connected peer's fingerprint. |

Profile names are 1 to 64 characters: ASCII letters, digits, `-`, `_`.

The identity is stable: the same profile gives the same fingerprint every launch. Losing the credential-store entry loses the identity; there is no recovery.

**Credential-store requirements.** macOS uses Keychain, Windows uses Credential Manager, Linux uses Secret Service (a running provider such as GNOME Keyring or KWallet is required). If startup or `profile init` fails with a storage error, check that the store is available to your session. Verify that an identity actually survives a restart on your platform; see [Troubleshooting](#troubleshooting).

## Commands

```text
IDENTITY
  profile init|use|list     manage identity profiles
  fingerprint [label]       show own or peer fingerprint

NETWORK
  start [--addr <addr>]     accept connections (default 0.0.0.0:4443)
  stop                      stop accepting new connections
  connect <addr>            connect to a peer

SESSIONS
  peers                     list sessions (label, direction, remote, status)
  use <label>               set the default target
  session <label>           show session details
  close <label>             close a session

MESSAGING
  chat [label]              open the chat view
  msg <label> <text>        send a message
  <text>                    send to the default target (any unrecognised input)

TAILSCALE
  tailscale status|up|ip    inspect or start the local Tailscale client

GENERAL
  help, quit
```

Each connection gets a label (`peer1`, `peer2`, ...). You can hold several connections at once; each is an independent two-party session.

Any input that is not a recognised command is sent as a message to the default target, so a mistyped command can be sent to your peer. Use `msg <label> <text>` when in doubt.

## First connection and the SAS

Every connection, first or hundredth, requires SAS approval from both people. RUXMSG remembers no one.

1. Both peers see: `SECURITY VERIFICATION` followed by three words.
2. Compare the words over an **independent** channel. Do not use the RUXMSG connection, and do not treat a matching IP address, hostname, or Tailscale name as verification.
3. If the words match exactly, approve. If not, reject and investigate.
4. Also check the peer's fingerprint against one you already know, if you have one.

A rejection, timeout, or mismatch aborts the connection and destroys all candidate state.

> **Planned (spec 1.1):** approval will require typing `yes` and Enter, will show the peer fingerprint alongside the words, and will time out. Currently a single `y` keypress approves and any other key rejects, so avoid typing while a connection request is pending.

## Chat view

`chat` (or `chat <label>`) opens the chat view for a connected session. Enter sends, Up/Down/PageUp/PageDown scroll, Esc returns to the REPL. Incoming messages for other sessions are not shown in the chat view. A SAS request for the chat's own session is displayed there but must be approved from the REPL.

## Sessions are tied to connections

A session lives exactly as long as its TCP connection. If the connection drops, the session is gone and its keys are destroyed. Reconnecting means a new handshake and a new SAS. Closing the program destroys all sessions.

`close <label>` sends a protocol CLOSE and ends the session. A CLOSE received from a peer is unauthenticated (anyone able to inject on the connection could send one), so the client reports it as the peer having closed, not as proof of intent.

## Tailscale

Tailscale provides reachability only. `tailscale status` reports whether it is running or needs login, `tailscale up` starts it, and `tailscale ip` prints your tailnet addresses. Use those addresses with `start --addr` and `connect`. If `tailscale` is not on `PATH` the client says how to install it.

## Troubleshooting

| Symptom | Likely cause |
| --- | --- |
| `no identity loaded` | Run `profile use <name>` or `profile init <name>`. |
| Storage error on `profile init`/`use` | Credential store unavailable. On Linux start a Secret Service provider. |
| Fingerprint changes after restart | The credential store may not be persistent on your platform or build; treat as a bug and report it. |
| `Connection refused` | Nobody is listening, wrong address, or firewall. Start the listener first. |
| SAS words differ | Reject. Possible interception or a wrong connection. Never approve a mismatch. |
| Handshake fails after a restart | Expected: session keys are memory-only; connect again. |
| Session vanished | The connection dropped; connect again and re-verify. |

## Known limitations (RUXMSG/1 in progress)

Tracked in the [conformance matrix](conformance-matrix.md); each is a spec 1.1 requirement not yet implemented:

- typed SAS approval and timeouts;
- terminal-output sanitization of peer text (a peer can currently send control characters);
- automatic rekey and peer-initiated rekey handling;
- handshake timeouts and a cap on concurrent unauthenticated handshakes;
- loopback or tailnet default for `start`;
- SAS approval from inside the chat view.

See the [security model](security-model.md), [architecture](architecture.md), and [specification](protocol-spec.md) for details.
