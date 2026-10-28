# RUXMSG command-line client

`ruxmsg` is an interactive terminal client for volatile peer-to-peer messaging. It has two frontends that share one set of live sessions: a line-oriented **REPL** for control, and a **conversation view** (Ratatui) for conversation. Press Esc in the conversation view to return to the REPL; the network session stays alive. The client is a single-threaded Tokio program over the sans-IO engine.

Nothing about your peers, sessions, or messages is saved. The only persistent item is your identity seed.

## Launching

```text
ruxmsg                      # start with no identity loaded
ruxmsg --profile alice      # load an existing profile at startup
ruxmsg --config ./my.toml   # read configuration from another file
```

If `--profile` names a profile that does not exist, the client says so; create it with `profile init alice`. Switching profiles with `profile use` or `profile init` is refused while sessions or a listener exist; close them first.

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
  start [--addr <addr>]     accept connections (default 127.0.0.1:4443, loopback only)
  stop                      stop accepting new connections
  connect <addr>            connect to a peer

SESSIONS
  peers                     list sessions (label, direction, remote, status)
  use <label>               set the default target
  session <label>           show session details
  close <label>             close a session

MESSAGING
  rekey <label>             start a rekey now
  chat [label]              open the conversation view
  msg <label> <text>        send a message
  <text>                    send to the default target (any unrecognised input)

TAILSCALE
  tailscale status|up|ip    inspect or start the local Tailscale client

GENERAL
  help, quit
```

`start` listens on loopback by default and warns if you bind every interface. `connect` returns immediately and reports success or failure as an event. Ctrl-C or Ctrl-D in the REPL quits.

Each connection gets a label (`peer1`, `peer2`, ...). You can hold several connections at once; each is an independent two-party session.

Any input that is not a recognised command is sent as a message to the default target, so a mistyped command can be sent to your peer. Use `msg <label> <text>` when in doubt.

## First connection and the SAS

Every connection, first or hundredth, requires SAS approval from both people. RUXMSG remembers no one.

1. Both peers see: `SECURITY VERIFICATION` followed by three words, the connection's direction and the peer's full fingerprint.
2. Compare the words over an **independent** channel. Do not use the RUXMSG connection, and do not treat a matching IP address, hostname, or Tailscale name as verification.
3. If the words match exactly, approve. If not, reject and investigate.
4. Also check the peer's fingerprint against one you already know, if you have one.

A rejection, timeout, or mismatch aborts the connection and destroys all candidate state.

The prompt shows the words, the peer's full fingerprint (claimed until you approve) and a 120 s countdown. Approval requires typing `yes` and pressing Enter; a single key, any other text, Esc, or the timeout rejects. The same prompt appears as a modal inside the conversation view, labelled with the connection it belongs to, and requests queue (at most four).

## Conversation view

`chat` (or `chat <label>`) opens the conversation view for a connected session. One conversation is open at a time; Esc returns to the REPL, where `use`, `chat` and `connect` switch conversations. The header shows the state (ACTIVE, rekeying, CLOSED) and the peer's full fingerprint.

| Key | Action |
| --- | --- |
| Enter | send |
| Esc, Ctrl-C | back to the REPL |
| Ctrl-R | rekey this session |
| Up, Down, PageUp, PageDown | scroll |

Messages for other sessions are kept (in memory) and announced in the status bar as `peerN +count`, never shown. Peer text is escaped before display, so control and bidirectional characters appear as `\u{..}` rather than acting on your terminal.

Scrollback is bounded (1,000 entries, 256 KiB per conversation), lives only in RAM, and is zeroized when the session closes, the conversation is left after a close, or the program exits. On exit the screen and its scrollback are cleared. Core dumps are disabled where the OS allows it. Nothing can protect against a live local compromise, `SIGKILL`, swap, or your terminal emulator's own memory.

## Sessions are tied to connections

A session lives exactly as long as its TCP connection. If the connection drops, the session is gone and its keys are destroyed. Reconnecting means a new handshake and a new SAS. Closing the program destroys all sessions.

`close <label>` sends a protocol CLOSE and ends the session. A CLOSE received from a peer is unauthenticated (anyone able to inject on the connection could send one), so the client reports it as the peer having closed, not as proof of intent.

## Tailscale

Tailscale provides reachability only. `tailscale status` reports whether it is running or needs login, `tailscale up` starts it, and `tailscale ip` prints your tailnet addresses. Use those addresses with `start --addr` and `connect`. If `tailscale` is not on `PATH` the client says how to install it.

## Configuration

Appearance and key bindings can be set in one global file, read once at startup and never written by the app. It is not tied to any profile. The default location is `$XDG_CONFIG_HOME/ruxmsg/config.toml` (else `~/.config/ruxmsg/config.toml`); `--config <path>` reads another file. A missing file means defaults.

```toml
[theme]            # named colours or #rrggbb
border = "dark-gray"
accent = "#ff8800"
local = "green"
remote = "yellow"
system = "magenta"
warning = "red"
dim = "gray"

[keys]             # names, f1-f12, or ctrl-/alt- plus a letter
leave = "esc"
rekey = "ctrl-r"
scroll_up = "up"
scroll_down = "down"
page_up = "pageup"
page_down = "pagedown"

[ui]
border = "rounded"   # plain, rounded, double, thick
tick_ms = 250        # 100 to 1000
```

The loader is strict because it is the one input read from a user-writable place. The file must be a regular file you own that group and others cannot write, and not a symlink. It is capped at 16 KiB and must be UTF-8. Unknown tables, fields and wrong types are rejected, and nothing in it is expanded, included or executed. Errors name a kind and a line number but never quote the file. On any error the client prints one warning and uses the defaults.

Some keys cannot be rebound: Enter, Backspace, typing, Ctrl-C, Ctrl-D, and everything in the SAS prompt. A plain letter cannot be bound, and no key may be bound to two actions.

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

Tracked in the [conformance matrix](conformance-matrix.md):

- memory locking is not done, so secrets can reach swap;
- zeroization and the exit wipe are implemented but not asserted by automated tests;
- the REPL and the SAS modal have no automated UI tests.

See the [security model](security-model.md), [architecture](architecture.md), and [specification](protocol-spec.md) for details.
