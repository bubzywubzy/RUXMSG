# RUXMSG command-line client

`ruxmsg` is the interactive terminal client for RUXMSG. It has two frontends that share the same live sessions: a line-oriented **REPL** for commands and a full-screen **Ratatui conversation view** for messaging.

The REPL handles profiles, connections, sessions, and configuration. The conversation view handles the actual back-and-forth. Press `Esc` or `Ctrl-C` in the conversation view to return to the REPL. The network session normally stays alive when you leave an active conversation; if the peer has already closed, leaving the view drops the session and zeroizes its scrollback.

The client is a single-threaded Tokio program built around the sans-IO protocol engine.

**RUXMSG does not persist peers, sessions, or messages.** The identity seed is the only intended persistent application data, stored in the operating system's credential store. Configuration is read from disk but is never written by the client.

## Launching

```text
ruxmsg                      # start without an identity loaded
ruxmsg --profile alice      # load an existing profile at startup
ruxmsg --config ./my.toml   # read configuration from another file
```

If `--profile` names a profile that doesn't exist, the client reports the error. Create it with `profile init <name>`.

You cannot switch profiles using `profile use` or `profile init` while a listener or active sessions exist. Stop the listener and close the sessions first.

## Profiles and identity

A profile represents one Ed25519 identity. Its 32-byte seed is stored in the operating system's credential store under service `ruxmsg-<profile>`, account `identity`.

There is no trust file, address book, or profile registry. RUXMSG does not maintain a persistent list of profile names, so you need to remember the names you create.

| Command | Effect |
|---|---|
| `profile init <name>` | Create a new identity and make it active. Fails if the profile already exists. |
| `profile use <name>` | Load an existing identity. |
| `profile list` | Not supported. There is no profile registry to enumerate. |
| `fingerprint` | Display your own 64-character hexadecimal public-key fingerprint. |
| `fingerprint <label>` | Display the fingerprint of a connected peer. |

Profile names must be 1–64 characters and contain only ASCII letters, digits, hyphens (`-`), or underscores (`_`).

The identity is stable: loading the same profile gives you the same fingerprint across launches. If the credential-store entry is lost, the identity is lost too. There is no recovery mechanism.

### Credential-store requirements

- **macOS:** Keychain.
- **Windows:** Credential Manager.
- **Linux:** Secret Service, with a running provider such as GNOME Keyring or KWallet.

If startup or `profile init` fails with a storage error, check that the credential store is available to your current session. Verify that the identity survives a client restart on your platform. A fingerprint that unexpectedly changes after a restart should be treated as a bug, not ignored.

## Commands

### Identity

```text
profile init <name>       create an identity profile
profile use <name>        load an existing identity profile
profile list              unsupported; no profile registry exists
fingerprint [label]       show your own or a peer's fingerprint
```

### Network

```text
start [--addr <addr>]     listen for incoming connections
stop                      stop accepting new connections
connect <addr>            connect to a peer
```

The listener defaults to `127.0.0.1:4443`, which is loopback-only. Other devices cannot connect through that address. Use an appropriate reachable address when you need to accept connections across devices.

Binding to every interface exposes the listener on all available network interfaces. The client warns when you do this; make sure that is intentional.

`connect` returns control to the REPL immediately. Connection success or failure is reported asynchronously as an event.

### Sessions

```text
peers                     list sessions and their status
use <label>               set the default messaging target
session <label>           show session details
close <label>             close a session
```

Each connection receives a label such as `peer1` or `peer2`. You can keep multiple connections open at once, but each is an independent two-party session.

### Messaging

```text
rekey <label>             initiate a rekey
chat [label]              open the conversation view
msg <label> <text>        send a message to a specific peer
```

Messages must use `msg <label> <text>` or be entered in the conversation view. Unrecognized input is reported as an unknown command; it is never sent as a message.

### Tailscale

```text
tailscale                 show Tailscale status
tailscale status          show Tailscale status
tailscale up              start Tailscale
tailscale ip              display local Tailscale addresses
```

Running `tailscale` without arguments is equivalent to `tailscale status`.

### General

```text
help                      show available commands
quit                      exit the client
exit                      alias for quit
```

`Ctrl-C` or `Ctrl-D` in the REPL also exits the client.

## First connection and SAS verification

Every connection requires explicit Short Authentication String (SAS) approval, whether it's your first connection or your hundredth. RUXMSG does not remember previously trusted peers.

When a connection reaches the verification stage, both peers see a `SECURITY VERIFICATION` prompt containing three words, the connection direction, and the peer's full hexadecimal fingerprint.

Follow these steps:

1. Compare all three SAS words over an **independent channel**, such as a voice call or an in-person conversation.
2. Make sure the words match exactly. Do not use the RUXMSG connection itself to verify the SAS.
3. Check the peer's fingerprint against a fingerprint you already know, if you have one.
4. Approve only when the SAS matches and the connection is the one you intended to establish.

A matching IP address, hostname, or Tailscale device name is not cryptographic verification.

Type `yes` and press Enter to approve. Any other input, including a single key, `Esc`, or a timeout, rejects the connection. The prompt has a 120-second countdown.

The same verification prompt can appear as a modal in the conversation view. Each prompt is labelled with the connection it belongs to, and up to four pending requests can be queued.

A rejection, timeout, or SAS mismatch aborts the handshake and destroys the candidate session state. **Never approve a connection when the SAS words differ.** Reject it and investigate.

## Conversation view

Run `chat` or `chat <label>` to open the full-screen conversation view for a connected peer. Only one conversation is displayed at a time. You can return to the REPL and switch to another session without closing an otherwise active connection.

The header shows the session state, such as `ACTIVE`, rekeying, or `CLOSED`, alongside the peer's full fingerprint.

| Key | Action |
|---|---|
| `Enter` | Send the current message. |
| `Esc` | Return to the REPL. |
| `Ctrl-C` | Return to the REPL. |
| `Ctrl-R` | Initiate a rekey for the current session. |
| `Up` / `Down` | Scroll one line. |
| `PageUp` / `PageDown` | Scroll one page. |

### Messages and scrollback

Messages belonging to other sessions stay in memory and are announced in the status bar, for example `peerN +count`. They are not displayed in the currently open conversation.

Peer-supplied text is sanitized before display. Control characters and bidirectional formatting characters are escaped so that peer content cannot directly use those characters to manipulate the terminal display. Tabs (`\t`) in peer messages are expanded to four spaces.

Individual scrollback entries are limited to 64 KiB (`MAX_ENTRY_BYTES`). Entries that exceed this limit are truncated at a valid UTF-8 character boundary, with `…` appended to indicate truncation.

Scrollback is bounded to 1,000 entries and 256 KiB per conversation. It exists only in RAM and is zeroized when the session closes, when you leave a conversation whose peer has closed, or when the program exits.

If a peer closes the connection while its conversation view is open, the view displays:

```text
CLOSED — <reason>
```

The view remains available so you can finish reading the existing conversation. Pressing `Esc` or `Ctrl-C` to return to the REPL then drops the session and zeroizes its scrollback.

On exit, the client clears the conversation display and its scrollback. Core dumps are disabled where the operating system permits it.

These measures reduce unnecessary retention, but they cannot protect against a live local compromise, forced termination such as `SIGKILL`, secrets reaching swap, or data retained by the terminal emulator itself.

## Sessions are tied to connections

A session lives only as long as its underlying TCP connection. When the connection drops, the session ends and its session keys are destroyed. Reconnecting requires a new handshake and a new SAS verification.

Closing the client destroys its in-memory sessions.

Running `close <label>` sends a protocol `CLOSE` and ends the session. However, a received `CLOSE` is not proof of the peer's intent: the protocol message is unauthenticated, so an attacker able to inject data into the connection may be able to trigger the same behavior. The client reports the peer as having closed the session, not as having cryptographically proven that the peer deliberately closed it.

## Tailscale

Tailscale provides network reachability, not peer authentication or end-to-end encryption for RUXMSG. The RUXMSG protocol remains responsible for establishing and protecting the session.

Use `tailscale status` to check whether Tailscale is running or requires login. Run `tailscale up` to start it, and `tailscale ip` to display your tailnet addresses.

Use an appropriate reachable Tailscale address with `start --addr` or `connect`. Remember that a listener bound to `127.0.0.1` is only reachable from the same machine.

If the Tailscale executable is not on `PATH`, the client reports that it needs to be installed.

## Configuration

The client supports a global configuration file for appearance and key bindings. It is read once at startup and is never written by RUXMSG. Configuration is not tied to a profile.

The default path is:

```text
$XDG_CONFIG_HOME/ruxmsg/config.toml
```

If `XDG_CONFIG_HOME` is not set, the default is:

```text
~/.config/ruxmsg/config.toml
```

Use `--config <path>` to load a different file. If the file does not exist, the client uses the defaults.

Example:

```toml
[theme]
border = "dark-gray"
accent = "#ff8800"
local = "green"
remote = "yellow"
system = "magenta"
warning = "red"
dim = "gray"

[keys]
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

### Configuration validation

The configuration loader is deliberately strict because it reads a file from a user-writable location.

The file must be a regular file owned by you, must not be writable by group or others, and must not be a symbolic link. It is limited to 16 KiB and must contain valid UTF-8.

Unknown tables, fields, and incorrect types are rejected. The client does not expand variables, include other files, or execute configuration content.

When configuration parsing fails, the client prints a warning containing an error category and line number without quoting the file contents. It then uses the default configuration.

Some keys cannot be rebound: `Enter`, `Backspace`, typing, `Ctrl-C`, `Ctrl-D`, and keys used by the SAS verification prompt. Plain letters cannot be bound to actions, and the same key cannot be assigned to multiple actions.

## Installing and uninstalling

Use the repository scripts to install or remove the client.

### Install

## Linux / macOS

```bash
./scripts/install.sh
```

## Windows (PowerShell)

```powershell
.\scripts\install.ps1
```

Both installers build from the checked-out source with Cargo and the committed lockfile; they do not download release binaries. Rust/Cargo and platform-native build dependencies are required. Linux/macOS use `INSTALL_DIR=/path`; Windows accepts `-InstallDir <path>` or `RUXMSG_INSTALL_DIR`. Defaults are `/usr/local/bin` and `%LOCALAPPDATA%\Programs\RUXMSG`, respectively. The scripts do not modify `PATH`.

Use `./scripts/install.sh --check` or `./scripts/install.ps1 -Check` to validate prerequisites and paths without building. Use `--dry-run` / `-DryRun` to preview build and install actions without changing files. Both scripts support `--help` / `-Help`.

### Uninstall

The uninstall scripts support two modes: `binary` removes the installed executable, while `all` also removes the client's configuration directory.

Both scripts accept a non-mutating `--dry-run` / `-DryRun` preview and help (`--help` / `-Help`). The default remains interactive and asks for confirmation before removing anything. The binary target must be a regular file; `all` recursively removes only the dedicated default configuration directory.

## Linux / macOS

```bash
./scripts/uninstall.sh binary
./scripts/uninstall.sh all
```

## Windows (PowerShell)

```powershell
.\scripts\uninstall.ps1 -Mode binary
.\scripts\uninstall.ps1 -Mode all
```

The `all` mode removes the installed binary and the configuration directory:

- `$XDG_CONFIG_HOME/ruxmsg`, when `XDG_CONFIG_HOME` is set.
- Otherwise, `~/.config/ruxmsg`.

On Windows, the application and script use an absolute process `XDG_CONFIG_HOME`, or process `HOME/.config/ruxmsg`. If neither resolves to an absolute path, `all` mode refuses to guess and remove a config directory.

**Neither uninstall mode removes OS credential-store entries.** Your identity seed remains in Keychain, Credential Manager, or Secret Service. Removing the executable and configuration does not delete your identity.

Check the scripts for supported installation paths and any additional prompts before running them.

## Troubleshooting

| Symptom | Likely cause or action |
|---|---|
| `no identity loaded` | Run `profile use <name>` to load an existing identity or `profile init <name>` to create one. |
| Storage error during `profile init` or `profile use` | The credential store may be unavailable. On Linux, ensure a Secret Service provider is running. |
| Fingerprint changes after restart | The credential-store entry may not be persisting correctly. Treat this as a bug and report it. |
| `Connection refused` | No listener is available at the target address, the address is incorrect, or a firewall is blocking the connection. |
| SAS words differ | Reject the connection. Investigate a possible interception or unintended connection. |
| Handshake fails after a restart | Session state is memory-only. Establish a new connection and verify the SAS again. |
| Session disappears | The underlying connection may have dropped. Reconnect and repeat SAS verification. |
| Peer closes while chat is open | Read the remaining displayed conversation, then press `Esc` or `Ctrl-C` to return to the REPL and release the closed session. |
| Configuration warning at startup | Check the TOML syntax, file permissions, file type, and supported fields. Invalid configuration falls back to defaults. |
| Identity is missing after uninstall | The credential-store entry may have been removed separately. RUXMSG does not provide identity recovery. |

## Known limitations

RUXMSG/1 is still under development. The current outstanding limitations include:

- **Memory locking is not implemented.** Secrets may be eligible for paging to swap.
- **Zeroization and exit-screen wiping are implemented but not asserted by automated tests.**
- **The REPL and SAS verification modal do not have automated UI tests.**
- **Independent security review has not been completed.**

See the [conformance matrix](conformance-matrix.md) for requirement and test status, the [security model](../SECURITY.md) for security assumptions and non-goals, the [architecture guide](architecture.md) for crate boundaries and runtime design, and the [protocol specification](protocol-spec.md) for the normative protocol behavior.
