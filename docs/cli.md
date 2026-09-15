# RUXMSG command-line client

The `ruxmsg` binary is a small terminal client for one peer-to-peer TCP connection. It is useful for exercising the protocol foundation, but it is not yet a complete multi-peer messaging application.

## Build and run

Build the binary with Cargo, then choose one side as the listener and the other as the connector.

Listener:

```text
ruxmsg --profile alice listen --addr 127.0.0.1:4443
```

Connector:

```text
ruxmsg --profile bob connect 127.0.0.1:4443
```

Use an address reachable by both peers when running across hosts. A transport such as Tailscale can provide reachability, but its network identity is not used as cryptographic proof.

## Profiles and local state

The `--profile` option scopes local credentials. The default profile is `default`.

The client uses:

- an OS credential-store entry named `ruxmsg-<profile>` for the identity seed and trust-store sealing key;
- a sealed trust file at `$HOME/.ruxmsg/<profile>/trust.sealed`.

The identity seed is generated on first use and remains stable for that profile. Do not copy the sealed file without the matching credential-store secret: the file alone is not sufficient to recover its records.

Credential-store availability depends on the operating system and desktop/session configuration. On Linux, the `keyring` dependency uses Secret Service; a working Secret Service provider may be required before the client can start.

## First-contact verification

During the initial handshake, each side displays a three-word SAS. Compare the words through an independent channel. Approve the connection only if the values match exactly and belong to the intended peer.

Reject a mismatch. Do not treat a matching TCP address, hostname, or Tailscale peer name as a replacement for SAS verification.

## Interaction

Once the connection is ready, type messages in the terminal UI. Incoming messages are displayed by the reader loop. Closing the UI or selecting the close action sends a protocol `CLOSE` and destroys local session state.

The current client implementation establishes one connection per process and uses one reader path plus one writer path. It does not yet provide a peer list, multi-conversation UI, or a complete trusted-peer enrollment workflow that skips SAS on later sessions.

## Troubleshooting

- **Credential-store errors:** verify that the OS keyring/Secret Service is available to the current user session.
- **Connection refused:** start the listener first and check the address and firewall.
- **SAS mismatch:** abort and investigate; never approve a mismatch.
- **Handshake failure after restart:** expected session keys are in memory only, so a fresh handshake is required.
- **Unexpected identity:** stop and verify the peer out of band before changing trust records.

For the protocol and implementation details, see the [architecture guide](architecture.md), [security model](security-model.md), and [protocol specification](../protocol-spec.md).
