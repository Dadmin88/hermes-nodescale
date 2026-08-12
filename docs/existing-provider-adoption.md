# Existing Tailscale provider adoption

V10 activates the owner-authorized path that turns one existing Tailscale observation into a Nodescale identity. It does not grant trust, an N6 binding, Fleet authority, or job execution by itself.

## Result

A successful confirmation atomically creates:

- one opaque Nodescale `DeviceId`;
- one N5 identity with `existing_provider_adoption` provenance;
- one N5 provider binding with `existing_provider_adoption` provenance;
- one N5 trust record in `untrusted` state;
- terminal adoption evidence, decision, receipt, and audit records.

A failed, stale, substituted, expired, or replay-conflicting proof creates no new `DeviceId`. Exact operation replay returns the existing result.

## Proof contract

`nodescale-adopt` accepts proof only from a live target-origin TCP connection. It:

1. opens the configured Tailscale provider and V10 state;
2. issues a short-lived owner-authorized adoption action;
3. delivers an opaque action challenge;
4. accepts one bounded target payload on the configured Tailscale listener;
5. uses the accepted peer address for controller-side `tailscale whois --json`;
6. requires exact equality between:
   - the pinned provider node ID;
   - WhoIs `Node.StableID`;
   - target-local Tailscale `Self.ID`;
   - WhoIs `Node.Key`;
   - target-local Tailscale `Self.PublicKey`;
7. fresh-rereads the provider and requires the exact pinned observation generation, semantic fingerprint, machine-key fingerprint, and current node-key fingerprint;
8. confirms through one SQLite transaction.

The target payload is one newline-terminated JSON object:

```json
{
  "action_id": "<issued action UUID>",
  "challenge": "<issued nsadopt1 token>",
  "provider_node_id": "<local tailscale Self.ID>",
  "node_key": "<local tailscale Self.PublicKey>"
}
```

The owner token file must be a regular owner-only file. The provider token remains a `secret://systemd/...` credential reference; neither token belongs in arguments, logs, source, or the database.

Before issuing an action, run the challenge-free transport preflight with an explicit operator-approved SSH destination. The destination is not stored in runtime configuration or defaulted by Nodescale. The target must have the matching `nodescale-adoption-target` binary installed on `PATH`:

```text
nodescale-adopt-preflight \
  --provider-node-id <Tailscale stable node ID> \
  --listen <controller Tailscale IP:port> \
  --ssh-destination <operator-approved OpenSSH destination>
```

The controller invokes a fixed `nodescale-adoption-target preflight` command through OpenSSH. Bounded JSON travels only over SSH stdin; no inline shell script, challenge, node key, token, username, or machine alias is embedded in source or command arguments. The preflight creates no adoption or authority rows and carries no challenge.

## One-shot commands

Bootstrap the existing N5 owner root and authority exactly once:

```text
nodescale-owner bootstrap --config <absolute-runtime.toml> --token-file <owner-only-new-file>
```

Run the target-origin adoption collector:

```text
nodescale-adopt \
  --config <absolute-runtime.toml> \
  --root-token-file <owner-only-token-file> \
  --authority-id <authority UUID> \
  --provider-node-id <Tailscale stable node ID> \
  --authorization-operation-id <unique operation ID> \
  --proof-operation-id <unique operation ID> \
  --listen <controller Tailscale IP:port> \
  --ssh-destination <operator-approved OpenSSH destination>
```

If an issued action is stranded and has naturally expired, terminalize that exact action through the owner boundary:

```text
nodescale-owner expire-adoption \
  --config <absolute-runtime.toml> \
  --root-token-file <owner-only-token-file> \
  --action-id <expired action UUID>
```

This succeeds only for an unchanged, unbound observation with no pending proof operation or resulting identity. It records the immutable expiry decision/audit and restores only that observation to `unmanaged`; it creates no device, trust, binding, projection, or Fleet authority.

After successful adoption, explicitly activate trust:

```text
nodescale-owner trust \
  --config <absolute-runtime.toml> \
  --root-token-file <owner-only-token-file> \
  --authority-id <authority UUID> \
  --device-id <adopted DeviceId>
```

N6 then uses the existing Keryx V2 Challenge/Bind service with the adopted `provider_binding_id`. N7 remains origin-agnostic and projects only an active, currently trusted N6 binding.

Run `nodescale-control-node --config <absolute-runtime.toml>` as a separately owned, short-lived Keryx edge with the existing Keryx relay environment and a dedicated keypair. It installs only the typed V1/V2 Nodescale identity handlers; adopted provenance is accepted only through V2.

On the target peer, `nodescale-keryx-v2-publisher` publishes Challenge V2 and then Bind V2 using the target's existing authenticated Keryx node ID/token. The challenge secret stays in that process and is moved directly into the bind nonce; its JSON receipt contains only the authenticated peer and terminal binding identity.

Project the resulting exact active binding through Fleet's existing local managed-control socket:

```text
nodescale-project \
  --config <absolute-runtime.toml> \
  --fleet-socket <absolute-managed-projection.sock> \
  --device-id <adopted DeviceId> \
  --operation-id <unique projection operation ID>
```

The projector rereads durable membership, trust, and exact active N6 provenance. It cannot construct desired Fleet state from request-supplied peer or binding identity.
