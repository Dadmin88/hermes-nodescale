# Nodescale runtime

`nodescale-runtime` is the minimal production loop that connects provider reconciliation to the existing N7 Fleet projection boundary. It owns no provider-specific authority outside the adapter and never reads Fleet state databases.

## Lifecycle

Each bounded cycle:

1. opens the file-backed Nodescale state through `StateStore`;
2. imports a configured provider once or reconciles its existing observations;
3. asks `StateStore` for canonical N7 desired projections backed by active Nodescale devices and exact active N6 provenance;
4. submits each desired projection through `N7ProjectionService` and the typed Fleet UDS client;
5. relies on Fleet inspection for authoritative completion;
6. sleeps until the configured interval.

SIGTERM and SIGINT stop the poll loop, close the N7 actor, join its owner thread, and exit cleanly. SQLite state and N7 attempted/applied records make the next start restart-safe.

Provider observations do **not** create devices, trust, Keryx bindings, Fleet rows, or execution authority. A Tailscale device remains `discovered_unmanaged` until the existing Nodescale identity/trust lifecycle can prove and admit it. Tailscale SaaS currently exposes no provider-authenticated join-reference correlation, so that admission path remains intentionally blocked rather than inferred from names, addresses, tags, or tailnet membership.

## Credentials

Configuration stores only `secret://systemd/<name>`. The runtime resolves that name under systemd's `CREDENTIALS_DIRECTORY`, requires a regular bounded file, reads it once, and moves it into the redacted/zeroizing provider key type. Plaintext tokens, environment-variable token values, symlinks, whitespace-bearing credentials, and arbitrary file paths are rejected.

The packaged unit uses:

```ini
LoadCredential=provider-token
```

Provision the matching system credential with the host's supported `systemd-creds` workflow. For example, an administrator may run the following interactively and provide the secret on standard input:

```bash
sudo systemd-creds encrypt --name=provider-token - /etc/credstore.encrypted/provider-token
```

Do not put the token in `runtime.toml`, shell history, an `Environment=` directive, the repository, or Nodescale SQLite state.

## Configuration

Use one of:

- `config/runtime.tailscale.example.toml`
- `config/runtime.headscale.example.toml`

The paths must be absolute. IDs must be stable UUIDs selected by the owner. Tailscale supports `api_access_token` and scoped `oauth_access_token` modes. The Tailscale adapter is deliberately read-only and advertises no mutation capabilities.

Run one bounded cycle for installation smoke testing:

```bash
/usr/bin/nodescale-runtime --config /etc/nodescale/runtime.toml --once
```

Run continuously through the packaged systemd unit. Verify both process state and application cycles:

```bash
systemctl status nodescale-runtime.service
journalctl -u nodescale-runtime.service --since "10 minutes ago"
```

An active process is not proof of a successful cycle. Require a recent `nodescale cycle complete` entry and inspect the reported observed/desired/retryable/conflict counts.

## Fleet boundary

The configured Fleet socket must be Fleet-owned and must authenticate the Nodescale service UID with Linux `SO_PEERCRED`. The runtime sends only `fleet.managed-projection.v1` through `nodescale-fleet-client`. It cannot grant `fleet.hermes.run`; generated grants remain limited to the N7 baseline.
