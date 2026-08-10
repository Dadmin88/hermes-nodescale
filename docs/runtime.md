# Nodescale provider observation runtime

`nodescale-runtime` is the minimal production loop that persists provider observations through the existing `StateStore`. It owns no provider-specific authority outside the selected adapter and never reads Fleet databases.

## Lifecycle

Each bounded cycle:

1. opens file-backed Nodescale state through `StateStore`;
2. imports a configured provider once or reconciles its existing observations;
3. commits a complete successful snapshot atomically;
4. preserves prior observations on provider failure;
5. sleeps until the configured interval.

SIGTERM and SIGINT stop the current-thread poll loop cleanly. SQLite observations and sanitized import metadata survive restart. Provider observations do **not** create devices, trust, Keryx bindings, Fleet rows, or execution authority.

## Deliberate N7 boundary

The daemon does **not** automatically project to Fleet. The earlier automatic loop was removed because unchanged polls advanced projection generations and eligibility withdrawal could leave stale Fleet authority active.

The explicit N7 library boundary remains unchanged for authorized callers. Automatic provider-to-Fleet reconciliation stays blocked until a durable state-owned reconciler proves all of the following:

- desired Fleet state comes from authoritative provider state plus trusted N6 provenance;
- unchanged desired state is a strict no-op across poll and restart;
- generations advance only on semantic transitions;
- provider disappearance, trust/binding withdrawal, revocation, disablement, and identity replacement create explicit disable/remove successors;
- retries are idempotent and failed delivery never marks state applied;
- last successfully applied state is durable and provider-neutral.

Tailscale SaaS currently exposes no provider-authenticated join-reference correlation, so Tailscale observations remain `discovered_unmanaged`. Do not infer admission from names, addresses, tags, or tailnet membership.

## Credentials

Configuration stores only `secret://systemd/<name>`. The runtime resolves that name under systemd's `CREDENTIALS_DIRECTORY`, opens the credential with no-follow/close-on-exec semantics, validates the opened regular file and bound, reads it once, and moves it into the redacted/zeroizing provider-key type. Plaintext config/env values, whitespace-bearing credentials, symlinks, and arbitrary paths are rejected.

The packaged unit decrypts the named system credential explicitly:

```ini
LoadCredentialEncrypted=provider-token:/etc/credstore.encrypted/provider-token
```

Provision the matching encrypted system credential interactively:

```bash
sudo systemd-creds encrypt --name=provider-token - /etc/credstore.encrypted/provider-token
```

Do not put the value in `runtime.toml`, shell history, `Environment=`, the repository, or SQLite.

## Installation contract

The system service assumes a dedicated `nodescale` account and installed artifacts. Build the exact release payload first, then install root-owned configuration readable by the service group:

```bash
cargo build -p nodescale-runtime --release --locked
sudo groupadd --system nodescale
sudo useradd --system --gid nodescale --home-dir /var/lib/nodescale --shell /usr/sbin/nologin nodescale
sudo install -Dm0755 target/release/nodescale-runtime /usr/bin/nodescale-runtime
sudo install -Dm0644 packaging/systemd/nodescale-runtime.service /etc/systemd/system/nodescale-runtime.service
sudo install -d -m0710 -o root -g nodescale /etc/nodescale
sudo install -m0640 -o root -g nodescale config/runtime.tailscale.example.toml /etc/nodescale/runtime.toml
```

The resulting configuration ownership is `root:nodescale`; the runtime account cannot rewrite its provider selection, identity, paths, or credential reference.

Edit the installed config with owner-selected IDs before activation. Do not enable the unit while example values remain.

Use one of:

- `config/runtime.tailscale.example.toml`
- `config/runtime.headscale.example.toml`

Paths must be absolute and IDs stable owner-selected UUIDs. The continuous Tailscale runtime accepts API access tokens. Library-only caller-managed OAuth bearer support remains available, but the daemon does not advertise it because it lacks client-credential refresh.

Validate the unit and let systemd provide the credential during the smoke cycle:

```bash
sudo systemd-analyze verify /etc/systemd/system/nodescale-runtime.service
sudo systemctl daemon-reload
sudo systemctl enable --now nodescale-runtime.service
sudo systemctl status nodescale-runtime.service
sudo journalctl -u nodescale-runtime.service --since "10 minutes ago"
```

Require a recent `nodescale observation cycle complete` entry. An active process alone is not proof of provider reconciliation.
