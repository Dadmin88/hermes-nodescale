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

## Optional same-UID observation socket

The runtime has no observation socket unless configuration contains an explicit `[observation_api]` table. V1 is Linux Unix-domain-socket only: `socket_path` must be absolute and canonical, its direct parent must be owned by the runtime UID with mode `0700`, and `peer_uid` must exactly equal the runtime service effective UID. The owned socket is mode `0600`; group and cross-UID sharing are not supported. Startup refuses every pre-existing socket-path entry, including another active socket, rather than unlinking foreign state. Graceful shutdown removes only the exact socket inode created by that listener.

The protocol version is `nodescale.observations.v1`. A client writes one big-endian u32 length-prefixed JSON request, then closes its write half. Closed request kinds are `capabilities`, `summary` with `network_id`, and `list` with `network_id`, bounded `limit`, and optional provider-node-ID `cursor`. Invalid, duplicate, unknown, truncated, trailing, or oversized input receives only a sanitized `invalid_request` result; valid requests that cannot read authoritative local state receive only `unavailable`. An unauthorized peer is closed before any body parsing. List responses never exceed the advertised 64 KiB frame bound; when a requested page must be shortened or may have more rows, `next_cursor` is the canonical provider-node ID of the last returned row. Paging is a current-state best-effort view, not an immutable event stream or frozen multi-page snapshot.

Responses are explicitly projected durable current-state observations. They expose an opaque deterministic observation ID, provider/network identifiers, bounded display/network fields, provider liveness/timestamps/classification, and a separate reconciliation freshness summary. They never expose device IDs, fingerprints, provider user data, credential correlation, keys, secrets, audit/trust/readiness/operations state, or Fleet/N5/N6/N7 data. Reads never reconcile a provider or mutate Nodescale state.

## Optional same-UID operator-control socket

The separate `[operator_api]` listener is disabled unless configured explicitly. It uses the same private-parent, exact `SO_PEERCRED` UID, mode `0600`, no-pre-existing-path, and owned-inode cleanup rules as the observation socket, but it has a separate path and protocol. Provider observation access never inherits operator authority.

The first contract slice is `nodescale.operator.v1` and is deliberately read-only. Its only request kinds are `capabilities`, bounded `devices.list`, and exact `devices.inspect`. `capabilities` advertises an empty mutation-operation set. Requests use one big-endian u32 length-prefixed JSON document followed by write-half close; unknown, duplicate, malformed, trailing, truncated, and oversized input is rejected with fixed error categories. Device pages are scoped to one exact network and use canonical device IDs as stable current-state cursors. Responses are capped at 64 KiB.

Operator device records expose durable Nodescale-owned identity, membership lifecycle, generation, projection-status, N5 trust-state/revision, provider-binding lifecycle, and latest N6 binding evidence. They never expose provider stable-key fingerprints, provider credential references, trust roots, authorizations, invitation tokens, nonces, or other secret material. This read path does **not** reconcile a provider: `live_trust_evidence` is therefore `not_reconciled_by_operator_read`. N6 lifecycle evidence is not transport-health evidence, so `live_keryx_binding_health` remains `not_exposed`. No value in this API grants Fleet admission, scheduler readiness, or execution permission.

Trust/revoke and invitation operations remain unavailable until later Phase 4 slices add individually typed, revision-fenced mutations with authoritative read-back. Fleet must consume this contract and must never query Nodescale SQLite directly.

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

The resulting configuration ownership is `root:nodescale`; the runtime account cannot rewrite its provider selection, identity, paths, or credential reference. The system unit leaves both local APIs disabled because the installed example has no active `[observation_api]` or `[operator_api]` section. Do not add a socket path until the owner has selected a same-UID local consumer and a service-owned `0700` parent directory.

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
