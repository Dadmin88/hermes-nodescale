# Nodescale

Nodescale is the device membership and trust layer for Hermes Fleet.

Its job is to answer questions such as:

- Which device joined this private network?
- Is it the same device we expected?
- Has the owner explicitly trusted it?
- Which authenticated Keryx peer belongs to it?
- Should it still be allowed to appear in Hermes Fleet?

The most important rule is:

> **Connected does not mean trusted. Trusted does not mean authorized to execute work.**

## How Nodescale fits into the Hermes stack

```text
Headscale / Tailscale
  Private network membership and reachability
        ↓
Nodescale
  Device identity, trust, join lifecycle, revocation
        ↓
Keryx
  Authenticated application peer identity and transport
        ↓
Hermes Fleet
  Final application grants, readiness, scheduling, execution policy
        ↓
Hermes Agent
  Performs the actual AI work
```

Each layer has its own job. Nodescale never treats Headscale membership as permission to run Hermes work.

## What Nodescale does today

The current implementation includes:

- Headscale discovery and compatibility checks;
- provider reconciliation and safe provider mutations;
- single-use invitations and durable join sessions;
- verified TLS invitation redemption;
- exact logical device identity creation;
- explicit owner-authorized device trust;
- provider-fresh trust checks;
- authenticated Keryx identity binding with replay, rotation, and revocation handling;
- managed Hermes Fleet projection with independent generations and authoritative read-back;
- durable SQLite state, migrations, and audit history;
- disposable acceptance tests using real Headscale/Tailscale and the real Fleet integration path.

The accepted managed flow now looks like this:

```text
device joins private mesh
        ↓
Nodescale correlates the exact provider device
        ↓
Nodescale creates a stable DeviceId
        ↓
owner explicitly trusts the device
        ↓
Keryx proves the application peer identity
        ↓
Nodescale projects safe managed state into Hermes Fleet
```

That final projection is still not blanket execution permission. Generated Fleet authority is limited to the accepted baseline operations, and Fleet-local deny rules remain authoritative.

## The identities are deliberately separate

Nodescale keeps three identities distinct:

1. **Provider identity**: the device as Headscale knows it.
2. **Nodescale DeviceId**: the stable logical identity owned by Nodescale.
3. **Keryx peer identity**: the authenticated application/runtime identity.

A hostname, display name, mesh IP, tag, or caller-provided peer ID is not enough to replace any of those identities.

## Trust is explicit

A device can be:

```text
connected to the mesh
but not trusted
```

or:

```text
trusted by Nodescale
but not yet Keryx-bound
```

or:

```text
trusted + Keryx-bound
but still not allowed to run arbitrary Fleet work
```

This separation is intentional. It limits the damage if a device is misconfigured, compromised, or later revoked.

## Managed Fleet projection

Nodescale N7 adds the production boundary that lets a trusted, Keryx-bound device appear in Hermes Fleet.

Nodescale persists desired Fleet state, sends it through the typed Fleet client, and then reads back Fleet's authoritative stored result before considering the projection applied.

Important properties:

- projection generations are independent and monotonic;
- exact replay is idempotent;
- stale, conflicting, skipped, or regressed generations fail closed;
- Fleet inspection is authoritative for what Fleet actually stored;
- response loss is recovered by inspecting before blindly retrying;
- revocation/disable/remove transitions do not grant execution authority;
- Nodescale never reads or writes Fleet's database directly.

See [N7 authenticated Fleet projection](docs/n7-authenticated-fleet-projection.md).

## Workspace overview

The Rust workspace is split by responsibility. The most important crates are:

| Crate | Purpose |
| --- | --- |
| `nodescale-domain` | Typed IDs, lifecycle rules, generations, and pure state decisions. |
| `nodescale-state` | Nodescale-owned SQLite state, migrations, audit history, and reconciliation state. |
| `nodescale-provider` | Provider-neutral read and mutation interfaces. |
| `nodescale-provider-headscale` | Headscale integration. |
| `nodescale-invitation` | Invitation and join-session lifecycle. |
| `nodescale-redemption-ingress` | Network endpoint for safe invitation redemption. |
| `nodescale-device-trust` | Exact device correlation and explicit trust. |
| `nodescale-binding` | Authenticated Keryx binding lifecycle. |
| `nodescale-fleet-client` | Typed client for the Hermes Fleet managed-projection service. |
| `nodescale-projection` | Production N7 reconciliation from Nodescale intent to Fleet state. |

Test-only helpers and provider fakes are kept separate from production authority paths.

## What Nodescale does not do

Nodescale does not:

- schedule AI work;
- decide CPU/GPU placement;
- execute Hermes runs;
- grant broad Fleet execution just because a node joined;
- read Keryx or Fleet databases directly;
- trust hostnames or IP addresses as device identity;
- replace Headscale or Tailscale.

## Development

The workspace uses stable Rust.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
```

See [Development](docs/development.md) for the complete validation workflow and optional acceptance tests.

## Documentation

Start with [docs/README.md](docs/README.md).

Useful references:

- [Architecture](docs/architecture.md)
- [Identity model](docs/identity-model.md)
- [Invitations and redemption](docs/invitations.md)
- [Device identity and trust](docs/device-trust.md)
- [N6 authenticated Keryx binding](docs/n6-authenticated-keryx-binding.md)
- [N7 authenticated Fleet projection](docs/n7-authenticated-fleet-projection.md)
- [Provider observation runtime](docs/runtime.md)
- [N8 provider-neutral Fleet projection reconciler](docs/n8-provider-neutral-fleet-reconciler.md)
- [Provider contract](docs/provider-contract.md)
- [Headscale compatibility](docs/headscale-compatibility.md)
- [Threat model](docs/threat-model.md)

## License

Current versions of Nodescale are licensed under the GNU Affero General Public License version 3 only (`AGPL-3.0-only`). See [LICENSE](LICENSE).

Code published in earlier commits under Apache-2.0 remains available under the license terms that applied when it was published.
