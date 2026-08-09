# Nodescale

Nodescale is the membership and identity control plane for Hermes Fleet. It manages private-device membership, provider-backed join flows, identity state, reconciliation, and revocation without treating mesh connectivity as application authorization.

> **Mesh membership is not application authorization.** A device appearing in Headscale does not make it a trusted Hermes Fleet node.

## What Nodescale provides

- **Provider discovery and reconciliation** for explicitly configured Headscale networks.
- **Normalized provider identity** that keeps provider, Nodescale, and Keryx identities distinct.
- **Capability-scoped provider mutation** for narrowly authorized operations such as bounded join credentials, exact node updates, and policy management where supported.
- **Single-use invitations and durable join sessions** backed by SQLite transactions and replay-resistant state transitions.
- **A bounded TLS redemption ingress** for exchanging an invitation token for one-time provider bootstrap material.
- **Authoritative logical-device correlation and explicit Nodescale trust** with provider-backed reconciliation, verifier-only owner authority, one-shot revision-fenced decisions, and append-only audit.
- **Durable lifecycle and audit state** with monotonic generations, explicit uncertainty handling, and secret-safe records.

Nodescale is intentionally conservative around trust. Provider observations, hostnames, tags, addresses, pre-auth-key associations, and invitation possession are evidence, not proof of Hermes Fleet authorization.

## Trust boundaries

Nodescale sits between four distinct authorities:

| Component | Authority |
| --- | --- |
| Mesh provider | Mesh admission, node reachability, provider identity, tags, and network policy. |
| Nodescale | Managed membership, Nodescale device identity, roles, lifecycle, generations, and desired application-state intent. |
| Keryx | Authenticated application-transport peer identity and runtime provenance. |
| Hermes Fleet | Final application authorization, scheduling, local policy, and execution. |

Trusted activation requires the relevant identities and policies to agree. Provider admission alone cannot activate a device, create a verified Keryx binding, or grant Hermes Fleet operations.

## Current scope

The repository currently includes:

- a Rust workspace with domain, state, provider, invitation, and redemption-ingress crates;
- read-only Headscale discovery and reconciliation;
- a Headscale mutation adapter with operation-specific authorization;
- opaque single-use invitation issuance and redemption;
- verified-TLS `POST /v1/redemptions` ingress with bounded admission and worker concurrency;
- deterministic fake-provider and loopback test infrastructure;
- Nodescale-generated immutable `DeviceId` confirmation from exact N4/provider registration evidence;
- explicit owner-root-gated logical trust activation/revocation and provider-binding cleanup/reconciliation;
- durable authenticated Keryx identity binding with provider-fresh challenges, replay-safe confirmation, rotation, revocation, and exact-tree acceptance tooling;
- disposable Headscale/Tailscale acceptance tooling for provider join plus N5 identity/trust verification.

N5 implements explicit Nodescale logical trust without making provider membership equivalent to trust. N6 binds that trust to authenticated Keryx transport identity without granting Hermes Fleet authority. Managed Hermes Fleet projection remains a separate integration boundary, and neither provider membership nor a Keryx binding is application activation. See the [N6 authenticated Keryx-binding contract](docs/n6-authenticated-keryx-binding.md).

## Workspace

| Crate | Purpose |
| --- | --- |
| `nodescale-domain` | Typed identities, lifecycle models, generations, secret wrappers, and pure state machines. |
| `nodescale-state` | SQLite schema, provider imports, mutation authorization state, reconciliation inventory, revocation state, and audit events. |
| `nodescale-provider` | Provider-neutral models and separate read-only and mutation contracts. |
| `nodescale-provider-fake` | Deterministic in-memory provider used by tests. |
| `nodescale-provider-headscale` | HTTPS Headscale adapter for discovery and explicitly authorized mutations. |
| `nodescale-invitation` | Invitation issuance, durable redemption, one-time provider-credential delivery, and cleanup orchestration. |
| `nodescale-redemption-ingress` | Bounded verified-TLS invitation redemption transport around `InvitationService`. |
| `nodescale-device-trust` | State-owned exact provider-registration correlation, explicit owner-authorized Nodescale trust, binding reconciliation, and typed trust queries. |
| `nodescale-keryx-adapter` | Authenticated Keryx control-frame parsing and secret-minimizing transport response mapping. |
| `nodescale-binding` | Production N6 provider-fresh challenge, durable binding, authorization, rotation, revocation, and actor lifecycle orchestration. |

## Development

The workspace uses stable Rust and requires `rustfmt` and `clippy`.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
```

See [Development](docs/development.md) for the full validation workflow and acceptance-test notes.

## Documentation

Start with the [documentation index](docs/README.md), then use the focused references below:

- [Architecture](docs/architecture.md)
- [Identity model](docs/identity-model.md)
- [Provider contract](docs/provider-contract.md)
- [Headscale compatibility](docs/headscale-compatibility.md)
- [Discovery and reconciliation](docs/discovery-reconciliation.md)
- [Invitations and redemption](docs/invitations.md)
- [Device identity and trust](docs/device-trust.md)
- [Threat model](docs/threat-model.md)
- [Architecture decision records](docs/adr/)

## License

Current versions of Nodescale are licensed under the GNU Affero General Public License version 3 only (`AGPL-3.0-only`). See [LICENSE](LICENSE).

Code published in earlier commits under Apache-2.0 remains available under the license terms that applied when it was published.
