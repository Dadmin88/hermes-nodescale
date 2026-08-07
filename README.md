# Nodescale

Nodescale is a small private-device membership and identity control plane for Hermes Fleet. This repository contains the accepted N0C Rust foundation, the N1A strictly read-only stock-Headscale provider adapter, and the N2A network-import/discovery reconciliation library.

## Status

N2A can import explicit read-only Headscale configuration, perform initial discovery, persist normalized provider observations, reconcile drift and conflicts, and expose sanitized doctor inventory. It does **not** deploy or mutate Headscale, join devices, bind Keryx identities, activate trusted membership, or project trust into Hermes Fleet.

**A Headscale node appearing in Nodescale discovery does not make it a trusted Hermes Fleet node.**

- Current Hermes Fleet implementation: Python prototype and behavioral reference.
- Planned future Hermes Fleet implementation: Rust.
- Both are the same product: **Hermes Fleet**.

Trusted activation remains gated on authenticated Keryx sender provenance and a stable Hermes Fleet managed-state contract with acceptance tests.

## Workspace

- `crates/nodescale-domain` — typed identities, models, generations, secret wrappers, and pure state machines.
- `crates/nodescale-state` — exclusive SQLite schema, versioned migrations, transactional import/discovery inventory, reconciliation reports, generations, revocation tombstones, and structured audit events.
- `crates/nodescale-provider` — normalized provider models plus separate async read-only and deterministic future-operation contracts.
- `crates/nodescale-provider-fake` — deterministic in-memory provider for tests.
- `crates/nodescale-provider-headscale` — real HTTPS Headscale v0.29.3 inspection adapter; no mutation surface.

## Development

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
```

See [`docs/architecture.md`](docs/architecture.md), [`docs/discovery-reconciliation.md`](docs/discovery-reconciliation.md), [`docs/headscale-compatibility.md`](docs/headscale-compatibility.md), [`docs/threat-model.md`](docs/threat-model.md), and [`docs/development.md`](docs/development.md).

## License

Apache-2.0.
