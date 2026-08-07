# Nodescale

Nodescale is a small private-device membership and identity control plane for Hermes Fleet. This repository contains the accepted N0C Rust foundation and the N1A strictly read-only stock-Headscale provider adapter.

## Status

N1A can inspect a pinned Headscale API, classify compatibility and health, and normalize provider-node evidence. It does **not** deploy or mutate Headscale, join devices, bind Keryx identities, activate trusted membership, or project trust into Hermes Fleet.

- Current Hermes Fleet implementation: Python prototype and behavioral reference.
- Planned future Hermes Fleet implementation: Rust.
- Both are the same product: **Hermes Fleet**.

Trusted activation remains gated on authenticated Keryx sender provenance and a stable Hermes Fleet managed-state contract with acceptance tests.

## Workspace

- `crates/nodescale-domain` — typed identities, models, generations, secret wrappers, and pure state machines.
- `crates/nodescale-state` — exclusive SQLite schema, migrations, transactions, generations, revocation tombstones, and structured audit events.
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

See [`docs/architecture.md`](docs/architecture.md), [`docs/headscale-compatibility.md`](docs/headscale-compatibility.md), [`docs/threat-model.md`](docs/threat-model.md), and [`docs/development.md`](docs/development.md).

## License

Apache-2.0.
