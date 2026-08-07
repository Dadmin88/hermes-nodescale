# Nodescale

Nodescale is a small private-device membership and identity control plane for Hermes Fleet. This repository currently contains the N0C foundation: a pure Rust domain model, Nodescale-owned SQLite state, a provider-neutral contract, and a deterministic fake provider.

## Status

N0C is foundation-only. It does **not** deploy or mutate Headscale, join devices, bind Keryx identities, or project trust into Hermes Fleet.

- Current Hermes Fleet implementation: Python prototype and behavioral reference.
- Planned future Hermes Fleet implementation: Rust.
- Both are the same product: **Hermes Fleet**.

Trusted activation remains gated on authenticated Keryx sender provenance and a stable Hermes Fleet managed-state contract with acceptance tests.

## Workspace

- `crates/nodescale-domain` — typed identities, models, generations, secret wrappers, and pure state machines.
- `crates/nodescale-state` — exclusive SQLite schema, migrations, transactions, generations, revocation tombstones, and structured audit events.
- `crates/nodescale-provider` — normalized provider models and capability-aware provider trait.
- `crates/nodescale-provider-fake` — deterministic in-memory provider for tests.

## Development

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
```

See [`docs/architecture.md`](docs/architecture.md), [`docs/threat-model.md`](docs/threat-model.md), and [`docs/development.md`](docs/development.md).

## License

Apache-2.0.
