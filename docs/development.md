# Development

## Prerequisites

- Stable Rust with `rustfmt` and `clippy`.
- No live Headscale, Keryx, Hermes Fleet, Tailscale, or network access is required.
- SQLite is compiled through `rusqlite`'s bundled feature for reproducible CI.

## Checks

```text
cargo metadata --no-deps --format-version 1
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo test -p nodescale-state --test state
cargo build --workspace
git diff --check
python3 scripts/check_public_hygiene.py
```

## Dependency rationale

- `serde` / `serde_json`: typed durable records and sanitized structured audit metadata.
- `chrono`: UTC timestamps with serialization.
- `uuid`: opaque strongly typed Nodescale-owned identifiers.
- `thiserror`: typed domain, state, and provider failures.
- `sha2`: one-way invitation verifier foundation.
- `rusqlite` with bundled SQLite: small synchronous transactional state layer with no runtime/framework.
- `tempfile` (tests only): isolated restart-safe SQLite tests.

No async runtime, HTTP framework, plugin system, message broker, cache, distributed consensus library, or external database is included.

## Test discipline

Behavior changes start with a focused failing test. Pure lifecycle rules stay in `nodescale-domain`; persistence tests use temporary or in-memory Nodescale-owned databases; provider behavior uses only the deterministic fake. Live integration belongs to later separately gated phases.
