# Development

## Prerequisites

- Stable Rust with `rustfmt` and `clippy`.
- No live Headscale, Keryx, Hermes Fleet, Tailscale, or network access is required for the default checks.
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
TREE="$(git write-tree)"
PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_public_hygiene.py --repo "$(pwd)" --tree "$TREE"
```

## Dependency rationale

- `serde` / `serde_json`: typed durable records and sanitized structured audit metadata.
- `chrono`: UTC timestamps with serialization.
- `uuid`: opaque strongly typed Nodescale-owned identifiers.
- `thiserror`: typed domain, state, and provider failures.
- `sha2`: stable non-secret fingerprints for provider/runtime evidence.
- `argon2`, `rand`, and `base64`: fixed-profile salted invitation verification and opaque 256-bit token generation.
- `rusqlite` with bundled SQLite: small synchronous transactional state layer with no runtime/framework.
- `async-trait`: narrow object-safe asynchronous read boundary shared by real and fake providers.
- `reqwest` with Rustls: HTTPS-only real-provider reads, URL/origin validation, normal certificate verification, and bounded requests.
- direct `rustls` ring provider selection: deterministic process-level crypto backend when client and server TLS feature sets coexist.
- `axum` / `axum-server`: the single strict N4B redemption route and verified-TLS serving boundary.
- `url`: canonical validation of the public Headscale login origin returned in bootstrap material.
- `semver`: deterministic fail-closed Headscale version classification.
- `tokio`: bounded ingress channel/current-thread worker plus deterministic transport and timeout tests.
- `tempfile` (tests only): isolated restart-safe SQLite tests.

No general web framework surface, plugin system, message broker, cache, distributed consensus library, or external database is included. Axum is confined to one N4B route. The Headscale crate remains a client library only.

## Test discipline

Behavior changes start with a focused failing test. Pure lifecycle rules stay in `nodescale-domain`; persistence tests use temporary or in-memory Nodescale-owned databases; provider behavior uses deterministic loopback servers and the fake provider. The ignored `disposable_provider` test remains the N4A credential-only proof. The retained `proofs/n4b/run.py` harness is the only supported N4B join acceptance path: it requires an exact candidate tree, extracts and builds that tree with locked dependencies and an external target directory, pins and platform-checks every runtime image, creates an isolated bridge, passes provider authority by owner-only file, runs ingress and clients without capabilities/host networking/TUN, and fails closed unless runtime cleanup and repository/host invariants hold. Its secret-free external JSON manifest—not source presence—establishes a completed run. Neither ignored proof is part of default CI.
