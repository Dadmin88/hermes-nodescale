# Development

## Prerequisites

- Stable Rust with `rustfmt` and `clippy`.
- Python 3 for repository hygiene and optional acceptance tooling.
- No live Headscale, Keryx, Hermes Fleet, Tailscale, or external network access is required for the default workspace checks.
- SQLite is compiled through `rusqlite`'s bundled feature for reproducible local and CI behavior.

## Standard validation

Run the full local validation set from the repository root:

```bash
cargo metadata --locked --no-deps --format-version 1
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo test -p nodescale-state --test state --locked
cargo build --workspace --locked
git diff --check
TREE="$(git write-tree)"
PYTHONDONTWRITEBYTECODE=1 python3 scripts/check_public_hygiene.py --repo "$(pwd)" --tree "$TREE"
```

The default checks are designed to be deterministic and to avoid dependence on production services.

## Test discipline

Keep behavior close to the layer that owns it:

- pure lifecycle and authorization rules belong in `nodescale-domain`;
- persistence behavior belongs in `nodescale-state` tests using temporary or in-memory Nodescale-owned databases;
- provider behavior should use the deterministic fake provider or bounded loopback servers;
- integration tests must preserve the same identity and capability boundaries as production code;
- secret-bearing values must not appear in fixtures, snapshots, logs, diagnostics, or failure messages.

Behavior changes should begin with a focused failing test when practical. Security-sensitive state transitions should include replay, stale-generation, ambiguous-outcome, and restart cases where applicable.

## Acceptance tooling

The repository includes optional disposable provider acceptance tooling under `proofs/`. It is intentionally separate from default CI because it launches pinned Headscale and Tailscale runtime images and validates a complete provider-join flow.

The harness is expected to:

- operate on an exact candidate Git tree;
- use locked Rust dependencies and an external target directory;
- verify pinned runtime images before use;
- isolate runtime networking;
- avoid host networking, TUN access, and unnecessary Linux capabilities;
- keep provider authority in owner-readable temporary files;
- validate single-use redemption and exact provider credential association;
- confirm one opaque logical `DeviceId` only from exact active N4 provenance, `ProviderAuthenticatedRegistration`, exact provider re-read, and matching machine-key fingerprint;
- prove pre-trust false, owner-root-gated activation true, explicit revocation false, provider cleanup/stale binding, and zero final trusted devices;
- prove zero Keryx bindings, Fleet enrollment/grants, and Hermes activation;
- revoke the credential and delete the disposable provider node during cleanup;
- fail if repository, listener, runtime-root, or host-network invariants are not restored.

Exact-tree N5 acceptance evidence establishes the disposable Nodescale identity/trust lifecycle only. It does not establish authenticated Keryx identity or Hermes Fleet authority.

## Dependency rationale

Key workspace dependencies are intentionally narrow:

- `serde` / `serde_json` — typed durable records and structured metadata.
- `chrono` — UTC timestamps and serialization.
- `uuid` — opaque strongly typed Nodescale identifiers.
- `thiserror` — typed failure surfaces.
- `sha2` — stable non-secret fingerprints and correlation digests.
- `argon2`, `rand_core`, and `base64` — invitation verification and opaque token generation.
- `rusqlite` with bundled SQLite — synchronous transactional state without an external database service.
- `async-trait` — object-safe asynchronous provider boundaries.
- `reqwest` with Rustls — HTTPS provider transport with normal certificate verification.
- `rustls` — deterministic TLS provider selection for client/server coexistence.
- `axum` / `axum-server` — the bounded redemption HTTP surface.
- `url` — canonical validation of provider login origins.
- `semver` — deterministic provider-version classification.
- `tokio` — bounded ingress, transport, and timeout coordination.
- `tempfile` — isolated test state.

Nodescale deliberately avoids introducing a message broker, cache service, distributed consensus layer, or external database into the current architecture.

## Versioned binary releases

A repository tag using a release name such as `v1.0.0` runs
`.github/workflows/release.yml`. The
workflow builds every `nodescale-runtime` binary with the locked dependency
graph and publishes one Linux x86-64 archive plus a SHA-256 checksum. The
archive includes the systemd unit template but contains no configuration,
provider credentials, trust-root token, or durable state.

Ordinary installations should consume an exact tag and verify the adjacent
checksum before installing binaries. A moving branch archive or developer
checkout is not an installation artifact. Creating a tag is a separate owner
release action; pull-request CI never publishes a release.
