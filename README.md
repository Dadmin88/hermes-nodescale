# Nodescale

Nodescale is a small private-device membership and identity control plane for Hermes Fleet. This repository contains the accepted N0C Rust foundation, the N1A/N2A read-only Headscale import and reconciliation path, the N3A capability-separated Headscale mutation provider, and the N4A invitation/join-session service.

## Status

N2A can import explicit read-only Headscale configuration, perform discovery, persist normalized provider observations, reconcile drift and conflicts, and expose sanitized doctor inventory. N3A adds separately configured, state-authorized provider mutation primitives for the exact clean Headscale v0.29.3 pin. N4A adds opaque single-use invitations, durable join sessions, and exactly-once coupling to bounded provider credentials. It does **not** deploy Headscale, join devices, bind Keryx identities, activate trusted membership, or project trust into Hermes Fleet.

**A Headscale node appearing in Nodescale discovery does not make it a trusted Hermes Fleet node.**

- Current Hermes Fleet implementation: Python prototype and behavioral reference.
- Planned future Hermes Fleet implementation: Rust.
- Both are the same product: **Hermes Fleet**.

Trusted activation remains gated on authenticated Keryx sender provenance and a stable Hermes Fleet managed-state contract with acceptance tests.

## N3A mutation boundary

N3A is implemented as a separate associated-type mutation boundary. Existing
imports remain `read_only = true` and `mutation_allowed = false`; they cannot
issue mutation authority. An owner must create a separate versioned state
configuration for an exact network/provider instance and exact capability set.
The complete provider surface is deliberately narrow:

- ensure one named network principal;
- create a join credential bounded to that principal, explicit expiry, and
  bounded use count, then invalidate that exact credential;
- set the complete desired tag set, expire, or delete one exact provider node;
- read or apply provider policy **only** in a separately verified database
  mode.

Each item is an independent capability, not a consequence of a role, version,
or server route. A transport acknowledgement is not success: the provider
returns an explicit rejected/unsupported/ambiguous outcome or requires an
authoritative read-back that proves the requested state. It does not assume
provider compare-and-swap (CAS) support. Join-credential plaintext is delivery-only
and does not enter SQLite, logs, diagnostics, or audit metadata; state stores
only a confirmed redacted provider reference. The disposable proof verified
custom-root TLS, exact clean runtime evidence, principal ensure, bounded
credential creation/invalidation, and database policy replacement. Node tag,
expiry, and deletion remain deterministic loopback contract evidence because
the proof was prohibited from joining a node. N3A does not create trusted membership,
Keryx bindings, or Hermes Fleet enrollment, grants, scheduling, or activation.

## N4A invitation boundary

N4A issues an opaque selector plus a 256-bit random secret and persists only an
Argon2id verifier and safe metadata. A successful presentation atomically
reserves one invitation and one durable join session before dispatching one
provider credential creation. The provider credential is single-use,
non-ephemeral, bounded by invitation expiry, and tagged only from the typed role
vocabulary. Invitation and provider plaintext are delivered through consuming,
redacted APIs and never enter SQLite or audit metadata.

SQLite transactions and compare-and-swap predicates reject replay across
connections. A possibly-applied creation whose secret is unavailable is never
retried. Revocation and expiry invalidate the exact provider reference and stay
nonterminal when provider certainty is ambiguous. The disposable production
proof exercised create, redeem, replay rejection, and revoke through the real
Headscale v0.29.3 adapter while provider-node and all trusted-activation counters
remained zero. A real device join remains explicitly deferred.

## Workspace

- `crates/nodescale-domain` — typed identities, models, generations, secret wrappers, and pure state machines.
- `crates/nodescale-state` — exclusive SQLite schema, read-only imports, explicit mutation configuration and single-use authorization, reconciliation inventory, generations, revocation tombstones, and structured audit events.
- `crates/nodescale-provider` — normalized provider models plus separate async read-only and capability-separated mutation contracts.
- `crates/nodescale-provider-fake` — deterministic in-memory provider for tests.
- `crates/nodescale-provider-headscale` — real HTTPS Headscale v0.29.3 inspection and explicitly authorized mutation adapters.
- `crates/nodescale-invitation` — opaque invitation issuance, durable redemption, one-time provider-credential delivery, and conservative cleanup orchestration.

## Development

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
```

See [`docs/architecture.md`](docs/architecture.md), [`docs/invitations.md`](docs/invitations.md), [`docs/discovery-reconciliation.md`](docs/discovery-reconciliation.md), [`docs/headscale-compatibility.md`](docs/headscale-compatibility.md), [`docs/threat-model.md`](docs/threat-model.md), and [`docs/development.md`](docs/development.md).

## License

Apache-2.0.
