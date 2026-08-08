# Nodescale

Nodescale is a small private-device membership and identity control plane for Hermes Fleet. This repository contains the accepted N0C Rust foundation, the N1A/N2A read-only Headscale import and reconciliation path, the N3A capability-separated Headscale mutation provider, the N4A invitation/join-session service, the N4B bounded redemption ingress, and the N5 authoritative device-identity/trust lifecycle.

## Status

N2A can import explicit read-only Headscale configuration, perform discovery, persist normalized provider observations, reconcile drift and conflicts, and expose sanitized doctor inventory. N3A adds separately configured, state-authorized provider mutation primitives for the exact clean Headscale v0.29.3 pin. N4A adds opaque single-use invitations, durable join sessions, and exactly-once coupling to bounded provider credentials. N4B adds a single verified-TLS redemption route plus an exact-tree disposable Tailscale/Headscale acceptance harness. N5 adds a Nodescale-generated logical device ID, exact join-session/provider-registration binding, explicit owner-authorized trust activation/revocation, append-only trust history, and a typed internal trust query. Completed N4B/N5 join claims require external evidence for the exact candidate tree; source presence alone is not execution evidence. N5 does **not** deploy production Headscale, bind Keryx identities, enroll Fleet, issue Fleet grants, or activate Hermes.

**A Headscale node appearing in Nodescale discovery does not make it a trusted Hermes Fleet node.**

- Current Hermes Fleet implementation: Python prototype and behavioral reference.
- Planned future Hermes Fleet implementation: Rust.
- Both are the same product: **Hermes Fleet**.

Nodescale trust activation is implemented in N5 and remains separate from provider membership. Keryx binding and Hermes Fleet authority remain gated on authenticated runtime provenance and later acceptance contracts.

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
remained zero. A real device join was explicitly deferred from N4A.

## N4B redemption-ingress boundary

N4B exposes only `POST /v1/redemptions`. The strict JSON body contains one
opaque invitation token; URLs, query strings, headers, cookies, forwarded peer
claims, hostnames, and client-supplied audit identities cannot carry or augment
the capability. Possession authenticates redemption but does not authenticate a
device or agent identity.

Per-source and global monotonic token buckets run before parsing or Argon2 work,
with a bounded source table and worker queue. A dedicated single-thread worker
owns `StateStore`, `InvitationService`, and provider authority, bounding Argon2
and provider creation concurrency to one while SQLite remains the exactly-once
security boundary across processes. The successful response contains only the
validated Headscale login origin, optional public CA material, and the consuming
one-time provider credential. Errors and caches cannot expose invitation state.

The retained acceptance harness must race two isolated redeemers, accept exactly one, reject
replay, and run a pinned Tailscale v1.98.10 userspace client with no capabilities,
TUN device, host socket, or host network. Headscale v0.29.3 observes exactly one
node whose pre-auth ID matches the durable credential reference. That is provider
credential association only—not trusted device identity. The client is stopped,
the exact credential is revoked through `InvitationService`, the exact node is
deleted. Acceptance requires exact-tree evidence of zero runtime residue, unchanged
repository and host-network invariants, and separately reported retained image cache.

## N5 authoritative identity and trust boundary

N5 confirms a logical Nodescale device only when one exact confirmed N4 provider-native credential reference matches one authoritative, non-expired Headscale pre-auth association and its machine-key evidence matches the canonical fingerprint. Nodescale generates the immutable UUID `DeviceId`; hostname, IP, timing, provider numeric ID, and labels are never identity selectors. Logical devices and provider bindings are separate records and lifetimes.

Every confirmed device starts untrusted. Owner-controlled configuration and one-time typed authorization actions gate exact-device activation and revocation. Trust decisions are append-only, revisioned, capability-specific, and bounded to normalized principal provenance. Revocation is terminal in N5. The internal query reports both logical trust and provider-binding state and returns current trust only when state is trusted and the exact binding is active. See [`docs/device-trust.md`](docs/device-trust.md).

N5 deliberately creates no Keryx binding, Fleet enrollment/grant, Hermes activation, runtime profile, scheduler, or public trust endpoint.

## Workspace

- `crates/nodescale-domain` — typed identities, models, generations, secret wrappers, and pure state machines.
- `crates/nodescale-state` — exclusive SQLite schema, read-only imports, explicit mutation configuration and single-use authorization, reconciliation inventory, generations, revocation tombstones, and structured audit events.
- `crates/nodescale-provider` — normalized provider models plus separate async read-only and capability-separated mutation contracts.
- `crates/nodescale-provider-fake` — deterministic in-memory provider for tests.
- `crates/nodescale-provider-headscale` — real HTTPS Headscale v0.29.3 inspection and explicitly authorized mutation adapters.
- `crates/nodescale-invitation` — opaque invitation issuance, durable redemption, one-time provider-credential delivery, and conservative cleanup orchestration.
- `crates/nodescale-redemption-ingress` — bounded verified-TLS capability redemption routed through `InvitationService`.
- `crates/nodescale-device-trust` — exact provider-registration correlation, logical device confirmation, typed trust activation/revocation, and authoritative internal trust query.

## Development

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace
```

See [`docs/architecture.md`](docs/architecture.md), [`docs/device-trust.md`](docs/device-trust.md), [`docs/invitations.md`](docs/invitations.md), [`docs/discovery-reconciliation.md`](docs/discovery-reconciliation.md), [`docs/headscale-compatibility.md`](docs/headscale-compatibility.md), [`docs/threat-model.md`](docs/threat-model.md), and [`docs/development.md`](docs/development.md).

## License

Apache-2.0.
