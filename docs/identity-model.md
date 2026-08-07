# Identity Model

Nodescale keeps three non-substitutable identities:

1. **Provider device identity** — proved by the provider's canonical node record and strongest stable key material.
2. **Nodescale device identity** — proved by Nodescale's typed device ID, authenticated join session, device credential, and credential generation.
3. **Keryx peer identity** — proved only by authenticated Keryx runtime/session provenance.

A durable binding relates these identities without collapsing them. Display names such as `controller-1`, hostnames, mesh addresses, tags, and request-body peer IDs are never authoritative.

For Headscale v0.29.3, the strongest scoped provider tuple is the owner-configured provider instance, canonical positive numeric Headscale node ID, and SHA-256 machine-key fingerprint. The node ID is canonical only inside that provider instance. The machine key is strong but replaceable stable-conditional correlation evidence; a changed fingerprint is a conflict/rotation observation, not automatic replacement. Node and disco keys are mutable cryptographic observations. User identity and pre-auth credential ID are conditional correlation metadata. Hostname/given name are mutable presentation metadata, addresses are mutable addressing metadata, and tags/online/timestamps are mutable observations. None can substitute for the provider tuple.

The N0C model can represent a pending or verified Keryx binding, its generation, verification time, and rotation metadata. It does not implement provenance or the future binding protocol. A self-reported Keryx peer value cannot create a verified binding.

Roles (`node`, `worker`, `controller`, `profile_host`, `observer`, `admin`) are descriptive. Exact operations (`fleet.health`, `fleet.inventory`, `fleet.message`, `fleet.hermes.run`) are separate values. No role automatically grants any operation, and membership never automatically grants `fleet.hermes.run`.

## N3A identity and mutation boundary

N3A can ensure a named provider principal and issue a bounded join
credential for it, but neither value proves Nodescale-device identity, a
completed join, or Keryx provenance. Credential creation requires explicit
principal, expiry, and use-count bounds; invalidation is by exact provider
credential ID. The plaintext credential is delivery-only and redacted from all
ordinary state, audit, and diagnostic surfaces.

Tag replacement, expiry, and deletion may target only the full scoped
`ProviderIdentity`; names, addresses, tags, and user metadata remain unsafe
selectors. Tags are provider policy metadata, not application grants. Provider
policy itself is a separate capability and is available only when a
database-mode compatibility decision is independently verified in isolated
proof—not because an identity, role, or HTTP API permits another mutation.

No provider mutation is assumed compare-and-swap (CAS). A requested identity-bound
state becomes certain only through authoritative read-back when available;
`rejected`, `unsupported`, and `ambiguous` outcomes must not be collapsed into
success. This mutation boundary cannot establish a verified Keryx binding or authorize
Hermes Fleet enrollment, grants, scheduling, or execution.
