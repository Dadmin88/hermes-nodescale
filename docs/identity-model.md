# Identity Model

Nodescale keeps three non-substitutable identities:

1. **Provider device identity** — proved by the provider's canonical node record and strongest stable key material.
2. **Nodescale device identity** — proved by Nodescale's typed device ID, authenticated join session, device credential, and credential generation.
3. **Keryx peer identity** — proved only by authenticated Keryx runtime/session provenance.

A durable binding relates these identities without collapsing them. Display names such as `controller-1`, hostnames, mesh addresses, tags, and request-body peer IDs are never authoritative.

The N0C model can represent a pending or verified Keryx binding, its generation, verification time, and rotation metadata. It does not implement provenance or the future binding protocol. A self-reported Keryx peer value cannot create a verified binding.

Roles (`node`, `worker`, `controller`, `profile_host`, `observer`, `admin`) are descriptive. Exact operations (`fleet.health`, `fleet.inventory`, `fleet.message`, `fleet.hermes.run`) are separate values. No role automatically grants any operation, and membership never automatically grants `fleet.hermes.run`.
