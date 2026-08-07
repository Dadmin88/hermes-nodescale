# Architecture

## Boundary

Nodescale owns managed membership, Nodescale device identity, roles, lifecycle, generations, and desired application-state intent. A mesh provider owns mesh admission and reachability. Keryx owns authenticated transport peer identity. Hermes Fleet owns final application authorization and scheduling.

Mesh membership is never application authorization.

## N0C crates

The workspace deliberately has four crates. The domain crate is pure. State owns one SQLite database and never reads provider, Keryx, or Hermes Fleet databases. Provider models are normalized before they can enter trusted state. The fake provider is deterministic test infrastructure, not production identity evidence.

## Identity separation

Provider identity, Nodescale identity, and verified Keryx identity are distinct types and records. Hostname, display name, mesh address, tags, and payload-supplied peer identifiers are observations only.

## Generations

Nodescale persists separate monotonic generations for network membership, device credentials, Keryx bindings, and Fleet projection. Compare-and-swap updates reject stale writers. Exact replay may be idempotent only where content identity is unchanged; same-generation divergent content is a conflict.

## Revocation

The durable ordering removes application trust before relying on provider cleanup:

`requested → application trust removal pending → credential revocation pending → Keryx binding disable pending → provider cleanup pending → revoked`

Provider outage can delay mesh cleanup but cannot preserve application authorization.

## Explicitly deferred

No server, agent, CLI, Headscale provider, Keryx adapter, Fleet adapter, privileged helper, web console, deployment tooling, distributed consensus, or live activation exists in N0C.
