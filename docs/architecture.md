# Architecture

## Boundary

Nodescale owns managed membership, Nodescale device identity, roles, lifecycle, generations, and desired application-state intent. A mesh provider owns mesh admission and reachability. Keryx owns authenticated transport peer identity. Hermes Fleet owns final application authorization and scheduling.

Mesh membership is never application authorization.

N2A imports an explicitly configured provider instance and persists normalized observations separately from trusted device records. Reconciliation is a deterministic one-shot library operation designed for later scheduling; it performs no provider mutation. See [Network Import and Read-Only Reconciliation](discovery-reconciliation.md).

**A Headscale node appearing in Nodescale discovery does not make it a trusted Hermes Fleet node.**

## Workspace crates

The workspace deliberately has five crates. The domain crate is pure. State owns one SQLite database and never reads provider, Keryx, or Hermes Fleet databases. Provider models are normalized before they can enter trusted state. The fake provider is deterministic test infrastructure, not production identity evidence. The Headscale crate implements both the permanent async read-only trait and a separate associated-type mutation trait; the read-only trait contains no mutation method.

## Identity separation

Provider identity, Nodescale identity, and verified Keryx identity are distinct types and records. Hostname, display name, mesh address, tags, and payload-supplied peer identifiers are observations only.

## Generations

Nodescale persists separate monotonic generations for network membership, device credentials, Keryx bindings, and Fleet projection. Compare-and-swap updates reject stale writers. Exact replay may be idempotent only where content identity is unchanged; same-generation divergent content is a conflict.

## Revocation

The durable ordering removes application trust before relying on provider cleanup:

`requested → application trust removal pending → credential revocation pending → Keryx binding disable pending → provider cleanup pending → revoked`

Provider outage can delay mesh cleanup but cannot preserve application authorization.

## N1A provider evidence

N1A adds only a stock-Headscale v0.29.3 read adapter. It can inspect version/health, list nodes, and look up one node by the provider's numeric node ID while verifying the machine-key fingerprint in the full `ProviderIdentity`. Hostname, given name, user metadata, addresses, tags, timestamps, online state, and pre-auth correlation remain observations. This adapter cannot activate membership or call any provider write route.

## N3A mutation boundary

N3A is a capability-separated provider-mutation implementation, not an
implicit extension of the N1A adapter. Its only effects are principal ensure;
bounded join-credential creation and exact invalidation; complete tag-set
replacement, expiry, and deletion for an exact provider node; and policy
read/apply only after database-mode verification. It does not infer any one
effect from another capability, an administrator role, a server version, or
the existence of a provider route.

State migration v3 leaves every imported provider permanently
`read_only = true, mutation_allowed = false`. Mutation authority comes only
from a separate exact network/provider configuration with monotonic
authorization and configuration generations, a non-secret fingerprint,
half-open validity, exact clean runtime identity, and an explicit capability.
The real authorization has private fields and is consumed by value; the fake
provider uses a different test-constructible type.

There is no provider compare-and-swap (CAS) assumption. Each operation therefore needs explicit
certainty handling: rejected, unsupported, and ambiguous outcomes remain
non-successes; requested state is certain only after appropriate authoritative
read-back. The disposable proof used controlled provider state and no
production mutation. It verified custom-root TLS, principal ensure, bounded
credential creation/invalidation, and database policy replacement. Node
operations remain deterministic loopback evidence because no proof node was
allowed to join.

No N3A provider result changes the authority split above: a principal or
provider node is not a trusted Nodescale device, and provider mutation cannot
create a Keryx binding or activate Hermes Fleet enrollment, grants, scheduling,
or execution. Those remain independently gated on their stated provenance,
local-control, and acceptance-test contracts.

## N4A invitation and join-session boundary

N4A composes the N3A credential primitives behind `InvitationService`. The
service issues opaque single-use invitations, reserves durable join sessions in
SQLite, and dispatches provider credential creation only after the reservation
commits. Invitation selectors carry no claims; typed roles are bounded
eligibility and approved-tag intent only. Administrative eligibility requires
explicit elevated intent.

Creation certainty is asymmetric: a possibly-applied request whose plaintext
credential was not recovered becomes terminal and cannot be blindly retried.
Invalidation carries no new secret, so ambiguous revocation or expiry remains
nonterminal and may be reconciled against the exact provider reference. Terminal
cleanup requires confirmed or already-satisfied provider evidence.

The production-path disposable proof exercised invitation creation, redemption,
replay rejection, and revocation through the real Headscale v0.29.3 adapter. It
used file-backed state and verified that invitation and provider plaintext were
absent from the database files. Provider node inventory and all Nodescale trust
counters remained zero.

## Explicitly deferred

No server, agent, CLI, Keryx adapter, Fleet adapter, privileged helper, web
console, deployment tooling, distributed consensus, device join, authenticated
agent-to-provider-node correlation, or live activation is added by N4A.
Transporting invitations to clients and exposing operator-facing invitation APIs
also remain separate work.
