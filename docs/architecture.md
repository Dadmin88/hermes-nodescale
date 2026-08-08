# Architecture

Nodescale is a control plane for managed device membership and identity. It intentionally separates mesh admission, Nodescale-owned identity, authenticated transport identity, and Hermes Fleet authorization.

## System boundaries

Nodescale owns:

- managed network and device membership;
- Nodescale device identity and credential generations;
- roles and lifecycle state;
- provider observations and reconciliation state;
- invitation and join-session state;
- desired Hermes Fleet enrollment and grant intent.

Adjacent systems retain their own authority:

- **Mesh providers** own mesh admission, reachability, provider-local node identity, tags, and network policy.
- **Keryx** owns authenticated application-transport peer identity and runtime provenance.
- **Hermes Fleet** owns final application authorization, scheduling, local overrides, and execution.

A mesh node is therefore never equivalent to a trusted Hermes Fleet node.

## Workspace structure

The Rust workspace separates policy and state boundaries so that no adapter can silently acquire broader authority:

- `nodescale-domain` contains pure typed domain models and state machines.
- `nodescale-state` owns the Nodescale SQLite database, migrations, persisted observations, mutation authorization state, lifecycle state, and audit records.
- `nodescale-provider` defines provider-neutral read and mutation contracts.
- `nodescale-provider-fake` provides deterministic test behavior.
- `nodescale-provider-headscale` implements Headscale discovery and explicitly authorized provider mutations.
- `nodescale-invitation` owns invitation and join-session lifecycle behavior.
- `nodescale-redemption-ingress` exposes the network transport for invitation redemption and delegates lifecycle decisions to `InvitationService`.

State code does not read provider, Keryx, or Hermes Fleet databases. Provider payloads are normalized before they can enter Nodescale state.

## Identity separation

Nodescale preserves three non-substitutable identities:

1. provider device identity;
2. Nodescale managed-device identity;
3. authenticated Keryx peer identity.

Hostnames, display names, mesh addresses, tags, and caller-supplied peer identifiers are observations only. A durable binding may relate authoritative identities, but one identity never substitutes for another.

See [Identity Model](identity-model.md).

## Provider discovery and reconciliation

An existing Headscale network can be imported using explicit configuration. Discovery reads provider state, validates the configured provider instance and compatibility, normalizes node observations, and stores them separately from trusted Nodescale devices.

Reconciliation is deterministic and fail-closed:

1. load the persisted provider configuration;
2. inspect provider health, version, and identity;
3. read and normalize the complete provider snapshot;
4. reject duplicate or conflicting canonical identities;
5. compare the snapshot with persisted observations;
6. classify changes and conflicts;
7. atomically persist observation, freshness, and audit updates;
8. return a sanitized diagnostic report.

Provider outages preserve the last successful inventory. They are not interpreted as mass deletion.

See [Discovery and Reconciliation](discovery-reconciliation.md).

## Provider mutation boundary

Provider reads and writes use separate interfaces. Read-only imports cannot acquire mutation authority from server capabilities, roles, tags, or compatibility alone.

Mutation requires all of the following:

- an exact configured network and provider instance;
- compatible runtime evidence;
- explicit mutation-enabled state;
- an operation-specific capability;
- a state-issued authorization consumed by the mutation call.

Supported mutation capabilities are deliberately narrow: principal creation, bounded join-credential creation and invalidation, exact-node tag replacement, expiry, deletion, and policy management in explicitly verified database mode.

The provider contract does not assume compare-and-swap support. A transport acknowledgement alone is not proof of success. Rejected, unsupported, and ambiguous outcomes remain distinct, and authoritative read-back is required where the provider exposes one.

See [Provider Contract](provider-contract.md).

## Invitation and redemption flow

An invitation contains an opaque selector and a random secret. Nodescale stores only a verifier and safe metadata. Successful presentation atomically reserves the invitation and creates a durable join session before a provider credential request is dispatched.

The provider credential is bounded to the configured principal, expiry, use count, and approved tags. Its plaintext is delivery-only and is not written to SQLite, audit metadata, or normal diagnostics.

The redemption ingress exposes one verified-TLS endpoint:

```text
POST /v1/redemptions
```

The request body contains only the invitation token. Source and global admission controls execute before expensive verification or provider work. A bounded worker owns the non-thread-safe state and invitation service, while SQLite remains authoritative for replay protection across independent processes.

A successful response returns only bootstrap material required by the provider client. It does not return Nodescale trust claims.

See [Invitations and Redemption](invitations.md).

## Generations and reconciliation

Nodescale persists independent monotonic generations for membership, device credentials, Keryx bindings, and Fleet projection. Stale writers are rejected.

Exact replay may be idempotent only when the generation and content identity both match. Reusing a generation with different content is a conflict.

Desired Hermes Fleet state is persisted before submission. Applied state must be read back through the Fleet integration boundary before projection is considered complete.

## Revocation

Revocation removes application trust before relying on provider cleanup. The durable ordering is conceptually:

```text
revocation requested
  -> Fleet scheduling/grants disabled
  -> managed enrollment disabled
  -> Nodescale credential revoked
  -> Keryx binding disabled or tombstoned
  -> provider cleanup pending
  -> revoked
```

Provider outages may delay mesh cleanup, but they must not preserve application authorization. Historical identity and audit evidence remain available for reconciliation and incident analysis.

## N5 authoritative device identity and Nodescale trust

Provider admission, invitation possession, and generic partial pre-auth association are insufficient for identity or trust. N5's state-owned confirmation operation requires one exact active and unexpired N4 provider reference, one `ProviderAuthenticatedRegistration` observation, an exact provider-node re-read, and matching machine-key fingerprint. It then generates an opaque immutable `DeviceId` and creates a separate active provider binding; the device starts untrusted.

A one-time local-owner bootstrap returns an opaque `nstrust_` 256-bit capability and persists only its fixed-profile Argon2id verifier. That active root gates sealed trust-authority configuration, one-shot revision-fenced action issuance, authority/root revocation, and append-only decisions. Root revocation disables linked authorities and invalidates unconsumed actions. Effective trust requires both logical trusted state and an active exact binding. Provider-backed reconciliation marks authoritative absence, expiry, credential drift, or machine-key drift stale; transient errors return no trusted result. Cleanup proceeds through revisioned `stale`, `cleanup_pending`, and `removed` states.

N5 still creates no authenticated Keryx identity, Fleet enrollment/grant, Hermes activation, scheduler, workload placement, or runtime profile. See [Device Identity and Trust](device-trust.md).

## Trusted activation beyond N5

Provider admission alone cannot establish Keryx or Hermes Fleet authority. Those later transitions require authenticated Keryx provenance and successful Hermes Fleet projection according to their own generations and policies.

The current repository implements N5 Nodescale identity/trust but does not complete Keryx binding or Hermes Fleet projection.

## Deliberate non-goals

The current architecture does not introduce:

- distributed consensus;
- a shared database between Nodescale and adjacent systems;
- direct mutation of Hermes Fleet configuration files;
- implicit authorization derived from provider tags or Nodescale roles;
- trust based on hostname, mesh address, or caller-supplied peer identifiers;
- a second invitation lifecycle inside the HTTP ingress layer.
