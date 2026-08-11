# N6 authenticated Keryx binding: architecture and operations

## Scope and evidence discipline

N6 is the durable binding of a confirmed Nodescale device identity to a Keryx
**authenticated transport peer**. This document describes the contracts that
are implemented in the N6 domain, state, production service, and Keryx adapter
sources. It is not a deployment guide, a claim that a Keryx relay is running,
or evidence of end-to-end or CI execution.

Treat an immutable Git object as the release/evidence boundary:

- Record the exact committed candidate SHA (or immutable tree ID where the
  proof runner requires one) with every migration, test result, and incident
  record. Do not call a moving worktree or an uncommitted `HEAD` a frozen N6
  implementation.
- The current proof envelope uses `NODESCALE_N6_TREE` and verifies that its own
  runner bytes come from that exact tree before testing it. It is therefore an
  appropriate evidence mechanism only after the candidate is committed.
- This document intentionally contains no hard-coded release SHA. The SHA is an
  operational fact that changes at each approved release; the release record,
  not prose, is authoritative for it.

The relevant implementation boundaries are:

| Boundary | Current implementation | Ownership rule |
| --- | --- | --- |
| Direct Keryx control | `nodescale-keryx-adapter` | Parses typed direct frames and obtains the peer only from `AuthenticatedDirectContext`. |
| Application service | `nodescale-binding::N6BindingService` | Owns serialization of binding work, provider reconciliation, and calls into durable state. |
| Durable authority | `nodescale-state` migration `0006_keryx_identity_binding.sql` and `src/n6.rs` | Owns binding/challenge/authorization state, fences, append-only decisions, and audit evidence. |
| Provider truth | `N5ConfiguredHeadscaleProvider` / N5 reconciliation | Must be re-read for issue, confirm, and peer authorization; durable observations alone are insufficient. |
| Owner control | N5 owner root, trust authority, and N6 capability/authorization records | Can authorize rotation or revocation; it is not a Keryx peer privilege. |

The installed direct-control path is the state-backed `N6BindingService`
implementation of `NodescaleIdentityControlPlane`. There is no parallel mock
or generic production path; lifecycle acceptance comes from the concrete
service, SQLite integration tests, and disposable transport proof.

## Trust model and process ownership

A Keryx peer ID in a frame body is never authoritative. The adapter derives
`AuthenticatedProvenance.authenticated_peer_id` from Keryx's authenticated
source context; source, destination, and relay-frame IDs are parsed as bounded
safe identifiers. The protobuf payload supplies network, device, join-session,
operation, generation, agent-version, and (for confirmation) nonce fields, but
not the authoritative sender identity.

The production service creates a named current-thread actor
(`nodescale-n6-binding`). That actor exclusively owns the intentionally
non-`Sync` `StateStore` SQLite connection and the configured provider object.
External callers enqueue typed challenge, confirmation, peer-authorization,
capability, one-shot authorization, rotation, and revocation commands and wait
for a one-shot reply. Do not share the state connection with relay handlers or
perform an equivalent state/provider sequence outside this actor.

Before **issue**, **confirm**, and **authorize**, the actor calls
`reconcile_n5_provider_binding` using the state-configured provider. The
reconciliation checks that the configured import has not changed, queries the
provider, and requires the exact stored N5 provider identity, authenticated
registration association, stable machine-key fingerprint, and unexpired
provider node. It returns a provider-fresh trusted result only when the device
is trusted and belongs to the requested network. A provider error, missing
node, or mismatch stales the N5 provider binding and prevents the N6 operation.

This is deliberately stronger than checking a historical device record. It is
also deliberately narrow: the current production service exposes no Keryx
control handler for rotation or revocation.

## Binding lifecycle

A binding is associated with exactly one `(network_id, device_id,
provider_binding_id, generation)`. The authoritative N6 record stores that exact N5 provider binding; subordinate N6 rows derive provenance through `(binding_id, network_id, device_id, generation)`. For byte-compatible replay fingerprints and historical views, state resolves the N4 `join_session_id` through the typed N5 subtype rather than persisting it in N6. A binding has these legal transitions:

```text
pending -> active | revoked
active  -> stale | rotated | revoked
stale   -> rotated | revoked
rotated and revoked are terminal
```

SQLite constraints and triggers make the binding records, decisions, linked
audit events, challenges, authorizations, and reservations append-only. They
also require exact confirmed N4 join-session and N5 identity provenance for
N6 decisions, one active binding per device, and one active binding per peer in
a network.

### 1. Challenge issuance

The Keryx `nodescale.identity.challenge.v1` handler validates bounded typed
input and uses the authenticated source peer. Its state-backed service:

1. reconciles provider truth and rejects unless the device is currently trusted
   in the requested network;
2. derives the next challengeable generation (initially generation 1; after a
   terminal/non-pending generation, rotation authorization is required);
3. creates a request tied to the exact N4/N5 provenance, expected Keryx peer,
   generation, expiry, and agent version;
4. durably reserves the operation **before** generating a nonce;
5. generates a nonce, stores only its verifier, then records the pending
   challenge and its audit/decision evidence in the same durable completion;
6. returns the plaintext nonce only in an `Issued` direct-control response.

A reservation is keyed by `(expected_authenticated_peer_id, operation_id)` and
a SHA-256 request fingerprint. The fingerprint covers the peer, network,
device, join session, generation, expiry, and agent version. A matching
unissued reservation is resumable after process interruption because no
plaintext nonce was persisted. A matching issued reservation is terminal for
that operation and returns `Duplicate`; it never produces another nonce.
Different bytes under the same peer/operation ID are a conflict and are
rejected.

A new challenge for a still-pending binding invalidates its prior pending
challenge and abandons an unissued prior reservation. Consequently, recovery
of a lost **issued** challenge response is operationally a *new* challenge
operation ID, not a retry that re-emits a secret. The generic orchestration
abstraction has an explicit `recovery_of` field; the current Keryx v1 challenge
message does not expose that field. The production wire path therefore records
operation-level idempotency but does not expose an operation-to-operation
recovery link.

### 2. Authenticated confirmation

The Keryx `nodescale.identity.bind.v1` handler takes the nonce from the typed
payload and the peer from authenticated transport provenance. Confirmation
again reconciles N5 provider truth before entering the state mutation. In one
transaction, state requires all of the following:

- a pending challenge for the exact network, device, join session, generation,
  authenticated peer, and agent version;
- `now < expires_at` (equality is expired);
- a successful verification of the presented nonce against the stored verifier;
- an unchanged pending binding snapshot and revision.

It then consumes the challenge, records the challenge-confirm decision,
activates the binding with the authenticated peer, records the binding-confirm
decision, and records the confirmation operation. A subsequent confirmation
with the same authenticated peer, operation ID, and complete request
fingerprint returns the existing binding as `AlreadyConfirmed`; a same-ID
request with a different nonce or other fingerprinted field returns a conflict.
Neither path turns a different peer or a consumed/invalidated/expired challenge
into an active binding.

### 3. Authorization check

`N6BindingService::authorize_peer(network_id, device_id, authenticated_peer)`
re-runs provider reconciliation, requires a currently trusted device in the
network, finds the active binding by `(network_id, peer)`, and verifies that it
belongs to `device_id`. Callers that gate a protected operation on an N6
binding must use this state-backed check (or an equivalently fresh service
boundary), not `n6_is_peer_active` or a cached direct-frame result alone.

## Owner-gated rotation and revocation

Rotation and revocation are durable owner actions, separate from Keryx
challenge/confirm control traffic.

1. An N5 owner-root token is verified against a live, enabled, unrevoked root.
   The root principal must match the sealed, enabled, unrevoked N5 trust
   authority.
2. The owner grants that authority a distinct immutable N6 `rotate` and/or
   `revoke` capability. Capability grants have audit evidence and are unique
   per authority/action.
3. The owner issues a one-use N6 authorization for one binding, exact
   generation and revision, action kind, actor, and expiry. The durable insert
   guard requires a live owner root, live authority, matching granted
   capability, and a binding currently eligible for that action.
4. The rotation or revocation intent repeats those authorization fences and is
   checked again by state and SQLite triggers while consuming the authorization.

Rotation requires an active or stale predecessor and creates a **pending**
successor at exactly `generation + 1`; it then marks the predecessor rotated.
The successor has no peer until a separate provider-fresh challenge/confirm
cycle completes. Revocation accepts pending, active, or stale bindings,
invalidates a pending challenge, consumes the revoke authorization, and makes
the binding terminal. Both actions require the exact expected revision; stale
or reused authorizations fail closed.

The authorizations are valid only from their issuance instant until, but not
including, `expires_at`; the authority's own validity window is checked during
issuance and consumption. The current implementation has schema support for
expired/invalidated authorization and challenge records, but no N6 background
expiry sweeper was found in `src/n6.rs`. Do not claim that expiry state is
materialized automatically. Mutation-time validation and trigger fences are the
implemented enforcement.

## Secret, timing, and response rules

### Secret handling

- `BindingNonce` is an opaque canonical `nsbind_` value. Its `Display` and
  `Debug` forms are redacted; `N6BindingChallengeDelivery` and adapter
  `ChallengeOutcome` also redact delivery values in debug output.
- The nonce is generated after durable reservation. State stores only a fixed
  Argon2id verifier (`v=19`, `m=19456`, `t=2`, `p=1`), not the plaintext nonce.
  Schema guards reject noncanonical verifier spellings.
- The plaintext appears only while building an issued Keryx response. Duplicate,
  rejected, invalid-request, and control-plane-error challenge results carry
  empty secret and challenge-ID fields.
- N6 decisions/audit metadata are constrained to public metadata; migration
  triggers reject nonce-looking strings and verifier prefixes there. Do not log
  direct messages, deliveries, nonce accessors, verifiers, or raw provider/API
  credentials.
- Adapter failures are mapped to fixed reason/code values; raw SQLite, provider,
  transport, and input error text is not returned to Keryx.

### Timing and validation

- Production challenge TTL must be strictly positive and no more than **600
  seconds**. The adapter validates an issued delivery again before returning it.
- Challenge and authorization expiry is exclusive: a value at `expires_at` is
  invalid. Confirmation requires consumption before challenge expiry; rotate and
  revoke intents and authorization consumption require use before authorization
  expiry.
- Agent versions, operation IDs, peer IDs, reason codes, and transport IDs are
  bounded identifier forms. Treat parser rejection as a normal rejected
  operation, never as a reason to relax the identifier grammar.
- The producer clock is the actor's `N6Clock` (system UTC by default). Runbook
  owners must keep the service host's UTC clock synchronized; the code does not
  implement a distributed-clock correction protocol.

## Operations runbook

### Composition and startup

1. Apply the N6 migration through the repository's normal state migration
   path, then construct the provider using the state-owned import configuration
   (`configured_n5_headscale_provider` or its configured custom-CA form). Do
   not construct an arbitrary provider adapter and treat it as N6-authoritative.
2. Construct `N6BindingService` with that `StateStore`, that configured provider,
   and a TTL in `(0, 600]` seconds. Construction rejects an out-of-range TTL.
3. Install `TryNodescaleKeryxAdapter` only around the state-backed control
   plane. It installs only the dedicated challenge and bind handlers after
   `validate_configuration` succeeds. Ensure the Keryx runtime supplies
   `AuthenticatedDirectContext`; do not substitute a caller-provided source.
4. Persist the immutable release SHA, migration result, configured provider
   identity, and chosen TTL in the deployment record. Never record nonce,
   verifier, API key, owner-root token, or direct response body there.

### Normal request handling

- **Issue:** send a fresh operation ID. On `Issued`, deliver the nonce only to
  the authenticated peer via the direct result and retain it only long enough
  for the immediate confirmation operation.
- **Retry before issuance completes:** retry the same operation ID and same
  logical request; the durable reservation may resume safely.
- **Lost issued response:** do not retry the same ID expecting another secret.
  Start a fresh challenge operation. The old pending challenge is invalidated
  as part of replacement issuance.
- **Confirm:** use a fresh confirmation operation ID with the exact nonce,
  provenance tuple, generation, and agent version. A transport retry of the
  exact same confirmation is safe and returns `AlreadyConfirmed`.
- **Authorize:** call the provider-fresh authorization method at each protected
  use boundary. Reject on any provider reconciliation or binding mismatch.
- **Rotate/revoke:** use only a currently live owner-root token and a matching,
  unconsumed state-issued authorization. For rotation, complete the successor's
  new challenge/confirm cycle before considering the replacement peer active.
  For revocation, local durable revocation remains available even when provider
  reconciliation is unavailable; it must not be delayed to wait for the
  provider.

### Failure and incident handling

- A provider rejection/error or network mismatch is fail-closed. It can stale
  N5 provider state; investigate provider identity, registration association,
  expiry, and configured-import drift before attempting a new N6 operation.
- `Duplicate` is not success for challenge issuance because it intentionally
  withholds the plaintext nonce. `AlreadyConfirmed` is success only for an
  exact confirmation replay.
- Treat an operation-ID conflict, nonce mismatch, expired challenge,
  nonmatching agent version, stale revision/generation, consumed authorization,
  and unauthorized owner root as denied operations. Do not mutate rows by hand
  to bypass the decision/audit/trigger fences.
- Preserve binding ID, challenge ID, authorization ID, decision ID, audit-event
  ID, operation ID, actor, provider result category, and frozen SHA for
  investigation. Keep all secret-bearing values out of tickets and logs.

## Verification status and required release evidence

The repository contains unit/integration-style Rust coverage for domain
redaction/lifecycle rules, state lifecycle and migration guards, the production
service, and adapter request/response mapping. Those tests establish source
contracts; they are not evidence that a real Keryx relay, Headscale provider,
SQLite migration path, or cleanup environment has succeeded together.

The disposable proof runner in `proofs/n6/` archives an exact candidate tree,
runs the one ignored integration selector in a private runtime root, scans
SQLite/WAL/SHM and other runtime artifacts for supplied secret sentinels, and
verifies cleanup, including deliberate interruption. The selector exercises
the authenticated Keryx edge stream, production adapter and binding service,
provider-fresh challenge and confirmation paths, durable SQLite restart and
replay behavior, and closed owned listeners after teardown. Release evidence
remains external and must identify the exact accepted candidate tree.

Before an activation decision, retain at minimum:

1. the immutable candidate SHA and clean-tree record;
2. migration and targeted test output from that SHA;
3. a successful real-relay/provider E2E result covering spoofed source,
   challenge expiry, invalidated challenge, exact confirmation replay,
   conflicting replay, provider loss/mismatch, owner rotation, and revocation;
4. a secret-residue and cleanup/interruption proof once the ignored selector
   exists; and
5. CI evidence tied to the same SHA.

N6 is accepted only when those records all identify the same immutable
candidate tree; source coverage or an earlier proof tree is not sufficient.

## Source map

- `crates/nodescale-keryx-adapter/src/lib.rs`
- `crates/nodescale-binding/src/production.rs`
- `crates/nodescale-binding/src/lib.rs`
- `crates/nodescale-state/src/n6.rs`
- `crates/nodescale-state/src/n5.rs`
- `crates/nodescale-state/migrations/0006_keryx_identity_binding.sql`
- `crates/nodescale-domain/tests/n6_keryx_binding.rs`
- `crates/nodescale-state/tests/n6_lifecycle.rs`
- `crates/nodescale-keryx-adapter/src/tests.rs`
- `proofs/n6/README.md`
