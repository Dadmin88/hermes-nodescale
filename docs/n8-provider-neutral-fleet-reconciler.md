# N8 provider-neutral Fleet projection reconciler

## Status

Planned. Automatic provider-to-Fleet projection remains disabled until this milestone is implemented and accepted.

## Goal

Add a durable, state-owned reconciler that derives Fleet desired state from authoritative Nodescale source state and exact trusted N6 binding provenance, then applies semantic transitions through the existing explicit N7 library boundary.

Headscale and Tailscale observations use the same reconciler. Provider adapters supply source observations only; they do not grant admission or Fleet authority.

## Required durable model

Persist one reconciler record per managed identity containing at least:

- source/network/device identity;
- authoritative source fingerprint and source revision;
- N5 trust/admission generation;
- exact N6 binding ID, authenticated peer ID, and binding generation;
- canonical semantic Fleet desired state and its digest;
- desired projection generation;
- last attempted operation ID and delivery state;
- last successfully applied semantic state/digest/generation;
- explicit pending disable/remove successor when eligibility is withdrawn.

The record is state authority. Poll cadence, process restart, wall-clock changes, or observation age alone must not change its semantic digest or projection generation.

## Reconciliation rules

1. Persist provider observations as source state before deriving authority.
2. Require current admitted trust and exact active N6 provenance for an upsert.
3. Compute a provider-neutral semantic desired document.
4. If the semantic digest equals the durable desired/applied digest, return a strict no-op.
5. Advance projection generation only when the semantic desired state changes.
6. Provider disappearance, binding withdrawal, revocation, disablement, identity replacement, or loss of required trust creates an explicit zero-grant disable/remove successor; never silently omit previously applied authority.
7. Persist desired state and operation ID before Fleet delivery.
8. Deliver through the existing N7 service and typed Fleet client.
9. Mark applied only after authoritative Fleet inspection proves exact body/hash parity.
10. Preserve retryable desired/attempted state after transport failure, timeout, crash, or unavailable inspection.
11. Reuse the same operation ID and generation for retries of the same desired digest.
12. A new binding or re-admission must use new trusted provenance and a real semantic successor generation.

## Non-goals

- no direct Fleet database access;
- no provider-specific Fleet semantics;
- no frontend-created authority;
- no Tailscale admission inferred from discovery, names, addresses, tags, or tailnet membership;
- no mutation of the current explicit N7 trust boundary without a separately reviewed concrete incompatibility;
- no live Headscale/Tailscale acceptance during source-only implementation.

## RED acceptance matrix

Add deterministic file-backed tests for:

- unchanged consecutive provider polls: one projection, then strict no-op;
- process crash after desired persistence but before delivery;
- process crash after Fleet accepted delivery but before local completion;
- restart with unchanged source: no new generation;
- provider outage: preserve source/applied state and do not deproject solely because authority is unavailable;
- provider recovery with unchanged source: no-op;
- authoritative provider removal: explicit remove successor;
- membership disablement/revocation: explicit zero-grant disable successor;
- N5 trust loss: explicit deprojection;
- N6 binding withdrawal: explicit deprojection;
- rebinding/identity replacement: old authority removed before new upsert;
- stale projection generation: fail closed;
- Fleet delivery timeout/failure: durable retryable state, never falsely applied;
- retry: same operation ID/body/generation;
- authoritative inspection mismatch: conflict, not applied;
- successful retry and inspection: durable applied state;
- restart after applied: strict no-op;
- equivalent Headscale and Tailscale source fixtures produce identical provider-neutral desired semantics when both possess the same admitted trust/N6 evidence;
- Tailscale discovery without supported admission correlation produces no upsert.

## Implementation slices

1. **N8-A durable semantic record:** migration, DTOs, fingerprints, strict no-op transition tests.
2. **N8-B eligibility and deprojection:** N5/N6/source withdrawal successors and ordering tests.
3. **N8-C N7 delivery recovery:** idempotent operation reservation, crash/retry/inspection tests.
4. **N8-D runtime integration:** bounded work queue, backoff, shutdown deadline, health/reporting.
5. **N8-E acceptance:** exact-tree disposable Fleet proof, then separately authorized real-provider proof.

Each slice must be independently reviewable and green before the next begins.

## Release gate

Do not describe automatic Tailscale→Fleet or Headscale→Fleet admission/projection as complete until all RED matrix cases pass, exact-head CI is green, and a separately authorized real acceptance proves source observation → admitted trust → N6 binding → durable semantic transition → N7/Fleet apply → Desktop parity without mocks or direct database writes.
