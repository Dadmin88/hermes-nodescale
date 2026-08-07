# ADR 0005: Membership Generation and Reconciliation

**Status:** Accepted
**Date:** 2026-08-07

## Context

Nodescale and Fleet can restart, lose connectivity, or receive duplicate and stale projection attempts. Submission cannot be treated as application.

## Decision

Nodescale is authoritative for monotonic per-network membership generations. Durable state also distinguishes device credential generation, Keryx binding generation, and Fleet desired/applied projection generation.

Projection is idempotent desired-state reconciliation:

- older generation is rejected;
- exact replay with identical content is `already_applied`;
- same generation with different content is `conflict`;
- Nodescale persists desired state before submission;
- Fleet transactionally persists applied generation and content identity before acknowledgement;
- partial effects are detectable;
- Nodescale reconciles until desired equals applied;
- restarts preserve both sides' ability to continue.

## Consequences

No distributed consensus is introduced. Recovery is driven by one membership authority and durable local Fleet state. Generation alone is insufficient for exact replay; content identity or equivalent conflict detection is required.

## Rejected Alternatives

- Last-write-wins without generation checks.
- Infer projection success from request acceptance.
- Keep lifecycle authority only in process memory.
- Introduce a distributed consensus subsystem for V1.
