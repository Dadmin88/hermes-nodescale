# ADR 0008: Hermes Fleet Managed Enrollment and Grant Contract

**Status:** Accepted contract requirement; implementation pending
**Date:** 2026-08-07

## Context

Fleet needs provenance-aware managed nodes, enrollments, exact generated grants, and projection status while preserving independent local policy.

## Decision

Require managed nodes with `source=nodescale`, network ID, device ID, display name, Keryx peer ID, roles, membership state, and generation. Require enrollment states `pending`, `approved`, `disabled`, and `removed`.

The language-neutral local API conceptually supports:

- upsert/remove managed node;
- upsert/disable/remove managed enrollment;
- set/remove generated exact grants;
- inspect projection;
- reconcile generation.

Every generated record preserves source, network, device, and generation provenance. Local operator state remains separate. Initial generated grants are only health, inventory, and message. Exact operation authorization remains Fleet-owned; local deny wins.

## Consequences

The contract can be implemented by Python Fleet first and future Rust Fleet later. Automatic projection remains blocked until versioning, authentication, persistence, idempotency, conflict handling, and read-back are implemented.

## Rejected Alternatives

- Store generated state directly in `nodes.yaml` as the permanent API.
- Give roles implicit grants.
- Let Nodescale authorize `fleet.hermes.run` by membership alone.
