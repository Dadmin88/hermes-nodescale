# ADR 0010: N0C Dependency and Gating Decision

**Status:** Accepted
**Date:** 2026-08-07

## Context

Useful Rust-first domain and provider work can proceed without fabricating Keryx identity proof or Fleet trust projection.

## Decision

After N0B documentation passes one focused independent architecture review, N0C may proceed only with explicit owner authorization.

Allowed in N0C:

- Rust workspace;
- domain models;
- SQLite state and migrations;
- fake provider;
- provider abstraction;
- audit primitives;
- ADRs and tests.

Still gated:

- Keryx binding implementation until the authenticated non-execution provenance surface exists;
- automatic Fleet projection until the stable managed enrollment/grant local-control contract exists;
- live trusted device activation until both paths pass acceptance tests.

N0C may model blocked states and interfaces but may not implement fake trust semantics or mark a device active without real evidence.

## Consequences

The project can build durable independent foundations immediately after owner authorization. Security-critical integrations remain explicit phase gates.

## Rejected Alternatives

- Wait for every dependency before creating domain foundations.
- Stub trust as successful during early development.
- Begin N0C automatically when N0B closes.
