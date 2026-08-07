# ADR 0007: Nodescale-to-Hermes-Fleet Local Control Boundary

**Status:** Accepted
**Date:** 2026-08-07

## Context

Nodescale must project membership to Fleet on each device without editing remote files, accessing Fleet databases, or coupling to the current Python implementation.

## Decision

Adopt this V1 distribution model:

```text
Nodescale server
  -> authenticated membership sync
Nodescale agent on each device
  -> versioned authenticated local control API / IPC
Hermes Fleet on that device
```

Prefer a Unix-domain socket on Linux when practical. Keep the schema language-neutral. Nodescale never imports Python Fleet modules, edits Fleet configuration files across machines, or accesses Fleet databases.

## Consequences

The current Python implementation and future Rust implementation of Hermes Fleet can implement the same boundary. Transport authentication, version negotiation, bounded requests, and truthful read-back are required before automatic projection.

## Rejected Alternatives

- Pairwise remote YAML editing.
- Shared/private Fleet database access.
- Python module imports as the contract.
- A separately named Rust Fleet product.
