# ADR 0009: Python Hermes Fleet Prototype Compatibility

**Status:** Accepted
**Date:** 2026-08-07

## Context

The current Python Hermes Fleet is proven enough to serve as a behavioral reference, while the planned permanent implementation generation is Rust. Nodescale needs an integration target without inheriting Python internals.

## Decision

Treat the current Python Hermes Fleet as:

- working prototype;
- behavioral reference;
- acceptance-test source;
- future integration-test target.

Later, add a thin adapter that implements the permanent language-neutral local control contract. The future Rust implementation of Hermes Fleet implements the same externally meaningful contract. Nodescale does not depend on Python classes, config files, private schemas, or databases.

The product name remains Hermes Fleet for both implementation generations.

## Consequences

Nodescale can test projection before the Fleet Rust rewrite is complete. Contract conformance—not code reuse—defines compatibility.

## Rejected Alternatives

- Couple Nodescale to Python imports or `nodes.yaml` internals.
- Block all Nodescale work on the Fleet Rust rewrite.
- Introduce a separately named Rust Fleet product identity.
