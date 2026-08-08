# ADR 0010: Integration Trust Gates

**Status:** Accepted
**Date:** 2026-08-07

## Context

Nodescale can implement durable domain, state, provider, invitation, and reconciliation foundations without inventing trust evidence that belongs to Keryx or Hermes Fleet.

Allowing incomplete integrations to report successful trust would weaken the authority boundaries established elsewhere in the architecture.

## Decision

Core Nodescale foundations may be developed and operated independently where they do not require missing external trust evidence.

The following integrations remain explicitly gated:

- **Keryx binding** requires authenticated non-execution sender provenance supplied by the trusted runtime rather than by the request payload.
- **Hermes Fleet projection** requires a stable, authenticated, language-neutral local control contract with durable generation, idempotency, conflict, provenance, and read-back semantics.
- **Trusted device activation** requires both authoritative Keryx binding evidence and successful Fleet projection according to the current managed-state contract.

Nodescale may model pending or blocked states before these integrations are complete, but it must not synthesize successful trust semantics or mark a device trusted without the required evidence.

## Consequences

Independent parts of Nodescale can evolve without coupling progress to every adjacent system. Security-critical integrations remain fail-closed until their real provenance and control contracts exist and pass acceptance tests.

## Rejected Alternatives

- Wait for every adjacent integration before implementing independent Nodescale foundations.
- Stub missing trust dependencies as successful during development.
- Promote provider admission or caller-supplied identity fields into trusted activation.
