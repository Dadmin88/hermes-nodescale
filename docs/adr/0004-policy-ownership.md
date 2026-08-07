# ADR 0004: Policy Ownership

**Status:** Accepted
**Date:** 2026-08-07

## Context

Network reachability, managed membership, and application authorization are different policy layers. Conflating Headscale tags or Nodescale roles with Fleet grants would allow mesh state to authorize execution.

## Decision

- Headscale owns mesh admission, reachability, tags, and network ACL/policy.
- Nodescale owns membership, device identity, roles, lifecycle, generations, and generated Fleet intent.
- Hermes Fleet owns final exact application authorization, scheduling, local overrides, and execution.

Initial Nodescale-generated grants are limited to `fleet.health`, `fleet.inventory`, and `fleet.message`. Nodescale membership never automatically grants `fleet.hermes.run`. Local Fleet deny always wins. Roles are descriptive metadata, not grants.

## Consequences

Provider tags never become application authorization. Elevated execution requires explicit Fleet policy. Generated and local operator state remain distinguishable.

## Rejected Alternatives

- Map Headscale tags directly to Fleet operations.
- Let a Nodescale role imply Hermes execution.
- Allow generated grants to override local Fleet deny.
