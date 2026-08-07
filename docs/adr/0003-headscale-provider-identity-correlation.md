# ADR 0003: Headscale Provider Identity Correlation

**Status:** Accepted
**Date:** 2026-08-07

## Context

Headscale pre-auth-key association is valuable join evidence but proves possession of a join capability, not the complete managed-device identity. Hostnames and mesh addresses are mutable and ambiguous.

## Decision

For the proposed first provider pin, use stock Headscale `v0.29.3`, subject to release reverification before implementation or deployment. Correlate a join only from the combined evidence of:

1. authenticated Nodescale join session;
2. exact Headscale node identity;
3. strongest stable provider key material exposed by the supported API;
4. agent-bound cryptographic/device credential evidence;
5. pre-auth-key association when exposed;
6. supporting timing, principal/tag, and local-client observations.

Ambiguity or conflict fails closed. Hostname-only and IP-only matching are prohibited. Administrative provider credentials remain server-side. Unknown compatibility disables unsafe mutations.

## Consequences

N2/N6 must prove the exact correlation against an isolated pinned Headscale instance. Provider observations are normalized and secret-bearing fields are redacted. The pin is explicit but not permanent.

## Rejected Alternatives

- Hostname or IP correlation.
- Pre-auth key alone as permanent identity.
- Direct Headscale database access.
- Fork Headscale before a documented public-API blocker exists.
