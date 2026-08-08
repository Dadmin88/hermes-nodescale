# ADR 0003: Headscale Provider Identity Correlation

**Status:** Accepted
**Date:** 2026-08-07

## Context

Headscale pre-auth credential association is valuable join evidence, but it proves possession of a provider admission capability rather than complete managed-device identity. Hostnames and mesh addresses are mutable and ambiguous.

## Decision

Use stock Headscale `v0.29.3` as the current provider compatibility pin.

Correlate a trusted join only from combined evidence that includes:

1. an authenticated Nodescale join session;
2. the exact scoped Headscale provider identity;
3. the strongest stable provider key material exposed by the supported interface;
4. agent-bound cryptographic or device-credential evidence;
5. pre-auth credential association when exposed by the provider;
6. supporting timing, principal/tag, and local-client observations where useful.

Ambiguity or conflict fails closed. Hostname-only and IP-only matching are prohibited. Administrative provider credentials remain server-side. Unknown compatibility disables unsafe mutations.

## Consequences

Provider observations are normalized and secret-bearing fields are redacted. Provider correlation must be exercised against an isolated instance of the pinned Headscale version before it can participate in trusted activation. The version pin is explicit and may change through a future reviewed compatibility decision.

## Rejected Alternatives

- Hostname or IP correlation.
- Pre-auth credential association alone as permanent identity.
- Direct Headscale database access for ordinary node identity correlation.
- Fork Headscale before a documented public-interface blocker exists.
