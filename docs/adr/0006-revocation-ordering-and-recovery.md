# ADR 0006: Revocation Ordering and Recovery

**Status:** Accepted
**Date:** 2026-08-07

## Context

Provider cleanup can be unavailable while application authorization remains security-critical. Revocation must remove useful trust before depending on mesh cleanup.

## Decision

Nodescale owns revocation intent. The durable state machine orders effects as follows:

1. mark device revoking;
2. remove Fleet scheduling eligibility;
3. remove/disable generated grants;
4. disable managed enrollment;
5. revoke Nodescale device credential;
6. tombstone/disable Keryx binding;
7. expire/delete the Headscale node;
8. publish a new membership generation;
9. reconcile and verify every reachable subsystem;
10. mark application trust revoked while tracking unfinished provider cleanup separately.

Application authorization fails closed during provider outage. Historical identity and audit tombstones remain.

## Consequences

A Headscale outage cannot preserve generated Fleet authorization. Provider cleanup is retryable and does not block application-trust revocation. Every external mutation uses authoritative read-back where supported.

## Rejected Alternatives

- Remove mesh membership before removing Fleet trust.
- Treat one failed subsystem as reason to leave all trust enabled.
- Erase identity history during revocation.
