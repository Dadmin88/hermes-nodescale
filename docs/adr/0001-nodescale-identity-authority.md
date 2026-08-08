# ADR 0001: Nodescale Identity Authority

**Status:** Accepted
**Date:** 2026-08-07

## Context

Nodescale correlates Headscale mesh devices, Nodescale-managed logical devices, and Keryx peers. Treating any one identity as a substitute for another would allow mesh admission, host metadata, or a self-reported peer ID to bypass the intended trust chain.

## Decision

Maintain three distinct identity authorities:

- Headscale authoritatively identifies the provider mesh node.
- Nodescale authoritatively identifies the managed logical device, join session, and device credential generation.
- Keryx authoritatively identifies the application-transport peer through trusted runtime provenance.

Persist a typed binding between the three identities with independent credential and binding generations. A request payload peer ID is never authoritative. Hostname, mesh IP, display name, and Headscale tags are non-authoritative observations.

## Consequences

N5 may record an owner-authorized Nodescale **logical trust state** after exact provider correlation; that state is not application/runtime activation. Live managed-device activation requires all three identities and an explicit verified binding. Conflicts fail closed. Revocation and rotation can advance one generation without rewriting identity history.

## Rejected Alternatives

- Use hostname or IP as device identity.
- Treat a Headscale tag as application identity.
- Accept a caller-supplied Keryx peer ID.
- Collapse provider and Nodescale device IDs into one identifier.
