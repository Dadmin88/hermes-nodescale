# ADR 0002: Keryx Binding Provenance Contract

**Status:** Accepted requirement; implementation blocked on future Keryx extension
**Date:** 2026-08-07

## Context

Current generic Keryx task/sender surfaces do not provide the narrow, unforgeable provenance contract required to bind a Nodescale device to a Keryx peer. Generic task idempotency is not one-time nonce consumption, and generic execution paths violate the zero-run requirement.

## Decision

Require a dedicated direct operation named `nodescale.identity.bind.v1`.

The operation:

- is non-execution control traffic;
- creates zero Hermes runs and zero Fleet execution bindings;
- receives authoritative sender peer ID only through authenticated Keryx runtime provenance;
- does not require an authoritative peer ID in its request payload;
- binds one network/device/join-session/nonce to one sender;
- atomically consumes the nonce;
- permits safe identical replay and rejects conflicting replay;
- records binding generation and supports explicit rotation.

Conceptual request fields are `network_id`, `device_id`, `join_session_id`, `nonce`, and `agent_version`. Conceptual handler context includes authenticated sender, destination, operation, and session/provenance.

## Consequences

Nodescale N0C-N6 can proceed independently. N7 and live trusted activation remain blocked until this surface exists and passes spoofing, replay, expiry, conflict, rotation, zero-run, and zero-binding tests.

## Rejected Alternatives

- Interpret generic `sender_peer_id` as sufficient proof.
- Put authoritative `peer_id` in the request body.
- Implement binding as a generic Hermes/Fleet delegated task.
