# ADR 0002: Keryx Binding Provenance Contract

**Status:** Accepted
**Date:** 2026-08-07

## Context

Generic Keryx task and sender surfaces do not provide the narrow, unforgeable provenance contract required to bind a Nodescale device to a Keryx peer. Generic task idempotency is not equivalent to one-time nonce consumption, and a device-binding operation must not create Hermes execution work as a side effect.

## Decision

Require a dedicated direct operation named `nodescale.identity.bind.v1`.

The operation:

- is non-execution control traffic;
- creates zero Hermes runs and zero Fleet execution bindings;
- receives authoritative sender peer ID only through authenticated Keryx runtime provenance;
- does not accept an authoritative peer ID from the request payload;
- binds one network, device, join session, and nonce to one authenticated sender;
- atomically consumes the nonce;
- permits safe identical replay and rejects conflicting replay;
- records a binding generation and supports explicit rotation.

Conceptual request fields are `network_id`, `device_id`, `join_session_id`, `nonce`, and `agent_version`. Conceptual handler context includes authenticated sender, destination, operation, and session provenance.

## Consequences

Nodescale components that do not depend on verified Keryx provenance can operate independently. Trusted device activation remains blocked until the binding surface exists and passes spoofing, replay, expiry, conflict, rotation, zero-run, and zero-execution-binding tests.

## Rejected Alternatives

- Interpret a generic `sender_peer_id` field as sufficient proof.
- Put authoritative `peer_id` in the request body.
- Implement identity binding as a generic Hermes or Fleet delegated task.
