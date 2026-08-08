# Nodescale Documentation

This directory contains the durable technical documentation for Nodescale. Implementation history and milestone notes should live in issues, pull requests, commit history, or release notes rather than in the reference documentation.

## Start here

- [Architecture](architecture.md) — system boundaries, component responsibilities, lifecycle flow, and trust gates.
- [Identity model](identity-model.md) — provider, Nodescale, and Keryx identity separation.
- [Provider contract](provider-contract.md) — normalized provider interfaces, mutation capabilities, and certainty rules.
- [Threat model](threat-model.md) — protected properties, secret handling, trust boundaries, and fail-closed behavior.

## Provider integration

- [Headscale compatibility](headscale-compatibility.md) — supported Headscale version behavior and HTTP safety requirements.
- [Discovery and reconciliation](discovery-reconciliation.md) — read-only import, provider observations, classifications, and reconciliation semantics.

## Device admission and trust

- [Invitations and redemption](invitations.md) — invitation tokens, join sessions, provider credential coupling, and the redemption transport.
- [Device identity and trust](device-trust.md) — authoritative N5 correlation, owner-root authorization, trust decisions, binding reconciliation, and cleanup.

## Contributor reference

- [Development](development.md) — prerequisites, checks, test discipline, and optional acceptance tooling.
- [Architecture decision records](adr/) — durable decisions and rejected alternatives.

## Documentation conventions

Reference documentation should describe current contracts and behavior. Avoid embedding temporary phase names, owner handoff notes, task status, checkpoint hashes, or implementation chronology unless the history itself is necessary to understand an architectural decision.
