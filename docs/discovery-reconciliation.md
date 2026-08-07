# Network Import and Read-Only Reconciliation

## Import boundary

N2A imports an explicitly configured existing Headscale provider. The operator supplies a Nodescale network name, the Headscale HTTPS origin, an expected provider-instance identity, the selected compatibility pin, a TLS verification policy, and an opaque `secret://` credential reference. Nodescale inspects the provider, verifies the instance and pinned version, reads the initial node snapshot, and atomically persists the Nodescale network, sanitized provider configuration, normalized observations, and audit records.

API credentials are injected at runtime by the provider adapter. Plaintext API credentials are not accepted by the import model and are never stored in SQLite. Headscale imports are permanently read-only in N2A: `read_only = true` and `mutation_allowed = false`.

Networks are never inferred from node hostnames, display names, or addresses.

## Observation is not identity or trust

A provider observation is timestamped evidence about a canonical provider-local Headscale node ID. It preserves the strongest available machine-key fingerprint plus mutable node-key, disco-key, hostname, address, tag, user, registration, last-seen, expiry, online, and sanitized pre-auth correlation evidence from the provider-neutral record.

Observations are stored separately from Nodescale `Device` records. Hostname, display-name, and address collisions never merge observations. A canonical Headscale node ID paired with incompatible machine-key evidence is classified as `identity_conflict`; the prior strong identity and historical evidence are preserved.

**A Headscale node appearing in Nodescale discovery does not make it a trusted Hermes Fleet node.**

Discovery creates no Nodescale device credential, authenticated Keryx binding, Hermes Fleet projection, Fleet grant, execution permission, or trusted `Active` state. Adoption is modeled only as staging pending Nodescale device-credential proof and cannot bypass either later gate.

## Classifications

Persisted observations use explicit classifications:

- `expected_joining`
- `discovered_unmanaged` (the default for every previously unknown provider node)
- `active`
- `provider_missing`
- `provider_expired`
- `provider_removed`
- `identity_conflict`
- `quarantined`
- `revoked`

N2A does not create trusted active records. The additional states exist so later lifecycle packets can preserve one vocabulary without weakening the N0C activation gate.

## Reconciliation

A one-shot reconciliation cycle:

1. loads the persisted read-only import configuration;
2. inspects compatibility and provider-instance identity;
3. lists and deterministically sorts the complete provider snapshot by canonical node ID;
4. rejects duplicate canonical IDs or mismatched provider instances before applying state;
5. compares normalized provider truth with prior observations;
6. classifies discoveries, mutable metadata changes, expiry, disappearance, and strong-identity conflict;
7. commits observation changes, classifications, provider freshness, and semantic audit events in one SQLite transaction;
8. returns a sanitized doctor report.

A repeated cycle against unchanged provider truth does not change trust, generations, classifications, semantic fingerprints, or audit history. Poll timestamps may refresh observation freshness. Missing unmanaged observations are retained and classified `provider_missing` rather than deleted.

## Outage and failure behavior

Provider unreachable, authentication failure, incompatible version, malformed response, identity conflict, and local state failure are distinct outcomes. A failed provider read preserves the last successful inventory and does not mark every node missing or removed. The persisted doctor report records the failed attempt and health state while retaining the last successful reconciliation timestamp.

No failure path grants trust, deletes membership, enables provider mutation, or creates Fleet authority. Recovery after a temporary outage applies the next successful complete snapshot normally.

## Doctor report

The library report exposes the Nodescale network ID, provider state and compatibility, provider version, last attempt and last success timestamps, observed/unmanaged/missing/expired/conflict/quarantined/active counts, sanitized warnings, and `provider_mutation_enabled = false`. It contains no provider credential material.
