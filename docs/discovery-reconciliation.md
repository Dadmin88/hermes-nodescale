# Network Import and Read-Only Reconciliation

## Import boundary

Nodescale can import an explicitly configured existing Headscale provider in read-only mode. The operator supplies:

- a Nodescale network name;
- the Headscale HTTPS origin;
- the expected provider-instance identity;
- the selected compatibility pin;
- a TLS verification policy;
- an opaque `secret://` credential reference.

Nodescale inspects the provider, verifies its identity and compatibility, reads the initial node snapshot, and atomically persists the Nodescale network, sanitized provider configuration, normalized observations, and audit records.

Provider API credentials are injected at runtime by the adapter. Plaintext API credentials are not part of the import model and are never stored in SQLite.

Read-only imports remain explicitly marked `read_only = true` and `mutation_allowed = false`. Mutation authorization is configured separately and cannot be inferred from a successful import.

Networks are never inferred from node hostnames, display names, tags, or addresses.

## Observation is not identity or trust

A provider observation is timestamped evidence about a canonical provider-local Headscale node ID. It may include:

- machine-key fingerprint;
- node and disco keys;
- hostname and given name;
- addresses;
- tags;
- user metadata;
- registration, last-seen, expiry, and online state;
- sanitized pre-auth credential correlation evidence.

Observations are stored separately from Nodescale `Device` records. Hostname, display-name, and address collisions never merge devices.

A canonical Headscale node ID paired with incompatible machine-key evidence is classified as an identity conflict. Prior strong identity evidence and historical observations are preserved rather than silently replaced.

A discovered provider node does not create a Nodescale device credential, verified Keryx binding, Hermes Fleet enrollment, Fleet grant, execution permission, or trusted active state.

## Classifications

Persisted observations use explicit classifications:

- `expected_joining`
- `discovered_unmanaged`
- `active`
- `provider_missing`
- `provider_expired`
- `provider_removed`
- `identity_conflict`
- `quarantined`
- `revoked`

New previously unknown provider nodes default to `discovered_unmanaged` unless stronger managed-state evidence exists.

The vocabulary includes trusted lifecycle states so later activation logic can use one model, but discovery itself does not create trusted `active` membership.

## Reconciliation

A reconciliation cycle:

1. loads the persisted provider configuration;
2. inspects compatibility and provider-instance identity;
3. reads the complete provider snapshot;
4. normalizes and deterministically sorts observations by canonical provider node ID;
5. rejects duplicate canonical IDs or mismatched provider instances before state changes are applied;
6. compares provider truth with prior observations;
7. classifies discoveries, mutable metadata changes, expiry, disappearance, and strong-identity conflicts;
8. atomically commits observations, classifications, freshness state, and semantic audit events;
9. returns a sanitized diagnostic report.

Repeating reconciliation against unchanged provider truth does not change trust, semantic classifications, content identity, or generations. Poll timestamps may still refresh freshness information.

Missing unmanaged observations are retained and classified `provider_missing` rather than deleted.

## Outage and failure behavior

Nodescale distinguishes provider unreachability, authentication failure, incompatible versions, malformed responses, identity conflicts, and local state failures.

A failed provider read:

- preserves the last successful inventory;
- does not mark every node missing or removed;
- updates provider health and the failed-attempt timestamp;
- preserves the last successful reconciliation timestamp.

No failure path grants trust, deletes membership, enables provider mutation, or creates Hermes Fleet authority.

## Diagnostic report

The reconciliation report exposes sanitized operational state such as:

- Nodescale network ID;
- provider health and compatibility;
- provider version;
- last attempt and last successful reconciliation timestamps;
- observed, unmanaged, missing, expired, conflict, quarantined, and active counts;
- bounded warnings;
- provider mutation state.

The report contains no provider credential material.
