# Provider Contract

The `nodescale-provider` crate defines normalized, provider-neutral models. Raw provider JSON is never trusted domain state.

## Compatibility

Providers report exactly one status:

- `compatible`
- `compatible_with_constraints`
- `read_only_degraded`
- `unsupported`
- `unreachable`
- `authentication_failed`

Only the first two can permit mutation, and an operation must also be truthfully listed as supported. Unknown compatibility never implies write authority.

## Operations

The trait covers server inspection, compatibility verification, network-principal management, join-credential create/revoke, node list/get, tag updates, node expiration/deletion, policy get/apply, and health. Unsupported operations return a typed error instead of pretending success.

## Identity

Provider node identity combines provider-instance identity, canonical provider node ID, and stable key fingerprint. Hostnames and addresses remain observations. Ambiguous mutation outcomes are represented explicitly and require later read-back/reconciliation; they are not reported as success.

## N0C implementation

`nodescale-provider-fake` provides deterministic identities and simulations for compatibility modes, authentication failure, outages, node lifecycle, credentials, and ambiguous outcomes. It is test-only and establishes no production identity.
