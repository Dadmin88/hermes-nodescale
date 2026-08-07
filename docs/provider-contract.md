# Provider Contract

## Normalization boundary

Raw provider payloads are untrusted. A provider adapter must validate and normalize observations into provider-neutral Rust types before domain or persistence code consumes them. Hostnames, display names, addresses, tags, roles, and payload-supplied peer identifiers are never canonical identity.

N2A provider configuration persists only an HTTPS origin, provider-instance identity, selected compatibility pin, opaque `secret://` reference, TLS verification policy, and permanent read-only flags. Plaintext provider credentials are runtime-only and never ordinary SQLite domain data.

Successful complete snapshots may update Nodescale-owned observations. Provider outages preserve the previous snapshot and update only sanitized provider health/freshness state; an outage is never interpreted as provider-side deletion.

`ProviderIdentity` combines a configured provider instance, provider-owned node ID, and stable-key fingerprint. Provider, Nodescale, and Keryx identifiers remain non-interchangeable newtypes.

N1A expands `ProviderNode` with separately typed identity evidence, conditional user and pre-auth correlation observations, display/address metadata, tags, temporal fields, and online/expiry state. Strong, conditional, mutable, display-only, and unsafe-for-identity classes are explicit rather than generic labels.

## Read and mutation boundaries

`ReadOnlyProvider` is the permanent async inspection boundary for real adapters. It exposes only:

- server inspection;
- compatibility verification;
- node listing;
- exact node lookup;
- provider health.

It contains no write method. The Headscale N1A adapter implements only this boundary. The older deterministic `Provider` trait remains the N0C future-operation simulator used by the fake provider; it is not implemented by the real Headscale adapter.

Compatibility and operation mode are separate gates. `CompatibilityReport::from_inspection` requires both a compatible status and explicit adapter mutation permission. Unknown compatibility, read-only degraded mode, or a read-only adapter can never gain mutation authority merely because a server exposes write routes.

## Capability truth

Provider capability observations are explicit operations, not broad role-derived authority. A provider reports only operations it can safely perform in its current mode. N1A Headscale reports inspection, list, exact lookup, and health. It never reports join-credential, node mutation, or policy capability, and always reports `mutation_allowed = false`.

Future mutation operations remain gated behind exact known compatibility and a separately authorized adapter phase. Unsupported operations must return `ProviderError::Unsupported`; they must never return apparent success. Ambiguous write outcomes must remain explicit and require later reconciliation.

## Health and errors

Health distinguishes healthy authenticated access, reachable but incompatible/degraded access, authentication failure, timeout, TLS failure, transport failure, and malformed provider output. Authentication material is redacted from `Debug`, `Display`, diagnostics, and errors.

The Headscale client verifies TLS by default, requires a clean HTTPS origin, disables redirects, applies bounded connect/request timeouts and response sizes, performs no automatic retries, and deterministically parses sanitized API responses.

## Identity and trust

Provider observations are evidence, not trusted membership. A normalized Headscale node cannot activate a Nodescale device, verify a Keryx binding, derive exact Hermes Fleet grants, or promote provider role/tag metadata into authorization. Pre-auth-key association is partial correlation evidence only.

The deterministic fake provider remains test infrastructure. Its legacy `Provider` implementation preserves mutable N0C simulation, while its async `ReadOnlyProvider` projection advertises only read capabilities, always denies mutation, and mirrors the real adapter's healthy/degraded/authentication/unreachable semantics.
