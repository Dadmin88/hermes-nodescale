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

It contains no write method. The Headscale read adapter remains on this boundary. `MutationProvider` is separate, consumes an associated authorization type by value, and is implemented by the fake and Headscale mutation adapters. The older deterministic `Provider` trait remains the N0C simulator.

Compatibility and operation mode are separate gates. `CompatibilityReport::from_inspection` requires both a compatible status and explicit adapter mutation permission. Unknown compatibility, read-only degraded mode, or a read-only adapter can never gain mutation authority merely because a server exposes write routes.

## Capability truth

Provider capability observations are explicit operations, not broad role-derived authority. The read-only Headscale adapter reports inspection, list, exact lookup, and health and always reports `mutation_allowed = false`. Mutation capabilities are persisted separately and authorized one operation at a time.

Mutation operations are gated behind exact known compatibility, explicit state configuration, and a state-issued single-use authorization. Unsupported operations never return apparent success. Ambiguous write outcomes remain explicit and require containment or later reconciliation.

## N3A mutation contract

The authorized adapter exposes these operations independently only after proving an
authenticated runtime reports the exact clean pin `version == "v0.29.3"` and
`dirty == false`, and after verifying explicit mutation-enabled configuration
for the exact network/provider instance. Dirty, malformed, prerelease,
build-suffixed, future, unsupported, unreachable, authentication-failing, or
read-only runtime evidence fails closed:

| Capability | Bounded operation | Required boundary |
| --- | --- | --- |
| `EnsureNetworkPrincipal` | Ensure one explicitly named provider principal. | Principal admission only; it neither creates Nodescale identity nor grants application authority. |
| `CreateJoinCredential` / `InvalidateJoinCredential` | Create a credential for that principal with explicit expiry and bounded use count; invalidate by its exact provider credential ID. | The returned plaintext is one-time delivery material, never ordinary persistence, audit, diagnostics, or retry input. |
| `ReplaceNodeTags` | Replace tags with the complete requested tag set for one exact `ProviderIdentity`. | Tags remain mutable provider policy metadata, never identity or Fleet authorization. |
| `ExpireNode` / `DeleteNode` | Expire or delete one exact `ProviderIdentity`. | Identity must be re-read and match before and, where observable, after mutation. |
| `ManagePolicy` | Read, check, and replace provider policy. | Available only with explicit trusted `database` policy mode and isolated proof; no generic HTTP route, response shape, `updatedAt`, or version inference authorizes policy mutation. |

Capability advertisement must remain operation-specific: a compatible server,
an enabled mutation mode, or one authorized operation does not authorize any
other row. The provider contract has no compare-and-swap (CAS) primitive, so the
provider must not promise CAS semantics. A write response alone is not a
certain outcome. Record `rejected`, `unsupported`, or `ambiguous` distinctly;
report a requested state as applied or already satisfied only after an
authoritative read-back where the provider makes one possible. An ambiguous
credential creation is never treated as a usable credential, is never recorded
as confirmed, and requires containment/reconciliation rather than blind retry.

The Headscale adapter checks authorization before any network request. Every
possibly dispatched non-credential mutation performs exactly one final
reconciliation read. Credential creation performs no blind retry; uncertainty
is terminally ambiguous. Policy mutation is available only in configured
database mode, performs at most one PUT, and performs exactly one final GET
after possible dispatch. File and unknown policy modes perform zero traffic and
return `Unsupported`.

None of these provider effects creates trusted Nodescale membership, verifies
a Keryx binding, or activates Hermes Fleet enrollment, grants, scheduling, or
execution.

## Health and errors

Health distinguishes healthy authenticated access, reachable but incompatible/degraded access, authentication failure, timeout, TLS failure, transport failure, and malformed provider output. Authentication material is redacted from `Debug`, `Display`, diagnostics, and errors.

The Headscale client verifies TLS by default, requires a clean HTTPS origin, disables redirects, applies bounded connect/request timeouts and response sizes, performs no automatic retries, and deterministically parses sanitized API responses.

## Identity and trust

Provider observations are evidence, not trusted membership. Generic pre-auth association remains partial, non-authorizing correlation evidence. The authenticated Headscale node record's exact credential-ID linkage is separately classified as `ProviderAuthenticatedRegistration`; N5 may use it only with exact active N4 provenance, exact provider re-read, and machine-key fingerprint verification to create an initially untrusted logical device. No provider observation can activate a Nodescale device, verify a Keryx binding, derive exact Hermes Fleet grants, or promote provider role/tag metadata into authorization.

The deterministic fake provider remains test infrastructure. Its legacy `Provider` implementation preserves mutable N0C simulation, while its async `ReadOnlyProvider` projection advertises only read capabilities, always denies mutation, and mirrors the real adapter's healthy/degraded/authentication/unreachable semantics.
