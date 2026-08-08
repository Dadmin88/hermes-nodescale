# Provider Contract

Provider adapters are a trust boundary. Raw provider payloads are untrusted and must be validated, normalized, and classified before domain or persistence code consumes them.

## Normalization boundary

Provider-neutral models preserve the difference between authoritative identity evidence and mutable metadata.

Hostnames, display names, addresses, tags, roles, and payload-supplied peer identifiers are never canonical identity.

`ProviderIdentity` combines:

- a configured provider instance;
- the provider-owned canonical node ID;
- a stable-key fingerprint used for conflict detection.

Provider, Nodescale, and Keryx identifiers remain distinct typed values.

Successful complete snapshots may update Nodescale-owned observations. Provider outages preserve the previous successful snapshot and update only sanitized provider health and freshness state. An outage is never interpreted as provider-side deletion.

Provider configuration stores only non-secret connection metadata and an opaque credential reference. Plaintext provider API credentials are injected at runtime and are not ordinary SQLite domain data.

## Read-only provider boundary

`ReadOnlyProvider` is the permanent inspection boundary for real adapters. It exposes only:

- server inspection;
- compatibility verification;
- node listing;
- exact node lookup;
- provider health.

It contains no write method.

Compatibility, provider routes, and provider-reported capabilities do not turn a read-only import into a mutation-authorized provider.

## Mutation provider boundary

`MutationProvider` is a separate interface. It consumes a provider-specific authorization value and exposes only operation-specific mutations.

Mutation requires:

- the exact configured network and provider instance;
- compatible runtime evidence;
- mutation-enabled state;
- the exact capability being requested;
- a state-issued authorization valid for that operation.

Authorization is not inferred from a role, a server version, a successful read, or the presence of another write route.

## Mutation capabilities

| Capability | Bounded operation | Security boundary |
| --- | --- | --- |
| `EnsureNetworkPrincipal` | Ensure one explicitly named provider principal. | Creates provider-side admission structure only; no Nodescale or Fleet trust. |
| `CreateJoinCredential` | Create one provider credential with explicit principal, expiry, and use count. | Plaintext is one-time delivery material and is never ordinary persistence, audit, or retry input. |
| `InvalidateJoinCredential` | Invalidate one exact provider credential ID. | Exact-reference cleanup only. |
| `ReplaceNodeTags` | Replace the complete desired tag set for one exact `ProviderIdentity`. | Tags remain provider policy metadata, not identity or Fleet grants. |
| `ExpireNode` | Expire one exact `ProviderIdentity`. | Target identity must be checked against authoritative provider evidence. |
| `DeleteNode` | Delete one exact `ProviderIdentity`. | Target identity must be checked against authoritative provider evidence. |
| `ManagePolicy` | Read, validate, and replace provider policy. | Available only in explicitly configured and verified supported policy mode. |

One authorized capability never implies another.

## Certainty semantics

The provider contract does not assume compare-and-swap support.

A write request can produce one of several meaningful states:

- applied;
- already satisfied;
- rejected;
- unsupported;
- ambiguous.

A transport acknowledgement is not enough to claim that state was applied. Where the provider exposes authoritative read-back, a mutation is considered certain only after the requested state is observed.

Ambiguous outcomes are handled conservatively:

- provider credential creation is not blindly retried because a second dispatch could create a second secret;
- exact-reference cleanup may be retried because it cannot create a new credential;
- unsupported or rejected operations remain explicit failures rather than apparent success.

## Headscale adapter requirements

The Headscale adapter validates authorization before issuing a write request.

Non-credential mutations perform a final reconciliation read where the provider exposes authoritative state. Credential creation performs no blind retry. Policy mutation is allowed only in the explicitly supported policy mode and performs a final read after any possible dispatch.

Unknown or unsupported policy modes produce no mutation traffic.

## Health and errors

Provider health distinguishes at least:

- healthy authenticated access;
- compatible or degraded read-only access;
- authentication failure;
- timeout;
- TLS failure;
- transport failure;
- malformed provider output;
- unsupported compatibility.

Authentication material is redacted from `Debug`, `Display`, diagnostics, and errors.

The Headscale client requires HTTPS, verifies TLS normally, disables redirects, applies bounded timeouts and response sizes, and performs no automatic write retries.

## Identity and trust

Provider observations are evidence, not trusted membership.

A normalized provider node cannot by itself:

- activate a Nodescale device;
- verify a Keryx binding;
- derive Hermes Fleet grants;
- authorize scheduling or execution;
- promote provider tags or roles into application authorization.

Pre-auth evidence is classified. Generic `Partial` association is non-authorizing. Headscale's authenticated node record may emit `ProviderAuthenticatedRegistration` for its exact credential-ID linkage; N5 may consume that only with exact active/unexpired N4 provenance, an exact provider re-read, and matching machine-key fingerprint to create an initially untrusted logical device. It never activates trust or establishes Keryx/Fleet authority.
