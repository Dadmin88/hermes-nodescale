# Headscale Compatibility

## Supported target

Nodescale is currently validated against stock Headscale **v0.29.3**. Compatibility is intentionally explicit and conservative: unknown, future, prerelease, malformed, or otherwise unsupported runtime versions fail closed for mutation.

Upstream references for the pinned version:

- [v0.29.3 release](https://github.com/juanfont/headscale/releases/tag/v0.29.3)
- [API documentation](https://github.com/juanfont/headscale/blob/v0.29.3/docs/ref/api.md)
- [OpenAPI document](https://github.com/juanfont/headscale/blob/v0.29.3/gen/openapiv2/headscale/v1/headscale.swagger.json)
- [service schema](https://github.com/juanfont/headscale/blob/v0.29.3/proto/headscale/v1/headscale.proto)
- [node schema](https://github.com/juanfont/headscale/blob/v0.29.3/proto/headscale/v1/node.proto)

The compatibility pin is a code and test contract, not a claim that the pinned release will always be the newest Headscale release.

## Read-only API surface

The read adapter issues only fixed `GET` requests. `/version` is public in stock Headscale and receives no bearer header. `/api/v1/*` requests use bearer authentication.

| Surface | Purpose |
| --- | --- |
| `GET /version` | Detect the running Headscale version. |
| `GET /api/v1/health` | Verify authenticated API access and provider health. |
| `GET /api/v1/node` | List provider nodes. |
| `GET /api/v1/node/{node_id}` | Read one node by Headscale's canonical numeric node ID. |

The v0.29.3 `ListNodes` operation exposes an optional `user` filter but no pagination token. The adapter therefore does not invent pagination behavior.

Unknown response fields may be ignored where safe. Missing required identity evidence fails closed.

## Compatibility classification

Read compatibility and mutation eligibility are separate decisions.

| Runtime observation | Compatibility |
| --- | --- |
| Exact clean `v0.29.3` | `compatible` |
| Exact `v0.29.3` reporting `dirty=true` | `compatible_with_constraints` |
| Clean `v0.29.0`–`v0.29.2` | `read_only_degraded` |
| Future, older-minor, prerelease, build-suffixed, or malformed version | `unsupported` |
| Timeout, TLS, or transport failure | `unreachable` |
| HTTP 401 or 403 | `authentication_failed` |

A successful read classification does not grant mutation authority. Mutation additionally requires the exact supported clean runtime, explicit mutation-enabled state for the exact provider instance, and an operation-specific authorization.

## Identity-field classification

Provider fields are classified by how safely they can participate in identity correlation:

| Headscale evidence | Classification | Nodescale use |
| --- | --- | --- |
| provider instance + positive node `id` + machine-key fingerprint | Strong scoped provider identity | Exact provider-local node identity and conflict detection. |
| `machineKey` | Strong but replaceable correlation evidence | Fingerprinted and retained as a rotation/conflict guard; never matched globally. |
| `nodeKey`, `discoKey` | Mutable cryptographic observation | Retained separately; never substituted for canonical provider identity. |
| user metadata | Conditional provider metadata | Observation only. |
| pre-auth credential ID relationship | Partial correlation evidence | Useful join evidence, but not device identity. |
| hostname / given name | Mutable presentation metadata | Display only. |
| IP addresses | Mutable addressing metadata | Never identity. |
| tags | Mutable provider policy metadata | Never identity or application authorization. |
| timestamps / online / expiry | Mutable operational observations | Diagnostics and correlation support only. |

Pre-auth credential association alone is insufficient for trusted device identity.

## HTTP safety

Production Headscale configuration requires a clean HTTPS origin. The adapter:

- uses normal Rustls certificate and hostname verification;
- provides no insecure-TLS public constructor;
- disables redirects;
- applies bounded connect and request timeouts;
- applies a configurable response-size ceiling;
- performs no automatic write retries;
- uses typed transport, authentication, and parsing failures;
- redacts authentication material from formatting and diagnostics.

An optional custom root is additive to system trust, bounded in size, and must contain valid CA material. It does not disable hostname or certificate verification.

## Mutation compatibility

The mutation adapter is capability-scoped. Compatible runtime evidence alone cannot authorize a write. Each mutation requires explicit state configuration and a single-use authorization for the exact operation.

Policy management is more restrictive than ordinary node mutation and is available only when the provider's supported policy mode is explicitly configured and verified.

See [Provider Contract](provider-contract.md) for operation-level semantics.
