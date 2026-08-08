# Headscale Compatibility

## Selected pin

Nodescale N1A targets stock Headscale **v0.29.3** (`v0.29.3`, upstream commit `5aff68b5b9921db5ccb88013bb1740077ab872fb`). The release was published on **2026-07-29 at 12:51:35 UTC**. It was reverified on 2026-08-07 as the latest non-draft, non-prerelease upstream release, so the N0A pin remains both current and conservative.

Primary upstream evidence:

- [official v0.29.3 release](https://github.com/juanfont/headscale/releases/tag/v0.29.3)
- [tagged API documentation](https://github.com/juanfont/headscale/blob/v0.29.3/docs/ref/api.md)
- [tagged OpenAPI document](https://github.com/juanfont/headscale/blob/v0.29.3/gen/openapiv2/headscale/v1/headscale.swagger.json)
- [tagged service schema](https://github.com/juanfont/headscale/blob/v0.29.3/proto/headscale/v1/headscale.proto)
- [tagged node schema](https://github.com/juanfont/headscale/blob/v0.29.3/proto/headscale/v1/node.proto)

No newer stable release existed at reverification time. There was therefore no API or identity-model change requiring a pin decision.

## Read-only API surface

The adapter issues only fixed `GET` requests. `/version` is public in stock Headscale and receives no bearer header; `/api/v1/*` requests are bearer-authenticated:

| Surface | Purpose |
| --- | --- |
| `GET /version` | Detect the running Headscale version. |
| `GET /api/v1/health` | Prove API authentication and database connectivity. |
| `GET /api/v1/node` | List normalized provider nodes. |
| `GET /api/v1/node/{node_id}` | Read one node by Headscale's numeric provider node ID. |

The v0.29.3 OpenAPI operation for `ListNodes` has only an optional `user` filter and no pagination parameters or page token. N1A therefore does not invent pagination behavior. Unknown response fields are ignored where safe; missing required identity evidence fails closed.

The stock API exposes write routes, but this crate does not model or call them. Its implemented trait has no mutation methods, redirects are disabled, and all reported capability sets contain only inspection, list, lookup, and health operations.

## Compatibility mapping

| Observation | Nodescale state | Mutation |
| --- | --- | --- |
| Exact clean `v0.29.3` (`dirty=false`) | `compatible` | Disabled |
| Exact `v0.29.3` with `dirty=true` | `compatible_with_constraints` | Disabled |
| Clean `v0.29.0`–`v0.29.2` | `read_only_degraded` | Disabled |
| Future, older-minor, prerelease, or build-suffixed version | `unsupported` | Disabled |
| Timeout, TLS, or transport failure | `unreachable` | Disabled |
| HTTP 401 or 403 | `authentication_failed` | Disabled |
| Missing or malformed version evidence | `unsupported` diagnostic / malformed-response health | Disabled |

Unknown and future versions never inherit write capability. N1A sets `mutation_allowed = false` independently of version or server capability.

## Identity-field classification

The adapter preserves identity classes rather than flattening provider data into interchangeable strings:

| Headscale field | Classification | N1A use |
| --- | --- | --- |
| provider instance ID + canonical positive Headscale node `id` + SHA-256 machine-key fingerprint | Strong scoped provider identity tuple | Exact list/lookup identity within one configured provider instance; machine-key change is a conflict/rotation observation |
| `machineKey` | Strong but replaceable / stable-conditional correlation evidence | Retained in a dedicated conditional-evidence type and fingerprinted as a conflict guard; never matched globally |
| `nodeKey`, `discoKey` | Mutable cryptographic observations | Retained separately; never substituted for canonical identity or durable correlation |
| user `id` and metadata | Conditional provider metadata | Observation only; user association may change |
| pre-auth-key `id` relationship | Partial correlation evidence | Observation only; no key secret is retained |
| hostname `name`, `givenName` | Mutable/display-only | Presentation metadata only |
| `ipAddresses` | Mutable addressing metadata | Never identity |
| tags | Mutable policy metadata | Never identity or authorization |
| created/last-seen/expiry/online state | Mutable temporal/health observations | Diagnostics and future correlation support only |

Pre-auth association alone is insufficient device identity. N5 combines the exact provider-native pre-auth reference with a durably confirmed, single-use N4 join session, the exact scoped provider identity, and verified machine-key fingerprint evidence before generating a logical Nodescale `DeviceId`. This identifies the joined provider registration but does not authenticate a Keryx runtime or grant trust; those remain separate boundaries.

## HTTP safety

Production construction accepts a clean HTTPS origin only. TLS certificate verification uses the Rustls-backed default trust behavior and cannot be disabled through the public constructor. The client applies bounded connect/request timeouts, a configurable response-size ceiling, no redirects, no automatic retries, typed transport/authentication/parsing failures, and redacted credential formatting.

## Scope and constraints

N1A performs no Headscale, Tailscale, Keryx, or Hermes Fleet mutation. It does not deploy Headscale, read Headscale's database, create users or credentials, alter tags or policy, join or delete nodes, activate Nodescale devices, bind Keryx identity, or project Fleet grants. Sanitized fixtures are the acceptance basis; no live provider proof was required or performed.
