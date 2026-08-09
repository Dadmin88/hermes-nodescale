# ADR 0011: Nodescale Fleet Control V1

**Status:** Selected implemented V1; exact-tree acceptance proof pending
**Date:** 2026-08-08
**License:** AGPL-3.0-only

## Context

N6 ends at the authenticated Keryx-binding boundary. It neither enrolls a Fleet
node nor grants Fleet authority. N7 is a separate local projection boundary: a
Nodescale client asks the Fleet service on the same Linux host to materialize
Fleet-owned managed state without gaining access to Fleet files, databases, or
a network API.

The selected V1 is intentionally minimal and is the surface exercised by the
Fleet local-control server and Nodescale client. This ADR records that surface;
it does **not** claim deployment or acceptance. N7 acceptance remains pending
the two-tree proof in `proofs/n7/README.md`.

## Decision

### Local transport and authentication

Fleet owns one local Unix-domain socket (UDS). On every accepted connection it
reads Linux `SO_PEERCRED` and dispatches only when the peer UID exactly equals
the configured Nodescale service UID. No bearer token, shared secret, HTTP
authorization header, caller-selected principal, or JSON identity claim exists
in V1.

A socket pathname, PID, GID, process name, filesystem ownership, or JSON field
is not a replacement for that exact UID comparison. Missing/unreadable peer
credentials, unsupported peer credentials, or a mismatched UID fail closed by
closing the connection before request dispatch. Fleet creates its socket as a
private Fleet-owned path; Nodescale is a client and does not bind or replace it.

### One-frame closed request grammar

Each direction uses one frame: a four-byte unsigned big-endian payload length,
followed by that many UTF-8 JSON bytes. Payload length must be in `1..=32768`.
The server bounds allocation from the header and rejects a zero-length,
oversized, truncated, non-UTF-8, or malformed request frame as
`invalid_request` when it can safely send a response.

The request parser rejects duplicate object keys at every level, JSON number
literals, non-object payloads, unknown keys, missing keys, and values outside
the exact request shape. It does not silently coerce or normalize request
values. This strictness applies to request JSON; V1 response envelopes use the
explicit `ok` Boolean and may carry `null` for an absent inspected record.

There is no request ID, `body` object, alternate envelope, version fallback, or
extension map. Every request has top-level `schema` and `kind`:

```json
{"schema":"fleet.managed-projection.v1","kind":"capabilities"}
```

The only request variants are:

| Kind | Exact top-level keys | Argument |
| --- | --- | --- |
| `capabilities` | `schema`, `kind` | none |
| `apply` | `schema`, `kind`, `document` | one closed projection document |
| `inspect` | `schema`, `kind`, `selector` | one closed identity selector |

`apply.document` has exactly `source`, `network_id`, `device_id`,
`projection_generation`, `membership_generation`, `binding_generation`,
`content_hash`, `operation`, `generated_operations`, and `provenance`.
`inspect.selector` has exactly `source`, `network_id`, and `device_id`.
`provenance` has exactly `source`, `network_id`, `device_id`, and `snapshot`,
and its identity fields must match the enclosing document. All document and
selector scalar identifiers are bounded nonempty strings; generated operations
are a list of strings.

### Exact response envelopes and outcomes

The response envelope is selected by the request kind:

```json
{"schema":"fleet.managed-projection.v1","kind":"capabilities","ok":true,"result":{"kinds":["capabilities","apply","inspect"]}}
{"schema":"fleet.managed-projection.v1","kind":"apply","ok":true,"result":{"outcome":"applied"}}
{"schema":"fleet.managed-projection.v1","kind":"inspect","ok":true,"result":{"generated":null,"effective":null}}
{"schema":"fleet.managed-projection.v1","kind":"error","ok":false,"error":"invalid_request"}
```

`capabilities.result.kinds` is exactly the three V1 kinds above. An accepted
`apply` returns only `result.outcome`; the current durable outcomes are exactly
`applied`, `already_applied`, `conflict`, `stale`, and `gap`. `inspect` returns
the Fleet durable read-back result rather than a request echo. A missing record
is exactly `{"generated":null,"effective":null}`. A present result separates
`generated` state from `effective` local-policy state. `generated` includes
state, the three persisted generations, content hash, allowed operations, and
provenance; `effective` includes state, allowed operations, and
operator-denied operations.

`ok: true` acknowledges a successfully handled local-control request; it is not
proof of an apply surviving a later process boundary. Nodescale establishes
observed durable state by a subsequent authoritative `inspect`, including after
an uncertain apply response. Authentication rejection is a connection close,
not an unauthenticated error envelope.

### Projection authority

Fleet persists accepted state in its dedicated Fleet-owned store. The managed
identity is `(source, network_id, device_id)`. Projection generation, membership
generation, binding generation, content hash, operation, generated operations,
and provenance are durable managed inputs. A stale generation yields `stale`; a
generation gap yields `gap`; the same generation with non-identical persisted
content yields `conflict`; an exact durable replay yields `already_applied`.

The only generated operation names are exactly `fleet.health`,
`fleet.inventory`, and `fleet.message`. Generated input cannot grant execution,
shell, file, process, admin, enrollment, wildcard, role-implied, or
`fleet.hermes.run` authority. Fleet's separately persisted local operator deny
remains authoritative and is never cleared by Nodescale input. Disable or
remove operations materialize no generated grants.

N6 binding rotation and revocation are ordered behind this authority boundary.
Once a projection dispatch has been attempted, Nodescale must not rotate or
revoke that exact binding until authoritative Fleet read-back proves either a
terminal `remove` projection or a later applied projection backed by different
binding provenance. A merely desired projection has made no external mutation
and does not block N6 revocation. An attempted, conflicting, or applied active
projection fails the N6 mutation closed. Operators therefore use this bounded
sequence for a managed node: reconcile uncertain projection state, apply and
inspect a grant-free `remove`, then rotate or revoke N6; after rotation, a new
active projection may be created from the replacement binding. Fleet
unavailability cannot be treated as successful deauthorization.

### Acceptance boundary

The selected V1 is not accepted on source review or unit tests alone. Acceptance
requires a disposable exact-tree proof across independently pinned Nodescale and
Fleet candidate trees. The proof must run archived bytes only and prove real
UDS/SO_PEERCRED enforcement, the four-byte big-endian `32768` limit, strict
closed request parsing, all three request/response shapes, all apply outcomes,
allowlisted operation names, durable authoritative inspect after restart, and a
separate SIGTERM cleanup run. See `proofs/n7/README.md`.

## Consequences

N7 remains language-neutral while Fleet keeps state and operator authority.
Nodescale has only a narrow local peer-UID-authenticated projection path, not a
general Fleet credential. N6 remains closed: it supplies neither an N7
credential nor Fleet enrollment, generated grants, or activation.

## Rejected alternatives

- Bearer tokens, shared secrets, caller-declared principals, or JSON UID claims.
- TCP/HTTP control endpoints or direct Fleet database/configuration access.
- Request IDs, a `body` wrapper, alternate envelopes, or permissive extensions.
- Trusting only a UDS path, PID, GID, or filesystem metadata.
- Treating request echoes or `ok: true` as authoritative durable read-back.
- Generated execution or wildcard authorization.
- One-repository, moving-worktree, or cleanup-unverified acceptance evidence.
