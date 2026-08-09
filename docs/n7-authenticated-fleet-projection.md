# N7 authenticated Fleet projection protocol

**Status:** Selected implemented V1; acceptance proof pending
**License:** AGPL-3.0-only

N7 is a Linux-local authenticated projection protocol from Nodescale to Fleet.
It is not a Keryx protocol, remote Fleet API, bearer-token protocol, or a
reopening of N6. This document describes the selected V1 exercised by Fleet
local control and the Nodescale client; it does not claim release acceptance.
That remains pending the two-tree proof.

## 1. Connection authority

Fleet owns the configured Unix-domain socket (UDS). Before reading a frame it
obtains Linux `SO_PEERCRED` and compares the peer UID with the configured
Nodescale service UID. Only an exact UID match reaches dispatch. Missing,
malformed, unsupported, or mismatched credentials close the connection; no
caller-selected identity, bearer token, shared secret, authorization header, or
JSON principal exists in V1.

Socket path ownership, mode, PID, GID, and JSON content are not substitutes for
`SO_PEERCRED`. The UDS is local-only and Fleet-owned; Nodescale does not bind or
replace it.

## 2. Framing

Every request and response is one frame:

```text
+--------------------------+----------------------------------+
| 4-byte unsigned BE length| exactly that many UTF-8 JSON bytes|
+--------------------------+----------------------------------+
```

The payload length is `1..=32768`. Fleet reads the header before allocating the
payload, then rejects a zero-length, oversized, truncated, invalid-UTF-8, or
malformed request as `invalid_request` when a response can safely be written.
The connection is bounded to one request/one response in V1. No HTTP mapping,
multiplexing, or fallback framing exists.

## 3. Closed request JSON

The request decoder rejects duplicate keys at every nesting level and JSON
number literals (including integer, decimal, exponent, and constants). Request
objects must have exactly their defined keys; unknown and missing keys fail.
The parser does not accept `null`, loose metadata, type coercion, a request ID,
a `body` wrapper, or an alternate envelope.

Every request includes exactly `schema: "fleet.managed-projection.v1"` and one
of the following closed top-level forms:

```json
{"schema":"fleet.managed-projection.v1","kind":"capabilities"}
{"schema":"fleet.managed-projection.v1","kind":"apply","document":{...}}
{"schema":"fleet.managed-projection.v1","kind":"inspect","selector":{...}}
```

`apply.document` has exactly these keys:

```text
source, network_id, device_id, projection_generation,
membership_generation, binding_generation, content_hash, operation,
generated_operations, provenance
```

`provenance` has exactly `source`, `network_id`, `device_id`, and `snapshot`;
its identity fields must equal the enclosing document identity. `inspect.selector`
has exactly `source`, `network_id`, and `device_id`. Scalar identifiers are
bounded nonempty strings and `generated_operations` is a string list.

These request restrictions do not erase the response's explicit typed values:
responses use Boolean `ok` and `inspect` uses `null` for a missing durable
record. No V1 response status is a JSON number.

## 4. Exact request/response shapes

| Request | Successful response |
| --- | --- |
| `{"schema":"fleet.managed-projection.v1","kind":"capabilities"}` | `{"schema":"fleet.managed-projection.v1","kind":"capabilities","ok":true,"result":{"kinds":["capabilities","apply","inspect"]}}` |
| `{"schema":"fleet.managed-projection.v1","kind":"apply","document":{...}}` | `{"schema":"fleet.managed-projection.v1","kind":"apply","ok":true,"result":{"outcome":"<outcome>"}}` |
| `{"schema":"fleet.managed-projection.v1","kind":"inspect","selector":{...}}` | `{"schema":"fleet.managed-projection.v1","kind":"inspect","ok":true,"result":{"generated":...,"effective":...}}` |

A request/frame/schema/grammar failure that reaches the response path is exactly:

```json
{"schema":"fleet.managed-projection.v1","kind":"error","ok":false,"error":"invalid_request"}
```

`capabilities.result.kinds` is exactly `capabilities`, `apply`, and `inspect`.
The exact `apply.result.outcome` vocabulary is `applied`, `already_applied`,
`conflict`, `stale`, and `gap`. There is no `unchanged`, generic `rejected`,
request correlation field, or nested result envelope in selected V1.

For `inspect`, a missing managed identity is exactly:

```json
{"generated":null,"effective":null}
```

A present `generated` record contains state, `projection_generation`,
`membership_generation`, `binding_generation`, `content_hash`,
`allowed_operations`, and `provenance`. `effective` separately contains state,
`allowed_operations`, and `operator_denied_operations` after Fleet policy. This
is Fleet's durable read-back, not an apply echo or Nodescale cache.

## 5. Durable state and generated authority

The durable key is `(source, network_id, device_id)`. An exact already-persisted
transition yields `already_applied`; a same-generation non-identical transition
yields `conflict`; a lower generation yields `stale`; and a non-successor
generation yields `gap`. A successful new transition yields `applied`.

The only generated Fleet grants are exactly:

- `fleet.health`
- `fleet.inventory`
- `fleet.message`

Fleet enforces that allowlist both at write and effective-authorization time.
Nodescale input cannot create `fleet.hermes.run`, execution, shell, file,
process, admin, wildcard, enrollment, role-implied, or future-operation access.
Fleet's separate local operator deny wins and is not removed by a projection.
A `disable` or `remove` operation has no generated grants.

An `apply` response is a handled-request receipt, not the evidence that a caller
later observes durable state. After an uncertain apply transport/response result,
Nodescale must use `inspect` before retrying or marking the projection observed.

## 6. Non-goals and required proof

V1 has no TCP listener, HTTP endpoint, token auth, caller principal, unknown
field compatibility, or implicit execution authority. A platform unable to make
the exact Linux `SO_PEERCRED` UID check does not implement this V1.

Source review and focused tests do not activate N7. Acceptance is pending the
exact-tree two-repository proof in `proofs/n7/README.md`, which must prove the
real UDS credential boundary, framing/parser failures, exact response forms,
durable restart/read-back, allowlist, and SIGTERM cleanup against the same
Nodescale and Fleet candidate trees.
