# Invitation and join-session contract

## Scope

N4A adds the Nodescale invitation layer above the accepted N3A provider-mutation primitives. It can issue an opaque Nodescale invitation, reserve one durable join session, create one bounded provider credential, deliver that provider credential once, and invalidate the exact provider credential during revocation or expiry.

N4A itself does **not** perform a Tailscale device join. N4B transports one invitation through a bounded ingress and retains an exact-tree disposable provider-join acceptance harness. A completed run is established only by its tree-bound external evidence manifest; it does not activate a Nodescale device, establish a Keryx binding, enroll or grant Hermes Fleet authority, or prove trusted membership.

## N4B redemption transport

The only network route is `POST /v1/redemptions` over verified TLS. Its strict
bounded JSON body contains exactly `invitation_token`. Tokens are forbidden from
URLs, query strings, headers, cookies, logs, labels, and caller-controlled audit
metadata. Forwarded peer headers are not trusted.

Per-source and global admission runs before body parsing and Argon2 work. Source
state, the overflow bucket, and the worker queue are bounded in memory. Unknown
selectors receive fixed-profile dummy Argon2 work after admission. The single
state-owning worker bounds expensive verification and provider creation to one;
SQLite, not that worker, remains authoritative for cross-process replay safety.

Malformed envelopes are fixed invalid requests. Unknown, wrong, expired,
revoked, consumed, provider-rejected, and ambiguous redemptions share one small
non-redeemable response. Perimeter exhaustion is retryable without consulting
invitation state. Successful responses are `no-store`, close the connection,
and contain only `login_server`, optional public `root_ca_pem`, and `auth_key`.
The state-owning worker does not relinquish cleanup responsibility merely because
an internal response channel accepted the delivery. The handler must consume,
serialize, and acknowledge the handoff in one poll; cancellation before that
point closes the acknowledgement and triggers exact credential revocation.
Worker shutdown is explicit, deadline-bounded, and joined after in-flight
containment completes.

## Invitation token

An invitation token contains an opaque UUID selector and a cryptographically random 32-byte secret. The selector is lookup-only and carries no role, network, identity, expiry, or authorization claims.

The complete plaintext token is returned only by the consuming delivery API. It is never stored in SQLite, audit metadata, logs, diagnostics, list/show views, or `Debug` output. SQLite stores only the selector, a fixed-profile Argon2id PHC verifier with a random salt, and safe invitation metadata.

Every invitation has:

- exactly one permitted use;
- a fixed bounded expiry;
- one exact network and provider instance;
- one exact provider principal;
- a non-empty bounded set of typed eligibility roles;
- explicit elevated intent when the `admin` role is present.

Roles constrain eligibility and provider tags. They do not grant Nodescale trust, Keryx identity, or Fleet authority.

## Durable lifecycle

SQLite transactions and compare-and-swap predicates are authoritative. In-memory locks are not used for correctness.

The invitation lifecycle is:

```text
issued -> reserved -> consumed
   |          |          |
   +-------> revoking -> revoked
   +-------> expiring -> expired
   +-------> failed
```

A successful token presentation atomically reserves the invitation and creates one join session before any provider request is dispatched. A replay, including a concurrent presentation through another SQLite connection, is rejected without a second provider dispatch.

The join session records only a SHA-256 digest of caller correlation metadata, workflow generation, provider reference, expiry/use bounds, and certainty state. It never stores caller correlation values, invitation plaintext, or provider-credential plaintext. Base invitation/session linkage and the single-use limit are immutable at the SQLite boundary, and expiry cannot be prepared before the durable deadline.

## Provider-credential coupling

Redemption uses the production `MutationProvider` boundary and a state-issued, single-use authorization for the exact network, provider instance, and `CreateJoinCredential` capability.

The requested provider credential is:

- bound to the persisted provider principal;
- non-reusable and non-ephemeral;
- limited to one use;
- bounded by the invitation expiry;
- tagged only from the closed typed role vocabulary.

The provider credential is returned only after authoritative provider confirmation and durable state confirmation. Its delivery wrapper is consuming and redacted. Nodescale persists only a generated Nodescale credential ID plus the exact provider-owned credential reference and digested confirmation correlation metadata. If provider creation succeeds but durable confirmation fails, Nodescale returns no secret, immediately attempts exact-reference invalidation with fresh authority, and best-effort records the creation as ambiguous; it never dispatches creation again.

## Uncertainty and retry rules

Provider credential creation is dispatched at most once. If the request might have applied but the response or secret is unavailable, the join session becomes terminally ambiguous/failed. Nodescale does not retry creation and does not synthesize, recover, or return a credential secret.

Definite pre-dispatch failures are recorded separately from ambiguous outcomes, but the single-use invitation is not reopened after reservation. This prevents a provider-side credential from being created twice.

Credential invalidation has different semantics because it carries no new secret. Ambiguous or retryable invalidation remains nonterminal and can be reconciled using the exact provider reference. When an exact reference exists, terminal revocation/expiry requires confirmed invalidation or authoritative already-absent/already-expired evidence. A creation that stayed ambiguous without any returned reference cannot be invalidated by guesswork; once its bounded credential deadline is reached, local invitation/session state expires without claiming provider invalidation evidence.

## Acceptance evidence

Automated acceptance covers:

- one-time invitation and provider-secret delivery;
- verifier and database secret safety;
- role/admin-intent bounds;
- replay and cross-connection concurrency;
- migration and immutable-linkage constraints;
- provider lost-response and invalidation uncertainty;
- revocation and expiry settlement;
- deterministic fake-provider dispatch counts.

The N4A release proof runs a disposable Headscale v0.29.3 image pinned by OCI digest over verified loopback TLS. It creates the synthetic provider principal directly because invitation service does not own principal provisioning, then executes invitation create, redeem, replay rejection, and revoke through `InvitationService` and the real Headscale mutation adapter. It verifies zero provider nodes and zero Nodescale device, Keryx, and Fleet counters.

The retained N4B proof adds the ingress and a pinned Tailscale v1.98.10 userspace
client. Two isolated source addresses race one invitation; exactly one bootstrap
is delivered and replay is rejected. The joined Headscale node must reference
the exact durable pre-auth credential ID. After client stop, the exact credential
is revoked and exact node deleted. Zero nodes, proof resources, listeners,
runtime roots, secrets, and host-network changes may remain.

## Deferred after N4B

The following remain blocked on separate owner authorization and acceptance criteria:

- correlating the joined provider node to authenticated agent identity;
- activating a trusted Nodescale device;
- creating a Keryx binding from authenticated runtime provenance;
- projecting managed enrollment or grants into Hermes Fleet;
- operator invitation issuance, CLI, and web-console surfaces.
