# Invitations and Redemption

Nodescale uses opaque single-use invitations to authorize a bounded provider bootstrap flow. Invitation possession is a redemption capability, not trusted device identity.

## Scope

The invitation service can:

- issue an opaque invitation;
- reserve one durable join session;
- create one bounded provider join credential;
- deliver that provider credential once;
- invalidate the exact provider credential during revocation or expiry.

A successful redemption does not by itself activate a Nodescale device, verify a Keryx binding, enroll the device in Hermes Fleet, or grant application authority.

## Invitation token

An invitation token contains:

- an opaque UUID selector used only for lookup;
- a cryptographically random 32-byte secret.

The selector carries no role, network, identity, expiry, or authorization claims.

Plaintext invitation tokens are returned only through the consuming delivery boundary. They are not stored in SQLite, audit metadata, logs, diagnostics, list/show views, or `Debug` output.

SQLite stores only the selector, a fixed-profile Argon2id verifier with a random salt, and safe invitation metadata.

Each invitation is bound to:

- exactly one permitted use;
- a bounded expiry;
- one network and provider instance;
- one provider principal;
- a non-empty bounded set of typed eligibility roles;
- explicit elevated intent when `admin` eligibility is present.

Roles constrain admission intent and provider tags. They do not grant Nodescale trust, Keryx identity, or Hermes Fleet authority.

## Durable lifecycle

SQLite transactions and compare-and-swap predicates are authoritative for invitation correctness. In-memory locks are not relied on for replay safety.

```text
issued -> reserved -> consumed
   |          |          |
   +-------> revoking -> revoked
   +-------> expiring -> expired
   +-------> failed
```

A successful token presentation atomically reserves the invitation and creates one join session before any provider request is dispatched.

Concurrent or repeated presentation of the same invitation is rejected without a second provider credential creation.

The join session stores only durable non-secret state, including correlation digests, workflow generation, provider reference, expiry/use bounds, and certainty state. It never stores invitation plaintext or provider-credential plaintext.

## Provider credential coupling

Redemption uses the production `MutationProvider` boundary with a state-issued authorization for the exact network, provider instance, and join-credential capability.

The requested provider credential is:

- bound to the persisted provider principal;
- limited to one use;
- bounded by the invitation expiry;
- tagged only from the approved typed role vocabulary;
- returned only after provider and durable state confirmation.

Nodescale persists only its own credential ID, the exact provider-owned credential reference, and safe correlation metadata. The provider credential plaintext remains one-time delivery material.

If provider creation succeeds but durable confirmation fails, Nodescale does not return the secret. It attempts exact-reference invalidation and records the outcome conservatively.

## Uncertainty and retry rules

Provider credential creation is dispatched at most once for a reserved invitation.

If a creation request might have applied but the plaintext credential cannot be recovered, the join session becomes terminally ambiguous or failed. Nodescale does not blindly retry creation, synthesize a replacement secret, or reopen the invitation.

Credential invalidation is different because retrying an exact-reference invalidation cannot create a second credential. Ambiguous or retryable cleanup may therefore remain nonterminal and be reconciled against the exact provider reference.

When no exact reference exists for an ambiguous creation, Nodescale does not guess. Local state may expire at the bounded credential deadline without claiming provider-side invalidation evidence.

## Redemption transport

The network redemption surface is:

```text
POST /v1/redemptions
```

It is served over verified TLS and accepts a strict bounded JSON body containing only `invitation_token`.

Invitation tokens are not accepted through URLs, query strings, headers, cookies, forwarded identity claims, or caller-controlled audit metadata.

Forwarded peer headers are not trusted for source identity.

### Admission controls

Resource admission occurs before body parsing and Argon2 verification:

- per-source token bucket;
- global token bucket;
- bounded source table;
- overflow bucket;
- request-body size limit;
- bounded worker queue.

Unknown selectors receive fixed-profile dummy Argon2 work after admission to reduce validity-oracle differences.

A dedicated state-owning worker bounds expensive verification and provider credential creation concurrency. SQLite transactions remain the cross-process authority for single-use redemption.

### Successful response

A successful response is non-cacheable and contains only provider bootstrap material:

- `login_server`;
- optional public `root_ca_pem`;
- one-time `auth_key`.

It does not include Nodescale IDs, provider references, roles, tags, hostnames, Keryx identity, or Hermes Fleet trust claims.

The worker retains cleanup responsibility until the HTTP handler has consumed and serialized the bootstrap handoff. Cancellation before that point causes exact credential cleanup rather than abandoning an active unrecoverable secret.

## Acceptance properties

Tests and disposable integration tooling should cover:

- one-time invitation and provider-secret delivery;
- verifier and database secret safety;
- role and elevated-intent bounds;
- replay and cross-connection concurrency;
- immutable invitation/session linkage;
- lost-response and ambiguous provider outcomes;
- revocation and expiry settlement;
- exact provider dispatch counts;
- isolated provider join using the exact issued credential;
- cleanup of disposable provider credentials, nodes, listeners, and runtime state.

Provider-join acceptance proves provider credential association. It does not prove authenticated Keryx identity or trusted Hermes Fleet membership.

## Current integration boundary

The repository does not yet complete:

- authenticated correlation from provider node to Keryx sender identity;
- trusted Nodescale device activation;
- managed Hermes Fleet enrollment and grant projection;
- a general operator invitation API, CLI, or web console.

Those integrations require their own authenticated contracts and acceptance tests rather than being inferred from invitation redemption.
