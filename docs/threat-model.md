# Threat Model

## Protected properties

- A hostname, mesh address, tag, role, or self-reported peer identifier cannot become authoritative identity.
- Roles do not grant exact Hermes Fleet operations.
- Unknown, unreachable, unsupported, or authentication-failed providers cannot authorize mutation.
- Stale generations cannot overwrite newer state.
- Required state and audit evidence commit atomically.
- Invitation plaintext and provider/device credentials are never persisted in ordinary domain records or audit metadata.

## Secret-bearing values

Invitation plaintext, provider API keys, provider join credentials, device credentials, and binding nonces use redacted wrappers. `Debug` and `Display` never expose their contents. APIs require an explicit exposure method at the narrow delivery boundary. SQLite stores invitation verifiers and opaque credential references, not plaintext secrets. Operator-owned secret files are expected to be owner-readable only; N0C does not implement a vault.

## Audit safety

Audit events record IDs, UTC timestamp, bounded actor/source, event kind, outcome, optional generation, and sanitized structured metadata. Metadata keys suggesting secrets, tokens, passwords, credentials, API keys, private keys, or nonces are rejected. Audit records must not contain credential values or private key material.

## Headscale N1A controls

The read adapter accepts only a clean HTTPS origin, uses normal certificate verification, disables redirects, sends bearer authentication only to the configured origin, bounds connection/request time and response bytes, and exposes typed sanitized errors. Its trait contains no mutation method and issues only documented `GET` requests. The mutation adapter shares the same transport controls. Its optional custom root is additive to system trust, bounded to 64 KiB, and must contain exactly one X.509 `CA:TRUE` certificate; hostname and certificate verification remain mandatory and no insecure-TLS switch exists.

Headscale output remains untrusted. Required provider node ID and machine-key evidence are validated before normalization. Hostnames and addresses cannot become identity. Pre-auth-key secrets are not modeled or retained. The authenticated Headscale node record's exact credential-ID linkage is classified as provider-authenticated registration evidence; generic partial associations remain non-authorizing. The doctor report is sanitized and hard-codes mutation as disabled.

## N3A mutation controls

N3A requires a separate, state-issued single-use capability for principal ensure, bounded join-credential
creation and exact invalidation, exact-node tag replacement, expiry, deletion,
and database-mode-only policy access. Compatibility, an administrator role,
or the presence of one provider write route cannot broaden that list; policy
is forbidden unless its database mode is explicitly configured and was
independently verified in the isolated proof.

Read-only imports remain immutable identity facts and cannot issue mutation
authority. The separate configuration binds exact network/provider identity,
positive monotonic generations, non-secret fingerprint, exact adapter/version,
half-open validity, policy mode, and explicit capabilities. Real authorization
fields are private and non-cloneable; fake authorization is type-incompatible.

A mutation target is the exact scoped `ProviderIdentity`, never a hostname,
tag, address, or request-supplied peer value. Complete desired tags are
replaced rather than merged implicitly. Credentials have explicit principal,
expiry, and use bounds; their plaintext may cross only the narrow delivery
boundary and must be absent from persistence, telemetry, errors, and audit
metadata. Invalidation refers to the exact credential ID, not a display name.

The provider contract offers no compare-and-swap (CAS) guarantee. A timeout, lost response, or
uncertain provider reply is `ambiguous`, not success and not a safe trigger for
blind retry; unsupported and rejected outcomes also remain distinct. Certainty
requires authoritative read-back where that is observable. The isolated proof
must leave no production provider mutation and cannot be used as evidence of
trusted membership, a Keryx binding or provenance, or Hermes Fleet activation.

## N4A invitation controls

The token selector is lookup-only and carries no authority. The 32-byte random
secret is verified with a randomly salted, fixed-profile Argon2id verifier.
Only the verifier and safe metadata persist. Invitation and provider secrets are
returned through consuming delivery wrappers and are excluded from formatting,
list/show views, audit metadata, SQLite text projections, and raw database/WAL
files as checked by the disposable acceptance harness.

SQLite transactions reserve a single-use invitation and create its join session
before provider dispatch. Cross-connection compare-and-swap predicates, not
process locks, enforce replay resistance. Role intent is typed, bounded, and
non-empty; administrative eligibility requires an explicit elevated-intent
record and still grants no trusted activation.

N4 correlation values are never persisted directly; SQLite receives only a
canonical SHA-256 digest. Base invitation/session identity, the one-use limit,
and confirmed-invalidation timestamps are protected by migration constraints
and direct-SQL triggers. State-level expiry preparation rejects pre-deadline
calls regardless of caller or current lifecycle state.

Provider creation is dispatched at most once. A potentially applied creation
whose plaintext response was lost becomes terminal and cannot be retried.
If creation confirms at the provider but local durable confirmation fails, the
service drops the secret, immediately attempts exact-reference invalidation
with fresh authority, and best-effort records ambiguity instead of returning an
ordinary availability error.
Invalidation uncertainty remains nonterminal because retrying exact-reference
cleanup cannot create another credential. Exact-reference terminal cleanup
requires confirmed or already-satisfied read-back evidence. A no-reference
ambiguous creation expires locally only at its bounded deadline and does not
claim provider invalidation evidence.

## N4B ingress controls

Invitation possession is the only redemption authentication factor and is not
device identity. The token is accepted only in a strict bounded JSON body over
verified TLS. URL, query, header, cookie, forwarded-address, hostname, and
caller-supplied audit/correlation transport is forbidden. Responses use fixed
small bodies, `no-store`, and no invitation or provider identifiers.

Monotonic per-source and global token buckets, a bounded source table, overflow
bucket, body cap, and bounded queue run before Argon2/provider work. Unknown
selectors perform dummy fixed-profile Argon2 work. A dedicated state-owning
worker bounds Argon2 and provider creation concurrency to one; this is resource
admission only. Cross-process single use still depends on SQLite transactions
and compare-and-swap transitions.

The successful bootstrap serializes directly from the consuming, redacted N4A
delivery wrapper and is not persisted, cloned, logged, or recoverable. Transport
loss never recreates a credential. An internal handoff is not accepted until the
HTTP handler has serialized it; request cancellation before that point closes an
acknowledgement channel and makes the worker revoke the exact credential. Worker
shutdown has an explicit deadline and join result rather than detached-thread
success. Provider failure classes do not become a
validity oracle. A provider node linked to an exact pre-auth ID is authenticated provider-registration evidence, not authenticated application/Keryx identity or trusted membership.

The disposable client proof forbids host networking, TUN, `NET_ADMIN`, host
Tailscale state/socket mounts, real devices, and production providers. Exact
credential revocation, exact node deletion, resource teardown, and sanitized
host-network equality are mandatory acceptance gates.

## N5 identity and trust controls

N5 does not reinterpret invitation possession as identity or trust. It requires one exact confirmed, active, unexpired N4 provider-native credential reference to match exactly one Headscale registration carrying `ProviderAuthenticatedRegistration` association strength, then re-reads the exact provider node and recomputes its machine-key fingerprint. Generic `Partial` associations, caller-assembled raw evidence, hostname, IP, timing proximity, online state, labels, and list cardinality remain non-authorizing.

Every confirmed logical device starts untrusted. A persisted one-time authorization action binds activate/revoke capability to exact authority generation, device, network, expected trust state/revision, principal, and a five-minute maximum lifetime. SQLite consumes it atomically with an append-only decision. Revocation is terminal in N5. Trust evaluates false whenever the exact provider binding is not active, even if historical logical trust state was trusted.

A raw machine key is never persisted by N5; only its canonical fingerprint is stored. Trust decisions contain bounded reason codes and safe correlation digests, not arbitrary text. Independent SQLite connections race durable revisions and uniqueness constraints rather than process locks. Full details are in [device-trust.md](device-trust.md).

## Out of scope after N5

N5 does not claim Keryx identity, transport authority, or Hermes Fleet authority. Keryx binding remains blocked until authenticated runtime provenance is supplied and owner-accepted. Fleet projection remains blocked until managed enrollment, exact grants, generations, reconciliation, provenance, and revocation have a language-neutral local control contract and acceptance tests.
