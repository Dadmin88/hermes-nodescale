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

Headscale output remains untrusted. Required provider node ID and machine-key evidence are validated before normalization. Hostnames and addresses cannot become identity. Pre-auth-key secrets are not modeled or retained; only the provider credential ID relationship is exposed as partial correlation evidence. The doctor report is sanitized and hard-codes mutation as disabled.

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

## Out of scope after N3A

N3A does not claim network, Keryx, or Hermes Fleet trust. The future Keryx binding operation remains blocked until authoritative sender identity is supplied by authenticated runtime provenance. The future Fleet projection remains blocked until managed enrollment, exact grants, generations, reconciliation, provenance, and revocation have a language-neutral local control contract and acceptance tests. Invitations, device joining, and live migration require separate owner authorization.
