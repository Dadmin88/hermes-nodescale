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

The real adapter accepts only a clean HTTPS origin, uses normal certificate verification, disables redirects, sends bearer authentication only to the configured origin, bounds connection/request time and response bytes, and exposes typed sanitized errors. The production constructor has no insecure-TLS switch. The adapter implements a read-only trait with no mutation methods and issues only documented `GET` requests.

Headscale output remains untrusted. Required provider node ID and machine-key evidence are validated before normalization. Hostnames and addresses cannot become identity. Pre-auth-key secrets are not modeled or retained; only the provider credential ID relationship is exposed as partial correlation evidence. The doctor report is sanitized and hard-codes mutation as disabled.

## Out of scope after N1A

N1A does not claim network, Keryx, or Hermes Fleet trust. The future Keryx binding operation remains blocked until authoritative sender identity is supplied by authenticated runtime provenance. The future Fleet projection remains blocked until managed enrollment, exact grants, generations, reconciliation, provenance, and revocation have a language-neutral local control contract and acceptance tests. Provider mutation, invitations, device joining, and live migration require separate owner authorization.
