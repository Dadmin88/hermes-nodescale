# Threat Model

Nodescale is designed around explicit trust boundaries and fail-closed transitions. The primary security concern is preventing weak provider or caller-controlled evidence from becoming trusted device identity or Hermes Fleet authority.

## Protected properties

Nodescale aims to preserve the following properties:

- hostname, mesh address, tag, role, or self-reported peer identifier cannot become authoritative identity;
- provider admission cannot become Hermes Fleet authorization by implication;
- Nodescale roles do not automatically grant exact Hermes Fleet operations;
- unknown, unreachable, unsupported, or authentication-failed providers cannot authorize mutation;
- stale generations cannot overwrite newer state;
- required state changes and audit evidence commit atomically where they form one security decision;
- invitation plaintext and provider/device credentials do not enter ordinary domain records or audit metadata;
- ambiguous provider outcomes are not promoted to success;
- revocation removes application trust without depending on successful provider cleanup.

## Trust boundaries

Nodescale interacts with several independent authorities:

- the mesh provider controls mesh admission and provider-local node state;
- Nodescale controls managed membership and Nodescale device state;
- Keryx controls authenticated transport peer identity;
- Hermes Fleet controls final application authorization and execution.

Compromise or spoofing in one layer must not silently grant authority owned by another layer.

## Secret-bearing values

Invitation plaintext, provider API keys, provider join credentials, device credentials, and binding nonces use redacted wrappers or narrow delivery types.

Secret-bearing values must not be exposed through ordinary `Debug` or `Display`, persisted in audit metadata, or copied into diagnostics.

SQLite stores invitation verifiers and opaque credential references rather than plaintext invitation or provider credentials.

Operator-managed secret files are expected to use restrictive filesystem permissions. Nodescale does not currently provide a general-purpose secrets vault.

## Audit safety

Audit events may record identifiers, UTC timestamps, bounded actor/source data, event kind, outcome, generations, and sanitized structured metadata.

Metadata that appears to contain secrets, tokens, passwords, credentials, API keys, private keys, or nonces must be rejected or redacted. Audit records must never contain credential values or private key material.

## Provider transport controls

The Headscale adapter accepts only clean HTTPS origins and uses normal certificate and hostname verification. Redirects are disabled so bearer credentials cannot be forwarded to another origin.

Connections and responses are bounded by time and size. Provider authentication material is redacted from errors and formatting.

An optional custom root extends trust rather than disabling verification and is subject to size and certificate constraints.

Provider output remains untrusted until normalized. Hostnames, addresses, tags, user metadata, and pre-auth associations cannot become complete device identity.

## Provider mutation controls

Mutation uses a separate capability-scoped interface. Read-only provider configuration cannot issue mutation authority.

Each authorized mutation is bound to exact provider configuration and an exact operation. A compatible server or administrator role does not broaden the allowed capability set.

Mutation targets use the full scoped provider identity rather than mutable display metadata.

Provider join credentials have explicit principal, expiry, and use bounds. Their plaintext may cross only the one-time delivery boundary.

The provider contract does not assume compare-and-swap. Rejected, unsupported, and ambiguous outcomes remain distinct, and authoritative read-back is required where available.

An ambiguous credential creation is never treated as a usable credential and is never blindly retried.

## Invitation controls

Invitation selectors are lookup-only and carry no authorization claims. The random secret is verified using a salted fixed-profile Argon2id verifier.

Only the verifier and safe invitation metadata persist.

A successful redemption atomically reserves the invitation and creates the join session before provider dispatch. Cross-connection SQLite predicates, not process-local locks, enforce single-use behavior.

Role eligibility is typed and bounded. Administrative eligibility requires explicit elevated intent and still does not grant trusted activation.

Correlation values are stored as canonical digests rather than caller plaintext where direct persistence is unnecessary.

## Redemption ingress controls

Invitation possession is the only redemption factor accepted by the HTTP ingress. It proves possession of a capability, not device identity.

The token is accepted only in a strict bounded JSON body over verified TLS. Tokens and caller-controlled identity claims are not accepted through URLs, query strings, cookies, forwarded headers, hostnames, or audit fields.

Resource admission occurs before expensive verification and provider work using bounded per-source and global controls, a bounded source table, request-body limit, and bounded queue.

Unknown selectors receive fixed-profile dummy Argon2 work after admission to reduce invitation-state oracle differences.

The state-owning worker bounds expensive work, but SQLite remains authoritative for cross-process replay safety.

Successful bootstrap material is not persisted or recoverable. Cancellation before the HTTP handoff is completed triggers exact credential cleanup rather than abandoning an active secret.

## Revocation and cleanup

Application trust is removed before provider cleanup is relied upon. A provider outage may leave stale mesh state temporarily, but it must not preserve generated Hermes Fleet authority.

Exact provider cleanup remains retryable and is tracked separately from application-trust revocation.

Disposable acceptance tooling must avoid production providers and real devices, and it must restore runtime, listener, repository, and host-network invariants after completion.

## N5 identity and trust controls

N5's state-owned confirmation path rejects caller-assembled raw identity persistence. It requires exact active/unexpired N4 provenance, one provider-authenticated registration association, exact provider re-read, and matching machine-key fingerprint. Zero/multiple matches, cross-session swaps, duplicate machine keys, expiry, and drift fail closed. The generated logical `DeviceId`, provider binding, and trust state remain separate.

A one-time local bootstrap returns an opaque `nstrust_` 256-bit capability; only a fixed-profile Argon2id verifier persists. The active root gates sealed authority capabilities and one-shot revision-fenced actions. Root or authority revocation invalidates future issuance; root revocation also disables linked authorities and unconsumed actions. Decisions and N5 audit events are immutable. Effective trust is false without an active exact binding, and provider reconciliation returns no trusted result on transient read failure.

## Trust not yet established by this repository

N5 Nodescale trust is implemented, but the repository does not claim that provider admission or N5 trust establishes:

- authenticated Keryx sender identity;
- a verified Keryx binding;
- managed Hermes Fleet enrollment or grants;
- Hermes Fleet scheduling or execution permission.

Those remaining trust transitions require their own authenticated evidence and integration contracts.
