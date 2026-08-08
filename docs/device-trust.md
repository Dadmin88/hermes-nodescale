# Authoritative device identity and explicit trust

Nodescale N5 turns the narrow N4 join correlation into a durable logical device identity and a separate, auditable trust decision.

The governing invariant is:

> Headscale membership does not imply Nodescale trust.

An invitation, a successfully redeemed provider credential, a Headscale registration, or possession of the registration's Tailscale machine key cannot activate trust. Identity answers which logical Nodescale device a registration represents. Trust answers whether Nodescale authority has explicitly approved that device.

## Logical device identity

`DeviceId` is a Nodescale-generated UUID. It is opaque, immutable, and independent of:

- hostname or given name;
- source, provider, or Tailscale-assigned IP address;
- Headscale numeric node ID;
- provider credential plaintext;
- registration time or observation order;
- mutable labels, roles, tags, online state, or user-agent data.

The existing `devices` row remains the logical device root. N5 adds a separate identity row and provider-binding row. It does not turn the legacy `membership_state` field into trust.

## Authoritative N4-to-N5 correlation

N5 identity confirmation starts from an N4 join session whose provider credential creation is durably confirmed and still active. `DeviceIdentityService` reads the configured provider and requires exactly one non-expired provider node satisfying all of these conditions:

1. the provider instance equals the join session's configured provider;
2. the node's pre-auth credential identifier exactly equals the confirmed provider-native credential reference for that join session;
3. the Headscale adapter supplies a stable machine-key fingerprint;
4. recomputing SHA-256 over the adapter's machine-key evidence yields that exact fingerprint.

The state-owned confirmation operation performs provider selection and exact `get_node` re-read itself; callers cannot submit raw identity evidence directly. Zero matches means identity remains unidentified. More than one exact match is ambiguous and fails closed. Hostname, address, nearest timestamp, list cardinality, online state, labels, and “only new node” are never substitutes.

The N4 credential's single-use and exact-reference properties make the pre-auth association authoritative for this registration. The Tailscale machine key is client-generated possession evidence already verified by the Headscale registration protocol. N5 therefore does not add a second keypair, challenge endpoint, CA, or certificate flow. The machine-key fingerprint is binding evidence, not the logical device ID and not trust authority.

## Logical device versus provider binding

A logical device and a provider registration have separate lifetimes. The binding records:

- logical `DeviceId`;
- origin N4 join session;
- internal Nodescale credential UUID;
- provider-native credential reference;
- provider instance and provider node ID;
- machine-key fingerprint;
- binding state and revision.

SQLite permits at most one active binding for a logical device, provider node, or machine-key fingerprint. Binding identity columns are immutable. Binding state moves forward only:

`active -> stale | cleanup_pending`, `stale -> cleanup_pending | removed`, and `cleanup_pending -> removed`.

The production service implements all of those transitions with revision fencing and durable audit. Its provider-backed reconciliation re-reads the exact node: authoritative absence, credential-association drift, expiry, or machine-key drift marks the binding stale; transient provider errors return an error and never a trusted result.

A stale, cleanup-pending, or removed binding never counts as an active trusted transport identity.

N5 does not implement automatic replacement. A new registration cannot inherit a trusted device by copying hostname, IP, labels, or metadata. Machine-key replacement and reinstall recovery require a later explicitly authenticated and approved flow. Until then, a replacement is a new logical device requiring new trust approval. Marking an old binding stale makes effective trust false without erasing trust history.

## Identity and trust lifecycle

The durable states remain separate:

- a successful N4 join with no N5 identity row is joined but unidentified;
- an N5 identity row with an active binding is identity-confirmed;
- every newly confirmed device starts `untrusted`;
- explicit authority may transition `untrusted -> trusted`;
- explicit authority may transition `untrusted | trusted -> revoked`;
- `revoked` is terminal in N5;
- binding staleness and provider cleanup remain independent of logical trust state.

N5 does not use one boolean for lifecycle. The typed query returns the logical trust state, trust revision, binding state, binding revision, and `currently_trusted`. `currently_trusted` is true only when logical state is `trusted` and the exact provider binding is `active`.

## Trust authority

Trust authority begins with an explicit local-owner bootstrap. It generates one opaque `nstrust_` 256-bit capability per network, returns plaintext once, persists only its fixed-profile Argon2id verifier, and redacts the token from `Debug`/`Display`. `DeviceTrustAuthorityAdminIntent::explicit()` is required only for that first local bootstrap; it is not itself authority.

Configuring, revoking, or issuing actions through a trust authority requires proof of the active owner-root capability. Revoking the owner root atomically disables every linked authority and makes all unconsumed actions unusable. Authorities are created unsealed, receive their closed capability set in one transaction, then seal and enable atomically; capabilities cannot be added, updated, or deleted after sealing. The authenticated root principal is used for configuration/issuance/revocation audit attribution. A configured authority has:

- exact network scope;
- normalized principal source and principal ID;
- monotonic generation;
- not-before and expiry bounds;
- explicit `ActivateDeviceTrust` and/or `RevokeDeviceTrust` capabilities.

Activation or revocation first issues a durable, one-time authorization action bound to the exact authority generation, device, network, expected trust state, expected revision, capability, principal, and a maximum five-minute lifetime. Applying the decision consumes that action atomically. Stale, expired, revoked, wrong-capability, wrong-device, or wrong-revision actions fail closed.

Invitation roles do not configure or issue trust authority. In particular, `Role::Admin` eligibility never activates trust.

## Trust decisions and history

Trust decisions are append-only and record bounded safe metadata:

- decision and action IDs;
- exact device and network;
- prior and new trust state;
- decision kind and timestamp;
- prior and new revision;
- authority ID and generation;
- normalized principal source and ID;
- bounded reason code;
- safe SHA-256 correlation digest.

SQLite triggers reject updates or deletes of decisions and authorizations. A trust-state update must correspond to the exact already-inserted decision, and decision insertion validates and consumes the exact unexpired authorization action. Activation requires an active provider binding. Revocation remains valid even when provider cleanup is pending.

No invitation plaintext, provider credential plaintext, device private key, arbitrary operator text, raw machine key, or signed challenge is persisted by N5.

## Concurrency and replay

Correctness uses SQLite `BEGIN IMMEDIATE` transactions and durable uniqueness/revision fences across independent connections. Process-local mutexes are not authoritative.

- two confirmations for one exact join session create one device; an exact replay returns the same device;
- substituted evidence after confirmation is rejected;
- one provider node, active machine key, or join session cannot create two active logical identities;
- concurrent trust actions against one revision allow one durable transition;
- the losing action becomes stale and cannot be replayed;
- direct trust-state or history rewriting is rejected by SQLite triggers;
- revocation is terminal and activation after revocation is rejected.

Provider read failure, zero observation, ambiguous observation, evidence mismatch, stale authorization, and infrastructure failure leave the device non-trusted. N5 never guesses identity or trust.

## N5 to N6 boundary

`nodescale-device-trust` exposes the internal authoritative service and structured trust query. N6 may consume that API, but N5 creates no:

- Keryx peer binding or transport;
- Fleet enrollment, registry entry, or grant;
- Hermes activation or run;
- scheduling, workload placement, telemetry, profile provisioning, or dashboard surface.

The N5 disposable proof ends with zero trusted devices, zero provider nodes, zero Keryx bindings, zero Fleet enrollments/grants, and zero Hermes activations. A revoked logical device may remain in the disposable database to prove that provider cleanup and trust history are separate lifetimes; the entire database is then destroyed with the proof runtime root.
