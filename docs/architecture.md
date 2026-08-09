# Nodescale Architecture

Nodescale is the device membership and trust control plane for Hermes Fleet.

The easiest way to understand it is to separate four questions:

```text
Headscale / Tailscale: Is this device on the private network?
Nodescale:             What device is this, and do we trust it?
Keryx:                 Which application peer is actually speaking?
Hermes Fleet:          What is this device allowed to do?
```

A "yes" at one layer does not automatically mean "yes" at the next layer.

## What Nodescale owns

Nodescale owns:

- managed network membership records;
- stable Nodescale `DeviceId` values;
- invitation and join-session state;
- provider observations and reconciliation;
- explicit device trust;
- Keryx identity-binding records;
- membership, binding, and projection generations;
- desired Hermes Fleet managed state;
- revocation and audit history.

Nodescale does not own Keryx transport state or Fleet scheduling state.

## What adjacent systems own

### Mesh provider

The mesh provider, currently Headscale with standard Tailscale clients, owns:

- network admission;
- reachability;
- provider-local node identity;
- tags and provider policy;
- mesh addresses.

A Headscale node is not automatically a trusted Nodescale device.

### Keryx

Keryx owns authenticated application peer identity and transport provenance.

Nodescale may bind a trusted `DeviceId` to an authenticated Keryx peer, but it never trusts a peer ID supplied by ordinary request JSON.

### Hermes Fleet

Fleet owns final application authority and coordination:

- local deny rules;
- allowed Fleet operations;
- readiness;
- future capacity and scheduling;
- Hermes execution authority.

Nodescale can project safe managed state into Fleet, but Fleet remains authoritative for what it actually stores and allows.

## Identity layers

Nodescale keeps three identities separate:

1. **Provider identity**: the device as the mesh provider knows it.
2. **Nodescale DeviceId**: the stable logical identity Nodescale creates.
3. **Keryx peer identity**: the authenticated application/runtime identity.

Hostnames, display names, IP addresses, tags, and caller-supplied peer IDs are observations. They are not substitutes for authoritative identity.

## Device lifecycle in plain English

The normal path is:

```text
invitation created
        ↓
device joins provider network
        ↓
Nodescale correlates the exact provider device
        ↓
Nodescale creates a DeviceId
        ↓
owner explicitly trusts the device
        ↓
Keryx proves the application peer identity
        ↓
Nodescale projects managed state into Fleet
```

Each step is durable and has its own generation or revision rules where needed.

## Provider discovery and reconciliation

Nodescale does not trust provider data blindly.

A reconciliation cycle roughly does this:

1. load the configured provider instance;
2. verify compatibility and health;
3. read the provider's current node view;
4. normalize provider-specific data;
5. reject conflicting canonical identities;
6. compare observations with durable Nodescale state;
7. classify changes, absence, expiry, or conflicts;
8. persist the new observation and audit information.

A provider outage is not treated as "all nodes were deleted." Nodescale keeps the last known state and fails closed where current evidence is required.

## Provider mutation boundary

Provider reads and provider writes are separate capabilities.

A mutation requires explicit Nodescale authority for that exact kind of operation. Examples include:

- create a bounded join credential;
- invalidate that credential;
- update the exact node's tags;
- expire or delete one exact node;
- update provider policy when the configured mode supports it.

A network response does not automatically prove that a provider mutation succeeded. Nodescale uses authoritative read-back when the provider supports it and preserves uncertainty when it cannot prove the final state.

## Invitations and join sessions

An invitation contains an opaque selector and random secret.

Nodescale stores a verifier rather than keeping the plaintext secret in normal durable state.

A successful redemption creates a durable join session before one-time provider bootstrap material is delivered.

The join credential is deliberately bounded by properties such as expiry, use count, principal, and approved tags.

Receiving join material proves only that the device may attempt to join. It does not prove trust or Fleet authorization.

## N5: device identity and explicit trust

N5 creates the stable logical `DeviceId` and separates identity from trust.

The important sequence is:

```text
exact provider evidence
→ DeviceId created
→ device starts untrusted
→ owner explicitly authorizes trust
```

Effective trust is provider-fresh. Durable state can remember that a device was logically trusted, but an affirmative "trusted right now" answer requires current provider evidence.

This prevents an old database snapshot from being treated as fresh proof that the provider binding still exists and still matches.

See [Device identity and trust](device-trust.md).

## N6: authenticated Keryx identity binding

N6 binds a trusted Nodescale `DeviceId` to an authenticated Keryx peer.

The key rule is:

> The authoritative Keryx peer comes from Keryx authentication context, not from a peer ID supplied by the caller.

Binding uses one-time challenge material, durable replay handling, exact generations, rotation, revocation, and provider-fresh checks.

N6 still does not grant Hermes Fleet execution authority.

See [N6 authenticated Keryx binding](n6-authenticated-keryx-binding.md).

## N7: managed Hermes Fleet projection

N7 connects Nodescale's trusted identity model to Hermes Fleet.

Nodescale persists the desired Fleet projection, sends it through the typed Fleet client, and then inspects Fleet's authoritative stored state.

```text
trusted DeviceId
+ active Keryx binding
        ↓
Nodescale desired projection
        ↓
Fleet managed-projection service
        ↓
Fleet-owned durable state
        ↓
Nodescale authoritative inspection
```

Important rules:

- projection generation advances independently from membership and Keryx binding generations;
- exact replay may be idempotent;
- stale, conflicting, skipped, or regressed generations fail closed;
- response loss is recovered by inspection before reapplying blindly;
- local Fleet deny remains authoritative;
- generated Fleet authority is limited to the accepted baseline operations;
- no N7 projection automatically grants `fleet.hermes.run`.

See [N7 authenticated Fleet projection](n7-authenticated-fleet-projection.md).

## Generations

Different parts of the system change independently, so Nodescale does not use one giant version number.

Examples include:

- membership generation;
- device credential generation;
- Keryx binding generation;
- Fleet projection generation.

Older generations cannot silently overwrite newer state. Reusing the same generation with different content is a conflict.

## Revocation

Application authority is removed before relying on slower network cleanup.

A simplified ordering is:

```text
revocation requested
→ Fleet authority/scheduling removed or disabled
→ Keryx binding disabled
→ Nodescale device authority revoked
→ provider cleanup
→ durable revoked state retained
```

If the provider is temporarily unavailable, application trust should still fail closed.

Historical identity and audit records are kept for recovery and incident analysis.

## State ownership

Nodescale owns its own SQLite database.

It does not read or write:

- Headscale's internal database;
- Keryx's database;
- Hermes Fleet's database.

Integration happens through supported provider APIs, Keryx authenticated control surfaces, and the Fleet local-control contract.

## Deliberate non-goals

Nodescale does not currently try to provide:

- distributed consensus;
- workload scheduling;
- GPU placement;
- Hermes profile deployment;
- direct Hermes execution;
- a shared cross-product database;
- trust based on hostname or mesh address;
- protection from an attacker who already controls the trusted Nodescale process or can arbitrarily replace its database.

Those boundaries keep the trust model understandable and stop network membership from turning into unlimited application authority.
