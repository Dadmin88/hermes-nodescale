# Identity Model

Nodescale keeps provider, Nodescale, and Keryx identity separate by design. They may be correlated through verified evidence, but they are never interchangeable.

## Identity authorities

1. **Provider device identity** — established by the provider's canonical node record and the strongest stable provider key evidence available through the supported interface.
2. **Nodescale device identity** — established by Nodescale's typed device ID, authenticated join-session state, device credential, and credential generation.
3. **Keryx peer identity** — established only by authenticated Keryx runtime or session provenance.

A durable binding can relate these identities. Display names, hostnames, mesh addresses, tags, and request-body peer identifiers are never authoritative identity.

## Headscale provider identity

For the supported Headscale integration, the strongest scoped provider identity combines:

- the configured provider instance;
- the canonical positive numeric Headscale node ID;
- a SHA-256 fingerprint of the machine key.

The node ID is canonical only within its provider instance. The machine key is strong but replaceable correlation evidence, so an unexpected fingerprint change is treated as a conflict or rotation observation rather than an automatic identity replacement.

Other Headscale fields remain observations:

- node and disco keys are mutable cryptographic observations;
- user identity and pre-auth credential association are conditional correlation evidence;
- hostname and given name are presentation metadata;
- IP addresses are addressing metadata;
- tags, online state, timestamps, and expiry are mutable policy or operational metadata.

None of those fields can substitute for the scoped provider identity.

## Nodescale device identity and N5 trust

A provider join does not create trusted Nodescale identity by itself. N5 creates a logical device only through the state-owned confirmation operation: exact active/unexpired N4 provenance, one `ProviderAuthenticatedRegistration`, exact provider re-read, and matching machine-key fingerprint. Nodescale generates the opaque immutable UUID `DeviceId`; provider IDs, hostnames, addresses, labels, and machine keys never become that logical ID.

Logical identity, provider binding, and trust are separate durable records. Confirmation creates an active binding and starts the device untrusted. An opaque verifier-backed local-owner root gates sealed trust authorities and revision-fenced one-shot activation/revocation decisions. Effective trust also requires an active exact binding; provider drift or cleanup makes current trust false without rewriting historical decisions. Root revocation disables linked authorities and unconsumed actions. See [Device Identity and Trust](device-trust.md).

Credential, trust, provider-binding, and membership generations are independent. Rotation or cleanup advances the relevant revision without rewriting historical identity.

## Keryx binding

A verified Keryx binding must come from authenticated runtime provenance. A caller-supplied peer identifier is not sufficient.

The intended binding contract relates a Nodescale network, device, join session, one-time nonce, and authoritative Keryx sender identity. Replay and conflict handling must be explicit, and binding rotation must advance its own generation.

Until that provenance contract is available and verified, a Nodescale device must not be promoted to trusted application identity merely because provider admission succeeded.

## Roles and application grants

Nodescale roles are descriptive membership metadata:

- `node`
- `worker`
- `controller`
- `profile_host`
- `observer`
- `admin`

Hermes Fleet operations are separate authorization values, such as:

- `fleet.health`
- `fleet.inventory`
- `fleet.message`
- `fleet.hermes.run`

No role automatically grants an operation. In particular, Nodescale membership does not automatically grant `fleet.hermes.run`.

## Provider mutation and identity

Provider mutation can create or update provider-side objects, but it cannot establish Nodescale or Keryx identity.

- Ensuring a provider principal does not create a Nodescale device.
- Creating a provider join credential proves only that a bounded admission capability was issued.
- A pre-auth credential association proves use of that provider capability, not complete device identity.
- Tags remain provider policy metadata, not Hermes Fleet grants.
- Exact node mutation must target the full scoped `ProviderIdentity`, never a hostname, address, tag, or user label.

When provider outcomes are uncertain, ambiguity remains explicit. Identity-bound state is not promoted on the basis of a transport acknowledgement alone.
