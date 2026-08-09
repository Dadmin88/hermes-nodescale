# Nodescale Documentation

These documents describe the current Nodescale product and its trust boundaries.

If you are new to the project, start with the architecture and identity pages. The more detailed protocol documents are useful after the basic model makes sense.

## Start here

1. [Architecture](architecture.md) - how Nodescale fits between the private mesh, Keryx, and Hermes Fleet.
2. [Identity model](identity-model.md) - why provider identity, Nodescale DeviceId, and Keryx peer identity are separate.
3. [Threat model](threat-model.md) - what Nodescale protects, what it deliberately does not protect, and where it fails closed.

## Joining and trusting a device

- [Invitations and redemption](invitations.md) - how a device receives short-lived join material without exposing provider administration credentials.
- [Device identity and trust](device-trust.md) - how Nodescale confirms the exact device and requires explicit owner trust.
- [N6 authenticated Keryx binding](n6-authenticated-keryx-binding.md) - how a trusted device is bound to an authenticated application peer.
- [N7 authenticated Fleet projection](n7-authenticated-fleet-projection.md) - how a trusted, Keryx-bound device is projected into Hermes Fleet with safe baseline authority.

The simple flow is:

```text
join mesh
→ identify exact device
→ explicit trust
→ authenticate Keryx peer
→ project managed state into Fleet
```

Each arrow is a separate trust boundary. Finishing one step does not automatically grant the next one.

## Provider integration

- [Provider contract](provider-contract.md) - the provider-neutral read and mutation interfaces.
- [Headscale compatibility](headscale-compatibility.md) - the supported Headscale behavior and HTTP/TLS requirements.
- [Discovery and reconciliation](discovery-reconciliation.md) - how Nodescale compares provider state with its own durable records.

## Development

- [Development](development.md) - build, test, lint, and acceptance-test guidance.
- [Architecture decision records](adr/) - durable design decisions and rejected alternatives.

## Documentation rules

Public reference documentation should explain current behavior in plain technical English.

Keep temporary checkpoint hashes, owner handoff notes, private machine names, private paths, secret material, and internal evidence out of public reference docs unless they are genuinely required to explain a public contract.

Implementation history belongs in pull requests, commit history, issues, or release notes. Reference docs should answer what the system does now and why its boundaries exist.
