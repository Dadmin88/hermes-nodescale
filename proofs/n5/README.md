# N5 disposable join proof

`run.py` is the retained acceptance harness for the N5 production path against disposable infrastructure only. A source-tree review establishes that the harness exists; completion requires a successful invocation bound to the exact candidate Git tree and retention of its secret-free JSON evidence outside the candidate tree.

For the required exact-tree run, the harness:

1. requires `NODESCALE_N5_TREE` and verifies that its ambient runner and image lock equal those Git-tree blobs;
2. extracts that tree with `git archive` and compiles the ignored production proof binary with `cargo --locked` into the disposable runtime root;
3. creates a dedicated Docker bridge and Headscale v0.29.3 container;
4. runs those exact proof bytes in a pinned Debian 13 container on that bridge;
5. starts the production redemption router, supervised state worker, `InvitationService`, and Headscale mutation adapter over verified TLS inside the proof network; ingress has no host-published port, while Headscale runner control is restricted to loopback `127.0.0.1:18443`;
6. sends concurrent redemption requests from two isolated source containers and requires exactly one success;
7. requires replay rejection after admission refill;
8. starts Tailscale v1.98.10 in userspace mode with no capabilities, TUN device, host network, host state, or host socket;
9. correlates the authoritative Headscale node's exact pre-auth credential reference and machine-key fingerprint with a Nodescale-generated logical `DeviceId`;
10. proves the identity-confirmed device is untrusted, executes a typed authorized activation, proves exact-device trust, executes explicit revocation, and proves the device is no longer trusted;
11. stops the client, revokes the exact credential, deletes the exact node, marks the provider binding stale, and verifies zero provider nodes and zero trusted devices;
12. proves the persisted Keryx binding count remains zero; exact-tree source review separately establishes that N5 contains no Fleet enrollment/grant or Hermes activation surface;
13. traps TERM/INT, terminates and reaps tracked subprocess groups, removes exact nonce-owned containers, bridge, extracted source, Cargo target, secrets, and the mode-0700 `/var/tmp` runtime root, then scans the full proof prefix and requires repository, `Cargo.lock`, and sanitized host-network invariants to equal their pre-proof values.

Headscale, Tailscale, and the ingress runtime are digest-pinned `linux/amd64` images in `images.lock`. The runner passes `--platform linux/amd64` and verifies each pulled image's OS/architecture. Pulled digest-pinned images are intentionally retained as Docker cache and are reported separately; “zero runtime residue” does not claim image removal. The harness activates trust only in its disposable SQLite database and revokes it before cleanup. It does not activate Keryx, Fleet, or Hermes.

Run from the repository root after constructing the immutable candidate tree:

```bash
PATH="$HOME/.cargo/bin:$PATH" RUSTFLAGS='-C link-arg=-fuse-ld=bfd' \
  NODESCALE_N5_TREE='<candidate-tree-id>' \
  python3 proofs/n5/run.py >'/tmp/nodescale-n5-evidence-<candidate-tree-id>.json'
```

Retain the deliberate-interruption acceptance result separately. Before loading or executing the proof runner, this wrapper resolves `NODESCALE_N5_TREE` and requires its own bytes to match `proofs/n5/verify_interruption.py` from that exact tree. It then waits for the runner's initialization marker, sends TERM, requires the child to fail without a success manifest, and independently verifies full-prefix residue, proof ports, repository status, `Cargo.lock`, and sanitized host-network state before emitting JSON. If the child does not exit within the TERM deadline, the wrapper kills and synchronously reaps it, still runs every postflight gate, and then fails the acceptance result:

```bash
PATH="$HOME/.cargo/bin:$PATH" RUSTFLAGS='-C link-arg=-fuse-ld=bfd' \
  NODESCALE_N5_TREE='<candidate-tree-id>' \
  python3 proofs/n5/verify_interruption.py \
  >'/tmp/nodescale-n5-interruption-<candidate-tree-id>.json'
```

The runner fails closed if any `nodescale-n5-proof-*` container, network, or `/var/tmp` runtime root already exists or teardown leaves one behind. Every resource it creates has a fresh cryptographic per-run nonce, and cleanup targets only those exact owned names. Invitation, provider, and TLS private keys exist only inside a mode-0700 temporary root. On success the one-line evidence manifest identifies the exact candidate tree, locked/external build inputs, platform, image digests, lifecycle outcomes, cleanup result, and host/repository invariants without containing secrets.
