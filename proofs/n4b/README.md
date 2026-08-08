# N4B disposable join proof

`run.py` is the retained acceptance harness for the N4B production path against disposable infrastructure only. A source-tree review establishes that the harness exists; completion requires a successful invocation bound to the exact candidate Git tree and retention of its secret-free JSON evidence outside the candidate tree.

For the required exact-tree run, the harness:

1. requires `NODESCALE_N4B_TREE` and verifies that its ambient runner and image lock equal those Git-tree blobs;
2. extracts that tree with `git archive` and compiles the ignored production proof binary with `cargo --locked` into the disposable runtime root;
3. creates a dedicated Docker bridge and Headscale v0.29.3 container;
4. runs those exact proof bytes in a pinned Debian 13 container on that bridge;
5. starts the production redemption router, supervised state worker, `InvitationService`, and Headscale mutation adapter over verified TLS without a host listener;
6. sends concurrent redemption requests from two isolated source containers and requires exactly one success;
7. requires replay rejection after admission refill;
8. starts Tailscale v1.98.10 in userspace mode with no capabilities, TUN device, host network, host state, or host socket;
9. correlates the authoritative Headscale node's pre-auth ID with the durable provider credential reference;
10. stops the client, revokes the exact credential, deletes the exact node, and verifies zero provider nodes;
11. traps TERM/INT, terminates and reaps tracked subprocess groups, removes exact nonce-owned containers, bridge, extracted source, Cargo target, secrets, and the mode-0700 `/var/tmp` runtime root, then scans the full proof prefix and requires repository, `Cargo.lock`, and sanitized host-network invariants to equal their pre-proof values.

Headscale, Tailscale, and the ingress runtime are digest-pinned `linux/amd64` images in `images.lock`. The runner passes `--platform linux/amd64` and verifies each pulled image's OS/architecture. Pulled digest-pinned images are intentionally retained as Docker cache and are reported separately; “zero runtime residue” does not claim image removal. The harness does not activate a Nodescale device, Keryx, Fleet, or Hermes.

Run from the repository root after constructing the immutable candidate tree:

```bash
PATH="$HOME/.cargo/bin:$PATH" RUSTFLAGS='-C link-arg=-fuse-ld=bfd' \
  NODESCALE_N4B_TREE='<candidate-tree-id>' \
  python3 proofs/n4b/run.py >'/tmp/nodescale-n4b-evidence-<candidate-tree-id>.json'
```

The runner fails closed if any `nodescale-n4b-proof-*` container, network, or `/var/tmp` runtime root already exists or teardown leaves one behind. Every resource it creates has a fresh cryptographic per-run nonce, and cleanup targets only those exact owned names. Invitation, provider, and TLS private keys exist only inside a mode-0700 temporary root. On success the one-line evidence manifest identifies the exact candidate tree, locked/external build inputs, platform, image digests, lifecycle outcomes, cleanup result, and host/repository invariants without containing secrets.
