# N6 disposable authenticated Keryx-binding proof

`run.py` is an **exact-tree, disposable proof envelope**, not an implementation
of Keryx, Fleet, or Hermes activation. It intentionally fails closed until the
candidate tree contains the real N6 integration proof.

## Exact selector contract

The archive must contain **exactly one** ignored Rust integration-test function
named:

```rust
#[tokio::test]
#[ignore]
async fn disposable_authenticated_keryx_binding_is_durable_and_cleans_up() { /* … */ }
```

The selector must be in a crate `tests/<target>.rs` target, consume all three
proof-only inputs below, and run successfully as exactly one targeted test:

- `NODESCALE_N6_PROOF_READY_MARKER`
- `NODESCALE_N6_PROOF_SECRET_SENTINEL_A`
- `NODESCALE_N6_PROOF_SECRET_SENTINEL_B`

The envelope resolves that selector from the archived source, derives its
package and test target, and runs only:

```text
cargo test --locked --offline --package <package> --test <target> \
  disposable_authenticated_keryx_binding_is_durable_and_cleans_up \
  -- --ignored --exact --nocapture --test-threads=1
```

A missing, non-ignored, ambiguous, non-integration, or zero-executed selector
therefore cannot produce a successful manifest. A name match elsewhere in the
workspace is not enough.

## Test-owned readiness and state discipline

The test receives a fresh nonce-qualified prefix, a mode-0700 private runtime
root, private Cargo target directory, and opaque secret sentinels. It must put
all durable test state under `NODESCALE_N6_PROOF_ROOT`, use the supplied prefix
for owned resource names, and emit this bounded secret-free JSON file **only
after** its SQLite state, authenticated listener(s), registered destination
handler, and any owned child/listener resources exist:

```json
{
  "owned_endpoints":[{"address":"127.0.0.1","port":12345,"transport":"tcp"}],
  "phase":"owned",
  "prefix":"<NODESCALE_N6_PROOF_PREFIX>"
}
```

`::1` is also accepted. At least one loopback TCP endpoint is required. The
runner rejects extra keys, malformed values, non-loopback addresses, duplicate
endpoints, or an unready/early-exiting test. It scans every regular artifact in
the private root—including SQLite DB/WAL/SHM files, logs, reports, and Cargo
artifacts—for both secret sentinels before deletion. No sentinel value or path
is placed in the JSON evidence.

For a committed candidate tree, the runner:

1. requires `NODESCALE_N6_TREE`, verifies its own bytes against that exact tree,
   archives the tree, and compiles only from archive bytes with locked offline
   Cargo resolution;
2. rejects preexisting resources across the full `nodescale-n6-proof-*`
   container, network, and `/var/tmp` runtime-root namespace;
3. starts the exact test in its own process group, waits for test-owned
   readiness, and only then releases the outer interruption marker;
4. masks further `TERM`/`INT` during teardown, reaps every tracked process group
   before deleting only this run's nonce-qualified Docker resources and runtime
   root; and
5. independently scans full-prefix residue, dynamic listeners, repository
   status, and `Cargo.lock` after cleanup before emitting one deterministic,
   sanitized JSON manifest. There are no intentional runtime-residue exceptions.

Run only after constructing an immutable candidate tree that includes these
proof files and the selector:

```bash
PATH="$HOME/.cargo/bin:$PATH" \
  NODESCALE_N6_TREE='<candidate-tree-id>' \
  python3 proofs/n6/run.py \
  >'/tmp/nodescale-n6-evidence-<candidate-tree-id>.json'
```

## Separate TERM acceptance

`verify_interruption.py` is a separate secret-free interruption manifest. It
binds **both** the wrapper and runner bytes to `NODESCALE_N6_TREE`, waits for
the test-owned readiness propagated by the runner, records the dynamic owned
endpoints, and sends `SIGTERM` to the runner's process group. It requires a
nonzero child exit, no success manifest, a child-reported signal and completed
cleanup, zero full-prefix residue, closed owned endpoints, and unchanged
repository/lockfile invariants.

If the child misses the TERM deadline, the wrapper sends `SIGKILL` to the same
process group, waits again to reap it, records the timeout as an acceptance
failure, and still runs every postflight gate. It never treats a timeout as a
reason to skip residue or invariant collection.

```bash
PATH="$HOME/.cargo/bin:$PATH" \
  NODESCALE_N6_TREE='<candidate-tree-id>' \
  python3 proofs/n6/verify_interruption.py \
  >'/tmp/nodescale-n6-interruption-<candidate-tree-id>.json'
```

The image cache is not used by this envelope, so `intentional_residue_exception`
is `none`. Keep both sanitized manifests outside the candidate tree and bind
release acceptance to the exact tree reported by each successful manifest.
