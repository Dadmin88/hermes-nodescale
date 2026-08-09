# N7 exact-tree authenticated Fleet-projection proof

**Status:** Runner and selector implemented; **release acceptance pending**. No
normal or interruption manifest for an exact archived execution has been
accepted, and this document makes no activation claim.
**License:** AGPL-3.0-only

This directory defines the executable, disposable two-repository acceptance
envelope for selected N7 V1. The current runner is `run.py`; its sole selector
is `crates/nodescale-projection/tests/disposable_n7.rs`::
`disposable_authenticated_fleet_projection_is_durable_and_cleans_up`.
Documentation, unit tests, a live checkout, a direct Cargo invocation, or a
one-repository run are not acceptance evidence. The runner and selector being
present does not relax the requirement for exact archived execution.

N7 does not reopen N6. N6-derived binding provenance may be an input to the
Nodescale side of the exercise; it is not a Fleet credential, enrollment,
generated grant, or activation result.

## Exact candidate inputs

Every normal or interruption invocation requires all three inputs before it
creates a resource:

- `NODESCALE_N7_TREE`: resolved immutable Nodescale candidate tree;
- `FLEET_N7_REPOSITORY`: independently checked-out Fleet repository; and
- `FLEET_N7_TREE`: resolved immutable Fleet candidate tree in that repository.

The runner binds its own bytes to `NODESCALE_N7_TREE`, binds every Fleet
harness/adapter byte it invokes to `FLEET_N7_TREE`, and uses `git archive` to
place both trees in separate nonce-qualified mode-0700 private roots. Build and
execution use only archive bytes. A matching commit, current-worktree import,
previous artifact, or Fleet harness from outside `FLEET_N7_TREE` is not proof.

The sanitized normal and interruption manifests must name the identical
Nodescale/Fleet tree pair. The runner preserves and verifies unchanged
source-worktree status fingerprints plus the Nodescale `Cargo.lock` and Fleet
`pyproject.toml` digests for both repositories.

## Exact selected-V1 exercise

The archived Nodescale tree must contain exactly one ignored Rust integration
selector: `disposable_authenticated_fleet_projection_is_durable_and_cleans_up`
in `crates/nodescale-projection/tests/disposable_n7.rs`, package
`nodescale-projection`. The runner rejects a missing, non-ignored, ambiguous,
non-integration, or zero-executed selector. Its only Cargo execution is the
narrow command shape:

```text
cargo test --locked --offline --package nodescale-projection --test disposable_n7 \
  disposable_authenticated_fleet_projection_is_durable_and_cleans_up -- \
  --ignored --exact --nocapture --test-threads=1
```

There is no workspace fallback. `--locked --offline`, `--ignored --exact`, and
single-threaded execution are mandatory; a manually run form of that command is
still not acceptance without the runner's two-tree binding, private archives,
and postflight evidence.

The selector runs a real Nodescale client path against the real Fleet UDS server
started from the separately archived Fleet tree. A helper, unit test, doctest,
Fleet-only test, broad workspace filter, fake server, request echo, client
cache, or apply receipt is insufficient. Against the exact selected V1 it must
prove all of the following:

1. Fleet accepts only the configured Nodescale UID reported by Linux
   `SO_PEERCRED`; a wrong UID is rejected by connection close before dispatch.
   No bearer token, shared secret, authorization header, or JSON identity field
   participates.
2. Requests and responses use a four-byte unsigned big-endian frame length with
   payload length `1..=32768`; zero, oversized, truncated, invalid-UTF-8, and
   malformed request frames fail closed.
3. Only `fleet.managed-projection.v1` and the exact `capabilities`, `apply`, and
   `inspect` top-level request shapes work. There is no request ID, `body`, or
   alternate envelope.
4. Request parsing rejects duplicate keys at every nesting level, numeric JSON,
   unknown/missing keys, and nonconforming document, provenance, or selector
   shapes.
5. `capabilities` returns exactly the three V1 kinds; `apply` returns one of
   `applied`, `already_applied`, `conflict`, `stale`, or `gap`; malformed input
   returns the closed `kind:"error", ok:false, error:"invalid_request"`
   response where the server can respond.
6. An exact replay is `already_applied`; same-generation non-identical content
   is `conflict`; lower generation is `stale`; and a non-successor generation is
   `gap`. A valid new transition is `applied`.
7. Generated operations are exactly `fleet.health`, `fleet.inventory`, and
   `fleet.message`; attempts to generate `fleet.hermes.run`, execution, admin,
   wildcard, role-implied, or other operation names fail.
8. After a Fleet restart against the same private durable state, `inspect` is
   authoritative: the expected generated/effective record, persisted
   generations, hash, provenance, and grants are returned. The proof must show
   a missing inspected record as `generated:null` and `effective:null`, and
   preserve the distinction between generated grants and Fleet's separate
   operator-deny-effective result.

## Isolation, residue, and interruption proof

The runner creates opaque secret sentinels only for runtime-residue scanning;
they are not Fleet, Nodescale, or bearer credentials. It scans regular files
under both private roots—including databases, WAL/SHM, logs, reports, build
artifacts, and generated files—before removal. Sanitized evidence must not
disclose a sentinel, credential, socket path, or private root.

A cryptographic nonce qualifies all test-owned resources. Before starting, the
runner fails closed if a full `nodescale-n7-proof-*` or `fleet-n7-proof-*`
namespace exists. Cleanup may delete only resources for its nonce; postflight
scans both full prefixes for residue. A normal run must terminate/reap owned
process groups, close UDS/listeners, remove archive/target/runtime roots, scan
for sentinels, and verify source worktrees/lockfiles unchanged.

`verify_interruption.py` is a separate SIGTERM acceptance wrapper. Once the
selector reports test-owned readiness for both archived sides, it sends SIGTERM
to the runner process group. It requires a nonzero child result, no success
manifest, and a failed child manifest that reports the signal and completed
cleanup, all owned groups reaped, endpoints closed, no two-prefix residue or
sentinels, and unchanged source/lockfile fingerprints. A deadline miss may
trigger SIGKILL and reap, but always fails the run and never skips postflight
checks.

## Invocation and acceptance gate

The runner and selector must be committed into the named immutable Nodescale
tree, and the required Fleet harness files must be committed into the named
immutable Fleet tree, before either invocation can produce meaningful evidence:

```bash
PATH="$HOME/.cargo/bin:$PATH" \
  NODESCALE_N7_TREE='<nodescale-candidate-tree>' \
  FLEET_N7_REPOSITORY='<fleet-repository>' \
  FLEET_N7_TREE='<fleet-candidate-tree>' \
  python3 -B proofs/n7/run.py \
  >'/tmp/nodescale-n7-normal.json'

PATH="$HOME/.cargo/bin:$PATH" \
  NODESCALE_N7_TREE='<nodescale-candidate-tree>' \
  FLEET_N7_REPOSITORY='<fleet-repository>' \
  FLEET_N7_TREE='<fleet-candidate-tree>' \
  python3 -B proofs/n7/verify_interruption.py \
  >'/tmp/nodescale-n7-sigterm.json'
```

Release acceptance remains explicitly pending until both sanitized manifests
pass for the identical Nodescale/Fleet candidate-tree pair. A source review,
focused test pass, or runner invocation that cannot bind and execute the exact
archived pair does not satisfy this gate.
