"""Focused behavioral coverage for the N7 proof runner and interruption wrapper."""

from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


PROOFS = Path(__file__).resolve().parents[1]
RUNNER_PATH = PROOFS / "run.py"
VERIFIER_PATH = PROOFS / "verify_interruption.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


RUNNER = load_module("nodescale_n7_runner_unit", RUNNER_PATH)
VERIFIER = load_module("nodescale_n7_verifier_unit", VERIFIER_PATH)


def git(repository: Path, *args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=repository, text=True).strip()


def commit_tree(repository: Path, message: str) -> str:
    git(repository, "add", ".")
    subprocess.check_call(
        ["git", "-c", "user.name=N7 Unit", "-c", "user.email=n7-unit@example.invalid", "commit", "-qm", message],
        cwd=repository,
    )
    return git(repository, "rev-parse", "HEAD^{tree}")


def write_fleet_harness(repository: Path) -> None:
    (repository / "pyproject.toml").write_text("[project]\nname = 'fleet-unit'\n", encoding="utf-8")
    for relative in VERIFIER.FLEET_HARNESS_FILES:
        path = repository / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("# exact-tree test harness\n", encoding="utf-8")


def write_selector(source: Path, *, name: str = RUNNER.PROOF_TEST_NAME) -> Path:
    crate = source / "crates" / "projection"
    test = crate / "tests" / "fleet_projection.rs"
    test.parent.mkdir(parents=True)
    (crate / "Cargo.toml").write_text("[package]\nname = 'nodescale-projection'\n", encoding="utf-8")
    test.write_text(
        "#[tokio::test]\n#[ignore]\n"
        f"async fn {name}() {{\n"
        'let _ = std::env::var("NODESCALE_N7_PROOF_READY_MARKER");\n'
        'let _ = std::env::var("NODESCALE_N7_PROOF_SECRET_SENTINEL_A");\n'
        'let _ = std::env::var("NODESCALE_N7_PROOF_SECRET_SENTINEL_B");\n'
        'let _ = std::env::var("NODESCALE_N7_PROOF_PREFIX");\n'
        'let _ = std::env::var("NODESCALE_N7_PROOF_ROOT");\n'
        'let _ = std::env::var("FLEET_N7_PROOF_ROOT");\n'
        '// SO_PEERCRED 32768 fleet.managed-projection.v1 capabilities apply inspect duplicate numeric bearer\n'
        "}\n",
        encoding="utf-8",
    )
    return test


class N7RunnerUnitTests(unittest.TestCase):
    def test_exact_selector_is_unique_and_command_is_locked_offline(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as directory:
            source = Path(directory)
            write_selector(source)
            selector = RUNNER.exact_ignored_integration_selector(source)
            self.assertEqual(
                selector,
                RUNNER.ExactSelector(
                    package="nodescale-projection",
                    target="fleet_projection",
                    relative_path="crates/projection/tests/fleet_projection.rs",
                ),
            )
            self.assertEqual(
                RUNNER.cargo_test_command(selector),
                [
                    "cargo", "test", "--locked", "--offline", "--package", "nodescale-projection",
                    "--test", "fleet_projection", RUNNER.PROOF_TEST_NAME, "--", "--ignored",
                    "--exact", "--nocapture", "--test-threads=1",
                ],
            )
            write_selector(source / "duplicate")
            with self.assertRaisesRegex(RUNNER.ProofFailure, "ambiguous"):
                RUNNER.exact_ignored_integration_selector(source)

    def test_secret_scan_detects_sentinel_split_across_read_chunks(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as directory:
            root = Path(directory)
            sentinel = b"cross-chunk-secret"
            artifact = root / "cargo-target" / "incremental" / "trace.bin"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"x" * (65536 - 5) + sentinel + b"tail")
            self.assertEqual(
                RUNNER.find_secret_sentinels((root,), (sentinel, b"other-sentinel")),
                ["secret_runtime_artifact"],
            )

    def test_readiness_accepts_only_owned_live_uds_socket(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as directory:
            fleet_root = Path(directory) / "fleet"
            fleet_root.mkdir()
            owned = fleet_root / "managed.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(os.fspath(owned))
                listener.listen()
                ready = fleet_root / "ready.json"
                ready.write_text(
                    json.dumps({"owned_uds_paths": [str(owned)], "phase": "owned", "prefix": RUNNER.PREFIX}),
                    encoding="utf-8",
                )
                self.assertEqual(RUNNER.parse_owned_readiness(ready, fleet_root), (owned,))
                ready.write_text(
                    json.dumps({"owned_uds_paths": [str(Path(directory) / "outside.sock")], "phase": "owned", "prefix": RUNNER.PREFIX}),
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(RUNNER.ProofFailure, "test_owned_readiness_invalid"):
                    RUNNER.parse_owned_readiness(ready, fleet_root)
            finally:
                listener.close()
                if owned.exists():
                    owned.unlink()

    def test_uds_closed_requires_no_filesystem_listener_or_connectable_socket(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as directory:
            path = Path(directory) / "managed.sock"
            listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            try:
                listener.bind(os.fspath(path))
                listener.listen()
                self.assertFalse(RUNNER.uds_is_closed(path))
            finally:
                listener.close()
                if path.exists():
                    path.unlink()
            self.assertTrue(RUNNER.uds_is_closed(path))


class N7InterruptionUnitTests(unittest.TestCase):
    def test_provenance_rejects_nodescale_bytes_and_missing_fleet_tree_harness(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as directory:
            temporary = Path(directory)
            nodescale = temporary / "nodescale"
            fleet = temporary / "fleet"
            nodescale.mkdir()
            fleet.mkdir()
            git(nodescale, "init", "-q")
            git(fleet, "init", "-q")
            runner_copy = nodescale / "proofs" / "n7" / "run.py"
            verifier_copy = nodescale / "proofs" / "n7" / "verify_interruption.py"
            runner_copy.parent.mkdir(parents=True)
            shutil.copy2(RUNNER_PATH, runner_copy)
            shutil.copy2(VERIFIER_PATH, verifier_copy)
            (nodescale / "Cargo.lock").write_text("# lock\n", encoding="utf-8")
            nodescale_tree = commit_tree(nodescale, "nodescale runner")
            write_fleet_harness(fleet)
            fleet_tree = commit_tree(fleet, "fleet harness")
            verifier = load_module("nodescale_n7_temp_verifier", verifier_copy)
            with mock.patch.dict(os.environ, {"FLEET_N7_REPOSITORY": str(fleet)}, clear=False):
                self.assertEqual(
                    verifier.verify_wrapper_provenance(nodescale_tree, fleet_tree),
                    (nodescale_tree, fleet.resolve(), fleet_tree),
                )
                runner_copy.write_bytes(runner_copy.read_bytes() + b"\n# mismatched local runner\n")
                with self.assertRaisesRegex(RuntimeError, "proof_files_not_bound_to_candidate_tree"):
                    verifier.verify_wrapper_provenance(nodescale_tree, fleet_tree)
                runner_copy.write_bytes(RUNNER_PATH.read_bytes())
                (fleet / "hermes_fleet" / "managed_service.py").unlink()
                git(fleet, "add", "-u")
                missing_harness_tree = git(fleet, "write-tree")
                with self.assertRaises(subprocess.CalledProcessError):
                    verifier.verify_wrapper_provenance(nodescale_tree, missing_harness_tree)

    def test_main_rejects_runner_resolving_different_nodescale_or_fleet_tree(self) -> None:
        fleet = Path(tempfile.mkdtemp(dir="/var/tmp"))
        self.addCleanup(shutil.rmtree, fleet)
        for resolved in (("other-nodescale", fleet, "fleet-tree"), ("nodescale-tree", fleet, "other-fleet")):
            runner = mock.Mock()
            runner.resolve_exact_trees.return_value = (VERIFIER.REPO, *resolved)
            with (
                mock.patch.dict(os.environ, {"NODESCALE_N7_TREE": "nodescale-tree", "FLEET_N7_TREE": "fleet-tree", "FLEET_N7_REPOSITORY": str(fleet)}, clear=False),
                mock.patch.object(VERIFIER, "verify_wrapper_provenance", return_value=("nodescale-tree", fleet, "fleet-tree")),
                mock.patch.object(VERIFIER, "load_runner", return_value=runner),
            ):
                fields, exit_code = VERIFIER.main()
            self.assertEqual((fields, exit_code), ({"reason": "runner_tree_mismatch"}, 1))

    def test_postflight_preserves_and_detects_source_and_lock_fingerprints(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as directory:
            temporary = Path(directory)
            nodescale, fleet = temporary / "nodescale", temporary / "fleet"
            nodescale.mkdir()
            fleet.mkdir()
            for repository, lockfile in ((nodescale, "Cargo.lock"), (fleet, "pyproject.toml")):
                git(repository, "init", "-q")
                (repository / lockfile).write_text("initial\n", encoding="utf-8")
                commit_tree(repository, "initial")
            runner = mock.Mock()
            runner.conflicting_resources.return_value = []
            runner.uds_is_closed.return_value = True
            nodescale_before, fleet_before = VERIFIER.fingerprint(nodescale), VERIFIER.fingerprint(fleet)
            cargo_before = VERIFIER.sha256_file(nodescale / "Cargo.lock")
            pyproject_before = VERIFIER.sha256_file(fleet / "pyproject.toml")
            with mock.patch.object(VERIFIER, "REPO", nodescale):
                self.assertEqual(
                    VERIFIER.collect_postflight_errors(runner, nodescale_before, fleet, fleet_before, cargo_before, pyproject_before, ()),
                    [],
                )
                (nodescale / "Cargo.lock").write_text("changed\n", encoding="utf-8")
                (fleet / "pyproject.toml").write_text("changed\n", encoding="utf-8")
                self.assertEqual(
                    VERIFIER.collect_postflight_errors(runner, nodescale_before, fleet, fleet_before, cargo_before, pyproject_before, ()),
                    ["cargo_lock_changed", "fleet_pyproject_changed", "fleet_worktree_changed", "nodescale_worktree_changed"],
                )

    def test_interruption_rejects_success_manifest_and_runtime_residue(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as directory:
            temporary = Path(directory)
            nodescale, fleet = temporary / "nodescale", temporary / "fleet"
            nodescale.mkdir()
            fleet.mkdir()
            for repository, lockfile in ((nodescale, "Cargo.lock"), (fleet, "pyproject.toml")):
                git(repository, "init", "-q")
                (repository / lockfile).write_text("initial\n", encoding="utf-8")
                commit_tree(repository, "initial")

            class TerminatedRunner:
                def __init__(self) -> None:
                    self.conflicting_resources_calls = 0

                def resolve_exact_trees(self):
                    return nodescale, "nodescale-tree", fleet, "fleet-tree"

                def conflicting_resources(self):
                    self.conflicting_resources_calls += 1
                    return [] if self.conflicting_resources_calls == 1 else ["runtime"]

                @staticmethod
                def uds_is_closed(_path: Path) -> bool:
                    return True

            class ChildProcess:
                pid = 987654321
                returncode = None

                def __init__(self, _args, *, env, stdout, **_kwargs) -> None:
                    Path(env["NODESCALE_N7_INITIALIZATION_MARKER"]).write_text("ready\n", encoding="ascii")
                    Path(env["NODESCALE_N7_INITIALIZATION_UDS"]).write_text(
                        json.dumps({"owned_uds_paths": ["/var/tmp/n7-unit-owned.sock"]}), encoding="utf-8"
                    )
                    stdout.write(b'{"status":"ok","cleanup":"zero","runtime_residue":"zero","termination_signal":15}\n')
                    stdout.flush()

                def poll(self):
                    return None

                def send_signal(self, _signum: int) -> None:
                    pass

                def wait(self, timeout: int | None = None) -> int:
                    self.returncode = -15
                    return -15

            runner = TerminatedRunner()
            with (
                mock.patch.dict(os.environ, {"NODESCALE_N7_TREE": "nodescale-tree", "FLEET_N7_TREE": "fleet-tree", "FLEET_N7_REPOSITORY": str(fleet)}, clear=False),
                mock.patch.object(VERIFIER, "REPO", nodescale),
                mock.patch.object(VERIFIER, "fingerprint", side_effect=lambda repository: f"fingerprint:{repository}"),
                mock.patch.object(VERIFIER, "sha256_file", side_effect=lambda path: f"sha256:{path}"),
                mock.patch.object(VERIFIER, "verify_wrapper_provenance", return_value=("nodescale-tree", fleet, "fleet-tree")),
                mock.patch.object(VERIFIER, "load_runner", return_value=runner),
                mock.patch.object(VERIFIER.subprocess, "Popen", ChildProcess),
            ):
                fields, exit_code = VERIFIER.main()
            self.assertEqual(exit_code, 1)
            self.assertEqual(fields["reason"], "interruption_postflight_failed")
            self.assertEqual(fields["runtime_residue"], "present")
            self.assertIn("term_runner_emitted_success", fields["acceptance_errors"])
            self.assertIn("term_runner_failure_manifest_missing", fields["acceptance_errors"])
            self.assertIn("runtime_residue", fields["postflight_errors"])


if __name__ == "__main__":
    unittest.main()
