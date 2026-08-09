"""Executable contract tests for the exact-tree N7 disposable proof runner.

The runner and its one ignored selector are implementation artifacts, not release
acceptance evidence.  N7 remains pending until the same immutable Nodescale/Fleet
tree pair has produced passing sanitized normal and SIGTERM manifests.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


PROOFS = Path(__file__).resolve().parents[1]
REPOSITORY = PROOFS.parents[1]
RUNNER_PATH = PROOFS / "run.py"
VERIFIER_PATH = PROOFS / "verify_interruption.py"
PROTOCOL_PATH = REPOSITORY / "docs" / "n7-authenticated-fleet-projection.md"
ADR_PATH = REPOSITORY / "docs" / "adr" / "0011-nodescale-fleet-control-v1.md"
README_PATH = PROOFS / "README.md"
PROOF_TEST_NAME = "disposable_authenticated_fleet_projection_is_durable_and_cleans_up"


def load_runner():
    """Load the current executable gate; its presence must not imply acceptance."""
    if not RUNNER_PATH.is_file():
        raise AssertionError("N7 proof runner is required for executable contract coverage")
    spec = importlib.util.spec_from_file_location("nodescale_n7_proof_contract_runner", RUNNER_PATH)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class N7DocumentationContractTests(unittest.TestCase):
    def test_frozen_documents_preserve_the_selected_security_contract(self) -> None:
        protocol = PROTOCOL_PATH.read_text(encoding="utf-8")
        adr = ADR_PATH.read_text(encoding="utf-8")
        proof = README_PATH.read_text(encoding="utf-8")
        for document in (protocol, adr, proof):
            self.assertIn("AGPL-3.0-only", document)
        for requirement in (
            "SO_PEERCRED",
            "Only an exact UID match",
            "Nodescale service UID",
            "bearer token",
            "4-byte unsigned BE length",
            "1..=32768",
            "fleet.managed-projection.v1",
            "`capabilities`",
            "`apply`",
            "`inspect`",
            "duplicate keys",
            "number literals",
            "content_hash",
            "`fleet.health`",
            "Fleet's durable read-back",
            "apply.result.outcome",
        ):
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, protocol)
        for requirement in (
            "NODESCALE_N7_TREE",
            "FLEET_N7_REPOSITORY",
            "FLEET_N7_TREE",
            "two-repository",
            PROOF_TEST_NAME,
            "--locked --offline",
            "--ignored --exact",
            "secret sentinels",
            "SIGTERM",
            "no success",
            "No bearer token",
            "exact archived execution",
        ):
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, proof)
        self.assertIn("N6 remains closed", adr)


class N7ProofContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_runner()

    def test_current_exact_ignored_selector_is_unique_and_targeted(self) -> None:
        self.assertEqual(self.runner.PROOF_TEST_NAME, PROOF_TEST_NAME)
        selector = self.runner.ExactSelector(
            package="nodescale-projection",
            target="disposable_n7",
            relative_path="crates/nodescale-projection/tests/disposable_n7.rs",
        )
        self.assertTrue(hasattr(self.runner, "exact_ignored_integration_selector"))
        selector_source = (REPOSITORY / selector.relative_path).read_text(encoding="utf-8")
        for requirement in (
            "#[ignore",
            "SO_PEERCRED",
            "32768",
            "fleet.managed-projection.v1",
            "capabilities",
            "apply",
            "inspect",
            "duplicate",
            "numeric",
            "bearer",
            "NODESCALE_N7_PROOF_READY_MARKER",
            "NODESCALE_N7_PROOF_SECRET_SENTINEL_A",
            "NODESCALE_N7_PROOF_SECRET_SENTINEL_B",
        ):
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, selector_source)

    def test_exact_selector_command_is_locked_offline_and_never_workspace_wide(self) -> None:
        selector = self.runner.ExactSelector(
            package="nodescale-projection",
            target="disposable_n7",
            relative_path="crates/nodescale-projection/tests/disposable_n7.rs",
        )
        self.assertEqual(
            self.runner.cargo_test_command(selector),
            [
                "cargo", "test", "--locked", "--offline", "--package", "nodescale-projection",
                "--test", "disposable_n7", PROOF_TEST_NAME, "--", "--ignored", "--exact",
                "--nocapture", "--test-threads=1",
            ],
        )
        source = RUNNER_PATH.read_text(encoding="utf-8")
        self.assertNotIn("--workspace", source)

    def test_two_immutable_trees_are_bound_and_archived_before_execution(self) -> None:
        source = RUNNER_PATH.read_text(encoding="utf-8")
        for requirement in (
            "NODESCALE_N7_TREE",
            "FLEET_N7_REPOSITORY",
            "FLEET_N7_TREE",
            "runner_not_bound_to_candidate_tree",
            "FLEET_HARNESS_FILES",
            "git", "archive",
            "archive_exact_tree",
            "resolve_exact_trees",
            "CARGO_NET_OFFLINE",
        ):
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, source)

    def test_private_environment_uses_sentinels_not_bearer_credentials(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as directory:
            root = Path(directory)
            environment = self.runner.proof_environment(root / "nodescale", root / "fleet")
        self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
        self.assertEqual(environment["NODESCALE_N7_PROOF_ROOT"], str(root / "nodescale"))
        self.assertEqual(environment["FLEET_N7_PROOF_ROOT"], str(root / "fleet"))
        proof_keys = [key for key in environment if key.startswith(("NODESCALE_N7_", "FLEET_N7_"))]
        self.assertFalse(any("TOKEN" in key or "CREDENTIAL" in key for key in proof_keys))
        self.assertTrue(environment["NODESCALE_N7_PROOF_SECRET_SENTINEL_A"])
        self.assertTrue(environment["NODESCALE_N7_PROOF_SECRET_SENTINEL_B"])

    def test_sentinel_scanning_and_sigterm_wrapper_fail_closed_on_residue_or_success(self) -> None:
        with tempfile.TemporaryDirectory(dir="/var/tmp") as directory:
            root = Path(directory)
            sentinel = b"n7-sentinel-crosses-read-boundary"
            artifact = root / "cargo-target" / "incremental" / "trace.bin"
            artifact.parent.mkdir(parents=True)
            artifact.write_bytes(b"x" * (65536 - 7) + sentinel)
            self.assertEqual(
                self.runner.find_secret_sentinels((root,), (sentinel, b"other-n7-sentinel")),
                ["secret_runtime_artifact"],
            )
        runner_source = RUNNER_PATH.read_text(encoding="utf-8")
        verifier_source = VERIFIER_PATH.read_text(encoding="utf-8")
        for requirement in (
            "SIGTERM",
            "process group",
            "secret_sentinel_residue",
            "runtime_residue",
            "owned_uds_remained",
        ):
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, runner_source)
        for requirement in (
            "SIGTERM",
            "SIGKILL",
            "term_runner_emitted_success",
            "term_runner_failure_manifest_missing",
            "term_runner_cleanup_not_reported_complete",
            "runtime_residue",
            "signal_process_group",
        ):
            with self.subTest(requirement=requirement):
                self.assertIn(requirement, verifier_source)


if __name__ == "__main__":
    unittest.main()
