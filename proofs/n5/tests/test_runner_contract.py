import importlib.util
import inspect
from pathlib import Path
import subprocess
import tempfile
import unittest


PROOFS = Path(__file__).resolve().parents[1]
REPO = PROOFS.parents[1]
RUNNER_PATH = PROOFS / "run.py"
VERIFIER_PATH = PROOFS / "verify_interruption.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


RUNNER = load_module("nodescale_n5_proof_runner", RUNNER_PATH)
VERIFIER = load_module("nodescale_n5_interruption_verifier", VERIFIER_PATH)


class N5RunnerContractTests(unittest.TestCase):
    def test_runner_invokes_the_exact_n5_disposable_test(self) -> None:
        self.assertEqual(
            RUNNER.PROOF_TEST_NAME,
            "disposable_join_confirms_identity_activates_revokes_and_cleans_up",
        )
        start_source = inspect.getsource(RUNNER.start_rust_proof)
        self.assertIn("PROOF_TEST_NAME", start_source)
        self.assertNotIn(
            "disposable_client_redeems_over_tls_joins_and_is_exactly_removed",
            RUNNER_PATH.read_text(encoding="utf-8"),
        )

    def test_lifecycle_markers_surface_early_rust_exit_logs(self) -> None:
        main_source = inspect.getsource(RUNNER.main)
        self.assertIn(
            'wait_proof_marker(root / "node-observed", cargo, cargo_log',
            main_source,
        )
        self.assertIn(
            'wait_proof_marker(root / "cleanup-complete", cargo, cargo_log',
            main_source,
        )
        self.assertNotIn('wait_file(root / "node-observed")', main_source)

    def test_cleanup_errors_cannot_skip_postflight_gates(self) -> None:
        cleanup_source = inspect.getsource(RUNNER.cleanup_resources)
        main_source = inspect.getsource(RUNNER.main)
        self.assertIn("return errors", cleanup_source)
        self.assertNotIn("raise RuntimeError", cleanup_source)
        cleanup_call = main_source.index("cleanup_errors = cleanup_resources")
        for gate in [
            "conflicting_resources()",
            "repository_after = command_hash",
            "cargo_lock_before != sha256",
            "after = host_invariant()",
        ]:
            self.assertGreater(main_source.index(gate, cleanup_call), cleanup_call)
        self.assertIn("if cleanup_errors or postflight_errors", main_source)
        for unsupported_counter in [
            '"fleet_enrollments"',
            '"fleet_grants"',
            '"hermes_activations"',
        ]:
            self.assertNotIn(unsupported_counter, main_source)

    def test_interruption_timeout_kills_reaps_and_preserves_postflight(self) -> None:
        class HungProcess:
            def __init__(self) -> None:
                self.wait_calls = 0
                self.killed = False
                self.signals: list[int] = []

            def send_signal(self, signum: int) -> None:
                self.signals.append(signum)

            def wait(self, timeout: int | None = None) -> int:
                self.wait_calls += 1
                if self.wait_calls == 1:
                    raise subprocess.TimeoutExpired("proof", timeout or 0)
                return -9

            def kill(self) -> None:
                self.killed = True

        process = HungProcess()
        exit_code, timeout_error = VERIFIER.terminate_and_reap(process, 120)
        self.assertEqual(process.signals, [VERIFIER.signal.SIGTERM])
        self.assertTrue(process.killed)
        self.assertEqual(process.wait_calls, 2)
        self.assertEqual(exit_code, -9)
        self.assertIn("timed out after TERM", timeout_error)

        main_source = inspect.getsource(VERIFIER.main)
        termination = main_source.index("terminate_and_reap")
        postflight = main_source.index("collect_postflight_errors", termination)
        self.assertGreater(postflight, termination)
        self.assertIn("acceptance_errors + postflight_errors", main_source[postflight:])

    def test_interruption_wrapper_rejects_bytes_not_bound_to_requested_tree(self) -> None:
        tree = subprocess.check_output(
            ["git", "write-tree"],
            cwd=REPO,
            text=True,
        ).strip()
        with tempfile.TemporaryDirectory() as directory:
            tampered = Path(directory) / "verify_interruption.py"
            tampered.write_bytes(VERIFIER_PATH.read_bytes() + b"\n# tampered\n")
            with self.assertRaisesRegex(RuntimeError, "wrapper does not match requested tree"):
                VERIFIER.verify_wrapper_provenance(REPO, tree, tampered)


if __name__ == "__main__":
    unittest.main()
