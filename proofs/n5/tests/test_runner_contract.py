import importlib.util
import inspect
from pathlib import Path
import unittest


RUNNER_PATH = Path(__file__).resolve().parents[1] / "run.py"
SPEC = importlib.util.spec_from_file_location("nodescale_n5_proof_runner", RUNNER_PATH)
assert SPEC is not None and SPEC.loader is not None
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


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


if __name__ == "__main__":
    unittest.main()
