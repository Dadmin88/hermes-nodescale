import importlib.util
import inspect
import json
from pathlib import Path
import subprocess
import tempfile
import unittest


PROOFS = Path(__file__).resolve().parents[1]
RUNNER_PATH = PROOFS / "run.py"
VERIFIER_PATH = PROOFS / "verify_interruption.py"


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_selector(source: Path, *, include_proof_inputs: bool = True, ignored: bool = True) -> Path:
    crate = source / "crates" / "binding"
    tests = crate / "tests"
    tests.mkdir(parents=True, exist_ok=True)
    (crate / "Cargo.toml").write_text("[package]\nname = 'nodescale-binding'\n", encoding="utf-8")
    attributes = "#[tokio::test]\n#[ignore]\n" if ignored else "#[tokio::test]\n"
    inputs = (
        'let _ = std::env::var("NODESCALE_N6_PROOF_READY_MARKER");\n'
        'let _ = std::env::var("NODESCALE_N6_PROOF_SECRET_SENTINEL_A");\n'
        'let _ = std::env::var("NODESCALE_N6_PROOF_SECRET_SENTINEL_B");\n'
        if include_proof_inputs
        else ""
    )
    test = tests / "direct_control.rs"
    test.write_text(
        attributes
        + "async fn disposable_authenticated_keryx_binding_is_durable_and_cleans_up() {\n"
        + inputs
        + "}\n",
        encoding="utf-8",
    )
    return test


class N6RunnerContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.runner = load_module("nodescale_n6_proof_runner", RUNNER_PATH)
        cls.verifier = load_module("nodescale_n6_interruption_verifier", VERIFIER_PATH)

    def test_selector_is_a_unique_targeted_ignored_integration_contract(self) -> None:
        self.assertEqual(
            self.runner.PROOF_TEST_NAME,
            "disposable_authenticated_keryx_binding_is_durable_and_cleans_up",
        )
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory)
            test = write_selector(source)
            selector = self.runner.exact_ignored_integration_selector(source)
            self.assertEqual(selector.package, "nodescale-binding")
            self.assertEqual(selector.target, "direct_control")
            self.assertEqual(selector.relative_path, "crates/binding/tests/direct_control.rs")
            self.assertTrue(self.runner.has_ignored_integration_selector(source))

            test.write_text(
                "#[test]\nfn disposable_authenticated_keryx_binding_is_durable_and_cleans_up() {}\n",
                encoding="utf-8",
            )
            self.assertFalse(self.runner.has_ignored_integration_selector(source))
            write_selector(source, include_proof_inputs=False)
            self.assertFalse(self.runner.has_ignored_integration_selector(source))

    def test_exact_selector_command_is_locked_offline_and_targeted(self) -> None:
        selector = self.runner.ExactSelector(
            package="nodescale-binding", target="direct_control", relative_path="crates/binding/tests/direct_control.rs"
        )
        command = self.runner.cargo_test_command(selector)
        self.assertEqual(
            command[:9],
            [
                "cargo", "test", "--locked", "--offline", "--package", "nodescale-binding",
                "--test", "direct_control", self.runner.PROOF_TEST_NAME,
            ],
        )
        self.assertEqual(command[-4:], ["--ignored", "--exact", "--nocapture", "--test-threads=1"])
        environment = self.runner.proof_environment(Path("/var/tmp/n6-proof"))
        self.assertIn("-fuse-ld=bfd", environment["RUSTFLAGS"])
        self.assertEqual(environment["CARGO_TARGET_DIR"], "/var/tmp/n6-proof/cargo-target")
        self.assertEqual(environment["CARGO_NET_OFFLINE"], "true")
        self.assertIn("NODESCALE_N6_PROOF_READY_MARKER", environment)

    def test_readiness_is_strict_and_propagates_only_owned_loopback_endpoints(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "ready.json"
            payload = {
                "owned_endpoints": [{"address": "127.0.0.1", "port": 32123, "transport": "tcp"}],
                "phase": "owned",
                "prefix": self.runner.PREFIX,
            }
            path.write_text(json.dumps(payload), encoding="utf-8")
            self.assertEqual(
                self.runner.parse_owned_readiness(path),
                (self.runner.OwnedEndpoint(address="127.0.0.1", port=32123),),
            )
            payload["owned_endpoints"][0]["address"] = "0.0.0.0"
            path.write_text(json.dumps(payload), encoding="utf-8")
            with self.assertRaisesRegex(self.runner.ProofFailure, "test_owned_readiness_invalid"):
                self.runner.parse_owned_readiness(path)

    def test_full_runtime_artifact_sentinel_scan_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            sentinel_a = b"secret-a"
            sentinel_b = b"secret-b"
            (root / "state.db-wal").write_bytes(sentinel_a)
            nested = root / "cargo-target" / "report.json"
            nested.parent.mkdir()
            nested.write_bytes(b"x" * 65533 + sentinel_b)
            self.assertEqual(
                self.runner.find_secret_sentinels(root, (sentinel_a, sentinel_b)),
                ["artifact:cargo-target/report.json", "artifact:state.db-wal"],
            )

    def test_zero_executed_or_fake_named_test_cannot_pass(self) -> None:
        valid = subprocess.CompletedProcess(
            ["cargo"],
            0,
            b"test disposable_authenticated_keryx_binding_is_durable_and_cleans_up ... ok\n"
            b"test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out;\n",
            b"",
        )
        self.runner.require_exact_test_execution(valid)
        with self.assertRaisesRegex(self.runner.ProofFailure, "not_executed"):
            self.runner.require_exact_test_execution(subprocess.CompletedProcess(["cargo"], 0, b"running 0 tests\n", b""))

    def test_cleanup_scans_full_prefix_but_deletes_only_exact_nonce_resources(self) -> None:
        cleanup_source = inspect.getsource(self.runner.cleanup_resources)
        resource_source = inspect.getsource(self.runner.conflicting_resources)
        docker_cleanup_source = inspect.getsource(self.runner.remove_exact_docker_resources)
        main_source = inspect.getsource(self.runner.main)
        self.assertIn("return errors", cleanup_source)
        self.assertIn("prefix=BASE_PREFIX", resource_source)
        self.assertIn("prefix=PREFIX", docker_cleanup_source)
        cleanup_call = main_source.index("cleanup_resources(root)")
        for gate in [
            "conflicting_resources()",
            "repository_after = repository_fingerprint()",
            "cargo_lock_before != sha256_file(REPO / \"Cargo.lock\")",
            "secret_sentinel_residue",
        ]:
            self.assertGreater(main_source.index(gate, cleanup_call), cleanup_call)

    def test_interruption_timeout_kills_process_group_reaps_and_keeps_postflight(self) -> None:
        class HungProcess:
            def __init__(self) -> None:
                self.wait_calls = 0
                self.signals: list[int] = []

            def send_signal(self, signum: int) -> None:
                self.signals.append(signum)

            def wait(self, timeout: int | None = None) -> int:
                self.wait_calls += 1
                if self.wait_calls == 1:
                    raise subprocess.TimeoutExpired("proof", timeout or 0)
                return -9

        process = HungProcess()
        exit_code, timeout_error = self.verifier.terminate_and_reap(process, 120)
        self.assertEqual(process.signals, [self.verifier.signal.SIGTERM, self.verifier.signal.SIGKILL])
        self.assertEqual(process.wait_calls, 2)
        self.assertEqual(exit_code, -9)
        self.assertEqual(timeout_error, "term_timeout")

        main_source = inspect.getsource(self.verifier.main)
        termination = main_source.index("terminate_and_reap")
        postflight = main_source.index("collect_postflight_errors", termination)
        self.assertGreater(postflight, termination)
        self.assertIn("start_new_session=True", main_source)
        self.assertIn("NODESCALE_N6_INITIALIZATION_ENDPOINTS", main_source)
        self.assertIn("term_runner_cleanup_not_reported_complete", main_source)


if __name__ == "__main__":
    unittest.main()
