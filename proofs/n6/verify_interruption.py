#!/usr/bin/env python3
"""Deliberately interrupt the exact-tree N6 runner and prove cleanup postflight."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from typing import Any

PROOFS = Path(__file__).resolve().parent
REPO = PROOFS.parents[1]
RUNNER_PATH = PROOFS / "run.py"


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_wrapper_provenance(repo: Path, requested_tree: str, wrapper_path: Path) -> str:
    resolved = subprocess.check_output(
        ["git", "rev-parse", "--verify", f"{requested_tree}^{{tree}}"],
        cwd=repo,
        stderr=subprocess.DEVNULL,
        text=True,
    ).strip()
    for relative, ambient in (
        ("proofs/n6/verify_interruption.py", wrapper_path),
        ("proofs/n6/run.py", RUNNER_PATH),
    ):
        expected = subprocess.check_output(
            ["git", "show", f"{resolved}:{relative}"],
            cwd=repo,
            stderr=subprocess.DEVNULL,
        )
        if ambient.read_bytes() != expected:
            raise RuntimeError("proof_files_not_bound_to_candidate_tree")
    return resolved


def load_runner():
    spec = importlib.util.spec_from_file_location("nodescale_n6_interrupt_runner", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("runner_load_failed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def signal_process_group(process, signum: int) -> None:
    """The runner owns a session; target that group, not merely its Python parent."""
    try:
        os.killpg(process.pid, signum)
    except (AttributeError, ProcessLookupError):
        process.send_signal(signum)


def terminate_and_reap(process, term_timeout: int) -> tuple[int | None, str | None]:
    signal_process_group(process, signal.SIGTERM)
    try:
        return process.wait(timeout=term_timeout), None
    except subprocess.TimeoutExpired:
        signal_process_group(process, signal.SIGKILL)
        try:
            return process.wait(timeout=10), "term_timeout"
        except subprocess.TimeoutExpired:
            return None, "term_timeout_reap_failed"


def read_child_manifest(stdout_path: Path) -> tuple[dict[str, object] | None, str | None]:
    try:
        lines = [line for line in stdout_path.read_text(encoding="utf-8").splitlines() if line]
    except (OSError, UnicodeDecodeError):
        return None, "child_manifest_unreadable"
    if len(lines) != 1:
        return None, "child_manifest_count_invalid"
    try:
        value = json.loads(lines[0])
    except json.JSONDecodeError:
        return None, "child_manifest_invalid"
    if not isinstance(value, dict):
        return None, "child_manifest_invalid"
    return value, None


def read_owned_endpoints(runner, path: Path) -> tuple[Any, ...]:
    try:
        raw = path.read_bytes()
        if len(raw) > 8192:
            raise ValueError("oversized")
        values = json.loads(raw)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise RuntimeError("owned_endpoints_invalid") from error
    if not isinstance(values, list) or not values:
        raise RuntimeError("owned_endpoints_invalid")
    endpoints = []
    for value in values:
        if not isinstance(value, dict) or set(value) != {"address", "port", "transport"}:
            raise RuntimeError("owned_endpoints_invalid")
        address, port, transport = value.get("address"), value.get("port"), value.get("transport")
        if address not in {"127.0.0.1", "::1"} or transport != "tcp" or not isinstance(port, int):
            raise RuntimeError("owned_endpoints_invalid")
        if not 1 <= port <= 65535:
            raise RuntimeError("owned_endpoints_invalid")
        endpoints.append(runner.OwnedEndpoint(address=address, port=port))
    if len(set(endpoints)) != len(endpoints):
        raise RuntimeError("owned_endpoints_invalid")
    return tuple(sorted(endpoints, key=lambda item: (item.address, item.port)))


def collect_postflight_errors(
    runner, repository_before: str, lock_before: str, endpoints: tuple[Any, ...]
) -> list[str]:
    errors: list[str] = []
    try:
        if runner.conflicting_resources():
            errors.append("runtime_residue")
    except Exception:
        errors.append("runtime_residue_inspection_failed")
    for endpoint in endpoints:
        try:
            if not runner.endpoint_is_free(endpoint):
                errors.append("owned_listener_remained")
        except Exception:
            errors.append("owned_listener_inspection_failed")
    try:
        if runner.repository_fingerprint() != repository_before:
            errors.append("source_worktree_changed")
    except Exception:
        errors.append("source_worktree_inspection_failed")
    try:
        if sha256_file(REPO / "Cargo.lock") != lock_before:
            errors.append("cargo_lock_changed")
    except OSError:
        errors.append("cargo_lock_inspection_failed")
    return sorted(set(errors))


def manifest(status: str, **fields: object) -> str:
    return json.dumps(
        {"proof": "n6_interruption_cleanup", "sanitized": True, "status": status, **fields},
        sort_keys=True,
        separators=(",", ":"),
    )


def main() -> tuple[dict[str, object], int]:
    requested_tree = os.environ.get("NODESCALE_N6_TREE", "").strip()
    if not requested_tree:
        return {"reason": "candidate_tree_required"}, 1
    try:
        exact_tree = verify_wrapper_provenance(REPO, requested_tree, Path(__file__).resolve())
        runner = load_runner()
        if runner.resolve_exact_tree() != exact_tree:
            return {"reason": "runner_tree_mismatch"}, 1
        if runner.conflicting_resources():
            return {"reason": "preexisting_n6_resources"}, 1
        repository_before = runner.repository_fingerprint()
        lock_before = sha256_file(REPO / "Cargo.lock")
    except Exception:
        return {"reason": "preflight_failed"}, 1

    acceptance_errors: list[str] = []
    endpoints: tuple[Any, ...] = ()
    exit_code: int | None = None
    child_manifest: dict[str, object] | None = None
    with tempfile.TemporaryDirectory(prefix="nodescale-n6-interruption-", dir="/var/tmp") as directory:
        temporary = Path(directory)
        marker = temporary / "initialized"
        endpoints_path = temporary / "owned-endpoints.json"
        stdout_path = temporary / "stdout.json"
        with stdout_path.open("wb") as stdout:
            process = subprocess.Popen(
                [sys.executable, "-B", str(RUNNER_PATH)],
                cwd=REPO,
                env={
                    **os.environ,
                    "NODESCALE_N6_TREE": exact_tree,
                    "NODESCALE_N6_INITIALIZATION_MARKER": str(marker),
                    "NODESCALE_N6_INITIALIZATION_ENDPOINTS": str(endpoints_path),
                },
                stdout=stdout,
                stderr=subprocess.DEVNULL,
                start_new_session=True,
            )
            deadline = time.monotonic() + 90
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            if not marker.exists():
                acceptance_errors.append(
                    "runner_exited_before_owned_marker" if process.poll() is not None else "owned_marker_timeout"
                )
            else:
                try:
                    endpoints = read_owned_endpoints(runner, endpoints_path)
                except RuntimeError as error:
                    acceptance_errors.append(str(error))
            if process.poll() is None:
                exit_code, termination_error = terminate_and_reap(process, 120)
                if termination_error:
                    acceptance_errors.append(termination_error)
            else:
                exit_code = process.returncode
                acceptance_errors.append("runner_exited_before_term")

        child_manifest, manifest_error = read_child_manifest(stdout_path)
        if manifest_error:
            acceptance_errors.append(manifest_error)
        elif child_manifest is not None:
            if child_manifest.get("status") == "ok":
                acceptance_errors.append("term_runner_emitted_success")
            if child_manifest.get("status") != "failed":
                acceptance_errors.append("term_runner_failure_manifest_missing")
            if child_manifest.get("termination_signal") != signal.SIGTERM:
                acceptance_errors.append("term_runner_signal_not_reported")
            if child_manifest.get("cleanup") != "zero":
                acceptance_errors.append("term_runner_cleanup_not_reported_complete")
            if child_manifest.get("runtime_residue") != "zero":
                acceptance_errors.append("term_runner_runtime_residue_not_zero")

    if exit_code is None:
        acceptance_errors.append("term_runner_not_reaped")
    elif exit_code == 0:
        acceptance_errors.append("term_runner_succeeded")
    postflight_errors = collect_postflight_errors(runner, repository_before, lock_before, endpoints)
    acceptance_errors = sorted(set(acceptance_errors))
    if acceptance_errors or postflight_errors:
        return {
            "candidate_tree": exact_tree,
            "reason": "interruption_postflight_failed",
            "runtime_residue": "zero" if "runtime_residue" not in postflight_errors else "present",
            "acceptance_errors": acceptance_errors,
            "postflight_errors": postflight_errors,
        }, 1
    return {
        "candidate_tree": exact_tree,
        "child_exit_code": exit_code,
        "runtime_residue": "zero",
        "source_worktree": "unchanged",
        "cargo_lock": "unchanged",
        "owned_endpoints": "closed",
        "termination_marker": "test_owned_readiness",
        "termination_signal": signal.SIGTERM,
    }, 0


if __name__ == "__main__":
    try:
        fields, exit_code = main()
    except Exception:
        fields, exit_code = {"reason": "internal_interruption_failure"}, 1
    print(manifest("ok" if exit_code == 0 else "failed", **fields))
    raise SystemExit(exit_code)
