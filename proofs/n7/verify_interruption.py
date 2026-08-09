#!/usr/bin/env python3
"""SIGTERM acceptance wrapper for the exact-tree two-repository N7 runner."""
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
FLEET_HARNESS_FILES = (
    "hermes_fleet/local_control.py",
    "hermes_fleet/managed_projection.py",
    "hermes_fleet/managed_service.py",
)


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def fingerprint(repository: Path) -> str:
    return hashlib.sha256(subprocess.check_output(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], cwd=repository)).hexdigest()


def fleet_repository_from_environment() -> Path:
    raw = os.environ.get("FLEET_N7_REPOSITORY", "").strip()
    if not raw:
        raise RuntimeError("fleet_repository_required")
    requested = Path(raw).expanduser().resolve()
    actual = Path(subprocess.check_output(["git", "rev-parse", "--show-toplevel"], cwd=requested, stderr=subprocess.DEVNULL, text=True).strip()).resolve()
    if actual != requested:
        raise RuntimeError("fleet_repository_must_be_worktree_root")
    return actual


def resolve_tree(repository: Path, requested: str) -> str:
    value = subprocess.check_output(["git", "rev-parse", "--verify", f"{requested}^{{tree}}"], cwd=repository, stderr=subprocess.DEVNULL, text=True).strip()
    if len(value) not in (40, 64) or any(character not in "0123456789abcdef" for character in value):
        raise RuntimeError("candidate_tree_invalid")
    return value


def tree_blob(repository: Path, tree: str, relative: str) -> bytes:
    return subprocess.check_output(["git", "show", f"{tree}:{relative}"], cwd=repository, stderr=subprocess.DEVNULL)


def verify_wrapper_provenance(nodescale_tree_request: str, fleet_tree_request: str) -> tuple[str, Path, str]:
    """Bind local wrapper/runner bytes and every Fleet-side harness to the two trees."""
    nodescale_tree = resolve_tree(REPO, nodescale_tree_request)
    for relative, ambient in (("proofs/n7/verify_interruption.py", Path(__file__).resolve()), ("proofs/n7/run.py", RUNNER_PATH)):
        if tree_blob(REPO, nodescale_tree, relative) != ambient.read_bytes():
            raise RuntimeError("proof_files_not_bound_to_candidate_tree")
    fleet_repository = fleet_repository_from_environment()
    fleet_tree = resolve_tree(fleet_repository, fleet_tree_request)
    # Do not import or execute live Fleet code.  Require the archived runner's
    # service adapters to exist in the exact Fleet tree before we interrupt it.
    for relative in FLEET_HARNESS_FILES:
        if not tree_blob(fleet_repository, fleet_tree, relative):
            raise RuntimeError("fleet_harness_not_bound_to_candidate_tree")
    return nodescale_tree, fleet_repository, fleet_tree


def load_runner():
    spec = importlib.util.spec_from_file_location("nodescale_n7_interrupt_runner", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("runner_load_failed")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def signal_process_group(process: Any, signum: int) -> None:
    """The runner owns a session: TERM/KILL always targets its process group."""
    try:
        os.killpg(process.pid, signum)
    except (AttributeError, ProcessLookupError):
        process.send_signal(signum)


def terminate_and_reap(process: Any, term_timeout: int) -> tuple[int | None, str | None]:
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
    return (value, None) if isinstance(value, dict) else (None, "child_manifest_invalid")


def read_owned_uds(path: Path) -> tuple[Path, ...]:
    try:
        value = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise RuntimeError("owned_uds_invalid") from error
    raw_paths = value.get("owned_uds_paths") if isinstance(value, dict) and set(value) == {"owned_uds_paths"} else None
    if not isinstance(raw_paths, list) or not raw_paths:
        raise RuntimeError("owned_uds_invalid")
    paths = tuple(sorted(Path(item) for item in raw_paths if isinstance(item, str) and item))
    if len(paths) != len(raw_paths) or len(set(paths)) != len(paths):
        raise RuntimeError("owned_uds_invalid")
    return paths


def collect_postflight_errors(runner: Any, nodescale_before: str, fleet_repository: Path, fleet_before: str, cargo_before: str, pyproject_before: str, uds_paths: tuple[Path, ...]) -> list[str]:
    errors: list[str] = []
    try:
        if runner.conflicting_resources():
            errors.append("runtime_residue")
    except Exception:
        errors.append("runtime_residue_inspection_failed")
    for path in uds_paths:
        try:
            if not runner.uds_is_closed(path):
                errors.append("owned_uds_remained")
        except Exception:
            errors.append("owned_uds_inspection_failed")
    try:
        if fingerprint(REPO) != nodescale_before:
            errors.append("nodescale_worktree_changed")
        if sha256_file(REPO / "Cargo.lock") != cargo_before:
            errors.append("cargo_lock_changed")
        if fingerprint(fleet_repository) != fleet_before:
            errors.append("fleet_worktree_changed")
        if sha256_file(fleet_repository / "pyproject.toml") != pyproject_before:
            errors.append("fleet_pyproject_changed")
    except (OSError, subprocess.SubprocessError):
        errors.append("source_postflight_inspection_failed")
    return sorted(set(errors))


def manifest(status: str, **fields: object) -> str:
    return json.dumps({"proof": "n7_interruption_cleanup", "sanitized": True, "status": status, **fields}, sort_keys=True, separators=(",", ":"))


def main() -> tuple[dict[str, object], int]:
    nodescale_request = os.environ.get("NODESCALE_N7_TREE", "").strip()
    fleet_request = os.environ.get("FLEET_N7_TREE", "").strip()
    if not nodescale_request or not fleet_request or not os.environ.get("FLEET_N7_REPOSITORY", "").strip():
        return {"reason": "candidate_inputs_required"}, 1
    try:
        nodescale_tree, fleet_repository, fleet_tree = verify_wrapper_provenance(nodescale_request, fleet_request)
        runner = load_runner()
        _, resolved_nodescale, resolved_fleet_repository, resolved_fleet = runner.resolve_exact_trees()
        if (resolved_nodescale, resolved_fleet_repository, resolved_fleet) != (nodescale_tree, fleet_repository, fleet_tree):
            return {"reason": "runner_tree_mismatch"}, 1
        if runner.conflicting_resources():
            return {"reason": "preexisting_n7_resources"}, 1
        nodescale_before, fleet_before = fingerprint(REPO), fingerprint(fleet_repository)
        cargo_before, pyproject_before = sha256_file(REPO / "Cargo.lock"), sha256_file(fleet_repository / "pyproject.toml")
    except Exception:
        return {"reason": "preflight_failed"}, 1

    acceptance_errors: list[str] = []
    uds_paths: tuple[Path, ...] = ()
    exit_code: int | None = None
    with tempfile.TemporaryDirectory(prefix="nodescale-n7-interruption-", dir="/var/tmp") as directory:
        temporary = Path(directory)
        marker, uds_file, stdout_path = temporary / "initialized", temporary / "owned-uds.json", temporary / "stdout.json"
        with stdout_path.open("wb") as stdout:
            process = subprocess.Popen([sys.executable, "-B", str(RUNNER_PATH)], cwd=REPO, env={**os.environ, "NODESCALE_N7_TREE": nodescale_tree, "FLEET_N7_REPOSITORY": str(fleet_repository), "FLEET_N7_TREE": fleet_tree, "NODESCALE_N7_INITIALIZATION_MARKER": str(marker), "NODESCALE_N7_INITIALIZATION_UDS": str(uds_file)}, stdout=stdout, stderr=subprocess.DEVNULL, start_new_session=True)
            deadline = time.monotonic() + 90
            while not marker.exists() and process.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            if not marker.exists():
                acceptance_errors.append("runner_exited_before_owned_marker" if process.poll() is not None else "owned_marker_timeout")
            else:
                try:
                    uds_paths = read_owned_uds(uds_file)
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
            if child_manifest.get("cleanup") != "zero" or child_manifest.get("runtime_residue") != "zero":
                acceptance_errors.append("term_runner_cleanup_not_reported_complete")
    if exit_code is None:
        acceptance_errors.append("term_runner_not_reaped")
    elif exit_code == 0:
        acceptance_errors.append("term_runner_succeeded")
    postflight_errors = collect_postflight_errors(runner, nodescale_before, fleet_repository, fleet_before, cargo_before, pyproject_before, uds_paths)
    acceptance_errors = sorted(set(acceptance_errors))
    if acceptance_errors or postflight_errors:
        return {"nodescale_tree": nodescale_tree, "fleet_tree": fleet_tree, "reason": "interruption_postflight_failed", "runtime_residue": "zero" if "runtime_residue" not in postflight_errors else "present", "acceptance_errors": acceptance_errors, "postflight_errors": postflight_errors}, 1
    return {"nodescale_tree": nodescale_tree, "fleet_tree": fleet_tree, "child_exit_code": exit_code, "runtime_residue": "zero", "source_worktrees": "unchanged", "cargo_lock": "unchanged", "fleet_pyproject": "unchanged", "owned_uds": "closed", "termination_marker": "test_owned_readiness", "termination_signal": signal.SIGTERM}, 0


if __name__ == "__main__":
    try:
        fields, exit_code = main()
    except Exception:
        fields, exit_code = {"reason": "internal_interruption_failure"}, 1
    print(manifest("ok" if exit_code == 0 else "failed", **fields))
    raise SystemExit(exit_code)
