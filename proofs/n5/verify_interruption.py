#!/usr/bin/env python3
"""Drive and retain the exact-tree N5 TERM-cleanup acceptance result."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
from pathlib import Path
import selectors
import signal
import socket
import subprocess
import sys
import tempfile
import time

PROOFS = Path(__file__).resolve().parent
RUNNER_PATH = PROOFS / "run.py"
REPO = PROOFS.parents[1]
MARKER = "N5 proof runtime initialized"


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_wrapper_provenance(repo: Path, requested_tree: str, wrapper_path: Path) -> str:
    resolved = subprocess.check_output(
        ["git", "rev-parse", "--verify", f"{requested_tree}^{{tree}}"],
        cwd=repo,
        stderr=subprocess.DEVNULL,
        text=True,
    ).strip()
    expected = subprocess.check_output(
        ["git", "show", f"{resolved}:proofs/n5/verify_interruption.py"],
        cwd=repo,
        stderr=subprocess.DEVNULL,
    )
    if wrapper_path.read_bytes() != expected:
        raise RuntimeError("interruption wrapper does not match requested tree")
    return resolved


def load_runner():
    spec = importlib.util.spec_from_file_location("nodescale_n5_interrupt_runner", RUNNER_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("unable to load N5 proof runner")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def terminate_and_reap(process, term_timeout: int) -> tuple[int, str | None]:
    process.send_signal(signal.SIGTERM)
    try:
        return process.wait(timeout=term_timeout), None
    except subprocess.TimeoutExpired:
        process.kill()
        exit_code = process.wait()
        return exit_code, f"proof timed out after TERM and was killed (exit {exit_code})"


def collect_postflight_errors(runner, repository_before: str, lock_before: str, host_before: str) -> list[str]:
    errors: list[str] = []
    conflicts = runner.conflicting_resources()
    if conflicts:
        errors.append(f"runtime residue: {conflicts}")
    for port in (runner.HEADSCALE_PORT, runner.INGRESS_PORT):
        if not port_is_free(port):
            errors.append(f"listener remained on port {port}")
    repository_after = runner.command_hash(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"]
    )
    if repository_after != repository_before:
        errors.append("repository status changed")
    if sha256(REPO / "Cargo.lock") != lock_before:
        errors.append("Cargo.lock changed")
    time.sleep(1.0)
    if runner.host_invariant() != host_before:
        errors.append("host-network invariant changed")
    return errors


def main() -> int:
    requested_tree = os.environ.get("NODESCALE_N5_TREE", "").strip()
    if not requested_tree:
        raise RuntimeError("NODESCALE_N5_TREE is required")

    exact_tree = verify_wrapper_provenance(REPO, requested_tree, Path(__file__).resolve())
    runner = load_runner()
    runner_tree = runner.resolve_exact_tree()
    if runner_tree != exact_tree:
        raise RuntimeError("resolved runner tree does not match verified wrapper tree")
    conflicts = runner.conflicting_resources()
    if conflicts:
        raise RuntimeError(f"pre-existing N5 proof resources: {conflicts}")
    for port in (runner.HEADSCALE_PORT, runner.INGRESS_PORT):
        if not port_is_free(port):
            raise RuntimeError(f"proof port is already in use: {port}")

    repository_before = runner.command_hash(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"]
    )
    lock_before = sha256(REPO / "Cargo.lock")
    host_before = runner.host_invariant()

    with tempfile.TemporaryDirectory(prefix="nodescale-n5-interrupt-log-", dir="/var/tmp") as directory:
        stdout_path = Path(directory) / "stdout"
        with stdout_path.open("wb") as stdout:
            process = subprocess.Popen(
                [sys.executable, "-B", str(RUNNER_PATH)],
                cwd=REPO,
                env={**os.environ, "NODESCALE_N5_TREE": exact_tree},
                stdout=stdout,
                stderr=subprocess.PIPE,
            )
            if process.stderr is None:
                raise RuntimeError("proof stderr pipe is unavailable")
            selector = selectors.DefaultSelector()
            selector.register(process.stderr, selectors.EVENT_READ)
            deadline = time.monotonic() + 30
            observed = b""
            while MARKER.encode() not in observed:
                if process.poll() is not None:
                    observed += process.stderr.read()
                    raise RuntimeError(
                        f"proof exited before interruption marker: {observed.decode(errors='replace')[-2000:]}"
                    )
                if time.monotonic() >= deadline:
                    process.kill()
                    process.wait(timeout=10)
                    raise RuntimeError("timed out waiting for interruption marker")
                if selector.select(timeout=0.25):
                    observed += os.read(process.stderr.fileno(), 4096)
            exit_code, termination_error = terminate_and_reap(process, 120)
            observed += process.stderr.read()
            diagnostic = observed.decode(errors="replace")[-2000:]
        acceptance_errors: list[str] = []
        if termination_error:
            acceptance_errors.append(termination_error)
        if exit_code == 0:
            acceptance_errors.append("TERM proof unexpectedly succeeded")
        if stdout_path.stat().st_size != 0:
            acceptance_errors.append("terminated proof emitted a success manifest")
        if "received signal 15" not in diagnostic:
            acceptance_errors.append("terminated proof did not report signal 15 cleanup")

    postflight_errors = collect_postflight_errors(
        runner, repository_before, lock_before, host_before
    )
    if acceptance_errors + postflight_errors:
        raise RuntimeError("; ".join(acceptance_errors + postflight_errors))

    print(
        json.dumps(
            {
                "candidate_tree": exact_tree,
                "child_exit_code": exit_code,
                "host_network_invariant": "exact",
                "repository_invariant": "exact",
                "runtime_residue": "zero",
                "termination_marker": MARKER,
                "termination_signal": signal.SIGTERM,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"N5 interruption proof failed: {error}", file=sys.stderr)
        raise SystemExit(1)
