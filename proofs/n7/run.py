#!/usr/bin/env python3
"""Exact-tree, two-repository N7 Fleet-projection proof runner.

Only immutable Nodescale and Fleet trees are accepted. Both inputs are copied by
``git archive`` into private roots; the sole Rust command runs from the archived
Nodescale tree and gets its Fleet service input only from the separately archived
Fleet tree. The ignored selector, rather than this wrapper, exercises SO_PEERCRED
for the configured Nodescale UID, the four-byte big-endian protocol, and the
managed-projection JSON contract (fleet.managed-projection.v1: capabilities,
apply, inspect). SIGTERM reaps the owned process group, closes every owned listener
and UDS path, scans both private roots for secret sentinels and runtime residue,
and emits a failed—not success manifest—when interrupted.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
from typing import Final, NamedTuple

REPO: Final = Path(__file__).resolve().parents[2]
BASE_PREFIX: Final = "nodescale-n7-proof"
FLEET_BASE_PREFIX: Final = "fleet-n7-proof"
RUN_NONCE: Final = secrets.token_hex(16)
PREFIX: Final = f"{BASE_PREFIX}-{RUN_NONCE}"
FLEET_PREFIX: Final = f"{FLEET_BASE_PREFIX}-{RUN_NONCE}"
PROOF_TEST_NAME: Final = "disposable_authenticated_fleet_projection_is_durable_and_cleans_up"
FLEET_HARNESS_FILES: Final = (
    "hermes_fleet/local_control.py",
    "hermes_fleet/managed_projection.py",
    "hermes_fleet/managed_service.py",
)
_ACTIVE_PROCESSES: set[subprocess.Popen[bytes]] = set()
_TERMINATION_REAP_ERRORS: list[str] = []


class ProofFailure(RuntimeError):
    """A deliberately secret-free failure reason safe for the JSON manifest."""


class ProofTerminationRequested(ProofFailure):
    def __init__(self, signum: int) -> None:
        super().__init__(f"signal_{signum}")
        self.signum = signum


class ExactSelector(NamedTuple):
    package: str
    target: str
    relative_path: str


class RepositoryBinding(NamedTuple):
    repository: Path
    tree: str
    worktree_fingerprint: str
    lockfile_digest: str


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256(path.read_bytes())


def run_tracked(args: list[str], *, cwd: Path, env: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.Popen(args, cwd=cwd, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
    _ACTIVE_PROCESSES.add(process)
    try:
        stdout, stderr = process.communicate()
    finally:
        if process.poll() is not None:
            _ACTIVE_PROCESSES.discard(process)
    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)


def command_output(args: list[str], *, cwd: Path) -> bytes:
    result = run_tracked(args, cwd=cwd)
    if result.returncode != 0:
        raise ProofFailure("required_command_failed")
    return result.stdout


def reap_owned_process(process: subprocess.Popen[bytes], errors: list[str]) -> None:
    if process.poll() is not None:
        _ACTIVE_PROCESSES.discard(process)
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)  # process group, including test-owned Fleet service
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            errors.append("owned_process_group_reap_failed")
    _ACTIVE_PROCESSES.discard(process)


def handle_termination(signum: int, _frame: object) -> None:
    errors: list[str] = []
    for process in tuple(_ACTIVE_PROCESSES):
        reap_owned_process(process, errors)
    _TERMINATION_REAP_ERRORS.extend(errors)
    raise ProofTerminationRequested(signum)


def repository_fingerprint(repository: Path) -> str:
    return sha256(command_output(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], cwd=repository))


def resolve_repository(path_value: str) -> Path:
    if not path_value.strip():
        raise ProofFailure("fleet_repository_required")
    requested = Path(path_value).expanduser().resolve()
    if not requested.is_dir():
        raise ProofFailure("fleet_repository_unavailable")
    try:
        actual = Path(command_output(["git", "rev-parse", "--show-toplevel"], cwd=requested).decode("utf-8").strip()).resolve()
    except (OSError, UnicodeDecodeError, ProofFailure) as error:
        raise ProofFailure("fleet_repository_unavailable") from error
    if actual != requested:
        raise ProofFailure("fleet_repository_must_be_worktree_root")
    return actual


def resolve_tree(repository: Path, requested: str, missing_reason: str, unavailable_reason: str) -> str:
    if not requested.strip():
        raise ProofFailure(missing_reason)
    result = run_tracked(["git", "rev-parse", "--verify", f"{requested}^{{tree}}"], cwd=repository)
    if result.returncode != 0:
        raise ProofFailure(unavailable_reason)
    tree = result.stdout.decode("ascii", errors="ignore").strip()
    if not re.fullmatch(r"[0-9a-f]{40,64}", tree):
        raise ProofFailure(unavailable_reason)
    return tree


def git_blob(repository: Path, tree: str, relative: str) -> bytes:
    result = run_tracked(["git", "show", f"{tree}:{relative}"], cwd=repository)
    if result.returncode != 0:
        raise ProofFailure("candidate_required_file_missing")
    return result.stdout


def resolve_exact_trees() -> tuple[Path, str, Path, str]:
    nodescale_tree = resolve_tree(REPO, os.environ.get("NODESCALE_N7_TREE", ""), "candidate_tree_required", "candidate_tree_unavailable")
    # Bind the running runner bytes before creating either private runtime root.
    if git_blob(REPO, nodescale_tree, "proofs/n7/run.py") != Path(__file__).read_bytes():
        raise ProofFailure("runner_not_bound_to_candidate_tree")
    fleet_repository = resolve_repository(os.environ.get("FLEET_N7_REPOSITORY", ""))
    fleet_tree = resolve_tree(fleet_repository, os.environ.get("FLEET_N7_TREE", ""), "fleet_tree_required", "fleet_tree_unavailable")
    # These are the only Fleet adapter modules the selector is allowed to use.
    for relative in FLEET_HARNESS_FILES:
        git_blob(fleet_repository, fleet_tree, relative)
    return REPO, nodescale_tree, fleet_repository, fleet_tree


def archive_exact_tree(root: Path, repository: Path, tree: str) -> tuple[Path, str]:
    archive = command_output(["git", "archive", "--format=tar", tree], cwd=repository)
    source = root / "source"
    source.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        bundle.extractall(source, filter="data")
    source.chmod(0o700)
    return source, sha256(archive)


def require_fleet_archive(source: Path) -> None:
    for relative in FLEET_HARNESS_FILES:
        path = source / relative
        if not path.is_file() or path.is_symlink():
            raise ProofFailure("fleet_archive_harness_missing")


def exact_ignored_integration_selector(source: Path) -> ExactSelector:
    """Return the one ignored Rust integration target; no workspace fallback exists."""
    pattern = re.compile(rf"\bfn\s+{re.escape(PROOF_TEST_NAME)}\s*\(")
    matches: list[ExactSelector] = []
    required_inputs = (
        "NODESCALE_N7_PROOF_READY_MARKER", "NODESCALE_N7_PROOF_SECRET_SENTINEL_A",
        "NODESCALE_N7_PROOF_SECRET_SENTINEL_B", "NODESCALE_N7_PROOF_PREFIX",
        "NODESCALE_N7_PROOF_ROOT", "FLEET_N7_PROOF_ROOT",
    )
    for candidate in sorted(source.rglob("*.rs")):
        try:
            relative, text = candidate.relative_to(source), candidate.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "tests" not in relative.parts:
            continue
        match = pattern.search(text)
        if match is None:
            continue
        attributes_match = re.search(r"(?s)((?:\s*#\[[^\n]*\]\s*)+)(?:pub\s+)?(?:async\s+)?$", text[:match.start()])
        if attributes_match is None:
            continue
        attributes = attributes_match.group(1)
        manifest = candidate.parents[1] / "Cargo.toml"
        if not (re.search(r"#\[ignore(?:\s*\([^\]]*\))?\s*\]", attributes) and ("#[test" in attributes or "::test" in attributes) and manifest.is_file()):
            continue
        if not all(name in text for name in required_inputs):
            continue
        # The selector must visibly own the actual protocol gates: SO_PEERCRED,
        # four-byte big-endian 32768 framing, duplicate/numeric JSON rejection,
        # and fleet.managed-projection.v1 capabilities/apply/inspect.  This is a
        # preflight for executable test code, not a substitute for running it.
        if not all(token in text for token in ("SO_PEERCRED", "32768", "fleet.managed-projection.v1", "capabilities", "apply", "inspect", "duplicate", "numeric", "bearer")):
            continue
        try:
            package = tomllib.loads(manifest.read_text(encoding="utf-8"))["package"]["name"]
        except (KeyError, OSError, tomllib.TOMLDecodeError, TypeError):
            continue
        if isinstance(package, str) and package:
            matches.append(ExactSelector(package, candidate.stem, relative.as_posix()))
    if len(matches) != 1:
        raise ProofFailure("n7_selector_missing_not_ignored_or_ambiguous")
    return matches[0]


def has_ignored_integration_selector(source: Path) -> bool:
    try:
        exact_ignored_integration_selector(source)
    except ProofFailure:
        return False
    return True


def cargo_test_command(selector: ExactSelector) -> list[str]:
    return ["cargo", "test", "--locked", "--offline", "--package", selector.package, "--test", selector.target, PROOF_TEST_NAME, "--", "--ignored", "--exact", "--nocapture", "--test-threads=1"]


def proof_environment(nodescale_root: Path, fleet_source: Path) -> dict[str, str]:
    rustflags = os.environ.get("RUSTFLAGS", "").strip()
    if "-fuse-ld=bfd" not in rustflags:
        rustflags = f"{rustflags} -C link-arg=-fuse-ld=bfd".strip()
    return {**os.environ, "RUSTFLAGS": rustflags, "CARGO_TARGET_DIR": str(nodescale_root / "cargo-target"), "CARGO_INCREMENTAL": "0", "CARGO_NET_OFFLINE": "true", "NODESCALE_N7_PROOF_ROOT": str(nodescale_root), "FLEET_N7_PROOF_ROOT": str(fleet_source), "NODESCALE_N7_PROOF_PREFIX": PREFIX, "FLEET_N7_PROOF_PREFIX": FLEET_PREFIX, "NODESCALE_N7_PROOF_READY_MARKER": str(nodescale_root / "test-owned-ready.json"), "NODESCALE_N7_PROOF_SECRET_SENTINEL_A": secrets.token_urlsafe(48), "NODESCALE_N7_PROOF_SECRET_SENTINEL_B": secrets.token_urlsafe(48)}


def parse_owned_readiness(path: Path, fleet_root: Path) -> tuple[Path, ...]:
    try:
        raw = path.read_bytes()
        if len(raw) > 8192:
            raise ValueError("oversized")
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ProofFailure("test_owned_readiness_invalid") from error
    if not isinstance(value, dict) or set(value) != {"owned_uds_paths", "phase", "prefix"} or value.get("phase") != "owned" or value.get("prefix") != PREFIX:
        raise ProofFailure("test_owned_readiness_invalid")
    raw_paths = value.get("owned_uds_paths")
    if not isinstance(raw_paths, list) or not raw_paths:
        raise ProofFailure("test_owned_readiness_invalid")
    resolved: list[Path] = []
    for raw_path in raw_paths:
        if not isinstance(raw_path, str) or not raw_path:
            raise ProofFailure("test_owned_readiness_invalid")
        path_value = Path(raw_path)
        if not path_value.is_absolute() or path_value.parent.resolve() != fleet_root.resolve():
            raise ProofFailure("test_owned_readiness_invalid")
        try:
            mode = path_value.lstat().st_mode
        except OSError as error:
            raise ProofFailure("test_owned_readiness_invalid") from error
        if not stat.S_ISSOCK(mode):
            raise ProofFailure("test_owned_readiness_invalid")
        resolved.append(path_value)
    if len(set(resolved)) != len(resolved):
        raise ProofFailure("test_owned_readiness_invalid")
    return tuple(sorted(resolved))


def wait_for_test_owned_readiness(process: subprocess.Popen[bytes], path: Path, fleet_root: Path, timeout: float = 90.0) -> tuple[Path, ...]:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if process.poll() is not None:
            raise ProofFailure("test_exited_before_owned_readiness")
        if time.monotonic() >= deadline:
            raise ProofFailure("test_owned_readiness_timeout")
        time.sleep(0.05)
    return parse_owned_readiness(path, fleet_root)


def write_private_json(path: Path, value: object) -> None:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)


def write_initialization_marker(uds_paths: tuple[Path, ...]) -> None:
    marker = os.environ.get("NODESCALE_N7_INITIALIZATION_MARKER", "").strip()
    paths = os.environ.get("NODESCALE_N7_INITIALIZATION_UDS", "").strip()
    try:
        if paths:
            write_private_json(Path(paths), {"owned_uds_paths": [str(item) for item in uds_paths]})
        if marker:
            destination = Path(marker)
            destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            destination.write_text("ready\n", encoding="ascii")
            destination.chmod(0o600)
    except OSError as error:
        raise ProofFailure("initialization_marker_write_failed") from error


def runtime_artifact_files(root: Path) -> list[Path]:
    return sorted(item for item in root.rglob("*") if item.is_file() and not item.is_symlink())


def find_secret_sentinels(roots: tuple[Path, ...], sentinels: tuple[bytes, bytes]) -> list[str]:
    matches: list[str] = []
    overlap = max(len(item) for item in sentinels) - 1
    for root in roots:
        for candidate in runtime_artifact_files(root):
            try:
                carry = b""
                with candidate.open("rb") as artifact:
                    while chunk := artifact.read(65536):
                        data = carry + chunk
                        if any(sentinel in data for sentinel in sentinels):
                            matches.append("secret_runtime_artifact")
                            break
                        carry = data[-overlap:] if overlap else b""
            except OSError:
                matches.append("unreadable_runtime_artifact")
    return sorted(set(matches))


def uds_is_closed(path: Path) -> bool:
    if path.exists() or path.is_symlink():
        return False
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        client.settimeout(0.2)
        return client.connect_ex(os.fspath(path)) != 0
    finally:
        client.close()


def conflicting_resources() -> list[str]:
    resources: list[str] = []
    for prefix in (BASE_PREFIX, FLEET_BASE_PREFIX):
        resources.extend(f"runtime:{path.name}" for path in Path("/var/tmp").glob(f"{prefix}-*"))
    return sorted(resources)


def cleanup_resources(roots: tuple[Path | None, Path | None]) -> list[str]:
    errors: list[str] = []
    for process in tuple(_ACTIVE_PROCESSES):
        reap_owned_process(process, errors)
    for root in roots:
        if root is None:
            continue
        try:
            shutil.rmtree(root)
        except FileNotFoundError:
            pass
        except OSError:
            errors.append("runtime_root_cleanup_failed")
        if root.exists():
            errors.append("runtime_root_remains")
    return errors


def require_exact_test_execution(result: subprocess.CompletedProcess[bytes]) -> None:
    output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
    expected = re.compile(rf"test\s+{re.escape(PROOF_TEST_NAME)}\s+\.\.\.\s+ok")
    summary = re.compile(r"test result: ok\. 1 passed; 0 failed; 0 ignored;")
    if result.returncode != 0 or not expected.search(output) or not summary.search(output):
        raise ProofFailure("n7_exact_selector_not_executed_successfully")


def evidence(status: str, *, nodescale_tree: str | None, fleet_tree: str | None, reason: str | None = None, **extra: object) -> dict[str, object]:
    value: dict[str, object] = {"proof": "n7_authenticated_fleet_projection", "sanitized": True, "status": status, "nodescale_tree": nodescale_tree, "fleet_tree": fleet_tree}
    if reason is not None:
        value["reason"] = reason
    value.update(extra)
    return value


def main() -> tuple[dict[str, object], int]:
    nodescale_root: Path | None = None
    fleet_root: Path | None = None
    nodescale_tree: str | None = None
    fleet_tree: str | None = None
    nodescale_before: RepositoryBinding | None = None
    fleet_before: RepositoryBinding | None = None
    sentinels: tuple[bytes, bytes] | None = None
    uds_paths: tuple[Path, ...] = ()
    selector: ExactSelector | None = None
    nodescale_archive_digest: str | None = None
    fleet_archive_digest: str | None = None
    failure: ProofFailure | None = None
    termination_signal: int | None = None
    cleanup_errors: list[str] = []
    secret_residue = False
    previous_umask: int | None = None
    _TERMINATION_REAP_ERRORS.clear()
    try:
        for command in ("cargo", "git", "ld.bfd"):
            if shutil.which(command) is None:
                raise ProofFailure("required_command_unavailable")
        if conflicting_resources():
            raise ProofFailure("preexisting_n7_resources")
        nodescale_repo, nodescale_tree, fleet_repo, fleet_tree = resolve_exact_trees()
        nodescale_before = RepositoryBinding(nodescale_repo, nodescale_tree, repository_fingerprint(nodescale_repo), sha256_file(nodescale_repo / "Cargo.lock"))
        fleet_before = RepositoryBinding(fleet_repo, fleet_tree, repository_fingerprint(fleet_repo), sha256_file(fleet_repo / "pyproject.toml"))
        signal.signal(signal.SIGTERM, handle_termination)
        signal.signal(signal.SIGINT, handle_termination)
        previous_umask = os.umask(0o077)
        nodescale_root = Path(tempfile.mkdtemp(prefix=f"{PREFIX}-", dir="/var/tmp")); nodescale_root.chmod(0o700)
        fleet_root = Path(tempfile.mkdtemp(prefix=f"{FLEET_PREFIX}-", dir="/var/tmp")); fleet_root.chmod(0o700)
        nodescale_source, nodescale_archive_digest = archive_exact_tree(nodescale_root, nodescale_repo, nodescale_tree)
        fleet_source, fleet_archive_digest = archive_exact_tree(fleet_root, fleet_repo, fleet_tree)
        require_fleet_archive(fleet_source)
        selector = exact_ignored_integration_selector(nodescale_source)
        environment = proof_environment(nodescale_root, fleet_source)
        sentinels = (environment["NODESCALE_N7_PROOF_SECRET_SENTINEL_A"].encode("ascii"), environment["NODESCALE_N7_PROOF_SECRET_SENTINEL_B"].encode("ascii"))
        test_process = subprocess.Popen(cargo_test_command(selector), cwd=nodescale_source, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        _ACTIVE_PROCESSES.add(test_process)
        try:
            uds_paths = wait_for_test_owned_readiness(test_process, Path(environment["NODESCALE_N7_PROOF_READY_MARKER"]), fleet_source)
            write_initialization_marker(uds_paths)
            stdout, stderr = test_process.communicate()
        finally:
            if test_process.poll() is not None:
                _ACTIVE_PROCESSES.discard(test_process)
        require_exact_test_execution(subprocess.CompletedProcess(cargo_test_command(selector), test_process.returncode, stdout, stderr))
    except ProofTerminationRequested as error:
        failure, termination_signal = error, error.signum
    except ProofFailure as error:
        failure = error
    except Exception:
        failure = ProofFailure("internal_runner_failure")
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN); signal.signal(signal.SIGINT, signal.SIG_IGN)
        if previous_umask is not None:
            os.umask(previous_umask)
        cleanup_errors.extend(_TERMINATION_REAP_ERRORS)
        for process in tuple(_ACTIVE_PROCESSES):
            reap_owned_process(process, cleanup_errors)
        if nodescale_root is not None and fleet_root is not None and sentinels is not None:
            secret_residue = bool(find_secret_sentinels((nodescale_root, fleet_root), sentinels))
        cleanup_errors.extend(cleanup_resources((nodescale_root, fleet_root)))
    postflight_errors: list[str] = []
    if any(not uds_is_closed(path) for path in uds_paths):
        postflight_errors.append("owned_uds_remained")
    if conflicting_resources():
        postflight_errors.append("runtime_residue")
    for binding, lockfile, worktree_error, lock_error in ((nodescale_before, "Cargo.lock", "nodescale_worktree_changed", "cargo_lock_changed"), (fleet_before, "pyproject.toml", "fleet_worktree_changed", "fleet_pyproject_changed")):
        if binding is None:
            continue
        try:
            if repository_fingerprint(binding.repository) != binding.worktree_fingerprint:
                postflight_errors.append(worktree_error)
            if sha256_file(binding.repository / lockfile) != binding.lockfile_digest:
                postflight_errors.append(lock_error)
        except (OSError, ProofFailure):
            postflight_errors.append("source_postflight_inspection_failed")
    if secret_residue:
        postflight_errors.append("secret_sentinel_residue")
    postflight_errors.extend(cleanup_errors)
    postflight_errors = sorted(set(postflight_errors))
    common = {"cleanup": "zero" if not cleanup_errors else "failed", "runtime_residue": "zero" if "runtime_residue" not in postflight_errors else "present", "secret_artifact_scan": "absent" if not secret_residue else "residue_detected", "termination_signal": termination_signal}
    if failure is not None or postflight_errors:
        return evidence("failed", nodescale_tree=nodescale_tree, fleet_tree=fleet_tree, reason=str(failure or ProofFailure("postflight_failed")), postflight_errors=postflight_errors, **common), 1
    return evidence("ok", nodescale_tree=nodescale_tree, fleet_tree=fleet_tree, nodescale_tree_digest=nodescale_archive_digest, fleet_tree_digest=fleet_archive_digest, cargo_locked=True, cargo_target="private_nodescale_runtime_root", exact_selector=PROOF_TEST_NAME, exact_selector_target=selector.relative_path if selector else None, fleet_source="private_archive", source_worktrees="unchanged", cargo_lock="unchanged", fleet_pyproject="unchanged", owned_uds="closed", intentional_residue_exception="none", **common), 0


if __name__ == "__main__":
    try:
        manifest, exit_code = main()
    except Exception:
        manifest, exit_code = evidence("failed", nodescale_tree=None, fleet_tree=None, reason="internal_runner_failure"), 1
    print(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
    raise SystemExit(exit_code)
