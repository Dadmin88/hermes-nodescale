#!/usr/bin/env python3
"""Exact-tree, disposable N6 Keryx-binding proof runner.

This runner deliberately contains no provider/Keryx implementation.  It runs only
an exact, ignored integration selector once that selector lands in the candidate
Git tree.  All build output, test state, and optional test-owned Docker resources
are confined to one private /var/tmp runtime root and nonce-qualified prefix.
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
import subprocess
import sys
import tarfile
import tempfile
import time
import tomllib
from typing import Final, NamedTuple

REPO: Final = Path(__file__).resolve().parents[2]
BASE_PREFIX: Final = "nodescale-n6-proof"
RUN_NONCE: Final = secrets.token_hex(16)
PREFIX: Final = f"{BASE_PREFIX}-{RUN_NONCE}"
PROOF_TEST_NAME: Final = "disposable_authenticated_keryx_binding_is_durable_and_cleans_up"
_ACTIVE_PROCESSES: set[subprocess.Popen[bytes]] = set()
_TERMINATION_REAP_ERRORS: list[str] = []


class ExactSelector(NamedTuple):
    """The one integration-test target that the archived tree is allowed to run."""

    package: str
    target: str
    relative_path: str


class OwnedEndpoint(NamedTuple):
    """A secret-free TCP listener declared by the real ignored integration test."""

    address: str
    port: int


class ProofFailure(RuntimeError):
    """A deliberately non-diagnostic failure that is safe to place in JSON."""


class ProofTerminationRequested(ProofFailure):
    def __init__(self, signum: int) -> None:
        super().__init__(f"signal_{signum}")
        self.signum = signum


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256(path.read_bytes())


def run_tracked(
    args: list[str], *, cwd: Path = REPO, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.Popen(
        args,
        cwd=cwd,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    _ACTIVE_PROCESSES.add(process)
    try:
        stdout, stderr = process.communicate()
    finally:
        if process.poll() is not None:
            _ACTIVE_PROCESSES.discard(process)
    return subprocess.CompletedProcess(args, process.returncode, stdout, stderr)


def reap_owned_process(process: subprocess.Popen[bytes], errors: list[str]) -> None:
    if process.poll() is not None:
        _ACTIVE_PROCESSES.discard(process)
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait(timeout=10)
        except (ProcessLookupError, subprocess.TimeoutExpired):
            errors.append("owned_process_reap_failed")
    _ACTIVE_PROCESSES.discard(process)


def handle_termination(signum: int, _frame: object) -> None:
    errors: list[str] = []
    for process in tuple(_ACTIVE_PROCESSES):
        reap_owned_process(process, errors)
    _TERMINATION_REAP_ERRORS.extend(errors)
    raise ProofTerminationRequested(signum)


def command_output(args: list[str], *, cwd: Path = REPO) -> bytes:
    result = run_tracked(args, cwd=cwd)
    if result.returncode != 0:
        raise ProofFailure("required_command_failed")
    return result.stdout


def repository_fingerprint() -> str:
    return sha256(
        command_output(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"])
    )


def resolve_exact_tree() -> str:
    requested = os.environ.get("NODESCALE_N6_TREE", "").strip()
    if not requested:
        raise ProofFailure("candidate_tree_required")
    result = run_tracked(["git", "rev-parse", "--verify", f"{requested}^{{tree}}"])
    if result.returncode != 0:
        raise ProofFailure("candidate_tree_unavailable")
    tree = result.stdout.decode("ascii", errors="ignore").strip()
    if not re.fullmatch(r"[0-9a-f]{40}", tree):
        raise ProofFailure("candidate_tree_invalid")
    expected = run_tracked(["git", "show", f"{tree}:proofs/n6/run.py"])
    if expected.returncode != 0 or expected.stdout != Path(__file__).read_bytes():
        raise ProofFailure("runner_not_bound_to_candidate_tree")
    return tree


def extract_exact_tree(root: Path, tree: str) -> Path:
    archive = command_output(["git", "archive", "--format=tar", tree])
    source = root / "source"
    source.mkdir(mode=0o700)
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        bundle.extractall(source, filter="data")
    return source


def exact_ignored_integration_selector(source: Path) -> ExactSelector:
    """Resolve one real ignored integration target, never a workspace-wide name match."""
    selector = re.compile(rf"\bfn\s+{re.escape(PROOF_TEST_NAME)}\s*\(")
    matches: list[ExactSelector] = []
    for candidate in sorted(source.rglob("*.rs")):
        try:
            relative = candidate.relative_to(source)
            text = candidate.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue
        if "tests" not in relative.parts:
            continue
        match = selector.search(text)
        if match is None:
            continue
        attributes_match = re.search(
            r"(?s)((?:\s*#\[[^\n]*\]\s*)+)(?:pub\s+)?(?:async\s+)?$",
            text[: match.start()],
        )
        if attributes_match is None:
            continue
        attributes = attributes_match.group(1)
        ignored = re.search(r"#\[ignore(?:\s*\([^\]]*\))?\s*\]", attributes)
        package_manifest = candidate.parents[1] / "Cargo.toml"
        if not (ignored and ("#[test" in attributes or "::test" in attributes)):
            continue
        if not package_manifest.is_file():
            continue
        try:
            package = tomllib.loads(package_manifest.read_text(encoding="utf-8"))["package"]["name"]
        except (KeyError, OSError, tomllib.TOMLDecodeError, TypeError):
            continue
        if not isinstance(package, str) or not package:
            continue
        # An empty or unrelated named test cannot satisfy the lifecycle contract:
        # it must consume the proof-only readiness and sentinel inputs.
        if not all(
            variable in text
            for variable in (
                "NODESCALE_N6_PROOF_READY_MARKER",
                "NODESCALE_N6_PROOF_SECRET_SENTINEL_A",
                "NODESCALE_N6_PROOF_SECRET_SENTINEL_B",
            )
        ):
            continue
        matches.append(
            ExactSelector(
                package=package,
                target=candidate.stem,
                relative_path=relative.as_posix(),
            )
        )
    if len(matches) != 1:
        raise ProofFailure("n6_selector_missing_not_ignored_or_ambiguous")
    return matches[0]


def has_ignored_integration_selector(source: Path) -> bool:
    try:
        exact_ignored_integration_selector(source)
    except ProofFailure:
        return False
    return True


def require_selector(source: Path) -> None:
    exact_ignored_integration_selector(source)


def proof_environment(root: Path) -> dict[str, str]:
    rustflags = os.environ.get("RUSTFLAGS", "").strip()
    if "-fuse-ld=bfd" not in rustflags:
        rustflags = f"{rustflags} -C link-arg=-fuse-ld=bfd".strip()
    return {
        **os.environ,
        "RUSTFLAGS": rustflags,
        "CARGO_TARGET_DIR": str(root / "cargo-target"),
        "CARGO_INCREMENTAL": "0",
        "CARGO_NET_OFFLINE": "true",
        "NODESCALE_N6_PROOF_ROOT": str(root),
        "NODESCALE_N6_PROOF_PREFIX": PREFIX,
        "NODESCALE_N6_PROOF_READY_MARKER": str(root / "test-owned-ready.json"),
        "NODESCALE_N6_PROOF_SECRET_SENTINEL_A": secrets.token_urlsafe(48),
        "NODESCALE_N6_PROOF_SECRET_SENTINEL_B": secrets.token_urlsafe(48),
    }


def cargo_test_command(selector: ExactSelector) -> list[str]:
    return [
        "cargo",
        "test",
        "--locked",
        "--offline",
        "--package",
        selector.package,
        "--test",
        selector.target,
        PROOF_TEST_NAME,
        "--",
        "--ignored",
        "--exact",
        "--nocapture",
        "--test-threads=1",
    ]


def write_private_json(path: Path, value: object) -> None:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("ascii")
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, encoded)
        os.fsync(fd)
    finally:
        os.close(fd)


def write_initialization_marker(endpoints: tuple[OwnedEndpoint, ...]) -> None:
    marker = os.environ.get("NODESCALE_N6_INITIALIZATION_MARKER", "").strip()
    endpoints_path = os.environ.get("NODESCALE_N6_INITIALIZATION_ENDPOINTS", "").strip()
    try:
        if endpoints_path:
            path = Path(endpoints_path)
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            write_private_json(
                path,
                [{"address": item.address, "port": item.port, "transport": "tcp"} for item in endpoints],
            )
        if not marker:
            return
        path = Path(marker)
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.write_text("ready\n", encoding="ascii")
        path.chmod(0o600)
    except OSError as error:
        raise ProofFailure("initialization_marker_write_failed") from error


def parse_owned_readiness(path: Path) -> tuple[OwnedEndpoint, ...]:
    """Accept only a bounded, secret-free endpoint record from the real test."""
    try:
        raw = path.read_bytes()
        if len(raw) > 8192:
            raise ValueError("oversized")
        value = json.loads(raw)
    except (OSError, UnicodeDecodeError, ValueError, json.JSONDecodeError) as error:
        raise ProofFailure("test_owned_readiness_invalid") from error
    if not isinstance(value, dict) or set(value) != {"owned_endpoints", "phase", "prefix"}:
        raise ProofFailure("test_owned_readiness_invalid")
    if value.get("phase") != "owned" or value.get("prefix") != PREFIX:
        raise ProofFailure("test_owned_readiness_invalid")
    raw_endpoints = value.get("owned_endpoints")
    if not isinstance(raw_endpoints, list) or not raw_endpoints:
        raise ProofFailure("test_owned_readiness_invalid")
    endpoints: list[OwnedEndpoint] = []
    for endpoint in raw_endpoints:
        if not isinstance(endpoint, dict) or set(endpoint) != {"address", "port", "transport"}:
            raise ProofFailure("test_owned_readiness_invalid")
        address, port, transport = endpoint.get("address"), endpoint.get("port"), endpoint.get("transport")
        if address not in {"127.0.0.1", "::1"} or transport != "tcp" or not isinstance(port, int):
            raise ProofFailure("test_owned_readiness_invalid")
        if not 1 <= port <= 65535:
            raise ProofFailure("test_owned_readiness_invalid")
        endpoints.append(OwnedEndpoint(address=address, port=port))
    if len(set(endpoints)) != len(endpoints):
        raise ProofFailure("test_owned_readiness_invalid")
    return tuple(sorted(endpoints, key=lambda item: (item.address, item.port)))


def wait_for_test_owned_readiness(
    process: subprocess.Popen[bytes], path: Path, timeout: float = 90.0
) -> tuple[OwnedEndpoint, ...]:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if process.poll() is not None:
            raise ProofFailure("test_exited_before_owned_readiness")
        if time.monotonic() >= deadline:
            raise ProofFailure("test_owned_readiness_timeout")
        time.sleep(0.05)
    return parse_owned_readiness(path)


def docker_names(kind: str, *, prefix: str = BASE_PREFIX) -> list[str]:
    if shutil.which("docker") is None:
        return []
    if kind == "container":
        result = run_tracked(["docker", "ps", "-a", "--format", "{{.Names}}"])
    elif kind == "network":
        result = run_tracked(["docker", "network", "ls", "--format", "{{.Name}}"])
    else:
        raise ValueError(kind)
    if result.returncode != 0:
        raise ProofFailure("docker_resource_inspection_failed")
    return sorted(
        name
        for name in result.stdout.decode(errors="replace").splitlines()
        if name.startswith(f"{prefix}-")
    )


def conflicting_resources() -> list[str]:
    """Scan the entire declared namespace; cleanup itself stays nonce-exact."""
    conflicts = [f"container:{name}" for name in docker_names("container", prefix=BASE_PREFIX)]
    conflicts.extend(f"network:{name}" for name in docker_names("network", prefix=BASE_PREFIX))
    conflicts.extend(f"runtime:{path.name}" for path in Path("/var/tmp").glob(f"{BASE_PREFIX}-*"))
    return sorted(conflicts)


def port_is_free(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind(("127.0.0.1", port))
        except OSError:
            return False
    return True


def remove_exact_docker_resources(errors: list[str]) -> None:
    if shutil.which("docker") is None:
        return
    for name in docker_names("container", prefix=PREFIX):
        if run_tracked(["docker", "rm", "-f", name]).returncode != 0:
            errors.append("owned_container_cleanup_failed")
    for name in docker_names("network", prefix=PREFIX):
        if run_tracked(["docker", "network", "rm", name]).returncode != 0:
            errors.append("owned_network_cleanup_failed")


def runtime_artifact_files(root: Path) -> list[Path]:
    """Every regular file below the private root is an artifact that may retain a secret."""
    return sorted(candidate for candidate in root.rglob("*") if candidate.is_file() and not candidate.is_symlink())


def find_secret_sentinels(root: Path, sentinels: tuple[bytes, bytes]) -> list[str]:
    matches: list[str] = []
    for candidate in runtime_artifact_files(root):
        try:
            carry = b""
            found = False
            with candidate.open("rb") as artifact:
                while chunk := artifact.read(65536):
                    data = carry + chunk
                    if any(sentinel in data for sentinel in sentinels):
                        found = True
                        break
                    carry = data[-(max(len(sentinel) for sentinel in sentinels) - 1) :]
        except OSError:
            matches.append("unreadable_runtime_artifact")
            continue
        if found:
            matches.append(f"artifact:{candidate.relative_to(root)}")
    return sorted(matches)


def endpoint_is_free(endpoint: OwnedEndpoint) -> bool:
    family = socket.AF_INET6 if endpoint.address == "::1" else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            listener.bind((endpoint.address, endpoint.port))
        except OSError:
            return False
    return True


def require_exact_test_execution(result: subprocess.CompletedProcess[bytes]) -> None:
    """`--exact` can return success after executing zero tests; reject that case."""
    output = (result.stdout + result.stderr).decode("utf-8", errors="replace")
    expected = re.compile(rf"test\s+{re.escape(PROOF_TEST_NAME)}\s+\.\.\.\s+ok")
    summary = re.compile(r"test result: ok\. 1 passed; 0 failed; 0 ignored;")
    if result.returncode != 0 or not expected.search(output) or not summary.search(output):
        raise ProofFailure("n6_exact_selector_not_executed_successfully")


def cleanup_resources(root: Path | None) -> list[str]:
    errors: list[str] = []
    for process in tuple(_ACTIVE_PROCESSES):
        reap_owned_process(process, errors)
    try:
        remove_exact_docker_resources(errors)
    except ProofFailure:
        errors.append("owned_docker_cleanup_inspection_failed")
    if root is not None:
        try:
            shutil.rmtree(root)
        except FileNotFoundError:
            pass
        except OSError:
            errors.append("runtime_root_cleanup_failed")
        if root.exists():
            errors.append("runtime_root_remains")
    return errors


def evidence(status: str, *, candidate_tree: str | None, reason: str | None = None, **extra: object) -> dict[str, object]:
    document: dict[str, object] = {
        "candidate_tree": candidate_tree,
        "proof": "n6_authenticated_keryx_binding",
        "sanitized": True,
        "status": status,
    }
    if reason is not None:
        document["reason"] = reason
    document.update(extra)
    return document


def main() -> tuple[dict[str, object], int]:
    root: Path | None = None
    exact_tree: str | None = None
    repository_before: str | None = None
    cargo_lock_before: str | None = None
    sentinels: tuple[bytes, bytes] | None = None
    selector: ExactSelector | None = None
    owned_endpoints: tuple[OwnedEndpoint, ...] = ()
    secret_sentinel_residue = False
    failure: ProofFailure | None = None
    termination_signal: int | None = None
    cleanup_errors: list[str] = []
    previous_umask: int | None = None
    _TERMINATION_REAP_ERRORS.clear()
    try:
        for command in ("cargo", "git", "ld.bfd"):
            if shutil.which(command) is None:
                raise ProofFailure("required_command_unavailable")
        if conflicting_resources():
            raise ProofFailure("preexisting_n6_resources")
        exact_tree = resolve_exact_tree()
        repository_before = repository_fingerprint()
        cargo_lock_before = sha256_file(REPO / "Cargo.lock")
        # Install handlers immediately before the first owned resource, then
        # make every file beneath it private by default.
        signal.signal(signal.SIGTERM, handle_termination)
        signal.signal(signal.SIGINT, handle_termination)
        previous_umask = os.umask(0o077)
        root = Path(tempfile.mkdtemp(prefix=f"{PREFIX}-", dir="/var/tmp"))
        root.chmod(0o700)
        source = extract_exact_tree(root, exact_tree)
        selector = exact_ignored_integration_selector(source)
        environment = proof_environment(root)
        sentinels = (
            environment["NODESCALE_N6_PROOF_SECRET_SENTINEL_A"].encode("ascii"),
            environment["NODESCALE_N6_PROOF_SECRET_SENTINEL_B"].encode("ascii"),
        )
        test_process = subprocess.Popen(
            cargo_test_command(selector),
            cwd=source,
            env=environment,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            start_new_session=True,
        )
        _ACTIVE_PROCESSES.add(test_process)
        try:
            owned_endpoints = wait_for_test_owned_readiness(
                test_process, Path(environment["NODESCALE_N6_PROOF_READY_MARKER"])
            )
            # This marker is intentionally downstream of the test-owned DB,
            # listener, and registered-handler readiness record.
            write_initialization_marker(owned_endpoints)
            stdout, stderr = test_process.communicate()
        finally:
            if test_process.poll() is not None:
                _ACTIVE_PROCESSES.discard(test_process)
        require_exact_test_execution(
            subprocess.CompletedProcess(cargo_test_command(selector), test_process.returncode, stdout, stderr)
        )
    except ProofTerminationRequested as error:
        failure = error
        termination_signal = error.signum
    except ProofFailure as error:
        failure = error
    except Exception:
        failure = ProofFailure("internal_runner_failure")
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        if previous_umask is not None:
            os.umask(previous_umask)
        cleanup_errors.extend(_TERMINATION_REAP_ERRORS)
        for process in tuple(_ACTIVE_PROCESSES):
            reap_owned_process(process, cleanup_errors)
        if root is not None and sentinels is not None:
            secret_sentinel_residue = bool(find_secret_sentinels(root, sentinels))
        cleanup_errors.extend(cleanup_resources(root))

    postflight_errors: list[str] = []
    for endpoint in owned_endpoints:
        if not endpoint_is_free(endpoint):
            postflight_errors.append("owned_listener_remained")
    try:
        if conflicting_resources():
            postflight_errors.append("runtime_residue")
    except ProofFailure:
        postflight_errors.append("runtime_residue_inspection_failed")
    try:
        repository_after = repository_fingerprint()
        if repository_before is not None and repository_after != repository_before:
            postflight_errors.append("source_worktree_changed")
    except ProofFailure:
        postflight_errors.append("source_worktree_inspection_failed")
    try:
        if cargo_lock_before is not None and cargo_lock_before != sha256_file(REPO / "Cargo.lock"):
            postflight_errors.append("cargo_lock_changed")
    except OSError:
        postflight_errors.append("cargo_lock_inspection_failed")
    if secret_sentinel_residue:
        postflight_errors.append("secret_sentinel_residue")
    if cleanup_errors:
        postflight_errors.extend(sorted(set(cleanup_errors)))
    postflight_errors = sorted(set(postflight_errors))

    if failure is not None or postflight_errors:
        return (
            evidence(
                "failed",
                candidate_tree=exact_tree,
                reason=str(failure or ProofFailure("postflight_failed")),
                cleanup="zero" if not cleanup_errors else "failed",
                postflight="exact" if not postflight_errors else "failed",
                runtime_residue="zero" if "runtime_residue" not in postflight_errors else "present",
                secret_artifact_scan="absent" if not secret_sentinel_residue else "residue_detected",
                termination_signal=termination_signal,
                postflight_errors=postflight_errors,
            ),
            1,
        )
    return (
        evidence(
            "ok",
            candidate_tree=exact_tree,
            cargo_locked=True,
            cargo_target="private_runtime_root",
            exact_selector=PROOF_TEST_NAME,
            exact_selector_target=selector.relative_path if selector is not None else None,
            linker="bfd",
            runtime_residue="zero",
            secret_artifact_scan="absent",
            source_worktree="unchanged",
            cargo_lock="unchanged",
            owned_endpoints="closed",
            intentional_residue_exception="none",
        ),
        0,
    )


if __name__ == "__main__":
    try:
        manifest, exit_code = main()
    except Exception:
        manifest, exit_code = evidence(
            "failed", candidate_tree=None, reason="internal_runner_failure"
        ), 1
    print(json.dumps(manifest, sort_keys=True, separators=(",", ":")))
    raise SystemExit(exit_code)
