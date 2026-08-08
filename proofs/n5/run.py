#!/usr/bin/env python3
"""Retained N5 disposable ingress-to-Headscale join proof."""

from __future__ import annotations

import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import shutil
import signal
import socket
import sqlite3
import subprocess
import sys
import tarfile
import tempfile
import time

REPO = Path(__file__).resolve().parents[2]
LOCK = Path(__file__).with_name("images.lock")
BASE_PREFIX = "nodescale-n5-proof"
RUN_NONCE = secrets.token_hex(8)
PREFIX = f"{BASE_PREFIX}-{RUN_NONCE}"
NETWORK = f"{PREFIX}-network"
HEADSCALE = f"{PREFIX}-headscale"
INGRESS = f"{PREFIX}-ingress"
TAILSCALE = f"{PREFIX}-tailscale"
REDEEMERS = [f"{PREFIX}-redeem-a", f"{PREFIX}-redeem-b", f"{PREFIX}-replay"]
HEADSCALE_PORT = 18443
INGRESS_PORT = 19443
PLATFORM = "linux/amd64"
PROOF_TEST_NAME = "disposable_join_confirms_identity_activates_revokes_and_cleans_up"
_ACTIVE_PROCESSES: set[subprocess.Popen[bytes]] = set()


class ProofTerminationRequested(RuntimeError):
    pass


def handle_termination(signum: int, _frame: object) -> None:
    for process in tuple(_ACTIVE_PROCESSES):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    raise ProofTerminationRequested(f"received signal {signum}")


def run(
    args: list[str],
    *,
    check: bool = True,
    capture: bool = True,
    env: dict[str, str] | None = None,
    cwd: Path = REPO,
) -> subprocess.CompletedProcess[bytes]:
    process = subprocess.Popen(
        args,
        cwd=cwd,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        env=env,
        start_new_session=True,
    )
    _ACTIVE_PROCESSES.add(process)
    try:
        stdout, stderr = process.communicate()
    finally:
        if process.poll() is not None:
            _ACTIVE_PROCESSES.discard(process)
    result = subprocess.CompletedProcess(args, process.returncode, stdout, stderr)
    if check and process.returncode != 0:
        raise subprocess.CalledProcessError(
            process.returncode,
            args,
            output=stdout,
            stderr=stderr,
        )
    return result


def docker(*args: str, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    command = list(args)
    if command and command[0] in {"pull", "run"}:
        command[1:1] = ["--platform", PLATFORM]
    return run(["docker", *command], check=check)


def assert_image_platform(image: str) -> None:
    actual = docker(
        "image", "inspect", "--format", "{{.Os}}/{{.Architecture}}", image
    ).stdout.decode().strip()
    if actual != PLATFORM:
        raise RuntimeError(f"image platform mismatch for {image}: {actual}")


def load_images() -> tuple[str, str, str]:
    values: dict[str, str] = {}
    for raw in LOCK.read_text(encoding="utf-8").splitlines():
        if raw and not raw.startswith("#"):
            key, value = raw.split("=", 1)
            values[key] = value
    return (
        values["HEADSCALE_IMAGE"],
        values["TAILSCALE_IMAGE"],
        values["INGRESS_RUNTIME_IMAGE"],
    )


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def resolve_exact_tree() -> str:
    requested = os.environ.get("NODESCALE_N5_TREE")
    if not requested:
        raise RuntimeError("NODESCALE_N5_TREE must name the immutable candidate tree")
    tree = run(["git", "rev-parse", f"{requested}^{{tree}}"]).stdout.decode().strip()
    if len(tree) != 40:
        raise RuntimeError("candidate tree did not resolve to a full Git object ID")
    for relative in ["proofs/n5/run.py", "proofs/n5/images.lock"]:
        expected = run(["git", "show", f"{tree}:{relative}"]).stdout
        if (REPO / relative).read_bytes() != expected:
            raise RuntimeError(f"ambient {relative} does not match candidate tree {tree}")
    return tree


def extract_exact_tree(root: Path, tree: str) -> Path:
    source = root / "source"
    source.mkdir(mode=0o700)
    archive = run(["git", "archive", "--format=tar", tree]).stdout
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:") as bundle:
        bundle.extractall(source, filter="data")
    return source


def command_hash(args: list[str]) -> str:
    return sha256(run(args).stdout)


def normalized_ip_address_hash() -> str:
    value = json.loads(run(["ip", "-j", "address", "show"]).stdout)

    def strip_dynamic(item: object) -> object:
        if isinstance(item, dict):
            return {
                key: strip_dynamic(child)
                for key, child in item.items()
                if key not in {"valid_life_time", "preferred_life_time"}
            }
        if isinstance(item, list):
            return [strip_dynamic(child) for child in item]
        return item

    canonical = json.dumps(strip_dynamic(value), sort_keys=True, separators=(",", ":")).encode()
    return sha256(canonical)


def sanitized_tailscale_status() -> dict[str, object]:
    raw = json.loads(run(["tailscale", "status", "--json"]).stdout)
    own = raw.get("Self") or {}
    peers = raw.get("Peer") or {}

    def identity(node: dict[str, object]) -> dict[str, object]:
        raw_ips = node.get("TailscaleIPs")
        ips = raw_ips if isinstance(raw_ips, list) else []
        return {
            "ID": node.get("ID"),
            "PublicKey": node.get("PublicKey"),
            "HostName": node.get("HostName"),
            "DNSName": node.get("DNSName"),
            "TailscaleIPs": sorted(str(value) for value in ips),
        }

    return {
        "BackendState": raw.get("BackendState"),
        "Self": identity(own),
        "Peers": sorted((identity(value) for value in peers.values()), key=lambda value: str(value["ID"])),
    }


def host_invariant() -> dict[str, object]:
    return {
        "tailscale_status": sanitized_tailscale_status(),
        "tailscale_prefs_sha256": command_hash(["tailscale", "debug", "prefs"]),
        "ip_addr_sha256": normalized_ip_address_hash(),
        "ip_route_sha256": command_hash(["ip", "-j", "route", "show", "table", "all"]),
        "ip_rule_sha256": command_hash(["ip", "-j", "rule", "show"]),
    }


def safe_state_diagnostic(path: Path) -> dict[str, object]:
    with sqlite3.connect(f"file:{path}?mode=ro", uri=True) as database:
        dispatch = database.execute(
            "SELECT dispatch_state, authorization_generation, configuration_generation "
            "FROM n4_join_session_dispatches"
        ).fetchall()
        events = database.execute(
            "SELECT event_kind FROM n4_audit_correlations ORDER BY event_kind"
        ).fetchall()
    return {"dispatch": dispatch, "events": [row[0] for row in events]}


def conflicting_resources() -> list[str]:
    conflicts: list[str] = []
    names = docker("ps", "-a", "--format", "{{.Names}}").stdout.decode().splitlines()
    conflicts.extend(name for name in names if name.startswith(BASE_PREFIX))
    networks = docker("network", "ls", "--format", "{{.Name}}").stdout.decode().splitlines()
    conflicts.extend(name for name in networks if name.startswith(BASE_PREFIX))
    conflicts.extend(str(path) for path in Path("/var/tmp").glob(f"{BASE_PREFIX}-*"))
    return sorted(conflicts)


def assert_port_free(address: str, port: int) -> None:
    family = socket.AF_INET6 if ":" in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((address, port))


def write_private(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        os.write(fd, data)
        os.fsync(fd)
    finally:
        os.close(fd)


def wait_file(path: Path, timeout: float = 90.0) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError(f"timed out waiting for marker {path.name}")
        time.sleep(0.1)


def wait_proof_marker(
    path: Path,
    process: subprocess.Popen[bytes],
    log_path: Path,
    label: str,
) -> None:
    deadline = time.monotonic() + 90.0
    while not path.exists():
        if process.poll() is not None:
            log = getattr(process, "_nodescale_log", None)
            if log is not None and not log.closed:
                log.close()
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
            raise RuntimeError(f"Rust proof exited before {label}:\n{tail}")
        if time.monotonic() >= deadline:
            tail = log_path.read_text(encoding="utf-8", errors="replace")[-4000:]
            raise RuntimeError(f"timed out waiting for {label}:\n{tail}")
        time.sleep(0.1)


def wait_headscale(ca_file: Path) -> None:
    deadline = time.monotonic() + 30.0
    last_error = ""
    while True:
        probe = run(
            [
                "curl", "--fail", "--silent", "--show-error",
                "--cacert", str(ca_file),
                f"https://localhost:{HEADSCALE_PORT}/health",
            ],
            check=False,
        )
        if probe.returncode == 0:
            return
        last_error = probe.stderr.decode(errors="replace").strip()
        if time.monotonic() >= deadline:
            result = docker("logs", HEADSCALE, check=False)
            logs = (result.stdout + result.stderr).decode(errors="replace")[-4000:]
            state = docker(
                "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", HEADSCALE, check=False
            ).stdout.decode(errors="replace").strip()
            raise RuntimeError(
                f"Headscale failed readiness ({state}; curl={last_error}): {logs}"
            )
        time.sleep(0.25)


def make_certificates(root: Path, gateway: str) -> None:
    ca_key = root / "ca.key"
    ca_cert = root / "ca.pem"
    leaf_key = root / "tls.key"
    leaf_csr = root / "tls.csr"
    leaf_cert = root / "tls.crt"
    extensions = root / "tls.ext"
    run(["openssl", "genrsa", "-out", str(ca_key), "3072"])
    run([
        "openssl", "req", "-x509", "-new", "-sha256", "-days", "2",
        "-key", str(ca_key), "-out", str(ca_cert),
        "-subj", "/CN=Nodescale N5 Disposable CA",
    ])
    run(["openssl", "genrsa", "-out", str(leaf_key), "2048"])
    run([
        "openssl", "req", "-new", "-key", str(leaf_key), "-out", str(leaf_csr),
        "-subj", "/CN=headscale",
    ])
    extensions.write_text(
        "subjectAltName=DNS:headscale,DNS:localhost,DNS:ingress.n5.test,IP:127.0.0.1,IP:" + gateway + "\n"
        "extendedKeyUsage=serverAuth\nkeyUsage=digitalSignature,keyEncipherment\n",
        encoding="utf-8",
    )
    run([
        "openssl", "x509", "-req", "-sha256", "-days", "2",
        "-in", str(leaf_csr), "-CA", str(ca_cert), "-CAkey", str(ca_key),
        "-CAcreateserial", "-out", str(leaf_cert), "-extfile", str(extensions),
    ])
    ca_key.chmod(0o600)
    leaf_key.chmod(0o644)


def write_headscale_config(root: Path) -> Path:
    config = root / "config.yaml"
    synthetic_ipv4_prefix = "100." + "64.0.0/10"
    config.write_text(
        f"""server_url: https://headscale:8080
listen_addr: 0.0.0.0:8080
metrics_listen_addr: 127.0.0.1:9090
grpc_listen_addr: 127.0.0.1:50443
grpc_allow_insecure: false
noise:
  private_key_path: /var/lib/headscale/noise_private.key
prefixes:
  v4: {synthetic_ipv4_prefix}
  v6: fd7a:115c:a1e0::/48
allocation: sequential
derp:
  server:
    enabled: true
    region_id: 999
    region_code: n5
    region_name: Nodescale N5 Disposable DERP
    verify_clients: true
    stun_listen_addr: "0.0.0.0:3478"
    private_key_path: /var/lib/headscale/derp_server_private.key
    automatically_add_embedded_derp_region: true
  urls: []
  paths: []
  auto_update_enabled: false
disable_check_updates: true
database:
  type: sqlite
  sqlite:
    path: /var/lib/headscale/db.sqlite
    write_ahead_log: true
    wal_autocheckpoint: 1000
acme_url: https://acme-v02.api.letsencrypt.org/directory
acme_email: ""
tls_letsencrypt_hostname: ""
tls_letsencrypt_cache_dir: /var/lib/headscale/cache
tls_letsencrypt_challenge_type: HTTP-01
tls_cert_path: /etc/headscale/tls.crt
tls_key_path: /etc/headscale/tls.key
log:
  format: text
  level: info
policy:
  mode: database
dns:
  magic_dns: false
  override_local_dns: false
  base_domain: n5.internal
  nameservers:
    global: []
""",
        encoding="utf-8",
    )
    config.chmod(0o644)
    return config


def start_headscale(root: Path, image: str, config: Path) -> None:
    data = root / "headscale-data"
    data.mkdir(mode=0o700)
    data.chmod(0o777)
    common = [
        "--network", NETWORK,
        "--network-alias", "headscale",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        "--tmpfs", "/var/run:rw,noexec,nosuid,size=4m,mode=1777",
        "-v", f"{config}:/etc/headscale/config.yaml:ro",
        "-v", f"{data}:/var/lib/headscale",
        "-v", f"{root / 'tls.crt'}:/etc/headscale/tls.crt:ro",
        "-v", f"{root / 'tls.key'}:/etc/headscale/tls.key:ro",
    ]
    configtest = docker("run", "--rm", *common, image, "configtest", check=False)
    if configtest.returncode != 0:
        detail = (configtest.stderr or configtest.stdout).decode(errors="replace")[-4000:]
        raise RuntimeError(f"Headscale configtest failed: {detail}")
    docker(
        "run", "-d", "--name", HEADSCALE,
        "-p", f"127.0.0.1:{HEADSCALE_PORT}:8080",
        *common,
        image, "serve",
    )


def create_headscale_identity(root: Path) -> None:
    docker("exec", HEADSCALE, "headscale", "users", "create", "principal-42")
    result = docker(
        "exec", HEADSCALE, "headscale", "apikeys", "create", "--expiration", "30m"
    ).stdout.strip()
    if len(result) < 24 or any(byte in result for byte in b" \t\r\n"):
        raise RuntimeError("Headscale API key output had an unexpected shape")
    write_private(root / "headscale-api-key", result)
    mutable = bytearray(result)
    mutable[:] = b"\x00" * len(mutable)


def build_proof_binary(root: Path, source: Path) -> Path:
    env = os.environ.copy()
    env.setdefault("RUSTFLAGS", "-C link-arg=-fuse-ld=bfd")
    env["CARGO_TARGET_DIR"] = str(root / "cargo-target")
    result = run(
        [
            "cargo", "test", "--locked", "-p", "nodescale-device-trust",
            "--test", "disposable_trust", "--no-run", "--message-format=json",
        ],
        env=env,
        cwd=source,
        check=False,
    )
    if result.returncode != 0:
        detail = result.stderr.decode(errors="replace")[-4000:]
        raise RuntimeError(f"exact-tree Cargo build failed: {detail}")
    executable: Path | None = None
    for raw in result.stdout.splitlines():
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            continue
        target = event.get("target") or {}
        if (
            event.get("reason") == "compiler-artifact"
            and target.get("name") == "disposable_trust"
            and event.get("executable")
        ):
            executable = Path(event["executable"]).resolve()
    if executable is None or not executable.is_file():
        raise RuntimeError("Cargo did not report the disposable proof executable")
    return executable


def start_rust_proof(
    root: Path,
    runtime_image: str,
    executable: Path,
    cargo_log: Path,
) -> subprocess.Popen[bytes]:
    log = cargo_log.open("wb")
    environment = [
        "-e", "NODESCALE_N5_PROOF_ROOT=/proof",
        "-e", "NODESCALE_N5_PROOF_STATE_DB=/proof/state.db",
        "-e", "NODESCALE_N5_HEADSCALE_URL=https://headscale:8080",
        "-e", "NODESCALE_N5_LOGIN_SERVER=https://headscale:8080",
        "-e", f"NODESCALE_N5_INGRESS_BIND=0.0.0.0:{INGRESS_PORT}",
        "-e", "NODESCALE_N5_ALLOW_PUBLIC_BIND=proof-only",
        "-e", "NODESCALE_N5_CA_FILE=/proof/ca.pem",
        "-e", "NODESCALE_N5_INGRESS_CERT_FILE=/proof/tls.crt",
        "-e", "NODESCALE_N5_INGRESS_KEY_FILE=/proof/tls.key",
        "-e", "NODESCALE_N5_HEADSCALE_API_KEY_FILE=/proof/headscale-api-key",
    ]
    process = subprocess.Popen(
        [
            "docker", "run", "--platform", PLATFORM, "--rm", "--name", INGRESS,
            "--network", NETWORK, "--network-alias", "ingress.n5.test",
            "--user", "1000:1000",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
            "-v", f"{root}:/proof",
            "-v", f"{executable}:/proof-bin:ro",
            *environment,
            "--entrypoint", "/proof-bin",
            runtime_image,
            PROOF_TEST_NAME,
            "--ignored", "--exact", "--nocapture",
        ],
        cwd=REPO,
        stdout=log,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    _ACTIVE_PROCESSES.add(process)
    process._nodescale_log = log  # type: ignore[attr-defined]
    return process


def prepare_request(root: Path, image: str) -> None:
    script = r'''set -eu
umask 077
capability="$(cat /proof/invitation-token)"
printf '{"invitation_token":"%s"}' "$capability" > /proof/request.json
'''
    prepared = docker(
        "run", "--rm", "--network", "none",
        "--user", "1000:1000",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "-v", f"{root}:/proof",
        "--entrypoint", "/bin/sh", image, "-c", script,
        check=False,
    )
    if prepared.returncode != 0:
        token_path = root / "invitation-token"
        stat = token_path.stat()
        listing = docker(
            "run", "--rm", "--network", "none", "--user", "1000:1000",
            "-v", f"{root}:/proof:ro", "--entrypoint", "/bin/sh", image,
            "-c", "id; ls -lnd /proof /proof/invitation-token",
            check=False,
        )
        detail = (prepared.stderr + prepared.stdout + listing.stdout + listing.stderr).decode(
            errors="replace"
        )[-2000:]
        raise RuntimeError(
            f"request preparation failed (uid={stat.st_uid} gid={stat.st_gid} "
            f"mode={oct(stat.st_mode & 0o777)}): {detail}"
        )


def redemption_process(root: Path, image: str, name: str, suffix: str) -> subprocess.Popen[bytes]:
    script = f'''exec wget -q -T 10 \
--header='Content-Type: application/json' --post-file=/proof/request.json \
-O /proof/response-{suffix}.json \
https://ingress.n5.test:{INGRESS_PORT}/v1/redemptions'''
    process = subprocess.Popen(
        [
            "docker", "run", "--platform", PLATFORM, "--rm", "--name", name,
            "--network", NETWORK,
            "--user", "1000:1000",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "-e", "SSL_CERT_FILE=/proof/ca.pem",
            "-v", f"{root}:/proof",
            "--entrypoint", "/bin/sh", image, "-c", script,
        ],
        cwd=REPO,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    _ACTIVE_PROCESSES.add(process)
    return process


def validate_and_extract(root: Path, image: str, successful: str) -> None:
    script = f'''set -eu
umask 077
grep -q '"auth_key"' /proof/response-{successful}.json
sed -n 's/.*"auth_key":"\\([^"]*\\)".*/\\1/p' /proof/response-{successful}.json > /proof/authkey
sed -n 's/.*"login_server":"\\([^"]*\\)".*/\\1/p' /proof/response-{successful}.json > /proof/login-server
test -s /proof/authkey
test -s /proof/login-server
chmod 600 /proof/authkey /proof/login-server
rm -f /proof/invitation-token /proof/request.json /proof/response-a.json /proof/response-b.json /proof/response-replay.json
'''
    validated = docker(
        "run", "--rm", "--network", "none",
        "--user", "1000:1000",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "-v", f"{root}:/proof",
        "--entrypoint", "/bin/sh", image, "-c", script,
        check=False,
    )
    if validated.returncode != 0:
        sizes = {
            path.name: path.stat().st_size
            for path in root.glob("response-*.json")
        }
        detail = (validated.stdout + validated.stderr).decode(errors="replace")[-2000:]
        raise RuntimeError(f"bootstrap validation failed (sizes={sizes}): {detail}")


def start_tailscale(root: Path, image: str) -> None:
    login_server = (root / "login-server").read_text(encoding="utf-8").strip()
    if login_server != "https://headscale:8080/":
        raise RuntimeError("bootstrap login_server did not match the disposable Headscale origin")
    state = root / "tailscale-state"
    state.mkdir(mode=0o700)
    state.chmod(0o777)
    docker(
        "run", "-d", "--name", TAILSCALE,
        "--network", NETWORK,
        "--user", "1000:1000",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        "-v", f"{root}:/proof:ro",
        "-v", f"{state}:/var/lib/tailscale",
        "-e", "TS_USERSPACE=true",
        "-e", "TS_STATE_DIR=/var/lib/tailscale",
        "-e", "TS_AUTH_ONCE=true",
        "-e", "TS_AUTHKEY=file:/proof/authkey",
        "-e", "SSL_CERT_FILE=/proof/ca.pem",
        "-e", f"TS_EXTRA_ARGS=--login-server={login_server} --accept-dns=false --hostname=nodescale-n5-ephemeral",
        image,
    )
    deadline = time.monotonic() + 60.0
    while True:
        status = docker(
            "exec", TAILSCALE, "tailscale", "--socket=/tmp/tailscaled.sock",
            "status", "--json", check=False,
        )
        if status.returncode == 0:
            parsed = json.loads(status.stdout)
            if parsed.get("BackendState") == "Running":
                return
        if time.monotonic() >= deadline:
            result = docker("logs", TAILSCALE, check=False)
            logs = (result.stdout + result.stderr).decode(errors="replace")[-4000:]
            state = docker(
                "inspect", "--format", "{{.State.Status}}:{{.State.ExitCode}}", TAILSCALE,
                check=False,
            ).stdout.decode(errors="replace").strip()
            raise RuntimeError(f"Tailscale client failed to join ({state}): {logs}")
        time.sleep(0.25)


def cleanup_resources(root: Path | None, cargo: subprocess.Popen[bytes] | None) -> None:
    errors: list[str] = []
    for process in tuple(_ACTIVE_PROCESSES):
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
                process.wait(timeout=5)
            except ProcessLookupError:
                pass
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait(timeout=5)
                except (ProcessLookupError, subprocess.TimeoutExpired):
                    errors.append(f"subprocess cleanup failed: pid={process.pid}")
        _ACTIVE_PROCESSES.discard(process)
    if cargo is not None:
        log = getattr(cargo, "_nodescale_log", None)
        if log is not None and not log.closed:
            log.close()
    for name in [*REDEEMERS, TAILSCALE, INGRESS, HEADSCALE]:
        removed = docker("rm", "-f", name, check=False)
        detail = (removed.stdout + removed.stderr).decode(errors="replace")
        if removed.returncode != 0 and "No such container" not in detail:
            errors.append(f"container cleanup failed: {name}")
    removed_network = docker("network", "rm", NETWORK, check=False)
    network_detail = (removed_network.stdout + removed_network.stderr).decode(errors="replace")
    if removed_network.returncode != 0 and "not found" not in network_detail:
        errors.append(f"network cleanup failed: {NETWORK}")
    if root is not None:
        try:
            shutil.rmtree(root)
        except FileNotFoundError:
            pass
        except OSError as error:
            errors.append(f"runtime-root cleanup failed: {error}")
        if root.exists():
            errors.append(f"runtime root remains: {root}")
    if errors:
        raise RuntimeError("; ".join(errors))


def main() -> int:
    for command in ["cargo", "curl", "docker", "ip", "openssl", "tailscale"]:
        if shutil.which(command) is None:
            raise RuntimeError(f"required command is unavailable: {command}")
    conflicts = conflicting_resources()
    if conflicts:
        raise RuntimeError(f"conflicting proof resources exist: {conflicts}")
    assert_port_free("127.0.0.1", HEADSCALE_PORT)
    exact_tree = resolve_exact_tree()
    repository_before = command_hash(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"])
    cargo_lock_before = sha256((REPO / "Cargo.lock").read_bytes())
    before = host_invariant()
    headscale_image, tailscale_image, runtime_image = load_images()
    root: Path | None = None
    cargo: subprocess.Popen[bytes] | None = None
    proof_result: dict[str, object] = {}
    termination: ProofTerminationRequested | None = None
    signal.signal(signal.SIGTERM, handle_termination)
    signal.signal(signal.SIGINT, handle_termination)
    try:
        root = Path(tempfile.mkdtemp(prefix=f"{PREFIX}-", dir="/var/tmp"))
        root.chmod(0o700)
        print("N5 proof runtime initialized", file=sys.stderr, flush=True)
        source = extract_exact_tree(root, exact_tree)
        docker("pull", headscale_image)
        docker("pull", tailscale_image)
        docker("pull", runtime_image)
        for image in [headscale_image, tailscale_image, runtime_image]:
            assert_image_platform(image)
        proof_binary = build_proof_binary(root, source)
        headscale_version = docker("run", "--rm", "--network", "none", headscale_image, "version").stdout.decode(errors="replace")
        tailscale_version = docker(
            "run", "--rm", "--network", "none", "--entrypoint", "tailscale", tailscale_image, "version"
        ).stdout.decode(errors="replace")
        if "0.29.3" not in headscale_version or "1.98.10" not in tailscale_version:
            raise RuntimeError("pinned image version output did not match the required versions")

        docker("network", "create", NETWORK)
        network_data = json.loads(docker("network", "inspect", NETWORK).stdout)[0]
        gateway = next(iter(network_data["IPAM"]["Config"]))["Gateway"]
        make_certificates(root, gateway)
        config = write_headscale_config(root)
        start_headscale(root, headscale_image, config)
        wait_headscale(root / "ca.pem")
        create_headscale_identity(root)

        cargo_log = root / "cargo-proof.log"
        cargo = start_rust_proof(root, runtime_image, proof_binary, cargo_log)
        wait_proof_marker(root / "ingress-ready", cargo, cargo_log, "ingress readiness")
        prepare_request(root, tailscale_image)

        first = redemption_process(root, tailscale_image, REDEEMERS[0], "a")
        second = redemption_process(root, tailscale_image, REDEEMERS[1], "b")
        first_out, first_err = first.communicate(timeout=30)
        second_out, second_err = second.communicate(timeout=30)
        first_rc = first.returncode
        second_rc = second.returncode
        if sorted([first_rc == 0, second_rc == 0]) != [False, True]:
            sizes = {
                suffix: (root / f"response-{suffix}.json").stat().st_size
                if (root / f"response-{suffix}.json").exists()
                else None
                for suffix in ["a", "b"]
            }
            diagnostics = (first_out + first_err + second_out + second_err).decode(
                errors="replace"
            )[-2000:]
            headscale_logs_result = docker("logs", HEADSCALE, check=False)
            headscale_logs = (
                headscale_logs_result.stdout + headscale_logs_result.stderr
            ).decode(errors="replace")[-3000:]
            rust_logs = cargo_log.read_text(encoding="utf-8", errors="replace")[-2000:]
            state = safe_state_diagnostic(root / "state.db")
            raise RuntimeError(
                f"concurrent redemption did not produce exactly one success "
                f"(rc={[first_rc, second_rc]} sizes={sizes}): {diagnostics}\n"
                f"Headscale tail:\n{headscale_logs}\nRust tail:\n{rust_logs}\nState:{state}"
            )
        successful, rejected = ("a", "b") if first_rc == 0 else ("b", "a")
        rejected_error = second_err if rejected == "b" else first_err
        if b"409 Conflict" not in rejected_error:
            raise RuntimeError("concurrent loser did not receive the fixed conflict status")

        time.sleep(1.1)
        replay = redemption_process(root, tailscale_image, REDEEMERS[2], "replay")
        _, replay_error = replay.communicate(timeout=30)
        if replay.returncode == 0:
            raise RuntimeError("invitation replay unexpectedly succeeded")
        if b"409 Conflict" not in replay_error:
            raise RuntimeError("invitation replay did not receive the fixed conflict status")
        validate_and_extract(root, tailscale_image, successful)
        start_tailscale(root, tailscale_image)
        write_private(root / "client-running", b"running\n")
        wait_proof_marker(root / "node-observed", cargo, cargo_log, "N5 node observation")
        for marker in [
            "identity-confirmed-untrusted",
            "trust-activated",
            "trust-revoked",
        ]:
            wait_proof_marker(root / marker, cargo, cargo_log, f"N5 marker {marker}")

        docker("rm", "-f", TAILSCALE)
        (root / "authkey").unlink(missing_ok=True)
        (root / "login-server").unlink(missing_ok=True)
        shutil.rmtree(root / "tailscale-state", ignore_errors=True)
        write_private(root / "client-stopped", b"stopped\n")
        wait_proof_marker(root / "cleanup-complete", cargo, cargo_log, "N5 cleanup completion")
        cargo_rc = cargo.wait(timeout=30)
        getattr(cargo, "_nodescale_log").close()
        if cargo_rc != 0:
            tail = cargo_log.read_text(encoding="utf-8", errors="replace")[-4000:]
            raise RuntimeError(f"Rust proof failed:\n{tail}")
        cargo = None

        proof_result = {
            "candidate_tree": exact_tree,
            "source_input": "git_archive_exact_tree",
            "cargo_locked": True,
            "cargo_target": "temporary_runtime_root",
            "platform": PLATFORM,
            "headscale_image": headscale_image,
            "headscale_version": "v0.29.3",
            "tailscale_image": tailscale_image,
            "tailscale_version": "v1.98.10",
            "ingress_runtime_image": runtime_image,
            "concurrent_redemption": "one_success_one_rejection",
            "replay": "rejected",
            "provider_nodes_after_join": 1,
            "provider_nodes_after_cleanup": 0,
            "logical_device_identity": "confirmed",
            "pre_trust_query": False,
            "trust_activation_query": True,
            "trust_revocation_query": False,
            "logical_devices_retained_in_disposable_state": 1,
            "trusted_devices_after_activation": 1,
            "trusted_devices_final": 0,
            "keryx_bindings": 0,
            "fleet_enrollments": 0,
            "fleet_grants": 0,
            "hermes_activations": 0,
            "client_network_mode": "userspace",
            "client_capabilities": "none",
        }
    except ProofTerminationRequested as error:
        termination = error
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        cleanup_resources(root, cargo)

    if conflicting_resources():
        raise RuntimeError("proof resources remained after cleanup")
    repository_after = command_hash(["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"])
    if repository_before != repository_after:
        raise RuntimeError("repository status changed during proof")
    if cargo_lock_before != sha256((REPO / "Cargo.lock").read_bytes()):
        raise RuntimeError("ambient Cargo.lock changed during proof")
    time.sleep(1.0)
    after = host_invariant()
    if before != after:
        changed = sorted(key for key in before if before[key] != after[key])
        raise RuntimeError(f"sanitized host-network invariant changed: {changed}")
    if termination is not None:
        raise RuntimeError(f"proof terminated after exact cleanup: {termination}")
    proof_result["host_network_invariant"] = "exact"
    proof_result["runtime_residue"] = "zero"
    proof_result["repository_invariant"] = "exact"
    proof_result["pulled_images"] = "retained_digest_pinned_cache"
    print(json.dumps(proof_result, sort_keys=True))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(f"N5 proof failed: {error}", file=sys.stderr)
        raise SystemExit(1)
