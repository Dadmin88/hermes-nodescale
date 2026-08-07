#!/usr/bin/env python3
"""Scan one exact Git tree for public-repository hygiene violations."""

from __future__ import annotations

import argparse
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
from typing import NoReturn

TEXT_SUFFIXES = {
    ".json",
    ".lock",
    ".md",
    ".py",
    ".rs",
    ".sql",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
FULL_OBJECT_ID = re.compile(r"[0-9a-f]{40,64}")

# Construct sensitive markers from fragments so this scanner does not match itself.
RULES = {
    "absolute-home-path": re.compile("/" + "home" + r"/[A-Za-z0-9_.-]+/"),
    "libp2p-peer-id": re.compile("12" + r"D3Koo[A-Za-z0-9]{20,}"),
    "mesh-range-address": re.compile(
        r"\b" + "100" + r"\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.\d{1,3}\.\d{1,3}\b"
    ),
    "private-hostname-suffix": re.compile(r"\b[A-Za-z0-9-]+\." + "mesh" + r"\b"),
    "invitation-value": re.compile(
        r"(?i)(?:invitation|pre.?auth).{0,20}(?:secret|key)\s*[:=]\s*['\"][^<][^'\"]{7,}"
    ),
    "credential-assignment": re.compile(
        r"(?i)(?:api.?key|token|password|private.?key)\s*[:=]\s*['\"][^<][^'\"]{7,}"
    ),
}


def fail(message: str) -> "NoReturn":
    print(message, file=sys.stderr)
    raise SystemExit(2)


def git(repo: Path, *arguments: str, input_bytes: bytes | None = None) -> bytes:
    try:
        completed = subprocess.run(
            ["git", *arguments],
            cwd=repo,
            input=input_bytes,
            check=True,
            capture_output=True,
        )
    except (OSError, subprocess.CalledProcessError) as error:
        fail(f"public-hygiene-error:{type(error).__name__}")
    return completed.stdout


def escaped_path(path: str) -> str:
    return json.dumps(path, ensure_ascii=True)[1:-1]


def tree_blobs(repo: Path, tree: str) -> list[tuple[str, str]]:
    output = git(repo, "ls-tree", "-r", "-z", "--full-tree", tree)
    blobs: list[tuple[str, str]] = []
    for record in output.split(b"\0"):
        if not record:
            continue
        try:
            metadata, raw_path = record.split(b"\t", 1)
            _mode, object_type, object_id = metadata.decode("ascii").split(" ", 2)
            path = raw_path.decode("utf-8", errors="surrogateescape")
        except (ValueError, UnicodeDecodeError):
            fail("public-hygiene-error:malformed-ls-tree")
        if object_type != "blob":
            continue
        if PurePosixPath(path).suffix.lower() in TEXT_SUFFIXES:
            blobs.append((object_id, path))
    return blobs


def read_blobs(repo: Path, blobs: list[tuple[str, str]]) -> list[tuple[str, bytes]]:
    if not blobs:
        return []
    process = subprocess.Popen(
        ["git", "cat-file", "--batch"],
        cwd=repo,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    )
    assert process.stdin is not None and process.stdout is not None
    try:
        contents: list[tuple[str, bytes]] = []
        for expected_id, path in blobs:
            process.stdin.write(expected_id.encode("ascii") + b"\n")
            process.stdin.flush()
            header = process.stdout.readline().rstrip(b"\n")
            parts = header.split(b" ")
            if len(parts) != 3 or parts[0].decode("ascii") != expected_id or parts[1] != b"blob":
                fail("public-hygiene-error:malformed-cat-file")
            try:
                size = int(parts[2])
            except ValueError:
                fail("public-hygiene-error:malformed-cat-file-size")
            content = process.stdout.read(size)
            delimiter = process.stdout.read(1)
            if len(content) != size or delimiter != b"\n":
                fail("public-hygiene-error:truncated-cat-file")
            contents.append((path, content))
        process.stdin.close()
        if process.wait() != 0:
            fail("public-hygiene-error:cat-file-failed")
        return contents
    finally:
        if process.poll() is None:
            process.kill()
            process.wait()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--tree", required=True)
    arguments = parser.parse_args()

    repo = Path(arguments.repo)
    if not repo.is_absolute() or not repo.is_dir():
        fail("public-hygiene-error:invalid-repo")
    if FULL_OBJECT_ID.fullmatch(arguments.tree) is None:
        fail("public-hygiene-error:tree-must-be-full-object-id")
    object_type = git(repo, "cat-file", "-t", arguments.tree).strip()
    if object_type != b"tree":
        fail("public-hygiene-error:object-is-not-tree")

    violations: list[tuple[str, int, str]] = []
    for path, body in read_blobs(repo, tree_blobs(repo, arguments.tree)):
        text = body.decode("utf-8", errors="replace")
        for rule_id, pattern in RULES.items():
            for match in pattern.finditer(text):
                line = text.count("\n", 0, match.start()) + 1
                violations.append((path, line, rule_id))

    for path, line, rule_id in sorted(violations):
        print(f"{escaped_path(path)}:{line}:{rule_id}")
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
