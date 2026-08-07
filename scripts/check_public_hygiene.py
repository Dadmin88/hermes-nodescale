#!/usr/bin/env python3
"""Fail if shipped project content contains private deployment-shaped values."""

from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
SELF = Path(__file__).resolve()
TEXT_SUFFIXES = {".md", ".rs", ".toml", ".yml", ".yaml", ".json", ".sql", ".txt"}

# Build sensitive markers from fragments so the checker does not match itself.
patterns = {
    "absolute home path": re.compile("/" + "home" + r"/[A-Za-z0-9_.-]+/"),
    "libp2p-style peer id": re.compile("12" + r"D3Koo[A-Za-z0-9]{20,}"),
    "mesh-range address": re.compile(r"\b" + "100" + r"\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\.\d{1,3}\.\d{1,3}\b"),
    "private hostname suffix": re.compile(r"\b[A-Za-z0-9-]+\." + "mesh" + r"\b"),
    "invitation value": re.compile(r"(?i)(?:invitation|pre.?auth).{0,20}(?:secret|key)\s*[:=]\s*['\"][^<][^'\"]{7,}"),
    "credential assignment": re.compile(r"(?i)(?:api.?key|token|password|private.?key)\s*[:=]\s*['\"][^<][^'\"]{7,}"),
}

completed = subprocess.run(
    ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
    cwd=ROOT,
    check=True,
    text=True,
    capture_output=True,
)
violations: list[str] = []
for relative in completed.stdout.splitlines():
    path = ROOT / relative
    if path.resolve() == SELF or path.suffix.lower() not in TEXT_SUFFIXES or not path.is_file():
        continue
    text = path.read_text(encoding="utf-8", errors="replace")
    for label, pattern in patterns.items():
        for match in pattern.finditer(text):
            line = text.count("\n", 0, match.start()) + 1
            violations.append(f"{relative}:{line}: {label}")

if violations:
    print("public repository hygiene failed:", file=sys.stderr)
    print("\n".join(violations), file=sys.stderr)
    raise SystemExit(1)
print("public repository hygiene: PASS")
