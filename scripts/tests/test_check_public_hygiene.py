from __future__ import annotations

import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCANNER = Path(__file__).resolve().parents[1] / "check_public_hygiene.py"


def run(*args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(args, cwd=cwd, text=True, capture_output=True, check=False)


class ExactTreeHygieneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repo = Path(self.temporary.name).resolve()
        self.assertEqual(run("git", "init", "-q", cwd=self.repo).returncode, 0)
        self.assertEqual(run("git", "config", "user.name", "fixture", cwd=self.repo).returncode, 0)
        self.assertEqual(
            run("git", "config", "user.email", "fixture@example.invalid", cwd=self.repo).returncode,
            0,
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def write_tree(self, path: str, content: str) -> str:
        target = self.repo / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content)
        self.assertEqual(run("git", "add", "--", path, cwd=self.repo).returncode, 0)
        result = run("git", "write-tree", cwd=self.repo)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.strip()

    def scan(self, tree: str) -> subprocess.CompletedProcess[str]:
        return run(
            sys.executable,
            os.fspath(SCANNER),
            "--repo",
            os.fspath(self.repo),
            "--tree",
            tree,
        )

    def test_scans_exact_tree_and_ignores_later_worktree_bytes(self) -> None:
        clean_tree = self.write_tree("README.md", "public fixture\n")
        assignment = "to" + "ken"
        (self.repo / "README.md").write_text(
            f"{assignment}='runtime-only-sensitive-marker'\n"
        )
        result = self.scan(clean_tree)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")

    def test_reports_rule_and_unusual_path_without_echoing_secret_value(self) -> None:
        secret = "runtime-only-sensitive-marker"
        assignment = "to" + "ken"
        tree = self.write_tree("docs/odd name\tline.md", f"{assignment}='{secret}'\n")
        result = self.scan(tree)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("credential-assignment", result.stdout)
        self.assertIn("odd name\\tline.md", result.stdout)
        self.assertNotIn(secret, result.stdout)
        self.assertNotIn(secret, result.stderr)

    def test_scans_python_scanner_source_and_lockfiles(self) -> None:
        secret = "runtime-only-sensitive-marker"
        token_assignment = "to" + "ken"
        api_key_assignment = "api" + "_key"
        self.write_tree(
            "scripts/check_public_hygiene.py", f"{token_assignment}='{secret}'\n"
        )
        tree = self.write_tree("Cargo.lock", f"{api_key_assignment}='{secret}'\n")
        result = self.scan(tree)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout.count("credential-assignment"), 2)
        self.assertIn("scripts/check_public_hygiene.py", result.stdout)
        self.assertIn("Cargo.lock", result.stdout)
        self.assertNotIn(secret, result.stdout)
        self.assertNotIn(secret, result.stderr)

    def test_rejects_commit_object_and_short_object_name(self) -> None:
        tree = self.write_tree("README.md", "public fixture\n")
        commit = run("git", "commit-tree", tree, cwd=self.repo,).stdout.strip()
        commit_result = self.scan(commit)
        self.assertEqual(commit_result.returncode, 2)
        self.assertIn("object-is-not-tree", commit_result.stderr)

        short_result = self.scan(tree[:12])
        self.assertEqual(short_result.returncode, 2)
        self.assertIn("tree-must-be-full-object-id", short_result.stderr)


if __name__ == "__main__":
    unittest.main()
