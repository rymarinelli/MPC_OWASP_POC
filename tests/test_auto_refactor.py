import subprocess
import tempfile
from pathlib import Path
import unittest

from mcp import AppliedPatch, PatchCandidate, Vulnerability
from scripts.auto_refactor import build_pr_body, stage_and_commit


class StageAndCommitTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.repo_root = Path(self.tempdir.name)
        self._git("init")
        self._git("config", "user.email", "test@example.com")
        self._git("config", "user.name", "Test User")
        initial_file = self.repo_root / "example.txt"
        initial_file.write_text("original contents\n", encoding="utf-8")
        self._git("add", "example.txt")
        self._git("commit", "-m", "initial commit")
        self.initial_commit_count = self._rev_count()

    def _git(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            ["git", *args],
            cwd=self.repo_root,
            check=True,
            capture_output=True,
            text=True,
        )

    def _rev_count(self) -> int:
        result = self._git("rev-list", "--count", "HEAD")
        return int(result.stdout.strip())

    def test_stage_and_commit_skips_when_no_changes(self) -> None:
        file_path = self.repo_root / "example.txt"
        file_path.write_text("original contents\n", encoding="utf-8")

        with self.assertLogs("scripts.auto_refactor", level="INFO") as logs:
            stage_and_commit(self.repo_root, [file_path], "test commit")

        self.assertTrue(
            any("No staged changes detected; skipping commit" in message for message in logs.output),
            msg="Expected informational log when no staged changes are present",
        )
        self.assertEqual(self.initial_commit_count, self._rev_count())
        status = self._git("status", "--porcelain").stdout.strip()
        self.assertEqual("", status)


class BuildPrBodyTests(unittest.TestCase):
    def test_build_pr_body_includes_llm_metadata(self) -> None:
        vulnerability = Vulnerability(
            identifier="OWASP-1",
            file_path=Path("src/example.py"),
            summary="Example finding",
            recommendation="Add input validation",
            severity="high",
            start_line=10,
            end_line=20,
        )
        candidate = PatchCandidate(
            file_path=Path("src/example.py"),
            replacement="# new file contents\n",
            metadata={
                "vulnerability_id": "OWASP-1",
                "analysis": "Validate user input before processing.",
                "test_recommendations": ["pytest tests/test_example.py"],
            },
        )
        applied = AppliedPatch(candidate=candidate, path=Path("/tmp/src/example.py"))

        body = build_pr_body([vulnerability], [applied])

        self.assertIn("LLM analysis: Validate user input before processing.", body)
        self.assertIn("Suggested validation: pytest tests/test_example.py", body)


if __name__ == "__main__":
    unittest.main()
