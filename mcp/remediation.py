"""Shared remediation helpers for CLI and server entrypoints."""

from __future__ import annotations

import json
import logging
import shlex
import subprocess
from pathlib import Path
from typing import Iterable, List, Mapping, Sequence

from .llm_client import OpenAICompatibleClient
from .scan_parser import ScanParser, Vulnerability

logger = logging.getLogger(__name__)


def normalise_validations(commands: Iterable[str]) -> List[List[str]]:
    """Split string commands into argument lists for subprocess."""

    return [shlex.split(command) for command in commands if command]


def parse_vulnerabilities_payload(payload, limit: int | None = None) -> List[Vulnerability]:
    """Parse an in-memory JSON payload into :class:`Vulnerability` objects."""

    parser = ScanParser()
    if isinstance(payload, (str, bytes, Path)):
        data = json.loads(Path(payload).read_text() if isinstance(payload, Path) else payload)
    else:
        data = payload

    if isinstance(data, dict) and "vulnerabilities" in data:
        data = data["vulnerabilities"]

    if not isinstance(data, Iterable):
        raise ValueError("Scan payload must be a list or contain a 'vulnerabilities' key")

    vulnerabilities = parser.parse(list(data))
    if limit is not None:
        vulnerabilities = vulnerabilities[:limit]
    return vulnerabilities


def load_vulnerabilities(scan_path: Path | str, limit: int | None = None) -> List[Vulnerability]:
    """Load vulnerabilities from a JSON scan file."""

    return parse_vulnerabilities_payload(Path(scan_path).read_text(), limit=limit)


def create_llm_client(endpoint: str | None, model: str | None, api_key: str | None) -> OpenAICompatibleClient:
    """Instantiate an OpenAI-compatible LLM client."""

    if not endpoint or not model or not api_key:
        raise ValueError("LLM endpoint, model, and API key must be configured")
    return OpenAICompatibleClient(endpoint=endpoint, model=model, api_key=api_key)


def git(repo_root: Path, *args: str, capture_output: bool = True) -> str:
    """Run a git command inside *repo_root* and return stdout when requested."""

    result = subprocess.run(
        ["git", *args],
        cwd=repo_root,
        check=True,
        capture_output=capture_output,
        text=True,
    )
    if capture_output:
        return (result.stdout or "").strip()
    return ""


def checkout_branch(repo_root: Path, new_branch: str) -> str:
    """Create and check out *new_branch*, returning the previous branch name."""

    current_branch = git(repo_root, "rev-parse", "--abbrev-ref", "HEAD")
    git(repo_root, "checkout", "-b", new_branch)
    return current_branch


def restore_branch(repo_root: Path, original_branch: str, *, delete_branch: str | None = None) -> None:
    """Return to *original_branch* and optionally delete *delete_branch*."""

    try:
        git(repo_root, "checkout", original_branch)
    finally:
        if delete_branch:
            try:
                git(repo_root, "branch", "-D", delete_branch)
            except subprocess.CalledProcessError:
                logger.warning("Failed to delete temporary branch %s", delete_branch)


def stage_and_commit(repo_root: Path, files: Iterable[Path], message: str) -> None:
    """Stage *files* inside *repo_root* and create a commit with *message*."""

    rel_paths = [str(Path(path).relative_to(repo_root)) for path in files]
    if rel_paths:
        git(repo_root, "add", *rel_paths)
    diff_check = subprocess.run(
        ["git", "diff", "--cached", "--quiet"],
        cwd=repo_root,
        capture_output=True,
        text=True,
    )
    if diff_check.returncode == 0:
        logger.info("No staged changes detected; skipping commit")
        return
    if diff_check.returncode not in (0, 1):
        diff_check.check_returncode()
    git(repo_root, "commit", "-m", message)


def push_branch(repo_root: Path, branch: str, remote: str) -> None:
    """Push *branch* to *remote*."""

    git(repo_root, "push", "--set-upstream", remote, branch, capture_output=False)


def _normalise_metadata_value(value) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        value = value.strip()
        return value or None
    if isinstance(value, (list, tuple, set)):
        parts = [str(item).strip() for item in value if str(item).strip()]
        if parts:
            return ", ".join(parts)
        return None
    return str(value)


def _extract_analysis(metadata: Mapping[str, object]) -> str | None:
    for key in ("analysis", "explanation", "summary", "rationale", "notes"):
        value = metadata.get(key)
        normalised = _normalise_metadata_value(value)
        if normalised:
            return normalised
    return None


def _extract_validation(metadata: Mapping[str, object]) -> str | None:
    for key in ("test_recommendations", "tests", "validation", "commands"):
        value = metadata.get(key)
        normalised = _normalise_metadata_value(value)
        if normalised:
            return normalised
    return None


def build_pr_body(vulnerabilities, applied_patches: Sequence["AppliedPatch"] | None = None) -> str:
    """Construct a pull request body summarising remediation actions."""

    from .pipeline import AppliedPatch  # Imported lazily to avoid circular import.

    lines = ["## Summary", "This PR proposes automated fixes for the following findings:"]

    recommendations: dict[str, list[Mapping[str, object]]] = {}
    unmatched_metadata: list[Mapping[str, object]] = []

    if applied_patches:
        for patch in applied_patches:
            if not isinstance(patch, AppliedPatch):
                continue
            metadata = patch.candidate.metadata or {}
            if not metadata:
                continue
            vuln_id = (
                metadata.get("vulnerability_id")
                or metadata.get("identifier")
                or metadata.get("id")
            )
            if isinstance(vuln_id, str) and vuln_id.strip():
                recommendations.setdefault(vuln_id.strip(), []).append(metadata)
            else:
                unmatched_metadata.append(metadata)

    for vuln in vulnerabilities:
        lines.append(
            f"- **{vuln.identifier}** ({vuln.severity}) in `{vuln.file_path}` lines {vuln.affected_range()}: {vuln.summary or 'No summary provided.'}"
        )
        if vuln.recommendation:
            lines.append(f"  - Recommended fix: {vuln.recommendation}")

        for metadata in recommendations.get(vuln.identifier, []):
            analysis = _extract_analysis(metadata)
            if analysis:
                lines.append(f"  - LLM analysis: {analysis}")
            validation = _extract_validation(metadata)
            if validation:
                lines.append(f"  - Suggested validation: {validation}")

    if unmatched_metadata:
        lines.append("\n## Additional LLM recommendations")
        for metadata in unmatched_metadata:
            analysis = _extract_analysis(metadata)
            validation = _extract_validation(metadata)
            if analysis or validation:
                lines.append("- " + " | ".join(filter(None, [analysis, validation])))

    return "\n".join(lines)


__all__ = [
    "normalise_validations",
    "parse_vulnerabilities_payload",
    "load_vulnerabilities",
    "create_llm_client",
    "git",
    "checkout_branch",
    "restore_branch",
    "stage_and_commit",
    "push_branch",
    "build_pr_body",
]
