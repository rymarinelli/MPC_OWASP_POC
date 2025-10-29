#!/usr/bin/env python3
"""Automated remediation entrypoint.

This script drives the MCP pipeline: it parses vulnerability scan results,
invokes the configured LLM, validates the generated patch, and finally opens a
pull request with the proposed fix.
"""

from __future__ import annotations

import argparse
import logging
import os
import shlex
import subprocess
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Mapping, Sequence

from mcp import (
    AppliedPatch,
    AutoRemediationPipeline,
    GitHubClient,
    OpenAICompatibleClient,
    PatchGenerator,
    PromptBuilder,
    PromptContext,
    PullRequestPayload,
    ScanParser,
)

logger = logging.getLogger(__name__)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Automate LLM-driven remediation")
    parser.add_argument("--scan-results", required=True, help="Path to the scan JSON file")
    parser.add_argument("--repo-root", default=os.getcwd(), help="Repository root path")
    parser.add_argument("--base-branch", default=os.getenv("GITHUB_BASE_REF", "main"))
    parser.add_argument("--branch-prefix", default="auto/remediate-")
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--formatter", action="append", default=[], help="Formatter command template with {path}")
    parser.add_argument(
        "--validate",
        action="append",
        default=[],
        help="Validation command executed after patches are applied",
    )
    parser.add_argument("--llm-endpoint", default=os.getenv("MCP_LLM_ENDPOINT"))
    parser.add_argument("--llm-model", default=os.getenv("MCP_LLM_MODEL"))
    parser.add_argument("--llm-api-key", default=os.getenv("MCP_LLM_API_KEY"))
    parser.add_argument("--github-token", default=os.getenv("GITHUB_TOKEN"))
    parser.add_argument("--github-repository", default=os.getenv("GITHUB_REPOSITORY"))
    parser.add_argument("--dry-run", action="store_true", help="Run without committing, pushing, or opening a PR")
    parser.add_argument("--max-vulnerabilities", type=int, default=None)
    return parser.parse_args()


def setup_logging() -> None:
    logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")


def normalise_validations(commands: Iterable[str]) -> List[List[str]]:
    return [shlex.split(command) for command in commands if command]


def load_vulnerabilities(scan_path: Path, limit: int | None = None):
    parser = ScanParser()
    vulnerabilities = parser.parse_file(scan_path)
    if limit is not None:
        vulnerabilities = vulnerabilities[:limit]
    return vulnerabilities


def create_llm_client(endpoint: str | None, model: str | None, api_key: str | None) -> OpenAICompatibleClient:
    if not endpoint or not model or not api_key:
        raise ValueError("LLM endpoint, model, and API key must be configured")
    return OpenAICompatibleClient(endpoint=endpoint, model=model, api_key=api_key)


def git(repo_root: Path, *args: str, capture_output: bool = True) -> str:
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
    current_branch = git(repo_root, "rev-parse", "--abbrev-ref", "HEAD")
    git(repo_root, "checkout", "-b", new_branch)
    return current_branch


def restore_branch(repo_root: Path, original_branch: str, *, delete_branch: str | None = None) -> None:
    try:
        git(repo_root, "checkout", original_branch)
    finally:
        if delete_branch:
            try:
                git(repo_root, "branch", "-D", delete_branch)
            except subprocess.CalledProcessError:
                logger.warning("Failed to delete temporary branch %s", delete_branch)


def stage_and_commit(repo_root: Path, files: Iterable[Path], message: str) -> None:
    rel_paths = [str(path.relative_to(repo_root)) for path in files]
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


def build_pr_body(vulnerabilities, applied_patches: Sequence[AppliedPatch] | None = None) -> str:
    lines = ["## Summary", "This PR proposes automated fixes for the following findings:"]

    recommendations: dict[str, list[Mapping[str, object]]] = defaultdict(list)
    unmatched_metadata: list[Mapping[str, object]] = []

    if applied_patches:
        for patch in applied_patches:
            metadata = patch.candidate.metadata or {}
            if not metadata:
                continue
            vuln_id = metadata.get("vulnerability_id") or metadata.get("identifier") or metadata.get("id")
            if isinstance(vuln_id, str) and vuln_id.strip():
                recommendations[vuln_id.strip()].append(metadata)
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
            if analysis:
                lines.append(f"- {analysis}")
            else:
                lines.append(f"- {metadata}")

    lines.append("\nGenerated by the MCP auto-refactor pipeline.")
    return "\n".join(lines)


def open_pull_request(
    github_token: str | None,
    repository: str | None,
    head: str,
    base: str,
    vulnerabilities,
    applied_patches: Sequence[AppliedPatch] | None = None,
) -> None:
    if not github_token or not repository:
        logger.warning("GitHub credentials missing; skipping PR creation")
        return
    client = GitHubClient(token=github_token, repository=repository)
    payload = PullRequestPayload(
        title=f"Automated remediation: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}",
        body=build_pr_body(vulnerabilities, applied_patches),
        head=head,
        base=base,
    )
    response = client.create_pull_request(payload)
    logger.info("Opened PR #%s: %s", response.get("number"), response.get("html_url"))


def main() -> int:
    setup_logging()
    args = parse_args()
    repo_root = Path(args.repo_root).resolve()
    scan_results = Path(args.scan_results)

    if args.max_vulnerabilities is None:
        max_from_env = os.getenv("MCP_MAX_VULNS")
        if max_from_env:
            try:
                args.max_vulnerabilities = int(max_from_env)
            except ValueError:
                logger.warning("Invalid MCP_MAX_VULNS value '%s'", max_from_env)

    vulnerabilities = load_vulnerabilities(scan_results, args.max_vulnerabilities)
    if not vulnerabilities:
        logger.info("No vulnerabilities detected; nothing to remediate")
        return 0

    branch_name = f"{args.branch_prefix}{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    original_branch = checkout_branch(repo_root, branch_name)
    logger.info("Created remediation branch %s from %s", branch_name, original_branch)

    try:
        context = PromptContext(
            repository_name=args.github_repository or repo_root.name,
            base_branch=args.base_branch,
        )
        llm_client = create_llm_client(args.llm_endpoint, args.llm_model, args.llm_api_key)
        prompt_builder = PromptBuilder(repo_root=repo_root, context=context)
        formatters = args.formatter
        if not formatters:
            default_formatter = os.getenv("MCP_FORMATTER")
            if default_formatter:
                formatters = [default_formatter]

        patch_generator = PatchGenerator(
            repo_root=repo_root,
            llm_client=llm_client,
            prompt_builder=prompt_builder,
            formatters=formatters,
        )
        pipeline = AutoRemediationPipeline(
            repo_root=repo_root,
            patch_generator=patch_generator,
            validations=normalise_validations(args.validate),
        )

        applied_patches = pipeline.run(vulnerabilities)
        if not applied_patches:
            logger.info("Pipeline did not produce any patches")
            restore_branch(repo_root, original_branch, delete_branch=branch_name)
            return 0

        if args.dry_run:
            logger.info("Dry run requested; skipping commit and PR creation")
            draft_body = build_pr_body(vulnerabilities, applied_patches)
            logger.info("Generated recommendations:\n%s", draft_body)
            restore_branch(repo_root, original_branch, delete_branch=branch_name)
            return 0

        commit_message = "chore: automated remediation for scan findings"
        stage_and_commit(repo_root, [patch.path for patch in applied_patches], commit_message)
        logger.info("Committed remediation changes")

        push_branch(repo_root, branch_name, args.remote)
        logger.info("Pushed branch %s to %s", branch_name, args.remote)

        open_pull_request(
            github_token=args.github_token,
            repository=args.github_repository,
            head=branch_name,
            base=args.base_branch,
            vulnerabilities=vulnerabilities,
            applied_patches=applied_patches,
        )
    finally:
        restore_branch(repo_root, original_branch)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
