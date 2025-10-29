"""CLI entrypoint for running the auto-remediation pipeline."""

from __future__ import annotations

import argparse
import logging
import os
import shlex
import subprocess
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable, List, Sequence

from .. import (
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


@dataclass
class AutoRefactorConfig:
    """Configuration required to execute the auto-refactor pipeline."""

    scan_results: Path
    repo_root: Path
    base_branch: str
    branch_prefix: str
    remote: str
    formatter: Sequence[str]
    validations: Sequence[str]
    llm_endpoint: str | None
    llm_model: str | None
    llm_api_key: str | None
    github_token: str | None
    github_repository: str | None
    dry_run: bool
    max_vulnerabilities: int | None


# ---------------------------- argument parsing ----------------------------


def build_argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Automate LLM-driven remediation")
    parser.add_argument("--scan-results", required=True, help="Path to the scan JSON file")
    parser.add_argument("--repo-root", default=os.getcwd(), help="Repository root path")
    parser.add_argument("--base-branch", default=os.getenv("GITHUB_BASE_REF", "main"))
    parser.add_argument("--branch-prefix", default="auto/remediate-")
    parser.add_argument("--remote", default="origin")
    parser.add_argument(
        "--formatter",
        action="append",
        default=[],
        help="Formatter command template with {path}",
    )
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
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run without committing, pushing, or opening a PR",
    )
    parser.add_argument("--max-vulnerabilities", type=int, default=None)
    return parser


def parse_args(argv: Sequence[str] | None = None) -> argparse.Namespace:
    parser = build_argument_parser()
    return parser.parse_args(argv)


def to_config(args: argparse.Namespace) -> AutoRefactorConfig:
    repo_root = Path(args.repo_root).resolve()
    scan_results = Path(args.scan_results)
    formatter = list(args.formatter or [])

    if not formatter:
        default_formatter = os.getenv("MCP_FORMATTER")
        if default_formatter:
            formatter = [default_formatter]

    max_vulnerabilities = args.max_vulnerabilities
    if max_vulnerabilities is None:
        max_from_env = os.getenv("MCP_MAX_VULNS")
        if max_from_env:
            try:
                max_vulnerabilities = int(max_from_env)
            except ValueError:
                logger.warning("Invalid MCP_MAX_VULNS value '%s'", max_from_env)

    return AutoRefactorConfig(
        scan_results=scan_results,
        repo_root=repo_root,
        base_branch=args.base_branch,
        branch_prefix=args.branch_prefix,
        remote=args.remote,
        formatter=tuple(formatter),
        validations=tuple(args.validate or []),
        llm_endpoint=args.llm_endpoint,
        llm_model=args.llm_model,
        llm_api_key=args.llm_api_key,
        github_token=args.github_token,
        github_repository=args.github_repository,
        dry_run=bool(args.dry_run),
        max_vulnerabilities=max_vulnerabilities,
    )


# ----------------------------- helper functions ----------------------------


def setup_logging(level: int = logging.INFO) -> None:
    logging.basicConfig(level=level, format="%(levelname)s:%(name)s:%(message)s")


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


# ------------------------------- git helpers -------------------------------


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
    git(repo_root, "commit", "-m", message)


def push_branch(repo_root: Path, branch: str, remote: str) -> None:
    git(repo_root, "push", "--set-upstream", remote, branch, capture_output=False)


# ------------------------------ PR generation ------------------------------


def build_pr_body(vulnerabilities) -> str:
    lines = ["## Summary", "This PR proposes automated fixes for the following findings:"]
    for vuln in vulnerabilities:
        lines.append(
            f"- **{vuln.identifier}** ({vuln.severity}) in `{vuln.file_path}` lines {vuln.affected_range()}: "
            f"{vuln.summary or 'No summary provided.'}"
        )
        if vuln.recommendation:
            lines.append(f"  - Recommended fix: {vuln.recommendation}")
    lines.append("\nGenerated by the MCP auto-refactor pipeline.")
    return "\n".join(lines)


def open_pull_request(
    github_token: str | None,
    repository: str | None,
    head: str,
    base: str,
    vulnerabilities,
) -> None:
    if not github_token or not repository:
        logger.warning("GitHub credentials missing; skipping PR creation")
        return
    client = GitHubClient(token=github_token, repository=repository)
    payload = PullRequestPayload(
        title=f"Automated remediation: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}",
        body=build_pr_body(vulnerabilities),
        head=head,
        base=base,
    )
    response = client.create_pull_request(payload)
    logger.info("Opened PR #%s: %s", response.get("number"), response.get("html_url"))


# ------------------------------- main runner -------------------------------


def run_pipeline(config: AutoRefactorConfig) -> int:
    vulnerabilities = load_vulnerabilities(config.scan_results, config.max_vulnerabilities)
    if not vulnerabilities:
        logger.info("No vulnerabilities detected; nothing to remediate")
        return 0

    branch_name = f"{config.branch_prefix}{datetime.utcnow().strftime('%Y%m%d%H%M%S')}"
    original_branch = checkout_branch(config.repo_root, branch_name)
    logger.info("Created remediation branch %s from %s", branch_name, original_branch)

    try:
        context = PromptContext(
            repository_name=config.github_repository or config.repo_root.name,
            base_branch=config.base_branch,
        )
        llm_client = create_llm_client(config.llm_endpoint, config.llm_model, config.llm_api_key)
        prompt_builder = PromptBuilder(repo_root=config.repo_root, context=context)

        patch_generator = PatchGenerator(
            repo_root=config.repo_root,
            llm_client=llm_client,
            prompt_builder=prompt_builder,
            formatters=config.formatter,
        )
        pipeline = AutoRemediationPipeline(
            repo_root=config.repo_root,
            patch_generator=patch_generator,
            validations=normalise_validations(config.validations),
        )

        applied_files = pipeline.run(vulnerabilities)
        if not applied_files:
            logger.info("Pipeline did not produce any patches")
            restore_branch(config.repo_root, original_branch, delete_branch=branch_name)
            return 0

        if config.dry_run:
            logger.info("Dry run requested; skipping commit and PR creation")
            restore_branch(config.repo_root, original_branch, delete_branch=branch_name)
            return 0

        commit_message = "chore: automated remediation for scan findings"
        stage_and_commit(config.repo_root, applied_files, commit_message)
        logger.info("Committed remediation changes")

        push_branch(config.repo_root, branch_name, config.remote)
        logger.info("Pushed branch %s to %s", branch_name, config.remote)

        open_pull_request(
            github_token=config.github_token,
            repository=config.github_repository,
            head=branch_name,
            base=config.base_branch,
            vulnerabilities=vulnerabilities,
        )
    finally:
        restore_branch(config.repo_root, original_branch)
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    setup_logging()
    args = parse_args(argv)
    config = to_config(args)
    return run_pipeline(config)
