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
import subprocess
from datetime import UTC, datetime
from pathlib import Path
from typing import Sequence

from mcp import (
    AppliedPatch,
    AutoRemediationPipeline,
    GitHubClient,
    PatchGenerator,
    PromptBuilder,
    PromptContext,
    PullRequestPayload,
)
from mcp.remediation import (
    build_pr_body,
    checkout_branch,
    create_llm_client,
    git,
    load_vulnerabilities,
    normalise_validations,
    push_branch,
    restore_branch,
    stage_and_commit,
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
        title=f"Automated remediation: {datetime.now(UTC).strftime('%Y-%m-%d %H:%M:%S %Z')}",
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

    branch_name = f"{args.branch_prefix}{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
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
