"""FastAPI server exposing the MCP auto-remediation workflow."""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Dict, List, Sequence
from urllib.parse import quote

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from .github_client import GitHubClient, PullRequestPayload
from .patch_generator import PatchGenerator
from .pipeline import AppliedPatch, AutoRemediationPipeline
from .prompt_builder import PromptBuilder, PromptContext
from .remediation import (
    build_pr_body,
    checkout_branch,
    create_llm_client,
    git,
    normalise_validations,
    parse_vulnerabilities_payload,
    push_branch,
    stage_and_commit,
)
from .scan_parser import Vulnerability

logger = logging.getLogger(__name__)
app = FastAPI(title="MCP Auto-Remediation Server")


class PatchResult(BaseModel):
    """Serialized representation of an applied patch."""

    file_path: str
    replacement: str
    metadata: Dict[str, Any] = Field(default_factory=dict)


class RemediationRequest(BaseModel):
    """Request payload describing a remediation job."""

    repository: str = Field(..., description="<owner>/<repo> identifier for GitHub")
    scan_results: Any = Field(..., description="Vulnerability scan payload or list")
    github_token: str = Field(..., description="Token with permissions to push branches and open PRs")
    llm_endpoint: str = Field(..., description="OpenAI-compatible endpoint URL")
    llm_model: str = Field(..., description="LLM model identifier")
    llm_api_key: str = Field(..., description="API key for the LLM provider")
    base_branch: str | None = Field(None, description="Base branch for remediation PRs")
    branch_name: str | None = Field(None, description="Optional explicit branch name")
    branch_prefix: str = Field("auto/remediate-", description="Prefix used when generating branch names")
    remote: str = Field("origin", description="Git remote to push to")
    formatter: List[str] = Field(default_factory=list, description="Formatter command templates")
    validations: List[str] = Field(default_factory=list, description="Validation commands to run")
    dry_run: bool = Field(False, description="Skip commit/push/PR steps while returning generated patches")
    max_vulnerabilities: int | None = Field(None, description="Limit number of vulnerabilities processed")
    repository_url: str | None = Field(None, description="Override clone URL; defaults to GitHub HTTPS")
    pr_title: str | None = Field(None, description="Optional pull request title override")
    commit_message: str | None = Field(None, description="Optional commit message override")
    git_author_name: str = Field("MCP Bot", description="Git commit author name")
    git_author_email: str = Field("mcp@example.com", description="Git commit author email")
    clone_depth: int | None = Field(None, description="Optional shallow clone depth")


class RemediationResponse(BaseModel):
    """Response payload describing the remediation outcome."""

    status: str
    branch: str | None = None
    base_branch: str | None = None
    commit_sha: str | None = None
    pr_url: str | None = None
    pr_number: int | None = None
    applied_patches: List[PatchResult] = Field(default_factory=list)
    validations: List[List[str]] = Field(default_factory=list)
    message: str | None = None


class HealthResponse(BaseModel):
    status: str


def _build_clone_url(request: RemediationRequest) -> str:
    if request.repository_url:
        return request.repository_url
    token = quote(request.github_token, safe="") if request.github_token else ""
    if token:
        return f"https://x-access-token:{token}@github.com/{request.repository}.git"
    return f"https://github.com/{request.repository}.git"


def _clone_repository(clone_url: str, destination: Path, depth: int | None = None) -> None:
    command = ["git", "clone"]
    if depth:
        command.extend(["--depth", str(depth)])
    command.extend([clone_url, str(destination)])
    logger.info("Cloning repository from %s", clone_url)
    subprocess.run(command, check=True, capture_output=True, text=True)


def _configure_git_identity(repo_root: Path, name: str, email: str) -> None:
    git(repo_root, "config", "user.name", name)
    git(repo_root, "config", "user.email", email)


def _serialise_patch(repo_root: Path, patch: AppliedPatch) -> PatchResult:
    relative_path = str(patch.path.relative_to(repo_root))
    return PatchResult(
        file_path=relative_path,
        replacement=patch.candidate.replacement,
        metadata=dict(patch.candidate.metadata or {}),
    )


def _default_commit_message() -> str:
    timestamp = datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S %Z")
    return f"chore: automated remediation ({timestamp})"


def _default_pr_title(vulnerabilities: Sequence[Vulnerability]) -> str:
    if vulnerabilities:
        head = vulnerabilities[0]
        return f"Automated remediation for {head.identifier}"
    return "Automated remediation"


def _generate_branch_name(prefix: str) -> str:
    return f"{prefix}{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"


def _parse_scan_results(payload: Any, limit: int | None = None) -> List[Vulnerability]:
    try:
        return parse_vulnerabilities_payload(payload, limit=limit)
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=f"Invalid scan payload: {exc}") from exc


def _run_pipeline(
    repo_root: Path,
    request: RemediationRequest,
    vulnerabilities: List[Vulnerability],
    base_branch: str,
    validations: List[List[str]],
) -> List[AppliedPatch]:
    context = PromptContext(repository_name=request.repository, base_branch=base_branch)
    prompt_builder = PromptBuilder(repo_root, context=context)
    llm_client = create_llm_client(request.llm_endpoint, request.llm_model, request.llm_api_key)
    patch_generator = PatchGenerator(
        repo_root=repo_root,
        llm_client=llm_client,
        prompt_builder=prompt_builder,
        formatters=request.formatter,
    )
    pipeline = AutoRemediationPipeline(repo_root, patch_generator, validations=validations)
    return pipeline.run(vulnerabilities)


def _checkout_base_branch(repo_root: Path, base_branch: str) -> None:
    git(repo_root, "checkout", base_branch)


def _prepare_branch(repo_root: Path, request: RemediationRequest, base_branch: str) -> str:
    branch_name = request.branch_name or _generate_branch_name(request.branch_prefix)
    _checkout_base_branch(repo_root, base_branch)
    checkout_branch(repo_root, branch_name)
    return branch_name


def _create_pull_request(
    request: RemediationRequest,
    base_branch: str,
    branch_name: str,
    vulnerabilities: Sequence[Vulnerability],
    applied_patches: Sequence[AppliedPatch],
) -> tuple[str | None, int | None]:
    github_client = GitHubClient(request.github_token, request.repository)
    pr_body = build_pr_body(vulnerabilities, applied_patches)
    pr_title = request.pr_title or _default_pr_title(vulnerabilities)
    payload = PullRequestPayload(title=pr_title, body=pr_body, head=branch_name, base=base_branch)
    response = github_client.create_pull_request(payload)
    return response.get("html_url"), response.get("number")


def _validate_base_branch(repo_root: Path, request: RemediationRequest) -> str:
    if request.base_branch:
        _checkout_base_branch(repo_root, request.base_branch)
        return request.base_branch
    return git(repo_root, "rev-parse", "--abbrev-ref", "HEAD")


def _execute_remediation(request: RemediationRequest) -> RemediationResponse:
    with tempfile.TemporaryDirectory() as tmp:
        workdir = Path(tmp) / "repo"
        clone_url = _build_clone_url(request)
        _clone_repository(clone_url, workdir, request.clone_depth)
        base_branch = _validate_base_branch(workdir, request)
        _configure_git_identity(workdir, request.git_author_name, request.git_author_email)

        validations = normalise_validations(request.validations)
        vulnerabilities = _parse_scan_results(request.scan_results, request.max_vulnerabilities)
        if not vulnerabilities:
            return RemediationResponse(
                status="no_vulnerabilities",
                base_branch=base_branch,
                validations=validations,
                message="No vulnerabilities to remediate",
            )

        branch_name = _prepare_branch(workdir, request, base_branch)
        applied_patches = _run_pipeline(workdir, request, vulnerabilities, base_branch, validations)
        patch_details = [_serialise_patch(workdir, patch) for patch in applied_patches]

        if not applied_patches:
            return RemediationResponse(
                status="no_patches",
                branch=branch_name,
                base_branch=base_branch,
                applied_patches=patch_details,
                validations=validations,
                message="Pipeline did not generate any patches",
            )

        if request.dry_run:
            return RemediationResponse(
                status="dry_run",
                branch=branch_name,
                base_branch=base_branch,
                applied_patches=patch_details,
                validations=validations,
                message="Dry run requested; changes were not committed",
            )

        head_before = git(workdir, "rev-parse", "HEAD")
        commit_message = request.commit_message or _default_commit_message()
        stage_and_commit(workdir, [patch.path for patch in applied_patches], commit_message)
        head_after = git(workdir, "rev-parse", "HEAD")

        if head_before == head_after:
            return RemediationResponse(
                status="no_changes",
                branch=branch_name,
                base_branch=base_branch,
                applied_patches=patch_details,
                validations=validations,
                message="No changes were committed",
            )

        commit_sha = head_after
        push_branch(workdir, branch_name, request.remote)
        pr_url, pr_number = _create_pull_request(request, base_branch, branch_name, vulnerabilities, applied_patches)

        return RemediationResponse(
            status="completed",
            branch=branch_name,
            base_branch=base_branch,
            commit_sha=commit_sha,
            pr_url=pr_url,
            pr_number=pr_number,
            applied_patches=patch_details,
            validations=validations,
            message="Remediation completed successfully",
        )


@app.get("/healthz", response_model=HealthResponse)
def healthcheck() -> HealthResponse:
    return HealthResponse(status="ok")


@app.post("/remediate", response_model=RemediationResponse)
def remediate(request: RemediationRequest) -> RemediationResponse:
    try:
        return _execute_remediation(request)
    except HTTPException:
        raise
    except subprocess.CalledProcessError as exc:
        logger.exception("Subprocess command failed: %s", exc)
        detail = {
            "command": exc.cmd,
            "returncode": exc.returncode,
            "stdout": exc.stdout,
            "stderr": exc.stderr,
        }
        raise HTTPException(status_code=500, detail=detail) from exc
    except Exception as exc:  # noqa: BLE001
        logger.exception("Remediation failed")
        raise HTTPException(status_code=500, detail=str(exc)) from exc


def create_app() -> FastAPI:
    """Return the configured FastAPI application."""

    return app


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8000)
