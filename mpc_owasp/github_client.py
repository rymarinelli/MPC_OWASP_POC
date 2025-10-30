"""GitHub API helpers for automated remediation."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional

import requests


@dataclass
class PullRequestPayload:
    """Payload used to open a pull request."""

    title: str
    body: str
    head: str
    base: str


class GitHubClient:
    """Thin wrapper around the GitHub REST API."""

    def __init__(self, token: str, repository: str, *, api_url: str = "https://api.github.com") -> None:
        self.token = token
        self.repository = repository
        self.api_url = api_url.rstrip("/")

    def _headers(self) -> Dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "Authorization": f"Bearer {self.token}",
            "X-GitHub-Api-Version": "2022-11-28",
        }

    def _request(self, method: str, path: str, **kwargs: Any) -> requests.Response:
        url = f"{self.api_url}/repos/{self.repository}/{path.lstrip('/')}"
        response = requests.request(method, url, headers=self._headers(), timeout=30, **kwargs)
        if response.status_code >= 400:
            raise RuntimeError(f"GitHub API {method} {url} failed: {response.status_code} {response.text}")
        return response

    def get_default_branch(self) -> str:
        response = self._request("GET", "")
        payload = response.json()
        return payload.get("default_branch", "main")

    def get_branch_sha(self, branch: str) -> str:
        response = self._request("GET", f"git/ref/heads/{branch}")
        payload = response.json()
        return payload["object"]["sha"]

    def create_branch(self, branch: str, sha: str) -> None:
        payload = {"ref": f"refs/heads/{branch}", "sha": sha}
        self._request("POST", "git/refs", json=payload)

    def create_pull_request(self, payload: PullRequestPayload) -> Dict[str, Any]:
        response = self._request(
            "POST",
            "pulls",
            json={
                "title": payload.title,
                "body": payload.body,
                "head": payload.head,
                "base": payload.base,
            },
        )
        return response.json()

    def ensure_branch(self, branch: str, base: Optional[str] = None) -> str:
        """Ensure *branch* exists and return its commit SHA."""

        try:
            return self.get_branch_sha(branch)
        except RuntimeError:
            base_branch = base or self.get_default_branch()
            sha = self.get_branch_sha(base_branch)
            self.create_branch(branch, sha)
            return sha


__all__ = ["GitHubClient", "PullRequestPayload"]
