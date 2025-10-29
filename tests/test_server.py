import json
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

from mcp import server


def _create_remote_repo(base_dir: Path) -> Path:
    workdir = base_dir / "work"
    workdir.mkdir()
    subprocess.run(
        ["git", "init", "--initial-branch", "main"],
        cwd=workdir,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=workdir,
        check=True,
        capture_output=True,
        text=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=workdir,
        check=True,
        capture_output=True,
        text=True,
    )
    src_dir = workdir / "src"
    src_dir.mkdir()
    (src_dir / "example.py").write_text("print('hello')\n", encoding="utf-8")
    subprocess.run(["git", "add", "src/example.py"], cwd=workdir, check=True, capture_output=True, text=True)
    subprocess.run(["git", "commit", "-m", "initial"], cwd=workdir, check=True, capture_output=True, text=True)

    remote_path = base_dir / "remote.git"
    subprocess.run(
        ["git", "clone", "--bare", str(workdir), str(remote_path)],
        check=True,
        capture_output=True,
        text=True,
    )
    return remote_path


class DummyLLM:
    def __init__(self, response: str) -> None:
        self._response = response

    def generate(self, prompt: str, **_: object) -> str:  # pragma: no cover - simple stub
        return self._response


def test_healthcheck() -> None:
    client = TestClient(server.app)
    response = client.get("/healthz")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_remediate_dry_run_returns_patch_details() -> None:
    client = TestClient(server.app)
    llm_response = json.dumps(
        [
            {
                "file_path": "src/example.py",
                "replacement": "print('patched')\n",
                "vulnerability_id": "OWASP-1",
                "analysis": "Patched for test",
            }
        ]
    )

    scan_results = [
        {
            "id": "OWASP-1",
            "file": "src/example.py",
            "summary": "Example finding",
            "recommendation": "Patched",
            "severity": "high",
            "start_line": 1,
            "end_line": 1,
        }
    ]

    with tempfile.TemporaryDirectory() as tmp:
        remote_repo = _create_remote_repo(Path(tmp))
        with patch("mcp.server.create_llm_client", return_value=DummyLLM(llm_response)):
            payload = {
                "repository": "example/repo",
                "repository_url": str(remote_repo),
                "scan_results": scan_results,
                "github_token": "dummy",
                "llm_endpoint": "http://dummy",
                "llm_model": "dummy-model",
                "llm_api_key": "dummy",
                "dry_run": True,
            }
            response = client.post("/remediate", json=payload)

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "dry_run"
    assert body["branch"].startswith("auto/remediate-")
    assert body["applied_patches"] == [
        {
            "file_path": "src/example.py",
            "replacement": "print('patched')\n",
            "metadata": {
                "vulnerability_id": "OWASP-1",
                "analysis": "Patched for test",
            },
        }
    ]
    assert body["message"] == "Dry run requested; changes were not committed"
