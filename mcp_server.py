from pathlib import Path
from typing import Optional, Dict, Any, List, Callable
import sys, inspect, os, json, subprocess, socket, tempfile, shutil, requests, traceback
from fastapi import FastAPI, HTTPException, Header
import uvicorn
from transformers import pipeline
from fastmcp import FastMCP
import os, json, tempfile, shutil, subprocess, traceback, requests
from pathlib import Path

# ============================================================
# CONFIG
# ============================================================
API_KEY = os.getenv("MCP_HTTP_API_KEY")
HF_MODEL_ID = os.getenv("HF_MODEL_ID", "ise-uiuc/Magicoder-CL-7B")
BACKUP_DIR = os.getenv("MCP_BACKUP_DIR", ".mcp_backups")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")

# ============================================================
# UTILITIES
# ============================================================
def get_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "127.0.0.1"
    return ip


def ensure_git_identity(cwd: str):
    """Ensure git has a user.name and user.email set locally."""
    try:
        subprocess.run(["git", "config", "user.email"], cwd=cwd, check=True, capture_output=True, text=True)
        subprocess.run(["git", "config", "user.name"], cwd=cwd, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError:
        subprocess.run(["git", "config", "user.email", "mcp-bot@example.com"], cwd=cwd, check=True)
        subprocess.run(["git", "config", "user.name", "MCP Bot"], cwd=cwd, check=True)


def run_cmd(cmd: list, cwd: Optional[str] = None) -> Dict[str, Any]:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return {"cmd": cmd, "returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}

# ============================================================
# LLM PIPELINE
# ============================================================
_textgen = None
def get_textgen():
    global _textgen
    if _textgen is None:
        _textgen = pipeline("text-generation", model=HF_MODEL_ID, trust_remote_code=True, device=0)
    return _textgen

def hf_remediation_from_findings(findings: List[dict]) -> str:
    textgen = get_textgen()
    issues_txt = "\n".join(
        f"- {f.get('check_id')}: {f.get('path')}:{f.get('start',{}).get('line')} – {f.get('extra',{}).get('message')}"
        for f in findings
    ) or "No issues."
    prompt = (
        "You are a senior application security engineer. Based on the following Semgrep findings, "
        "write (1) a short risk summary, (2) prioritized remediation steps, and (3) example code/patterns.\n\n"
        f"Findings:\n{issues_txt}\n\nAnswer:\n"
    )
    out = textgen(prompt, max_new_tokens=256, do_sample=False)[0]["generated_text"]
    return out[len(prompt):].strip() if out.startswith(prompt) else out

# ============================================================
# MCP SETUP
# ============================================================
mcp = FastMCP("mcp-owasp-remediator")
TOOL_REGISTRY: Dict[str, Callable[..., Any]] = {}

def register_tool(name: str):
    def decorator(func):
        mcp.tool(name=name)(func)
        TOOL_REGISTRY[name] = func
        return func
    return decorator

# ============================================================
# TOOLS
# ============================================================
@register_tool("ping")
def ping() -> Dict[str, Any]:
    return {"ok": True, "ip": get_ip()}


@register_tool("scan_github_repo")
def scan_github_repo(
    repo_url: str,
    semgrep_config: str = "p/ci",
    llm_proposal: bool = True,
    quick: bool = True,
    create_pr: bool = True,
    base_branch: str = "main",
    pr_labels: Optional[List[str]] = None,
) -> dict:
    """
    Clone, run Semgrep, let LLM propose AND APPLY fixes, write a Markdown report,
    commit, push, and open a PR with Markdown rendered in the PR body.
    """
    if pr_labels is None:
        pr_labels = ["security", "automated", "needs-review"]

    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    tmp_dir = tempfile.mkdtemp(prefix="mcp_semgrep_")
    repo_dir = os.path.join(tmp_dir, "repo")

    try:
        parts = repo_url.rstrip("/").split("/")
        owner, repo = parts[-2], parts[-1]
        clone_url = f"https://x-access-token:{GITHUB_TOKEN}@github.com/{owner}/{repo}.git" if GITHUB_TOKEN else f"https://github.com/{owner}/{repo}.git"

        clone_cmd = ["git", "clone", "--depth", "1", "--branch", base_branch, clone_url, repo_dir]
        clone_proc = subprocess.run(clone_cmd, capture_output=True, text=True)
        if clone_proc.returncode != 0:
            clone_cmd = ["git", "clone", "--depth", "1", "--branch", "master", clone_url, repo_dir]
            clone_proc = subprocess.run(clone_cmd, capture_output=True, text=True)
            if clone_proc.returncode != 0:
                return {"error": "could not clone repo", "stderr": clone_proc.stderr}

        if not os.path.isdir(os.path.join(repo_dir, ".git")):
            return {"error": "repo cloned but .git missing", "repo_dir": repo_dir}

        semgrep_cmd = ["semgrep","scan","--json","--exclude","node_modules","--exclude",".npm", "--exclude", "__pycache__", "--exclude", ".venv", "--config",("auto" if quick else semgrep_config),repo_dir]
        semgrep_proc = subprocess.run(semgrep_cmd, capture_output=True, text=True)
        findings: List[dict] = []
        if semgrep_proc.returncode == 0:
            try:
                findings = json.loads(semgrep_proc.stdout).get("results", [])
            except Exception:
                findings = []

        remediation_text = hf_remediation_from_findings(findings) if llm_proposal else ""

        ensure_git_identity(repo_dir)
        branch_name = "mcp/remediation"
        subprocess.run(["git", "checkout", "-b", branch_name], cwd=repo_dir, check=True)

        def apply_llm_fix_to_file(finding: dict):
            """
            Comment the vulnerable line and show the LLM's proposed fix beneath it.
            LLM outputs only code, we handle wrapping.
            """
            rel_path = finding.get("path")
            if not rel_path:
                return False

            target_file = os.path.join(repo_dir, rel_path)
            if not os.path.exists(target_file):
                return False

            start_info = finding.get("start", {}) or finding.get("extra", {}).get("lines", {})
            line_no = start_info.get("line")
            if not line_no:
                print(f"[MCP] Missing line info for {rel_path}")
                return False

            extra = finding.get("extra", {})
            message = extra.get("message", "")
            severity = extra.get("severity", "")
            check_id = finding.get("check_id", "semgrep_rule")

            try:
                with open(target_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()

                vuln_line = lines[line_no - 1].rstrip("\n")

                llm_prompt = (
                    "You are a secure code assistant. Rewrite ONLY this single line securely.\n"
                    f"Rule: {check_id}\nSeverity: {severity}\nMessage: {message}\n"
                    "Return ONLY the corrected code. Do not explain.\n"
                    f"Vulnerable line:\n{vuln_line}"
                )

                textgen = get_textgen()
                llm_out = textgen(llm_prompt, max_new_tokens=60, do_sample=False)[0]["generated_text"]
                fixed_line = llm_out[len(llm_prompt):].strip()

                if not fixed_line:
                    print(f"[MCP] No fix returned for {rel_path}:{line_no}")
                    return False

            except Exception as e:
                print(f"[MCP] LLM failure for {rel_path}: {e}")
                return False

            try:
                # Build a comment block wrapping old/new lines
                block = [
                    f"# === MCP FIX START ({check_id}) ===\n",
                    f"# {message}\n",
                    f"# Severity: {severity}\n",
                    vuln_line + "\n",
                    f"# → Suggested secure fix:\n",
                    fixed_line + "\n",
                    "# === MCP FIX END ===\n",
                ]

                # Insert below the original line
                lines[line_no - 1:line_no] = block

                with open(target_file, "w", encoding="utf-8") as f:
                    f.writelines(lines)

                # ✅ Refresh file for next patch
                with open(target_file, "r", encoding="utf-8") as f:
                    _ = f.read()

                print(f"[MCP] Suggested fix added to {rel_path}:{line_no}")
                return True
            except Exception as e:
                print(f"[MCP] Write failed for {rel_path}: {e}")
                return False


          
        applied = 0
        for fnd in findings[:50]:
            if apply_llm_fix_to_file(fnd):
                applied += 1
                rel_path = fnd.get("path")
                check_id = fnd.get("check_id", "semgrep_rule")
                msg = f"Auto remediation: {rel_path} ({check_id})"
                subprocess.run(["git", "add", rel_path], cwd=repo_dir)
                subprocess.run(["git", "commit", "-m", msg], cwd=repo_dir)

        report_path = os.path.join(repo_dir, "MCP_SECURITY_REPORT.md")
        ts = __import__("datetime").datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"# MCP Security Report\n\nTarget: {repo_url}\nTime: {ts}\nFindings: {len(findings)}\nPatched: {applied}\n\n{remediation_text}\n")

        subprocess.run(["git", "add", report_path], cwd=repo_dir)
        subprocess.run(["git", "commit", "-m", "Add MCP security report"], cwd=repo_dir)
        subprocess.run(["git", "push", "-u", "origin", branch_name, "--force"], cwd=repo_dir)

        return {"repo_dir": repo_dir, "num_findings": len(findings), "llm_applied_fixes": applied, "report_path": report_path}

    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ============================================================
# FASTAPI SERVER
# ============================================================
app = FastAPI()

@app.get("/")
async def root():
    return {"status": "ok", "tools": list(TOOL_REGISTRY.keys()), "ip": get_ip()}

@app.post("/call_tool")
async def call_tool(payload: Dict[str, Any], x_api_key: Optional[str] = Header(default=None)):
    if API_KEY:
        if not x_api_key or x_api_key != API_KEY:
            raise HTTPException(status_code=401, detail="invalid or missing API key")

    name = payload.get("tool_name")
    args = payload.get("params") or {}
    if not name:
        raise HTTPException(status_code=400, detail="tool_name required")
    func = TOOL_REGISTRY.get(name)
    if func is None:
        raise HTTPException(status_code=404, detail=f"Tool '{name}' not found")
    try:
        result = func(**args)
    except Exception as e:
        result = {"error": str(e), "trace": traceback.format_exc()}
    return result

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
