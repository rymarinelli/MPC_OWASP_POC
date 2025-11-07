from pathlib import Path
from typing import Optional, Dict, Any, List, Callable
import sys, inspect, os, json, subprocess, socket, tempfile, shutil, requests, traceback
from fastapi import FastAPI, HTTPException, Header
import uvicorn
from transformers import pipeline
from fastmcp import FastMCP
import os, json, tempfile, shutil, subprocess, traceback, requests
from pathlib import Path
from datetime import datetime
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
        ts = datetime.utcnow().strftime("%a-%d-%b-%Y-%H%MUTC")  # e.g. Thu-06-Nov-2025-1423UTC
        branch_name = f"mcp/remediation-{ts}"
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
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(f"# MCP Security Report\n\nTarget: {repo_url}\nTime: {ts}\nFindings: {len(findings)}\nPatched: {applied}\n\n{remediation_text}\n")

        subprocess.run(["git", "add", report_path], cwd=repo_dir)
        subprocess.run(["git", "commit", "-m", "Add MCP security report"], cwd=repo_dir)
        subprocess.run(["git", "push", "-u", "origin", branch_name, "--force"], cwd=repo_dir)
        # ============================================================
        # 🧱 SANDBOX INSPECTION STEP (TIMESTAMPED REPORT + COMMIT)
        # ============================================================
        try:
            print("[MCP] 🔄 Cloning sandbox inspection repo...")
            sandbox_repo_url = "https://github.com/rymarinelli/sandbox.git"
            sandbox_dir = os.path.join(tmp_dir, "sandbox")
            if os.path.exists(sandbox_dir):
                shutil.rmtree(sandbox_dir, ignore_errors=True)


            try:
                subprocess.run(["git", "clone", sandbox_repo_url, sandbox_dir], check=True, capture_output=True, text=True)
            except subprocess.CalledProcessError as e:
                token = os.getenv("GITHUB_TOKEN")
                if token:
                    authed_url = sandbox_repo_url.replace(
                        "https://", f"https://{token}@"
                    )
                    print("[MCP] 🔑 Retrying clone with token authentication...")
                    subprocess.run(["git", "clone", authed_url, sandbox_dir], check=True)
                else:
                    print("[MCP] ❌ Sandbox clone failed and no GITHUB_TOKEN available.")
                    print(e.stderr)
                    raise
            if clone_proc.returncode != 0:
                print(f"[MCP] ⚠️ Sandbox clone failed: {clone_proc.stderr.strip()}")
                return {
                    "error": "could not clone sandbox repo",
                    "stderr": clone_proc.stderr,
                    "returncode": clone_proc.returncode,
                }
            print("[MCP] ✅ Sandbox repo cloned successfully.")

         
            print("[MCP] 🧩 Installing sandbox dependencies...")
            subprocess.run(
                ["pip", "install", "-r", "requirements-dev.txt"],
                cwd=sandbox_dir, check=True, capture_output=True, text=True
            )

            print("[MCP] 🧠 Running inspect_vibe_code.py against remediated workspace...")

            sandbox_json = os.path.join(repo_dir, "sandbox_report.json")

            # Derive timestamp + use same suffix as remediation branch
            ts_suffix = branch_name.split("mcp/remediation-")[-1]  # e.g. Thu-06-Nov-2025-1423UTC
            sandbox_md = os.path.join(repo_dir, f"SANDBOX_SCAN_REPORT_{ts_suffix}.md")

            sandbox_proc = subprocess.run(
                [
                    "python",
                    "scripts/inspect_vibe_code.py",
                    "--workspace",
                    repo_dir,
                    "--prompt",
                    os.path.join(repo_dir, "prompts/user.txt")
                    if os.path.exists(os.path.join(repo_dir, "prompts/user.txt"))
                    else "prompts/user.txt",
                    "--fail-on-high",
                    "--json",
                ],
                cwd=sandbox_dir,
                capture_output=True,
                text=True,
            )

            with open(sandbox_json, "w", encoding="utf-8") as f:
                f.write(sandbox_proc.stdout)

            sandbox_status = "passed" if sandbox_proc.returncode == 0 else (
                "failed-high" if sandbox_proc.returncode == 2 else "error"
            )

            # ✅ Write Markdown summary (persistent trace)
            ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            with open(sandbox_md, "w", encoding="utf-8") as f:
                f.write(f"# Sandbox Inspection Report ({ts_suffix})\n\n")
                f.write(f"**Time:** {ts}\n\n")
                f.write(f"**Sandbox Status:** {sandbox_status}\n\n")
                f.write("## Raw Output\n\n```\n")
                if sandbox_proc.stdout.strip():
                    f.write("### STDOUT\n")
                    f.write(sandbox_proc.stdout[:8000])
                    f.write("\n\n")
                if sandbox_proc.stderr.strip():
                    f.write("### STDERR\n")
                    f.write(sandbox_proc.stderr[:8000])
                    f.write("\n")
                if not sandbox_proc.stdout.strip() and not sandbox_proc.stderr.strip():
                    f.write("(no output captured — process may have exited early or failed silently)\n")
                f.write("```\n")

            # ✅ Always commit & push the report
            ensure_git_identity(repo_dir)
            subprocess.run(["git", "add", sandbox_md], cwd=repo_dir)
            subprocess.run(
                ["git", "commit", "-m", f"Add sandbox scan report ({sandbox_status})"],
                cwd=repo_dir,
                check=False,
            )
            subprocess.run(
                ["git", "push", "-u", "origin", branch_name, "--force"],
                cwd=repo_dir,
                check=False,
            )

            if sandbox_proc.returncode == 2:
                print("[MCP] ❌ High severity findings detected — aborting PR creation.")
                return {
                    "repo_dir": repo_dir,
                    "sandbox_status": sandbox_status,
                    "sandbox_report": sandbox_md,
                    "stderr": sandbox_proc.stderr,
                }


            print(f"[MCP] Sandbox inspection complete ({sandbox_status}). Report committed.")
           # ============================================================
            # 🔍 Detailed sandbox run logging
            # ============================================================
            start_ts = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
            print(f"[MCP] 🧪 Sandbox run started at: {start_ts}")
            print(f"[MCP] 🧱 Sandbox command: {' '.join(sandbox_proc.args)}")
            print(f"[MCP] 🕒 Return code: {sandbox_proc.returncode}")

            stdout_preview = sandbox_proc.stdout[:1000].strip()
            stderr_preview = sandbox_proc.stderr[:1000].strip()

            print(f"[MCP] 📤 STDOUT (first 1k chars):\n{stdout_preview}\n---")
            if stderr_preview:
                print(f"[MCP] ⚠️ STDERR (first 1k chars):\n{stderr_preview}\n---")

            duration = getattr(sandbox_proc, "duration", None)
            if duration:
                print(f"[MCP] ⏱️ Duration: {duration:.2f}s")

        except Exception as e:
          print(f"[MCP] ⚠️ Sandbox inspection failed: {e}")
          fail_suffix = branch_name.split("mcp/remediation-")[-1]
          fail_md = os.path.join(repo_dir, f"SANDBOX_SCAN_REPORT_{fail_suffix}.md")

          raw_trace = traceback.format_exc()
          token = os.getenv("GITHUB_TOKEN")
          if token and token in raw_trace:
              masked_trace = raw_trace.replace(token, "***MASKED_GITHUB_TOKEN***")
          else:
              masked_trace = raw_trace

          # Also scrub any accidental 'https://<token>@' pattern (defense-in-depth)
          import re
          masked_trace = re.sub(r"https://[A-Za-z0-9_\-]+@github\.com", "https://***@github.com", masked_trace)

          with open(fail_md, "w", encoding="utf-8") as f:
              f.write(f"# Sandbox Inspection Error ({fail_suffix})\n\n")
              f.write(masked_trace + "\n")

          ensure_git_identity(repo_dir)
          subprocess.run(["git", "add", fail_md], cwd=repo_dir)
          subprocess.run(["git", "commit", "-m", "Add sandbox scan failure report"], cwd=repo_dir)
          subprocess.run(["git", "push", "-u", "origin", branch_name, "--force"], cwd=repo_dir)

          return {
              "repo_dir": repo_dir,
              "error": "sandbox step failed",
              "trace": masked_trace,
          }



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
