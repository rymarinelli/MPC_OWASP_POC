from pathlib import Path
from typing import Optional, Dict, Any, List
from fastmcp import FastMCP
import subprocess, json, socket, os

# HF imports
from transformers import pipeline


def get_ip():
    """Get the machine's local IP (works in Colab, WSL, etc.)."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
    except Exception:
        ip = "127.0.0.1"
    return ip


mcp = FastMCP("mcp-owasp-remediator", host="0.0.0.0", port=8000)


# ------------------------
# Hugging Face textgen
# ------------------------
HF_MODEL_ID = os.getenv("HF_MODEL_ID", "HuggingFaceH4/zephyr-7b-beta")
_textgen = None


def get_textgen():
    global _textgen
    if _textgen is None:
        _textgen = pipeline(
            "text-generation",
            model=HF_MODEL_ID,
            trust_remote_code=True
        )
    return _textgen


def run_cmd(cmd: list, cwd: Optional[str] = None) -> Dict[str, Any]:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    return {
        "cmd": cmd,
        "returncode": proc.returncode,
        "stdout": proc.stdout,
        "stderr": proc.stderr,
    }


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


@mcp.tool()
def scan_repo(
    repo_path: str = ".",
    semgrep_config: str = "p/ci",
    llm_proposal: bool = True
) -> Dict[str, Any]:
    """
    Run Semgrep on the repo and (optionally) generate a Hugging Face remediation draft.
    """
    semgrep_cmd = [
        "semgrep",
        "scan",
        "--json",
        "--config", semgrep_config,
        repo_path,
    ]
    semgrep_result = run_cmd(semgrep_cmd)

    findings: List[dict] = []
    # Semgrep can return nonzero even with results, so always try to parse
    try:
        parsed = json.loads(semgrep_result["stdout"])
        findings = parsed.get("results", [])
    except Exception:
        findings = []

    remediation_text = ""
    if llm_proposal:
        remediation_text = hf_remediation_from_findings(findings)

    return {
        "semgrep": semgrep_result,
        "findings": findings,
        "llm_proposal": remediation_text,
        "model_used": HF_MODEL_ID,
    }


@mcp.tool()
def remediate(scan_results_path: str,
              validate_cmd: Optional[str] = "pytest -q",
              formatter: Optional[str] = "") -> Dict[str, Any]:
    """Run the auto-remediation pipeline."""
    cmd = [
        "python", "scripts/auto_refactor.py",
        "--scan-results", scan_results_path,
        "--validate", validate_cmd or ""
    ]
    if formatter:
        cmd += ["--formatter", formatter]
    proc = subprocess.run(cmd, capture_output=True, text=True)
    return {"stdout": proc.stdout, "stderr": proc.stderr, "returncode": proc.returncode}


@mcp.tool()
def open_pr(branch: str = "mcp/remediation",
            title: str = "Automated remediation",
            body: str = "Proposed fixes from MCP remediator") -> Dict[str, Any]:
    """Create a PR from the current branch."""
    def run(*args): subprocess.run(list(args), check=True)
    run("git", "checkout", "-B", branch)
    run("git", "add", "-A")
    try:
        run("git", "commit", "-m", title)
    except Exception:
        pass
    run("git", "push", "-u", "origin", branch, "--force")
    return {"branch": branch, "title": title, "body": body}


if __name__ == "__main__":
    ip = get_ip()
    print(f"\n🚀 MCP server running at:")
    print(f"   → http://{ip}:8000")
    print(f"   → curl -X POST http://{ip}:8000/call_tool -H 'Content-Type: application/json' "
          f"-d '{{\"tool_name\":\"remediate\",\"params\":{{\"scan_results_path\":\"results/scan.json\"}}}}'")
    print(f"   → curl -X POST http://{ip}:8000/call_tool -H 'Content-Type: application/json' "
          f"-d '{{\"tool_name\":\"scan_repo\",\"params\":{{\"repo_path\":\".\",\"semgrep_config\":\"p/ci\",\"llm_proposal\":true}}}}'\n")
    mcp.run()
