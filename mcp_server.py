%%writefile mcp_server.py
from pathlib import Path
import re
from typing import Optional, Dict, Any, List, Callable
import sys, inspect, os, json, subprocess, socket, tempfile, shutil, requests, traceback, hashlib
from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from durinn_topic_model import topic_model_vulns
from durinn_topic_drift import (
    topic_distribution,
    kl_divergence,
    jaccard_drift,
    topic_heatmap_points,
    topic_drift_points
)
import uvicorn
from transformers import pipeline
from fastmcp import FastMCP
from datetime import datetime

# ============================================================
# CONFIG
# ============================================================
API_KEY = os.getenv("MCP_HTTP_API_KEY")
HF_MODEL_ID = os.getenv("HF_MODEL_ID", "ise-uiuc/Magicoder-CL-7B")
BACKUP_DIR = os.getenv("MCP_BACKUP_DIR", ".mcp_backups")
GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
TSDB_API_KEY = os.getenv("TSDB_API_KEY")
TSDB_ENDPOINT = os.getenv("TSDB_ENDPOINT")

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


def mask_sensitive(text: str) -> str:
    TOKEN_MASK = "***MASKED_GITHUB_TOKEN***"
    EMAIL_MASK = "***MASKED_EMAIL***"
    if not text:
        return text
    tok = os.getenv("GITHUB_TOKEN")

    if tok:
        text = text.replace(tok, TOKEN_MASK)
        # also mask URLs like https://<token>@github.com
        text = re.sub(r"https://[^/@\s]+@github\.com", f"https://{TOKEN_MASK}@github.com", text)
    # Mask generic 20-100 char token-ish blobs that appear in basic-auth URLs
    text = re.sub(r"https://[A-Za-z0-9_\-]{20,100}@github\.com", f"https://{TOKEN_MASK}@github.com", text)
    # Mask emails
    text = re.sub(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", EMAIL_MASK, text)
    return text


# ============================================================
# COMMIT-LEVEL VULNERABILITY TRACKER
# ============================================================

def load_json(path: str | Path) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: str | Path, data: dict):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def stable_uid(rule_id: str, file_path: str, f: dict) -> str:
    fp = (f.get("raw") or {}).get("extra", {}).get("fingerprint")
    if fp:
        return fp

    # fallback if no fingerprint exists
    start = (f.get("raw") or {}).get("start", {}).get("line", "")
    end   = (f.get("raw") or {}).get("end", {}).get("line", "")

    h = hashlib.sha1()
    h.update((rule_id or "").encode())
    h.update((file_path or "").encode())
    h.update(f"{start}-{end}".encode())
    return h.hexdigest()

def extract_vulns(snapshot: dict) -> Dict[str, dict]:
    """
    Extract normalized vulnerabilities from an MCP scan snapshot.
    FLATTEN Semgrep metadata → keep only minimal fields needed for analytics.
    """
    vulns: Dict[str, dict] = {}

    for f in snapshot.get("findings", []):
        rule_id = f.get("rule_id")
        file_path = f.get("file")
        code = f.get("code_excerpt", "") or ""
        severity = f.get("severity")

        # Semgrep raw
        raw = (f.get("raw") or {})
        extra = (raw.get("extra") or {})

        uid = stable_uid(rule_id or "", file_path or "", f)

        vuln = {
            "uid": uid,
            "rule_id": rule_id,
            "file": file_path,
            "code": code,
            "severity": severity,
            # flatten fields you asked for
            "semgrep_fingerprint": extra.get("fingerprint"),
            "asvs": (extra.get("metadata") or {}).get("asvs"),
            "owasp": (extra.get("metadata") or {}).get("owasp"),
            "references": (extra.get("metadata") or {}).get("references"),
        }

        vulns[uid] = vuln

    return vulns

def compute_diff(prev: Dict[str, dict], curr: Dict[str, dict]) -> dict:
    prev_set = set(prev.keys())
    curr_set = set(curr.keys())

    return {
        "added": list(curr_set - prev_set),
        "removed": list(prev_set - curr_set),
        "persisted": list(curr_set & prev_set),
    }

def update_ttf_store(ttf_path: str, commit_sha: str, timestamp: str,
                     diff: dict):
    """
    ttf_store.json structure:
    {
        vuln_uid: {
            "first_seen_sha": "...",
            "first_seen_at": "...",
            "last_seen_sha": "...",
            "resolved_sha": null,
            "resolved_at": null
        }
    }
    """
    if os.path.exists(ttf_path):
        store = load_json(ttf_path)
    else:
        store = {}

    # Seed store the first time we see any vulns, so that "removed" doesn't blow up.
    if not store:
        for uid in diff.get("persisted", []) + diff.get("removed", []):
            if uid not in store:
                store[uid] = {
                    "first_seen_sha": commit_sha,
                    "first_seen_at": timestamp,
                    "last_seen_sha": commit_sha,
                    "resolved_sha": None,
                    "resolved_at": None,
                }

    # Newly added → record first_seen
    for uid in diff.get("added", []):
        if uid not in store:
            store[uid] = {
                "first_seen_sha": commit_sha,
                "first_seen_at": timestamp,
                "last_seen_sha": commit_sha,
                "resolved_sha": None,
                "resolved_at": None,
            }
        else:
            store[uid]["last_seen_sha"] = commit_sha

    # Persisted → ensure they exist and update last_seen
    for uid in diff.get("persisted", []):
        if uid not in store:
            store[uid] = {
                "first_seen_sha": commit_sha,
                "first_seen_at": timestamp,
                "last_seen_sha": commit_sha,
                "resolved_sha": None,
                "resolved_at": None,
            }
        else:
            store[uid]["last_seen_sha"] = commit_sha

    # Removed → mark as resolved *only if* we know about them
    for uid in diff.get("removed", []):
        if uid in store and store[uid].get("resolved_sha") is None:
            store[uid]["resolved_sha"] = commit_sha
            store[uid]["resolved_at"] = timestamp

    write_json(ttf_path, store)
    return store


def topic_model_vulns(vuln_records: Dict[str, dict]) -> Dict[str, str]:
    """
    Stub: plug in your real embedding + clustering pipeline.
    Return:
        { vuln_uid: topic_cluster }
    """
    # For now just echo rule_id as pseudo-topic
    return {uid: (v.get("rule_id") or "unknown") for uid, v in vuln_records.items()}

def push_commit_report_to_timeseries(report: dict, owner: str, repo: str):
    """
    Push commit-level vulnerability data into a time-series backend.

    Shape (generic JSON for an HTTP ingester):
      - One summary point per commit
      - One point per vuln present in that commit
      - One point per topic frequency (heatmap)
    """
    if not TSDB_ENDPOINT:
        return

    points: List[dict] = []

    # Extract fields from report FIRST
    commit_sha = report.get("commit_sha")
    ts_iso = report.get("timestamp")  # ISO-8601 UTC
    stats = report.get("stats", {}) or {}
    vulns = report.get("vulns", {}) or {}
    topics = report.get("topics", {}) or {}

    # ----- Topic Heatmap -----
    try:
        topic_points = topic_heatmap_points(
            commit_sha=commit_sha,
            timestamp=ts_iso,
            topics=topics,
            owner=owner,
            repo=repo
        )
        points.extend(topic_points)
    except Exception as e:
        print(f"[MCP] ⚠️ Topic heatmap generation failed: {e}")

    # ----- Summary point per commit -----
    points.append({
        "measurement": "vuln_commit_summary",
        "time": ts_iso,
        "tags": {
            "owner": owner,
            "repo": repo,
            "commit_sha": commit_sha,
        },
        "fields": {
            "total": int(stats.get("total", 0) or 0),
            "added": int(stats.get("added", 0) or 0),
            "removed": int(stats.get("removed", 0) or 0),
            "persisted": int(stats.get("persisted", 0) or 0),
        },
    })

    # ----- per-vuln point -----
    for uid, v in vulns.items():
        points.append({
            "measurement": "vuln_state",
            "time": ts_iso,
            "tags": {
                "owner": owner,
                "repo": repo,
                "commit_sha": commit_sha,
                "vuln_uid": uid,
                "rule_id": v.get("rule_id") or "",
                "severity": v.get("severity") or "",
            },
            "fields": {
                "is_present": 1,
            },
        })

    # ----- Send all points -----
    headers = {"Content-Type": "application/json"}
    if TSDB_API_KEY:
        headers["Authorization"] = f"Bearer {TSDB_API_KEY}"

    try:
        resp = requests.post(TSDB_ENDPOINT, headers=headers, json=points, timeout=5)
        if resp.status_code >= 400:
            print(f"[MCP] ⚠️ TSDB push HTTP {resp.status_code}: {resp.text[:300]}")
    except requests.RequestException as e:
        print(f"[MCP] ⚠️ TSDB push failed: {e}")


def build_commit_report(
        commit_sha: str,
        timestamp: str,
        curr_snapshot_path: str,
        prev_snapshot_path: Optional[str],
        ttf_store_path: str,
        sandbox_path: str,
        output_dir: str,
        owner: str,
        repo: str):

    # ---- Extract vuln sets ----
    curr = extract_vulns(load_json(curr_snapshot_path))
    prev = extract_vulns(load_json(prev_snapshot_path)) if prev_snapshot_path else {}

    # ---- Diff ----
    diff = compute_diff(prev, curr)

    # ---- Time-to-fix store update ----
    ttf_store = update_ttf_store(
        ttf_store_path,
        commit_sha,
        timestamp,
        diff
    )

    # ---- Topic modeling (current commit) ----
    topics = topic_model_vulns(curr)

    # ---- Topic modeling (previous commit) ----
    if prev_snapshot_path:
        prev_snapshot = load_json(prev_snapshot_path)
        prev_vulns = extract_vulns(prev_snapshot)
        prev_topics = topic_model_vulns(prev_vulns)
    else:
        prev_topics = {}

    # ---- Drift calculation ----
    curr_dist = topic_distribution(topics)
    prev_dist = topic_distribution(prev_topics)

    topic_drift = {
        "jaccard": jaccard_drift(prev_topics, topics),
        "kl_divergence": kl_divergence(prev_dist, curr_dist)
    }

    # ---- Build final report JSON ----
    report = {
        "commit_sha": commit_sha,
        "timestamp": timestamp,
        "stats": {
            "total": len(curr),
            "added": len(diff["added"]),
            "removed": len(diff["removed"]),
            "persisted": len(diff["persisted"]),
        },
        "diff": diff,
        "vulns": curr,
        "topics": topics,
        "topic_drift": topic_drift,
        "time_to_fix_store": ttf_store,
    }

    # ---- Write commit report file ----
    out_path = Path(output_dir) / f"commit_report_{commit_sha}.json"
    write_json(out_path, report)

    # ---- Send to TSDB ----
    try:
        push_commit_report_to_timeseries(report, owner=owner, repo=repo)
    except Exception as e:
        print(f"[MCP] ⚠️ Failed to push commit report to TSDB: {e}")

    return out_path


def build_snapshot_from_semgrep_results(results: List[dict]) -> dict:
    """
    Convert Semgrep JSON 'results' into MCP snapshot format expected by extract_vulns().
    """
    findings: List[dict] = []
    for r in results:
        extra = r.get("extra", {}) or {}
        findings.append({
            "rule_id": r.get("check_id"),
            "file": r.get("path"),
            "code_excerpt": extra.get("lines", "") or "",
            "severity": extra.get("severity"),
            "raw": r,
        })
    return {
        "tool": "semgrep",
        "generated_at": datetime.utcnow().isoformat() + "Z",
        "findings": findings,
    }


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
        f"- {f.get('check_id')}: {f.get('path')}:{(f.get('start') or {}).get('line')} – {(f.get('extra') or {}).get('message')}"
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
# SANDBOX INSPECTION (REUSABLE)
# ============================================================
def run_sandbox_inspect(repo_dir: str, tmp_root: str, ts_suffix: str, prompt: str) -> dict:
    """
    Clones sandbox repo, runs inspect script against repo_dir, writes
    a timestamped Markdown + JSON, returns dict with status/stdout/stderr/paths.
    Always returns safely with masked outputs.
    """
    sandbox_repo_url = "https://github.com/rymarinelli/sandbox.git"
    sandbox_dir = os.path.join(tmp_root, "sandbox")
    if os.path.exists(sandbox_dir):
        shutil.rmtree(sandbox_dir, ignore_errors=True)

    # Clone sandbox (retry with token if necessary)
    SUPABASE_TOKEN = os.getenv("SUPABASE_TOKEN")
    try:
        subprocess.run(["git", "clone", sandbox_repo_url, sandbox_dir], check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError:
        token = os.getenv("GITHUB_TOKEN")
        if token:
            authed_url = sandbox_repo_url.replace("https://", f"https://{token}@")
            subprocess.run(["git", "clone", authed_url, sandbox_dir], check=True, capture_output=True, text=True)
        else:
            raise

    # Install deps if present
    req = os.path.join(sandbox_dir, "requirements-dev.txt")
    if os.path.exists(req):
        subprocess.run(["pip", "install", "-r", "requirements-dev.txt"], cwd=sandbox_dir, check=True, capture_output=True, text=True)

    # Run inspection
    json_path = os.path.join(repo_dir, f"sandbox_report_{ts_suffix}.json")
    md_path = os.path.join(repo_dir, f"SANDBOX_SCAN_REPORT_{ts_suffix}.md")

    prompts_dir = os.path.join(repo_dir, "prompts")
    os.makedirs(prompts_dir, exist_ok=True)
    user_prompt_path = os.path.join(prompts_dir, "user.txt")
    with open(user_prompt_path, "w", encoding="utf-8") as f:
        f.write(prompt or "")

    proc = subprocess.run(
        [
            "python", "scripts/inspect_vibe_code.py",
            "--workspace", repo_dir,
            "--prompt",
            user_prompt_path,
            "--fail-on-high",
            "--json",
        ],
        cwd=sandbox_dir,
        capture_output=True,
        text=True,
    )

    status = "passed" if proc.returncode == 0 else ("failed-high" if proc.returncode == 2 else "error")
    ts_abs = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    masked_stdout = mask_sensitive(proc.stdout)
    masked_stderr = mask_sensitive(proc.stderr)

    if status == "passed":
        try:
            url = "https://psogrrrvxrqxnuhcbvlm.supabase.co/functions/v1/increment-sandbox"
            headers = {
                "Authorization": f"Bearer {SUPABASE_TOKEN}",
                "Content-Type": "application/json"
            }
            requests.post(url, headers=headers)
        except requests.exceptions.RequestException as e:
            print(f"❌ User insights failed: {e}")

    with open(json_path, "w", encoding="utf-8") as jf:
        jf.write(masked_stdout or "{}")

    with open(md_path, "w", encoding="utf-8") as mf:
        mf.write(f"# Sandbox Inspection Report ({ts_suffix})\n\n")
        mf.write(f"**Time:** {ts_abs}\n\n")
        mf.write(f"**Sandbox Status:** {status}\n\n")
        mf.write(f"**Exit Code:** {proc.returncode}\n\n")
        mf.write("## Raw Output\n\n```\n")
        if masked_stdout.strip():
            mf.write("### STDOUT\n")
            mf.write(masked_stdout[:8000] + ("\n" if not masked_stdout.endswith("\n") else ""))
            mf.write("\n")
        if masked_stderr.strip():
            mf.write("\n### STDERR\n")
            mf.write(masked_stderr[:8000] + ("\n" if not masked_stderr.endswith("\n") else ""))
        if not masked_stdout.strip() and not masked_stderr.strip():
            mf.write("(no output captured)\n")
        mf.write("```\n")

    try:
        url = "https://psogrrrvxrqxnuhcbvlm.supabase.co/functions/v1/increment-prompts"
        headers = {
            "Authorization": f"Bearer {SUPABASE_TOKEN}",
            "Content-Type": "application/json"
        }
        requests.post(url, headers=headers)
    except requests.exceptions.RequestException as e:
        print(f"❌ User insights failed: {e}")

    return {
        "status": status,
        "returncode": proc.returncode,
        "stdout": masked_stdout,
        "stderr": masked_stderr,
        "json_path": json_path,
        "md_path": md_path,
    }


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
    if pr_labels is None:
        pr_labels = ["security", "automated", "needs-review"]

    GITHUB_TOKEN = os.getenv("GITHUB_TOKEN")
    SUPABASE_TOKEN = os.getenv("SUPABASE_TOKEN")
    tmp_dir = tempfile.mkdtemp(prefix="mcp_semgrep_")
    repo_dir = os.path.join(tmp_dir, "repo")

    # Durinn meta dirs for commit-level tracking
    durinn_meta_dir = os.path.join(repo_dir, ".durinn")
    snapshots_dir = os.path.join(durinn_meta_dir, "snapshots")
    commit_reports_dir = os.path.join(durinn_meta_dir, "commit_reports")
    ttf_store_path = os.path.join(durinn_meta_dir, "time_to_fix.json")

    try:
        repo_url_webhook = re.sub(r"^https://github\.com/", "", repo_url).replace(".git", "").strip("/")
        requests.post(
            "https://beczmeknbeejgbaskdkc.supabase.co/functions/v1/scan-webhook",
            headers={"Content-Type": "application/json"},
            json={
                "repo": repo_url_webhook,
                "type": "status",
                "data": {"step": "auth", "message": "Authenticating GitHub user..."}
            }
        )

        # --- clone ---
        parts = repo_url.rstrip("/").split("/")
        owner, repo = parts[-2], parts[-1]
        clone_url = (
            f"https://x-access-token:{GITHUB_TOKEN}@github.com/{owner}/{repo}.git"
            if GITHUB_TOKEN else
            f"https://github.com/{owner}/{repo}.git"
        )

        requests.post(
            "https://beczmeknbeejgbaskdkc.supabase.co/functions/v1/scan-webhook",
            headers={"Content-Type": "application/json"},
            json={"repo": repo_url_webhook, "type": "status", "data": {"step": "scan", "message": "Analyzing project structure..."}}
        )

        requests.post(
            "https://beczmeknbeejgbaskdkc.supabase.co/functions/v1/scan-webhook",
            headers={"Content-Type": "application/json"},
            json={
                "repo": repo_url_webhook,
                "type": "status",
                "data": {"step": "context", "message": "Cloning repository for analysis..."}
            }
        )
        for branch_try in (base_branch, "master"):
            clone_proc = subprocess.run(
                ["git", "clone", "--depth", "1", "--branch", branch_try, clone_url, repo_dir],
                capture_output=True, text=True
            )
            if clone_proc.returncode == 0:
                base_branch = branch_try
                break
        if clone_proc.returncode != 0:
            return {"error": "could not clone repo", "stderr": mask_sensitive(clone_proc.stderr)}

        if not os.path.isdir(os.path.join(repo_dir, ".git")):
            return {"error": "repo cloned but .git missing", "repo_dir": repo_dir}

        os.makedirs(snapshots_dir, exist_ok=True)
        os.makedirs(commit_reports_dir, exist_ok=True)

        requests.post(
            "https://beczmeknbeejgbaskdkc.supabase.co/functions/v1/scan-webhook",
            headers={"Content-Type": "application/json"},
            json={
                "repo": repo_url_webhook,
                "type": "status",
                "data": {"step": "scan", "message": "Scanning project for security issues..."}
            }
        )

        # --- semgrep (initial scan baseline) ---
        semgrep_cmd = [
            "semgrep", "scan", "--json",
            "--exclude", "node_modules", "--exclude", ".npm", "--exclude", "__pycache__", "--exclude", ".venv",
            "--config", ("auto" if quick else semgrep_config),
            repo_dir
        ]
        semgrep_proc = subprocess.run(semgrep_cmd, capture_output=True, text=True)
        try:
            semgrep_json = json.loads(semgrep_proc.stdout)
            findings: List[dict] = semgrep_json.get("results", [])
        except Exception:
            findings = []

        # Baseline snapshot (pre-remediation)
        baseline_snapshot = build_snapshot_from_semgrep_results(findings)
        baseline_snapshot_path = os.path.join(snapshots_dir, "snapshot_baseline.json")
        write_json(baseline_snapshot_path, baseline_snapshot)
        prev_snapshot_path: Optional[str] = baseline_snapshot_path

        findings_message = f"Found {len(findings)} security issues"
        requests.post(
            "https://beczmeknbeejgbaskdkc.supabase.co/functions/v1/scan-webhook",
            headers={"Content-Type": "application/json"},
            json={"repo": repo_url_webhook, "type": "status", "data": {"step": "analyze", "message": findings_message}}
        )
        remediation_text = hf_remediation_from_findings(findings) if llm_proposal else ""

        ensure_git_identity(repo_dir)
        ts_branch = datetime.utcnow().strftime("%a-%d-%b-%Y-%H%MUTC")  # Thu-06-Nov-2025-1423UTC
        branch_name = f"mcp/remediation-{ts_branch}"
        subprocess.run(["git", "checkout", "-b", branch_name], cwd=repo_dir, check=True)

        # --- remediation loop (sandbox BEFORE each commit) ---
        def apply_llm_fix_to_file(finding: dict) -> Optional[tuple[str, str]]:
            rel_path = finding.get("path")
            if not rel_path:
                return None
            target_file = os.path.join(repo_dir, rel_path)
            if not os.path.exists(target_file):
                return None
            start_obj = finding.get("start") or {}
            line_no = start_obj.get("line")
            if not line_no:
                return None

            # default empty prompt; we will fill when calling LLM
            prompt = ""

            try:
                with open(target_file, "r", encoding="utf-8") as f:
                    lines = f.readlines()
                vuln_line = lines[line_no - 1].rstrip("\n")
                textgen = get_textgen()
                prompt = (
                    "You are a secure code assistant. Rewrite ONLY the given vulnerable line securely.\n"
                    "Use the examples below as guidance.\n\n"
                    "### Examples\n"
                    "# Input: eval(user_input)\n"
                    "# Output: ast.literal_eval(user_input)\n\n"
                    "# Input: child_process.exec('rm -rf ' + path)\n"
                    "# Output: child_process.execFile('rm', ['-rf', path])\n\n"
                    "### Now fix this:\n"
                    f"# Rule: {finding.get('check_id','semgrep_rule')}\n"
                    f"# Message: {(finding.get('extra') or {}).get('message','')}\n"
                    f"Vulnerable line:\n{vuln_line}\n"
                    "Return ONLY the corrected code. Do not explain.\n"
                )
                out = textgen(prompt, max_new_tokens=80, do_sample=False)[0]["generated_text"]
                fixed_line = out[len(prompt):].strip() or None
                if not fixed_line:
                    return None
            except Exception:
                return None

            block = [
                f"# === MCP FIX START ({finding.get('check_id','semgrep_rule')}) ===\n",
                f"# Severity: {(finding.get('extra') or {}).get('severity','')}\n",
                vuln_line + "\n",
                "# → Suggested secure fix:\n",
                fixed_line + "\n",
                "# === MCP FIX END ===\n",
            ]

            try:
                lines[line_no - 1:line_no] = block
                with open(target_file, "w", encoding="utf-8") as f:
                    f.writelines(lines)
                return rel_path, prompt
            except Exception:
                return None

        requests.post(
            "https://beczmeknbeejgbaskdkc.supabase.co/functions/v1/scan-webhook",
            headers={"Content-Type": "application/json"},
            json={"repo": repo_url_webhook, "type": "status", "data": {"step": "risk", "message": "Generating remediation plan..."}}
        )

        applied = 0
        for fnd in findings[:50]:
            result = apply_llm_fix_to_file(fnd)
            if not result:
                continue
            rel_path, prompt = result

            # 🔒 SANDBOX BEFORE REMEDIATION COMMIT — always commit a report (success/fail)
            ts_suffix = f"{branch_name.split('mcp/remediation-')[-1]}-{applied+1:03d}"
            try:
                sbx = run_sandbox_inspect(repo_dir, tmp_dir, ts_suffix, prompt)
                sbx_json = sbx.get("json_path")
                sbx_md = sbx.get("md_path")
                ensure_git_identity(repo_dir)

                # add sandbox artifacts
                for p in (sbx_json, sbx_md):
                    if p and os.path.exists(p):
                        subprocess.run(["git", "add", p], cwd=repo_dir, check=False)

                commit_msg = f"Sandbox inspection report ({ts_suffix}) – status: {sbx.get('status','unknown')}"
                subprocess.run(["git", "commit", "-m", commit_msg], cwd=repo_dir, check=False)

                # --- webhook: sandbox commit ---
                try:
                    sha_sbx = subprocess.run(
                        ["git", "rev-parse", "HEAD"],
                        cwd=repo_dir,
                        capture_output=True,
                        text=True
                    ).stdout.strip()
                    requests.post(
                        "https://beczmeknbeejgbaskdkc.supabase.co/functions/v1/scan-webhook",
                        headers={"Content-Type": "application/json"},
                        json={
                            "repo": repo_url_webhook,
                            "type": "commit",
                            "data": {
                                "sha": sha_sbx,
                                "message": commit_msg,
                                "author": "MCP Agent",
                                "url": f"https://github.com/{owner}/{repo}/commit/{sha_sbx}",
                            },
                        },
                    )
                except Exception as e:
                    print(f"⚠️ Commit webhook failed: {e}")

                print(f"[MCP] ✅ Committed sandbox report: {sbx_md or sbx_json}")
                # --- webhook: sandbox status ---
                try:
                    requests.post(
                        "https://beczmeknbeejgbaskdkc.supabase.co/functions/v1/scan-webhook",
                        headers={"Content-Type": "application/json"},
                        json={
                            "repo": repo_url_webhook,
                            "type": "sandbox",
                            "data": {
                                "id": ts_suffix,
                                "status": sbx.get("status", "unknown"),
                                "commit": sha_sbx,
                            },
                        },
                    )
                except Exception as e:
                    print(f"⚠️ Sandbox webhook failed: {e}")

            except Exception:
                masked_trace = mask_sensitive(traceback.format_exc())
                fail_md = os.path.join(repo_dir, f"SANDBOX_SCAN_REPORT_{ts_suffix}.md")
                with open(fail_md, "w", encoding="utf-8") as f:
                    f.write(f"# Sandbox Inspection Error ({ts_suffix})\n\n```\n{masked_trace}\n```\n")
                sbx = {"status": "error", "returncode": 99, "md_path": fail_md}

            # Now commit the actual remediation for this file
            check_id = fnd.get("check_id", "semgrep_rule")
            msg = f"Auto remediation: {rel_path} ({check_id})"
            print(f"git add: {msg}")
            subprocess.run(["git", "add", rel_path], cwd=repo_dir)
            subprocess.run(["git", "commit", "-m", msg], cwd=repo_dir)

            # 🔗 COMMIT-LEVEL VULN NODE FOR THIS REMEDIATION COMMIT
            try:
                sha = subprocess.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=repo_dir,
                    capture_output=True,
                    text=True
                ).stdout.strip()

                # re-run semgrep to see current vuln state at this commit
                post_semgrep_proc = subprocess.run(semgrep_cmd, capture_output=True, text=True)
                try:
                    post_semgrep_json = json.loads(post_semgrep_proc.stdout)
                    post_results: List[dict] = post_semgrep_json.get("results", [])
                except Exception:
                    post_results = []

                curr_snapshot = build_snapshot_from_semgrep_results(post_results)
                curr_snapshot_path = os.path.join(snapshots_dir, f"snapshot_{sha}.json")
                write_json(curr_snapshot_path, curr_snapshot)

                commit_report_path = build_commit_report(
                    commit_sha=sha,
                    timestamp=datetime.utcnow().isoformat(),
                    curr_snapshot_path=curr_snapshot_path,
                    prev_snapshot_path=prev_snapshot_path,
                    ttf_store_path=ttf_store_path,
                    sandbox_path=repo_dir,
                    output_dir=commit_reports_dir,
                    owner=owner,
                    repo=repo,
                )
                prev_snapshot_path = curr_snapshot_path

                # commit the node report (this is the "node" for the remediation commit)
                subprocess.run(["git", "add", str(commit_report_path)], cwd=repo_dir, check=False)
                subprocess.run(
                    ["git", "commit", "-m", f"Add commit-level vuln node for {sha}"],
                    cwd=repo_dir,
                    check=False,
                )

            except Exception as e:
                print(f"[MCP] ⚠️ Failed to create commit-level vuln node: {e}")

            applied += 1

        if applied == 0:
            print("⚠️ No LLM fixes applied, skipping report and PR.")
            return {
                "warning": "no changes applied",
                "repo_dir": repo_dir,
                "num_findings": len(findings),
            }

        # --- overall report file (after fixes) ---
        report_path = os.path.join(repo_dir, "MCP_SECURITY_REPORT.md")
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(
                f"# MCP Security Report\n\nTarget: {repo_url}\nTime: {ts_branch}\n"
                f"Findings: {len(findings)}\nPatched: {applied}\n\n{remediation_text}\n"
            )

        print(f"git add MCP Security Report\n\nTarget: {repo_url}\nTime: {ts_branch}\n")
        subprocess.run(["git", "add", report_path], cwd=repo_dir)
        subprocess.run(["git", "commit", "-m", "Add MCP security report"], cwd=repo_dir)

        # push (PR happens next)
        subprocess.run(["git", "push", "-u", "origin", branch_name, "--force"], cwd=repo_dir, check=False)
        print("git pushed")

        # Create PR with Markdown body and labels (fully qualified head)
        pr_info = None
        pr_html_url = None
        if GITHUB_TOKEN and create_pr:
            md_lines = [
                "# MCP: Automated Security Remediation",
                "",
                f"- **Target repo:** `{owner}/{repo}`",
                f"- **Base branch:** `{base_branch}`",
                f"- **Head branch:** `{branch_name}`",
                f"- **Findings (Semgrep):** {len(findings)}",
                f"- **Patched files:** {applied}",
                "",
                "## Reports",
                f"- `{os.path.basename(report_path)}`",
            ]
            pr_body = "\n".join(md_lines)

            headers = {
                "Authorization": f"Bearer {GITHUB_TOKEN}",
                "Accept": "application/vnd.github+json",
            }
            pr_payload = {
                "title": "MCP: automated security remediation",
                "head": f"{owner}:{branch_name}",
                "base": base_branch,
                "body": pr_body,
            }
            pr_url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
            pr_resp = requests.post(pr_url, headers=headers, json=pr_payload)

            if pr_resp.status_code in (200, 201):
                pr_json = pr_resp.json()
                pr_number = pr_json.get("number")
                pr_html_url = pr_json.get("html_url")

                if pr_labels:
                    labels_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{pr_number}/labels"
                    try:
                        requests.post(labels_url, headers=headers, json={"labels": pr_labels})
                    except Exception:
                        pass

                pr_info = {
                    "branch": branch_name,
                    "pushed": True,
                    "pull_request": pr_html_url,
                    "number": pr_number,
                }
            else:
                pr_info = {
                    "branch": branch_name,
                    "pushed": True,
                    "pr_error_status": pr_resp.status_code,
                    "pr_error_body": mask_sensitive(pr_resp.text),
                    "pr_payload": pr_payload,
                    "pr_url": pr_url,
                }

        # --- webhook: pull request ---
        if pr_html_url:
            try:
                requests.post(
                    "https://beczmeknbeejgbaskdkc.supabase.co/functions/v1/scan-webhook",
                    headers={"Content-Type": "application/json"},
                    json={
                        "repo": repo_url_webhook,
                        "type": "pr",
                        "data": {"url": pr_html_url, "status": "open"},
                    },
                )
            except Exception as e:
                print(f"⚠️ PR webhook failed: {e}")

        try:
            url = "https://psogrrrvxrqxnuhcbvlm.supabase.co/functions/v1/increment-scan"
            headers = {
                "Authorization": f"Bearer {SUPABASE_TOKEN}",
                "Content-Type": "application/json"
            }
            requests.post(url, headers=headers)
        except requests.exceptions.RequestException as e:
            print(f"❌ User insights failed: {e}")

        return {
            "repo_dir": repo_dir,
            "num_findings": len(findings),
            "llm_applied_fixes": applied,
            "report_path": report_path,
            "pr_info": pr_info,
        }

    finally:
        print("finally======>")
        shutil.rmtree(tmp_dir, ignore_errors=True)


# ============================================================
# FASTAPI SERVER
# ============================================================
app = FastAPI()
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
    allow_credentials=False,
)


@app.options("/{rest_of_path:path}")
async def preflight_handler(request: Request, rest_of_path: str):
    return JSONResponse(
        content={"status": "ok"},
        headers={
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "*",
        },
    )


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
