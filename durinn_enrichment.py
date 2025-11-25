# durinn_enrichment.py
from __future__ import annotations
from typing import Dict, List, Any, Optional
from collections import Counter, defaultdict
import re


def _owasp_name_to_tag(name: str) -> Optional[str]:
    """
    Convert OWASP name like:
      'A03:2025 - Software Supply Chain Failures'
    → 'a03-2025'
    """
    if not name:
        return None
    m = re.match(r"A(\d+):(\d{4})", name.strip())
    if not m:
        return None
    idx = m.group(1).zfill(2)
    year = m.group(2)
    return f"a{idx}-{year}".lower()


def _normalize_owasp(value):
    """Ensure owasp metadata is always returned as a list of strings."""
    if not value:
        return []
    if isinstance(value, list):
        return value
    if isinstance(value, str):
        return [value]
    return []


def _aggregate_vulns(vulns: Dict[str, dict]) -> Dict[str, Any]:
    """
    Aggregate flattened Semgrep vulns (output of extract_vulns) into
    the repo-level summary shape used in the Hacktoberfest dataset.
    """
    rule_counts: Counter = Counter()
    severity_counts: Counter = Counter()
    owasp_counts: Counter = Counter()
    owasp_tags_set = set()

    for v in vulns.values():
        rule_id = v.get("rule_id") or "unknown"
        severity = (v.get("severity") or "UNKNOWN").upper()
        rule_counts[rule_id] += 1
        severity_counts[severity] += 1

        owasp_raw = _normalize_owasp(v.get("owasp"))
        for o_name in owasp_raw:
            owasp_counts[o_name] += 1
            tag = _owasp_name_to_tag(o_name)
            if tag:
                owasp_tags_set.add(tag)

    return {
        "total_findings": int(sum(rule_counts.values())),
        "rule_counts": dict(rule_counts),
        "owasp_counts": dict(owasp_counts),
        "severity_counts": dict(severity_counts),
        "owasp_tags": sorted(owasp_tags_set),
    }


def _diff_aggregates(before: Dict[str, Any], after: Dict[str, Any]) -> Dict[str, Any]:
    def diff_counter(b: Dict[str, int], a: Dict[str, int]) -> Dict[str, int]:
        all_keys = set(b.keys()) | set(a.keys())
        return {k: int(a.get(k, 0) - b.get(k, 0)) for k in sorted(all_keys)}

    return {
        "total_delta": int(after.get("total_findings", 0) - before.get("total_findings", 0)),
        "rule_delta": diff_counter(before.get("rule_counts", {}), after.get("rule_counts", {})),
        "owasp_delta": diff_counter(before.get("owasp_counts", {}), after.get("owasp_counts", {})),
    }


def _label_risk(agg: Dict[str, Any]) -> str:
    """
    Simple heuristic risk label strategy, aligned with dataset vocabulary:
      - 'high'    : many ERRORs or very large total
      - 'flagged' : any findings but not 'high'
      - 'clean'   : no findings
    """
    total = int(agg.get("total_findings", 0) or 0)
    sev = {k.upper(): int(v) for k, v in (agg.get("severity_counts") or {}).items()}
    errors = sev.get("ERROR", 0)
    warnings = sev.get("WARNING", 0)

    if total == 0:
        return "clean"

    # Heuristic thresholds – tuned to look like your Hacktober examples
    if errors >= 50 or total >= 1000:
        return "high"

    if errors > 0 or warnings > 0:
        return "flagged"

    return "flagged"


# ---------------------------------------------------------------------------
# Per-rule narratives (dataset-style)
# ---------------------------------------------------------------------------

_RULE_TEMPLATES: Dict[str, str] = {
    "owasp-a03-unpinned-python-requirements": (
        "Software Supply Chain: unpinned Python dependency (no version specified). "
        "Pin dependencies to exact versions for reproducible builds and safer supply chain. "
        "This relates to A03:2025 - Software Supply Chain Failures."
    ),
    "owasp-a03-unpinned-npm-dependency": (
        "Software Supply Chain: unpinned npm dependency (no version or loose range specified). "
        "Pin versions or use trusted lockfiles to reduce supply-chain risk. "
        "This relates to A03:2025 - Software Supply Chain Failures."
    ),
    "owasp-a08-dynamic-code-eval": (
        "Software/Data Integrity Failure: dynamic code evaluation (eval/exec/Function) "
        "can lead to remote code execution if inputs are not strictly controlled. "
        "This relates to A08:2025 - Software or Data Integrity Failures."
    ),
    "owasp-a09-swallowed-exception-no-logging": (
        "Logging & Alerting Failure: exceptions are swallowed without logging, making it difficult "
        "to detect and respond to production issues or attacks. "
        "This relates to A09:2025 - Logging & Alerting Failures."
    ),
    "owasp-a10-broad-exception-catch": (
        "Mishandling of Exceptional Conditions: broad exception handlers can hide real failures "
        "and security conditions, preventing proper error handling and alerting. "
        "This relates to A10:2025 - Mishandling of Exceptional Conditions."
    ),
    "owasp-a10-assert-used-for-security-checks": (
        "Mishandling of Exceptional Conditions: using assertions as security checks is unsafe, "
        "because assertions can be stripped in production builds. "
        "This relates to A10:2025 - Mishandling of Exceptional Conditions."
    ),
    "owasp-a04-insecure-crypto-algorithms": (
        "Cryptographic Failure: use of weak or outdated cryptographic algorithms (e.g., MD5, SHA1, "
        "insecure ciphers) that no longer provide adequate security guarantees. "
        "This relates to A04:2025 - Cryptographic Failures."
    ),
    "owasp-a07-plaintext-password-literal": (
        "Authentication Failure: plaintext passwords or secrets stored directly in code. "
        "This increases the risk of credential leakage and lateral movement. "
        "This relates to A07:2025 - Authentication Failures."
    ),
    "owasp-a01-public-admin-endpoint": (
        "Broken Access Control: public or unauthenticated administrative endpoints greatly increase "
        "the blast radius of misconfigurations and common web attacks. "
        "This relates to A01:2025 - Broken Access Control."
    ),
    "owasp-a05-sql-injection-dynamic-query": (
        "Injection: dynamically building SQL queries from untrusted input can lead to SQL injection. "
        "Use prepared statements or parameterized queries instead. "
        "This relates to A05:2025 - Injection."
    ),
}


def _build_rule_explanations(vulns: Dict[str, dict]) -> Dict[str, str]:
    """
    Build a dataset-style explanation per rule_id.
    Falls back to a generic narrative using OWASP name + Semgrep message.
    """
    by_rule: Dict[str, List[dict]] = defaultdict(list)
    for v in vulns.values():
        rule_id = v.get("rule_id") or "unknown"
        by_rule[rule_id].append(v)

    explanations: Dict[str, str] = {}
    for rule_id, items in by_rule.items():
        # Prefer handcrafted template if we have one
        if rule_id in _RULE_TEMPLATES:
            explanations[rule_id] = _RULE_TEMPLATES[rule_id]
            continue

        sample = items[0]
        owasp_names = _normalize_owasp(sample.get("owasp"))

        owasp_name = owasp_names[0] if owasp_names else None
        severity = (sample.get("severity") or "UNKNOWN").upper()
        msg = (sample.get("message") or "").strip()

        parts = []
        if msg:
            parts.append(msg)
        if owasp_name:
            parts.append(f"This relates to {owasp_name}.")
        parts.append(f"Observed severity: {severity} in {len(items)} finding(s).")

        explanations[rule_id] = " ".join(parts)

    return explanations


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_repo_enrichment(
    owner: str,
    repo: str,
    prev_vulns: Dict[str, dict] | None,
    curr_vulns: Dict[str, dict],
    ml_risk_score: Optional[float] = None,
    ml_risk_label: Optional[str] = None,
    ml_persistence: Optional[Dict[str, float]] = None,
) -> Dict[str, Any]:
    """
    Build a repo-level enrichment payload shaped like your
    Durinn_Hacktoberfest_Retrospective dataset entries.

    ml_* fields are optional hooks where the calibration critic (or a future
    model trained from commit_report_*.json) can inject:
      - ml_risk_score: float 0–1
      - ml_risk_label: 'low'|'medium'|'high'|'unknown'
      - ml_persistence: { vuln_uid: probability_it_persists }
    """
    prev_vulns = prev_vulns or {}
    before_agg = _aggregate_vulns(prev_vulns) if prev_vulns else None
    after_agg = _aggregate_vulns(curr_vulns)
    diff = _diff_aggregates(before_agg, after_agg) if before_agg else None

    heuristic_flag = _label_risk(after_agg)
    rule_explanations = _build_rule_explanations(curr_vulns)

    enrichment: Dict[str, Any] = {
        "type": "repo",
        "repo": f"{owner}/{repo}",
        "flag_status": heuristic_flag,
        "after": after_agg,
        "semantic": {
            "owasp_tags": after_agg.get("owasp_tags", []),
        },
        "rule_explanations": rule_explanations,
        "ml": {
            "risk_score": ml_risk_score,
            "risk_label": ml_risk_label,
            "persistence": ml_persistence or {},
        },
    }

    if before_agg is not None:
        enrichment["before"] = before_agg
    if diff is not None:
        enrichment["diff"] = diff

    return enrichment
