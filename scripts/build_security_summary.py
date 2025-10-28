#!/usr/bin/env python3
"""Compose aggregated security summary for GitHub Actions."""

from __future__ import annotations

import json
import pathlib


def main() -> None:
    summary: list[str] = []

    semgrep_report = pathlib.Path("semgrep-report.json")
    if semgrep_report.exists():
        try:
            data = json.loads(semgrep_report.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive
            raise SystemExit(f"Unable to parse Semgrep summary JSON: {exc}")

        results = data.get("results", [])
        summary.append("### Semgrep OWASP Top Ten")
        summary.append(f"Total findings: {len(results)}")
        for result in results[:10]:
            severity = result.get("extra", {}).get("severity", "UNKNOWN")
            rule_id = result.get("check_id", "rule")
            path = result.get("path")
            line = result.get("start", {}).get("line")
            summary.append(f"- **{severity}** `{rule_id}` at {path}:{line}")
    else:
        summary.append("Semgrep report not available.")

    inspect_summary = pathlib.Path("inspect-summary.md")
    if inspect_summary.exists():
        try:
            inspect_text = inspect_summary.read_text(encoding="utf-8")
        except OSError as exc:  # pragma: no cover - defensive
            raise SystemExit(f"Unable to read Inspect summary: {exc}")
        summary.append(inspect_text)
    else:
        summary.append("Inspect AI summary not available.")

    summary_text = "\n\n".join(summary)
    pathlib.Path("security-summary.md").write_text(summary_text, encoding="utf-8")
    print(summary_text)


if __name__ == "__main__":
    main()
