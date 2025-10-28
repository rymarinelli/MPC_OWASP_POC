#!/usr/bin/env python3
"""Evaluate Inspect AI results and expose findings for GitHub Actions."""

from __future__ import annotations

import json
import os
import pathlib
import sys
from typing import Any, cast


def main() -> None:
    report_path = pathlib.Path("inspect-report.json")
    if not report_path.exists():
        print("Inspect AI report not found.", file=sys.stderr)
        sys.exit(1)

    try:
        with report_path.open(encoding="utf-8") as fp:
            data = json.load(fp)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        print(f"Unable to parse Inspect AI report: {exc}", file=sys.stderr)
        sys.exit(1)

    findings_list: list[dict[str, Any]] = []

    def walk(node: Any) -> None:
        if isinstance(node, dict):
            dict_node = cast(dict[str, Any], node)
            if (
                any(key in dict_node for key in ("severity", "impact", "priority"))
                and any(
                    key in dict_node for key in ("title", "rule_id", "description")
                )
            ):
                findings_list.append(dict_node)
            for value in dict_node.values():
                walk(value)
        elif isinstance(node, list):
            for item in node:
                walk(item)

    walk(data)
    findings = len(findings_list)
    print(f"Inspect AI findings: {findings}")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as handle:
            handle.write(f"findings={findings}\n")

    summary_lines = ["### Inspect AI Findings", f"Total findings: {findings}"]
    for finding in findings_list[:10]:
        severity = finding.get("severity") or finding.get("impact") or "unknown"
        title = finding.get("title") or finding.get("rule_id") or "untitled finding"
        summary_lines.append(f"- **{severity}** {title}")

    pathlib.Path("inspect-summary.md").write_text(
        "\n".join(summary_lines), encoding="utf-8"
    )


if __name__ == "__main__":
    main()
