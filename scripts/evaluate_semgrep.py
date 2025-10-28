#!/usr/bin/env python3
"""Evaluate Semgrep results and expose findings for GitHub Actions."""

from __future__ import annotations

import json
import os
import pathlib
import sys


def main() -> None:
    report_path = pathlib.Path("semgrep-report.json")
    if not report_path.exists():
        print("Semgrep report not found.", file=sys.stderr)
        sys.exit(1)

    try:
        with report_path.open(encoding="utf-8") as fp:
            data = json.load(fp)
    except json.JSONDecodeError as exc:  # pragma: no cover - defensive
        print(f"Unable to parse Semgrep report: {exc}", file=sys.stderr)
        sys.exit(1)

    findings = len(data.get("results", []))
    print(f"Semgrep findings: {findings}")

    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as handle:
            handle.write(f"findings={findings}\n")


if __name__ == "__main__":
    main()
