#!/usr/bin/env python3
"""Automated remediation entrypoint."""

from __future__ import annotations

import sys
from pathlib import Path

if __package__ in (None, ""):
    repo_root = Path(__file__).resolve().parents[1]
    if str(repo_root) not in sys.path:
        sys.path.insert(0, str(repo_root))

from mcp.cli.auto_refactor import main


if __name__ == "__main__":
    raise SystemExit(main())
