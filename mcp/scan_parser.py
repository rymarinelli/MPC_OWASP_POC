"""Utilities for normalising vulnerability scan outputs."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Sequence


@dataclass(frozen=True)
class Vulnerability:
    """A normalised vulnerability record derived from scan output."""

    identifier: str
    file_path: Path
    summary: str
    recommendation: str = ""
    severity: str = "unknown"
    start_line: int | None = None
    end_line: int | None = None
    metadata: dict = field(default_factory=dict)

    def affected_range(self) -> str:
        """Return a human readable range for logging or prompts."""

        if self.start_line is None:
            return "unknown"
        if self.end_line is None or self.end_line == self.start_line:
            return str(self.start_line)
        return f"{self.start_line}-{self.end_line}"


class ScanParser:
    """Parse JSON scan outputs into :class:`Vulnerability` objects."""

    def parse(self, payload: Sequence[dict]) -> List[Vulnerability]:
        """Parse an in-memory JSON payload."""

        vulnerabilities: List[Vulnerability] = []
        for entry in payload:
            if not isinstance(entry, dict):
                raise ValueError("Scan entries must be objects")

            identifier = str(entry.get("id") or entry.get("identifier") or "unknown")
            file_path = Path(entry["file"] if "file" in entry else entry.get("file_path", ""))
            if not file_path:
                raise ValueError(f"Scan entry {identifier} is missing a file path")

            start_line = entry.get("start_line") or entry.get("line")
            end_line = entry.get("end_line") or entry.get("line_end")

            vulnerabilities.append(
                Vulnerability(
                    identifier=identifier,
                    file_path=file_path,
                    summary=str(entry.get("summary") or entry.get("description") or ""),
                    recommendation=str(entry.get("recommendation") or ""),
                    severity=str(entry.get("severity") or "unknown"),
                    start_line=int(start_line) if start_line is not None else None,
                    end_line=int(end_line) if end_line is not None else None,
                    metadata={k: v for k, v in entry.items() if k not in {"id", "identifier", "file", "file_path", "summary", "description", "recommendation", "severity", "start_line", "line", "end_line", "line_end"}},
                )
            )
        return vulnerabilities

    def parse_file(self, path: Path | str) -> List[Vulnerability]:
        """Read scan results from a JSON file."""

        file_path = Path(path)
        if not file_path.exists():
            raise FileNotFoundError(f"Scan result file '{file_path}' does not exist")

        payload = json.loads(file_path.read_text())
        if isinstance(payload, dict) and "vulnerabilities" in payload:
            payload = payload["vulnerabilities"]
        if not isinstance(payload, Iterable):
            raise ValueError("Scan payload must be a list or contain a 'vulnerabilities' key")
        return self.parse(list(payload))


__all__ = ["ScanParser", "Vulnerability"]
