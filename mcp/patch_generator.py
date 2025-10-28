"""Patch generation using LLM responses."""

from __future__ import annotations

import json
import logging
import shlex
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, List, Sequence

from .llm_client import LLMClient
from .prompt_builder import PromptBuilder
from .scan_parser import Vulnerability

logger = logging.getLogger(__name__)


@dataclass
class PatchCandidate:
    """A representation of a code change produced by the LLM."""

    file_path: Path
    replacement: str
    metadata: dict = field(default_factory=dict)

    def write_to_repo(self, repo_root: Path) -> Path:
        target_path = repo_root / self.file_path
        target_path.parent.mkdir(parents=True, exist_ok=True)
        target_path.write_text(self.replacement)
        return target_path


class PatchGenerator:
    """Generate patches for vulnerabilities via an LLM client."""

    def __init__(
        self,
        repo_root: Path,
        llm_client: LLMClient,
        prompt_builder: PromptBuilder,
        *,
        formatters: Sequence[str] | None = None,
    ) -> None:
        self.repo_root = Path(repo_root)
        self.llm_client = llm_client
        self.prompt_builder = prompt_builder
        self.formatters = list(formatters or [])

    def generate(self, vulnerability: Vulnerability) -> List[PatchCandidate]:
        prompt = self.prompt_builder.build_prompt(vulnerability)
        raw = self.llm_client.generate(prompt)
        return self._parse_response(raw)

    def generate_batch(self, vulnerabilities: Iterable[Vulnerability]) -> List[PatchCandidate]:
        prompt = self.prompt_builder.build_batch_prompt(vulnerabilities)
        raw = self.llm_client.generate(prompt)
        return self._parse_response(raw)

    def _parse_response(self, response: str) -> List[PatchCandidate]:
        try:
            payload = json.loads(response)
        except json.JSONDecodeError:
            try:
                payload = json.loads(self._extract_json(response))
            except json.JSONDecodeError as exc:
                raise ValueError("LLM response was not valid JSON") from exc

        if isinstance(payload, dict) and "patches" in payload:
            patches = payload["patches"]
        else:
            patches = payload

        if not isinstance(patches, list):
            raise ValueError("LLM response must be a list of patches")

        candidates: List[PatchCandidate] = []
        for patch in patches:
            if not isinstance(patch, dict):
                raise ValueError("Each patch entry must be an object")
            if "file_path" not in patch or "replacement" not in patch:
                raise ValueError("Patch entries must include 'file_path' and 'replacement'")

            candidate = PatchCandidate(
                file_path=Path(patch["file_path"]),
                replacement=str(patch["replacement"]),
                metadata={k: v for k, v in patch.items() if k not in {"file_path", "replacement"}},
            )
            candidates.append(self._apply_formatters(candidate))
        return candidates

    def _extract_json(self, response: str) -> str:
        start = response.find("[")
        if start == -1:
            start = response.find("{")
        end = response.rfind("]")
        if end == -1:
            end = response.rfind("}")
        if start == -1 or end == -1:
            raise ValueError("Unable to locate JSON content in response")
        return response[start : end + 1]

    def _apply_formatters(self, candidate: PatchCandidate) -> PatchCandidate:
        if not self.formatters:
            return candidate

        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp) / candidate.file_path.name
            tmp_path.write_text(candidate.replacement)
            for formatter in self.formatters:
                command = shlex.split(formatter.format(path=str(tmp_path)))
                try:
                    subprocess.run(command, check=True, cwd=tmp_path.parent, capture_output=True, text=True)
                except subprocess.CalledProcessError as exc:
                    logger.warning("Formatter %s failed: %s", formatter, exc.stderr)
                    raise
            candidate.replacement = tmp_path.read_text()
        return candidate


__all__ = ["PatchGenerator", "PatchCandidate"]
