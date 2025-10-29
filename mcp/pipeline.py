"""High level orchestration of the MCP remediation flow."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, List, Sequence

from .patch_generator import PatchCandidate, PatchGenerator
from .scan_parser import Vulnerability


@dataclass
class AppliedPatch:
    """Represents a patch that has been written to the repository."""

    candidate: PatchCandidate
    path: Path


class AutoRemediationPipeline:
    """Co-ordinates vulnerability remediation."""

    def __init__(
        self,
        repo_root: Path,
        patch_generator: PatchGenerator,
        *,
        validations: Sequence[Sequence[str]] | None = None,
    ) -> None:
        self.repo_root = Path(repo_root)
        self.patch_generator = patch_generator
        self.validations: List[Sequence[str]] = [tuple(v) for v in (validations or [])]

    def plan(self, vulnerabilities: Iterable[Vulnerability]) -> List[PatchCandidate]:
        patches: List[PatchCandidate] = []
        for vulnerability in vulnerabilities:
            candidates = self.patch_generator.generate(vulnerability)
            if not candidates:
                continue
            patches.append(candidates[0])
        return patches

    def apply(self, patches: Iterable[PatchCandidate]) -> List[AppliedPatch]:
        applied: List[AppliedPatch] = []
        for patch in patches:
            applied_path = patch.write_to_repo(self.repo_root)
            applied.append(AppliedPatch(candidate=patch, path=applied_path))
        return applied

    def validate(self) -> None:
        for command in self.validations:
            if not command:
                continue
            subprocess.run(command, cwd=self.repo_root, check=True)

    def run(self, vulnerabilities: Iterable[Vulnerability]) -> List[AppliedPatch]:
        patches = self.plan(vulnerabilities)
        if not patches:
            return []
        applied = self.apply(patches)
        self.validate()
        return applied


__all__ = ["AutoRemediationPipeline", "AppliedPatch"]
