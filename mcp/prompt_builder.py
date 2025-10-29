"""Prompt construction helpers for MCP."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .scan_parser import Vulnerability


@dataclass
class PromptContext:
    """Additional context for the language model."""

    repository_name: str
    base_branch: str
    coding_guidelines: str | None = None


class PromptBuilder:
    """Craft structured prompts for the code generation LLM."""

    def __init__(self, repo_root: Path, context: PromptContext | None = None):
        self.repo_root = Path(repo_root)
        self.context = context

    def load_file_context(self, file_path: Path, max_lines: int = 200) -> str:
        """Return a snippet of the existing file around the vulnerability."""

        absolute_path = self.repo_root / file_path
        if not absolute_path.exists():
            return ""
        content = absolute_path.read_text().splitlines()
        if max_lines <= 0 or len(content) <= max_lines:
            return "\n".join(content)
        head = max_lines // 2
        tail = max_lines - head
        return "\n".join(content[:head] + ["...", "# truncated"] + content[-tail:])

    def build_prompt(self, vulnerability: Vulnerability) -> str:
        """Construct a descriptive prompt for the coding model."""

        context_lines = self.load_file_context(vulnerability.file_path)
        header = [
            f"Repository: {self.context.repository_name if self.context else 'unknown'}",
            f"Base branch: {self.context.base_branch if self.context else 'unknown'}",
            f"Severity: {vulnerability.severity}",
            f"File: {vulnerability.file_path} (lines {vulnerability.affected_range()})",
            f"Vulnerability ID: {vulnerability.identifier}",
        ]
        if vulnerability.summary:
            header.append(f"Summary: {vulnerability.summary}")
        if vulnerability.recommendation:
            header.append(f"Recommendation: {vulnerability.recommendation}")
        if self.context and self.context.coding_guidelines:
            header.append("Coding guidelines:\n" + self.context.coding_guidelines.strip())

        prompt = "\n".join(header)
        if context_lines:
            prompt += "\n\nCurrent implementation:\n" + context_lines
        prompt += (
            "\n\nPlease produce a JSON array named 'patches'. Each item must include the keys "
            "'file_path', 'replacement', 'vulnerability_id', and 'analysis'."
        )
        prompt += (
            "\nSet 'vulnerability_id' to the identifier listed above and use 'analysis' to explain the remediation."
        )
        prompt += (
            "\nIf helpful, also provide 'test_recommendations' describing commands or checks reviewers should run."
        )
        prompt += "\nEnsure the replacement text is complete file content that resolves the vulnerability while preserving formatting."
        return prompt

    def build_batch_prompt(self, vulnerabilities: Iterable[Vulnerability]) -> str:
        """Combine multiple vulnerabilities into a single prompt."""

        prompts = [self.build_prompt(v) for v in vulnerabilities]
        return "\n\n---\n\n".join(prompts)


__all__ = ["PromptBuilder", "PromptContext"]
