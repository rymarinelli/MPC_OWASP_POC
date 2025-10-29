"""Main entrypoints for the Model-driven Code Patching (MCP) utilities."""

from .scan_parser import ScanParser, Vulnerability
from .prompt_builder import PromptBuilder
from .prompt_builder import PromptContext
from .patch_generator import PatchCandidate, PatchGenerator
from .llm_client import LLMClient, OpenAICompatibleClient
from .github_client import GitHubClient, PullRequestPayload
from .pipeline import AppliedPatch, AutoRemediationPipeline

__all__ = [
    "ScanParser",
    "Vulnerability",
    "PromptContext",
    "PromptBuilder",
    "PatchCandidate",
    "PatchGenerator",
    "LLMClient",
    "OpenAICompatibleClient",
    "GitHubClient",
    "PullRequestPayload",
    "AppliedPatch",
    "AutoRemediationPipeline",
]
