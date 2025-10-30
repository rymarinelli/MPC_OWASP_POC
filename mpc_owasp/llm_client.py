"""LLM client wrappers for the MCP pipeline."""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional

import requests


class LLMClient(ABC):
    """Abstract base class for LLM interactions."""

    @abstractmethod
    def generate(self, prompt: str, *, temperature: float = 0.0) -> str:
        """Return the raw model completion for *prompt*."""


@dataclass
class OpenAICompatibleClient(LLMClient):
    """Minimal client for OpenAI-compatible text completion endpoints."""

    endpoint: str
    api_key: str
    model: str
    default_headers: Dict[str, str] | None = None

    def _headers(self) -> Dict[str, str]:
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        if self.default_headers:
            headers.update(self.default_headers)
        return headers

    def generate(
        self,
        prompt: str,
        *,
        temperature: float = 0.0,
        stop: Optional[Iterable[str]] = None,
    ) -> str:
        payload: Dict[str, Any] = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": "You produce structured JSON diffs."},
                {"role": "user", "content": prompt},
            ],
            "temperature": temperature,
        }
        if stop is not None:
            payload["stop"] = list(stop)

        response = requests.post(self.endpoint, json=payload, headers=self._headers(), timeout=60)
        response.raise_for_status()
        data = response.json()

        if "choices" not in data or not data["choices"]:
            raise RuntimeError(f"LLM response missing choices: {json.dumps(data)}")

        message = data["choices"][0].get("message") or {}
        content = message.get("content")
        if not content:
            raise RuntimeError(f"LLM response missing content: {json.dumps(data)}")
        return content


__all__ = ["LLMClient", "OpenAICompatibleClient"]
