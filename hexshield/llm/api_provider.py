"""OpenAI-compatible provider: works with OpenAI, Groq, DeepSeek, Ollama's
/compat endpoint, or any local gateway exposing the /v1/chat/completions API.

Uses only the Python standard library (no openai SDK dependency).
"""

from __future__ import annotations

import json
import os
import time
import urllib.request
from typing import Any, Dict, List, Optional

from .provider import LLMError, LLMProvider


class OpenAICompatProvider(LLMProvider):
    name = "openai-compat"

    def __init__(
        self,
        model: str = "",
        api_key: str = "",
        base_url: str = "https://api.openai.com/v1",
    ):
        # env-var fallbacks keep the key out of any config file
        self.model = model or os.environ.get("HEXSHIELD_API_MODEL", "")
        self.api_key = api_key or os.environ.get("HEXSHIELD_API_KEY", "")
        self.base_url = base_url.rstrip("/") or os.environ.get(
            "HEXSHIELD_API_BASE", "https://api.openai.com/v1"
        )

    def is_available(self) -> bool:
        return bool(self.model and self.api_key)

    def _is_configured(self) -> bool:
        return bool(self.model and self.api_key)

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 2048,
        timeout: int = 120,
    ) -> str:
        if not self.is_available():
            raise LLMError("openai-compat provider not configured (model/key missing)")
        payload = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        req = urllib.request.Request(
            f"{self.base_url}/chat/completions",
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self.api_key}",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except Exception as e:
            raise LLMError(f"api request failed: {e}") from e

        try:
            return data["choices"][0]["message"]["content"]
        except (KeyError, IndexError, TypeError) as e:
            raise LLMError(f"api returned unexpected payload: {data!r}") from e

    def health_details(self) -> Optional[Dict[str, Any]]:
        return {
            "provider": self.name,
            "model": self.model,
            "base_url": self.base_url,
            "available": self.is_available(),
        }