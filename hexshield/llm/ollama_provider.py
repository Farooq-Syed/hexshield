"""Ollama provider: talks to a local Ollama server over HTTP.

Ollama automatically runs on GPU when the model fits in VRAM and offloads
to CPU otherwise, so a single model name covers the GPU/CPU case.
"""

from __future__ import annotations

import json
import re
import time
import urllib.request
from typing import Any, Dict, List, Optional

from .provider import LLMError, LLMProvider


class OllamaProvider(LLMProvider):
    name = "ollama"

    def __init__(self, model: str = "robit/ornith:9b", host: str = "http://127.0.0.1:11434"):
        self.model = model
        self.host = host.rstrip("/")
        self._models: Optional[List[str]] = None

    # -- helpers -------------------------------------------------------------

    def _post(self, path: str, payload: Dict[str, Any], timeout: int) -> Any:
        req = urllib.request.Request(
            f"{self.host}{path}",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except Exception as e:  # URLError, TimeoutError, JSON decode
            raise LLMError(f"ollama request to {path} failed: {e}") from e

    # -- LLMProvider ---------------------------------------------------------

    def is_available(self) -> bool:
        """True if the Ollama server is reachable AND the requested model is present."""
        try:
            with urllib.request.urlopen(f"{self.host}/api/tags", timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                self._models = [m.get("name", "") for m in data.get("models", [])]
        except Exception:
            return False
        return self._model_present()

    def _is_configured(self) -> bool:
        """True if a model name was requested (independent of server/model state)."""
        return bool(self.model)

    def _model_present(self) -> bool:
        if not self._models:
            return False
        wanted = self.model
        return any(m == wanted or m.startswith(wanted.split(":")[0] + ":") for m in self._models)

    def auto_select(self) -> bool:
        """If the configured model is missing but models are pulled, switch to
        a suitable one automatically. Prefers 8B-class, else the smallest.
        Returns True if a usable model was selected.
        """
        if not self._models:
            return False
        if self._model_present():
            return True
        # rank: prefer models that fit in typical 8GB VRAM (<=10B), then
        # mainstream families, then 8B-ish, then smallest.
        def size_key(name: str):
            m = re.search(r":?(\d{1,3})b", name, re.I)
            return int(m.group(1)) if m else 999
        def family_rank(name: str):
            lower = name.lower()
            # robit/ornith:9b is the user's preferred local model
            if "robit/ornith" in lower:
                return -1
            for i, fam in enumerate(["qwen", "llama", "mistral", "phi", "gemma", "deepseek", "ornith"]):
                if fam in lower:
                    return i
            return 99  # unknown/uncensored variants ranked last
        def vram_fits(name: str):
            return size_key(name) <= 10  # prefer small models (fast on 8GB VRAM)
        candidates = sorted(
            self._models,
            key=lambda n: (
                not vram_fits(n),   # small/fast first
                family_rank(n),
                abs(size_key(n) - 8),
                size_key(n),
            ),
        )
        for name in candidates:
            self.model = name
            if self._model_present():
                return True
        return False

    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 2048,
        timeout: int = 120,
    ) -> str:
        payload = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "think": False,  # disable qwen3-style thinking so content is populated
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        data = self._post("/api/chat", payload, timeout=timeout)
        if "message" in data and "content" in data["message"]:
            content = data["message"]["content"]
            if not content.strip() and data["message"].get("thinking"):
                # some models ignore "think": false and emit everything in `thinking`
                content = data["message"]["thinking"]
            if content.strip():
                return content
        raise LLMError(f"ollama returned empty/unexpected payload: {data!r}")

    def health_details(self) -> Optional[Dict[str, Any]]:
        start = time.time()
        try:
            available = self.is_available()
        except Exception:
            available = False
        return {
            "provider": self.name,
            "model": self.model,
            "available": available,
            "latency_ms": int((time.time() - start) * 1000),
            "pulled_models": self._models,
        }