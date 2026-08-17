"""LLM fallback chain: try local Ollama (GPU/CPU) -> API key -> heuristic.

The chain returns a callable `complete()` that never raises: if every LLM
provider is unreachable, it falls back to a small rule-based generator so
the CLI always produces a usable answer.
"""

from __future__ import annotations

import logging
from typing import Any, Callable, Dict, List, Optional

from .api_provider import OpenAICompatProvider
from .ollama_provider import OllamaProvider
from .provider import LLMError, LLMProvider

logger = logging.getLogger("hexshield.llm")


class LLMChain:
    def __init__(
        self,
        ollama_model: str = "robit/ornith:9b",
        ollama_host: str = "http://127.0.0.1:11434",
        api_model: str = "",
        api_key: str = "",
        api_base: str = "",
        enable_api: bool = True,
    ):
        self.providers: List[LLMProvider] = []
        if ollama_model:
            self.providers.append(OllamaProvider(model=ollama_model, host=ollama_host))
        if enable_api and (api_model or api_key):
            self.providers.append(
                OpenAICompatProvider(model=api_model, api_key=api_key, base_url=api_base)
            )
        self.active: Optional[LLMProvider] = None

    def _probe(self) -> Optional[LLMProvider]:
        """Return the first reachable provider without doing any chat work."""
        for p in self.providers:
            try:
                if p.is_available():
                    return p
            except Exception as e:  # defensive
                logger.debug("probe failed for %s: %s", p.name, e)
        return None

    def health(self) -> List[Dict[str, Any]]:
        return [p.health_details() or {"provider": p.name} for p in self.providers]

    def ensure_llm(self) -> Dict[str, Any]:
        """Probe all providers and report which (if any) is usable.

        Returns a structured diagnostic so the caller can decide whether to
        proceed, fall back, or guide the user to set up an LLM.
        """
        result: Dict[str, Any] = {
            "available": False,
            "active_provider": None,
            "providers": [],
        }
        for p in self.providers:
            try:
                ok = p.is_available()
            except Exception as e:  # defensive
                ok = False
            # Auto-select a pulled model if the configured Ollama model is missing.
            if not ok and hasattr(p, "auto_select"):
                try:
                    if p.auto_select():
                        ok = p.is_available()
                except Exception:
                    ok = False
            detail = p.health_details() or {}
            detail["available"] = ok
            detail["configured"] = p._is_configured() if hasattr(p, "_is_configured") else ok
            result["providers"].append(detail)
            if ok and not result["available"]:
                result["available"] = True
                result["active_provider"] = p.name
        return result

    def _chat_with(
        self, provider: LLMProvider, messages: List[Dict[str, str]], **kwargs
    ) -> str:
        try:
            self.active = provider
            return provider.chat(messages, **kwargs)
        except LLMError as e:
            logger.warning("provider %s failed: %s", provider.name, e)
            self.active = None
            raise

    def complete(
        self,
        messages: List[Dict[str, str]],
        heuristic_fallback: Callable[[List[Dict[str, str]]], str] | None = None,
        **kwargs,
    ) -> str:
        """Best-effort completion across all providers + heuristic fallback."""
        for provider in self._ordered_providers():
            try:
                if not provider.is_available():
                    continue
                text = self._chat_with(provider, messages, **kwargs)
                if text and text.strip():
                    return text
                # empty response -> treat as failure, try next provider
                logger.warning("provider %s returned empty content; trying next", provider.name)
            except LLMError:
                continue

        if heuristic_fallback is not None:
            logger.info("no usable LLM; using rule-based fallback")
            return heuristic_fallback(messages)

        raise LLMError("no LLM provider available and no heuristic fallback registered")

    def _ordered_providers(self) -> List[LLMProvider]:
        """Providers ordered by preference: configured/reachable first."""
        reachable = [p for p in self.providers if p.is_available()]
        others = [p for p in self.providers if p not in reachable]
        return reachable + others


_default_chain: Optional[LLMChain] = None


def get_llm_chain(
    ollama_model: str = "robit/ornith:9b",
    ollama_host: str = "http://127.0.0.1:11434",
    api_model: str = "",
    api_key: str = "",
    api_base: str = "",
    enable_api: bool = True,
) -> LLMChain:
    global _default_chain
    _default_chain = LLMChain(
        ollama_model=ollama_model,
        ollama_host=ollama_host,
        api_model=api_model,
        api_key=api_key,
        api_base=api_base,
        enable_api=enable_api,
    )
    return _default_chain