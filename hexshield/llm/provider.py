"""Abstract LLM provider interface.

Any local or remote model backend implements this. The rest of HexShield
only ever talks to LLMProvider, so swapping models is a config change, not
a code change.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional


class LLMProvider(ABC):
    """Common interface for a chat-completion style LLM backend."""

    name: str = "base"

    @abstractmethod
    def is_available(self) -> bool:
        """Return True if this provider can be reached right now."""

    @abstractmethod
    def chat(
        self,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 2048,
        timeout: int = 120,
    ) -> str:
        """Send a chat completion and return the assistant text.

        messages: [{"role": "system"|"user"|"assistant", "content": "..."}]
        Raises LLMError on failure.
        """

    def health_details(self) -> Optional[Dict[str, Any]]:
        """Optional diagnostic info about the provider (model, latency)."""
        return None


class LLMError(Exception):
    """Raised when an LLM call fails (connection, timeout, bad response)."""