"""Provider abstraction for LLM narrative enhancement.

Every backend implements :class:`LLMProvider`. ``is_llm`` distinguishes real
text-generating providers (Anthropic/OpenAI/Ollama) from the deterministic
:class:`~krillreport.llm_enhancer.providers.offline.OfflineProvider`, which fills
missing prose from templates without a network call. ``available()`` lets the enhancer
fall back to offline behaviour when a selected provider's SDK or credentials are
missing, instead of failing the whole report.
"""

from __future__ import annotations

import abc


class ProviderError(Exception):
    """Raised when an LLM provider call fails irrecoverably."""


class LLMProvider(abc.ABC):
    """Base class for narrative-enhancement providers."""

    #: Provider identifier (e.g. ``"anthropic"``).
    name: str = "base"
    #: True for real text-generating providers; False for the offline template provider.
    is_llm: bool = True

    @abc.abstractmethod
    def available(self) -> bool:
        """Return True if this provider can actually be used right now.

        Checks SDK importability and credential presence — never makes a network call.
        """
        raise NotImplementedError

    @abc.abstractmethod
    def generate(self, system: str, user: str) -> str:
        """Generate text for the given system + user prompt. May raise ProviderError."""
        raise NotImplementedError
