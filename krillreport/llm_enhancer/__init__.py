"""LLM narrative enhancement.

Public API::

    from krillreport.llm_enhancer import Enhancer, build_provider, LLMProvider

The default provider is ``offline`` (deterministic, no network), so enhancement always
works; selecting ``anthropic`` / ``openai`` / ``ollama`` upgrades the prose quality.
"""

from __future__ import annotations

from .base import LLMProvider, ProviderError
from .enhancer import Enhancer, build_provider

__all__ = ["Enhancer", "build_provider", "LLMProvider", "ProviderError"]
