"""Offline provider — deterministic, no network, no credentials.

This is the default and the universal fallback. It does not generate text itself; the
enhancer detects ``is_llm == False`` and instead fills only the *missing* narrative
fields from the deterministic templates in :mod:`krillreport.llm_enhancer.prompts`,
leaving any prose already present in the inputs untouched.
"""

from __future__ import annotations

from ..base import LLMProvider


class OfflineProvider(LLMProvider):
    name = "offline"
    is_llm = False

    def available(self) -> bool:
        return True

    def generate(self, system: str, user: str) -> str:  # pragma: no cover - never called
        # The enhancer never calls generate() on a non-LLM provider.
        return ""
