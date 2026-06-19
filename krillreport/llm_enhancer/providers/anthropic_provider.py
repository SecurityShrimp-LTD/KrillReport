"""Anthropic (Claude) provider.

Uses the official ``anthropic`` SDK. The default model is Claude Opus 4.8
(``claude-opus-4-8``). The ``anthropic`` package and SDK calls are imported lazily so
the dependency is only required when this provider is actually selected. Sampling
parameters (``temperature``) are intentionally not sent — current Opus models reject
them — and adaptive thinking is left at the model default, which is appropriate for
short narrative rewriting.
"""

from __future__ import annotations

import os
from typing import Optional

from ...logging_config import get_logger
from ..base import LLMProvider, ProviderError

logger = get_logger(__name__)


class AnthropicProvider(LLMProvider):
    name = "anthropic"
    is_llm = True

    def __init__(
        self,
        model: str = "claude-opus-4-8",
        api_key: Optional[str] = None,
        max_tokens: int = 2048,
        timeout: float = 90.0,
        **_: object,
    ) -> None:
        self.model = model or "claude-opus-4-8"
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        self.max_tokens = max_tokens
        self.timeout = timeout

    def available(self) -> bool:
        import importlib.util

        if importlib.util.find_spec("anthropic") is None:
            logger.warning("anthropic SDK not installed; install with `pip install anthropic`.")
            return False
        if not self.api_key:
            logger.warning("ANTHROPIC_API_KEY not set; cannot use the anthropic provider.")
            return False
        return True

    def generate(self, system: str, user: str) -> str:
        try:
            import anthropic

            client = anthropic.Anthropic(api_key=self.api_key, timeout=self.timeout)
            response = client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=system,
                messages=[{"role": "user", "content": user}],
            )
            return "".join(
                getattr(block, "text", "")
                for block in response.content
                if getattr(block, "type", "") == "text"
            ).strip()
        except Exception as exc:  # SDK raises a variety of typed errors
            raise ProviderError(f"Anthropic request failed: {exc}") from exc
