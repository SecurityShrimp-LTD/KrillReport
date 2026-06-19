"""OpenAI (and OpenAI-compatible) provider.

Uses the official ``openai`` SDK's Chat Completions API. Setting ``base_url`` lets this
provider target any OpenAI-compatible gateway (vLLM, LiteLLM, Azure-compatible proxies,
etc.), in which case an API key may not be required.
"""

from __future__ import annotations

import os
from typing import Optional

from ...logging_config import get_logger
from ..base import LLMProvider, ProviderError

logger = get_logger(__name__)


class OpenAIProvider(LLMProvider):
    name = "openai"
    is_llm = True

    def __init__(
        self,
        model: str = "gpt-4o",
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        max_tokens: int = 2048,
        temperature: Optional[float] = None,
        timeout: float = 90.0,
        **_: object,
    ) -> None:
        self.model = model or "gpt-4o"
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        self.base_url = base_url
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout = timeout

    def available(self) -> bool:
        import importlib.util

        if importlib.util.find_spec("openai") is None:
            logger.warning("openai SDK not installed; install with `pip install openai`.")
            return False
        # A key is required for api.openai.com but not necessarily for a local gateway.
        if not self.api_key and not self.base_url:
            logger.warning("OPENAI_API_KEY not set and no base_url given; cannot use openai provider.")
            return False
        return True

    def generate(self, system: str, user: str) -> str:
        try:
            from openai import OpenAI

            client = OpenAI(api_key=self.api_key, base_url=self.base_url, timeout=self.timeout)
            kwargs = {
                "model": self.model,
                "max_tokens": self.max_tokens,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
            }
            if self.temperature is not None:
                kwargs["temperature"] = self.temperature
            response = client.chat.completions.create(**kwargs)
            return (response.choices[0].message.content or "").strip()
        except Exception as exc:
            raise ProviderError(f"OpenAI request failed: {exc}") from exc
