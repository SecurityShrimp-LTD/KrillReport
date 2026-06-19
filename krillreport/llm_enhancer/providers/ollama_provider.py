"""Ollama provider — local models via the Ollama HTTP API.

Talks to a running Ollama server (default ``http://localhost:11434``) over its
``/api/chat`` endpoint using ``httpx``. No API key is needed; the model must be pulled
on the server (``ollama pull llama3.1``).
"""

from __future__ import annotations

from typing import Optional

from ...logging_config import get_logger
from ..base import LLMProvider, ProviderError

logger = get_logger(__name__)

_DEFAULT_BASE_URL = "http://localhost:11434"


class OllamaProvider(LLMProvider):
    name = "ollama"
    is_llm = True

    def __init__(
        self,
        model: str = "llama3.1",
        base_url: Optional[str] = None,
        max_tokens: int = 2048,
        temperature: Optional[float] = None,
        timeout: float = 90.0,
        **_: object,
    ) -> None:
        self.model = model or "llama3.1"
        self.base_url = (base_url or _DEFAULT_BASE_URL).rstrip("/")
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout = timeout

    def available(self) -> bool:
        import importlib.util

        if importlib.util.find_spec("httpx") is None:
            logger.warning("httpx not installed; install with `pip install httpx`.")
            return False
        # We assume a configured server is reachable; a failed call falls back gracefully.
        return True

    def generate(self, system: str, user: str) -> str:
        try:
            import httpx

            options = {"num_predict": self.max_tokens}
            if self.temperature is not None:
                options["temperature"] = self.temperature
            payload = {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "stream": False,
                "options": options,
            }
            response = httpx.post(
                f"{self.base_url}/api/chat", json=payload, timeout=self.timeout
            )
            response.raise_for_status()
            data = response.json()
            return (data.get("message", {}).get("content", "") or "").strip()
        except Exception as exc:
            raise ProviderError(f"Ollama request failed: {exc}") from exc
