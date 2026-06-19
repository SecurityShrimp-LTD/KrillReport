"""Application configuration.

Configuration is resolved, in order of decreasing precedence, from:

1. Explicit keyword arguments passed to :class:`Settings` (e.g. CLI flags).
2. Environment variables prefixed ``KRILLREPORT_`` (nested via ``__``), plus the
   standard provider variables ``ANTHROPIC_API_KEY`` / ``OPENAI_API_KEY``.
3. A ``.env`` file in the working directory.
4. A YAML config file (``config.yaml`` by default, override with ``KRILLREPORT_CONFIG``).
5. Built-in defaults.

This layered approach means the same build runs unconfigured (offline narrative
enhancement, data under ``./krilldata``) yet can be fully driven by env/yaml in a
container or CI without code changes.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Optional, Tuple, Type

from pydantic import Field, model_validator
from pydantic_settings import (
    BaseSettings,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
    YamlConfigSettingsSource,
)

# Sensible per-provider default models. Anthropic defaults to the current Opus model.
DEFAULT_MODELS = {
    "anthropic": "claude-opus-4-8",
    "openai": "gpt-4o",
    "ollama": "llama3.1",
    "offline": "offline-template",
}


class LLMSettings(BaseSettings):
    """Settings for the narrative-enhancement LLM provider.

    ``provider`` selects the backend. ``offline`` performs deterministic, template
    based enhancement and requires no credentials — it is the default so the tool
    works out of the box and remains fully testable without network access.
    """

    model_config = SettingsConfigDict(env_prefix="KRILLREPORT_LLM__", extra="ignore")

    provider: str = "offline"  # offline | anthropic | openai | ollama
    model: str = ""  # resolved from DEFAULT_MODELS when left blank
    api_key: Optional[str] = None  # falls back to provider-native env var if None
    base_url: Optional[str] = None  # for ollama / OpenAI-compatible gateways
    max_tokens: int = 2048
    # Temperature is intentionally optional: some Anthropic models reject the
    # parameter, so providers only forward it when explicitly set.
    temperature: Optional[float] = None
    timeout: float = 90.0
    # Master switch — when False, narrative sections are passed through verbatim.
    enabled: bool = True

    @model_validator(mode="after")
    def _resolve_model(self) -> "LLMSettings":
        if not self.model:
            self.model = DEFAULT_MODELS.get(self.provider, DEFAULT_MODELS["offline"])
        return self


class Settings(BaseSettings):
    """Top-level application settings."""

    model_config = SettingsConfigDict(
        env_prefix="KRILLREPORT_",
        env_nested_delimiter="__",
        env_file=".env",
        env_file_encoding="utf-8",
        yaml_file=os.getenv("KRILLREPORT_CONFIG", "config.yaml"),
        extra="ignore",
    )

    # Filesystem layout. Only ``data_dir`` needs to be set; the others are derived
    # from it when left unset (see :meth:`_derive_dirs`).
    data_dir: Path = Path("krilldata")
    templates_dir: Optional[Path] = None
    output_dir: Optional[Path] = None
    upload_dir: Optional[Path] = None

    # Web server.
    host: str = "127.0.0.1"
    port: int = 8000

    # Observability.
    log_level: str = "INFO"
    log_file: Optional[Path] = None

    llm: LLMSettings = Field(default_factory=LLMSettings)

    @model_validator(mode="after")
    def _derive_dirs(self) -> "Settings":
        if self.templates_dir is None:
            self.templates_dir = self.data_dir / "templates"
        if self.output_dir is None:
            self.output_dir = self.data_dir / "output"
        if self.upload_dir is None:
            self.upload_dir = self.data_dir / "uploads"
        return self

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: Type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> Tuple[PydanticBaseSettingsSource, ...]:
        # Precedence: init kwargs > env > .env > YAML file > file secrets.
        return (
            init_settings,
            env_settings,
            dotenv_settings,
            YamlConfigSettingsSource(settings_cls),
            file_secret_settings,
        )

    def ensure_dirs(self) -> None:
        """Create the data/template/output/upload directories if missing.

        Called by the entry points (CLI / API) at start-up rather than at import time
        so merely importing the package has no filesystem side effects.
        """
        for directory in (self.data_dir, self.templates_dir, self.output_dir, self.upload_dir):
            if directory is not None:
                Path(directory).mkdir(parents=True, exist_ok=True)


_settings: Optional[Settings] = None


def get_settings(reload: bool = False, **overrides) -> Settings:
    """Return a process-wide cached :class:`Settings` instance.

    Pass ``reload=True`` (or any ``overrides``) to rebuild — used by the CLI to inject
    flag values such as a chosen provider or output directory.
    """
    global _settings
    if _settings is None or reload or overrides:
        _settings = Settings(**overrides)
    return _settings
