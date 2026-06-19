"""YAML ingestion.

YAML loads to the same Python primitives as JSON, so once parsed it shares the
:func:`parse_structured` walker. ``yaml.safe_load`` is used to avoid arbitrary object
construction from untrusted input.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from ..logging_config import get_logger
from .base import BaseParser, ParseResult, register_parser
from .common import parse_structured

logger = get_logger(__name__)


@register_parser
class YAMLParser(BaseParser):
    name = "yaml"
    extensions = (".yaml", ".yml")

    def parse(self, path: Path) -> ParseResult:
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            # A YAML file may contain multiple documents; combine list/dict docs.
            documents = list(yaml.safe_load_all(text))
        except yaml.YAMLError as exc:
            logger.warning("Failed to parse %s as YAML: %s", path.name, exc)
            return ParseResult(
                source_file=path.name,
                parser=self.name,
                warnings=[f"Invalid YAML: {exc}"],
            )

        documents = [doc for doc in documents if doc is not None]
        if not documents:
            return ParseResult(
                source_file=path.name, parser=self.name, warnings=["Empty YAML document."]
            )

        result = ParseResult(source_file=path.name, parser=self.name)
        for doc in documents:
            result.extend(parse_structured(doc, source_file=path.name, parser=self.name))
        return result
