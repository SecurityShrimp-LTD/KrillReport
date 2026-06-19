"""JSON ingestion.

Handles standard JSON (object or array) and falls back to JSON Lines (one object per
line) which several tools emit. The loaded structure is handed to the shared
:func:`parse_structured` walker, so any nesting / field naming is handled uniformly.
"""

from __future__ import annotations

import json
from pathlib import Path

from ..logging_config import get_logger
from .base import BaseParser, ParseResult, register_parser
from .common import build_finding, looks_like_host, build_host, parse_structured

logger = get_logger(__name__)


@register_parser
class JSONParser(BaseParser):
    name = "json"
    extensions = (".json",)

    def can_parse(self, path: Path, sample: str) -> bool:
        if super().can_parse(path, sample):
            return True
        stripped = sample.lstrip()
        return stripped.startswith("{") or stripped.startswith("[")

    def parse(self, path: Path) -> ParseResult:
        text = path.read_text(encoding="utf-8", errors="replace")
        try:
            data = json.loads(text)
        except json.JSONDecodeError as exc:
            # Fall back to JSON Lines.
            jsonl = self._try_jsonl(text, path)
            if jsonl is not None:
                return jsonl
            logger.warning("Failed to parse %s as JSON: %s", path.name, exc)
            return ParseResult(
                source_file=path.name,
                parser=self.name,
                warnings=[f"Invalid JSON: {exc}"],
            )
        return parse_structured(data, source_file=path.name, parser=self.name)

    def _try_jsonl(self, text: str, path: Path):
        """Attempt to read the file as JSON Lines; return None if it isn't JSONL."""
        objects = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                objects.append(json.loads(line))
            except json.JSONDecodeError:
                return None
        if not objects:
            return None
        result = ParseResult(source_file=path.name, parser=self.name)
        for obj in objects:
            if isinstance(obj, dict):
                if looks_like_host(obj):
                    result.hosts.append(build_host(obj))
                else:
                    result.findings.append(build_finding(obj, source_file=path.name))
        logger.info("Parsed %s as JSON Lines (%d records)", path.name, len(objects))
        return result
