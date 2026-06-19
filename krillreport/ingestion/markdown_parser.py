"""Markdown (``.md``) ingestion.

Markdown reports typically use the top ``# H1`` as the report title and ``## H2`` /
``### H3`` headings to introduce findings. We extract the first H1 as the report title,
then run the free-text engine with ``min_heading_level=2`` so the title heading is not
mistaken for a finding. Fenced code blocks become evidence.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..logging_config import get_logger
from ..models import Appendix
from .base import BaseParser, ParseResult, register_parser
from .text_extract import extract_findings_from_text
from .text_parser import _sections_to_metadata

logger = get_logger(__name__)

_H1_RE = re.compile(r"^#\s+(.*\S)\s*$", re.MULTILINE)


@register_parser
class MarkdownParser(BaseParser):
    name = "markdown"
    extensions = (".md", ".markdown")

    def parse(self, path: Path) -> ParseResult:
        text = path.read_text(encoding="utf-8", errors="replace")
        result = ParseResult(source_file=path.name, parser=self.name)
        if not text.strip():
            result.warnings.append("Empty Markdown file.")
            return result

        # First H1 becomes the report title (if any).
        h1 = _H1_RE.search(text)
        if h1:
            result.metadata["report_title"] = h1.group(1).strip()

        extraction = extract_findings_from_text(
            text, source_file=path.name, min_heading_level=2
        )
        result.findings = extraction.findings
        result.metadata.update(_sections_to_metadata(extraction.sections))

        if not result.findings:
            result.appendices.append(
                Appendix(title=f"Imported Markdown — {path.stem}", content=text.strip())
            )
            result.warnings.append(
                "No finding sections detected; content imported as an appendix."
            )
        logger.info("Parsed %s: %d finding(s)", path.name, len(result.findings))
        return result
