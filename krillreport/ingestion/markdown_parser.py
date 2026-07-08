"""Markdown (``.md``) ingestion.

Markdown reports come in three broad shapes, tried most-specific first:

1. A **multi-finding report** — a whole engagement in one file (often LLM-authored): an
   H1 title, a ``**Key:** value`` header, ``## N. Section`` headings, and each finding as
   an ``### Fn — Title (Severity)`` subsection. Handled by :mod:`report_document`.
2. A **single structured finding** — one finding written as a KV table + titled sections.
   Handled by :mod:`structured_finding`.
3. **Everything else** — the first H1 is the report title, and the free-text engine runs
   with ``min_heading_level=2`` so the title is not mistaken for a finding; ``##``/``###``
   headings introduce findings and fenced code blocks become evidence.
"""

from __future__ import annotations

import re
from pathlib import Path

from ..logging_config import get_logger
from ..models import Appendix
from .base import BaseParser, ParseResult, register_parser
from .common import build_finding
from .report_document import build_report, looks_like_finding_report
from .structured_finding import build_structured_record, looks_like_structured_finding
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

        # A whole multi-finding report (e.g. an LLM-authored assessment): each
        # ``### F1 — Title (Severity)`` subsection is one finding; section prose and the
        # ``**Key:** value`` header seed metadata / appendices. Checked before the
        # single-finding shape below, which its section headings would otherwise match.
        if looks_like_finding_report(text):
            report_title, metadata, records, appendix_sections = build_report(text)
            for record, status in records:
                finding = build_finding(record, source_file=path.name)
                if status is not None:
                    finding.status = status
                result.findings.append(finding)
            result.metadata.update(metadata)
            for ap_title, ap_body in appendix_sections:
                result.appendices.append(Appendix(title=ap_title, content=ap_body))
            logger.info(
                "Parsed %s as a multi-finding report: %d finding(s), %d appendix section(s).",
                path.name, len(result.findings), len(appendix_sections),
            )
            return result

        # A document that *is* a single finding (titled sections + a Severity/CVSS
        # metadata table) is mapped to one Finding, not split per heading.
        if looks_like_structured_finding(text):
            record, status = build_structured_record(text)
            finding = build_finding(record, source_file=path.name)
            if status is not None:
                finding.status = status
            result.findings = [finding]
            logger.info("Parsed %s as a single structured finding.", path.name)
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
