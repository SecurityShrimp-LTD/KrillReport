"""PDF ingestion via pdfplumber.

Extracts page text and tables. Findings are recovered two ways:

* **Tables** — a table whose header row names finding-ish columns
  (severity/title/description …) has each data row mapped to a finding.
* **Text** — the concatenated page text is run through the shared free-text engine.

Whatever cannot be structured is preserved as an appendix. PDF text extraction is
inherently lossy, so this is explicitly best-effort and never raises on a difficult
document.
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, List

import pdfplumber

from ..logging_config import get_logger
from ..models import Appendix
from .base import BaseParser, ParseResult, register_parser
from .common import build_finding, looks_like_finding
from .text_extract import extract_findings_from_text
from .text_parser import _sections_to_metadata

logger = get_logger(__name__)

_MIN_APPENDIX_CHARS = 120


@register_parser
class PDFParser(BaseParser):
    name = "pdf"
    extensions = (".pdf",)

    def can_parse(self, path: Path, sample: str) -> bool:
        if super().can_parse(path, sample):
            return True
        return sample.startswith("%PDF")

    def parse(self, path: Path) -> ParseResult:
        result = ParseResult(source_file=path.name, parser=self.name)
        page_texts: List[str] = []
        tables: List[List[List[str]]] = []

        try:
            with pdfplumber.open(str(path)) as pdf:
                for page in pdf.pages:
                    page_texts.append(page.extract_text() or "")
                    try:
                        for table in page.extract_tables() or []:
                            if table:
                                tables.append(table)
                    except Exception as exc:  # pragma: no cover - pdfplumber edge cases
                        logger.debug("Table extraction failed on a page of %s: %s", path.name, exc)
        except Exception as exc:
            logger.warning("Failed to read PDF %s: %s", path.name, exc)
            result.warnings.append(f"Could not read PDF: {exc}")
            return result

        # 1. Findings from tables.
        table_findings = self._findings_from_tables(tables, path.name)
        result.findings.extend(table_findings)

        # 2. Findings + sections from the body text.
        full_text = "\n".join(page_texts).strip()
        if full_text:
            extraction = extract_findings_from_text(full_text, source_file=path.name)
            # Avoid double-counting: only add text findings if tables produced none.
            if not table_findings:
                result.findings.extend(extraction.findings)
            result.metadata.update(_sections_to_metadata(extraction.sections))

        # 3. Fallback appendix if nothing structured.
        if not result.findings and full_text and len(full_text) >= _MIN_APPENDIX_CHARS:
            result.appendices.append(
                Appendix(title=f"Extracted text — {path.stem}", content=full_text)
            )
            result.warnings.append(
                "No structured findings detected in PDF; extracted text imported as an appendix."
            )

        logger.info(
            "Parsed %s: %d finding(s) from %d table(s) + body text",
            path.name,
            len(result.findings),
            len(tables),
        )
        return result

    def _findings_from_tables(self, tables, source_file: str):
        findings = []
        for table in tables:
            if len(table) < 2:
                continue
            header = [self._clean_cell(c) for c in table[0]]
            header_lower = {h.lower() for h in header if h}
            # Only treat as a findings table if the header looks finding-ish.
            if not (header_lower & {"severity", "risk", "finding", "title", "vulnerability", "description"}):
                continue
            for row in table[1:]:
                if not any(self._clean_cell(c) for c in row):
                    continue
                record: Dict[str, str] = {}
                for key, cell in zip(header, row):
                    if key:
                        record[key] = self._clean_cell(cell)
                if looks_like_finding(record):
                    findings.append(build_finding(record, source_file=source_file))
        return findings

    @staticmethod
    def _clean_cell(cell) -> str:
        if cell is None:
            return ""
        return " ".join(str(cell).split())
