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

import re
from pathlib import Path
from typing import Dict, List

import pdfplumber

from ..logging_config import get_logger
from ..models import Appendix
from ..utils import sanitize_xml
from .base import BaseParser, ParseResult, register_parser
from .common import build_finding, looks_like_finding
from .text_extract import extract_findings_from_text
from .text_parser import _sections_to_metadata

logger = get_logger(__name__)

_MIN_APPENDIX_CHARS = 120

# --- NodeZero / Horizon3 report support ------------------------------------ #
# These reports introduce each weakness with a section-numbered heading whose line
# ends in an UPPERCASE severity word and a CVSS score, e.g.:
#   "2.5.2. Git Repo Exposed on a Web Server HIGH 7.5"
# The leading section number + letter-initial title (and excluding tcp/udp rows)
# distinguishes a real weakness heading from the asset/port table rows that also end
# in "<SEV> <score>".
_NZ_HEADING_RE = re.compile(
    r"^\s*\d+\.\d+(?:\.\d+)*\.?\s+"
    r"(?P<title>[A-Za-z][^\n]*?)\s+"
    r"(?P<sev>CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL|INFO)\s+"
    r"(?P<score>\d+(?:\.\d+)?)\s*$"
)

# Bare-line sub-section labels inside a weakness -> canonical finding field.
_NZ_SUBHEADINGS = {
    "details": "description",
    "description": "description",
    "context": "description",
    "summary": "description",
    "impact": "impact",
    "recommendation": "remediation",
    "recommendations": "remediation",
    "remediation": "remediation",
    "proof": "evidence",
    "references": "references",
    "affected assets": "affected",
}

# Caps so a single weakness can't bloat the report.
_NZ_MAX_FIELD_CHARS = 6000
_NZ_MAX_ASSETS = 60


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
                    page_texts.append(sanitize_xml(page.extract_text() or ""))
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

        full_text = "\n".join(page_texts).strip()

        # 0. NodeZero / Horizon3-style structured weakness extraction (guarded; only
        #    activates when several section-numbered severity headings are present).
        nz_findings = self._nodezero_findings(full_text, path.name) if full_text else []
        if nz_findings:
            result.findings.extend(nz_findings)
            logger.info("Parsed %s: %d NodeZero-style weakness(es)", path.name, len(nz_findings))
            return result

        # 1. Findings from tables.
        table_findings = self._findings_from_tables(tables, path.name)
        result.findings.extend(table_findings)

        # 2. Findings + sections from the body text.
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

    # ------------------------------------------------------------------ #
    # NodeZero / Horizon3 extraction
    # ------------------------------------------------------------------ #

    def _nodezero_findings(self, full_text: str, source_file: str):
        """Extract weaknesses from a NodeZero/Horizon3-style report (or return [])."""
        lines = full_text.split("\n")
        heads = []  # (line_index, title, severity, score)
        for index, line in enumerate(lines):
            match = _NZ_HEADING_RE.match(line)
            if not match:
                continue
            title = match.group("title").strip()
            low = title.lower()
            # Exclude port/service rows ("tcp/445 …") that share the trailing pattern.
            if low.startswith(("tcp/", "udp/")) or len(title) > 90:
                continue
            heads.append((index, title, match.group("sev"), match.group("score")))

        # Require a few headings before treating this as a NodeZero report, to avoid
        # mis-firing on an unrelated PDF that happens to contain one such line.
        if len(heads) < 3:
            return []

        findings = []
        for position, (line_no, title, severity, score) in enumerate(heads):
            end = heads[position + 1][0] if position + 1 < len(heads) else len(lines)
            block = lines[line_no + 1 : end]
            record: Dict[str, str] = {"title": title, "severity": severity, "cvss_score": score}
            record.update(self._nz_parse_block(block))
            findings.append(build_finding(record, source_file=source_file, source_tool="NodeZero"))
        return findings

    def _nz_parse_block(self, block: List[str]) -> Dict[str, str]:
        """Map a weakness block's bare-label sub-sections to canonical finding fields."""
        fields: Dict[str, str] = {}
        current = None
        buffer: List[str] = []

        def flush() -> None:
            if not current or not buffer:
                return
            if current == "affected":
                assets = self._nz_assets(buffer)
                if assets:
                    fields["affected"] = assets
                return
            text = "\n".join(buffer).strip()
            if not text:
                return
            existing = fields.get(current, "")
            combined = f"{existing}\n\n{text}" if existing else text
            fields[current] = combined[:_NZ_MAX_FIELD_CHARS]

        for raw in block:
            label = raw.strip().lower()
            if label in _NZ_SUBHEADINGS:
                flush()
                current = _NZ_SUBHEADINGS[label]
                buffer = []
                continue
            if current is not None:
                buffer.append(raw)
        flush()
        return fields

    @staticmethod
    def _nz_assets(rows: List[str]) -> str:
        """Extract asset identifiers (first column) from an 'Affected Assets' table."""
        assets: List[str] = []
        for row in rows:
            text = row.strip()
            # Skip the table header row.
            if not text or text.lower().startswith("asset "):
                continue
            token = text.split()[0]
            if token and token not in assets:
                assets.append(token)
            if len(assets) >= _NZ_MAX_ASSETS:
                break
        return ", ".join(assets)

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
        return sanitize_xml(" ".join(str(cell).split()))
