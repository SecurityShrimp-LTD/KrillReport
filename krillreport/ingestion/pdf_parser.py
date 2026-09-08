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

# The report's "Impact Details" section numbers each business impact ("2.2.1. Business
# Email Compromise CRITICAL 9.8") using the exact same shape as a real weakness heading,
# so weakness-heading scanning must start after the "Weakness Details" section title or
# those impacts get double-counted as weaknesses; they're extracted separately below as
# their own findings instead.
_NZ_SECTION_RE = re.compile(r"^\s*(?:\d+(?:\.\d+)*\.?\s+)?Weakness Details\s*$", re.IGNORECASE)
_NZ_IMPACT_SECTION_RE = re.compile(r"^\s*(?:\d+(?:\.\d+)*\.?\s+)?Impact Details\s*$", re.IGNORECASE)

# Inside an impact block, everything before this bare-line marker is the narrative
# ("Compromised 96 hosts via 97 separate attack vectors. …"); everything after is the
# list of assets/vectors that make up the attack path, with no further sub-structure.
_NZ_ATTACK_PATHS_RE = re.compile(r"^\s*Attack Paths\s*$", re.IGNORECASE)

# Asset identifiers scraped out of an impact's free-text "Attack Paths" list, which
# (unlike a weakness's "Affected Assets" table) has no column structure to key off of.
# On-prem impacts identify assets by IP/hostname/domain user; cloud impacts (Entra ID,
# M365) identify them by UPN or email instead — both forms need covering.
_NZ_IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_NZ_HOSTNAME_PAREN_RE = re.compile(r"\(([A-Za-z0-9][\w-]*(?:\.[A-Za-z0-9][\w-]*)+)\)")
_NZ_DOMAIN_USER_RE = re.compile(r"\b(?:Domain|Microsoft Entra|Entra ID)\s+User\s+([^\s(]+)", re.IGNORECASE)
_NZ_EMAIL_RE = re.compile(r"\b[\w.+-]+@[\w-]+\.[\w.-]+\b")

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
    "mitigation": "remediation",
    "mitigations": "remediation",
    "proof": "evidence",
    "proofs": "evidence",
    "references": "references",
    "affected assets": "affected",
    "affected asset": "affected",
}

# A "Downstream Impacts" table cell that lists several impacts wraps onto its own lines
# in extracted text, e.g. "Business Email Compromise (1)" sitting apart from its asset
# row; such continuation lines end in a bare "(<count>)" and aren't a new asset.
_NZ_IMPACT_CONTINUATION_RE = re.compile(r"\(\d+\)\s*$")

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
        """Extract weaknesses + business impacts from a NodeZero/Horizon3-style report."""
        lines = full_text.split("\n")

        # Scan only from the "Weakness Details" section onward: the "Impact Details"
        # section earlier in the report numbers business impacts with the identical
        # "N.N. Title SEV score" shape, and those aren't weaknesses in their own right —
        # they're extracted below as their own "Business Impact"-tagged findings instead.
        start = 0
        anchored = False
        for index, line in enumerate(lines):
            if _NZ_SECTION_RE.match(line):
                start = index + 1
                anchored = True
                break

        # Impact extraction relies on the same "Weakness Details" anchor as its upper
        # bound, so it only runs once we have one — without it, an unanchored document's
        # weakness-heading scan below (which starts at line 0) would pick up the exact
        # same headings, double-counting each impact as a weakness too.
        impact_findings = self._nodezero_impacts(lines, start, source_file) if anchored else []

        heads = []  # (line_index, title, severity, score)
        for index in range(start, len(lines)):
            match = _NZ_HEADING_RE.match(lines[index])
            if not match:
                continue
            title = match.group("title").strip()
            low = title.lower()
            # Exclude port/service rows ("tcp/445 …") that share the trailing pattern.
            if low.startswith(("tcp/", "udp/")) or len(title) > 90:
                continue
            heads.append((index, title, match.group("sev"), match.group("score")))

        # Require a few headings before treating this as a NodeZero report, to avoid
        # mis-firing on an unrelated PDF that happens to contain one such line — unless
        # we're anchored to an actual "Weakness Details" heading, which is already
        # strong enough evidence on its own (a report can have just one weakness).
        # A found "Impact Details" section is its own, equally strong anchor, so the
        # business-impact findings it already produced above are kept either way.
        if len(heads) < (1 if anchored else 3):
            return impact_findings

        findings = list(impact_findings)
        for position, (line_no, title, severity, score) in enumerate(heads):
            end = heads[position + 1][0] if position + 1 < len(heads) else len(lines)
            block = lines[line_no + 1 : end]
            record: Dict[str, str] = {"title": title, "severity": severity, "cvss_score": score}
            record.update(self._nz_parse_block(block))
            findings.append(build_finding(record, source_file=source_file, source_tool="NodeZero"))
        return findings

    def _nodezero_impacts(self, lines: List[str], end: int, source_file: str):
        """Extract business impacts from the "Impact Details" section (before ``end``).

        Each impact reuses the same "N.N. Title SEV score" heading shape as a weakness
        (see ``_NZ_HEADING_RE``), but its body is unstructured narrative text followed
        by an "Attack Paths" list rather than bare-label sub-sections, so it's parsed
        with its own, simpler block parser instead of ``_nz_parse_block``.
        """
        start = None
        for index in range(0, end):
            if _NZ_IMPACT_SECTION_RE.match(lines[index]):
                start = index + 1
                break
        if start is None:
            return []

        heads = []  # (line_index, title, severity, score)
        for index in range(start, end):
            match = _NZ_HEADING_RE.match(lines[index])
            if not match:
                continue
            title = match.group("title").strip()
            if len(title) > 90:
                continue
            heads.append((index, title, match.group("sev"), match.group("score")))
        if not heads:
            return []

        findings = []
        for position, (line_no, title, severity, score) in enumerate(heads):
            block_end = heads[position + 1][0] if position + 1 < len(heads) else end
            block = lines[line_no + 1 : block_end]
            record: Dict[str, str] = {
                "title": title,
                "severity": severity,
                "cvss_score": score,
                "category": "Business Impact",
            }
            record.update(self._nz_parse_impact_block(block))
            finding = build_finding(record, source_file=source_file, source_tool="NodeZero")
            if "business-impact" not in finding.tags:
                finding.tags.append("business-impact")
            findings.append(finding)
        return findings

    @staticmethod
    def _nz_parse_impact_block(block: List[str]) -> Dict[str, str]:
        """Split an impact block into its narrative (-> description) and Attack Paths list."""
        fields: Dict[str, str] = {}
        split_at = next((i for i, line in enumerate(block) if _NZ_ATTACK_PATHS_RE.match(line)), None)
        narrative = block[:split_at] if split_at is not None else block

        description = "\n".join(line.strip() for line in narrative if line.strip()).strip()
        if description:
            fields["description"] = description[:_NZ_MAX_FIELD_CHARS]

        if split_at is not None:
            paths = block[split_at + 1 :]
            evidence = "\n".join(line.strip() for line in paths if line.strip()).strip()
            if evidence:
                fields["evidence"] = evidence[:_NZ_MAX_FIELD_CHARS]
            assets = PDFParser._nz_impact_assets(paths)
            if assets:
                fields["affected"] = assets
        return fields

    @staticmethod
    def _nz_impact_assets(rows: List[str]) -> str:
        """Scrape IPs / hostnames / domain users out of an impact's free-text attack paths."""
        assets: List[str] = []
        for row in rows:
            for candidate in (
                *_NZ_IP_RE.findall(row),
                *_NZ_HOSTNAME_PAREN_RE.findall(row),
                *_NZ_DOMAIN_USER_RE.findall(row),
                *_NZ_EMAIL_RE.findall(row),
            ):
                if candidate not in assets:
                    assets.append(candidate)
            if len(assets) >= _NZ_MAX_ASSETS:
                break
        return ", ".join(assets[:_NZ_MAX_ASSETS])

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
            lines = self._nz_dewrap_references(buffer) if current == "references" else buffer
            text = "\n".join(lines).strip()
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
    def _nz_dewrap_references(lines: List[str]) -> List[str]:
        """Rejoin a "Title @ URL" reference line that PDF extraction wrapped mid-URL.

        Each entry is one line until the page width forces a break; the break either
        lands right after a dangling "@" (URL starts the next line) or mid-URL at a
        hyphen (the URL's own hyphen, so no space belongs at the join).
        """
        entries: List[str] = []
        for raw in lines:
            line = raw.strip()
            if not line:
                continue
            prev = entries[-1] if entries else None
            if prev is not None and prev.endswith("@"):
                entries[-1] = f"{prev} {line}"
            elif prev is not None and prev.endswith("-"):
                entries[-1] = prev + line
            else:
                entries.append(line)
        return entries

    @staticmethod
    def _nz_assets(rows: List[str]) -> str:
        """Extract asset identifiers (first column) from an 'Affected Assets' table."""
        assets: List[str] = []
        for row in rows:
            text = row.strip()
            # Skip the table header row.
            if not text or text.lower().startswith("asset "):
                continue
            # Skip a wrapped "Downstream Impacts" continuation line (its cell can list
            # several impacts, each landing on its own line rather than the asset row).
            if _NZ_IMPACT_CONTINUATION_RE.search(text):
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
