"""Heuristic extraction of findings from free-form text (TXT, Markdown, PDF text).

Many human-authored reports and tool text dumps follow recognizable conventions:
headings introduce findings, and labelled lines (``Severity:``, ``Remediation:`` …)
carry the structured fields. This engine splits text into finding blocks on headings,
``Title:``-style labels, or bracketed severities, parses labelled fields within each
block, and recognizes a handful of narrative section titles (Executive Summary,
Methodology, Scope, Conclusion) so they populate report metadata rather than becoming
bogus "findings".

It is deliberately conservative: anything it cannot confidently structure is left in
``preamble`` for the caller to file as an appendix, so no content is silently lost.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from ..models import Finding
from ..utils import normalize_whitespace
from .common import build_finding

# Label text (lowercased) -> canonical record key understood by ``build_finding``.
_LABELS: Dict[str, str] = {
    "title": "title", "finding": "title", "vulnerability": "title", "issue": "title",
    "name": "title", "finding name": "title", "weakness": "title",
    "severity": "severity", "risk": "severity", "rating": "severity", "risk rating": "severity",
    "cvss": "cvss_score", "cvss score": "cvss_score", "cvss base score": "cvss_score",
    "cve": "cve", "cwe": "cwe",
    "description": "description", "summary": "description", "synopsis": "description",
    "details": "description", "detail": "description", "observation": "description",
    "finding description": "description",
    "impact": "impact", "business impact": "impact", "risk description": "impact",
    "remediation": "remediation", "recommendation": "remediation",
    "recommendations": "remediation", "solution": "remediation", "mitigation": "remediation",
    "fix": "remediation", "remediation guidance": "remediation",
    "affected": "affected", "affected hosts": "affected", "affected assets": "affected",
    "affected systems": "affected", "hosts": "affected", "host": "affected",
    "asset": "affected", "assets": "affected", "url": "affected", "urls": "affected",
    "target": "affected", "targets": "affected", "location": "affected", "endpoint": "affected",
    "references": "references", "reference": "references", "links": "references",
    "see also": "references",
    "evidence": "evidence", "proof": "evidence", "poc": "evidence", "output": "evidence",
    "proof of concept": "evidence", "steps to reproduce": "evidence",
    "confidence": "confidence", "category": "category", "type": "category", "status": "status",
}

# Block titles that are narrative sections, not findings -> mapped to metadata keys.
_SECTION_TITLES: Dict[str, str] = {
    "executive summary": "executive_summary",
    "summary": "executive_summary",
    "overview": "executive_summary",
    "methodology": "methodology",
    "approach": "methodology",
    "method": "methodology",
    "scope": "scope",
    "engagement scope": "scope",
    "conclusion": "conclusion",
    "conclusions": "conclusion",
    "closing remarks": "conclusion",
}

# Inline labels that introduce a narrative section, e.g. ``Executive Summary:`` in a
# plain-text report. ``summary``/``overview`` are intentionally excluded here because
# inside a finding ``Summary:`` means the description — they only mean a section when
# used as a heading (handled via ``_SECTION_TITLES``).
_SECTION_LABEL_TRIGGERS = {
    "executive summary",
    "methodology",
    "scope",
    "engagement scope",
    "conclusion",
    "conclusions",
}

_LABEL_RE = re.compile(r"^\s*[-*]?\s*\*{0,2}([A-Za-z][A-Za-z /_]{1,28}?)\*{0,2}\s*:\s*(.*)$")
_BRACKET_SEV_RE = re.compile(
    r"^\s*\[(critical|high|medium|low|informational|info|none)\]\s*(.*)$", re.IGNORECASE
)
_FENCE_RE = re.compile(r"^\s*```")


@dataclass
class _Block:
    title: Optional[str] = None
    fields: Dict[str, List[str]] = field(default_factory=dict)
    raw_lines: List[str] = field(default_factory=list)
    current_field: Optional[str] = None

    def add_field_line(self, key: str, value: str) -> None:
        self.fields.setdefault(key, [])
        if value:
            self.fields[key].append(value)
        self.current_field = key


@dataclass
class TextExtraction:
    """Result of :func:`extract_findings_from_text`."""

    findings: List[Finding] = field(default_factory=list)
    sections: Dict[str, str] = field(default_factory=dict)
    preamble: str = ""


def extract_findings_from_text(
    text: str,
    *,
    source_file: str = "",
    source_tool: str = "",
    min_heading_level: int = 1,
) -> TextExtraction:
    """Parse free-form text into findings + recognized narrative sections."""
    heading_re = re.compile(r"^#{%d,6}\s+(.*\S)\s*$" % max(1, min_heading_level))

    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    blocks: List[_Block] = []
    preamble: List[str] = []
    current: Optional[_Block] = None
    in_fence = False
    fence_buffer: List[str] = []

    for raw in lines:
        line = raw.rstrip("\n")

        # --- fenced code blocks: capture verbatim as evidence -----------------
        if _FENCE_RE.match(line):
            if not in_fence:
                in_fence, fence_buffer = True, []
            else:
                in_fence = False
                fenced = "\n".join(fence_buffer)
                if current is not None and fenced.strip():
                    current.fields.setdefault("evidence", []).append(fenced)
                    current.raw_lines.append(fenced)
                elif fenced.strip():
                    preamble.append(fenced)
            continue
        if in_fence:
            fence_buffer.append(line)
            continue

        # --- finding boundaries ----------------------------------------------
        heading = heading_re.match(line)
        if heading:
            current = _Block(title=normalize_whitespace(heading.group(1)))
            blocks.append(current)
            continue

        bracket = _BRACKET_SEV_RE.match(line)
        if bracket:
            current = _Block(title=normalize_whitespace(bracket.group(2)) or "Finding")
            current.add_field_line("severity", bracket.group(1))
            current.current_field = None  # subsequent prose -> description
            blocks.append(current)
            continue

        label = _LABEL_RE.match(line)
        if label:
            key = label.group(1).strip().lower()
            value = label.group(2).strip()
            canonical = _LABELS.get(key)
            if canonical == "title":
                current = _Block(title=normalize_whitespace(value))
                blocks.append(current)
                continue
            if key in _SECTION_LABEL_TRIGGERS:
                # Start a narrative-section block (routed to metadata in _finalize).
                current = _Block(title=key)
                blocks.append(current)
                current.current_field = None
                if value:
                    current.raw_lines.append(value)
                continue
            if canonical:
                if current is None:
                    current = _Block(title=None)
                    blocks.append(current)
                current.add_field_line(canonical, value)
                current.raw_lines.append(line.strip())
                continue
            # Unknown label -> fall through and treat the whole line as prose.

        # --- continuation / plain prose --------------------------------------
        if current is None:
            preamble.append(line)
            continue
        target = current.current_field or "description"
        current.fields.setdefault(target, []).append(line.strip())
        current.current_field = target
        if line.strip():
            current.raw_lines.append(line.strip())

    return _finalize(blocks, preamble, source_file, source_tool)


def _finalize(
    blocks: List[_Block], preamble: List[str], source_file: str, source_tool: str
) -> TextExtraction:
    extraction = TextExtraction()

    for block in blocks:
        title_norm = (block.title or "").strip().lower().rstrip(":")
        # Narrative section?
        if title_norm in _SECTION_TITLES:
            body = _join_block_body(block)
            if not body:
                continue
            key = _SECTION_TITLES[title_norm]
            # Append if the same section appears more than once.
            if key in extraction.sections:
                extraction.sections[key] += "\n\n" + body
            else:
                extraction.sections[key] = body
            continue

        record = _block_to_record(block)
        # Require at least a title or some substantive field to count as a finding.
        if not record.get("title") and not any(
            record.get(k) for k in ("description", "severity", "impact", "remediation")
        ):
            continue
        extraction.findings.append(
            build_finding(record, source_file=source_file, source_tool=source_tool)
        )

    extraction.preamble = "\n".join(preamble).strip()
    return extraction


def _join_block_body(block: _Block) -> str:
    text = "\n".join(block.raw_lines).strip()
    return re.sub(r"\n{3,}", "\n\n", text)


def _block_to_record(block: _Block) -> Dict[str, str]:
    record: Dict[str, str] = {}
    if block.title:
        record["title"] = block.title
    for key, value_lines in block.fields.items():
        joined = "\n".join(value_lines).strip()
        joined = re.sub(r"\n{3,}", "\n\n", joined)
        if joined:
            record[key] = joined
    return record
