"""Recognize a Markdown document that *is a single finding* written as a report.

A common hand-authored style writes one finding as a structured document: an ``# H1``
title, a borderless key/value metadata table (``| **Severity** | High |`` …), and
``##`` sections such as Summary, Reproduction, Impact, Root Cause, Remediation, and
Appendices. The generic free-text engine mis-reads this — every ``##`` heading becomes
a separate bogus "finding" and the metadata table is dropped.

This module detects that shape and maps it to **one** record (consumed by
``common.build_finding``): the KV table populates severity/category/status/CVSS/assets,
the Impact and Remediation sections fill those fields, and everything else (Summary,
Affected Components, Reproduction, Root Cause, Appendices) is kept as Markdown in the
description — so the renderers (which now format Markdown) reproduce the full structure,
including code blocks and tables. Nothing is discarded.

Detection is conservative: it fires only when a Severity KV row is present or several
section headings are recognized finding sections, so ordinary multi-finding Markdown
(where each ``##`` really is a distinct finding) is left to the existing engine.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from ..models import FindingStatus

# Section heading (normalized, numbering stripped) -> target finding field.
_SECTION_FIELD: Dict[str, str] = {
    "summary": "description", "overview": "description", "executive summary": "description",
    "description": "description", "details": "description", "detail": "description",
    "technical details": "description", "finding": "description", "finding details": "description",
    "background": "description", "observations": "description", "analysis": "description",
    "affected": "description", "affected components": "description", "affected assets": "description",
    "affected systems": "description", "affected hosts": "description", "scope": "description",
    "reproduction": "description", "steps to reproduce": "description", "steps": "description",
    "proof of concept": "description", "poc": "description", "walkthrough": "description",
    "exploitation": "description", "evidence": "description",
    "root cause": "description", "cause": "description",
    "impact": "impact", "business impact": "impact", "risk": "impact", "risk description": "impact",
    "remediation": "remediation", "recommendation": "remediation", "recommendations": "remediation",
    "mitigation": "remediation", "fix": "remediation", "remediation guidance": "remediation",
    "references": "references", "reference": "references", "links": "references", "see also": "references",
}

# Key/value metadata-table label (normalized) -> target finding field.
_KV_FIELD: Dict[str, str] = {
    "severity": "severity", "risk": "severity", "risk rating": "severity",
    "rating": "severity", "criticality": "severity",
    "cvss": "cvss_score", "cvss score": "cvss_score", "cvss base score": "cvss_score",
    "cvss vector": "cvss_vector",
    "category": "category", "type": "category", "class": "category", "vulnerability class": "category",
    "status": "status", "state": "status",
    "cve": "cve", "cwe": "cwe", "confidence": "confidence",
    "affected": "affected", "affected ssid": "affected", "affected components": "affected",
    "affected assets": "affected", "affected systems": "affected", "affected hosts": "affected",
    "asset": "affected", "assets": "affected", "host": "affected", "hosts": "affected",
    "target": "affected", "targets": "affected", "ssid": "affected",
    "url": "affected", "endpoint": "affected",
}

_SEP_RE = re.compile(r"^\s*\|?\s*:?-{1,}:?\s*(\|\s*:?-{1,}:?\s*)*\|?\s*$")
_FENCE_RE = re.compile(r"^\s*(```|~~~)")
_HR_RE = re.compile(r"^\s*([-*_])\1{2,}\s*$")
_NUM_RE = re.compile(r"^\d+[.)]\s*")
_H1_RE = re.compile(r"^#\s+(.*\S)\s*$")
_H2_RE = re.compile(r"^##\s+(.*\S)\s*$")


def _norm_label(text: str) -> str:
    text = re.sub(r"^\*+|\*+$", "", text.strip()).strip()
    text = text.strip(":").strip()
    return re.sub(r"\s+", " ", text).lower()


def _section_field(title: str) -> Optional[str]:
    norm = _NUM_RE.sub("", _norm_label(title))
    if norm.startswith("appendix"):
        return "description"
    return _SECTION_FIELD.get(norm)


def _split_row(line: str) -> List[str]:
    """Split a table row into cells, honouring ``\\|`` escapes and code spans."""
    line = line.strip()
    if line.startswith("|"):
        line = line[1:]
    if line.endswith("|"):
        line = line[:-1]
    cells: List[str] = []
    buf: List[str] = []
    in_code = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and i + 1 < len(line) and line[i + 1] == "|":
            buf.append("|")
            i += 2
            continue
        if ch == "`":
            in_code = not in_code
            buf.append(ch)
        elif ch == "|" and not in_code:
            cells.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
        i += 1
    cells.append("".join(buf).strip())
    return cells


def _split_doc(text: str) -> Tuple[Optional[str], List[str], List[Dict[str, object]]]:
    """Split into ``(title, preamble_lines, sections)``; ``##`` starts a section.

    Headings inside fenced code blocks are ignored so a ``# comment`` in a shell snippet
    is never mistaken for a title or section break.
    """
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    title: Optional[str] = None
    preamble: List[str] = []
    sections: List[Dict[str, object]] = []
    current: Optional[Dict[str, object]] = None
    in_fence = False
    fence_tok: Optional[str] = None

    def sink() -> List[str]:
        return current["body"] if current is not None else preamble  # type: ignore[index]

    for line in lines:
        fence = _FENCE_RE.match(line)
        if fence:
            if not in_fence:
                in_fence, fence_tok = True, fence.group(1)
            elif line.strip().startswith(fence_tok or "```"):
                in_fence = False
            sink().append(line)
            continue
        if in_fence:
            sink().append(line)
            continue

        h2 = _H2_RE.match(line)
        if h2:
            current = {"title": h2.group(1), "body": []}
            sections.append(current)
            continue
        h1 = _H1_RE.match(line)
        if h1 and title is None and current is None:
            title = h1.group(1)
            continue
        sink().append(line)
    return title, preamble, sections


def _extract_kv_table(lines: List[str]) -> Tuple[List[Tuple[str, str]], List[str]]:
    """Find the first key/value metadata table; return its pairs + the remaining lines."""
    n = len(lines)
    i = 0
    while i < n:
        if "|" in lines[i] and i + 1 < n and "|" in lines[i + 1] and _SEP_RE.match(lines[i + 1]):
            header = lines[i]
            j = i + 2
            body: List[str] = []
            while j < n and lines[j].strip() and "|" in lines[j]:
                body.append(lines[j])
                j += 1
            rows = []
            hcells = _split_row(header)
            if any(c.strip() for c in hcells):  # KV tables use an empty `| | |` header
                rows.append(hcells)
            rows.extend(_split_row(b) for b in body)
            pairs = [(r[0], r[1]) for r in rows if len(r) >= 2]
            if pairs and any(_KV_FIELD.get(_norm_label(k)) for k, _ in pairs):
                return pairs, lines[:i] + lines[j:]
            i = j  # not a metadata table — skip past and keep looking
            continue
        i += 1
    return [], lines


def _strip_hr(text: str) -> str:
    """Drop standalone horizontal-rule lines (``---``) that sit outside code fences."""
    out: List[str] = []
    in_fence = False
    fence_tok: Optional[str] = None
    for line in text.split("\n"):
        fence = _FENCE_RE.match(line)
        if fence:
            if not in_fence:
                in_fence, fence_tok = True, fence.group(1)
            elif line.strip().startswith(fence_tok or "```"):
                in_fence = False
            out.append(line)
            continue
        if not in_fence and _HR_RE.match(line):
            continue
        out.append(line)
    return "\n".join(out).strip()


# Handling/operator-note language: these blocks are evidence-file instructions for the
# tester (redact before delivery, internal-only, contains secrets), not client-facing
# finding prose, so they are dropped from the report body.
_OPERATOR_RE = re.compile(
    r"operator copy|operator[\s-]?only|operator evidence|internal[\s-]?only|"
    r"internal use|for internal|do not (?:distribute|deliver|share|send|publish)|"
    r"before deliver|before .{0,25}client|\bsanitize\b|\bredact|"
    r"live secrets?|contains? .{0,25}secrets?|strip .{0,30}before|remove .{0,30}before|"
    r"redacted version",
    re.IGNORECASE,
)


def _is_operator_note(text: str) -> bool:
    return bool(_OPERATOR_RE.search(text))


def _strip_operator_notes(text: str) -> str:
    """Drop preamble blocks (callouts/paragraphs) that are operator-handling notes."""
    blocks = re.split(r"\n\s*\n", text)
    kept = [b for b in blocks if not _is_operator_note(re.sub(r"(?m)^\s*>\s?", "", b))]
    return "\n\n".join(kept).strip()


def _assets_from_value(value: str) -> List[str]:
    """Pull the primary identifier from a KV value (the first code span, else the value)."""
    spans = re.findall(r"`([^`]+)`", value)
    if spans:
        return [spans[0].strip()]
    value = value.strip()
    return [value] if value else []


def _coerce_status(value: str) -> Optional[FindingStatus]:
    norm = _norm_label(value)
    for status in FindingStatus:
        if status.value.lower() == norm:
            return status
    mapping = {
        "verified": FindingStatus.CONFIRMED,
        "exploited": FindingStatus.CONFIRMED,
        "fixed": FindingStatus.REMEDIATED,
        "resolved": FindingStatus.REMEDIATED,
        "closed": FindingStatus.REMEDIATED,
        "accepted": FindingStatus.ACCEPTED_RISK,
        "risk accepted": FindingStatus.ACCEPTED_RISK,
        "fp": FindingStatus.FALSE_POSITIVE,
    }
    return mapping.get(norm)


def looks_like_structured_finding(text: str) -> bool:
    """True when the document is one finding written as titled sections + KV metadata."""
    _, preamble, sections = _split_doc(text)
    if not sections:
        return False
    kv_rows, _ = _extract_kv_table(preamble)
    has_severity = any(_KV_FIELD.get(_norm_label(k)) == "severity" for k, _ in kv_rows)
    recognized = sum(1 for s in sections if _section_field(str(s["title"])))
    return has_severity or recognized >= 3


def build_structured_record(text: str) -> Tuple[Dict[str, object], Optional[FindingStatus]]:
    """Map a single-finding Markdown document to a ``build_finding`` record + status."""
    title, preamble, sections = _split_doc(text)
    kv_rows, preamble_rest = _extract_kv_table(preamble)

    record: Dict[str, object] = {}
    status: Optional[FindingStatus] = None
    affected: List[str] = []
    leftover_kv: List[Tuple[str, str]] = []

    if title:
        # Drop a leading "Finding —"/"Finding:" label that names the section, not the issue.
        record["title"] = re.sub(r"^\s*finding\s*[—:\-]\s*", "", title, flags=re.IGNORECASE).strip() or title

    for key, value in kv_rows:
        field = _KV_FIELD.get(_norm_label(key))
        if field == "affected":
            affected.extend(_assets_from_value(value))
        elif field == "status":
            status = _coerce_status(value)
        elif field in ("cve", "cwe"):
            record.setdefault(field, value)
        elif field:
            record[field] = re.sub(r"^\*+|\*+$", "", value.strip()).strip("` ").strip()
        else:
            leftover_kv.append((key, value))
    if affected:
        record["affected"] = affected

    description_parts: List[str] = []
    impact_parts: List[str] = []
    remediation_parts: List[str] = []
    reference_parts: List[str] = []

    preamble_text = _strip_operator_notes(_strip_hr("\n".join(preamble_rest)))
    if preamble_text:
        description_parts.append(preamble_text)
    # Preserve KV rows we could not map (e.g. Date, Tester platform) as a small list.
    if leftover_kv:
        bullets = "\n".join(
            f"- **{_norm_label(k).title()}:** {v.strip()}" for k, v in leftover_kv
        )
        description_parts.append(bullets)

    for section in sections:
        sec_title = str(section["title"]).strip()
        body = _strip_hr("\n".join(section["body"]))  # type: ignore[arg-type]
        field = _section_field(sec_title)
        if field == "impact":
            if body:
                impact_parts.append(body)
        elif field == "remediation":
            if body:
                remediation_parts.append(body)
        elif field == "references":
            if body:
                reference_parts.append(body)
        else:
            # Keep the section heading so the structure survives in the rendered finding.
            chunk = f"### {sec_title}"
            if body:
                chunk += "\n\n" + body
            description_parts.append(chunk)

    record["description"] = "\n\n".join(p for p in description_parts if p).strip()
    if impact_parts:
        record["impact"] = "\n\n".join(impact_parts).strip()
    if remediation_parts:
        record["remediation"] = "\n\n".join(remediation_parts).strip()
    if reference_parts:
        record["references"] = "\n".join(reference_parts).strip()

    return record, status
