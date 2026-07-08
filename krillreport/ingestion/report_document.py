"""Recognize a full multi-finding assessment report written as one Markdown document.

LLM assistants (Claude, etc.) and human analysts routinely emit a *whole report* as a
single Markdown file: an ``# H1`` title, a ``**Key:** value`` metadata block, numbered
``## N. Section`` headings (Executive Summary, Scope & Methodology, Findings, …), and —
crucially — each finding as an ``### F1 — Title (Severity)`` subsection whose body uses
bold labels (``**Location:**``, ``**Impact.**``, ``**Recommendation.**``) rather than a
metadata table.

The generic free-text engine mis-reads this shape badly: it treats *every* ``##``/``###``
heading as a finding, so section titles ("1. Executive Summary", "Findings overview")
become bogus findings, and the ``(Severity)`` suffix in a finding heading is ignored.

This module detects that shape and maps it correctly:

* each ``### … (Severity)`` subsection becomes **one** :class:`Finding`, with the severity
  read from the heading suffix and the leading ``F1``/``F1.2`` id preserved in the title
  (so the report's own cross-references — "see F9", "F1/F2" — still resolve);
* ``**Location:**`` populates affected assets, ``**Impact.**`` the impact, and
  ``**Recommendation(s).**`` the remediation; every other bold-labelled block (Dynamic
  verification, Code evidence, Severity note …) and the lead paragraph are preserved as
  Markdown in the description, so the renderers reproduce the full structure;
* Executive Summary → ``executive_summary`` and Scope/Methodology → ``methodology``
  metadata; any other non-finding ``##`` section is preserved verbatim as an appendix;
* the ``**Key:** value`` header block seeds engagement metadata (dates, scope, assessors).

Detection is conservative — it fires only when **two or more** finding headings (a heading
ending in a recognized ``(Severity)``) are present, so single-finding structured documents
(handled by :mod:`structured_finding`) and ordinary prose are left to the other engines.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from ..models import Confidence, FindingStatus
from .structured_finding import (
    _FENCE_RE,
    _HR_RE,
    _norm_label,
    _split_doc,
    _coerce_status,
)

# Severities that may terminate a finding heading, e.g. ``### F1 — Title (Medium)``.
_HEADING_SEVERITY = r"critical|high|medium|low|informational|info"

# A finding heading: any ``##``–``####`` heading ending in a parenthesised severity. The
# severity may carry a trailing qualifier — ``(Low, robustness)``, ``(Medium — arch)`` —
# so only the leading word of the final parenthesis has to be a severity.
_FINDING_HEADING_RE = re.compile(
    r"^(#{2,4})\s+(.*?)\s*\((%s)\b[^)]*\)\s*$" % _HEADING_SEVERITY,
    re.IGNORECASE,
)

# Leading finding id in a heading: ``F1``, ``F1.2``, ``V-01``, ``3.4`` … up to the
# em dash / colon / dot separator that introduces the title.
_ID_PREFIX_RE = re.compile(
    r"^\s*([A-Za-z]{0,5}-?\d+(?:\.\d+)?)\s*[—–:.)\-]\s+(.+)$"
)

_ANY_HEADING_RE = re.compile(r"^(#{1,6})\s+\S")

# A bold label starting a line: ``**Location:**``, ``**Impact.**``, ``**Code evidence
# (static).**`` — captures the label text and the trailing value on the same line.
_BOLD_LABEL_RE = re.compile(r"^\*\*(.+?)\*\*[:.]?\s*(.*)$")

# Bold-label (normalized, parenthetical qualifier and trailing punctuation stripped) ->
# target finding field. Anything not listed stays in the description verbatim.
_BODY_FIELD: Dict[str, str] = {
    "location": "affected", "locations": "affected", "affected": "affected",
    "affected assets": "affected", "affected components": "affected",
    "affected systems": "affected", "affected hosts": "affected",
    "endpoint": "affected", "endpoints": "affected", "url": "affected",
    "urls": "affected", "target": "affected", "targets": "affected",
    "impact": "impact", "business impact": "impact",
    "recommendation": "remediation", "recommendations": "remediation",
    "remediation": "remediation", "fix": "remediation", "mitigation": "remediation",
    "references": "references", "reference": "references",
    "category": "category", "confidence": "confidence", "status": "status",
    "cvss": "cvss_score", "cvss score": "cvss_score",
}

# ``## N. Section`` title (normalized, leading numbering stripped) -> metadata field.
_NUM_PREFIX_RE = re.compile(r"^\d+(?:\.\d+)*[.)]?\s+")
_METADATA_SECTION: Dict[str, str] = {
    "executive summary": "executive_summary",
    "summary": "executive_summary",
    "overview": "executive_summary",
    "scope & methodology": "methodology",
    "scope and methodology": "methodology",
    "methodology & scope": "methodology",
    "methodology": "methodology",
    "approach": "methodology",
    "scope": "methodology",
    "scope and approach": "methodology",
    "methodology and approach": "methodology",
}

# ``**Key:** value`` header labels (normalized) -> metadata handling.
_HEADER_SCOPE = {"target", "targets", "scope", "in scope", "asset", "assets", "system", "systems"}
_HEADER_ASSESSORS = {
    "reviewer", "reviewers", "assessor", "assessors", "tester", "testers",
    "author", "authors", "consultant", "consultants", "analyst", "analysts",
}
_HEADER_CLIENT = {"client", "customer", "organization", "organisation", "company"}
_HEADER_PROJECT = {"project", "engagement", "engagement name", "project name"}
_HEADER_VERSION = {"version", "report version", "revision"}
_HEADER_CLASSIFICATION = {"classification", "tlp", "sensitivity"}
_HEADER_DATES = {"date", "dates", "timeline", "engagement dates", "testing dates"}

_ISO_DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
_CODE_SPAN_RE = re.compile(r"`([^`]+)`")


def _clean_severity(text: str) -> str:
    """Normalize a heading severity token to a word ``Severity.coerce`` understands."""
    return text.strip().lower()


def _strip_hr_lines(lines: List[str]) -> List[str]:
    """Drop standalone ``---`` horizontal rules that sit outside code fences."""
    out: List[str] = []
    in_fence = False
    tok: Optional[str] = None
    for line in lines:
        fence = _FENCE_RE.match(line)
        if fence:
            if not in_fence:
                in_fence, tok = True, fence.group(1)
            elif line.strip().startswith(tok or "```"):
                in_fence = False
            out.append(line)
            continue
        if not in_fence and _HR_RE.match(line):
            continue
        out.append(line)
    return out


def _iter_finding_blocks(
    body_lines: List[str],
) -> Tuple[List[str], List[Tuple[str, str, List[str]]]]:
    """Split a section body into ``(pre_lines, finding_blocks)``.

    ``finding_blocks`` is a list of ``(severity, heading_text, block_lines)``. Headings
    inside code fences are ignored, and a non-finding heading at or above a finding's
    level ends that finding's block.
    """
    pre: List[str] = []
    blocks: List[Tuple[str, str, List[str]]] = []
    cur_body: Optional[List[str]] = None
    cur_level = 0
    in_fence = False
    tok: Optional[str] = None

    for line in body_lines:
        fence = _FENCE_RE.match(line)
        if fence:
            if not in_fence:
                in_fence, tok = True, fence.group(1)
            elif line.strip().startswith(tok or "```"):
                in_fence = False
            (cur_body if cur_body is not None else pre).append(line)
            continue
        if in_fence:
            (cur_body if cur_body is not None else pre).append(line)
            continue

        finding = _FINDING_HEADING_RE.match(line)
        if finding:
            cur_level = len(finding.group(1))
            cur_body = []
            blocks.append((_clean_severity(finding.group(3)), finding.group(2).strip(), cur_body))
            continue

        heading = _ANY_HEADING_RE.match(line)
        if heading and cur_body is not None and len(heading.group(1)) <= cur_level:
            # A non-finding heading closes the current finding; it belongs to the section.
            cur_body = None
            pre.append(line)
            continue

        (cur_body if cur_body is not None else pre).append(line)

    return pre, blocks


def _split_body_segments(body_lines: List[str]) -> List[Tuple[Optional[str], List[str]]]:
    """Split a finding body into ``(label, lines)`` segments.

    A new segment starts at a bold-label line (``**Impact.** …``); its value continues on
    following non-label, non-blank lines (a wrapped value or a bullet list that hugs the
    label). A blank line also ends the current segment, so a following prose paragraph is
    not swallowed into the preceding label. Lead prose before any label — and every other
    unlabelled paragraph — carries ``label=None``. Fenced code is captured verbatim and
    never treated as a label boundary.
    """
    segments: List[Tuple[Optional[str], List[str]]] = []
    cur_label: Optional[str] = None
    cur_lines: List[str] = []
    have = False
    in_fence = False
    tok: Optional[str] = None

    def flush() -> None:
        nonlocal cur_label, cur_lines, have
        if have:
            segments.append((cur_label, cur_lines))
        cur_label, cur_lines, have = None, [], False

    for line in body_lines:
        fence = _FENCE_RE.match(line)
        if fence:
            if not in_fence:
                in_fence, tok = True, fence.group(1)
            elif line.strip().startswith(tok or "```"):
                in_fence = False
            cur_lines.append(line)
            have = True
            continue
        if in_fence:
            cur_lines.append(line)
            have = True
            continue
        if not line.strip():
            flush()
            continue
        stripped = line.lstrip()
        is_list = stripped.startswith(("- ", "* ", "+ "))
        label = None if is_list else _BOLD_LABEL_RE.match(line)
        if label:
            flush()
            cur_label = label.group(1).strip()
            rest = label.group(2)
            cur_lines = [rest] if rest else []
            have = True
            continue
        cur_lines.append(line)
        have = True
    flush()
    return segments


def _canonical_body_field(label: str) -> Optional[str]:
    """Map a bold label (minus any ``(qualifier)`` and trailing punctuation) to a field."""
    base = re.sub(r"\(.*?\)", "", label)  # drop "(CONFIRMED)", "(static)" qualifiers
    return _BODY_FIELD.get(_norm_label(base).strip(" ."))


def _assets_from_text(value: str) -> List[str]:
    """Pull affected assets from a Location value: code spans, else the raw text."""
    spans = [s.strip() for s in _CODE_SPAN_RE.findall(value) if s.strip()]
    if spans:
        return spans
    value = value.strip()
    return [value] if value else []


def _infer_confidence(body_text: str) -> Optional[str]:
    """Read the dynamic-verification posture into an assessor-confidence value."""
    lowered = body_text.lower()
    if re.search(r"dynamic verification\s*\(confirmed\)", lowered) or "confirmed at runtime" in lowered:
        return Confidence.CONFIRMED.value
    if "static only" in lowered or "not runtime-verified" in lowered or "not runtime verified" in lowered:
        return Confidence.TENTATIVE.value
    return None


def _build_finding_record(severity: str, heading: str, body_lines: List[str]) -> Tuple[dict, Optional[FindingStatus]]:
    """Map one ``### F1 — Title (Severity)`` block to a ``build_finding`` record."""
    match = _ID_PREFIX_RE.match(heading)
    if match:
        fid, title = match.group(1).strip(), match.group(2).strip()
        display_title = f"{fid} — {title}"
    else:
        display_title = heading

    record: dict = {"title": display_title, "severity": severity}
    description_parts: List[str] = []
    impact_parts: List[str] = []
    remediation_parts: List[str] = []
    affected: List[str] = []
    references: List[str] = []
    status: Optional[FindingStatus] = None

    for label, seg_lines in _split_body_segments(_strip_hr_lines(body_lines)):
        text = "\n".join(seg_lines).strip()
        field = _canonical_body_field(label) if label else None

        if field == "affected":
            affected.extend(_assets_from_text(text))
        elif field == "impact":
            if text:
                impact_parts.append(text)
        elif field == "remediation":
            if text:
                remediation_parts.append(text)
        elif field == "references":
            if text:
                references.append(text)
        elif field == "status":
            status = _coerce_status(text) or status
        elif field in ("category", "confidence", "cvss_score"):
            if text:
                record.setdefault(field, text)
        elif label is None:
            if text:
                description_parts.append(text)
        else:
            # Unrecognized bold label (Dynamic verification, Code evidence, Severity
            # note, …): keep it in the description with its label — inline, as written —
            # so the structure survives when the renderers format the Markdown.
            description_parts.append(f"**{label}** {text}" if text else f"**{label}**")

    if affected:
        record["affected"] = affected
    if impact_parts:
        record["impact"] = "\n\n".join(impact_parts)
    if remediation_parts:
        record["remediation"] = "\n\n".join(remediation_parts)
    if references:
        record["references"] = references
    record["description"] = "\n\n".join(p for p in description_parts if p).strip()

    if "confidence" not in record:
        inferred = _infer_confidence("\n".join(body_lines))
        if inferred:
            record["confidence"] = inferred

    return record, status


def _header_metadata(preamble_lines: List[str]) -> Dict[str, object]:
    """Read the ``**Key:** value`` header block into engagement-metadata fields."""
    metadata: Dict[str, object] = {}
    for line in preamble_lines:
        match = _BOLD_LABEL_RE.match(line.strip())
        if not match:
            continue
        key = _norm_label(match.group(1))
        value = match.group(2).strip()
        if not value:
            continue
        if key in _HEADER_SCOPE:
            metadata.setdefault("scope", []).extend(_split_scope(value))  # type: ignore[union-attr]
        elif key in _HEADER_ASSESSORS:
            metadata.setdefault("assessors", []).extend(_split_scope(value))  # type: ignore[union-attr]
        elif key in _HEADER_CLIENT:
            metadata.setdefault("client_name", value)
        elif key in _HEADER_PROJECT:
            metadata.setdefault("project_name", value)
        elif key in _HEADER_VERSION:
            spans = _CODE_SPAN_RE.findall(value)
            metadata.setdefault("version", spans[0] if spans else value)
        elif key in _HEADER_CLASSIFICATION:
            metadata.setdefault("classification", value)
        elif key in _HEADER_DATES:
            dates = _ISO_DATE_RE.findall(value)
            if dates:
                metadata.setdefault("start_date", dates[0])
                metadata.setdefault("end_date", dates[-1])
    return metadata


def _split_scope(value: str) -> List[str]:
    """Split a header value into items, keeping a parenthetical qualifier attached."""
    value = re.sub(r"`([^`]+)`", r"\1", value).strip()
    # Only split on separators that sit outside parentheses (so "Foo (a, b)" stays whole).
    parts = re.split(r"[;\n]+|,(?![^(]*\))", value)
    return [p.strip() for p in parts if p.strip()]


def looks_like_finding_report(text: str) -> bool:
    """True when the document is a multi-finding report (≥2 severity-tagged findings)."""
    _, _, sections = _split_doc(text)
    count = 0
    for section in sections:
        if _FINDING_HEADING_RE.match("## " + str(section["title"])):
            count += 1
        _, blocks = _iter_finding_blocks(section["body"])  # type: ignore[arg-type]
        count += len(blocks)
        if count >= 2:
            return True
    return False


def build_report(text: str):
    """Parse a multi-finding Markdown report.

    Returns ``(report_title, metadata, findings_and_status, appendix_sections)`` where
    ``findings_and_status`` is a list of ``(record, status)`` pairs ready for
    ``build_finding``, and ``appendix_sections`` is a list of ``(title, markdown)`` for
    non-finding, non-metadata sections that should be preserved verbatim.
    """
    title, preamble, sections = _split_doc(text)
    metadata: Dict[str, object] = _header_metadata(preamble)
    if title:
        metadata["report_title"] = title

    findings: List[Tuple[dict, Optional[FindingStatus]]] = []
    appendices: List[Tuple[str, str]] = []

    for section in sections:
        sec_title = str(section["title"]).strip()
        body_lines: List[str] = list(section["body"])  # type: ignore[arg-type]

        # A section whose own heading is a finding heading is a single finding.
        heading_match = _FINDING_HEADING_RE.match("## " + sec_title)
        if heading_match:
            record, status = _build_finding_record(
                _clean_severity(heading_match.group(3)), heading_match.group(2).strip(), body_lines
            )
            findings.append((record, status))
            continue

        pre_lines, blocks = _iter_finding_blocks(body_lines)
        for severity, heading, block_lines in blocks:
            findings.append(_build_finding_record(severity, heading, block_lines))

        if blocks:
            continue  # a findings container ("## Findings"); its lead-in prose is a header

        # Non-finding section: route to metadata or preserve as an appendix.
        norm = _NUM_PREFIX_RE.sub("", _norm_label(sec_title))
        body_text = "\n".join(_strip_hr_lines(pre_lines)).strip()
        field = _METADATA_SECTION.get(norm)
        if field and body_text:
            existing = metadata.get(field)
            metadata[field] = f"{existing}\n\n{body_text}" if existing else body_text
        elif body_text:
            appendices.append((sec_title, body_text))

    return metadata.get("report_title", title), metadata, findings, appendices
