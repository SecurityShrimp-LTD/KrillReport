"""Shared render context + small presentation helpers for both renderers.

Centralizing the derived presentation values (formatted dates, severity breakdown
with percentages, overall risk posture, image data URIs) here guarantees the DOCX and
PDF outputs say the same thing — only the rendering mechanics differ between them.
"""

from __future__ import annotations

import base64
import mimetypes
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..models import NormalizedReport
from ..normalization.severity import risk_posture

# The canonical top-level section order shared by both renderers.
SECTION_ORDER = [
    "cover",
    "executive_summary",
    "scope",
    "methodology",
    "findings_summary",
    "findings",
    "assets",
    "conclusion",
    "appendices",
]


def format_date(value: Optional[date]) -> str:
    """Render a date as e.g. ``04 May 2026``; empty dates become an en dash."""
    if value is None:
        return "—"
    if isinstance(value, datetime):
        value = value.date()
    return value.strftime("%d %b %Y")


def date_range(start: Optional[date], end: Optional[date]) -> str:
    if start and end:
        return f"{format_date(start)} – {format_date(end)}"
    if start:
        return format_date(start)
    if end:
        return format_date(end)
    return "—"


def image_data_uri(path: Optional[str]) -> Optional[str]:
    """Read an image file and return a ``data:`` URI, or ``None`` if unavailable.

    Used so the PDF renderer embeds the logo / evidence screenshots without depending
    on file-path resolution at render time.
    """
    if not path:
        return None
    file_path = Path(path)
    if not file_path.exists() or not file_path.is_file():
        return None
    mime, _ = mimetypes.guess_type(str(file_path))
    if mime is None or not mime.startswith("image/"):
        return None
    try:
        encoded = base64.b64encode(file_path.read_bytes()).decode("ascii")
    except OSError:
        return None
    return f"data:{mime};base64,{encoded}"


def severity_rows(report: NormalizedReport, branding) -> List[Dict[str, Any]]:
    """Severity breakdown rows with counts, colours and percentages for charts/tables."""
    summary = report.summary()
    total = summary.total_findings or 1
    rows: List[Dict[str, Any]] = []
    for entry in summary.by_severity:
        rows.append(
            {
                "label": entry.severity.value,
                "severity": entry.severity,
                "count": entry.count,
                "color": branding.severity_color(entry.severity),
                "pct": round(entry.count / total * 100, 1),
            }
        )
    return rows


def build_context(report: NormalizedReport, branding) -> Dict[str, Any]:
    """Assemble the full presentation context consumed by the renderers."""
    metadata = report.metadata
    summary = report.summary()
    posture_sev, posture_label = risk_posture(report)

    findings = report.sorted_findings()
    # Number findings for stable cross-referencing (Finding 1, 2, …).
    numbered = [(idx + 1, finding) for idx, finding in enumerate(findings)]

    return {
        "report": report,
        "branding": branding,
        "metadata": metadata,
        "summary": summary,
        "title": metadata.report_title,
        "client": metadata.client_name,
        "engagement_type": metadata.engagement_type.value,
        "classification": metadata.classification,
        "version": metadata.version,
        "date_range": date_range(metadata.start_date, metadata.end_date),
        "generated": format_date(report.generated_at.date()),
        "assessors": ", ".join(metadata.assessors),
        "scope": metadata.scope,
        "posture_label": posture_label,
        "posture_color": branding.severity_color(posture_sev),
        "severity_rows": severity_rows(report, branding),
        "findings": findings,
        "numbered_findings": numbered,
        "hosts": report.hosts,
        "appendices": report.appendices,
        "has_findings": bool(findings),
        "has_hosts": bool(report.hosts),
        "logo_uri": image_data_uri(branding.logo_path),
    }
