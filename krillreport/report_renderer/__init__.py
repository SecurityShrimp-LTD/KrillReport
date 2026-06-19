"""Report rendering: branded DOCX (python-docx) and PDF (Jinja2 + WeasyPrint).

Public API::

    from krillreport.report_renderer import DocxRenderer, PdfRenderer, render_reports
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, Optional

from ..models import NormalizedReport
from ..template_engine import Branding
from .docx_renderer import DocxRenderer
from .pdf_renderer import PdfRenderer
from .sections import build_context

__all__ = ["DocxRenderer", "PdfRenderer", "render_reports", "build_context"]


def render_reports(
    report: NormalizedReport,
    branding: Optional[Branding],
    output_dir: Path,
    basename: str,
    formats: Iterable[str] = ("pdf", "docx"),
) -> Dict[str, Path]:
    """Render the report in the requested formats; return ``{format: path}``."""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    formats = {f.lower() for f in formats}
    outputs: Dict[str, Path] = {}
    if "pdf" in formats:
        outputs["pdf"] = PdfRenderer().render(report, branding, output_dir / f"{basename}.pdf")
    if "docx" in formats:
        outputs["docx"] = DocxRenderer().render(report, branding, output_dir / f"{basename}.docx")
    return outputs
