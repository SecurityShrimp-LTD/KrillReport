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
from .docx_template_renderer import DocxTemplateRenderer
from .pdf_renderer import PdfRenderer
from .sanitize import sanitize_report
from .sections import build_context

__all__ = [
    "DocxRenderer",
    "DocxTemplateRenderer",
    "PdfRenderer",
    "render_reports",
    "build_context",
    "sanitize_report",
]


def render_reports(
    report: NormalizedReport,
    branding: Optional[Branding],
    output_dir: Path,
    basename: str,
    formats: Iterable[str] = ("pdf", "docx"),
    layout_template: Optional[Path] = None,
) -> Dict[str, Path]:
    """Render the report in the requested formats; return ``{format: path}``.

    When ``layout_template`` (a ``.docx``) is given, the DOCX is rendered *into* that
    template for layout fidelity; the PDF still uses the built-in layout (template PDF
    parity is a later phase).
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    # Strip XML-illegal control characters so neither renderer can be handed an
    # unrenderable string (common with text extracted from PDFs).
    sanitize_report(report)
    formats = {f.lower() for f in formats}
    outputs: Dict[str, Path] = {}
    if "pdf" in formats:
        outputs["pdf"] = PdfRenderer().render(report, branding, output_dir / f"{basename}.pdf")
    if "docx" in formats:
        docx_path = output_dir / f"{basename}.docx"
        if layout_template is not None:
            outputs["docx"] = DocxTemplateRenderer().render(
                report, branding, docx_path, Path(layout_template)
            )
        else:
            outputs["docx"] = DocxRenderer().render(report, branding, docx_path)
    return outputs
