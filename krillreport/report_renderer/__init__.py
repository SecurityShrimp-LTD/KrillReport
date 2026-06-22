"""Report rendering: branded DOCX (python-docx) and PDF (Jinja2 + WeasyPrint).

Public API::

    from krillreport.report_renderer import DocxRenderer, PdfRenderer, render_reports
"""

from __future__ import annotations

from pathlib import Path
from typing import Dict, Iterable, Optional

from ..models import NormalizedReport
from ..template_engine import Branding
from ..logging_config import get_logger
from .docx_renderer import DocxRenderer
from .docx_template_renderer import DocxTemplateRenderer
from .docx_to_pdf import convert_docx_to_pdf, libreoffice_available
from .pdf_renderer import PdfRenderer
from .sanitize import sanitize_report
from .sections import build_context

logger = get_logger(__name__)

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

    if layout_template is not None:
        return _render_with_template(
            report, branding, output_dir, basename, formats, Path(layout_template)
        )

    if "pdf" in formats:
        outputs["pdf"] = PdfRenderer().render(report, branding, output_dir / f"{basename}.pdf")
    if "docx" in formats:
        outputs["docx"] = DocxRenderer().render(report, branding, output_dir / f"{basename}.docx")
    return outputs


def _render_with_template(
    report: NormalizedReport,
    branding: Optional[Branding],
    output_dir: Path,
    basename: str,
    formats: set,
    layout_template: Path,
) -> Dict[str, Path]:
    """Layout-template path: fill the DOCX, derive the PDF from it for a matching output.

    The DOCX is rendered into the customer template. The PDF is produced by converting that
    DOCX with LibreOffice so both outputs match the template; if LibreOffice is unavailable,
    fall back to the built-in WeasyPrint layout and warn.
    """
    outputs: Dict[str, Path] = {}
    docx_path = output_dir / f"{basename}.docx"
    # A DOCX is needed as the source whenever either format is requested.
    DocxTemplateRenderer().render(report, branding, docx_path, layout_template)
    if "docx" in formats:
        outputs["docx"] = docx_path

    if "pdf" in formats:
        pdf_path = output_dir / f"{basename}.pdf"
        if libreoffice_available():
            try:
                outputs["pdf"] = convert_docx_to_pdf(docx_path, pdf_path)
            except RuntimeError as exc:
                logger.warning("Template PDF via LibreOffice failed (%s); using built-in layout.", exc)
                outputs["pdf"] = PdfRenderer().render(report, branding, pdf_path)
        else:
            logger.warning(
                "LibreOffice not found; PDF uses the built-in layout, not the template. "
                "Install LibreOffice for a template-faithful PDF."
            )
            outputs["pdf"] = PdfRenderer().render(report, branding, pdf_path)

    # Clean up the intermediate DOCX if only a PDF was requested.
    if "docx" not in formats and docx_path.exists():
        docx_path.unlink()
    return outputs
