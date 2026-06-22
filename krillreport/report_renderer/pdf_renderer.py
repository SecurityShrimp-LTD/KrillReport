"""Render a :class:`NormalizedReport` to a branded PDF via Jinja2 + WeasyPrint.

The HTML template (``templates/report.html``) carries the layout and branded CSS; this
module wires up the Jinja environment (including the prose-formatting filters), builds
the render context, and drives WeasyPrint. WeasyPrint is imported lazily so importing
this package stays cheap when only DOCX output is needed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..logging_config import get_logger
from ..models import NormalizedReport
from ..template_engine import Branding, default_branding
from .markdown_render import to_html
from .sections import build_context, image_data_uri

logger = get_logger(__name__)

_TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"


class PdfRenderer:
    """Render reports to PDF."""

    def __init__(self) -> None:
        self.env = Environment(
            loader=FileSystemLoader(str(_TEMPLATE_DIR)),
            autoescape=select_autoescape(["html", "xml"]),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.env.filters["md"] = to_html
        self.env.filters["data_uri"] = image_data_uri

    def render_html(self, report: NormalizedReport, branding: Optional[Branding] = None) -> str:
        """Render the report to an HTML string (used for PDF and web preview)."""
        branding = branding or default_branding()
        context = build_context(report, branding)
        template = self.env.get_template("report.html")
        return template.render(**context)

    def render(
        self,
        report: NormalizedReport,
        branding: Optional[Branding],
        output_path: Path,
    ) -> Path:
        """Render the report to a PDF file at ``output_path``."""
        from weasyprint import HTML  # lazy import — heavy native dependency

        branding = branding or default_branding()
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        html_str = self.render_html(report, branding)
        # base_url lets WeasyPrint resolve any relative asset URLs; images are
        # embedded as data URIs, so this is mostly a safety net.
        HTML(string=html_str, base_url=str(_TEMPLATE_DIR)).write_pdf(str(output_path))
        logger.info("Wrote PDF report: %s", output_path)
        return output_path
