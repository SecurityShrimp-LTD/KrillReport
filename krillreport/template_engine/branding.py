"""The branding model — colours, fonts, logo and chrome for a report template.

A :class:`Branding` instance fully describes how a report should look. It is produced
either by extracting style from an uploaded sample document (see the extractors) or by
falling back to sensible defaults, and is then consumed by both renderers (DOCX reads
RGB tuples / font names; PDF reads CSS via :meth:`Branding.css_variables`).
"""

from __future__ import annotations

from typing import Dict, Optional, Tuple

from pydantic import BaseModel, ConfigDict, Field

from ..models import Severity
from ..utils import slugify


def hex_to_rgb(value: str) -> Tuple[int, int, int]:
    """Convert ``#RRGGBB`` (or ``RRGGBB``) to an ``(r, g, b)`` tuple of ints."""
    text = (value or "").strip().lstrip("#")
    if len(text) == 3:  # short form #abc
        text = "".join(ch * 2 for ch in text)
    if len(text) != 6:
        return (0, 0, 0)
    try:
        return tuple(int(text[i : i + 2], 16) for i in (0, 2, 4))  # type: ignore[return-value]
    except ValueError:
        return (0, 0, 0)


# Font family fallbacks for the PDF/CSS renderer, keyed by the configured family name's
# general style. WeasyPrint only has access to system fonts, so robust fallback stacks
# matter for portability.
_SERIF_FALLBACK = '"Times New Roman", Times, serif'
_SANS_FALLBACK = 'Helvetica, Arial, "Liberation Sans", sans-serif'
_MONO_FALLBACK = '"DejaVu Sans Mono", "Courier New", monospace'

# Heuristic mapping of common font names to a fallback stack style.
_SERIF_FONTS = {"georgia", "times", "times new roman", "garamond", "cambria", "merriweather", "pt serif"}
_MONO_FONTS = {"consolas", "courier", "courier new", "monaco", "menlo", "dejavu sans mono"}


class Branding(BaseModel):
    """Visual identity for a report template."""

    model_config = ConfigDict(extra="ignore")

    name: str = "default"  # slug / id
    display_name: str = "Default"

    # Colours (hex).
    primary_color: str = "#1F3A5F"  # headings, cover, section bars
    secondary_color: str = "#2E5E8C"  # sub-headings, accents
    accent_color: str = "#C0392B"  # call-outs / links
    text_color: str = "#222222"
    muted_color: str = "#6B7280"

    # Typography (family names).
    heading_font: str = "Helvetica"
    body_font: str = "Georgia"
    mono_font: str = "Consolas"

    # Chrome.
    logo_path: Optional[str] = None
    header_text: str = ""
    footer_text: str = ""
    cover_subtitle: str = ""
    page_size: str = "A4"  # A4 | letter

    # Optional per-severity colour overrides (hex), keyed by severity value.
    severity_colors: Dict[str, str] = Field(default_factory=dict)

    # Provenance.
    source_sample: str = ""

    # ------------------------------------------------------------------ #

    def severity_color(self, severity: Severity) -> str:
        """Resolve the colour for a severity, honouring any override."""
        return self.severity_colors.get(severity.value, severity.color)

    def primary_rgb(self) -> Tuple[int, int, int]:
        return hex_to_rgb(self.primary_color)

    def secondary_rgb(self) -> Tuple[int, int, int]:
        return hex_to_rgb(self.secondary_color)

    def accent_rgb(self) -> Tuple[int, int, int]:
        return hex_to_rgb(self.accent_color)

    def text_rgb(self) -> Tuple[int, int, int]:
        return hex_to_rgb(self.text_color)

    @staticmethod
    def _font_stack(family: str) -> str:
        key = (family or "").strip().lower()
        if key in _MONO_FONTS:
            return f'"{family}", {_MONO_FALLBACK}'
        if key in _SERIF_FONTS:
            return f'"{family}", {_SERIF_FALLBACK}'
        return f'"{family}", {_SANS_FALLBACK}'

    def heading_font_stack(self) -> str:
        return self._font_stack(self.heading_font)

    def body_font_stack(self) -> str:
        return self._font_stack(self.body_font)

    def mono_font_stack(self) -> str:
        return self._font_stack(self.mono_font)

    def css_variables(self) -> Dict[str, str]:
        """Return a dict of CSS custom-property values for the PDF HTML template."""
        return {
            "primary": self.primary_color,
            "secondary": self.secondary_color,
            "accent": self.accent_color,
            "text": self.text_color,
            "muted": self.muted_color,
            "heading-font": self.heading_font_stack(),
            "body-font": self.body_font_stack(),
            "mono-font": self.mono_font_stack(),
            "page-size": "A4" if self.page_size.lower() == "a4" else "letter",
        }


def default_branding() -> Branding:
    """A clean, professional default used when no template is selected."""
    return Branding(name="default", display_name="Default (built-in)")


def make_template_id(name: str) -> str:
    """Normalize a human name into a template id/slug."""
    return slugify(name, fallback="template")
