"""Extract branding from a sample PDF (best-effort).

PDF carries no semantic style information, so we infer it: the most common explicit
text/fill colours (excluding black/white/grey) approximate the brand palette, the
dominant glyph font approximates the body font, and the font of the largest glyphs
approximates the heading font. Logo extraction from PDFs is unreliable across producers
and is intentionally skipped — the template falls back to no logo, which the operator
can override. Everything is guarded so a difficult PDF never raises.
"""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, Optional

import pdfplumber

from ..logging_config import get_logger

logger = get_logger(__name__)

# How many leading pages to sample (cover + first content page is plenty for style).
_MAX_PAGES = 2

# PostScript / subset font name -> friendly family.
_FONT_ALIASES = {
    "arialmt": "Arial",
    "arial": "Arial",
    "timesnewromanpsmt": "Times New Roman",
    "times": "Times New Roman",
    "timesnewroman": "Times New Roman",
    "helvetica": "Helvetica",
    "calibri": "Calibri",
    "georgia": "Georgia",
    "courier": "Courier New",
    "couriernew": "Courier New",
    "verdana": "Verdana",
}


def extract_pdf_branding(path: Path, dest_dir: Path) -> Dict[str, Any]:  # dest_dir unused (no logo)
    """Return a dict of branding fields inferred from ``path``."""
    branding: Dict[str, Any] = {}
    color_counter: Counter = Counter()
    font_chars: Counter = Counter()
    font_by_size: Dict[float, Counter] = defaultdict(Counter)

    try:
        with pdfplumber.open(str(path)) as pdf:
            for page in pdf.pages[:_MAX_PAGES]:
                _scan_page(page, color_counter, font_chars, font_by_size, branding)
    except Exception as exc:
        logger.warning("Could not read PDF template %s: %s", path.name, exc)
        return branding

    _resolve_colors(color_counter, branding)
    _resolve_fonts(font_chars, font_by_size, branding)

    logger.info("Extracted PDF branding from %s: %s", path.name, sorted(branding))
    return branding


def _scan_page(page, color_counter, font_chars, font_by_size, branding) -> None:
    # Page size from the first page only.
    if "page_size" not in branding:
        try:
            branding["page_size"] = "letter" if page.width > 602 else "A4"
        except Exception:
            pass

    for char in page.chars:
        hex_color = _color_to_hex(char.get("non_stroking_color"))
        if hex_color and _is_brand_color(hex_color):
            color_counter[hex_color] += 1
        font = _clean_font(char.get("fontname", ""))
        if font:
            font_chars[font] += 1
            size = round(float(char.get("size", 0)), 1)
            font_by_size[size][font] += 1

    # Filled rectangles (header bars / accents) weigh strongly toward primary colour.
    for rect in getattr(page, "rects", []):
        hex_color = _color_to_hex(rect.get("non_stroking_color"))
        if hex_color and _is_brand_color(hex_color):
            area = max(0.0, float(rect.get("width", 0))) * max(0.0, float(rect.get("height", 0)))
            color_counter[hex_color] += 10 if area > 5000 else 3


def _resolve_colors(counter: Counter, branding: Dict[str, Any]) -> None:
    ranked = [c for c, _ in counter.most_common()]
    if ranked:
        branding["primary_color"] = ranked[0]
    if len(ranked) > 1:
        branding["secondary_color"] = ranked[1]
    if len(ranked) > 2:
        branding["accent_color"] = ranked[2]


def _resolve_fonts(font_chars: Counter, font_by_size: Dict[float, Counter], branding: Dict[str, Any]) -> None:
    if font_chars:
        branding["body_font"] = font_chars.most_common(1)[0][0]
    if font_by_size:
        largest_size = max(font_by_size)
        heading_counter = font_by_size[largest_size]
        if heading_counter:
            branding["heading_font"] = heading_counter.most_common(1)[0][0]


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _clean_font(raw: str) -> str:
    if not raw:
        return ""
    # Strip subset prefix "ABCDEF+" and any weight/style suffix after '-' or ','.
    base = raw.split("+")[-1]
    base = re.split(r"[-,]", base)[0].strip()
    return _FONT_ALIASES.get(base.lower(), base)


def _color_to_hex(color: Any) -> Optional[str]:
    """Convert a pdfplumber colour (gray float, RGB/CMYK tuple) to ``#RRGGBB``."""
    if color is None:
        return None
    try:
        if isinstance(color, (int, float)):
            g = _clamp(color)
            return _rgb_hex(g, g, g)
        if isinstance(color, (list, tuple)):
            if len(color) == 1:
                g = _clamp(color[0])
                return _rgb_hex(g, g, g)
            if len(color) == 3:
                return _rgb_hex(_clamp(color[0]), _clamp(color[1]), _clamp(color[2]))
            if len(color) == 4:
                c, m, y, k = (_clamp(v) for v in color)
                r = round(255 * (1 - c) * (1 - k))
                g = round(255 * (1 - m) * (1 - k))
                b = round(255 * (1 - y) * (1 - k))
                return _rgb_hex(r, g, b)
    except (TypeError, ValueError):
        return None
    return None


def _clamp(value: float) -> int:
    """Map a 0-1 (or already 0-255) colour component to a 0-255 int."""
    v = float(value)
    if v <= 1.0:
        v *= 255.0
    return max(0, min(255, round(v)))


def _rgb_hex(r: int, g: int, b: int) -> str:
    return f"#{r:02X}{g:02X}{b:02X}"


def _is_brand_color(hex_value: str) -> bool:
    r, g, b = (int(hex_value[i : i + 2], 16) for i in (1, 3, 5))
    if max(r, g, b) - min(r, g, b) < 24:
        return False
    if r + g + b < 80:
        return False
    if min(r, g, b) > 232:
        return False
    return True
