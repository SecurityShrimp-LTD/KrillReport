"""Template engine: branding model, branding extraction, and template management.

Public API::

    from krillreport.template_engine import (
        Branding, default_branding, TemplateManager,
        extract_branding, SUPPORTED_TEMPLATE_EXTENSIONS,
    )
"""

from __future__ import annotations

from .branding import Branding, default_branding, hex_to_rgb, make_template_id
from .extractor import SUPPORTED_TEMPLATE_EXTENSIONS, extract_branding
from .manager import DEFAULT_TEMPLATE_NAME, TemplateManager

__all__ = [
    "Branding",
    "default_branding",
    "hex_to_rgb",
    "make_template_id",
    "extract_branding",
    "SUPPORTED_TEMPLATE_EXTENSIONS",
    "TemplateManager",
    "DEFAULT_TEMPLATE_NAME",
]
