"""Dispatch branding extraction by sample file type, with override support.

Produces a fully-populated :class:`Branding` by layering, in increasing precedence:
built-in defaults -> values extracted from the sample -> explicit operator overrides.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from ..logging_config import get_logger
from .branding import Branding, default_branding, make_template_id
from .docx_extractor import extract_docx_branding
from .pdf_extractor import extract_pdf_branding

logger = get_logger(__name__)

#: File types we can extract branding from.
SUPPORTED_TEMPLATE_EXTENSIONS = {".docx", ".pdf"}


def extract_branding(
    sample_path: Path,
    dest_dir: Path,
    *,
    name: Optional[str] = None,
    overrides: Optional[Dict[str, Any]] = None,
) -> Branding:
    """Build a :class:`Branding` from a sample document.

    ``dest_dir`` is where an extracted logo is written; it should be the template's own
    directory so the asset travels with the template.
    """
    sample_path = Path(sample_path)
    dest_dir = Path(dest_dir).resolve()  # absolute so logo_path is portable
    suffix = sample_path.suffix.lower()

    extracted: Dict[str, Any] = {}
    if suffix == ".docx":
        extracted = extract_docx_branding(sample_path, dest_dir)
    elif suffix == ".pdf":
        extracted = extract_pdf_branding(sample_path, dest_dir)
    elif suffix == ".doc":
        logger.warning(
            "Legacy .doc is not supported for branding extraction; using defaults. "
            "Convert %s to .docx for style extraction.",
            sample_path.name,
        )
    else:
        logger.warning("Unsupported template sample type %s; using defaults.", suffix)

    fields = default_branding().model_dump()
    # Only override defaults with non-empty extracted values.
    fields.update({k: v for k, v in extracted.items() if v not in (None, "")})
    if overrides:
        fields.update({k: v for k, v in overrides.items() if v not in (None, "")})

    display = name or sample_path.stem
    fields["name"] = make_template_id(display)
    fields["display_name"] = display
    fields["source_sample"] = sample_path.name

    return Branding(**fields)
