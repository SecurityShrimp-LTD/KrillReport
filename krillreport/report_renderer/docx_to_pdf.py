"""Convert a ``.docx`` to PDF via a headless LibreOffice, when one is installed.

Used for **layout-template** reports: rendering the PDF from the same DOCX that was filled
into the customer's template makes both outputs match exactly (one source of truth).
LibreOffice is an *optional* dependency — :func:`libreoffice_available` lets callers fall
back to the built-in WeasyPrint layout when it is absent, so nothing breaks for users who
don't have it.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Optional

from ..logging_config import get_logger

logger = get_logger(__name__)

_CANDIDATES = ("soffice", "libreoffice")
_TIMEOUT_SECONDS = 180


def libreoffice_binary() -> Optional[str]:
    """Return the path to a LibreOffice/soffice executable, or ``None`` if not found."""
    for name in _CANDIDATES:
        found = shutil.which(name)
        if found:
            return found
    return None


def libreoffice_available() -> bool:
    return libreoffice_binary() is not None


def convert_docx_to_pdf(docx_path: Path, output_pdf: Path) -> Path:
    """Convert ``docx_path`` to ``output_pdf`` using headless LibreOffice.

    Raises :class:`RuntimeError` if LibreOffice is unavailable or the conversion fails or
    produces no file — callers catch this to fall back to another renderer.
    """
    binary = libreoffice_binary()
    if not binary:
        raise RuntimeError("LibreOffice (soffice) not found on PATH")

    docx_path = Path(docx_path)
    output_pdf = Path(output_pdf)
    output_pdf.parent.mkdir(parents=True, exist_ok=True)

    # Convert into a private temp dir, then move into place: LibreOffice names the output
    # after the input stem, which may differ from the requested filename.
    with tempfile.TemporaryDirectory(prefix="krill_lo_") as tmp:
        profile = Path(tmp) / "profile"
        cmd = [
            binary,
            "--headless",
            "--norestore",
            f"-env:UserInstallation=file://{profile}",  # isolated profile → no lock clashes
            "--convert-to",
            "pdf",
            "--outdir",
            tmp,
            str(docx_path),
        ]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=_TIMEOUT_SECONDS, check=False
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise RuntimeError(f"LibreOffice conversion failed to run: {exc}") from exc
        if result.returncode != 0:
            raise RuntimeError(
                f"LibreOffice exited {result.returncode}: {result.stderr.strip()[:300]}"
            )
        produced = Path(tmp) / (docx_path.stem + ".pdf")
        if not produced.exists():
            raise RuntimeError("LibreOffice reported success but produced no PDF")
        shutil.move(str(produced), str(output_pdf))

    logger.info("Converted %s → %s via LibreOffice", docx_path.name, output_pdf.name)
    return output_pdf
