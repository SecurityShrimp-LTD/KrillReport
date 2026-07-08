"""Verbatim file attachments (engagement scripts, configs) → report appendices.

Unlike the registered parsers, attachments are *not* parsed into findings/hosts — they
are operator-supplied artifacts (a custom ``.sh`` harness, a config) that should appear
in the report exactly as written. Each attached file becomes one :class:`Appendix` whose
``content`` is the raw text and whose ``language`` (inferred from the extension) tells the
renderers to emit it as a monospaced code block.

**Markdown attachments are the exception.** A ``.md``/``.markdown`` file (e.g. a companion
``DYNAMIC_RESULTS.md`` supporting document) is *prose*, not source to reproduce verbatim —
so it is attached with **no ``language``**, which tells the renderers to format it as
Markdown (headings, tables, code fences, blockquotes) rather than dump the raw source in a
code block. Its leading ``# H1`` becomes the appendix title when present.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Iterable, List

from ..logging_config import get_logger
from ..models import Appendix

logger = get_logger(__name__)

# Markdown attachments render as formatted Markdown (not a verbatim code block).
_MARKDOWN_EXTS = {".md", ".markdown"}
_H1_RE = re.compile(r"^#\s+(.*\S)\s*$", re.MULTILINE)

# File extension -> syntax-highlight hint. Anything unknown still renders verbatim
# (as ``text``) — the point of an attachment is to reproduce it as-is.
_LANGUAGE_BY_EXT = {
    ".sh": "bash", ".bash": "bash", ".zsh": "bash", ".ksh": "bash",
    ".ps1": "powershell", ".psm1": "powershell", ".bat": "bat", ".cmd": "bat",
    ".py": "python", ".rb": "ruby", ".pl": "perl", ".php": "php",
    ".js": "javascript", ".ts": "typescript", ".go": "go", ".rs": "rust",
    ".sql": "sql", ".yaml": "yaml", ".yml": "yaml", ".json": "json",
    ".xml": "xml", ".html": "html", ".css": "css",
    ".conf": "ini", ".cfg": "ini", ".ini": "ini", ".toml": "toml",
    ".txt": "text", ".log": "text",
}

# Raster/vector image extensions that the renderers can embed directly. Reading these
# as text would produce binary garbage, so they become image appendices instead.
_IMAGE_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".svg", ".tif", ".tiff",
}


def language_for(path: Path) -> str:
    """Best-effort syntax hint for a file (defaults to ``text`` so it still renders raw)."""
    return _LANGUAGE_BY_EXT.get(path.suffix.lower(), "text")


def is_image(path: Path) -> bool:
    """True if the file should be embedded as an image rather than read as text."""
    return Path(path).suffix.lower() in _IMAGE_EXTS


def is_markdown(path: Path) -> bool:
    """True if the file is a Markdown document (rendered formatted, not verbatim)."""
    return Path(path).suffix.lower() in _MARKDOWN_EXTS


def build_attachment(path: Path) -> Appendix:
    """Turn a file into an :class:`Appendix` titled by its filename.

    Image files are embedded as pictures; Markdown files are rendered as formatted
    Markdown (with their leading ``# H1`` promoted to the appendix title); every other
    file is reproduced verbatim as a monospaced code block.
    """
    path = Path(path)
    if is_image(path):
        appendix = Appendix(title=path.name, image_path=str(path))
        logger.info("Attached %s as an image appendix", path.name)
        return appendix

    content = path.read_text(encoding="utf-8", errors="replace").strip("\n")

    if is_markdown(path):
        # No ``language`` -> the renderers format the Markdown instead of code-blocking it.
        title, body = _split_markdown_title(content, fallback=path.name)
        appendix = Appendix(title=title, content=body)
        logger.info("Attached %s as a formatted Markdown appendix", path.name)
        return appendix

    appendix = Appendix(title=path.name, content=content, language=language_for(path))
    logger.info("Attached %s as a verbatim appendix (%s)", path.name, appendix.language)
    return appendix


def _split_markdown_title(content: str, *, fallback: str) -> tuple[str, str]:
    """Promote a leading ``# H1`` to the appendix title, returning ``(title, body)``.

    Only a *leading* H1 (the first non-blank line) is consumed, so the appendix heading
    isn't duplicated by the document's own title. If there is no leading H1, the filename
    is used and the content is left untouched.
    """
    stripped = content.lstrip("\n")
    match = _H1_RE.match(stripped)
    if match:
        body = stripped[match.end():].lstrip("\n")
        return match.group(1).strip(), body
    return fallback, content


def build_attachments(paths: Iterable[Path]) -> List[Appendix]:
    """Build appendices for each attachment path, skipping unreadable files."""
    appendices: List[Appendix] = []
    for path in paths:
        path = Path(path)
        try:
            appendices.append(build_attachment(path))
        except OSError as exc:  # never abort a run over one bad attachment
            logger.warning("Could not read attachment %s: %s", path, exc)
    return appendices
