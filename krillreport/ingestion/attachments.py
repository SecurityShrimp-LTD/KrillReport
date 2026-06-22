"""Verbatim file attachments (engagement scripts, configs) → report appendices.

Unlike the registered parsers, attachments are *not* parsed into findings/hosts — they
are operator-supplied artifacts (a custom ``.sh`` harness, a config) that should appear
in the report exactly as written. Each attached file becomes one :class:`Appendix` whose
``content`` is the raw text and whose ``language`` (inferred from the extension) tells the
renderers to emit it as a monospaced code block.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List

from ..logging_config import get_logger
from ..models import Appendix

logger = get_logger(__name__)

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
    ".txt": "text", ".log": "text", ".md": "text",
}


def language_for(path: Path) -> str:
    """Best-effort syntax hint for a file (defaults to ``text`` so it still renders raw)."""
    return _LANGUAGE_BY_EXT.get(path.suffix.lower(), "text")


def build_attachment(path: Path) -> Appendix:
    """Read a file into a verbatim code :class:`Appendix` titled by its filename."""
    path = Path(path)
    content = path.read_text(encoding="utf-8", errors="replace").rstrip("\n")
    appendix = Appendix(title=path.name, content=content, language=language_for(path))
    logger.info("Attached %s as a verbatim appendix (%s)", path.name, appendix.language)
    return appendix


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
