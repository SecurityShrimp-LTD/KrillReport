"""Small, dependency-light helpers shared across the package.

Kept deliberately generic — anything domain-specific lives in the module that owns
the concept (e.g. severity coercion is on :class:`krillreport.models.Severity`).
"""

from __future__ import annotations

import re
import unicodedata
from datetime import date, datetime
from typing import Any, Iterable, List, Optional

_SLUG_STRIP = re.compile(r"[^a-z0-9]+")
_WHITESPACE = re.compile(r"\s+")

# Date formats we attempt when parsing free-form date strings out of tool output,
# ordered most- to least-common. ISO formats are tried first via ``date.fromisoformat``.
_DATE_FORMATS = (
    "%Y-%m-%d",
    "%Y/%m/%d",
    "%d-%m-%Y",
    "%d/%m/%Y",
    "%m/%d/%Y",
    "%d %b %Y",
    "%d %B %Y",
    "%b %d, %Y",
    "%B %d, %Y",
    "%Y-%m-%dT%H:%M:%S",
)


def slugify(text: str, *, max_length: int = 80, fallback: str = "item") -> str:
    """Return a lowercase, hyphen-separated ASCII slug.

    Used for stable finding IDs and safe filenames. Non-ASCII characters are
    transliterated where possible and otherwise dropped.
    """
    if not text:
        return fallback
    normalized = unicodedata.normalize("NFKD", str(text))
    ascii_text = normalized.encode("ascii", "ignore").decode("ascii").lower()
    slug = _SLUG_STRIP.sub("-", ascii_text).strip("-")
    if max_length and len(slug) > max_length:
        slug = slug[:max_length].rstrip("-")
    return slug or fallback


def safe_filename(name: str, *, default: str = "report") -> str:
    """Return a filesystem-safe filename stem derived from ``name``."""
    cleaned = slugify(name, max_length=120, fallback=default)
    return cleaned or default


def normalize_whitespace(text: Optional[str]) -> str:
    """Collapse runs of whitespace and trim. ``None`` becomes an empty string."""
    if not text:
        return ""
    return _WHITESPACE.sub(" ", str(text)).strip()


def truncate(text: Optional[str], length: int = 280, suffix: str = "…") -> str:
    """Truncate ``text`` to ``length`` characters on a word boundary where possible."""
    if not text:
        return ""
    text = str(text).strip()
    if len(text) <= length:
        return text
    cut = text[: length - len(suffix)]
    # Prefer to break at the last space so we don't sever a word mid-token.
    if " " in cut:
        cut = cut[: cut.rfind(" ")]
    return cut.rstrip() + suffix


def ensure_list(value: Any) -> List[Any]:
    """Coerce a scalar / None / iterable into a list.

    Strings and bytes are treated as scalars (wrapped), never iterated character by
    character — a common foot-gun when normalizing tool output.
    """
    if value is None:
        return []
    if isinstance(value, (str, bytes)):
        return [value]
    if isinstance(value, (list, tuple, set)):
        return list(value)
    if isinstance(value, Iterable):
        return list(value)
    return [value]


def parse_date(value: Any) -> Optional[date]:
    """Best-effort parse of a date from a string / datetime / date.

    Returns ``None`` if the value is empty or unparseable rather than raising, since
    tool metadata is frequently missing or inconsistently formatted.
    """
    if value is None or value == "":
        return None
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip()
    if not text:
        return None
    # ISO first — handles "2026-06-19" and "2026-06-19T10:00:00" via fromisoformat.
    try:
        return date.fromisoformat(text[:10])
    except ValueError:
        pass
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).date()
        except ValueError:
            continue
    return None


def coerce_float(value: Any) -> Optional[float]:
    """Parse a float from numbers or strings (handles ``"7.5"``, ``"CVSS:7.5"``)."""
    if value is None or value == "":
        return None
    if isinstance(value, (int, float)):
        return float(value)
    match = re.search(r"-?\d+(?:\.\d+)?", str(value))
    if match:
        try:
            return float(match.group())
        except ValueError:
            return None
    return None


def first_non_empty(*values: Any) -> Optional[Any]:
    """Return the first argument that is neither ``None`` nor an empty string/list."""
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if isinstance(value, (list, tuple, dict, set)) and len(value) == 0:
            continue
        return value
    return None
