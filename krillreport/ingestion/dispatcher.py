"""Format detection and routing.

Given a file, the dispatcher reads a short content sample and asks each registered
parser (in registration order) whether it can handle the file — extension first, with
content sniffing as a fallback for mislabeled / extensionless files. The chosen parser
produces a :class:`ParseResult`.
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterable, List, Optional, Set

from ..logging_config import get_logger

# Importing the parser modules triggers their ``@register_parser`` side effects. The
# import order here is the dispatch priority order.
from . import (  # noqa: F401
    csv_parser,
    json_parser,
    markdown_parser,
    pdf_parser,
    text_parser,
    xml_parser,
    yaml_parser,
)
from .base import PARSER_REGISTRY, BaseParser, ParseResult, ParserError

logger = get_logger(__name__)

_SAMPLE_BYTES = 8192

# Instantiate each registered parser once and reuse.
_PARSERS: List[BaseParser] = [cls() for cls in PARSER_REGISTRY]


def supported_extensions() -> Set[str]:
    """Return the set of file extensions any parser claims (for UI hints)."""
    exts: Set[str] = set()
    for parser in _PARSERS:
        exts.update(parser.extensions)
    return exts


def _read_sample(path: Path) -> str:
    """Read and decode a short prefix of the file for content sniffing."""
    try:
        with path.open("rb") as handle:
            raw = handle.read(_SAMPLE_BYTES)
        return raw.decode("utf-8", errors="replace")
    except OSError as exc:
        raise ParserError(f"Cannot read {path}: {exc}") from exc


def detect_parser(path: Path) -> Optional[BaseParser]:
    """Return the parser that should handle ``path``, or ``None`` if unsupported."""
    sample = _read_sample(path)
    for parser in _PARSERS:
        try:
            if parser.can_parse(path, sample):
                return parser
        except Exception as exc:  # a misbehaving can_parse must not break detection
            logger.debug("Parser %s.can_parse raised: %s", parser.name, exc)
    return None


def ingest_file(path: Path) -> ParseResult:
    """Parse a single file, choosing the parser automatically.

    Never raises for content problems — an unreadable or unsupported file yields a
    :class:`ParseResult` carrying a warning, so a batch ingest continues past a bad file.
    """
    path = Path(path)
    if not path.exists():
        return ParseResult(source_file=path.name, warnings=[f"File not found: {path}"])
    if not path.is_file():
        return ParseResult(source_file=path.name, warnings=[f"Not a file: {path}"])

    try:
        parser = detect_parser(path)
    except ParserError as exc:
        return ParseResult(source_file=path.name, warnings=[str(exc)])

    if parser is None:
        logger.warning("No parser matched %s (suffix %s)", path.name, path.suffix)
        return ParseResult(
            source_file=path.name,
            warnings=[f"Unsupported file type: {path.suffix or '(none)'}"],
        )

    logger.info("Ingesting %s with %s parser", path.name, parser.name)
    try:
        return parser.parse(path)
    except Exception as exc:  # defensive: a parser bug shouldn't abort the batch
        logger.exception("Parser %s crashed on %s", parser.name, path.name)
        return ParseResult(
            source_file=path.name,
            parser=parser.name,
            warnings=[f"Parser error: {exc}"],
        )


def ingest_paths(paths: Iterable[Path]) -> List[ParseResult]:
    """Ingest multiple files, returning one :class:`ParseResult` per file."""
    return [ingest_file(Path(p)) for p in paths]
