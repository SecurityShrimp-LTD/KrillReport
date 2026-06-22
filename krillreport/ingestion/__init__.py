"""Ingestion package: per-format parsers + a format-detecting dispatcher.

Public API::

    from krillreport.ingestion import ingest_file, ingest_paths, supported_extensions

Each parser maps its format into the shared :class:`~krillreport.models.Finding` /
:class:`~krillreport.models.Host` model via :mod:`krillreport.ingestion.common`, so
downstream code is format-agnostic.
"""

from __future__ import annotations

from .attachments import build_attachments
from .base import BaseParser, ParseResult, ParserError, register_parser
from .dispatcher import (
    detect_parser,
    ingest_file,
    ingest_paths,
    supported_extensions,
)

__all__ = [
    "BaseParser",
    "ParseResult",
    "ParserError",
    "register_parser",
    "build_attachments",
    "detect_parser",
    "ingest_file",
    "ingest_paths",
    "supported_extensions",
]
