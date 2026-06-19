"""Parser base class, parse-result container, and the parser registry.

Each concrete parser subclasses :class:`BaseParser`, declares the file extensions it
owns, and is registered via :func:`register_parser`. The dispatcher walks the registry
to pick a parser for a given file. Parsers always return a :class:`ParseResult` and
record non-fatal problems in ``warnings`` rather than raising — a single malformed
input file should degrade gracefully, not abort the whole ingest.
"""

from __future__ import annotations

import abc
from pathlib import Path
from typing import Any, Dict, List, Type

from pydantic import BaseModel, Field

from ..models import Appendix, Finding, Host


class ParserError(Exception):
    """Raised for unrecoverable parse failures (e.g. a file that cannot be read)."""


class ParseResult(BaseModel):
    """Everything a single source file contributed to the report.

    ``metadata`` is a loose dict of engagement-metadata fields (``client_name`` etc.)
    that normalization merges into :class:`~krillreport.models.EngagementMetadata`.
    """

    source_file: str = ""
    parser: str = ""
    findings: List[Finding] = Field(default_factory=list)
    hosts: List[Host] = Field(default_factory=list)
    appendices: List[Appendix] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    warnings: List[str] = Field(default_factory=list)

    def extend(self, other: "ParseResult") -> None:
        """Absorb another result's content (used when one file yields several parts)."""
        self.findings.extend(other.findings)
        self.hosts.extend(other.hosts)
        self.appendices.extend(other.appendices)
        self.metadata.update(other.metadata)
        self.warnings.extend(other.warnings)

    @property
    def item_count(self) -> int:
        return len(self.findings) + len(self.hosts) + len(self.appendices)


class BaseParser(abc.ABC):
    """Abstract base for all format parsers."""

    #: Human-readable parser name, surfaced in provenance and logs.
    name: str = "base"
    #: Lowercase file extensions (with dot) this parser claims by default.
    extensions: tuple = ()

    def can_parse(self, path: Path, sample: str) -> bool:
        """Return True if this parser should handle ``path``.

        Default implementation matches on extension. Parsers override this to add
        content sniffing for extensionless or ambiguously-named files. ``sample`` is a
        short decoded prefix of the file content for sniffing.
        """
        return path.suffix.lower() in self.extensions

    @abc.abstractmethod
    def parse(self, path: Path) -> ParseResult:
        """Parse ``path`` and return a :class:`ParseResult`."""
        raise NotImplementedError


# Registry of parser classes, ordered by registration. The dispatcher tries them in
# order, so more specific parsers should register before generic fallbacks.
PARSER_REGISTRY: List[Type[BaseParser]] = []


def register_parser(cls: Type[BaseParser]) -> Type[BaseParser]:
    """Class decorator that adds a parser to the registry."""
    PARSER_REGISTRY.append(cls)
    return cls
