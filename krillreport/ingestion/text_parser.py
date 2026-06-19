"""Plain-text (``.txt`` / ``.log``) ingestion.

Delegates to the shared free-text engine. Recognized narrative sections become
metadata; anything the engine could not structure is preserved as an appendix so the
operator never silently loses pasted notes.
"""

from __future__ import annotations

from pathlib import Path

from ..logging_config import get_logger
from ..models import Appendix
from .base import BaseParser, ParseResult, register_parser
from .text_extract import extract_findings_from_text

logger = get_logger(__name__)

# Below this length, leftover preamble is treated as noise rather than an appendix.
_MIN_APPENDIX_CHARS = 80


@register_parser
class TextParser(BaseParser):
    name = "text"
    extensions = (".txt", ".text", ".log")

    def parse(self, path: Path) -> ParseResult:
        text = path.read_text(encoding="utf-8", errors="replace")
        result = ParseResult(source_file=path.name, parser=self.name)
        if not text.strip():
            result.warnings.append("Empty text file.")
            return result

        extraction = extract_findings_from_text(text, source_file=path.name)
        result.findings = extraction.findings
        result.metadata.update(_sections_to_metadata(extraction.sections))

        if extraction.findings:
            # Keep substantial leftover prose as a note appendix.
            if len(extraction.preamble) >= _MIN_APPENDIX_CHARS:
                result.appendices.append(
                    Appendix(title=f"Notes — {path.stem}", content=extraction.preamble)
                )
        else:
            # Nothing structured at all: import the whole file as an appendix.
            result.appendices.append(
                Appendix(title=f"Imported notes — {path.stem}", content=text.strip())
            )
            result.warnings.append(
                "No structured findings detected; content imported as an appendix."
            )
        logger.info("Parsed %s: %d finding(s)", path.name, len(result.findings))
        return result


def _sections_to_metadata(sections: dict) -> dict:
    """Map recognized narrative sections to engagement-metadata fields."""
    metadata = {}
    if "executive_summary" in sections:
        metadata["executive_summary"] = sections["executive_summary"]
    if "methodology" in sections:
        metadata["methodology"] = sections["methodology"]
    if "conclusion" in sections:
        metadata["conclusion"] = sections["conclusion"]
    if "scope" in sections:
        # Scope is a list field; split on newlines / bullets.
        lines = [
            ln.strip(" -*\t")
            for ln in sections["scope"].splitlines()
            if ln.strip(" -*\t")
        ]
        if lines:
            metadata["scope"] = lines
    return metadata
