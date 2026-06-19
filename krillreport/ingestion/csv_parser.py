"""CSV ingestion.

Sniffs the delimiter, reads rows as dicts, and decides per-file whether the rows
describe findings or hosts based on the header columns. A CSV that mixes host and
finding columns (``host,port,severity,title``) is treated as findings, with the host
column folded into each finding's affected assets by the shared field mapper.
"""

from __future__ import annotations

import csv
import io
from pathlib import Path

from ..logging_config import get_logger
from .base import BaseParser, ParseResult, register_parser
from .common import (
    DESCRIPTION_ALIASES,
    HOST_OS_ALIASES,
    HOST_PORT_ALIASES,
    SEVERITY_ALIASES,
    TITLE_ALIASES,
    build_finding,
    build_host,
)

logger = get_logger(__name__)

# Column signals that mark a row as host-centric rather than finding-centric.
_HOST_SIGNAL_COLUMNS = set(HOST_PORT_ALIASES + HOST_OS_ALIASES + ("service", "services", "protocol"))
_FINDING_SIGNAL_COLUMNS = set(TITLE_ALIASES + SEVERITY_ALIASES + DESCRIPTION_ALIASES + ("cve", "cvss"))


@register_parser
class CSVParser(BaseParser):
    name = "csv"
    extensions = (".csv", ".tsv")

    def parse(self, path: Path) -> ParseResult:
        text = path.read_text(encoding="utf-8-sig", errors="replace")
        if not text.strip():
            return ParseResult(source_file=path.name, parser=self.name, warnings=["Empty CSV file."])

        dialect = self._sniff(text, path)
        reader = csv.DictReader(io.StringIO(text), dialect=dialect)
        if reader.fieldnames is None:
            return ParseResult(
                source_file=path.name, parser=self.name, warnings=["CSV has no header row."]
            )

        columns = {(c or "").strip().lower() for c in reader.fieldnames}
        as_hosts = self._is_host_table(columns)

        result = ParseResult(source_file=path.name, parser=self.name)
        rows = 0
        for row in reader:
            # Drop fully-empty rows and None keys produced by ragged lines.
            clean = {k: v for k, v in row.items() if k is not None and (v or "").strip()}
            if not clean:
                continue
            rows += 1
            if as_hosts:
                result.hosts.append(build_host(clean))
            else:
                result.findings.append(build_finding(clean, source_file=path.name))

        logger.info(
            "Parsed %s: %d %s row(s)", path.name, rows, "host" if as_hosts else "finding"
        )
        if rows == 0:
            result.warnings.append("CSV header present but no data rows.")
        return result

    def _sniff(self, text: str, path: Path) -> csv.Dialect:
        """Detect the delimiter; default to comma (or tab for .tsv) on failure."""
        sample = text[:4096]
        try:
            return csv.Sniffer().sniff(sample, delimiters=",\t;|")
        except csv.Error:
            class _Default(csv.excel):
                delimiter = "\t" if path.suffix.lower() == ".tsv" else ","

            return _Default()

    def _is_host_table(self, columns: set) -> bool:
        """Heuristic: host table if host signals present and finding signals absent."""
        has_addr = bool(columns & {"ip", "ip_address", "address", "hostname", "host", "fqdn"})
        has_host_signal = bool(columns & _HOST_SIGNAL_COLUMNS)
        has_finding_signal = bool(columns & _FINDING_SIGNAL_COLUMNS)
        return has_addr and has_host_signal and not has_finding_signal
