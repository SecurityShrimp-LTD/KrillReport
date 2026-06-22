"""Nmap grepable output (``-oG`` / ``.gnmap``) ingestion.

Nmap's grepable format emits one or more ``Host:`` lines per target, tab-separated into
``Status:`` / ``Ports:`` / ``OS:`` fields. A host's facts are spread across several such
lines (status, ports, OS) that repeat the same address, so we accumulate by IP and emit a
single :class:`Host` per target — matching how the XML parser produces the Asset Inventory
(and feeding the finding↔host correlation).

A ``Ports:`` field is a comma-separated list of ``port/state/proto/owner/service/rpc/
version/`` records; only ports in an open state are kept, since those are what the
inventory cares about.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Optional

from ..logging_config import get_logger
from ..models import Host, Service
from .base import BaseParser, ParseResult, register_parser

logger = get_logger(__name__)

# ``Host: <ip> (<hostname>)`` — the hostname parens are optional and often empty.
_HOST_RE = re.compile(r"^Host:\s+(\S+)(?:\s+\((.*?)\))?$")


class _HostAcc:
    """Mutable accumulator for a host whose facts arrive across several lines."""

    __slots__ = ("ip", "hostname", "os", "status", "services")

    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.hostname = ""
        self.os = ""
        self.status = ""
        self.services: List[Service] = []


@register_parser
class GnmapParser(BaseParser):
    name = "gnmap"
    extensions = (".gnmap",)

    def can_parse(self, path: Path, sample: str) -> bool:
        if path.suffix.lower() in self.extensions:
            return True
        # Sniff grepable output saved under another name: distinctive Host:…Status/Ports.
        return "Nmap" in sample and bool(re.search(r"(?m)^Host:\s+\S+.*\t(?:Status|Ports):", sample))

    def parse(self, path: Path) -> ParseResult:
        text = path.read_text(encoding="utf-8", errors="replace")
        result = ParseResult(source_file=path.name, parser=self.name)

        accs: Dict[str, _HostAcc] = {}
        for raw in text.splitlines():
            line = raw.rstrip("\n")
            if not line.startswith("Host:"):
                continue  # skip comment/banner lines (``# Nmap …``)
            fields = line.split("\t")
            host_match = _HOST_RE.match(fields[0].strip())
            if not host_match:
                continue
            ip = host_match.group(1)
            acc = accs.setdefault(ip, _HostAcc(ip))
            if host_match.group(2):
                acc.hostname = acc.hostname or host_match.group(2).strip()

            for field in fields[1:]:
                field = field.strip()
                if field.startswith("Status:"):
                    acc.status = field[len("Status:"):].strip()
                elif field.startswith("Ports:"):
                    acc.services.extend(_parse_ports(field[len("Ports:"):]))
                elif field.startswith("OS:"):
                    acc.os = acc.os or field[len("OS:"):].strip()

        for acc in accs.values():
            if acc.status.lower() == "down" and not acc.services:
                continue  # a down host with nothing to show is noise
            result.hosts.append(
                Host(
                    hostname=acc.hostname,
                    ip_address=acc.ip,
                    operating_system=acc.os,
                    services=acc.services,
                )
            )

        if not result.hosts:
            result.warnings.append("No hosts found in grepable Nmap output.")
        logger.info("Parsed %s: %d host(s)", path.name, len(result.hosts))
        return result


def _parse_ports(ports_field: str) -> List[Service]:
    """Parse an Nmap grepable ``Ports:`` value into open-port :class:`Service` records."""
    services: List[Service] = []
    for entry in ports_field.split(","):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split("/")
        if len(parts) < 3:
            continue
        state = parts[1].strip()
        if not state.startswith("open"):  # skip closed / filtered
            continue
        port = _to_int(parts[0])
        # The version field (index 6) may itself contain "/"; rejoin the tail.
        version = "/".join(parts[6:]).strip("/ ").strip() if len(parts) > 6 else ""
        services.append(
            Service(
                port=port,
                protocol=(parts[2].strip() or "tcp"),
                name=parts[4].strip() if len(parts) > 4 else "",
                product=version,
            )
        )
    return services


def _to_int(value: str) -> Optional[int]:
    try:
        return int(value.strip())
    except (TypeError, ValueError):
        return None
