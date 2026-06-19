"""XML ingestion.

XML schemas vary wildly between tools, so this parser uses a layered strategy:

1. **Known record tags** — ``ReportItem`` (Nessus), ``issue`` (Burp Suite),
   ``result`` (OpenVAS/GVM), and generic ``vulnerability``/``finding``/``alert``
   elements are converted to dicts and mapped via the shared field mapper.
2. **Nmap** — ``host`` elements are turned into :class:`Host` objects with services.
3. **Generic fallback** — if nothing above matched, find the repeated element tag
   whose elements most look like findings (or hosts) and use those.

The parser uses a recovering parser so a slightly malformed document still yields
what it can rather than failing outright.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

from lxml import etree

from ..logging_config import get_logger
from ..models import Host, Service
from .base import BaseParser, ParseResult, register_parser
from .common import build_finding, build_host, looks_like_finding, looks_like_host

logger = get_logger(__name__)

# Element local-names that we know hold one finding each.
KNOWN_FINDING_TAGS = ("reportitem", "issue", "result", "vulnerability", "finding", "alert", "weakness")


def _localname(element) -> str:
    """Return the namespace-stripped, lowercased tag name."""
    return etree.QName(element).localname.lower()


def _element_to_dict(element) -> Dict[str, Any]:
    """Flatten an XML element into a dict of attributes + child text.

    Repeated child tags accumulate into a list (e.g. multiple ``<cve>`` elements).
    Children that themselves have children are recursed into.
    """
    record: Dict[str, Any] = {}
    for key, value in element.attrib.items():
        record[str(key).lower()] = value

    for child in element:
        if not isinstance(child.tag, str):  # skip comments / processing instructions
            continue
        tag = _localname(child)
        if len(child):
            value: Any = _element_to_dict(child)
        else:
            value = (child.text or "").strip()
        if tag in record:
            if not isinstance(record[tag], list):
                record[tag] = [record[tag]]
            record[tag].append(value)
        else:
            record[tag] = value

    text = (element.text or "").strip()
    if text and not record:
        record["value"] = text
    return record


@register_parser
class XMLParser(BaseParser):
    name = "xml"
    extensions = (".xml", ".nessus")

    def can_parse(self, path: Path, sample: str) -> bool:
        if super().can_parse(path, sample):
            return True
        return sample.lstrip().startswith("<")

    def parse(self, path: Path) -> ParseResult:
        result = ParseResult(source_file=path.name, parser=self.name)
        try:
            parser = etree.XMLParser(recover=True, huge_tree=True, resolve_entities=False)
            tree = etree.parse(str(path), parser)
            root = tree.getroot()
        except (etree.XMLSyntaxError, OSError) as exc:
            logger.warning("Failed to parse %s as XML: %s", path.name, exc)
            result.warnings.append(f"Invalid XML: {exc}")
            return result
        if root is None:
            result.warnings.append("Empty XML document.")
            return result

        # Map local-name -> list of elements, for known-tag and generic passes.
        by_tag: Dict[str, List] = defaultdict(list)
        for element in root.iter():
            if isinstance(element.tag, str):
                by_tag[_localname(element)].append(element)

        matched = False

        # 1. Nmap hosts (handled specially because of nested address/ports structure).
        if "nmaprun" in {_localname(root)} or "nmaprun" in by_tag:
            hosts = self._parse_nmap_hosts(by_tag.get("host", []))
            if hosts:
                result.hosts.extend(hosts)
                matched = True

        # 2. Known finding tags.
        for tag in KNOWN_FINDING_TAGS:
            for element in by_tag.get(tag, []):
                record = _element_to_dict(element)
                self._attach_parent_host(element, record)
                result.findings.append(build_finding(record, source_file=path.name))
                matched = True

        if matched:
            self._log(path, result)
            return result

        # 3. Generic fallback — pick the best repeated record tag.
        self._generic_fallback(by_tag, result, path)
        self._log(path, result)
        if not result.findings and not result.hosts:
            result.warnings.append("No recognizable findings or hosts in XML.")
        return result

    # ------------------------------------------------------------------ #

    def _attach_parent_host(self, element, record: Dict[str, Any]) -> None:
        """For Nessus ReportItem, fold the enclosing ReportHost name into the record."""
        if "host" in record or "affected" in record:
            return
        parent = element.getparent()
        while parent is not None:
            if _localname(parent) in ("reporthost", "host"):
                name = parent.get("name") or parent.get("ip")
                if name:
                    record["host"] = name
                return
            parent = parent.getparent()

    def _parse_nmap_hosts(self, host_elements: List) -> List[Host]:
        hosts: List[Host] = []
        for host_el in host_elements:
            ip = ""
            hostname = ""
            os_name = ""
            services: List[Service] = []
            for child in host_el:
                if not isinstance(child.tag, str):
                    continue
                tag = _localname(child)
                if tag == "address":
                    addr_type = child.get("addrtype", "")
                    if addr_type.startswith("ip") or not ip:
                        ip = child.get("addr", ip)
                elif tag == "hostnames":
                    for hn in child:
                        if isinstance(hn.tag, str) and _localname(hn) == "hostname":
                            hostname = hostname or hn.get("name", "")
                elif tag == "os":
                    for match in child:
                        if isinstance(match.tag, str) and _localname(match) == "osmatch":
                            os_name = os_name or match.get("name", "")
                elif tag == "ports":
                    for port_el in child:
                        if not isinstance(port_el.tag, str) or _localname(port_el) != "port":
                            continue
                        state = port_el.find("state")
                        if state is not None and state.get("state") not in (None, "open"):
                            continue
                        svc = port_el.find("service")
                        try:
                            port_num = int(port_el.get("portid"))
                        except (TypeError, ValueError):
                            port_num = None
                        services.append(
                            Service(
                                port=port_num,
                                protocol=port_el.get("protocol", "tcp"),
                                name=(svc.get("name") if svc is not None else "") or "",
                                product=(svc.get("product") if svc is not None else "") or "",
                                version=(svc.get("version") if svc is not None else "") or "",
                            )
                        )
            if ip or hostname:
                hosts.append(
                    Host(
                        hostname=hostname,
                        ip_address=ip,
                        operating_system=os_name,
                        services=services,
                    )
                )
        return hosts

    def _generic_fallback(self, by_tag: Dict[str, List], result: ParseResult, path: Path) -> None:
        best_finding_tag: Optional[str] = None
        best_finding_count = 0
        best_host_tag: Optional[str] = None
        best_host_count = 0

        for tag, elements in by_tag.items():
            # Only consider tags that repeat and represent compound records.
            container_elements = [e for e in elements if len(e) > 0]
            if len(container_elements) < 1:
                continue
            dicts = [_element_to_dict(e) for e in container_elements]
            finding_like = sum(1 for d in dicts if looks_like_finding(d))
            host_like = sum(1 for d in dicts if looks_like_host(d))
            if finding_like > best_finding_count:
                best_finding_count, best_finding_tag = finding_like, tag
            if host_like > best_host_count:
                best_host_count, best_host_tag = host_like, tag

        if best_finding_tag and best_finding_count >= best_host_count:
            for element in by_tag[best_finding_tag]:
                if len(element) > 0:
                    record = _element_to_dict(element)
                    if looks_like_finding(record):
                        result.findings.append(build_finding(record, source_file=path.name))
        elif best_host_tag:
            for element in by_tag[best_host_tag]:
                if len(element) > 0:
                    record = _element_to_dict(element)
                    if looks_like_host(record):
                        result.hosts.append(build_host(record))

    def _log(self, path: Path, result: ParseResult) -> None:
        logger.info(
            "Parsed %s: %d finding(s), %d host(s)",
            path.name,
            len(result.findings),
            len(result.hosts),
        )
