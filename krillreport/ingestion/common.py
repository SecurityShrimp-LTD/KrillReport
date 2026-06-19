"""Shared mapping logic: arbitrary records -> normalized :class:`Finding` / :class:`Host`.

Security tools disagree on field names for the same concept — a description might be
``description``, ``synopsis``, ``details``, or ``info``; a severity might be ``risk``,
``risk_factor``, ``criticality``, or a CVSS number. This module centralizes that
aliasing so every parser (JSON, CSV, XML, YAML, …) maps to the unified model the same
way. It also contains the recursive walker that turns a loaded JSON/YAML structure
into a :class:`ParseResult`.
"""

from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

from ..logging_config import get_logger
from ..models import (
    Confidence,
    Evidence,
    Finding,
    Host,
    Reference,
    Service,
    Severity,
)
from ..utils import coerce_float, ensure_list, normalize_whitespace
from .base import ParseResult

logger = get_logger(__name__)

# --------------------------------------------------------------------------- #
# Alias tables — ordered; first matching key wins.
# --------------------------------------------------------------------------- #

TITLE_ALIASES = (
    "title", "name", "finding", "finding_title", "vulnerability", "vuln",
    "issue", "issue_name", "plugin_name", "alert", "check", "summary",
)
SEVERITY_ALIASES = (
    "severity", "risk", "risk_factor", "criticality", "level", "priority",
    "threat", "rating", "risk_rating", "severity_level",
)
DESCRIPTION_ALIASES = (
    "description", "desc", "synopsis", "details", "detail", "body", "info",
    "finding_description", "issue_background", "background", "observation",
)
IMPACT_ALIASES = (
    "impact", "business_impact", "consequence", "issue_detail", "risk_description",
)
REMEDIATION_ALIASES = (
    "remediation", "recommendation", "recommendations", "solution", "fix",
    "mitigation", "remedy", "remediation_background", "fix_recommendation",
)
CVSS_SCORE_ALIASES = (
    "cvss_score", "cvss3_score", "cvss_base_score", "cvss_v3_base_score",
    "base_score", "cvssscore", "cvss3_base_score", "cvss", "score",
)
CVSS_VECTOR_ALIASES = (
    "cvss_vector", "cvss3_vector", "cvss_v3_vector", "vector", "cvss_vector_string",
)
CVE_ALIASES = ("cve", "cves", "cve_id", "cve_ids")
CWE_ALIASES = ("cwe", "cwe_id", "cwes")
CATEGORY_ALIASES = (
    "category", "type", "class", "family", "plugin_family", "group", "vuln_class",
)
CONFIDENCE_ALIASES = ("confidence", "certainty")
ASSET_ALIASES = (
    "host", "hosts", "asset", "assets", "target", "targets", "affected",
    "affected_hosts", "affected_assets", "url", "urls", "ip", "ips",
    "ip_address", "location", "endpoint", "affected_url",
)
REFERENCE_ALIASES = ("references", "reference", "refs", "links", "see_also", "external_references")
EVIDENCE_ALIASES = (
    "evidence", "proof", "poc", "output", "plugin_output", "request",
    "response", "payload", "exploit", "reproduction", "steps",
)
TOOL_ALIASES = ("tool", "source", "scanner", "engine", "source_tool")

# Host-specific aliases.
HOST_HOSTNAME_ALIASES = ("hostname", "host", "name", "fqdn", "dns")
HOST_IP_ALIASES = ("ip", "ip_address", "address", "ipv4", "ipaddr")
HOST_OS_ALIASES = ("os", "operating_system", "platform", "os_name")
HOST_PORT_ALIASES = ("port", "ports", "portid")

# Engagement-metadata aliases, used when a structured file carries report-level info.
METADATA_ALIASES = {
    "client_name": ("client", "client_name", "customer", "organization", "company"),
    "project_name": ("project", "project_name", "engagement", "engagement_name"),
    "report_title": ("report_title", "title", "report_name"),
    "start_date": ("start_date", "start", "begin_date", "date_start", "from"),
    "end_date": ("end_date", "end", "finish_date", "date_end", "to"),
    "version": ("version", "report_version", "revision"),
    "classification": ("classification", "tlp", "sensitivity"),
    "executive_summary": ("executive_summary", "summary", "overview"),
    "methodology": ("methodology", "method", "approach"),
}

# Keys whose value (a list of dicts) is a collection of findings / hosts.
FINDING_CONTAINER_KEYS = (
    "findings", "vulnerabilities", "vulns", "issues", "results", "alerts",
    "items", "report_items", "weaknesses",
)
HOST_CONTAINER_KEYS = ("hosts", "assets", "targets", "machines", "systems")
METADATA_CONTAINER_KEYS = ("metadata", "engagement", "report", "project", "client", "scan_info")

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_MULTI_SPLIT_RE = re.compile(r"[,;\n]+")


# --------------------------------------------------------------------------- #
# Low-level helpers
# --------------------------------------------------------------------------- #


def _lower_keys(record: Dict[str, Any]) -> Dict[str, Any]:
    """Return a copy of ``record`` with keys lowercased and stripped for matching."""
    out: Dict[str, Any] = {}
    for key, value in record.items():
        if key is None:
            continue
        out[str(key).strip().lower()] = value
    return out


def _normkey(text: str) -> str:
    """Reduce a key to alphanumerics only, so ``plugin_name``/``pluginName``/``plugin name`` all match."""
    return re.sub(r"[^a-z0-9]", "", text.lower())


def _is_empty(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str) and not value.strip():
        return True
    if isinstance(value, (list, dict)) and len(value) == 0:
        return True
    return False


def _get_alias(record_lower: Dict[str, Any], aliases: Tuple[str, ...]) -> Optional[Any]:
    """Return the value for the first alias present and non-empty.

    Matching is tolerant of separator/casing differences: a record key
    ``pluginName`` (lowercased here to ``pluginname``) matches the alias
    ``plugin_name`` because both normalize to ``pluginname``.
    """
    # First pass: exact (already-lowercased) key match — fast and unambiguous.
    for alias in aliases:
        if alias in record_lower and not _is_empty(record_lower[alias]):
            return record_lower[alias]
    # Second pass: separator-insensitive match.
    norm_map = {_normkey(k): v for k, v in record_lower.items()}
    for alias in aliases:
        value = norm_map.get(_normkey(alias))
        if value is not None and not _is_empty(value):
            return value
    return None


def split_multi(value: Any) -> List[str]:
    """Split a scalar/list value into a clean list of strings.

    Handles lists, and strings delimited by comma / semicolon / newline. Dict items
    are reduced to their most identifying value.
    """
    if value is None:
        return []
    items: List[str] = []
    for element in ensure_list(value):
        if isinstance(element, dict):
            # e.g. {"ip": "10.0.0.1"} or {"host": "web01"} or {"url": "..."}
            candidate = (
                element.get("ip")
                or element.get("host")
                or element.get("hostname")
                or element.get("url")
                or element.get("name")
                or element.get("value")
            )
            if candidate:
                items.append(str(candidate).strip())
            continue
        text = str(element).strip()
        if not text:
            continue
        # Only split scalar strings that look delimited; keep single values intact.
        if isinstance(element, str) and _MULTI_SPLIT_RE.search(text):
            items.extend(p.strip() for p in _MULTI_SPLIT_RE.split(text) if p.strip())
        else:
            items.append(text)
    # De-duplicate while preserving order.
    seen = set()
    result = []
    for item in items:
        if item.lower() not in seen:
            seen.add(item.lower())
            result.append(item)
    return result


def _extract_codes(text: str, regex: re.Pattern) -> List[str]:
    """Return upper-cased, de-duplicated CVE/CWE identifiers found in ``text``."""
    seen = set()
    out = []
    for match in regex.findall(text or ""):
        code = match.upper()
        if code not in seen:
            seen.add(code)
            out.append(code)
    return out


def _build_references(value: Any) -> List[Reference]:
    refs: List[Reference] = []
    for element in ensure_list(value):
        # A reference field may itself be a delimited string of URLs.
        if isinstance(element, str) and _MULTI_SPLIT_RE.search(element):
            for part in split_multi(element):
                ref = Reference.from_value(part)
                if ref:
                    refs.append(ref)
        else:
            ref = Reference.from_value(element)
            if ref:
                refs.append(ref)
    return refs


def _build_evidence(record_lower: Dict[str, Any]) -> List[Evidence]:
    """Collect any evidence-like fields into :class:`Evidence` blocks."""
    evidence: List[Evidence] = []
    for alias in EVIDENCE_ALIASES:
        if alias in record_lower:
            value = record_lower[alias]
            if value is None or (isinstance(value, str) and not value.strip()):
                continue
            text = value if isinstance(value, str) else _stringify(value)
            evidence.append(Evidence(caption=alias.replace("_", " ").title(), text=text.strip()))
    return evidence


def _stringify(value: Any) -> str:
    """Render a non-string value as readable text for evidence/description fields."""
    if isinstance(value, str):
        return value
    if isinstance(value, (list, tuple)):
        return "\n".join(_stringify(v) for v in value)
    if isinstance(value, dict):
        return "\n".join(f"{k}: {_stringify(v)}" for k, v in value.items())
    return str(value)


# --------------------------------------------------------------------------- #
# Record classification + builders
# --------------------------------------------------------------------------- #


def looks_like_finding(record: Dict[str, Any]) -> bool:
    """Heuristic: does this dict describe a finding/vulnerability?"""
    low = _lower_keys(record)
    has_title = any(a in low for a in TITLE_ALIASES)
    has_signal = any(
        a in low for a in (SEVERITY_ALIASES + DESCRIPTION_ALIASES + CVE_ALIASES + CVSS_SCORE_ALIASES)
    )
    return has_title and has_signal


def looks_like_host(record: Dict[str, Any]) -> bool:
    """Heuristic: does this dict describe a host/asset rather than a finding?"""
    low = _lower_keys(record)
    has_addr = any(a in low for a in (HOST_IP_ALIASES + ("hostname", "fqdn")))
    has_finding_signal = any(a in low for a in (SEVERITY_ALIASES + CVE_ALIASES + DESCRIPTION_ALIASES))
    has_host_signal = any(a in low for a in (HOST_PORT_ALIASES + HOST_OS_ALIASES + ("services",)))
    return has_addr and has_host_signal and not has_finding_signal


def build_finding(record: Dict[str, Any], *, source_file: str = "", source_tool: str = "") -> Finding:
    """Map an arbitrary record into a normalized :class:`Finding`."""
    low = _lower_keys(record)

    title = _get_alias(low, TITLE_ALIASES)
    title = normalize_whitespace(str(title)) if title else "Untitled Finding"

    description = _stringify(_get_alias(low, DESCRIPTION_ALIASES) or "").strip()
    impact = _stringify(_get_alias(low, IMPACT_ALIASES) or "").strip()
    remediation = _stringify(_get_alias(low, REMEDIATION_ALIASES) or "").strip()

    cvss_score = coerce_float(_get_alias(low, CVSS_SCORE_ALIASES))
    cvss_vector = _get_alias(low, CVSS_VECTOR_ALIASES)
    cvss_vector = str(cvss_vector).strip() if cvss_vector else None

    severity_raw = _get_alias(low, SEVERITY_ALIASES)
    if severity_raw is not None:
        severity = Severity.coerce(severity_raw)
    elif cvss_score is not None:
        severity = Severity.from_cvss(cvss_score)
    else:
        severity = Severity.MEDIUM

    # CVE / CWE: from explicit fields plus anything mentioned in the prose.
    cve = split_multi(_get_alias(low, CVE_ALIASES))
    cwe = split_multi(_get_alias(low, CWE_ALIASES))
    haystack = " ".join([title, description, impact, remediation])
    cve = _dedup_codes(cve + _extract_codes(haystack, _CVE_RE))
    cwe = _dedup_codes(cwe + _extract_codes(haystack, _CWE_RE))

    confidence = Confidence.coerce(_get_alias(low, CONFIDENCE_ALIASES))
    category = _get_alias(low, CATEGORY_ALIASES)
    category = normalize_whitespace(str(category)) if category else ""

    affected = split_multi(_get_alias(low, ASSET_ALIASES))
    references = _build_references(_get_alias(low, REFERENCE_ALIASES))
    evidence = _build_evidence(low)

    tool = _get_alias(low, TOOL_ALIASES)
    tool = str(tool).strip() if tool else source_tool

    return Finding(
        title=title,
        severity=severity,
        confidence=confidence,
        cvss_score=cvss_score,
        cvss_vector=cvss_vector,
        description=description,
        impact=impact,
        remediation=remediation,
        category=category,
        affected_assets=affected,
        evidence=evidence,
        references=references,
        cve=cve,
        cwe=cwe,
        source_tool=tool,
        source_files=[source_file] if source_file else [],
        raw=_jsonable(record),
    )


def build_host(record: Dict[str, Any]) -> Host:
    """Map an arbitrary record into a normalized :class:`Host`."""
    low = _lower_keys(record)
    hostname = _get_alias(low, HOST_HOSTNAME_ALIASES)
    ip = _get_alias(low, HOST_IP_ALIASES)
    os_name = _get_alias(low, HOST_OS_ALIASES)

    services: List[Service] = []
    raw_services = low.get("services") or low.get("ports")
    for svc in ensure_list(raw_services):
        if isinstance(svc, dict):
            svc_low = _lower_keys(svc)
            port = svc_low.get("port") or svc_low.get("portid")
            try:
                port_int = int(port) if port not in (None, "") else None
            except (TypeError, ValueError):
                port_int = None
            services.append(
                Service(
                    port=port_int,
                    protocol=str(svc_low.get("protocol") or svc_low.get("proto") or "tcp"),
                    name=str(svc_low.get("name") or svc_low.get("service") or ""),
                    product=str(svc_low.get("product") or ""),
                    version=str(svc_low.get("version") or ""),
                    banner=str(svc_low.get("banner") or ""),
                )
            )
        elif svc not in (None, ""):
            # A bare port number or "443/tcp" string.
            text = str(svc).strip()
            match = re.match(r"(\d+)(?:/(\w+))?", text)
            if match:
                services.append(
                    Service(port=int(match.group(1)), protocol=match.group(2) or "tcp")
                )

    # Flat tables often carry a single port/service per row as scalar columns
    # (e.g. CSV: ip,hostname,os,port,service). Capture that as one service.
    if not services:
        scalar_port = low.get("port") or low.get("portid")
        if scalar_port not in (None, ""):
            try:
                port_int = int(str(scalar_port).split("/")[0])
            except (TypeError, ValueError):
                port_int = None
            services.append(
                Service(
                    port=port_int,
                    protocol=str(low.get("protocol") or low.get("proto") or "tcp"),
                    name=str(low.get("service") or low.get("name") or ""),
                    product=str(low.get("product") or ""),
                    version=str(low.get("version") or ""),
                )
            )

    return Host(
        hostname=normalize_whitespace(str(hostname)) if hostname else "",
        ip_address=normalize_whitespace(str(ip)) if ip else "",
        operating_system=normalize_whitespace(str(os_name)) if os_name else "",
        services=services,
        tags=split_multi(low.get("tags")),
        notes=_stringify(low.get("notes") or "").strip(),
    )


def extract_metadata(data: Dict[str, Any]) -> Dict[str, Any]:
    """Pull engagement-metadata fields from a structured record."""
    low = _lower_keys(data)
    # Merge any nested metadata container in first, then top-level keys override.
    for container in METADATA_CONTAINER_KEYS:
        nested = low.get(container)
        if isinstance(nested, dict):
            for k, v in _lower_keys(nested).items():
                low.setdefault(k, v)

    metadata: Dict[str, Any] = {}
    for field, aliases in METADATA_ALIASES.items():
        value = _get_alias(low, aliases)
        if value is not None:
            metadata[field] = value

    scope = low.get("scope") or low.get("in_scope") or low.get("targets")
    if scope is not None:
        metadata["scope"] = split_multi(scope)
    assessors = low.get("assessors") or low.get("testers") or low.get("authors") or low.get("consultants")
    if assessors is not None:
        metadata["assessors"] = split_multi(assessors)
    return metadata


def _dedup_codes(codes: List[str]) -> List[str]:
    seen = set()
    out = []
    for code in codes:
        c = code.strip().upper()
        if c and c not in seen:
            seen.add(c)
            out.append(c)
    return out


def _jsonable(value: Any) -> Any:
    """Coerce a parsed record into JSON-serializable primitives for the ``raw`` field."""
    if isinstance(value, dict):
        return {str(k): _jsonable(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_jsonable(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


# --------------------------------------------------------------------------- #
# Structured (JSON / YAML) walker
# --------------------------------------------------------------------------- #


def parse_structured(
    data: Any, *, source_file: str = "", source_tool: str = "", parser: str = "structured"
) -> ParseResult:
    """Convert an already-loaded JSON/YAML structure into a :class:`ParseResult`.

    Strategy, in order:

    1. A top-level list -> classify each dict as finding or host.
    2. A dict -> pull metadata, then findings/hosts from known container keys.
    3. If no containers matched, treat the dict itself as a single finding when it
       looks like one; otherwise recursively search for the first lists of
       finding-like / host-like dicts anywhere in the structure.
    """
    result = ParseResult(source_file=source_file, parser=parser)

    if isinstance(data, list):
        _ingest_list(data, result, source_file, source_tool)
        return result

    if not isinstance(data, dict):
        result.warnings.append("Top-level structure is neither an object nor a list; nothing ingested.")
        return result

    # Engagement metadata.
    result.metadata.update(extract_metadata(data))

    matched_container = False
    low = _lower_keys(data)
    for key in FINDING_CONTAINER_KEYS:
        container = low.get(key)
        if isinstance(container, list) and container:
            for item in container:
                if isinstance(item, dict):
                    result.findings.append(
                        build_finding(item, source_file=source_file, source_tool=source_tool)
                    )
            matched_container = True
    for key in HOST_CONTAINER_KEYS:
        container = low.get(key)
        if isinstance(container, list) and container:
            for item in container:
                if isinstance(item, dict):
                    result.hosts.append(build_host(item))
            matched_container = True

    if matched_container:
        return result

    # No known container. Is the dict itself a finding?
    if looks_like_finding(data):
        result.findings.append(build_finding(data, source_file=source_file, source_tool=source_tool))
        return result

    # Last resort: deep-search for finding-like lists.
    found_any = _deep_search(data, result, source_file, source_tool)
    if not found_any:
        result.warnings.append("No findings or hosts recognized in structured input.")
    return result


def _ingest_list(items: List[Any], result: ParseResult, source_file: str, source_tool: str) -> None:
    for item in items:
        if not isinstance(item, dict):
            continue
        if looks_like_host(item):
            result.hosts.append(build_host(item))
        else:
            result.findings.append(
                build_finding(item, source_file=source_file, source_tool=source_tool)
            )


def _deep_search(
    data: Any, result: ParseResult, source_file: str, source_tool: str, depth: int = 0
) -> bool:
    """Recursively look for the first list of finding-like (or host-like) dicts."""
    if depth > 6:
        return False
    found = False
    if isinstance(data, dict):
        for value in data.values():
            if isinstance(value, list) and value:
                dict_items = [v for v in value if isinstance(v, dict)]
                if dict_items:
                    finding_like = [v for v in dict_items if looks_like_finding(v)]
                    host_like = [v for v in dict_items if looks_like_host(v)]
                    if finding_like and len(finding_like) >= len(dict_items) / 2:
                        for item in finding_like:
                            result.findings.append(
                                build_finding(item, source_file=source_file, source_tool=source_tool)
                            )
                        found = True
                        continue
                    if host_like and len(host_like) >= len(dict_items) / 2:
                        for item in host_like:
                            result.hosts.append(build_host(item))
                        found = True
                        continue
            # Recurse into nested dicts/lists.
            if isinstance(value, (dict, list)):
                found = _deep_search(value, result, source_file, source_tool, depth + 1) or found
    elif isinstance(data, list):
        for value in data:
            if isinstance(value, (dict, list)):
                found = _deep_search(value, result, source_file, source_tool, depth + 1) or found
    return found
