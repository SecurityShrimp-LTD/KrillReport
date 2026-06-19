"""Turn many :class:`ParseResult` objects into one coherent :class:`NormalizedReport`.

Responsibilities:

* **Metadata consolidation** — merge engagement metadata from every source (and any
  explicit user overrides), parsing dates and inferring the engagement type.
* **Finding deduplication & grouping** — fold findings that describe the same issue
  (shared CVE, or matching normalized title) across sources into one, unioning their
  affected assets, evidence and references.
* **Host merging** — collapse host records that refer to the same asset, unioning
  their services.
* **Severity reconciliation & stable IDs** — keep severity/CVSS consistent and ensure
  every finding has a unique slug id for cross-referencing.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional

from ..ingestion.base import ParseResult
from ..logging_config import get_logger
from ..models import (
    Appendix,
    EngagementMetadata,
    EngagementType,
    Finding,
    Host,
    NormalizedReport,
)
from ..utils import ensure_list, parse_date, slugify
from .severity import reconcile_severity

logger = get_logger(__name__)

# Scalar metadata fields whose first non-empty value wins; list fields are unioned.
_LIST_METADATA_FIELDS = ("scope", "assessors")


def normalize(
    results: Iterable[ParseResult],
    *,
    overrides: Optional[Dict[str, Any]] = None,
) -> NormalizedReport:
    """Build a single normalized report from the per-file parse results.

    ``overrides`` is a mapping of :class:`EngagementMetadata` field names to values
    supplied explicitly by the operator (CLI flags / web form); these take precedence
    over anything discovered in the input files.
    """
    results = list(results)
    all_findings: List[Finding] = []
    all_hosts: List[Host] = []
    all_appendices: List[Appendix] = []
    metadata_dicts: List[Dict[str, Any]] = []

    for result in results:
        all_findings.extend(result.findings)
        all_hosts.extend(result.hosts)
        all_appendices.extend(result.appendices)
        if result.metadata:
            metadata_dicts.append(result.metadata)

    findings = _dedupe_findings(all_findings)
    for finding in findings:
        reconcile_severity(finding)
    _assign_unique_ids(findings)

    hosts = _merge_hosts(all_hosts)
    appendices = _dedupe_appendices(all_appendices)
    metadata = _build_metadata(metadata_dicts, overrides or {}, findings)

    logger.info(
        "Normalized report: %d finding(s) from %d raw, %d host(s) from %d raw",
        len(findings),
        len(all_findings),
        len(hosts),
        len(all_hosts),
    )

    return NormalizedReport(
        metadata=metadata,
        findings=findings,
        hosts=hosts,
        appendices=appendices,
    )


def collect_warnings(results: Iterable[ParseResult]) -> List[str]:
    """Flatten parser warnings, prefixing each with its source filename."""
    warnings: List[str] = []
    for result in results:
        for warning in result.warnings:
            prefix = f"[{result.source_file}] " if result.source_file else ""
            warnings.append(f"{prefix}{warning}")
    return warnings


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #


def _dedupe_findings(findings: List[Finding]) -> List[Finding]:
    """Merge findings sharing a dedup key, preserving first-seen order."""
    index: Dict[str, Finding] = {}
    order: List[str] = []
    for finding in findings:
        key = finding.dedup_key()
        if key in index:
            index[key].merge(finding)
        else:
            index[key] = finding
            order.append(key)
    return [index[key] for key in order]


def _assign_unique_ids(findings: List[Finding]) -> None:
    """Ensure every finding has a unique, stable slug id (for cross-references)."""
    seen: set = set()
    for finding in findings:
        base = finding.id or slugify(finding.title, fallback="finding")
        candidate = base
        suffix = 2
        while candidate in seen:
            candidate = f"{base}-{suffix}"
            suffix += 1
        finding.id = candidate
        seen.add(candidate)


def _dedupe_appendices(appendices: List[Appendix]) -> List[Appendix]:
    """Drop appendices with duplicate (title, content) pairs."""
    seen: set = set()
    unique: List[Appendix] = []
    for appendix in appendices:
        key = (appendix.title.strip().lower(), appendix.content.strip())
        if key in seen:
            continue
        seen.add(key)
        unique.append(appendix)
    return unique


# --------------------------------------------------------------------------- #
# Hosts
# --------------------------------------------------------------------------- #


def _merge_hosts(hosts: List[Host]) -> List[Host]:
    """Collapse hosts referring to the same asset, unioning services.

    Hosts are keyed by IP when available (most stable), otherwise hostname. A record
    that contributes a hostname to an IP-keyed host fills in the missing hostname.
    """
    index: Dict[str, Host] = {}
    order: List[str] = []
    for host in hosts:
        key = (host.ip_address or host.hostname or host.identifier).strip().lower()
        if not key:
            continue
        if key in index:
            _merge_host_into(index[key], host)
        else:
            index[key] = host
            order.append(key)
    return [index[key] for key in order]


def _merge_host_into(target: Host, other: Host) -> None:
    target.hostname = target.hostname or other.hostname
    target.ip_address = target.ip_address or other.ip_address
    target.operating_system = target.operating_system or other.operating_system
    if not target.identifier or target.identifier == "unknown-host":
        target.identifier = other.identifier

    existing = {(s.port, s.protocol.lower()) for s in target.services}
    for service in other.services:
        sig = (service.port, service.protocol.lower())
        if sig not in existing:
            target.services.append(service)
            existing.add(sig)

    for tag in other.tags:
        if tag not in target.tags:
            target.tags.append(tag)
    if other.notes and other.notes not in target.notes:
        target.notes = "\n".join(p for p in (target.notes, other.notes) if p)


# --------------------------------------------------------------------------- #
# Metadata
# --------------------------------------------------------------------------- #


def _build_metadata(
    metadata_dicts: List[Dict[str, Any]],
    overrides: Dict[str, Any],
    findings: List[Finding],
) -> EngagementMetadata:
    merged: Dict[str, Any] = {}

    for source in metadata_dicts:
        for key, value in source.items():
            if key in _LIST_METADATA_FIELDS:
                merged.setdefault(key, [])
                for item in ensure_list(value):
                    if item not in merged[key]:
                        merged[key].append(item)
            elif key not in merged or _is_empty(merged[key]):
                merged[key] = value

    # Explicit operator overrides win outright.
    for key, value in overrides.items():
        if not _is_empty(value):
            merged[key] = value

    engagement_type = _coerce_engagement_type(merged.get("engagement_type"), merged, findings)
    client = str(merged.get("client_name", "") or "").strip()
    project = str(merged.get("project_name", "") or "").strip()
    report_title = str(merged.get("report_title", "") or "").strip() or _default_title(
        client, engagement_type
    )

    return EngagementMetadata(
        client_name=client,
        project_name=project,
        report_title=report_title,
        engagement_type=engagement_type,
        start_date=parse_date(merged.get("start_date")),
        end_date=parse_date(merged.get("end_date")),
        scope=[str(s) for s in merged.get("scope", [])],
        assessors=[str(a) for a in merged.get("assessors", [])],
        contact_name=str(merged.get("contact_name", "") or ""),
        contact_email=str(merged.get("contact_email", "") or ""),
        version=str(merged.get("version", "") or "1.0"),
        classification=str(merged.get("classification", "") or "CONFIDENTIAL"),
        executive_summary=str(merged.get("executive_summary", "") or ""),
        methodology=str(merged.get("methodology", "") or ""),
        conclusion=str(merged.get("conclusion", "") or ""),
    )


def _default_title(client: str, engagement_type: EngagementType) -> str:
    if client:
        return f"{client} {engagement_type.value}"
    return engagement_type.value


def _coerce_engagement_type(
    value: Any, merged: Dict[str, Any], findings: List[Finding]
) -> EngagementType:
    """Resolve the engagement type from explicit value or contextual heuristics."""
    if isinstance(value, EngagementType):
        return value
    if isinstance(value, str) and value.strip():
        text = value.strip().lower()
        for member in EngagementType:
            if member.value.lower() == text or member.name.lower() == text:
                return member
        # Keyword match.
        if "red" in text:
            return EngagementType.RED_TEAM
        if "web" in text or "app" in text:
            return EngagementType.WEB_APP_TEST
        if "audit" in text:
            return EngagementType.SECURITY_AUDIT
        if "vuln" in text:
            return EngagementType.VULNERABILITY_ASSESSMENT

    # Heuristic from project name / methodology / finding tags.
    context = " ".join(
        str(merged.get(k, "")) for k in ("project_name", "methodology", "report_title")
    ).lower()
    if "red team" in context:
        return EngagementType.RED_TEAM
    if "web" in context or "application" in context:
        return EngagementType.WEB_APP_TEST
    if "audit" in context:
        return EngagementType.SECURITY_AUDIT
    return EngagementType.PENETRATION_TEST


def _is_empty(value: Any) -> bool:
    if value is None:
        return True
    if isinstance(value, str) and not value.strip():
        return True
    if isinstance(value, (list, dict, tuple, set)) and len(value) == 0:
        return True
    return False
