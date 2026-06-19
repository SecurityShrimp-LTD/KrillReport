"""Defensive XML sanitization of a report before rendering.

Renderers (python-docx in particular) reject text containing XML-illegal control
characters. Inputs extracted from PDFs and other binary formats routinely contain them.
Rather than scatter cleaning across every ``add_run`` / template field, we make one pass
over every user-visible string in the report just before rendering, so neither renderer
can be handed an unrenderable string. ``Finding.raw`` is intentionally left untouched —
it is provenance, never written to the document.
"""

from __future__ import annotations

from typing import List

from ..models import NormalizedReport
from ..utils import sanitize_xml

_METADATA_FIELDS = (
    "client_name", "project_name", "report_title", "contact_name", "contact_email",
    "version", "classification", "executive_summary", "methodology", "conclusion",
)
_FINDING_FIELDS = (
    "title", "description", "impact", "remediation", "category", "source_tool", "cvss_vector",
)
_HOST_FIELDS = ("identifier", "hostname", "ip_address", "operating_system", "notes")
_SERVICE_FIELDS = ("protocol", "name", "product", "version", "banner")


def _clean_list(items: List[str]) -> List[str]:
    return [sanitize_xml(item) for item in items]


def sanitize_report(report: NormalizedReport) -> NormalizedReport:
    """Sanitize all user-visible strings in ``report`` in place and return it."""
    md = report.metadata
    for field in _METADATA_FIELDS:
        setattr(md, field, sanitize_xml(getattr(md, field)))
    md.scope = _clean_list(md.scope)
    md.assessors = _clean_list(md.assessors)

    for finding in report.findings:
        for field in _FINDING_FIELDS:
            setattr(finding, field, sanitize_xml(getattr(finding, field)))
        finding.affected_assets = _clean_list(finding.affected_assets)
        finding.cve = _clean_list(finding.cve)
        finding.cwe = _clean_list(finding.cwe)
        finding.tags = _clean_list(finding.tags)
        finding.source_files = _clean_list(finding.source_files)
        for evidence in finding.evidence:
            evidence.caption = sanitize_xml(evidence.caption)
            evidence.description = sanitize_xml(evidence.description)
            evidence.text = sanitize_xml(evidence.text)
        for reference in finding.references:
            reference.title = sanitize_xml(reference.title)
            reference.url = sanitize_xml(reference.url)

    for host in report.hosts:
        for field in _HOST_FIELDS:
            setattr(host, field, sanitize_xml(getattr(host, field)))
        host.tags = _clean_list(host.tags)
        for service in host.services:
            for field in _SERVICE_FIELDS:
                setattr(service, field, sanitize_xml(getattr(service, field)))

    for appendix in report.appendices:
        appendix.title = sanitize_xml(appendix.title)
        appendix.content = sanitize_xml(appendix.content)

    return report
