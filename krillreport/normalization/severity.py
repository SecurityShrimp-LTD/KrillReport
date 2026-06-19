"""Severity / risk-rating helpers used during normalization.

Severity *coercion* (parsing messy inputs) lives on :class:`krillreport.models.Severity`.
This module handles the consistency pass and report-level risk posture that normalization
applies once all findings are gathered.
"""

from __future__ import annotations

from typing import Tuple

from ..models import Finding, NormalizedReport, Severity


def reconcile_severity(finding: Finding) -> None:
    """Keep a finding's severity and CVSS score mutually consistent.

    If a CVSS score is present but the severity is still at the neutral default
    (``Medium``), derive the severity from the score. We never override an explicitly
    stated severity — assessors sometimes intentionally rate risk above or below the
    raw CVSS based on business context.
    """
    if finding.cvss_score is not None and finding.severity == Severity.MEDIUM:
        derived = Severity.from_cvss(finding.cvss_score)
        if derived != Severity.MEDIUM:
            finding.severity = derived


def risk_posture(report: NormalizedReport) -> Tuple[Severity, str]:
    """Return the overall risk severity and a one-word posture label for the report.

    The posture is driven by the most severe finding present — the standard way exec
    summaries headline overall risk.
    """
    summary = report.summary()
    highest = summary.highest_severity
    labels = {
        Severity.CRITICAL: "Critical",
        Severity.HIGH: "High",
        Severity.MEDIUM: "Moderate",
        Severity.LOW: "Low",
        Severity.INFORMATIONAL: "Informational",
    }
    if summary.total_findings == 0:
        return Severity.INFORMATIONAL, "Informational"
    return highest, labels[highest]
