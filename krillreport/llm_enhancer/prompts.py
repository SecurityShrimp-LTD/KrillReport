"""Prompt builders for LLM enhancement, plus deterministic offline fallbacks.

Two parallel paths share this module:

* **LLM path** — :func:`narrative_prompt` / :func:`finding_prompt` produce ``(system, user)``
  message pairs that instruct a model to write or polish prose from the structured facts.
* **Offline / fallback path** — the ``fallback_*`` functions synthesize professional,
  factual prose directly from the data, with no model. These are used by the offline
  provider and whenever an LLM call is unavailable or fails, so a report always has
  readable narrative sections.

Both paths are grounded strictly in the structured finding data — neither invents
vulnerabilities, CVEs, or affected hosts that were not ingested.
"""

from __future__ import annotations

from typing import List, Tuple

from ..models import Finding, NormalizedReport, Severity
from ..normalization.severity import risk_posture

# Section markers used by the combined per-finding prompt/response.
DESCRIPTION_MARK = "### DESCRIPTION"
IMPACT_MARK = "### IMPACT"
REMEDIATION_MARK = "### REMEDIATION"

SYSTEM_PROMPT = (
    "You are a senior penetration tester and technical writer producing a client-facing "
    "security assessment report. Write clear, concise, factual, professional prose. "
    "Crucially: do not invent vulnerabilities, CVEs, hosts, or facts that are not provided "
    "in the input — only rephrase, expand on, and professionally frame what you are given. "
    "Do not use marketing language or hyperbole. Output only the requested prose: no "
    "preambles like 'Here is', no markdown headers, and no bullet characters unless asked."
)


# --------------------------------------------------------------------------- #
# LLM prompts
# --------------------------------------------------------------------------- #


def narrative_prompt(kind: str, existing: str, report: NormalizedReport) -> Tuple[str, str]:
    """Build a ``(system, user)`` prompt for a report-level narrative section."""
    summary = report.summary()
    _, posture = risk_posture(report)
    metadata = report.metadata
    breakdown = ", ".join(
        f"{row.count} {row.severity.value.lower()}" for row in summary.by_severity if row.count
    ) or "no findings"
    top = "; ".join(
        f"{f.title} ({f.severity.value})" for f in report.sorted_findings()[:5]
    ) or "none"

    facts = (
        f"Engagement type: {metadata.engagement_type.value}\n"
        f"Client: {metadata.client_name or 'the client'}\n"
        f"Overall risk posture: {posture}\n"
        f"Findings: {summary.total_findings} total ({breakdown})\n"
        f"Most significant findings: {top}\n"
        f"In-scope targets: {', '.join(metadata.scope) or 'as agreed with the client'}\n"
    )

    if kind == "executive_summary":
        instruction = (
            "Write a 2-3 paragraph executive summary for a non-technical audience. "
            "State the engagement purpose, summarize the overall risk and the most "
            "significant issues, and end with a high-level call to action."
        )
    elif kind == "methodology":
        instruction = (
            "Write a 1-2 paragraph methodology section describing, in general terms, a "
            "professional, standards-aligned approach for this engagement type "
            "(reconnaissance, enumeration, exploitation/validation, and reporting)."
        )
    elif kind == "conclusion":
        instruction = (
            "Write a 1-2 paragraph conclusion summarizing the security posture and the "
            "value of remediating the identified issues in priority order."
        )
    else:  # pragma: no cover - guarded by caller
        instruction = "Write a concise professional paragraph."

    polish = (
        f"\n\nAn existing draft is provided; improve its clarity and professionalism while "
        f"preserving its facts:\n---\n{existing.strip()}\n---"
        if existing and existing.strip()
        else ""
    )

    user = f"{instruction}\n\nFacts:\n{facts}{polish}"
    return SYSTEM_PROMPT, user


def finding_prompt(finding: Finding) -> Tuple[str, str]:
    """Build a combined ``(system, user)`` prompt covering a finding's three prose fields."""
    facts = (
        f"Title: {finding.title}\n"
        f"Severity: {finding.severity.value}\n"
        f"CVSS: {finding.cvss_score if finding.cvss_score is not None else 'n/a'}\n"
        f"CVE: {', '.join(finding.cve) or 'none'}\n"
        f"CWE: {', '.join(finding.cwe) or 'none'}\n"
        f"Affected assets: {', '.join(finding.affected_assets) or 'not specified'}\n"
        f"Existing description: {finding.description.strip() or '(none)'}\n"
        f"Existing impact: {finding.impact.strip() or '(none)'}\n"
        f"Existing remediation: {finding.remediation.strip() or '(none)'}\n"
    )
    instruction = (
        "Using only the facts below, write three prose sections for this security finding. "
        "Improve any existing text and fill in what is missing, but never invent specifics "
        "(versions, hosts, CVEs) not given. Return the three sections in this exact format, "
        "each header on its own line:\n"
        f"{DESCRIPTION_MARK}\n<one short paragraph explaining the issue>\n"
        f"{IMPACT_MARK}\n<one short paragraph on business/technical impact>\n"
        f"{REMEDIATION_MARK}\n<one short paragraph of concrete remediation guidance>"
    )
    return SYSTEM_PROMPT, f"{instruction}\n\nFacts:\n{facts}"


def parse_finding_response(text: str) -> dict:
    """Parse a combined finding response into ``{description, impact, remediation}``."""
    result = {"description": "", "impact": "", "remediation": ""}
    if not text:
        return result
    current = None
    buffers: dict = {"description": [], "impact": [], "remediation": []}
    for line in text.splitlines():
        stripped = line.strip()
        upper = stripped.upper()
        if upper.startswith(DESCRIPTION_MARK):
            current = "description"
            continue
        if upper.startswith(IMPACT_MARK):
            current = "impact"
            continue
        if upper.startswith(REMEDIATION_MARK):
            current = "remediation"
            continue
        if current:
            buffers[current].append(line)
    for key, lines in buffers.items():
        result[key] = "\n".join(lines).strip()
    return result


# --------------------------------------------------------------------------- #
# Offline / fallback templates (deterministic, no model)
# --------------------------------------------------------------------------- #


def fallback_executive_summary(report: NormalizedReport) -> str:
    summary = report.summary()
    _, posture = risk_posture(report)
    metadata = report.metadata
    client = metadata.client_name or "the client"
    counts = {row.severity: row.count for row in summary.by_severity}

    parts: List[str] = []
    parts.append(
        f"This report presents the results of the {metadata.engagement_type.value.lower()} "
        f"conducted for {client}. The objective was to identify and assess security "
        f"weaknesses across the in-scope environment and to provide prioritized, actionable "
        f"recommendations for remediation."
    )

    if summary.total_findings == 0:
        parts.append(
            "No security findings were identified during this assessment within the agreed "
            "scope and time-box. This indicates a strong security posture for the tested "
            "components, though continued vigilance and periodic re-testing remain advisable."
        )
        return "\n\n".join(parts)

    breakdown = ", ".join(
        f"{counts[sev]} {sev.value.lower()}"
        for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFORMATIONAL)
        if counts.get(sev)
    )
    parts.append(
        f"In total, {summary.total_findings} finding(s) were identified ({breakdown}), giving "
        f"an overall risk posture of {posture}. The table and detailed sections that follow "
        f"describe each issue, its impact, and the recommended remediation."
    )

    top = report.sorted_findings()[:3]
    if top:
        titles = "; ".join(f"{f.title} ({f.severity.value.lower()})" for f in top)
        parts.append(
            f"The most significant issues requiring prompt attention are: {titles}. "
            f"{client} is advised to remediate findings in order of severity, beginning with "
            f"the highest-rated issues, and to validate fixes through re-testing."
        )
    return "\n\n".join(parts)


def fallback_methodology(report: NormalizedReport) -> str:
    engagement = report.metadata.engagement_type.value.lower()
    return (
        f"The {engagement} followed a structured, industry-aligned methodology comprising "
        "reconnaissance and scoping, enumeration and discovery, vulnerability identification, "
        "manual validation and exploitation where authorized, and consolidated reporting. "
        "Automated tooling was used to achieve broad coverage and was complemented by manual "
        "testing to confirm findings, eliminate false positives, and assess real-world impact. "
        "All testing was conducted within the agreed scope and rules of engagement."
    )


def fallback_conclusion(report: NormalizedReport) -> str:
    summary = report.summary()
    _, posture = risk_posture(report)
    if summary.total_findings == 0:
        return (
            "The assessment did not identify exploitable weaknesses within the tested scope. "
            "Maintaining the current controls, alongside regular patching and periodic "
            "re-assessment, will help preserve this posture as the environment evolves."
        )
    return (
        f"The assessment identified {summary.total_findings} finding(s) resulting in an overall "
        f"risk posture of {posture}. Addressing the higher-severity issues first will deliver "
        "the greatest reduction in risk. Once remediation is complete, re-testing is "
        "recommended to confirm that the issues have been resolved and that no regressions "
        "have been introduced."
    )


# Generic, severity-aware impact statements used when a finding lacks an impact field.
_IMPACT_BY_SEVERITY = {
    Severity.CRITICAL: (
        "If exploited, this issue could lead to a complete compromise of the affected system "
        "or data, with severe consequences for confidentiality, integrity, and availability."
    ),
    Severity.HIGH: (
        "Successful exploitation could allow significant unauthorized access or disruption, "
        "materially affecting the confidentiality or integrity of affected assets."
    ),
    Severity.MEDIUM: (
        "Exploitation could provide an attacker with a meaningful foothold or information "
        "that facilitates further attacks against the environment."
    ),
    Severity.LOW: (
        "The issue presents limited direct risk but may aid an attacker in combination with "
        "other weaknesses or degrade the overall security posture."
    ),
    Severity.INFORMATIONAL: (
        "This item does not present a direct security risk but is documented to support "
        "defense-in-depth and configuration best practice."
    ),
}


def fallback_description(finding: Finding) -> str:
    refs = ""
    if finding.cve:
        refs = f" This issue is associated with {', '.join(finding.cve)}."
    assets = ""
    if finding.affected_assets:
        assets = f" The following asset(s) are affected: {', '.join(finding.affected_assets)}."
    return (
        f"During testing, the issue '{finding.title}' was identified and rated "
        f"{finding.severity.value.lower()} severity.{refs}{assets} Further technical detail "
        "is provided in the evidence and remediation sections below."
    )


def fallback_impact(finding: Finding) -> str:
    return _IMPACT_BY_SEVERITY.get(finding.severity, _IMPACT_BY_SEVERITY[Severity.MEDIUM])


def fallback_remediation(finding: Finding) -> str:
    base = (
        "Remediate the issue in line with vendor guidance and security best practice. "
        "Apply available patches or configuration hardening, validate the change in a "
        "non-production environment first, and re-test to confirm the issue is resolved."
    )
    if finding.cve:
        base += (
            f" Prioritize patching for the referenced vulnerabilities ({', '.join(finding.cve)})."
        )
    return base
