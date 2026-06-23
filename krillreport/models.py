"""The unified, normalized internal data model.

Every ingestion parser produces these types, normalization refines them, the LLM
enhancer rewrites prose fields on them, and both renderers consume them. Keeping a
single well-defined model here is what lets wildly different inputs (a Nessus XML
export, a hand-written Markdown findings list, a CSV of hosts) end up in one report.

The model is built on Pydantic v2 so it is self-validating, JSON-serializable
(``report.model_dump_json()``) and round-trippable for caching / API transport.
"""

from __future__ import annotations

import re
from datetime import date, datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from .utils import normalize_whitespace, slugify

# --------------------------------------------------------------------------- #
# Enumerations
# --------------------------------------------------------------------------- #


class Severity(str, Enum):
    """Risk severity rating for a finding.

    Values are display-ready title case. Helpers provide ordering, a default colour
    (overridable by branding), and lenient coercion from the many ways tools express
    severity (``"info"``, ``5``, ``"P1"`` …).
    """

    INFORMATIONAL = "Informational"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

    @property
    def rank(self) -> int:
        """Numeric rank for sorting; higher == more severe."""
        return _SEVERITY_RANK[self]

    @property
    def color(self) -> str:
        """Default hex colour used when a branding template provides no override."""
        return _SEVERITY_COLOR[self]

    @classmethod
    def from_cvss(cls, score: Optional[float]) -> "Severity":
        """Map a CVSS v3 base score to a severity band."""
        if score is None:
            return cls.INFORMATIONAL
        if score >= 9.0:
            return cls.CRITICAL
        if score >= 7.0:
            return cls.HIGH
        if score >= 4.0:
            return cls.MEDIUM
        if score > 0.0:
            return cls.LOW
        return cls.INFORMATIONAL

    @classmethod
    def _from_number(cls, number: float, *, integer: bool) -> "Severity":
        """Interpret a numeric severity expression.

        Integers ``0..4`` are treated as the common 5-band scanner scale
        (0=Informational … 4=Critical, as used by Nessus/OpenVAS). Any other value —
        a decimal, or an integer ≥ 5 — is interpreted as a CVSS base score.
        """
        if integer and 0 <= number <= 4:
            return _SEVERITY_BAND[int(number)]
        return cls.from_cvss(number)

    @classmethod
    def coerce(cls, value: Any, default: "Severity" = None) -> "Severity":
        """Best-effort parse of an arbitrary severity expression.

        Accepts enum members, numeric CVSS-like scores, and a wide range of strings
        (``critical``/``crit``, ``high``, ``p1``, ``sev1``, ``info``…). Falls back to
        ``default`` (or ``MEDIUM``) when nothing matches.
        """
        if default is None:
            default = cls.MEDIUM
        if isinstance(value, Severity):
            return value
        if value is None:
            return default
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return cls._from_number(float(value), integer=float(value).is_integer())
        text = str(value).strip().lower()
        if not text:
            return default
        if text in _SEVERITY_ALIASES:
            return _SEVERITY_ALIASES[text]
        # A purely numeric string is a band index (integer 0-4) or a CVSS score.
        if re.fullmatch(r"-?\d+(?:\.\d+)?", text):
            number = float(text)
            return cls._from_number(number, integer="." not in text)
        # Substring match as a last resort ("high risk" -> HIGH).
        for alias, severity in _SEVERITY_ALIASES.items():
            if alias in text:
                return severity
        return default


_SEVERITY_RANK: Dict[Severity, int] = {
    Severity.INFORMATIONAL: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}

# The common 5-band scanner severity scale (Nessus/OpenVAS), indexed 0-4.
_SEVERITY_BAND: Dict[int, Severity] = {
    0: Severity.INFORMATIONAL,
    1: Severity.LOW,
    2: Severity.MEDIUM,
    3: Severity.HIGH,
    4: Severity.CRITICAL,
}

_SEVERITY_COLOR: Dict[Severity, str] = {
    Severity.CRITICAL: "#C0392B",
    Severity.HIGH: "#E74C3C",
    Severity.MEDIUM: "#E67E22",
    Severity.LOW: "#F1C40F",
    Severity.INFORMATIONAL: "#3498DB",
}

# Maps lowercase aliases to severity. Ordered loosely by specificity for the
# substring fallback in ``Severity.coerce``.
_SEVERITY_ALIASES: Dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "crit": Severity.CRITICAL,
    "severe": Severity.CRITICAL,
    "p1": Severity.CRITICAL,
    "sev1": Severity.CRITICAL,
    "high": Severity.HIGH,
    "important": Severity.HIGH,
    "p2": Severity.HIGH,
    "sev2": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "med": Severity.MEDIUM,
    "p3": Severity.MEDIUM,
    "sev3": Severity.MEDIUM,
    "low": Severity.LOW,
    "minor": Severity.LOW,
    "p4": Severity.LOW,
    "sev4": Severity.LOW,
    "informational": Severity.INFORMATIONAL,
    "information": Severity.INFORMATIONAL,
    "info": Severity.INFORMATIONAL,
    "note": Severity.INFORMATIONAL,
    "none": Severity.INFORMATIONAL,
    "log": Severity.INFORMATIONAL,
}


class Confidence(str, Enum):
    """Assessor confidence that a finding is a true positive."""

    TENTATIVE = "Tentative"
    FIRM = "Firm"
    CONFIRMED = "Confirmed"

    @classmethod
    def coerce(cls, value: Any) -> Optional["Confidence"]:
        if value is None or value == "":
            return None
        if isinstance(value, Confidence):
            return value
        text = str(value).strip().lower()
        mapping = {
            "tentative": cls.TENTATIVE,
            "low": cls.TENTATIVE,
            "possible": cls.TENTATIVE,
            "firm": cls.FIRM,
            "medium": cls.FIRM,
            "probable": cls.FIRM,
            "confirmed": cls.CONFIRMED,
            "high": cls.CONFIRMED,
            "certain": cls.CONFIRMED,
        }
        return mapping.get(text)


class FindingStatus(str, Enum):
    """Lifecycle status of a finding within the engagement."""

    OPEN = "Open"
    CONFIRMED = "Confirmed"
    REMEDIATED = "Remediated"
    ACCEPTED_RISK = "Accepted Risk"
    FALSE_POSITIVE = "False Positive"


class EngagementType(str, Enum):
    """The kind of security engagement the report documents."""

    PENETRATION_TEST = "Penetration Test"
    RED_TEAM = "Red Team Engagement"
    VULNERABILITY_ASSESSMENT = "Vulnerability Assessment"
    WEB_APP_TEST = "Web Application Assessment"
    SECURITY_AUDIT = "Security Audit"


# --------------------------------------------------------------------------- #
# Leaf models
# --------------------------------------------------------------------------- #


class Reference(BaseModel):
    """An external reference (advisory, CVE page, vendor doc)."""

    model_config = ConfigDict(extra="ignore")

    title: str = ""
    url: str = ""

    @classmethod
    def from_value(cls, value: Any) -> Optional["Reference"]:
        """Build a reference from a string URL or a ``{title, url}`` mapping."""
        if value is None:
            return None
        if isinstance(value, Reference):
            return value
        if isinstance(value, dict):
            url = value.get("url") or value.get("href") or value.get("link") or ""
            title = value.get("title") or value.get("name") or url
            if not (url or title):
                return None
            return cls(title=str(title), url=str(url))
        text = str(value).strip()
        if not text:
            return None
        # Markdown link: ``[title](url)`` -> title + url.
        link = re.search(r"\[([^\]]+)\]\(\s*(https?://[^)\s]+)\s*\)", text)
        if link:
            return cls(title=link.group(1).strip(), url=link.group(2).strip())
        # A bare URL, possibly embedded in "Title — https://..." style text.
        bare = re.search(r"https?://[^\s|)\]]+", text)
        if bare:
            url = bare.group(0)
            title = text.replace(url, "").strip(" \t-—–:|[]()")
            return cls(title=title or url, url=url)
        return cls(title=text, url="")


class Service(BaseModel):
    """A network service / open port discovered on a host."""

    model_config = ConfigDict(extra="ignore")

    port: Optional[int] = None
    protocol: str = "tcp"
    name: str = ""
    product: str = ""
    version: str = ""
    banner: str = ""

    def label(self) -> str:
        """Human-readable one-liner, e.g. ``443/tcp https (nginx 1.25)``."""
        parts: List[str] = []
        if self.port is not None:
            parts.append(f"{self.port}/{self.protocol}")
        if self.name:
            parts.append(self.name)
        product = " ".join(p for p in (self.product, self.version) if p).strip()
        if product:
            parts.append(f"({product})")
        return " ".join(parts).strip()


class Host(BaseModel):
    """A target host / asset and the services found on it."""

    model_config = ConfigDict(extra="ignore")

    identifier: str = Field(default="", description="Stable id: hostname or IP")
    hostname: str = ""
    ip_address: str = ""
    operating_system: str = ""
    services: List[Service] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)
    notes: str = ""

    def model_post_init(self, __context: Any) -> None:
        # Guarantee a stable identifier for grouping / display.
        if not self.identifier:
            self.identifier = self.hostname or self.ip_address or "unknown-host"


class Evidence(BaseModel):
    """A piece of supporting evidence for a finding.

    ``text`` holds command output / request-response pairs / log excerpts and is
    rendered in a monospaced block. ``image_path`` references a screenshot to embed.
    """

    model_config = ConfigDict(extra="ignore")

    caption: str = ""
    description: str = ""
    text: str = ""
    image_path: Optional[str] = None
    language: str = ""  # optional syntax hint for code/output blocks


# --------------------------------------------------------------------------- #
# Finding
# --------------------------------------------------------------------------- #


class Finding(BaseModel):
    """A single security finding — the heart of the data model.

    Prose fields (``description``, ``impact``, ``remediation``) are the ones the LLM
    enhancer may rewrite. ``raw`` preserves the original parsed record for traceability
    and debugging, and ``sources`` / ``merged_count`` track provenance after dedup.
    """

    model_config = ConfigDict(extra="ignore", use_enum_values=False)

    id: str = ""
    title: str = "Untitled Finding"
    severity: Severity = Severity.MEDIUM
    confidence: Optional[Confidence] = None
    status: FindingStatus = FindingStatus.OPEN

    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None

    description: str = ""
    impact: str = ""
    remediation: str = ""

    category: str = ""
    affected_assets: List[str] = Field(default_factory=list)
    evidence: List[Evidence] = Field(default_factory=list)
    references: List[Reference] = Field(default_factory=list)
    cve: List[str] = Field(default_factory=list)
    cwe: List[str] = Field(default_factory=list)
    tags: List[str] = Field(default_factory=list)

    # Provenance / dedup bookkeeping.
    source_tool: str = ""
    source_files: List[str] = Field(default_factory=list)
    merged_count: int = 1
    raw: Dict[str, Any] = Field(default_factory=dict)

    def model_post_init(self, __context: Any) -> None:
        if not self.id:
            self.id = slugify(self.title, fallback="finding")
        # If a CVSS score is present but severity was left at the default, derive it.
        if self.cvss_score is not None and self.severity == Severity.MEDIUM:
            self.severity = Severity.from_cvss(self.cvss_score)

    def dedup_key(self) -> str:
        """A normalized key used to detect duplicate findings across sources.

        Prefers a shared CVE (the strongest signal that two records describe the same
        issue); otherwise falls back to a normalized title.
        """
        if self.cve:
            return f"cve:{sorted(c.lower() for c in self.cve)[0]}"
        normalized = normalize_whitespace(self.title).lower()
        return f"title:{slugify(normalized, max_length=120, fallback=self.id)}"

    def merge(self, other: "Finding") -> None:
        """Fold ``other`` into ``self`` (used during deduplication).

        Keeps the higher severity / CVSS, unions affected assets, evidence, references
        and identifiers, and records the extra provenance. The richer prose is kept so
        we never lose detail by merging a sparse duplicate over a detailed one.
        """
        if other.severity.rank > self.severity.rank:
            self.severity = other.severity
        if other.cvss_score is not None and (
            self.cvss_score is None or other.cvss_score > self.cvss_score
        ):
            self.cvss_score = other.cvss_score
            if other.cvss_vector:
                self.cvss_vector = other.cvss_vector

        # Prefer the longer/richer prose for each narrative field.
        for field in ("description", "impact", "remediation"):
            current = getattr(self, field)
            incoming = getattr(other, field)
            if len(incoming) > len(current):
                setattr(self, field, incoming)

        self.affected_assets = _dedup_keep_order(self.affected_assets + other.affected_assets)
        self.cve = _dedup_keep_order(self.cve + other.cve)
        self.cwe = _dedup_keep_order(self.cwe + other.cwe)
        self.tags = _dedup_keep_order(self.tags + other.tags)
        self.evidence.extend(other.evidence)

        existing_refs = {(r.title, r.url) for r in self.references}
        for ref in other.references:
            if (ref.title, ref.url) not in existing_refs:
                self.references.append(ref)

        self.source_files = _dedup_keep_order(self.source_files + other.source_files)
        if other.source_tool and other.source_tool not in self.source_tool:
            self.source_tool = (
                f"{self.source_tool}, {other.source_tool}".strip(", ")
                if self.source_tool
                else other.source_tool
            )
        self.merged_count += other.merged_count


def _dedup_keep_order(items: List[str]) -> List[str]:
    """De-duplicate a list of strings while preserving first-seen order."""
    seen = set()
    result: List[str] = []
    for item in items:
        if item is None:
            continue
        key = item.strip()
        if not key or key.lower() in seen:
            continue
        seen.add(key.lower())
        result.append(key)
    return result


# --------------------------------------------------------------------------- #
# Engagement metadata + report
# --------------------------------------------------------------------------- #


class EngagementMetadata(BaseModel):
    """Top-level engagement details and the narrative sections of the report.

    The narrative fields (``executive_summary``, ``methodology``, ``conclusion``) are
    optional and may be generated/enhanced by the LLM layer.
    """

    model_config = ConfigDict(extra="ignore", use_enum_values=False)

    client_name: str = ""
    project_name: str = ""
    report_title: str = "Security Assessment Report"
    engagement_type: EngagementType = EngagementType.PENETRATION_TEST

    start_date: Optional[date] = None
    end_date: Optional[date] = None

    scope: List[str] = Field(default_factory=list)
    assessors: List[str] = Field(default_factory=list)
    contact_name: str = ""
    contact_email: str = ""

    version: str = "1.0"
    classification: str = "CONFIDENTIAL"

    # Narrative sections (may be LLM-enhanced).
    executive_summary: str = ""
    methodology: str = ""
    conclusion: str = ""


class Appendix(BaseModel):
    """An arbitrary extra section appended after the findings.

    When ``language`` is set (e.g. an attached engagement script), the renderers emit
    ``content`` verbatim as a monospaced code block instead of interpreting it as
    Markdown; the value is a syntax hint (``bash``, ``python``, …).

    When ``image_path`` is set (an attached screenshot/diagram), the renderers embed
    the image instead of rendering ``content``; ``content`` may still hold a caption.
    """

    model_config = ConfigDict(extra="ignore")

    title: str
    content: str = ""
    language: str = ""
    image_path: Optional[str] = None


class SeverityCount(BaseModel):
    """Count of findings at a single severity, with display metadata."""

    severity: Severity
    count: int
    color: str

    model_config = ConfigDict(use_enum_values=False)


class ReportSummary(BaseModel):
    """Aggregate statistics computed from the findings (for the dashboard/charts)."""

    total_findings: int = 0
    total_hosts: int = 0
    by_severity: List[SeverityCount] = Field(default_factory=list)
    highest_severity: Severity = Severity.INFORMATIONAL

    model_config = ConfigDict(use_enum_values=False)


class NormalizedReport(BaseModel):
    """The complete, normalized report ready for rendering."""

    model_config = ConfigDict(extra="ignore", use_enum_values=False)

    metadata: EngagementMetadata = Field(default_factory=EngagementMetadata)
    findings: List[Finding] = Field(default_factory=list)
    hosts: List[Host] = Field(default_factory=list)
    appendices: List[Appendix] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def sorted_findings(self) -> List[Finding]:
        """Findings ordered most-severe first, then by CVSS score, then title."""
        return sorted(
            self.findings,
            key=lambda f: (-f.severity.rank, -(f.cvss_score or 0.0), f.title.lower()),
        )

    def summary(self) -> ReportSummary:
        """Compute aggregate statistics across the current findings."""
        counts: Dict[Severity, int] = {sev: 0 for sev in Severity}
        for finding in self.findings:
            counts[finding.severity] += 1

        # Order the breakdown most-severe first for display.
        ordered = sorted(Severity, key=lambda s: -s.rank)
        by_severity = [
            SeverityCount(severity=sev, count=counts[sev], color=sev.color) for sev in ordered
        ]

        highest = Severity.INFORMATIONAL
        for finding in self.findings:
            if finding.severity.rank > highest.rank:
                highest = finding.severity

        return ReportSummary(
            total_findings=len(self.findings),
            total_hosts=len(self.hosts),
            by_severity=by_severity,
            highest_severity=highest,
        )
