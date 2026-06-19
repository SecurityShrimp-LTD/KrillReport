"""Tests for the data model: severity coercion and finding merge."""

from __future__ import annotations

import pytest

from krillreport.models import Finding, Severity


@pytest.mark.parametrize(
    "value,expected",
    [
        ("critical", Severity.CRITICAL),
        ("High", Severity.HIGH),
        ("med", Severity.MEDIUM),
        ("p1", Severity.CRITICAL),
        ("info", Severity.INFORMATIONAL),
        (9.1, Severity.CRITICAL),       # CVSS float
        ("7.5", Severity.HIGH),         # CVSS string
        (2, Severity.MEDIUM),           # 0-4 band scale (Nessus)
        (0, Severity.INFORMATIONAL),
        (None, Severity.MEDIUM),        # default
    ],
)
def test_severity_coerce(value, expected):
    assert Severity.coerce(value) == expected


def test_from_cvss_bands():
    assert Severity.from_cvss(9.0) == Severity.CRITICAL
    assert Severity.from_cvss(7.0) == Severity.HIGH
    assert Severity.from_cvss(4.0) == Severity.MEDIUM
    assert Severity.from_cvss(0.1) == Severity.LOW
    assert Severity.from_cvss(0.0) == Severity.INFORMATIONAL


def test_finding_autoslug_and_cvss_severity():
    f = Finding(title="SQL Injection in Login", cvss_score=9.3)
    assert f.id == "sql-injection-in-login"
    assert f.severity == Severity.CRITICAL  # derived from CVSS


def test_finding_merge_unions_and_keeps_richer():
    a = Finding(title="Struts RCE", severity=Severity.HIGH, cve=["CVE-2017-5638"],
                affected_assets=["10.0.0.1"], description="short")
    b = Finding(title="Struts", severity=Severity.CRITICAL, cve=["CVE-2017-5638"],
                affected_assets=["10.0.0.2"], description="a much longer description here")
    assert a.dedup_key() == b.dedup_key()  # shared CVE
    a.merge(b)
    assert a.severity == Severity.CRITICAL                 # higher severity kept
    assert set(a.affected_assets) == {"10.0.0.1", "10.0.0.2"}
    assert a.description == "a much longer description here"  # richer prose kept
    assert a.merged_count == 2
