"""Tests for single-finding structured Markdown reports (KV table + titled sections)."""

from pathlib import Path

from krillreport.ingestion.dispatcher import ingest_file
from krillreport.ingestion.structured_finding import (
    build_structured_record,
    looks_like_structured_finding,
)
from krillreport.models import FindingStatus, Severity

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = REPO_ROOT / "examples" / "sample_inputs" / "structured_finding.md"


def test_detects_structured_finding():
    text = SAMPLE.read_text(encoding="utf-8")
    assert looks_like_structured_finding(text)


def test_ordinary_markdown_is_not_misdetected():
    # A multi-finding report whose H2s are finding titles, not section names.
    text = (
        "# Web App Test\n\n"
        "## Executive Summary\n\nIntro.\n\n"
        "## SQL Injection in Login\n\nSeverity: High\n\nbad.\n\n"
        "## Reflected XSS in Search\n\nSeverity: Medium\n\nalso bad.\n"
    )
    assert not looks_like_structured_finding(text)


def test_structured_record_maps_metadata_and_sections():
    record, status = build_structured_record(SAMPLE.read_text(encoding="utf-8"))
    assert record["title"].startswith("Guest Wi-Fi Has No Client Isolation")  # "Finding —" stripped
    assert record["severity"] == "High"
    assert record["category"].startswith("Wireless Client Isolation Bypass")
    assert status is FindingStatus.CONFIRMED
    assert record["affected"] == ["Guest_WiFi"]  # first code span of the SSID row
    # Impact and Remediation are pulled into their own fields...
    assert "ARP spoofing" in record["impact"]
    assert "isolation" in record["remediation"].lower()
    # ...while Summary / Reproduction / Appendix stay in the description as Markdown.
    desc = record["description"]
    assert "### 1. Summary" in desc
    assert "arp-scan" in desc  # the fenced reproduction code survives
    assert "OPERATOR COPY" not in desc  # the operator-handling callout is dropped
    assert "**Date:** 2026-06-17" in desc  # unmapped KV row kept, not dropped


def test_operator_header_dropped_but_section_notes_kept():
    text = (
        "# Finding — Example Issue\n\n"
        "> ⚠ **OPERATOR COPY — CONTAINS LIVE SECRETS.** Sanitize and redact "
        "credentials before delivering to the client.\n\n"
        "| | |\n|---|---|\n| **Severity** | High |\n\n"
        "## 1. Summary\n\nThe service is misconfigured.\n\n"
        "> Note: this technical caveat is legitimate finding content.\n"
    )
    record, _ = build_structured_record(text)
    desc = record["description"]
    assert "OPERATOR COPY" not in desc
    assert "Sanitize" not in desc
    # An in-section blockquote that is not a handling note must survive.
    assert "this technical caveat is legitimate finding content" in desc


def test_full_ingest_yields_single_finding():
    result = ingest_file(SAMPLE)
    assert len(result.findings) == 1
    finding = result.findings[0]
    assert finding.severity is Severity.HIGH
    assert finding.status is FindingStatus.CONFIRMED
    assert finding.affected_assets == ["Guest_WiFi"]
    assert not result.warnings
