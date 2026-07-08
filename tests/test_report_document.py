"""Tests for multi-finding assessment reports written as one Markdown document.

These reports (typically LLM-authored) carry the whole engagement in one file: an H1
title, a ``**Key:** value`` header, numbered ``## N. Section`` headings, and each finding
as an ``### Fn — Title (Severity)`` subsection with bold-labelled fields. The generic
free-text engine mis-reads them (section headings become bogus findings); this module and
parser recognize the shape and map it correctly.
"""

from pathlib import Path

from krillreport.ingestion.dispatcher import ingest_file
from krillreport.ingestion.report_document import (
    build_report,
    looks_like_finding_report,
)
from krillreport.models import Severity

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = REPO_ROOT / "examples" / "sample_inputs" / "assessment_report.md"


def test_detects_multi_finding_report():
    assert looks_like_finding_report(SAMPLE.read_text(encoding="utf-8"))


def test_single_finding_doc_is_not_a_report():
    # Only one severity-tagged heading -> handled by structured_finding, not this engine.
    text = "# XSS\n\n## Impact\n\nbad\n\n## Fix\n\ndo it (High)\n"
    assert not looks_like_finding_report(text)


def test_ordinary_headings_without_severity_are_not_a_report():
    text = "# Notes\n\n## Background\n\ntext\n\n## Next Steps\n\nmore text\n"
    assert not looks_like_finding_report(text)


def test_parser_extracts_each_finding_not_section_headings():
    result = ingest_file(SAMPLE)
    assert result.parser == "markdown"
    titles = [f.title for f in result.findings]
    # Three findings, no section headings ("Executive Summary", "Findings", "Appendix").
    assert titles == [
        "F1 — IDOR on `/invoices/{id}`",
        "F2 — No rate limiting on `/auth/login`",
        "F3 — Verbose error messages leak stack traces",
    ]


def test_severity_is_read_from_heading_suffix():
    result = ingest_file(SAMPLE)
    by_title = {f.title.split(" — ")[0]: f for f in result.findings}
    assert by_title["F1"].severity is Severity.HIGH
    assert by_title["F2"].severity is Severity.MEDIUM
    # "(Low, robustness)" — a severity with a trailing qualifier still maps to Low.
    assert by_title["F3"].severity is Severity.LOW


def test_bold_labels_map_to_finding_fields():
    result = ingest_file(SAMPLE)
    f1 = result.findings[0]
    assert "InvoiceController.show" in f1.affected_assets
    assert f1.impact.startswith("Full cross-tenant disclosure")
    assert f1.remediation.startswith("Enforce an ownership check")
    # The lead paragraph (before the first bold label) is the description.
    assert f1.description.startswith("Any authenticated user")


def test_consecutive_label_lines_are_separated():
    # F2's Location/Impact/Recommendation sit on consecutive lines with no blank between.
    f2 = ingest_file(SAMPLE).findings[1]
    assert f2.affected_assets == ["POST /auth/login"]
    assert f2.impact == "Unbounded credential-stuffing and password-brute-force attempts."
    assert f2.remediation.startswith("Add per-account and per-IP throttling")


def test_header_and_sections_populate_metadata():
    result = ingest_file(SAMPLE)
    meta = result.metadata
    assert meta["report_title"] == "PayFlow API — Security Assessment (Final Report)"
    assert meta["client_name"] == "PayFlow Inc."
    assert meta["assessors"] == ["Alex Rivera", "Jordan Lee"]
    assert meta["start_date"] == "2026-05-04" and meta["end_date"] == "2026-05-18"
    assert meta["executive_summary"].startswith("The PayFlow API is well-built")
    assert "OWASP" in meta["methodology"] and "manual verification" in meta["methodology"]


def test_non_finding_sections_preserved_as_appendices():
    result = ingest_file(SAMPLE)
    titles = [a.title for a in result.appendices]
    assert "Appendix A — Tooling" in titles


def test_build_report_returns_records_and_status():
    title, meta, findings, appendices = build_report(SAMPLE.read_text(encoding="utf-8"))
    assert title == "PayFlow API — Security Assessment (Final Report)"
    assert len(findings) == 3
    assert [t for t, _ in appendices] == ["Appendix A — Tooling"]
