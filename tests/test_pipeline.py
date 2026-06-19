"""Tests for normalization, branding extraction, enhancement, and rendering."""

from __future__ import annotations

import zipfile
from pathlib import Path

from krillreport.config import LLMSettings
from krillreport.ingestion import ingest_paths
from krillreport.llm_enhancer import Enhancer
from krillreport.llm_enhancer.base import LLMProvider
from krillreport.normalization import normalize
from krillreport.pipeline import run_pipeline
from krillreport.template_engine import TemplateManager, extract_branding


def test_normalize_dedupes_and_merges_hosts(sample_inputs):
    report = normalize(ingest_paths(sample_inputs))
    # The two Struts records (shared CVE) collapse to one.
    struts = [f for f in report.findings if "struts" in f.id.lower()]
    assert len(struts) == 1
    assert struts[0].merged_count == 2
    # db01 appears in both nmap and the host inventory -> merged once.
    db_hosts = [h for h in report.hosts if "db01" in (h.hostname or "")]
    assert len(db_hosts) == 1


def test_branding_extraction_from_docx(branded_docx, tmp_path):
    branding = extract_branding(branded_docx, tmp_path, name="ACME")
    assert branding.primary_color.upper() == "#0E7C7B"  # teal heading colour
    assert branding.heading_font == "Calibri"
    assert "CONFIDENTIAL" in branding.header_text


def test_template_manager_roundtrip(branded_docx, tmp_path):
    manager = TemplateManager(tmp_path / "templates")
    branding = manager.create_from_sample(branded_docx, name="ACME Corp")
    assert manager.exists("ACME Corp")
    assert manager.get("acme-corp").primary_color == branding.primary_color
    assert manager.delete("acme-corp")
    assert not manager.exists("acme-corp")


def test_enhancer_offline_fills_gaps(sample_inputs):
    report = normalize(ingest_paths(sample_inputs))
    Enhancer(LLMSettings(provider="offline", enabled=True)).enhance_report(report)
    # Every finding ends with all three prose fields populated.
    for finding in report.findings:
        assert finding.description.strip()
        assert finding.impact.strip()
        assert finding.remediation.strip()
    assert report.metadata.methodology.strip()
    assert report.metadata.conclusion.strip()


def test_enhancer_stub_llm(sample_inputs):
    class Stub(LLMProvider):
        name = "stub"
        is_llm = True

        def available(self):
            return True

        def generate(self, system, user):
            if "### DESCRIPTION" in user:
                return "### DESCRIPTION\nD\n### IMPACT\nI\n### REMEDIATION\nR"
            return "STUB"

    report = normalize(ingest_paths(sample_inputs))
    Enhancer(LLMSettings(provider="offline", enabled=True), provider=Stub()).enhance_report(report)
    assert report.metadata.executive_summary == "STUB"
    assert report.findings[0].description == "D"


def test_full_pipeline_renders_both_formats(sample_inputs, tmp_path):
    result = run_pipeline(
        sample_inputs,
        output_dir=tmp_path / "out",
        basename="report",
        llm_settings=LLMSettings(provider="offline", enabled=True),
    )
    pdf = result.outputs["pdf"]
    docx = result.outputs["docx"]
    assert pdf.exists() and pdf.read_bytes()[:4] == b"%PDF"
    assert docx.exists() and zipfile.is_zipfile(docx)
    assert result.report.summary().total_findings > 0
