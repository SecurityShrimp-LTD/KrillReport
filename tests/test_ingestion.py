"""Tests for ingestion parsers and the dispatcher."""

from __future__ import annotations

from krillreport.ingestion import ingest_file, supported_extensions
from krillreport.models import Severity


def _by_name(sample_inputs, name):
    return next(p for p in sample_inputs if p.name == name)


def test_supported_extensions_cover_all_formats():
    exts = supported_extensions()
    for required in (".json", ".csv", ".xml", ".yaml", ".txt", ".md", ".pdf", ".nessus"):
        assert required in exts


def test_json_findings_and_metadata(sample_inputs):
    result = ingest_file(_by_name(sample_inputs, "scanner_findings.json"))
    assert result.parser == "json"
    assert len(result.findings) == 3
    assert result.metadata["client_name"] == "ACME Corporation"
    struts = next(f for f in result.findings if "Struts" in f.title)
    assert struts.severity == Severity.CRITICAL
    assert "CVE-2017-5638" in struts.cve


def test_csv_findings_vs_hosts(sample_inputs):
    findings = ingest_file(_by_name(sample_inputs, "web_findings.csv"))
    assert len(findings.findings) == 4 and not findings.hosts

    hosts = ingest_file(_by_name(sample_inputs, "host_inventory.csv"))
    assert len(hosts.hosts) == 4 and not hosts.findings
    assert hosts.hosts[0].services  # per-row port/service captured


def test_nessus_xml_titles_and_severity(sample_inputs):
    result = ingest_file(_by_name(sample_inputs, "nessus_scan.nessus"))
    assert len(result.findings) == 2
    titles = {f.title for f in result.findings}
    assert any("OpenSSH" in t for t in titles)  # pluginName (camelCase) resolved


def test_nmap_xml_hosts(sample_inputs):
    result = ingest_file(_by_name(sample_inputs, "nmap_scan.xml"))
    assert len(result.hosts) == 2
    db = next(h for h in result.hosts if "db01" in h.hostname)
    assert {s.port for s in db.services} == {22, 5432}


def test_markdown_sections_and_findings(sample_inputs):
    result = ingest_file(_by_name(sample_inputs, "manual_findings.md"))
    assert result.metadata.get("report_title")
    assert "executive_summary" in result.metadata
    assert len(result.findings) == 2
    # Code fence becomes evidence on the IDOR finding.
    idor = next(f for f in result.findings if "Invoice" in f.title)
    assert idor.evidence


def test_text_sections_and_findings(sample_inputs):
    result = ingest_file(_by_name(sample_inputs, "consultant_notes.txt"))
    assert "executive_summary" in result.metadata
    assert "scope" in result.metadata
    assert len(result.findings) == 3
