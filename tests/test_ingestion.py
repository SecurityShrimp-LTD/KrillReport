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


def test_nodezero_weakness_extraction():
    """NodeZero/Horizon3-style PDF text: section-numbered weakness headings + sub-sections."""
    from krillreport.ingestion.pdf_parser import PDFParser

    text = "\n".join(
        [
            "2.1. Kerberoasting HIGH 7.5",
            "H3-2022-0001",
            "Details",
            "Kerberoasting exploits service accounts with weak passwords.",
            "Affected Assets",
            "Asset Host Description Downstream Impacts Severity",
            "svc-one Kerb Tgs Hash for svc-one HIGH 7.5",
            "svc-two Kerb Tgs Hash for svc-two HIGH 7.5",
            "Proof",
            "$ GetUserSPNs.py -request ...",
            "2.2. SMB Null Session Allowed LOW 0.1",
            "Details",
            "SMB allows anonymous null sessions.",
            "2.3. Git Repo Exposed on a Web Server HIGH 7.5",
            "Details",
            "A .git directory is exposed in the web root.",
            "2.4. tcp/445 microsoft-ds MEDIUM 5",  # port row — must be excluded
        ]
    )
    findings = PDFParser()._nodezero_findings(text, "report.pdf")
    titles = [f.title for f in findings]
    assert "Kerberoasting" in titles
    assert "SMB Null Session Allowed" in titles
    assert "Git Repo Exposed on a Web Server" in titles
    assert not any(t.lower().startswith("tcp/") for t in titles)  # port row filtered out

    kerb = next(f for f in findings if f.title == "Kerberoasting")
    assert kerb.severity.value == "High" and kerb.cvss_score == 7.5
    assert "svc-one" in kerb.affected_assets and "svc-two" in kerb.affected_assets
    assert kerb.evidence and "GetUserSPNs" in kerb.evidence[0].text


def test_nodezero_business_impact_extraction():
    """The "Impact Details" section (business impacts) is imported as its own findings."""
    from krillreport.ingestion.pdf_parser import PDFParser

    text = "\n".join(
        [
            "2.1. Business Risk Details",
            "No Business Risks Found",
            "2.2. Impact Details",
            "2.2.1. Host Compromise CRITICAL 9.2",
            "Compromised 2 hosts via 2 separate attack vectors. Host compromise can lead to",
            "attackers gaining access to sensitive information.",
            "Attack Paths",
            "Host 10.1.2.3 (web01.example.com)",
            "SMB service at 10.1.2.3:445 accessed by credential jsmith",
            "Domain Controller 10.1.2.4 (dc01.example.com)",
            "SMB service at 10.1.2.4:445 accessed by credential jsmith",
            "2.2.2. Business Email Compromise CRITICAL 9.8",
            "Compromised 1 email account.",
            "Attack Paths",
            "Business email account jsmith@example.com",
            "Weakness Details",
            "2.5.1. Kerberoasting HIGH 7.5",
            "Details",
            "Kerberoasting exploits service accounts with weak passwords.",
            "2.5.2. SMB Null Session Allowed LOW 0.1",
            "Details",
            "SMB allows anonymous null sessions.",
            "2.5.3. Git Repo Exposed on a Web Server HIGH 7.5",
            "Details",
            "A .git directory is exposed in the web root.",
        ]
    )
    findings = PDFParser()._nodezero_findings(text, "report.pdf")
    impacts = [f for f in findings if f.category == "Business Impact"]
    weaknesses = [f for f in findings if f.category != "Business Impact"]

    assert {f.title for f in impacts} == {"Host Compromise", "Business Email Compromise"}
    assert {f.title for f in weaknesses} == {
        "Kerberoasting",
        "SMB Null Session Allowed",
        "Git Repo Exposed on a Web Server",
    }

    host_compromise = next(f for f in impacts if f.title == "Host Compromise")
    assert host_compromise.severity.value == "Critical" and host_compromise.cvss_score == 9.2
    assert "business-impact" in host_compromise.tags
    assert "Compromised 2 hosts" in host_compromise.description
    assert "10.1.2.3" in host_compromise.affected_assets
    assert "dc01.example.com" in host_compromise.affected_assets
    assert host_compromise.evidence and "SMB service" in host_compromise.evidence[0].text

    email_compromise = next(f for f in impacts if f.title == "Business Email Compromise")
    assert "jsmith@example.com" in email_compromise.affected_assets
