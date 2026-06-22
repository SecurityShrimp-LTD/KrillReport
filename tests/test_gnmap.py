"""Tests for the Nmap grepable (``-oG`` / ``.gnmap``) parser."""

from pathlib import Path

from krillreport.ingestion.dispatcher import detect_parser, ingest_file
from krillreport.ingestion.gnmap_parser import GnmapParser

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = REPO_ROOT / "examples" / "sample_inputs" / "nmap_scan.gnmap"


def test_dispatcher_selects_gnmap_parser():
    assert isinstance(detect_parser(SAMPLE), GnmapParser)


def test_gnmap_hosts_ports_and_os():
    result = ingest_file(SAMPLE)
    assert not result.findings  # grepable output carries hosts, not findings
    # The "Down" host is dropped; two up hosts remain.
    assert len(result.hosts) == 2

    gw = next(h for h in result.hosts if h.ip_address == "198.51.100.5")
    assert gw.hostname == "gw.example.com"
    assert gw.operating_system == "Linux 5.15"  # OS spread onto a separate Host: line
    ports = {s.port for s in gw.services}
    assert ports == {22, 80, 443}  # closed 3306 excluded
    ssh = next(s for s in gw.services if s.port == 22)
    assert ssh.name == "ssh"
    assert "OpenSSH 8.9p1" in ssh.product

    vpn = next(h for h in result.hosts if h.ip_address == "198.51.100.9")
    udp = next(s for s in vpn.services if s.port == 500)
    assert udp.protocol == "udp" and udp.name == "isakmp"


def test_gnmap_content_sniff_without_extension(tmp_path):
    # Grepable output saved under a non-.gnmap name is still recognized by content.
    txt = (
        "# Nmap 7.94 scan initiated as: nmap -oG - host\n"
        "Host: 10.0.0.1 (h.example)\tStatus: Up\n"
        "Host: 10.0.0.1 (h.example)\tPorts: 22/open/tcp//ssh///\n"
    )
    path = tmp_path / "scan.txt"
    path.write_text(txt)
    parser = GnmapParser()
    assert parser.can_parse(path, txt)
