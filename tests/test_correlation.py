"""Tests for finding <-> scanned-host correlation in the render context."""

from krillreport.models import Finding, Host, Service, Severity
from krillreport.report_renderer.sections import correlate


def _host(hostname, ip, os_name, port):
    return Host(
        hostname=hostname,
        ip_address=ip,
        operating_system=os_name,
        services=[Service(port=port, protocol="tcp", name="svc")],
    )


def test_correlate_matches_by_ip_and_hostname():
    f1 = Finding(id="f1", title="RCE", severity=Severity.HIGH, affected_assets=["203.0.113.10"])
    f2 = Finding(id="f2", title="XSS", severity=Severity.LOW, affected_assets=["https://web01.acme.example/x"])
    f3 = Finding(id="f3", title="Unrelated", severity=Severity.LOW, affected_assets=["Guest_WiFi"])
    web = _host("web01.acme.example", "203.0.113.10", "Ubuntu 22.04", 443)
    db = _host("db01.acme.example", "203.0.113.40", "Linux", 5432)

    scan_rows, host_findings = correlate([(1, f1), (2, f2), (3, f3)], [web, db])

    # f1 matches web by IP, f2 matches web by hostname; f3 matches nothing.
    assert "f1" in scan_rows and "web01.acme.example" in scan_rows["f1"][0]
    assert "f2" in scan_rows
    assert "f3" not in scan_rows
    # Reverse map: web is referenced by findings 1 and 2; db by none.
    assert host_findings["web01.acme.example"] == [1, 2]
    assert "db01.acme.example" not in host_findings
    # The summary carries OS + services for corroboration.
    assert "Ubuntu 22.04" in scan_rows["f1"][0]
    assert "443/tcp" in scan_rows["f1"][0]


def test_ip_match_respects_boundaries():
    # 203.0.113.16 must not match inside 203.0.113.169.
    finding = Finding(id="f", title="x", severity=Severity.LOW, affected_assets=["203.0.113.169"])
    host = _host("h", "203.0.113.16", "Linux", 22)
    scan_rows, host_findings = correlate([(1, finding)], [host])
    assert scan_rows == {}
    assert host_findings == {}
