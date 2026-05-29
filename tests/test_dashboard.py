"""Tests for the server-rendered dashboard."""

from datetime import datetime, timezone

from exporters.dashboard import DashboardRenderer
from models.vulnerability import ScanResult, Vulnerability


def _scan(scan_id, status="completed", risk=42):
    return ScanResult(
        scan_id=scan_id, name=f"Scan {scan_id}", source_type="zip",
        source_path="/tmp/x", status=status,
        start_time=datetime.now(timezone.utc), risk_score=risk,
        vulnerabilities=[
            Vulnerability(scan_id=scan_id, file_path="a.py", line_number=1,
                          severity="HIGH", category="XSS", title="t",
                          description="d", tool_source="semgrep")
        ],
        stats={"total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
    )


def _stats():
    return {
        "total_scans": 2,
        "by_status": {"completed": 1, "failed": 1, "running": 0, "pending": 0},
        "total_vulnerabilities": 3,
        "by_severity": {"critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0},
    }


def test_render_structure():
    html = DashboardRenderer().render(_stats(), [_scan("s1"), _scan("s2", "failed")])
    assert "<!DOCTYPE html>" in html
    assert "</html>" in html
    assert "CodeShield" in html
    assert "Dashboard" in html


def test_render_includes_scan_rows():
    html = DashboardRenderer().render(_stats(), [_scan("abc123")])
    assert "abc123" in html
    assert "Recent scans" in html


def test_render_includes_stat_values():
    html = DashboardRenderer().render(_stats(), [])
    assert "Total scans" in html
    assert "Total findings" in html


def test_render_empty_scans():
    html = DashboardRenderer().render(_stats(), [])
    assert "No scans yet." in html


def test_render_escapes_names():
    s = _scan("x")
    s.name = "<script>alert(1)</script>"
    html = DashboardRenderer().render(_stats(), [s])
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html


def test_render_is_responsive():
    html = DashboardRenderer().render(_stats(), [])
    assert "max-width:900px" in html
    assert "viewport" in html
