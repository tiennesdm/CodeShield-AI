"""
Tests for CodeShield AI new API endpoints.

Tests export, risk, secrets, dependencies, and webhook endpoints.
"""

import os
import sys
from datetime import datetime, timezone

# Ensure backend is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest
from fastapi.testclient import TestClient

# Set up test environment before importing main
os.environ.setdefault("DATA_DIR", "./test_data")
os.environ.setdefault("TEMP_DIR", "./test_tmp")

from main import app, db
from models.vulnerability import ScanResult, Vulnerability


client = TestClient(app)


def create_test_scan_in_db(scan_id="test-scan-1"):
    """Create and save a test scan in the database."""
    vulns = [
        Vulnerability(
            scan_id=scan_id,
            file_path="src/app.py",
            line_number=42,
            severity="CRITICAL",
            category="SQL Injection",
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            title="SQL Injection",
            description="Test SQL injection",
            code_snippet="cursor.execute(query)",
            fix_suggestion="Use parameterized queries.",
            tool_source="bandit",
            cvss_score=9.8,
            owasp_category="A03",
            confidence="HIGH",
        ),
        Vulnerability(
            scan_id=scan_id,
            file_path="config/settings.py",
            line_number=15,
            severity="HIGH",
            category="Hardcoded Secret",
            cwe_id="CWE-798",
            cwe_name="Hardcoded Credentials",
            title="Hardcoded API Key",
            description="Hardcoded secret",
            code_snippet="API_KEY = 'secret'",
            fix_suggestion="Use env vars.",
            tool_source="custom_ai",
            cvss_score=7.5,
            owasp_category="A07",
            confidence="HIGH",
        ),
        Vulnerability(
            scan_id=scan_id,
            file_path="requirements.txt",
            line_number=0,
            severity="HIGH",
            category="Vulnerable Dependency",
            cwe_id="CWE-1104",
            cwe_name="Using Components with Known Vulnerabilities",
            title="Vulnerable django 3.2.0",
            description="Known vulnerability",
            tool_source="osv_scanner",
            cvss_score=7.5,
            owasp_category="A06",
            confidence="HIGH",
        ),
    ]

    scan = ScanResult(
        scan_id=scan_id,
        name="Test Scan",
        source_type="zip",
        source_path="/tmp/test",
        status="completed",
        progress=100,
        start_time=datetime.now(timezone.utc),
        end_time=datetime.now(timezone.utc),
        languages=["python"],
        total_files=10,
        total_lines=500,
        scan_duration=60,
        tools_used=["bandit", "custom_ai", "osv_scanner"],
        vulnerabilities=vulns,
        stats={"total": 3, "critical": 1, "high": 2, "medium": 0, "low": 0, "info": 0},
        risk_score=50,
    )
    return scan


# Sync fixture to set up test data
@pytest.fixture(scope="module")
def setup_test_data():
    """Set up test scans in the database using asyncio.run for sync compatibility."""
    import asyncio

    async def _setup():
        scans = [
            create_test_scan_in_db("test-export-scan"),
            create_test_scan_in_db("test-risk-scan"),
            create_test_scan_in_db("test-secrets-scan"),
            create_test_scan_in_db("test-deps-scan"),
        ]
        for scan in scans:
            await db.save_scan(scan)
        return [s.scan_id for s in scans]

    ids = asyncio.run(_setup())
    yield ids

    # Cleanup
    async def _cleanup():
        for sid in ids:
            await db.delete_scan(sid)
    asyncio.run(_cleanup())


class TestExportEndpoints:
    """Tests for /api/export/{scan_id} endpoint."""

    def test_export_sarif(self, setup_test_data):
        """Test SARIF export."""
        scan_id = setup_test_data[0]
        response = client.get(f"/api/export/{scan_id}?format=sarif")
        assert response.status_code == 200
        assert "application/sarif+json" in response.headers["content-type"]
        data = response.json()
        assert "runs" in data

    def test_export_json(self, setup_test_data):
        """Test JSON export."""
        scan_id = setup_test_data[0]
        response = client.get(f"/api/export/{scan_id}?format=json")
        assert response.status_code == 200
        assert "application/json" in response.headers["content-type"]
        data = response.json()
        assert "scan" in data
        assert "vulnerabilities" in data

    def test_export_junit(self, setup_test_data):
        """Test JUnit XML export."""
        scan_id = setup_test_data[0]
        response = client.get(f"/api/export/{scan_id}?format=junit")
        assert response.status_code == 200
        assert "xml" in response.headers["content-type"]
        assert "<testsuites>" in response.text

    def test_export_html(self, setup_test_data):
        """Test HTML export."""
        scan_id = setup_test_data[0]
        response = client.get(f"/api/export/{scan_id}?format=html")
        assert response.status_code == 200
        assert "text/html" in response.headers["content-type"]
        assert "<!DOCTYPE html>" in response.text

    def test_export_not_found(self):
        """Test export for non-existent scan."""
        response = client.get("/api/export/nonexistent?format=json")
        assert response.status_code == 404

    def test_export_invalid_format(self, setup_test_data):
        """Test export with invalid format."""
        scan_id = setup_test_data[0]
        response = client.get(f"/api/export/{scan_id}?format=invalid")
        assert response.status_code == 422


class TestRiskEndpoints:
    """Tests for /api/risk/{scan_id} endpoint."""

    def test_get_risk_score(self, setup_test_data):
        """Test getting risk score."""
        scan_id = setup_test_data[1]
        response = client.get(f"/api/risk/{scan_id}")
        assert response.status_code == 200
        data = response.json()
        assert "overall_score" in data
        assert "overall_band" in data
        assert "overall_label" in data
        assert "recommended_action" in data
        assert "vulnerability_count" in data
        assert "vulnerabilities" in data

    def test_risk_not_found(self):
        """Test risk score for non-existent scan."""
        response = client.get("/api/risk/nonexistent")
        assert response.status_code == 404


class TestSecretsEndpoints:
    """Tests for /api/secrets endpoint."""

    def test_list_secrets(self, setup_test_data):
        """Test listing detected secrets."""
        scan_id = setup_test_data[2]
        response = client.get(f"/api/secrets?scan_id={scan_id}")
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert "total_secrets" in data
        assert "secrets" in data

    def test_list_secrets_by_severity(self, setup_test_data):
        """Test filtering secrets by severity."""
        scan_id = setup_test_data[2]
        response = client.get(f"/api/secrets?scan_id={scan_id}&severity=HIGH")
        assert response.status_code == 200
        data = response.json()
        for secret in data["secrets"]:
            assert secret["severity"] == "HIGH"

    def test_secrets_not_found(self):
        """Test secrets for non-existent scan."""
        response = client.get("/api/secrets?scan_id=nonexistent")
        assert response.status_code == 404


class TestDependencyEndpoints:
    """Tests for /api/dependencies/{scan_id} endpoint."""

    def test_get_dependencies(self, setup_test_data):
        """Test getting dependency vulnerability report."""
        scan_id = setup_test_data[3]
        response = client.get(f"/api/dependencies/{scan_id}")
        assert response.status_code == 200
        data = response.json()
        assert "scan_id" in data
        assert "total_dependencies_affected" in data
        assert "dependencies" in data

    def test_dependencies_not_found(self):
        """Test dependencies for non-existent scan."""
        response = client.get("/api/dependencies/nonexistent")
        assert response.status_code == 404


class TestWebhookEndpoints:
    """Tests for /api/webhook endpoint."""

    def test_configure_webhook(self):
        """Test configuring a webhook."""
        config = {
            "url": "https://hooks.example.com/codeshield",
            "events": ["scan.completed", "scan.failed"],
            "secret": "my-webhook-secret",
        }
        response = client.post("/api/webhook", json=config)
        assert response.status_code == 200
        data = response.json()
        assert "webhook_id" in data
        assert data["url"] == config["url"]
        assert data["status"] == "configured"
        assert data["events"] == config["events"]

    def test_configure_webhook_missing_url(self):
        """Test webhook without URL."""
        response = client.post("/api/webhook", json={"events": ["scan.completed"]})
        assert response.status_code == 400

    def test_list_webhooks(self):
        """Test listing webhooks."""
        response = client.get("/api/webhook")
        assert response.status_code == 200
        data = response.json()
        assert "webhooks" in data

    def test_delete_webhook(self):
        """Test deleting a webhook."""
        config = {"url": "https://example.com/webhook"}
        create_response = client.post("/api/webhook", json=config)
        assert create_response.status_code == 200
        webhook_id = create_response.json()["webhook_id"]

        delete_response = client.delete(f"/api/webhook/{webhook_id}")
        assert delete_response.status_code == 200
        assert delete_response.json()["deleted"] is True

    def test_delete_webhook_not_found(self):
        """Test deleting non-existent webhook."""
        response = client.delete("/api/webhook/nonexistent")
        assert response.status_code == 404
