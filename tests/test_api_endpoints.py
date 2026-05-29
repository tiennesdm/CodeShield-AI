"""
Tests for CodeShield AI new API endpoints.

Tests export, risk, secrets, dependencies, and webhook endpoints.
"""

import os
import sys
from datetime import datetime, timezone
from unittest.mock import patch, AsyncMock

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


class TestDownloadEndpoint:
    """Tests for /api/scan/{scan_id}/download endpoint."""

    def test_download_not_found(self):
        """Test download for non-existent scan."""
        response = client.get("/api/scan/abcdef99/download")
        assert response.status_code == 404

    def test_download_not_completed(self, setup_test_data):
        """Test download for pending/running scan."""
        import asyncio
        # Create a scan that is running
        scan_id = "abcdef88"
        scan = create_test_scan_in_db(scan_id)
        scan.status = "running"
        asyncio.run(db.save_scan(scan))

        try:
            response = client.get(f"/api/scan/{scan_id}/download")
            assert response.status_code == 400
            assert "Scan is not yet complete" in response.json()["detail"]
        finally:
            asyncio.run(db.delete_scan(scan_id))

    def test_download_success(self, setup_test_data):
        """Test successful patched code download."""
        import asyncio
        import zipfile
        import io
        from utils.config import get_settings
        
        scan_id = "abcdef77"
        scan = create_test_scan_in_db(scan_id)
        scan.status = "completed"
        
        settings = get_settings()
        extract_dir = settings.temp_dir / f"extract_{scan_id}"
        extract_dir.mkdir(parents=True, exist_ok=True)
        zip_path = extract_dir / f"upload_{scan_id}.zip"
        
        with zipfile.ZipFile(zip_path, "w") as zf:
            zf.writestr("src/app.py", "cursor.execute(query)\n")
            zf.writestr("config/settings.py", "API_KEY = 'secret'\n")

        asyncio.run(db.save_scan(scan))

        try:
            response = client.get(f"/api/scan/{scan_id}/download")
            assert response.status_code == 200
            assert "application/zip" in response.headers["content-type"]
            assert f"patched_Test_Scan_{scan_id}.zip" in response.headers["content-disposition"]
            
            resp_zip_data = io.BytesIO(response.content)
            with zipfile.ZipFile(resp_zip_data, "r") as zf:
                file_list = zf.namelist()
                assert "src/app.py" in file_list
                assert "config/settings.py" in file_list
        finally:
            asyncio.run(db.delete_scan(scan_id))
            import shutil
            shutil.rmtree(extract_dir, ignore_errors=True)

    def test_download_github_success(self, setup_test_data):
        """Test successful patched code download for github scans."""
        import asyncio
        import zipfile
        import io
        from unittest.mock import patch, AsyncMock
        from utils.config import get_settings
        
        scan_id = "abcdef66"
        scan = create_test_scan_in_db(scan_id)
        scan.source_type = "github"
        scan.source_url = "https://github.com/tiennesdm/CodeShield-AI"
        scan.status = "completed"
        
        settings = get_settings()
        clone_dir = settings.temp_dir / f"github_patched_download_{scan_id}_CodeShield-AI"
        clone_dir.mkdir(parents=True, exist_ok=True)
        
        # Create mock file in the clone directory
        src_dir = clone_dir / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        with open(src_dir / "app.py", "w") as f:
            f.write("cursor.execute(query)\n")
            
        asyncio.run(db.save_scan(scan))

        try:
            with patch("scanner.github_handler.GitHubHandler.clone_repository", new_callable=AsyncMock) as mock_clone:
                mock_clone.return_value = str(clone_dir)
                response = client.get(f"/api/scan/{scan_id}/download")
                assert response.status_code == 200
                assert "application/zip" in response.headers["content-type"]
                assert f"patched_Test_Scan_{scan_id}.zip" in response.headers["content-disposition"]
                
                resp_zip_data = io.BytesIO(response.content)
                with zipfile.ZipFile(resp_zip_data, "r") as zf:
                    file_list = zf.namelist()
                    assert "src/app.py" in file_list
        finally:
            asyncio.run(db.delete_scan(scan_id))
            import shutil
            shutil.rmtree(clone_dir, ignore_errors=True)


class TestWorkflowEndpoints:
    """Test Custom Swarm Workflows and Compliance Integration."""

    def test_list_workflows(self):
        """Test listing available agentic workflows."""
        response = client.get("/api/agents/workflows")
        assert response.status_code == 200
        data = response.json()
        assert "workflows" in data
        assert "total" in data
        assert data["total"] > 0
        
        # Verify workflow list keys
        workflows = data["workflows"]
        first_wf = workflows[0]
        assert "workflow_id" in first_wf
        assert "name" in first_wf
        assert "description" in first_wf
        assert "required_agents" in first_wf

    def test_generate_compliance_report_frameworks(self):
        """Test listing available compliance frameworks."""
        response = client.get("/api/compliance/frameworks")
        assert response.status_code == 200
        data = response.json()
        assert "frameworks" in data
        assert "total" in data
        assert data["total"] > 0

    def test_generate_compliance_report_for_scan(self, setup_test_data):
        """Test generating compliance report for a specific scan."""
        import asyncio
        scan_id = "abcde123"
        scan = create_test_scan_in_db(scan_id)
        scan.status = "completed"
        import json
        scan_dict = json.loads(scan.model_dump_json())
        asyncio.run(db.save_scan(scan))

        try:
            response = client.post(
                "/api/compliance/report/soc2_type2",
                json={"scan_results": [scan_dict]}
            )
            assert response.status_code == 200
            data = response.json()
            assert "framework_id" in data
            assert data["framework_id"] == "soc2_type2"
            assert "executive_summary" in data
            assert "control_evidence" in data
        finally:
            asyncio.run(db.delete_scan(scan_id))


class TestGitScanEndpoints:
    """Test generic Git URLs and custom branch selection for repository scanning."""

    def test_scan_github_custom_branch_success(self):
        """Test successful scan trigger with custom branch selection."""
        payload = {
            "source_type": "github",
            "source_url": "https://github.com/tiennesdm/CodeShield-AI",
            "branch": "feature/testing-branch",
            "config": {
                "workflow_id": "full_scan",
                "tools": ["custom_ai"]
            }
        }
        
        with patch("scanner.github_handler.GitHubHandler.clone_repository", new_callable=AsyncMock) as mock_clone:
            mock_clone.return_value = "/tmp/fake_clone_dir"
            
            # Since _run_scan_with_cleanup runs in the background, we mock it to prevent side-effects
            with patch("main._run_scan_with_cleanup", new_callable=AsyncMock) as mock_run:
                response = client.post("/api/scan/github", json=payload)
                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "running"
                assert "scan_id" in data
                
                # Check that cloning was called with branch parameter
                mock_clone.assert_called_once_with(
                    "https://github.com/tiennesdm/CodeShield-AI",
                    data["scan_id"],
                    branch="feature/testing-branch"
                )

    def test_scan_gitlab_success(self):
        """Test successful scan trigger with GitLab repository URL."""
        payload = {
            "source_type": "git",
            "source_url": "https://gitlab.com/tiennesdm/CodeShield-AI",
            "branch": "main",
            "config": {
                "workflow_id": "full_scan"
            }
        }
        
        with patch("scanner.github_handler.GitHubHandler.clone_repository", new_callable=AsyncMock) as mock_clone:
            mock_clone.return_value = "/tmp/fake_clone_dir"
            with patch("main._run_scan_with_cleanup", new_callable=AsyncMock) as mock_run:
                response = client.post("/api/scan/github", json=payload)
                assert response.status_code == 200
                data = response.json()
                assert data["status"] == "running"
                
                mock_clone.assert_called_once_with(
                    "https://gitlab.com/tiennesdm/CodeShield-AI",
                    data["scan_id"],
                    branch="main"
                )

    def test_scan_git_invalid_url(self):
        """Test scanning fails with invalid Git URL hosting domain."""
        payload = {
            "source_type": "git",
            "source_url": "https://some-other-host.com/tiennesdm/CodeShield-AI"
        }
        response = client.post("/api/scan/github", json=payload)
        assert response.status_code == 422
        assert any("Git URL" in d["msg"] or "Invalid Git URL" in d["msg"] for d in response.json()["detail"])





