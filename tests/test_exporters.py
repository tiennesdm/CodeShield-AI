"""
Tests for CodeShield AI exporters (SARIF, JUnit, JSON, HTML).

Tests export functionality for all supported formats.
"""

import json
import os
import sys
import tempfile
import xml.etree.ElementTree as ET
from datetime import datetime

# Ensure backend is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from models.vulnerability import ScanResult, Vulnerability

from exporters.sarif_exporter import SARIFExporter
from exporters.json_exporter import JSONExporter
from exporters.junit_exporter import JUnitExporter
from exporters.html_exporter import HTMLExporter


def create_test_scan():
    """Create a test ScanResult with sample vulnerabilities."""
    vulns = [
        Vulnerability(
            scan_id="test-scan-1",
            file_path="src/app.py",
            line_number=42,
            severity="CRITICAL",
            category="SQL Injection",
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            title="SQL Injection in app.py",
            description="User input directly used in SQL query",
            code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            fix_suggestion="Use parameterized queries.",
            tool_source="bandit",
            cvss_score=9.8,
            owasp_category="A03",
            confidence="HIGH",
            created_at=datetime(2024, 1, 15, 10, 30, 0),
        ),
        Vulnerability(
            scan_id="test-scan-1",
            file_path="config/settings.py",
            line_number=15,
            severity="HIGH",
            category="Hardcoded Secret",
            cwe_id="CWE-798",
            cwe_name="Hardcoded Credentials",
            title="Hardcoded API Key",
            description="API key hardcoded in settings file",
            code_snippet="API_KEY = 'sk-1234567890abcdef'",
            fix_suggestion="Use environment variables.",
            tool_source="custom_ai",
            cvss_score=7.5,
            owasp_category="A07",
            confidence="HIGH",
            created_at=datetime(2024, 1, 15, 10, 30, 0),
        ),
        Vulnerability(
            scan_id="test-scan-1",
            file_path="public/main.js",
            line_number=120,
            severity="MEDIUM",
            category="Cross-site Scripting (XSS)",
            cwe_id="CWE-79",
            cwe_name="Cross-site Scripting (XSS)",
            title="DOM-based XSS",
            description="innerHTML assignment with user input",
            code_snippet="element.innerHTML = userInput + '<br>'",
            fix_suggestion="Use textContent or sanitize input.",
            tool_source="semgrep",
            cvss_score=6.1,
            owasp_category="A03",
            confidence="MEDIUM",
            created_at=datetime(2024, 1, 15, 10, 30, 0),
        ),
        Vulnerability(
            scan_id="test-scan-1",
            file_path="utils/helpers.py",
            line_number=88,
            severity="LOW",
            category="Information Exposure",
            cwe_id="CWE-200",
            cwe_name="Information Exposure",
            title="Debug info exposed",
            description="Debug information exposed in response",
            code_snippet="return {'debug': True, 'stack': traceback}",
            fix_suggestion="Remove debug info from production.",
            tool_source="custom_ai",
            cvss_score=2.3,
            owasp_category="A05",
            confidence="LOW",
            created_at=datetime(2024, 1, 15, 10, 30, 0),
        ),
    ]

    return ScanResult(
        scan_id="test-scan-1",
        name="Test Scan",
        source_type="zip",
        source_path="/tmp/test_scan",
        status="completed",
        progress=100,
        start_time=datetime(2024, 1, 15, 10, 0, 0),
        end_time=datetime(2024, 1, 15, 10, 30, 0),
        languages=["python", "javascript"],
        total_files=45,
        total_lines=3250,
        scan_duration=1800,
        tools_used=["bandit", "semgrep", "custom_ai"],
        vulnerabilities=vulns,
        stats={"total": 4, "critical": 1, "high": 1, "medium": 1, "low": 1, "info": 0},
        risk_score=42,
    )


class TestSARIFExporter:
    """Tests for SARIF 2.1.0 exporter."""

    def test_export_structure(self):
        """Test that SARIF export has correct top-level structure."""
        scan = create_test_scan()
        exporter = SARIFExporter()
        result = exporter.export(scan)

        data = json.loads(result)
        assert data["$schema"] == "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
        assert data["version"] == "2.1.0"
        assert "runs" in data
        assert len(data["runs"]) == 1

    def test_run_structure(self):
        """Test SARIF run structure."""
        scan = create_test_scan()
        exporter = SARIFExporter()
        result = exporter.export(scan)

        data = json.loads(result)
        run = data["runs"][0]
        assert "tool" in run
        assert "results" in run
        assert "invocations" in run
        assert "properties" in run

    def test_tool_component(self):
        """Test tool driver has rules."""
        scan = create_test_scan()
        exporter = SARIFExporter()
        result = exporter.export(scan)

        data = json.loads(result)
        driver = data["runs"][0]["tool"]["driver"]
        assert driver["name"] == "CodeShield AI"
        assert "rules" in driver
        assert len(driver["rules"]) > 0

    def test_results_count(self):
        """Test that all vulnerabilities are exported as results."""
        scan = create_test_scan()
        exporter = SARIFExporter()
        result = exporter.export(scan)

        data = json.loads(result)
        results = data["runs"][0]["results"]
        assert len(results) == len(scan.vulnerabilities)

    def test_result_fields(self):
        """Test that each result has required SARIF fields."""
        scan = create_test_scan()
        exporter = SARIFExporter()
        result = exporter.export(scan)

        data = json.loads(result)
        for sarif_result in data["runs"][0]["results"]:
            assert "ruleId" in sarif_result
            assert "level" in sarif_result
            assert "message" in sarif_result
            assert "locations" in sarif_result
            assert "properties" in sarif_result

    def test_locations_present(self):
        """Test that locations are included in results."""
        scan = create_test_scan()
        exporter = SARIFExporter()
        result = exporter.export(scan)

        data = json.loads(result)
        for sarif_result in data["runs"][0]["results"]:
            locations = sarif_result["locations"]
            assert len(locations) > 0
            assert "physicalLocation" in locations[0]

    def test_export_to_file(self):
        """Test exporting to a file."""
        scan = create_test_scan()
        exporter = SARIFExporter()
        with tempfile.NamedTemporaryFile(suffix=".sarif", delete=False) as f:
            tmp = f.name
        try:
            exporter.export_to_file(scan, tmp)
            with open(tmp, "r") as f:
                data = json.load(f)
            assert "runs" in data
        finally:
            os.unlink(tmp)


class TestJSONExporter:
    """Tests for JSON exporter."""

    def test_export_structure(self):
        """Test JSON export structure."""
        scan = create_test_scan()
        exporter = JSONExporter()
        result = exporter.export(scan)

        data = json.loads(result)
        assert "export_metadata" in data
        assert "scan" in data
        assert "vulnerabilities" in data
        assert data["export_metadata"]["format"] == "json"

    def test_vulnerability_count(self):
        """Test all vulnerabilities are included."""
        scan = create_test_scan()
        exporter = JSONExporter()
        result = exporter.export(scan)

        data = json.loads(result)
        assert len(data["vulnerabilities"]) == len(scan.vulnerabilities)

    def test_scan_fields(self):
        """Test scan metadata is complete."""
        scan = create_test_scan()
        exporter = JSONExporter()
        result = exporter.export(scan)

        data = json.loads(result)
        scan_data = data["scan"]
        assert scan_data["scan_id"] == "test-scan-1"
        assert scan_data["name"] == "Test Scan"
        assert scan_data["status"] == "completed"
        assert scan_data["risk_score"] == 42

    def test_summary_export(self):
        """Test summary-only export."""
        scan = create_test_scan()
        exporter = JSONExporter()
        result = exporter.export_summary(scan)

        data = json.loads(result)
        assert "scan_id" in data
        assert "risk_score" in data
        assert "vulnerability_count" in data
        assert "vulnerabilities" not in data


class TestJUnitExporter:
    """Tests for JUnit XML exporter."""

    def test_export_structure(self):
        """Test JUnit XML has correct structure."""
        scan = create_test_scan()
        exporter = JUnitExporter()
        result = exporter.export(scan)

        assert '<?xml version="1.0" encoding="UTF-8"?>' in result
        assert "<testsuites>" in result
        assert "<testsuite" in result

    def test_testsuite_attributes(self):
        """Test testsuite has correct attributes."""
        scan = create_test_scan()
        exporter = JUnitExporter()
        result = exporter.export(scan)

        root = ET.fromstring(result.replace('<?xml version="1.0" encoding="UTF-8"?>', ''))
        testsuite = root.find("testsuite")
        assert testsuite is not None
        assert int(testsuite.get("tests")) == len(scan.vulnerabilities)
        assert int(testsuite.get("errors")) == 0

    def test_testcase_count(self):
        """Test correct number of test cases."""
        scan = create_test_scan()
        exporter = JUnitExporter()
        result = exporter.export(scan)

        root = ET.fromstring(result.replace('<?xml version="1.0" encoding="UTF-8"?>', ''))
        testsuite = root.find("testsuite")
        testcases = testsuite.findall("testcase")
        assert len(testcases) == len(scan.vulnerabilities)

    def test_failure_and_skipped(self):
        """Test that non-INFO vulns are failures and INFO are skipped."""
        scan = create_test_scan()
        exporter = JUnitExporter()
        result = exporter.export(scan)

        root = ET.fromstring(result.replace('<?xml version="1.0" encoding="UTF-8"?>', ''))
        testsuite = root.find("testsuite")
        failures = testsuite.findall(".//failure")
        skipped = testsuite.findall(".//skipped")

        # All our test vulns are CRITICAL, HIGH, MEDIUM, LOW (no INFO)
        assert len(failures) > 0
        assert len(skipped) == 0  # No INFO in test data

    def test_properties_present(self):
        """Test that properties are included."""
        scan = create_test_scan()
        exporter = JUnitExporter()
        result = exporter.export(scan)

        assert "scan_id" in result
        assert "risk_score" in result

    def test_export_to_file(self):
        """Test exporting to file."""
        scan = create_test_scan()
        exporter = JUnitExporter()
        with tempfile.NamedTemporaryFile(suffix=".xml", delete=False) as f:
            tmp = f.name
        try:
            exporter.export_to_file(scan, tmp)
            with open(tmp, "r") as f:
                content = f.read()
            assert "<testsuites>" in content
        finally:
            os.unlink(tmp)


class TestHTMLExporter:
    """Tests for HTML exporter."""

    def test_export_structure(self):
        """Test HTML export has correct structure."""
        scan = create_test_scan()
        exporter = HTMLExporter()
        result = exporter.export(scan)

        assert "<!DOCTYPE html>" in result
        assert "<html" in result
        assert "</html>" in result
        assert "CodeShield AI" in result

    def test_contains_vulnerability_data(self):
        """Test that vulnerability data is in the HTML."""
        scan = create_test_scan()
        exporter = HTMLExporter()
        result = exporter.export(scan)

        # Check for vulnerability categories
        assert "SQL Injection" in result or "Hardcoded Secret" in result

    def test_contains_summary(self):
        """Test that summary data is in the HTML."""
        scan = create_test_scan()
        exporter = HTMLExporter()
        result = exporter.export(scan)

        assert "test-scan-1" in result

    def test_export_to_file(self):
        """Test exporting to file."""
        scan = create_test_scan()
        exporter = HTMLExporter()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as f:
            tmp = f.name
        try:
            exporter.export_to_file(scan, tmp)
            with open(tmp, "r") as f:
                content = f.read()
            assert "<!DOCTYPE html>" in content
        finally:
            os.unlink(tmp)
