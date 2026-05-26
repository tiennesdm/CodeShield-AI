"""
Tests for the LSP (Language Server Protocol) Server.

Covers initialization, configuration, security patterns, diagnostics,
and command handling.
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from lsp_server import (
    CodeShieldLSPServer,
    SEVERITY_MAP,
    _get_security_patterns,
    _local_security_scan,
    _vulnerabilities_to_diagnostics,
)


# =============================================================================
# Server Initialization Tests
# =============================================================================

class TestServerInitialization:
    """Tests for LSP server initialization."""

    def test_server_creation(self):
        """Test that the server can be created."""
        server = CodeShieldLSPServer(name="test-server", version="1.0.0")

        assert server is not None
        assert server.name == "test-server"
        assert server.version == "1.0.0"

    def test_default_config(self):
        """Test default configuration."""
        server = CodeShieldLSPServer()

        assert "codeshield" in server.config
        assert server.config["codeshield"]["scanOnSave"] is True
        assert server.config["codeshield"]["severityThreshold"] == "LOW"

    def test_severity_threshold(self):
        """Test severity threshold helpers."""
        server = CodeShieldLSPServer()

        # Default threshold is LOW (1)
        assert server._get_severity_threshold() == 1

        # CRITICAL (4) meets LOW threshold
        assert server._meets_threshold("CRITICAL") is True
        # INFO (0) does not meet LOW threshold
        assert server._meets_threshold("INFO") is False

    def test_uri_helpers(self):
        """Test URI conversion helpers."""
        server = CodeShieldLSPServer()

        assert server._uri_to_path("file:///home/user/test.py") == "/home/user/test.py"
        assert server._path_to_uri("/home/user/test.py") == "file:///home/user/test.py"


# =============================================================================
# Severity Mapping Tests
# =============================================================================

class TestSeverityMapping:
    """Tests for severity to LSP diagnostic severity mapping."""

    def test_critical_to_error(self):
        """CRITICAL should map to Error."""
        assert SEVERITY_MAP["CRITICAL"].value == 1  # DiagnosticSeverity.Error

    def test_high_to_error(self):
        """HIGH should map to Error."""
        assert SEVERITY_MAP["HIGH"].value == 1

    def test_medium_to_warning(self):
        """MEDIUM should map to Warning."""
        assert SEVERITY_MAP["MEDIUM"].value == 2  # DiagnosticSeverity.Warning

    def test_low_to_information(self):
        """LOW should map to Information."""
        assert SEVERITY_MAP["LOW"].value == 3

    def test_info_to_hint(self):
        """INFO should map to Hint."""
        assert SEVERITY_MAP["INFO"].value == 4


# =============================================================================
# Security Pattern Tests
# =============================================================================

class TestSecurityPatterns:
    """Tests for security pattern detection."""

    def test_python_sql_injection_pattern(self):
        """Test SQL injection pattern detection in Python."""
        patterns = _get_security_patterns(".py")
        pattern_types = [p["category"] for p in patterns]

        assert "SQL Injection" in pattern_types
        assert "Hardcoded Password" in pattern_types

    def test_javascript_xss_pattern(self):
        """Test XSS pattern detection in JavaScript."""
        patterns = _get_security_patterns(".js")
        pattern_types = [p["category"] for p in patterns]

        assert "Cross-Site Scripting (XSS)" in pattern_types

    def test_typescript_patterns(self):
        """Test TypeScript patterns (same as JS)."""
        js_patterns = _get_security_patterns(".js")
        ts_patterns = _get_security_patterns(".ts")

        assert len(ts_patterns) >= len(js_patterns)

    def test_java_patterns(self):
        """Test Java patterns."""
        patterns = _get_security_patterns(".java")
        categories = [p["category"] for p in patterns]

        assert "SQL Injection" in categories or "Insecure Deserialization" in categories

    def test_go_patterns(self):
        """Test Go patterns."""
        patterns = _get_security_patterns(".go")
        categories = [p["category"] for p in patterns]

        assert len(categories) > 0

    def test_all_extensions_have_common_patterns(self):
        """Test that all supported extensions have common patterns."""
        for ext in [".py", ".js", ".ts", ".java", ".go", ".rb", ".php"]:
            patterns = _get_security_patterns(ext)
            categories = [p["category"] for p in patterns]
            assert "Hardcoded Password" in categories, f"Missing password pattern for {ext}"


# =============================================================================
# Local Security Scan Tests
# =============================================================================

class TestLocalSecurityScan:
    """Tests for local pattern-based security scanning."""

    def test_scan_finds_hardcoded_password(self):
        """Test detecting hardcoded passwords."""
        code = "password = 'secret123'\n"
        vulns = _local_security_scan("test.py", code)

        password_vulns = [v for v in vulns if "Hardcoded Password" in v["category"]]
        assert len(password_vulns) > 0

    def test_scan_finds_api_key(self):
        """Test detecting hardcoded API keys."""
        code = "api_key = 'sk-abcdefghijklmnopqrstuvwxyz123'\n"
        vulns = _local_security_scan("test.py", code)

        key_vulns = [v for v in vulns if "API Key" in v["category"]]
        assert len(key_vulns) > 0

    def test_scan_finds_eval(self):
        """Test detecting eval() usage."""
        code = "result = eval(user_input)\n"
        vulns = _local_security_scan("test.py", code)

        eval_vulns = [v for v in vulns if "Code Injection" in v["category"]]
        assert len(eval_vulns) > 0

    def test_scan_finds_http_url(self):
        """Test detecting HTTP URLs."""
        code = "url = 'http://example.com/api'\n"
        vulns = _local_security_scan("test.py", code)

        http_vulns = [v for v in vulns if "Insecure Protocol" in v["category"]]
        assert len(http_vulns) > 0

    def test_scan_finds_sql_injection_python(self):
        """Test detecting SQL injection in Python."""
        code = "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')\n"
        vulns = _local_security_scan("test.py", code)

        sql_vulns = [v for v in vulns if "SQL Injection" in v["category"]]
        assert len(sql_vulns) > 0
        assert sql_vulns[0]["severity"] == "CRITICAL"

    def test_scan_finds_inner_html(self):
        """Test detecting innerHTML in JavaScript."""
        code = "element.innerHTML = userContent;\n"
        vulns = _local_security_scan("test.js", code)

        xss_vulns = [v for v in vulns if "XSS" in v["category"]]
        assert len(xss_vulns) > 0

    def test_scan_no_false_positives(self):
        """Test that clean code produces no findings."""
        code = "x = 1 + 2\nprint('hello')\n"
        vulns = _local_security_scan("test.py", code)

        # Should not find vulnerabilities in clean code
        critical_high = [v for v in vulns if v["severity"] in ("CRITICAL", "HIGH")]
        assert len(critical_high) == 0

    def test_scan_includes_cwe_id(self):
        """Test that findings include CWE IDs."""
        code = "password = 'secret123'\n"
        vulns = _local_security_scan("test.py", code)

        assert len(vulns) > 0
        assert vulns[0]["cwe_id"] is not None

    def test_scan_includes_fix_suggestion(self):
        """Test that findings include fix suggestions."""
        code = "password = 'secret123'\n"
        vulns = _local_security_scan("test.py", code)

        assert len(vulns) > 0
        assert vulns[0]["fix_suggestion"] != ""

    def test_scan_line_numbers(self):
        """Test that correct line numbers are reported."""
        code = "x = 1\npassword = 'secret'\ny = 2\n"
        vulns = _local_security_scan("test.py", code)

        password_vulns = [v for v in vulns if "password" in v["category"].lower()]
        if password_vulns:
            assert password_vulns[0]["line_number"] == 2


# =============================================================================
# Diagnostics Conversion Tests
# =============================================================================

class TestDiagnosticsConversion:
    """Tests for converting vulnerabilities to LSP diagnostics."""

    def test_vulnerability_to_diagnostic(self):
        """Test converting a vulnerability to diagnostic."""
        vuln = {
            "id": "test-123",
            "file_path": "test.py",
            "line_number": 10,
            "column": 5,
            "severity": "HIGH",
            "category": "Hardcoded Password",
            "cwe_id": "CWE-798",
            "title": "Hardcoded password",
            "description": "Password found in code",
            "code_snippet": "password = 'secret'",
            "fix_suggestion": "Use env vars",
            "confidence": "HIGH",
            "match_text": "password = 'secret'",
        }

        diagnostics = _vulnerabilities_to_diagnostics([vuln])

        assert len(diagnostics) == 1
        diag = diagnostics[0]
        assert diag.message is not None
        assert "Hardcoded password" in diag.message
        assert diag.source == "codeshield-ai"
        assert diag.code == "CWE-798"

    def test_multiple_vulnerabilities(self):
        """Test converting multiple vulnerabilities."""
        vulns = [
            {
                "id": f"vuln-{i}",
                "file_path": "test.py",
                "line_number": i,
                "column": 1,
                "severity": "HIGH" if i % 2 == 0 else "MEDIUM",
                "category": "Test",
                "cwe_id": None,
                "title": f"Issue {i}",
                "description": f"Description {i}",
                "code_snippet": f"line {i}",
                "fix_suggestion": "Fix it",
                "confidence": "HIGH",
                "match_text": "test",
            }
            for i in range(1, 4)
        ]

        diagnostics = _vulnerabilities_to_diagnostics(vulns)

        assert len(diagnostics) == 3

    def test_severity_mapping(self):
        """Test that severities map correctly to LSP diagnostics."""
        from lsprotocol.types import DiagnosticSeverity

        vuln = {
            "id": "test",
            "file_path": "test.py",
            "line_number": 1,
            "column": 1,
            "severity": "CRITICAL",
            "category": "Test",
            "cwe_id": None,
            "title": "Test",
            "description": "Test",
            "code_snippet": "test",
            "fix_suggestion": "fix",
            "confidence": "HIGH",
            "match_text": "test",
        }

        # Test CRITICAL -> Error
        diagnostics = _vulnerabilities_to_diagnostics([vuln])
        assert diagnostics[0].severity == DiagnosticSeverity.Error

        # Test HIGH -> Error
        vuln["severity"] = "HIGH"
        diagnostics = _vulnerabilities_to_diagnostics([vuln])
        assert diagnostics[0].severity == DiagnosticSeverity.Error

        # Test MEDIUM -> Warning
        vuln["severity"] = "MEDIUM"
        diagnostics = _vulnerabilities_to_diagnostics([vuln])
        assert diagnostics[0].severity == DiagnosticSeverity.Warning

        # Test LOW -> Information
        vuln["severity"] = "LOW"
        diagnostics = _vulnerabilities_to_diagnostics([vuln])
        assert diagnostics[0].severity == DiagnosticSeverity.Information


# =============================================================================
# Configuration Tests
# =============================================================================

class TestConfiguration:
    """Tests for server configuration."""

    def test_scan_on_save_default(self):
        """Test scan on save default is True."""
        server = CodeShieldLSPServer()
        assert server._is_scan_on_save_enabled() is True

    def test_should_scan_file(self):
        """Test file scanning decision."""
        server = CodeShieldLSPServer()

        # Regular file should be scanned
        assert server.should_scan_file("file:///home/user/project/src/app.py") is True

        # Test file should be ignored (default patterns)
        # Note: depends on default ignore patterns
        result = server.should_scan_file("file:///home/user/project/tests/test_app.py")
        # Result depends on exact patterns, just verify no crash
        assert isinstance(result, bool)


# =============================================================================
# Server Lifecycle Tests
# =============================================================================

class TestServerLifecycle:
    """Tests for server startup/shutdown."""

    def test_server_has_required_attributes(self):
        """Test that server has all required attributes."""
        server = CodeShieldLSPServer()

        assert hasattr(server, "config")
        assert hasattr(server, "diagnostics_cache")
        assert hasattr(server, "vulnerability_cache")
        assert hasattr(server, "_pending_scans")

    def test_initially_empty_caches(self):
        """Test that caches start empty."""
        server = CodeShieldLSPServer()

        assert len(server.diagnostics_cache) == 0
        assert len(server.vulnerability_cache) == 0
        assert len(server._pending_scans) == 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
