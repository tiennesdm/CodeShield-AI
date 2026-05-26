"""
Tests for DAST Scanner.

Covers URL security checks, SSL/TLS validation, security headers,
CORS policy checks, information disclosure, clickjacking, and open redirects.
"""

import json
import os
import tempfile
from unittest.mock import MagicMock, patch

import pytest

from scanner.tools.dast_scanner import (
    DASTFinding,
    DASTScanner,
    URLSecurityScanner,
    ZAPScanner,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def url_scanner():
    """Create a URLSecurityScanner instance."""
    return URLSecurityScanner(timeout=10)


@pytest.fixture
def dast_scanner():
    """Create a DASTScanner instance."""
    return DASTScanner()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


def write_file(temp_dir: str, filename: str, content: str) -> str:
    """Helper to write a test file."""
    filepath = os.path.join(temp_dir, filename)
    with open(filepath, "w") as f:
        f.write(content)
    return filepath


# ============================================================================
# ZAP Scanner Tests
# ============================================================================

class TestZAPScanner:
    """Tests for OWASP ZAP integration."""

    def test_zap_not_available(self):
        """Test ZAP availability check."""
        with patch("shutil.which", return_value=None):
            zap = ZAPScanner()
            assert zap.zap_available is False

    def test_run_scan_without_zap(self):
        """Test that scan returns empty when ZAP is unavailable."""
        import asyncio

        zap = ZAPScanner()
        with patch.object(zap, "_zap_available", False):
            findings = asyncio.get_event_loop().run_until_complete(
                zap.run_scan("http://example.com")
            )
            assert len(findings) == 0

    def test_zap_scanner_init(self):
        """Test ZAP scanner initialization."""
        zap = ZAPScanner(
            zap_path="/opt/zap/zap.sh",
            api_key="test-key",
            proxy="http://127.0.0.1:8090",
        )
        assert zap.zap_path == "/opt/zap/zap.sh"
        assert zap.api_key == "test-key"
        assert zap.proxy == "http://127.0.0.1:8090"


# ============================================================================
# URL Security Scanner Tests
# ============================================================================

class TestURLSecurityScanner:
    """Tests for fallback URL security checks."""

    @patch("scanner.tools.dast_scanner.urllib.request.urlopen")
    def test_missing_security_headers(self, mock_urlopen, url_scanner):
        """Test detection of missing security headers."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.headers = {
            "Content-Type": "text/html",
            "Server": "nginx/1.18.0",
        }
        mock_response.geturl.return_value = "https://example.com"
        mock_response.read.return_value = b"<html></html>"
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        import asyncio
        findings = asyncio.get_event_loop().run_until_complete(
            url_scanner.scan_url("https://example.com")
        )

        # Should find missing HSTS, CSP, X-Frame-Options, X-Content-Type-Options
        hsts = [f for f in findings if "Strict-Transport-Security" in f.title]
        xframe = [f for f in findings if "X-Frame-Options" in f.title]
        assert len(hsts) > 0
        assert len(xframe) > 0

    @patch("scanner.tools.dast_scanner.urllib.request.urlopen")
    def test_security_headers_present(self, mock_urlopen, url_scanner):
        """Test that present security headers don't trigger findings."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.headers = {
            "Content-Type": "text/html",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'self'",
            "Referrer-Policy": "strict-origin-when-cross-origin",
        }
        mock_response.geturl.return_value = "https://example.com"
        mock_response.read.return_value = b"<html></html>"
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        import asyncio
        findings = asyncio.get_event_loop().run_until_complete(
            url_scanner.scan_url("https://example.com")
        )

        # Should have minimal findings with all headers present
        header_findings = [f for f in findings if "Missing" in f.title]
        assert len(header_findings) == 0

    @patch("scanner.tools.dast_scanner.urllib.request.urlopen")
    def test_information_disclosure(self, mock_urlopen, url_scanner):
        """Test detection of information disclosure headers."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.headers = {
            "Content-Type": "text/html",
            "Server": "Apache/2.4.41 (Ubuntu)",
            "X-Powered-By": "PHP/7.4.3",
            "X-AspNet-Version": "4.0.30319",
        }
        mock_response.geturl.return_value = "https://example.com"
        mock_response.read.return_value = b"<html></html>"
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        import asyncio
        findings = asyncio.get_event_loop().run_until_complete(
            url_scanner.scan_url("https://example.com")
        )

        info_disc = [f for f in findings if "Disclosure" in f.title]
        assert len(info_disc) > 0

    @patch("scanner.tools.dast_scanner.urllib.request.urlopen")
    def test_clickjacking_protection(self, mock_urlopen, url_scanner):
        """Test clickjacking detection."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.headers = {
            "Content-Type": "text/html",
        }
        mock_response.geturl.return_value = "https://example.com"
        mock_response.read.return_value = b"<html></html>"
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        import asyncio
        findings = asyncio.get_event_loop().run_until_complete(
            url_scanner.scan_url("https://example.com")
        )

        clickjack = [f for f in findings if "Clickjacking" in f.title]
        assert len(clickjack) > 0

    @patch("scanner.tools.dast_scanner.urllib.request.urlopen")
    def test_cors_wildcard(self, mock_urlopen, url_scanner):
        """Test CORS wildcard detection."""
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.headers = {
            "Content-Type": "text/html",
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": "true",
        }
        mock_response.geturl.return_value = "https://example.com"
        mock_response.read.return_value = b"<html></html>"
        mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)

        import asyncio
        findings = asyncio.get_event_loop().run_until_complete(
            url_scanner.scan_url("https://example.com")
        )

        cors = [f for f in findings if "CORS" in f.title]
        assert len(cors) > 0

    def test_http_url_warning(self, url_scanner):
        """Test that HTTP URLs trigger HTTPS warning."""
        with patch("scanner.tools.dast_scanner.urllib.request.urlopen") as mock:
            mock_response = MagicMock()
            mock_response.status = 200
            mock_response.headers = {"Content-Type": "text/html"}
            mock_response.geturl.return_value = "http://example.com"
            mock_response.read.return_value = b"<html></html>"
            mock.return_value.__enter__ = MagicMock(return_value=mock_response)
            mock.return_value.__exit__ = MagicMock(return_value=False)

            import asyncio
            findings = asyncio.get_event_loop().run_until_complete(
                url_scanner.scan_url("http://example.com")
            )

            https_warnings = [f for f in findings if "HTTPS Not Enforced" in f.title]
            assert len(https_warnings) > 0

    def test_server_version_disclosure(self, url_scanner):
        """Test server version disclosure detection."""
        headers = {
            "server": "nginx/1.18.0",
        }
        findings = url_scanner._check_server_version("https://example.com", headers)

        assert len(findings) > 0
        assert "nginx" in findings[0].title

    def test_weak_csp_frame_ancestors(self, url_scanner):
        """Test CSP missing frame-ancestors."""
        headers = {
            "content-security-policy": "default-src 'self'; script-src 'self'",
        }
        findings = url_scanner._check_clickjacking("https://example.com", headers)

        frame_anc = [f for f in findings if "frame-ancestors" in f.title]
        assert len(frame_anc) > 0

    def test_short_hsts_max_age(self, url_scanner):
        """Test detection of short HSTS max-age."""
        headers = {
            "strict-transport-security": "max-age=3600",
        }
        findings = url_scanner._check_security_headers("https://example.com", headers)

        short_hsts = [f for f in findings if "Short HSTS" in f.title]
        assert len(short_hsts) > 0

    def test_xframe_weak_value(self, url_scanner):
        """Test weak X-Frame-Options value."""
        headers = {
            "x-frame-options": "ALLOWALL",
        }
        findings = url_scanner._check_security_headers("https://example.com", headers)

        weak_xframe = [f for f in findings if "Weak X-Frame-Options" in f.title]
        assert len(weak_xframe) > 0

    def test_scan_url_error_handling(self, url_scanner):
        """Test error handling for unreachable URLs."""
        with patch("scanner.tools.dast_scanner.urllib.request.urlopen", side_effect=Exception("Connection refused")):
            import asyncio
            findings = asyncio.get_event_loop().run_until_complete(
                url_scanner.scan_url("https://nonexistent.invalid")
            )

            assert len(findings) > 0
            assert findings[0].title == "URL Scan Failed"


# ============================================================================
# DAST Scanner Integration Tests
# ============================================================================

class TestDASTScanner:
    """Integration tests for the main DAST scanner."""

    def test_dast_scanner_init(self):
        """Test DAST scanner initialization."""
        scanner = DASTScanner()
        assert scanner.zap_scanner is not None
        assert scanner.url_scanner is not None

    @patch("scanner.tools.dast_scanner.URLSecurityScanner.scan_url")
    def test_scan_with_target(self, mock_scan_url, dast_scanner):
        """Test scanning a target URL."""
        import asyncio

        mock_scan_url.return_value = [
            DASTFinding(
                title="Missing HSTS",
                description="HSTS header missing",
                severity="HIGH",
                cwe="CWE-319",
                category="DAST: Security Headers",
                evidence="Header not found",
                remediation="Add HSTS header",
                url="https://example.com",
            ),
        ]

        vulns = asyncio.get_event_loop().run_until_complete(
            dast_scanner.scan("https://example.com", "test-d1")
        )

        assert len(vulns) > 0
        mock_scan_url.assert_called_once()

    def test_findings_to_vulnerabilities(self, dast_scanner):
        """Test conversion of DAST findings to Vulnerabilities."""
        findings = [
            DASTFinding(
                title="Test Finding",
                description="Test description",
                severity="HIGH",
                cwe="CWE-79",
                category="DAST: XSS",
                evidence="Evidence here",
                remediation="Fix it",
                url="https://example.com",
            ),
        ]

        vulns = dast_scanner._findings_to_vulnerabilities(findings, "test-scan")
        assert len(vulns) == 1
        assert vulns[0].severity == "HIGH"
        assert vulns[0].category == "DAST: XSS"
        assert vulns[0].tool_source == "dast_scanner"

    def test_extract_urls_from_source(self, dast_scanner, temp_dir):
        """Test URL extraction from source code."""
        write_file(temp_dir, "config.py", """
BASE_URL = "https://api.example.com/v1"
WEBHOOK_URL = "https://hooks.example.com/webhook"
""")

        urls = dast_scanner._extract_urls_from_source(temp_dir)
        assert len(urls) > 0

    def test_extract_urls_ignores_localhost(self, dast_scanner, temp_dir):
        """Test that localhost URLs are filtered out."""
        write_file(temp_dir, "config.py", """
DEV_URL = "http://localhost:5000"
PROD_URL = "https://api.example.com"
""")

        urls = dast_scanner._extract_urls_from_source(temp_dir)
        assert all("localhost" not in url for url in urls)


# ============================================================================
# DASTFinding Data Class Tests
# ============================================================================

class TestDASTFinding:
    """Tests for DASTFinding data class."""

    def test_finding_creation(self):
        """Test creating a DASTFinding."""
        finding = DASTFinding(
            title="Test Title",
            description="Test description",
            severity="HIGH",
            cwe="CWE-89",
            category="DAST: SQL Injection",
            evidence="Some evidence",
            remediation="Fix the issue",
            url="https://example.com",
        )

        assert finding.title == "Test Title"
        assert finding.severity == "HIGH"
        assert finding.cwe == "CWE-89"
        assert finding.url == "https://example.com"

    def test_finding_with_empty_url(self):
        """Test creating a DASTFinding with empty URL."""
        finding = DASTFinding(
            title="Test",
            description="Test",
            severity="LOW",
            cwe="CWE-200",
            category="DAST: Info",
            evidence="",
            remediation="",
        )
        assert finding.url == ""
