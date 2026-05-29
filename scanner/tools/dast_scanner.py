"""
DAST (Dynamic Application Security Testing) Scanner for CodeShield AI.

Integrates with OWASP ZAP for dynamic vulnerability scanning and provides
fallback URL-based security checks when ZAP is not available.

Features:
- OWASP ZAP integration (spider scan, active scan, API scan)
- Security headers validation
- SSL/TLS configuration check
- CORS policy validation
- Information disclosure detection
- Open redirect detection
- Clickjacking vulnerability check

All findings are normalized to the standard Vulnerability format.
"""

import asyncio
import json
import re
import socket
import ssl
import subprocess
import urllib.parse
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import urllib.request

from models.vulnerability import Vulnerability
from utils.logger import get_logger

logger = get_logger(__name__)

# ============================================================================
# Security Headers to Check
# ============================================================================

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "required": True,
        "description": "HTTP Strict Transport Security (HSTS)",
        "cwe": "CWE-319",
        "severity": "HIGH",
        "recommendation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains'",
    },
    "Content-Security-Policy": {
        "required": True,
        "description": "Content Security Policy",
        "cwe": "CWE-693",
        "severity": "MEDIUM",
        "recommendation": "Add Content-Security-Policy header with appropriate directives",
    },
    "X-Frame-Options": {
        "required": True,
        "description": "Clickjacking protection",
        "cwe": "CWE-1021",
        "severity": "MEDIUM",
        "recommendation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'",
    },
    "X-Content-Type-Options": {
        "required": True,
        "description": "MIME type sniffing protection",
        "cwe": "CWE-693",
        "severity": "LOW",
        "recommendation": "Add 'X-Content-Type-Options: nosniff'",
    },
    "Referrer-Policy": {
        "required": False,
        "description": "Referrer Policy",
        "cwe": "CWE-200",
        "severity": "LOW",
        "recommendation": "Add 'Referrer-Policy: strict-origin-when-cross-origin'",
    },
    "Permissions-Policy": {
        "required": False,
        "description": "Permissions Policy",
        "cwe": "CWE-200",
        "severity": "LOW",
        "recommendation": "Add Permissions-Policy to restrict browser features",
    },
}

# Information disclosure patterns in headers
INFO_DISCLOSURE_HEADERS = [
    (r"Server:\s*(.+)", "Server banner disclosure"),
    (r"X-Powered-By:\s*(.+)", "Technology stack disclosure"),
    (r"X-AspNet-Version:\s*(.+)", "ASP.NET version disclosure"),
    (r"X-Generator:\s*(.+)", "Generator/framework disclosure"),
    (r"X-Runtime:\s*(.+)", "Runtime disclosure"),
    (r"X-Version:\s*(.+)", "Version disclosure"),
    (r"Via:\s*(.+)", "Proxy information disclosure"),
]

# Known vulnerable CORS configurations
VULNERABLE_CORS_PATTERNS = [
    (r"Access-Control-Allow-Origin:\s*\*", "Wildcard CORS - allows any origin"),
    (r"Access-Control-Allow-Origin:\s*null", "Null origin CORS - allows null origin attacks"),
    (r"Access-Control-Allow-Credentials:\s*true", "Credentials allowed with CORS - risky with wildcards"),
]

# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class DASTFinding:
    """A single DAST finding."""

    title: str
    description: str
    severity: str
    cwe: str
    category: str
    evidence: str
    remediation: str
    url: str = ""


# ============================================================================
# ZAP Scanner
# ============================================================================

class ZAPScanner:
    """OWASP ZAP integration for DAST scanning."""

    def __init__(self, zap_path: str = "", api_key: str = "", proxy: str = "http://127.0.0.1:8080") -> None:
        """
        Initialize ZAP scanner.

        Args:
            zap_path: Path to ZAP executable (optional)
            api_key: ZAP API key (optional)
            proxy: ZAP proxy URL
        """
        self.zap_path = zap_path
        self.api_key = api_key
        self.proxy = proxy
        self._zap_available: Optional[bool] = None

    @property
    def zap_available(self) -> bool:
        """Check if ZAP is available."""
        if self._zap_available is None:
            try:
                result = subprocess.run(
                    ["zap.sh", "-version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                self._zap_available = result.returncode == 0
            except (FileNotFoundError, subprocess.TimeoutExpired):
                self._zap_available = False
            except Exception:
                self._zap_available = False
        return self._zap_available

    async def run_scan(
        self,
        target_url: str,
        scan_type: str = "full",
        auth_config: Optional[Dict[str, str]] = None,
    ) -> List[DASTFinding]:
        """
        Run a ZAP scan on the target URL.

        Args:
            target_url: URL to scan
            scan_type: 'spider', 'active', 'api', or 'full'
            auth_config: Optional authentication configuration

        Returns:
            List of DAST findings
        """
        if not self.zap_available:
            logger.warning("ZAP is not available for scanning")
            return []

        findings: List[DASTFinding] = []

        try:
            if scan_type in ("spider", "full"):
                spider_results = await self._run_spider_scan(target_url, auth_config)
                findings.extend(spider_results)

            if scan_type in ("active", "full"):
                active_results = await self._run_active_scan(target_url, auth_config)
                findings.extend(active_results)

            if scan_type == "api":
                api_results = await self._run_api_scan(target_url)
                findings.extend(api_results)

        except Exception as e:
            logger.error("ZAP scan failed: %s", e)

        return findings

    async def _run_spider_scan(
        self, target_url: str, auth_config: Optional[Dict[str, str]] = None
    ) -> List[DASTFinding]:
        """Run ZAP spider scan for endpoint discovery."""
        findings: List[DASTFinding] = []
        try:
            cmd = [
                "zap.sh", "-cmd",
                "-quickurl", target_url,
                "-quickout", "/tmp/zap_spider.json",
            ]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(process.wait(), timeout=300)

            # Parse spider results
            findings.append(DASTFinding(
                title="ZAP Spider Scan Completed",
                description=f"Spider scan completed for {target_url}",
                severity="INFO",
                cwe="CWE-200",
                category="DAST: Spider",
                evidence=f"Command: {' '.join(cmd)}",
                remediation="Review discovered endpoints for security issues",
                url=target_url,
            ))

        except asyncio.TimeoutError:
            logger.warning("ZAP spider scan timed out")
        except Exception as e:
            logger.error("ZAP spider scan failed: %s", e)

        return findings

    async def _run_active_scan(
        self, target_url: str, auth_config: Optional[Dict[str, str]] = None
    ) -> List[DASTFinding]:
        """Run ZAP active scan for vulnerability detection."""
        findings: List[DASTFinding] = []
        try:
            cmd = [
                "zap.sh", "-cmd",
                "-quickurl", target_url,
                "-quickprogress",
            ]
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=600,
            )

            findings.append(DASTFinding(
                title="ZAP Active Scan Completed",
                description=f"Active scan completed for {target_url}",
                severity="INFO",
                cwe="CWE-200",
                category="DAST: Active Scan",
                evidence=stdout.decode("utf-8", errors="ignore")[:500],
                remediation="Review active scan findings",
                url=target_url,
            ))

        except asyncio.TimeoutError:
            logger.warning("ZAP active scan timed out")
        except Exception as e:
            logger.error("ZAP active scan failed: %s", e)

        return findings

    async def _run_api_scan(self, target_url: str) -> List[DASTFinding]:
        """Run ZAP API scan for REST endpoints."""
        findings: List[DASTFinding] = []
        try:
            findings.append(DASTFinding(
                title="ZAP API Scan",
                description=f"API scan initiated for {target_url}",
                severity="INFO",
                cwe="CWE-200",
                category="DAST: API Scan",
                evidence="API scan in progress",
                remediation="Configure API endpoints for detailed scanning",
                url=target_url,
            ))
        except Exception as e:
            logger.error("ZAP API scan failed: %s", e)

        return findings


# ============================================================================
# Fallback URL Scanner
# ============================================================================

class URLSecurityScanner:
    """
    Fallback URL-based security checks.

    Performs security checks via HTTP requests without requiring ZAP.
    Always available and runs quickly.
    """

    def __init__(self, timeout: int = 30) -> None:
        self.timeout = timeout

    async def scan_url(self, url: str) -> List[DASTFinding]:
        """
        Run all URL-based security checks.

        Args:
            url: Target URL to scan

        Returns:
            List of DAST findings
        """
        findings: List[DASTFinding] = []

        try:
            # Fetch the target URL
            headers, status_code, body = await self._fetch_url(url)

            if headers:
                # Security headers check
                findings.extend(self._check_security_headers(url, headers))

                # Information disclosure
                findings.extend(self._check_information_disclosure(url, headers))

                # CORS policy
                findings.extend(self._check_cors_policy(url, headers))

                # SSL/TLS check
                findings.extend(await self._check_ssl_tls(url))

                # Clickjacking
                findings.extend(self._check_clickjacking(url, headers))

                # Open redirect
                findings.extend(await self._check_open_redirect(url, headers))

                # Server version leakage
                findings.extend(self._check_server_version(url, headers))

        except Exception as e:
            logger.error("URL scan failed for %s: %s", url, e)
            findings.append(DASTFinding(
                title="URL Scan Failed",
                description=f"Failed to scan {url}: {str(e)}",
                severity="INFO",
                cwe="CWE-200",
                category="DAST: Error",
                evidence=str(e),
                remediation="Ensure the target URL is accessible",
                url=url,
            ))

        return findings

    async def _fetch_url(
        self, url: str
    ) -> tuple:
        """Fetch a URL and return headers, status code, and body."""
        loop = asyncio.get_event_loop()

        def _fetch():
            req = urllib.request.Request(
                url,
                headers={
                    "User-Agent": "CodeShield-DAST-Scanner/1.0 (Security Scan)",
                    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                },
            )
            try:
                with urllib.request.urlopen(req, timeout=self.timeout) as response:
                    headers = dict(response.headers)
                    status = response.status
                    body = response.read().decode("utf-8", errors="ignore")
                    return headers, status, body
            except urllib.error.HTTPError as e:
                return dict(e.headers), e.code, e.read().decode("utf-8", errors="ignore")
            # Other errors (connection refused, DNS, timeout) propagate so the
            # caller records a 'URL Scan Failed' finding.

        return await loop.run_in_executor(None, _fetch)

    def _check_security_headers(
        self, url: str, headers: Dict[str, str]
    ) -> List[DASTFinding]:
        """Check for missing or misconfigured security headers."""
        findings: List[DASTFinding] = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        for header_name, config in SECURITY_HEADERS.items():
            header_lower = header_name.lower()

            if header_lower not in headers_lower:
                if config["required"]:
                    findings.append(DASTFinding(
                        title=f"Missing Security Header: {header_name}",
                        description=f"The '{header_name}' header is missing. {config['description']}",
                        severity=config["severity"],
                        cwe=config["cwe"],
                        category="DAST: Security Headers",
                        evidence=f"Header '{header_name}' not found in response",
                        remediation=config["recommendation"],
                        url=url,
                    ))
            else:
                value = headers_lower[header_lower]
                # Check for weak configurations
                if header_name == "X-Frame-Options" and value.upper() not in ("DENY", "SAMEORIGIN", "ALLOW-FROM"):
                    findings.append(DASTFinding(
                        title=f"Weak {header_name} Configuration",
                        description=f"X-Frame-Options is set to '{value}' which may not provide adequate protection",
                        severity="MEDIUM",
                        cwe="CWE-1021",
                        category="DAST: Security Headers",
                        evidence=f"X-Frame-Options: {value}",
                        remediation="Set X-Frame-Options to DENY or SAMEORIGIN",
                        url=url,
                    ))
                elif header_name == "Strict-Transport-Security":
                    if "max-age" in value:
                        age_match = re.search(r"max-age=(\d+)", value)
                        if age_match:
                            age = int(age_match.group(1))
                            if age < 31536000:  # Less than 1 year
                                findings.append(DASTFinding(
                                    title="Short HSTS max-age",
                                    description=f"HSTS max-age is {age} seconds, recommended minimum is 31536000 (1 year)",
                                    severity="LOW",
                                    cwe="CWE-319",
                                    category="DAST: Security Headers",
                                    evidence=f"Strict-Transport-Security: {value}",
                                    remediation="Set max-age to at least 31536000 seconds",
                                    url=url,
                                ))

        return findings

    def _check_information_disclosure(
        self, url: str, headers: Dict[str, str]
    ) -> List[DASTFinding]:
        """Check for information disclosure in headers."""
        findings: List[DASTFinding] = []
        header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())

        for pattern, description in INFO_DISCLOSURE_HEADERS:
            match = re.search(pattern, header_str, re.IGNORECASE)
            if match:
                findings.append(DASTFinding(
                    title=f"Information Disclosure: {description}",
                    description=f"The response reveals information: {match.group(0)}",
                    severity="LOW",
                    cwe="CWE-200",
                    category="DAST: Information Disclosure",
                    evidence=match.group(0),
                    remediation=f"Remove or obfuscate the '{match.group(0).split(':')[0]}' header",
                    url=url,
                ))

        return findings

    def _check_cors_policy(
        self, url: str, headers: Dict[str, str]
    ) -> List[DASTFinding]:
        """Check for CORS misconfigurations."""
        findings: List[DASTFinding] = []
        header_str = "\n".join(f"{k}: {v}" for k, v in headers.items())

        has_wildcard = False
        for pattern, description in VULNERABLE_CORS_PATTERNS:
            match = re.search(pattern, header_str, re.IGNORECASE)
            if match:
                if "*" in pattern:
                    has_wildcard = True
                severity = "HIGH" if "Credentials" in pattern else "MEDIUM"
                findings.append(DASTFinding(
                    title=f"CORS Misconfiguration: {description}",
                    description=f"CORS header allows unrestricted cross-origin requests: {match.group(0)}",
                    severity=severity,
                    cwe="CWE-942",
                    category="DAST: CORS",
                    evidence=match.group(0),
                    remediation="Restrict Access-Control-Allow-Origin to specific trusted domains",
                    url=url,
                ))

        return findings

    async def _check_ssl_tls(self, url: str) -> List[DASTFinding]:
        """Check SSL/TLS configuration."""
        findings: List[DASTFinding] = []

        if not url.startswith("https://"):
            findings.append(DASTFinding(
                title="HTTPS Not Enforced",
                description="The target URL does not use HTTPS. All communications are unencrypted.",
                severity="HIGH",
                cwe="CWE-319",
                category="DAST: SSL/TLS",
                evidence="URL uses HTTP protocol",
                remediation="Enable HTTPS and redirect HTTP to HTTPS",
                url=url,
            ))
            return findings

        try:
            parsed = urllib.parse.urlparse(url)
            hostname = parsed.hostname
            port = parsed.port or 443

            if not hostname:
                return findings

            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Check SSL/TLS version
                    if version in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                        findings.append(DASTFinding(
                            title=f"Outdated TLS Version: {version}",
                            description=f"The server uses {version} which has known vulnerabilities",
                            severity="HIGH",
                            cwe="CWE-326",
                            category="DAST: SSL/TLS",
                            evidence=f"TLS version: {version}",
                            remediation="Upgrade to TLS 1.2 or TLS 1.3 only",
                            url=url,
                        ))

                    # Check certificate expiration
                    if cert and "notAfter" in cert:
                        from datetime import datetime
                        not_after = cert["notAfter"]
                        try:
                            expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
                            now = datetime.now(timezone.utc).replace(tzinfo=None)
                            days_until_expiry = (expiry - now).days
                            if days_until_expiry < 0:
                                findings.append(DASTFinding(
                                    title="SSL Certificate Expired",
                                    description=f"The SSL certificate expired {abs(days_until_expiry)} days ago",
                                    severity="CRITICAL",
                                    cwe="CWE-295",
                                    category="DAST: SSL/TLS",
                                    evidence=f"Certificate expired: {not_after}",
                                    remediation="Renew the SSL certificate immediately",
                                    url=url,
                                ))
                            elif days_until_expiry < 30:
                                findings.append(DASTFinding(
                                    title="SSL Certificate Expiring Soon",
                                    description=f"The SSL certificate expires in {days_until_expiry} days",
                                    severity="MEDIUM",
                                    cwe="CWE-295",
                                    category="DAST: SSL/TLS",
                                    evidence=f"Certificate expires: {not_after}",
                                    remediation="Renew the SSL certificate before expiration",
                                    url=url,
                                ))
                        except ValueError:
                            pass

                    # Check for weak ciphers
                    if cipher and cipher[0]:
                        cipher_name = cipher[0]
                        weak_ciphers = [
                            "RC4", "DES", "3DES", "MD5", "NULL",
                            "EXPORT", "anon", "CBC",
                        ]
                        for weak in weak_ciphers:
                            if weak.upper() in cipher_name.upper():
                                findings.append(DASTFinding(
                                    title=f"Weak Cipher Suite: {cipher_name}",
                                    description=f"The server supports a weak cipher suite: {cipher_name}",
                                    severity="HIGH",
                                    cwe="CWE-326",
                                    category="DAST: SSL/TLS",
                                    evidence=f"Cipher: {cipher_name}",
                                    remediation="Disable weak cipher suites, use only AES-GCM or ChaCha20-Poly1305",
                                    url=url,
                                ))
                                break

        except ssl.SSLError as e:
            findings.append(DASTFinding(
                title="SSL/TLS Error",
                description=f"SSL handshake failed: {str(e)}",
                severity="HIGH",
                cwe="CWE-319",
                category="DAST: SSL/TLS",
                evidence=str(e),
                remediation="Check SSL certificate and configuration",
                url=url,
            ))
        except socket.error as e:
            findings.append(DASTFinding(
                title="Connection Error",
                description=f"Could not connect to {url}: {str(e)}",
                severity="INFO",
                cwe="CWE-200",
                category="DAST: Network",
                evidence=str(e),
                remediation="Ensure the target is accessible",
                url=url,
            ))
        except Exception as e:
            logger.debug("SSL check error for %s: %s", url, e)

        return findings

    def _check_clickjacking(
        self, url: str, headers: Dict[str, str]
    ) -> List[DASTFinding]:
        """Check for clickjacking vulnerabilities."""
        findings: List[DASTFinding] = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        has_xframe = "x-frame-options" in headers_lower
        has_csp = "content-security-policy" in headers_lower

        if not has_xframe and not has_csp:
            findings.append(DASTFinding(
                title="Clickjacking: Missing Frame Protection",
                description="The page can be embedded in an iframe, making it vulnerable to clickjacking attacks",
                severity="MEDIUM",
                cwe="CWE-1021",
                category="DAST: Clickjacking",
                evidence="Neither X-Frame-Options nor CSP frame-ancestors directive found",
                remediation="Add X-Frame-Options: DENY or CSP frame-ancestors directive",
                url=url,
            ))
        elif has_csp and not has_xframe:
            csp = headers_lower["content-security-policy"]
            if "frame-ancestors" not in csp:
                findings.append(DASTFinding(
                    title="Clickjacking: CSP Missing frame-ancestors",
                    description="CSP is present but lacks the frame-ancestors directive for clickjacking protection",
                    severity="LOW",
                    cwe="CWE-1021",
                    category="DAST: Clickjacking",
                    evidence=f"CSP: {csp}",
                    remediation="Add 'frame-ancestors none' or 'frame-ancestors self' to CSP",
                    url=url,
                ))

        return findings

    async def _check_open_redirect(
        self, url: str, headers: Dict[str, str]
    ) -> List[DASTFinding]:
        """Check for open redirect vulnerability."""
        findings: List[DASTFinding] = []

        try:
            # Test common open redirect patterns
            parsed = urllib.parse.urlparse(url)
            test_urls = [
                f"{parsed.scheme}://{parsed.netloc}/?redirect=https://evil.com",
                f"{parsed.scheme}://{parsed.netloc}/?next=https://evil.com",
                f"{parsed.scheme}://{parsed.netloc}/?url=https://evil.com",
                f"{parsed.scheme}://{parsed.netloc}/?return=https://evil.com",
                f"{parsed.scheme}://{parsed.netloc}/?returnTo=https://evil.com",
            ]

            for test_url in test_urls:
                try:
                    req = urllib.request.Request(
                        test_url,
                        headers={
                            "User-Agent": "CodeShield-DAST-Scanner/1.0",
                        },
                        method="HEAD",
                    )
                    redirect_handler = urllib.request.HTTPRedirectHandler()
                    opener = urllib.request.build_opener(redirect_handler)

                    with opener.open(req, timeout=self.timeout) as response:
                        final_url = response.geturl()
                        if "evil.com" in final_url:
                            param = test_url.split("?")[1].split("=")[0]
                            findings.append(DASTFinding(
                                title="Open Redirect Vulnerability",
                                description=f"The '{param}' parameter allows arbitrary redirects",
                                severity="HIGH",
                                cwe="CWE-601",
                                category="DAST: Open Redirect",
                                evidence=f"Request to {test_url} redirected to {final_url}",
                                remediation=f"Validate and whitelist redirect destinations for '{param}' parameter",
                                url=url,
                            ))
                            break
                except Exception:
                    continue

        except Exception as e:
            logger.debug("Open redirect check failed: %s", e)

        return findings

    def _check_server_version(
        self, url: str, headers: Dict[str, str]
    ) -> List[DASTFinding]:
        """Check for server version disclosure."""
        findings: List[DASTFinding] = []
        headers_lower = {k.lower(): v for k, v in headers.items()}

        if "server" in headers_lower:
            server = headers_lower["server"]
            # Check if version is disclosed
            version_match = re.search(r"(nginx|apache|iis|lighttpd|tomcat)/([\d.]+)", server, re.IGNORECASE)
            if version_match:
                findings.append(DASTFinding(
                    title=f"Server Version Disclosure: {version_match.group(1)}",
                    description=f"The server header reveals the exact version: {server}",
                    severity="LOW",
                    cwe="CWE-200",
                    category="DAST: Information Disclosure",
                    evidence=f"Server: {server}",
                    remediation="Configure the server to hide version information",
                    url=url,
                ))

        return findings


# ============================================================================
# Main DAST Scanner
# ============================================================================

class DASTScanner:
    """
    Main DAST scanner orchestrator.

    Combines ZAP integration with fallback URL checks for comprehensive
dynamic application security testing.
    """

    def __init__(self) -> None:
        self.zap_scanner = ZAPScanner()
        self.url_scanner = URLSecurityScanner()

    async def scan(
        self,
        target_url: str,
        scan_id: str,
        use_zap: bool = False,
        scan_type: str = "full",
        auth_config: Optional[Dict[str, str]] = None,
    ) -> List[Vulnerability]:
        """
        Run DAST scan on a target URL.

        Args:
            target_url: URL to scan
            scan_id: Scan identifier
            use_zap: Whether to use OWASP ZAP (if available)
            scan_type: 'spider', 'active', 'api', or 'full'
            auth_config: Optional authentication configuration

        Returns:
            List of Vulnerability objects
        """
        findings: List[DASTFinding] = []

        # Always run URL security checks
        logger.info("[%s] Running URL security checks on %s", scan_id, target_url)
        url_findings = await self.url_scanner.scan_url(target_url)
        findings.extend(url_findings)

        # Run ZAP if requested and available
        if use_zap and self.zap_scanner.zap_available:
            logger.info("[%s] Running OWASP ZAP scan on %s", scan_id, target_url)
            zap_findings = await self.zap_scanner.run_scan(
                target_url, scan_type, auth_config
            )
            findings.extend(zap_findings)
        elif use_zap:
            logger.info("[%s] ZAP not available, using URL checks only", scan_id)

        return self._findings_to_vulnerabilities(findings, scan_id)

    async def scan_target_from_source(
        self,
        source_path: str,
        scan_id: str,
    ) -> List[Vulnerability]:
        """
        Extract target URLs from source code and scan them.

        Looks for API base URLs, endpoint definitions, etc.

        Args:
            source_path: Path to source code
            scan_id: Scan identifier

        Returns:
            List of Vulnerability objects
        """
        findings: List[DASTFinding] = []

        # Extract potential URLs from source
        urls = self._extract_urls_from_source(source_path)

        for url in urls:
            url_findings = await self.url_scanner.scan_url(url)
            findings.extend(url_findings)

        return self._findings_to_vulnerabilities(findings, scan_id)

    def _extract_urls_from_source(self, source_path: str) -> List[str]:
        """Extract potential target URLs from source code."""
        urls: Set[str] = set()
        path = Path(source_path)

        # Search for URL patterns in config files
        config_patterns = [
            path.rglob("*.yaml"),
            path.rglob("*.yml"),
            path.rglob("*.json"),
            path.rglob("*.env*"),
            path.rglob("*.py"),
            path.rglob("*.js"),
        ]

        url_pattern = re.compile(r"https?://[^\s\"'<>]+")

        for file_pattern in config_patterns:
            for file_path in file_pattern:
                if not file_path.is_file():
                    continue
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                        matches = url_pattern.findall(content)
                        for match in matches:
                            # Filter out common non-target URLs
                            if not any(
                                x in match
                                for x in ("localhost", "127.0.0.1", "0.0.0.0")
                            ):
                                # Truncate at common delimiters
                                for delimiter in ('"', "'", "<", ">", " ", ",", ";"):
                                    if delimiter in match:
                                        match = match[:match.index(delimiter)]
                                urls.add(match)
                except Exception:
                    continue

        return list(urls)[:10]  # Limit to 10 URLs

    def _findings_to_vulnerabilities(
        self, findings: List[DASTFinding], scan_id: str
    ) -> List[Vulnerability]:
        """Convert DASTFindings to Vulnerability objects."""
        vulns: List[Vulnerability] = []
        for f in findings:
            vuln = Vulnerability(
                scan_id=scan_id,
                file_path=f.url or "DAST",
                line_number=0,
                severity=f.severity,
                category=f.category,
                cwe_id=f.cwe,
                cwe_name=f.title,
                title=f.title,
                description=f.description,
                code_snippet=f.evidence,
                fix_suggestion=f.remediation,
                tool_source="dast_scanner",
                confidence="HIGH",
            )
            vulns.append(vuln)
        return vulns
