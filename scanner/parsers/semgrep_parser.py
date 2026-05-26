"""
Semgrep JSON output parser for CodeShield AI.

Parses Semgrep JSON results into standardized Vulnerability objects.
"""

import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from models.vulnerability import Vulnerability
from utils.constants import CWE_MAPPING, SEVERITY_MAP
from utils.helpers import read_file_snippet
from utils.logger import get_logger

logger = get_logger(__name__)


class SemgrepParser:
    """
    Parser for Semgrep JSON output.

    Converts Semgrep findings into standardized Vulnerability models
    with CWE mapping and severity normalization.
    """

    def __init__(self) -> None:
        """Initialize the Semgrep parser."""
        self.tool_name = "semgrep"

    def parse(self, data: Dict[str, Any], scan_id: str, source_path: str) -> List[Vulnerability]:
        """
        Parse Semgrep JSON output into Vulnerability objects.

        Args:
            data: Semgrep JSON output
            scan_id: Scan identifier
            source_path: Source code directory path

        Returns:
            List of parsed Vulnerability objects
        """
        vulnerabilities: List[Vulnerability] = []

        if not isinstance(data, dict):
            logger.warning("Semgrep output is not a dictionary")
            return vulnerabilities

        results = data.get("results", [])
        if not isinstance(results, list):
            logger.warning("Semgrep results is not a list")
            return vulnerabilities

        for finding in results:
            try:
                vuln = self._parse_finding(finding, scan_id, source_path)
                if vuln:
                    vulnerabilities.append(vuln)
            except Exception as e:
                logger.debug("Failed to parse Semgrep finding: %s", e)

        logger.info("Parsed %d Semgrep findings", len(vulnerabilities))
        return vulnerabilities

    def _parse_finding(
        self, finding: Dict[str, Any], scan_id: str, source_path: str
    ) -> Optional[Vulnerability]:
        """
        Parse a single Semgrep finding.

        Args:
            finding: Single Semgrep result
            scan_id: Scan identifier
            source_path: Source code directory

        Returns:
            Vulnerability object or None
        """
        file_path = finding.get("path", "")
        start = finding.get("start", {})
        line_number = start.get("line", 1)
        column = start.get("col", 1)

        # Extract metadata
        extra = finding.get("extra", {})
        message = extra.get("message", "No description provided")
        severity = extra.get("severity", "WARNING")
        confidence = extra.get("metadata", {}).get("confidence", "MEDIUM")
        cwe_info = extra.get("metadata", {}).get("cwe", [])

        # Normalize severity
        normalized_severity = SEVERITY_MAP.get(severity.upper(), "MEDIUM")

        # Extract CWE
        cwe_id = None
        cwe_name = None
        if cwe_info:
            cwe_text = cwe_info[0] if isinstance(cwe_info, list) else cwe_info
            cwe_match = self._extract_cwe(cwe_text)
            if cwe_match:
                cwe_id, cwe_name = cwe_match

        # Extract OWASP category
        owasp = extra.get("metadata", {}).get("owasp", [])
        owasp_category = None
        if owasp:
            owasp_text = owasp[0] if isinstance(owasp, list) else owasp
            owasp_category = self._extract_owasp(owasp_text)

        # Get code snippet
        code_snippet = extra.get("lines", "")
        if not code_snippet and file_path:
            abs_path = os.path.join(source_path, file_path) if not os.path.isabs(file_path) else file_path
            if os.path.exists(abs_path):
                code_snippet = read_file_snippet(abs_path, line_number, context=2)

        # Get fix suggestion
        fix = extra.get("fix", "")
        if not fix:
            fix = self._generate_fix_suggestion(cwe_id)

        # Get check ID for category
        check_id = finding.get("check_id", "")
        category = self._get_category(check_id, cwe_name, message)

        return Vulnerability(
            scan_id=scan_id,
            file_path=file_path,
            line_number=line_number,
            column=column,
            severity=normalized_severity,
            category=category,
            cwe_id=cwe_id,
            cwe_name=cwe_name or category,
            title=message[:100] if message else category,
            description=message,
            code_snippet=code_snippet,
            fix_suggestion=fix,
            tool_source=self.tool_name,
            cvss_score=self._get_cvss_score(normalized_severity),
            owasp_category=owasp_category,
            confidence=confidence.upper() if isinstance(confidence, str) else "MEDIUM",
            created_at=datetime.now(timezone.utc),
        )

    def _extract_cwe(self, cwe_text: str) -> Optional[tuple]:
        """Extract CWE ID and name from CWE text."""
        match = re.search(r"CWE-(\d+):\s*(.+)", cwe_text)
        if match:
            cwe_id = f"CWE-{match.group(1)}"
            cwe_name = match.group(2).strip()
            return cwe_id, cwe_name

        # Try just CWE number
        match = re.search(r"CWE-(\d+)", cwe_text)
        if match:
            cwe_id = f"CWE-{match.group(1)}"
            cwe_name = CWE_MAPPING.get(cwe_id, "Unknown CWE")
            return cwe_id, cwe_name

        return None

    def _extract_owasp(self, owasp_text: str) -> Optional[str]:
        """Extract OWASP category code."""
        match = re.search(r"A(\d{2})", owasp_text)
        if match:
            return f"A{match.group(1)}"
        return None

    def _get_category(self, check_id: str, cwe_name: Optional[str], message: str) -> str:
        """Determine the vulnerability category."""
        if cwe_name:
            return cwe_name

        check_lower = check_id.lower()
        if "sql" in check_lower:
            return "SQL Injection"
        elif "xss" in check_lower:
            return "Cross-site Scripting"
        elif "command" in check_lower or "exec" in check_lower:
            return "Command Injection"
        elif "secret" in check_lower or "password" in check_lower:
            return "Secret Leak"
        elif "crypto" in check_lower or "hash" in check_lower:
            return "Cryptographic Issue"
        elif "traversal" in check_lower or "path" in check_lower:
            return "Path Traversal"
        elif "ssrf" in check_lower:
            return "Server-Side Request Forgery"

        # Fall back to first sentence of message
        if message:
            return message.split(".")[0][:80]

        return "Security Issue"

    def _generate_fix_suggestion(self, cwe_id: Optional[str]) -> str:
        """Generate a fix suggestion based on CWE."""
        suggestions = {
            "CWE-79": "Sanitize user input before rendering in HTML. Use auto-escaping frameworks.",
            "CWE-89": "Use parameterized queries. Never concatenate user input into SQL.",
            "CWE-78": "Use subprocess with argument lists. Avoid shell=True.",
            "CWE-94": "Avoid eval()/exec(). Use safe evaluation alternatives.",
            "CWE-22": "Validate and sanitize file paths. Use allowlists.",
            "CWE-798": "Move secrets to environment variables or secret managers.",
            "CWE-327": "Use strong cryptographic algorithms (SHA-256, bcrypt).",
        }
        return suggestions.get(cwe_id, "Review the finding and apply appropriate security controls.")

    def _get_cvss_score(self, severity: str) -> float:
        """Get approximate CVSS score."""
        scores = {
            "CRITICAL": 9.0,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.0,
            "INFO": 0.0,
        }
        return scores.get(severity.upper(), 5.0)
