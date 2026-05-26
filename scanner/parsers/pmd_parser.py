"""
PMD JSON output parser for CodeShield AI.

Parses PMD JSON results into standardized Vulnerability objects.
"""

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from models.vulnerability import Vulnerability
from utils.helpers import read_file_snippet
from utils.logger import get_logger

logger = get_logger(__name__)

# PMD security rule mappings
PMD_RULE_MAP = {
    "GuardLogStatement": ("Logging", None, "LOW"),
    "AvoidUsingHardCodedIP": ("Hardcoded IP", "CWE-200", "MEDIUM"),
    "InsecureCryptoIv": ("Weak Cryptography", "CWE-330", "HIGH"),
    "HardCodedCryptoKey": ("Hardcoded Crypto Key", "CWE-798", "CRITICAL"),
    "AvoidHardcodingPassword": ("Hardcoded Password", "CWE-798", "CRITICAL"),
    "UseProperClassLoader": ("Code Quality", None, "MEDIUM"),
    "BadComparison": ("Logic Error", None, "MEDIUM"),
    "BeanMembersShouldSerialize": ("Code Quality", None, "INFO"),
    "GuardDebugLogging": ("Logging", None, "LOW"),
    "UnusedImports": ("Code Quality", None, "INFO"),
    "UnusedLocalVariable": ("Code Quality", None, "INFO"),
    "UnusedPrivateField": ("Code Quality", None, "INFO"),
    "UnusedPrivateMethod": ("Code Quality", None, "INFO"),
    "UselessParentheses": ("Code Quality", None, "INFO"),
}

# PMD priority to severity
PRIORITY_SEVERITY = {
    1: "HIGH",
    2: "MEDIUM",
    3: "MEDIUM",
    4: "LOW",
    5: "INFO",
}


class PMDParser:
    """
    Parser for PMD JSON output.

    Converts PMD findings into standardized Vulnerability models.
    """

    def __init__(self) -> None:
        """Initialize the PMD parser."""
        self.tool_name = "pmd"

    def parse(self, data: Dict[str, Any], scan_id: str, source_path: str) -> List[Vulnerability]:
        """
        Parse PMD JSON output into Vulnerability objects.

        Args:
            data: PMD JSON output
            scan_id: Scan identifier
            source_path: Source code directory

        Returns:
            List of parsed Vulnerability objects
        """
        vulnerabilities: List[Vulnerability] = []

        if not isinstance(data, dict):
            logger.warning("PMD output is not a dictionary")
            return vulnerabilities

        files = data.get("files", [])
        if isinstance(files, list):
            for file_data in files:
                try:
                    file_vulns = self._parse_file(file_data, scan_id, source_path)
                    vulnerabilities.extend(file_vulns)
                except Exception as e:
                    logger.debug("Failed to parse PMD file result: %s", e)

        # Alternative format
        violations = data.get("violations", [])
        if isinstance(violations, list):
            for violation in violations:
                try:
                    vuln = self._parse_violation(violation, scan_id, source_path)
                    if vuln:
                        vulnerabilities.append(vuln)
                except Exception as e:
                    logger.debug("Failed to parse PMD violation: %s", e)

        logger.info("Parsed %d PMD findings", len(vulnerabilities))
        return vulnerabilities

    def _parse_file(
        self, file_data: Dict[str, Any], scan_id: str, source_path: str
    ) -> List[Vulnerability]:
        """Parse PMD results for a single file."""
        vulnerabilities: List[Vulnerability] = []
        file_path = file_data.get("filename", "")
        violations = file_data.get("violations", [])

        if not isinstance(violations, list):
            return vulnerabilities

        for violation in violations:
            try:
                vuln = self._parse_violation(
                    violation, scan_id, source_path, file_path=file_path
                )
                if vuln:
                    vulnerabilities.append(vuln)
            except Exception as e:
                logger.debug("Failed to parse PMD violation: %s", e)

        return vulnerabilities

    def _parse_violation(
        self,
        violation: Dict[str, Any],
        scan_id: str,
        source_path: str,
        file_path: str = "",
    ) -> Optional[Vulnerability]:
        """Parse a single PMD violation."""
        if not file_path:
            file_path = violation.get("fileName", violation.get("filename", ""))

        line_number = violation.get("beginLine", violation.get("line", 1))
        column = violation.get("beginColumn", violation.get("column", 1))
        rule = violation.get("rule", "")
        ruleset = violation.get("ruleset", "")
        priority = violation.get("priority", 3)
        description = violation.get("description", "")
        message = violation.get("message", "")

        # Use description or message
        desc = description or message or f"PMD rule: {rule}"

        # Get mapping
        category, cwe_id, default_severity = PMD_RULE_MAP.get(
            rule, ("Code Quality", None, "LOW")
        )

        # Override severity by priority
        severity = PRIORITY_SEVERITY.get(priority, default_severity)

        # Make file path relative
        if os.path.isabs(file_path):
            try:
                file_path = os.path.relpath(file_path, source_path)
            except ValueError:
                pass

        # Get code snippet
        code_snippet = None
        abs_path = os.path.join(source_path, file_path) if not os.path.isabs(file_path) else file_path
        if abs_path and os.path.exists(abs_path):
            code_snippet = read_file_snippet(abs_path, line_number, context=2)

        return Vulnerability(
            scan_id=scan_id,
            file_path=file_path,
            line_number=line_number,
            column=column,
            severity=severity,
            category=category,
            cwe_id=cwe_id,
            cwe_name=category,
            title=f"PMD: {rule}",
            description=desc,
            code_snippet=code_snippet,
            fix_suggestion=f"Fix the PMD violation: {rule}. {desc}",
            tool_source=self.tool_name,
            cvss_score=self._get_cvss_score(severity),
            owasp_category=None,
            confidence="MEDIUM",
            created_at=datetime.now(timezone.utc),
        )

    def _get_cvss_score(self, severity: str) -> float:
        """Get CVSS score."""
        scores = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.0}
        return scores.get(severity, 2.0)
