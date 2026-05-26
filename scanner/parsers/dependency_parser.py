"""
OWASP Dependency-Check JSON output parser for CodeShield AI.

Parses Dependency-Check JSON results into standardized Vulnerability objects.
"""

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from models.vulnerability import Vulnerability
from utils.logger import get_logger

logger = get_logger(__name__)

# CVSSv3 severity ranges
CVSS_SEVERITY = {
    (0.0, 0.0): "INFO",
    (0.1, 3.9): "LOW",
    (4.0, 6.9): "MEDIUM",
    (7.0, 8.9): "HIGH",
    (9.0, 10.0): "CRITICAL",
}


def cvss_to_severity(score: float) -> str:
    """Convert CVSS score to severity level."""
    for (low, high), severity in CVSS_SEVERITY.items():
        if low <= score <= high:
            return severity
    return "MEDIUM"


class DependencyParser:
    """
    Parser for OWASP Dependency-Check JSON output.

    Converts dependency vulnerability findings into standardized Vulnerability models.
    """

    def __init__(self) -> None:
        """Initialize the Dependency-Check parser."""
        self.tool_name = "dependency-check"

    def parse(self, data: Dict[str, Any], scan_id: str, source_path: str) -> List[Vulnerability]:
        """
        Parse Dependency-Check JSON output into Vulnerability objects.

        Args:
            data: Dependency-Check JSON output
            scan_id: Scan identifier
            source_path: Source code directory

        Returns:
            List of parsed Vulnerability objects
        """
        vulnerabilities: List[Vulnerability] = []

        if not isinstance(data, dict):
            logger.warning("Dependency-Check output is not a dictionary")
            return vulnerabilities

        # Get dependencies
        dependencies = data.get("dependencies", [])
        if not isinstance(dependencies, list):
            logger.warning("Dependencies is not a list")
            return vulnerabilities

        for dep in dependencies:
            try:
                dep_vulns = self._parse_dependency(dep, scan_id, source_path)
                vulnerabilities.extend(dep_vulns)
            except Exception as e:
                logger.debug("Failed to parse dependency: %s", e)

        logger.info("Parsed %d Dependency-Check findings", len(vulnerabilities))
        return vulnerabilities

    def _parse_dependency(
        self, dep: Dict[str, Any], scan_id: str, source_path: str
    ) -> List[Vulnerability]:
        """Parse vulnerabilities for a single dependency."""
        vulnerabilities: List[Vulnerability] = []

        file_path = dep.get("filePath", "")
        file_name = dep.get("fileName", "")
        file_version = dep.get("fileVersion", "")

        # Get vulnerability list
        vulns = dep.get("vulnerabilities", [])
        if not isinstance(vulns, list):
            vulns = dep.get("vuls", [])

        if not isinstance(vulns, list):
            return vulnerabilities

        for vuln_data in vulns:
            try:
                vuln = self._parse_vulnerability(
                    vuln_data, file_path, file_name, file_version, scan_id, source_path
                )
                if vuln:
                    vulnerabilities.append(vuln)
            except Exception as e:
                logger.debug("Failed to parse dependency vulnerability: %s", e)

        return vulnerabilities

    def _parse_vulnerability(
        self,
        vuln_data: Dict[str, Any],
        file_path: str,
        file_name: str,
        file_version: str,
        scan_id: str,
        source_path: str,
    ) -> Optional[Vulnerability]:
        """Parse a single dependency vulnerability."""
        name = vuln_data.get("name", "")
        source = vuln_data.get("source", "NVD")
        severity_score = vuln_data.get("severity", "")
        cvssv3 = vuln_data.get("cvssv3", {})
        cvssv2 = vuln_data.get("cvssv2", {})
        description = vuln_data.get("description", "")

        # Get CVSS score
        cvss_score = 0.0
        if isinstance(cvssv3, dict):
            base_score = cvssv3.get("baseScore", 0.0)
            if base_score:
                cvss_score = float(base_score)
        elif isinstance(cvssv2, dict):
            score = cvssv2.get("score", 0.0)
            if score:
                cvss_score = float(score)

        # Determine severity
        if cvss_score > 0:
            severity = cvss_to_severity(cvss_score)
        elif severity_score:
            severity_map = {"LOW": "LOW", "MEDIUM": "MEDIUM", "HIGH": "HIGH", "CRITICAL": "CRITICAL"}
            severity = severity_map.get(str(severity_score).upper(), "MEDIUM")
        else:
            severity = "MEDIUM"

        # CWE extraction
        cwe = vuln_data.get("cwes", [])
        cwe_id = None
        if isinstance(cwe, list) and cwe:
            cwe_id = cwe[0]
        elif isinstance(cwe, str):
            cwe_id = cwe

        # CVE reference
        cve = name if name.startswith("CVE-") else None

        # Display file path
        display_path = file_name or file_path
        if os.path.isabs(display_path):
            try:
                display_path = os.path.relpath(display_path, source_path)
            except ValueError:
                pass

        # Build description
        desc = description or f"Vulnerability in {file_name}"
        if file_version:
            desc += f" (version {file_version})"

        # Build code snippet showing dependency info
        code_snippet = f"Dependency: {file_name}"
        if file_version:
            code_snippet += f"\nVersion: {file_version}"
        if cve:
            code_snippet += f"\nCVE: {cve}"

        return Vulnerability(
            scan_id=scan_id,
            file_path=display_path,
            line_number=1,
            column=1,
            severity=severity,
            category="Vulnerable Dependency",
            cwe_id=cwe_id,
            cwe_name=None,
            title=f"Vulnerable Dependency: {file_name}",
            description=desc,
            code_snippet=code_snippet,
            fix_suggestion=self._get_fix_suggestion(file_name, file_version, cve),
            tool_source=self.tool_name,
            cvss_score=cvss_score if cvss_score > 0 else None,
            owasp_category="A06",
            confidence="HIGH",
            created_at=datetime.now(timezone.utc),
        )

    def _get_fix_suggestion(
        self, file_name: str, file_version: str, cve: Optional[str]
    ) -> str:
        """Generate fix suggestion for a vulnerable dependency."""
        suggestion = f"Update {file_name} to a non-vulnerable version."

        if cve:
            suggestion += f"\nReference: https://nvd.nist.gov/vuln/detail/{cve}"

        suggestion += (
            "\nUse a dependency management tool to check for updates:\n"
            "- Python: pip-audit, safety\n"
            "- JavaScript: npm audit, yarn audit\n"
            "- Java: OWASP Dependency-Check\n"
            "- Ruby: bundle audit\n"
            "Enable Dependabot or similar automated dependency update tools."
        )

        return suggestion
