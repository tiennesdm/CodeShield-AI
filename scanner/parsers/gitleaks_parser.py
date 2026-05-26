"""
Gitleaks JSON output parser for CodeShield AI.

Parses Gitleaks JSON results into standardized Vulnerability objects.
"""

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from models.vulnerability import Vulnerability
from utils.helpers import read_file_snippet
from utils.logger import get_logger

logger = get_logger(__name__)

# Secret type to severity mapping
SECRET_SEVERITY = {
    "aws-access-token": "CRITICAL",
    "aws-secret-key": "CRITICAL",
    "private-key": "CRITICAL",
    "github-token": "CRITICAL",
    "gitlab-token": "HIGH",
    "slack-token": "HIGH",
    "slack-webhook": "HIGH",
    "generic-api-key": "HIGH",
    "generic-secret": "HIGH",
    "password": "CRITICAL",
    "jwt": "HIGH",
    "bearer-token": "HIGH",
    "basic-auth": "CRITICAL",
    "api-key": "HIGH",
    "secret-key": "CRITICAL",
}


class GitleaksParser:
    """
    Parser for Gitleaks JSON output.

    Converts Gitleaks findings into standardized Vulnerability models.
    """

    def __init__(self) -> None:
        """Initialize the Gitleaks parser."""
        self.tool_name = "gitleaks"

    def parse(self, data: List[Any], scan_id: str, source_path: str) -> List[Vulnerability]:
        """
        Parse Gitleaks JSON output into Vulnerability objects.

        Args:
            data: Gitleaks JSON output (list of findings)
            scan_id: Scan identifier
            source_path: Source code directory

        Returns:
            List of parsed Vulnerability objects
        """
        vulnerabilities: List[Vulnerability] = []

        if not isinstance(data, list):
            logger.warning("Gitleaks output is not a list")
            return vulnerabilities

        for finding in data:
            try:
                vuln = self._parse_finding(finding, scan_id, source_path)
                if vuln:
                    vulnerabilities.append(vuln)
            except Exception as e:
                logger.debug("Failed to parse Gitleaks finding: %s", e)

        logger.info("Parsed %d Gitleaks findings", len(vulnerabilities))
        return vulnerabilities

    def _parse_finding(
        self, finding: Dict[str, Any], scan_id: str, source_path: str
    ) -> Optional[Vulnerability]:
        """Parse a single Gitleaks finding."""
        file_path = finding.get("File", "")
        line_number = finding.get("StartLine", 1)
        column = finding.get("StartColumn", 1)
        secret_type = finding.get("RuleID", finding.get("Type", "secret"))
        match = finding.get("Match", "")
        entropy = finding.get("Entropy", 0.0)
        tags = finding.get("Tags", [])

        # Determine severity based on secret type
        severity = "HIGH"  # Default for secrets
        for tag in tags:
            if isinstance(tag, str):
                severity = SECRET_SEVERITY.get(tag.lower(), severity)
                break

        # Check RuleID for severity
        severity = SECRET_SEVERITY.get(secret_type.lower(), severity)

        # Make file path relative
        if os.path.isabs(file_path):
            try:
                file_path = os.path.relpath(file_path, source_path)
            except ValueError:
                pass

        # Redact the secret from display
        display_match = self._redact_secret(match)

        # Get code snippet
        code_snippet = display_match
        abs_path = os.path.join(source_path, file_path) if not os.path.isabs(file_path) else file_path
        if abs_path and os.path.exists(abs_path):
            snippet = read_file_snippet(abs_path, line_number, context=1)
            if snippet:
                code_snippet = snippet

        return Vulnerability(
            scan_id=scan_id,
            file_path=file_path,
            line_number=line_number,
            column=column,
            severity=severity,
            category="Secret Leak",
            cwe_id="CWE-798",
            cwe_name="Hardcoded Credentials",
            title=f"Secret Found: {secret_type}",
            description=f"Detected {secret_type} in source code. This is a security risk as secrets should not be committed to version control.",
            code_snippet=code_snippet,
            fix_suggestion=(
                "1. Remove the secret from source code immediately.\n"
                "2. Rotate the exposed secret/credentials.\n"
                "3. Use environment variables or a secrets manager (e.g., AWS Secrets Manager, HashiCorp Vault).\n"
                "4. Add the file to .gitignore or use git-filter-repo to remove from history."
            ),
            tool_source=self.tool_name,
            cvss_score=8.5,
            owasp_category="A07",
            confidence="HIGH",
            created_at=datetime.now(timezone.utc),
        )

    def _redact_secret(self, match: str) -> str:
        """
        Redact a secret value for display.

        Args:
            match: The matched secret string

        Returns:
            Redacted version showing only first/last few characters
        """
        if not match:
            return "[REDACTED]"

        if len(match) <= 8:
            return "*" * len(match)

        # Show first 3 and last 3 characters
        return f"{match[:3]}{'*' * (len(match) - 6)}{match[-3:]}"

    def _get_cvss_score(self, severity: str) -> float:
        """Get CVSS score."""
        scores = {"CRITICAL": 9.0, "HIGH": 8.5, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.0}
        return scores.get(severity, 5.0)
