"""
ESLint JSON output parser for CodeShield AI.

Parses ESLint JSON results into standardized Vulnerability objects.
"""

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from models.vulnerability import Vulnerability
from utils.helpers import read_file_snippet
from utils.logger import get_logger

logger = get_logger(__name__)

# Security-focused ESLint rule mappings
RULE_MAP = {
    "no-eval": ("Code Injection", "CWE-94", "HIGH"),
    "no-implied-eval": ("Code Injection", "CWE-94", "HIGH"),
    "no-new-func": ("Code Injection", "CWE-94", "MEDIUM"),
    "no-script-url": ("Cross-site Scripting", "CWE-79", "MEDIUM"),
    "no-inner-declarations": ("Code Quality", None, "LOW"),
    "no-unused-vars": ("Code Quality", None, "LOW"),
    "no-console": ("Information Exposure", "CWE-200", "LOW"),
    "no-debugger": ("Debug Code in Production", "CWE-489", "LOW"),
    "no-alert": ("Information Exposure", "CWE-200", "INFO"),
    "no-global-assign": ("Code Quality", None, "MEDIUM"),
    "no-prototype-builtins": ("Code Quality", None, "MEDIUM"),
}

# Severity mapping from ESLint levels
SEVERITY_FROM_LEVEL = {
    1: "LOW",      # Warning
    2: "MEDIUM",   # Error
}


class ESLintParser:
    """
    Parser for ESLint JSON output.

    Converts ESLint findings into standardized Vulnerability models.
    """

    def __init__(self) -> None:
        """Initialize the ESLint parser."""
        self.tool_name = "eslint"

    def parse(self, data: List[Any], scan_id: str, source_path: str) -> List[Vulnerability]:
        """
        Parse ESLint JSON output into Vulnerability objects.

        Args:
            data: ESLint JSON output (list of file results)
            scan_id: Scan identifier
            source_path: Source code directory

        Returns:
            List of parsed Vulnerability objects
        """
        vulnerabilities: List[Vulnerability] = []

        if not isinstance(data, list):
            logger.warning("ESLint output is not a list")
            return vulnerabilities

        for file_result in data:
            try:
                file_vulns = self._parse_file_result(file_result, scan_id, source_path)
                vulnerabilities.extend(file_vulns)
            except Exception as e:
                logger.debug("Failed to parse ESLint file result: %s", e)

        logger.info("Parsed %d ESLint findings", len(vulnerabilities))
        return vulnerabilities

    def _parse_file_result(
        self, file_result: Dict[str, Any], scan_id: str, source_path: str
    ) -> List[Vulnerability]:
        """Parse results for a single file."""
        vulnerabilities: List[Vulnerability] = []

        file_path = file_result.get("filePath", "")
        messages = file_result.get("messages", [])

        # Make file path relative
        if os.path.isabs(file_path):
            try:
                file_path = os.path.relpath(file_path, source_path)
            except ValueError:
                pass

        for message in messages:
            try:
                vuln = self._parse_message(file_path, message, scan_id, source_path)
                if vuln:
                    vulnerabilities.append(vuln)
            except Exception as e:
                logger.debug("Failed to parse ESLint message: %s", e)

        return vulnerabilities

    def _parse_message(
        self,
        file_path: str,
        message: Dict[str, Any],
        scan_id: str,
        source_path: str,
    ) -> Optional[Vulnerability]:
        """Parse a single ESLint message."""
        rule_id = message.get("ruleId", "")
        severity_level = message.get("severity", 1)
        line_number = message.get("line", 1)
        column = message.get("column", 1)
        msg_text = message.get("message", "")

        if not rule_id:
            return None

        # Skip non-security rules
        if rule_id not in RULE_MAP:
            # Still report security-adjacent rules
            if not any(
                keyword in rule_id.lower()
                for keyword in ["eval", "inject", "xss", "crypto", "secret", "password"]
            ):
                return None

        # Get mapping info
        category, cwe_id, default_severity = RULE_MAP.get(
            rule_id, ("Code Quality", None, "LOW")
        )

        # Determine severity
        severity = SEVERITY_FROM_LEVEL.get(severity_level, default_severity)

        # Get code snippet
        code_snippet = None
        abs_path = os.path.join(source_path, file_path) if not os.path.isabs(file_path) else file_path
        if os.path.exists(abs_path):
            code_snippet = read_file_snippet(abs_path, line_number, context=2)

        return Vulnerability(
            scan_id=scan_id,
            file_path=file_path,
            line_number=line_number,
            column=column,
            severity=severity,
            category=category,
            cwe_id=cwe_id,
            cwe_name=category if cwe_id else None,
            title=f"ESLint: {rule_id}",
            description=msg_text,
            code_snippet=code_snippet,
            fix_suggestion=self._get_fix_suggestion(rule_id),
            tool_source=self.tool_name,
            cvss_score=self._get_cvss_score(severity),
            owasp_category="A03" if "Injection" in category else None,
            confidence="MEDIUM",
            created_at=datetime.now(timezone.utc),
        )

    def _get_fix_suggestion(self, rule_id: str) -> str:
        """Get fix suggestion for a rule."""
        suggestions = {
            "no-eval": "Remove eval() usage. Use safe alternatives like JSON.parse() for data parsing.",
            "no-implied-eval": "Avoid setTimeout/setInterval with string arguments. Use function references instead.",
            "no-new-func": "Avoid new Function(). Use safer alternatives for dynamic code execution.",
            "no-script-url": "Avoid javascript: URLs. Use event handlers instead.",
            "no-console": "Remove console.log() statements from production code. Use a proper logging framework.",
            "no-debugger": "Remove debugger statements before deploying to production.",
        }
        return suggestions.get(rule_id, f"Review and fix the ESLint rule: {rule_id}")

    def _get_cvss_score(self, severity: str) -> float:
        """Get CVSS score."""
        scores = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.0}
        return scores.get(severity, 2.0)
