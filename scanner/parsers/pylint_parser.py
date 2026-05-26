"""
Pylint JSON output parser for CodeShield AI.

Parses Pylint JSON results into standardized Vulnerability objects.
"""

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from models.vulnerability import Vulnerability
from utils.helpers import read_file_snippet
from utils.logger import get_logger

logger = get_logger(__name__)

# Pylint message types to severity mapping
PYLINT_TYPE_SEVERITY = {
    "convention": "INFO",
    "refactor": "INFO",
    "warning": "LOW",
    "error": "MEDIUM",
    "fatal": "HIGH",
}

# Security-related Pylint check mappings
SECURITY_CHECKS = {
    "W0123": ("Code Injection", "CWE-94", "MEDIUM"),      # eval-used
    "W0702": ("Error Handling", "CWE-391", "MEDIUM"),     # bare-except
    "W0703": ("Error Handling", "CWE-396", "LOW"),        # broad-except
    "W0102": ("Dangerous Default", "CWE-453", "MEDIUM"),  # dangerous-default-value
    "W0603": ("Global State", None, "LOW"),               # global-statement
    "W0613": ("Code Quality", None, "INFO"),              # unused-argument
    "C0301": ("Code Quality", None, "INFO"),              # line-too-long
    "R0913": ("Code Complexity", None, "INFO"),           # too-many-arguments
}


class PylintParser:
    """
    Parser for Pylint JSON output.

    Converts Pylint findings into standardized Vulnerability models.
    """

    def __init__(self) -> None:
        """Initialize the Pylint parser."""
        self.tool_name = "pylint"

    def parse(self, data: List[Any], scan_id: str, source_path: str) -> List[Vulnerability]:
        """
        Parse Pylint JSON output into Vulnerability objects.

        Args:
            data: Pylint JSON output (list of message dicts)
            scan_id: Scan identifier
            source_path: Source code directory

        Returns:
            List of parsed Vulnerability objects
        """
        vulnerabilities: List[Vulnerability] = []

        if not isinstance(data, list):
            logger.warning("Pylint output is not a list")
            return vulnerabilities

        for message in data:
            try:
                vuln = self._parse_message(message, scan_id, source_path)
                if vuln:
                    vulnerabilities.append(vuln)
            except Exception as e:
                logger.debug("Failed to parse Pylint message: %s", e)

        logger.info("Parsed %d Pylint findings", len(vulnerabilities))
        return vulnerabilities

    def _parse_message(
        self, message: Dict[str, Any], scan_id: str, source_path: str
    ) -> Optional[Vulnerability]:
        """Parse a single Pylint message."""
        msg_type = message.get("type", "")
        symbol = message.get("symbol", "")
        msg_id = message.get("message-id", "")
        msg_text = message.get("message", "")
        module = message.get("module", "")
        path = message.get("path", "")
        line_number = message.get("line", 1)
        column = message.get("column", 1)

        # Only report security-relevant issues
        if msg_id not in SECURITY_CHECKS:
            # Allow eval-used and exec-used (treated as HIGH security issues)
            if symbol not in ("eval-used", "exec-used"):
                if msg_type in ("convention", "refactor"):
                    return None

        # Get mapping
        category, cwe_id, default_severity = SECURITY_CHECKS.get(
            msg_id, ("Code Quality", None, "LOW")
        )

        # Override severity for security issues
        if symbol in ("eval-used", "exec-used"):
            severity = "HIGH"
            category = "Code Injection"
            cwe_id = "CWE-94"
        else:
            severity = PYLINT_TYPE_SEVERITY.get(msg_type, default_severity)

        # Make path relative
        if os.path.isabs(path):
            try:
                path = os.path.relpath(path, source_path)
            except ValueError:
                pass

        # Get code snippet
        code_snippet = None
        abs_path = os.path.join(source_path, path) if path and not os.path.isabs(path) else path
        if abs_path and os.path.exists(abs_path):
            code_snippet = read_file_snippet(abs_path, line_number, context=2)

        return Vulnerability(
            scan_id=scan_id,
            file_path=path or module.replace(".", "/") + ".py",
            line_number=line_number,
            column=column,
            severity=severity,
            category=category,
            cwe_id=cwe_id,
            cwe_name=None,
            title=f"Pylint: {symbol}",
            description=msg_text,
            code_snippet=code_snippet,
            fix_suggestion=self._get_fix_suggestion(symbol),
            tool_source=self.tool_name,
            cvss_score=self._get_cvss_score(severity),
            owasp_category="A03" if "Injection" in category else None,
            confidence="MEDIUM",
            created_at=datetime.now(timezone.utc),
        )

    def _get_fix_suggestion(self, symbol: str) -> str:
        """Get fix suggestion for a Pylint check."""
        suggestions = {
            "eval-used": "Remove eval() usage. Use ast.literal_eval() for safe evaluation or refactor to avoid dynamic execution.",
            "exec-used": "Remove exec() usage. Use importlib for dynamic imports or refactor.",
            "bare-except": "Use specific exception types (e.g., except ValueError:) instead of bare except.",
            "broad-except": "Catch specific exceptions instead of catching all exceptions.",
            "dangerous-default-value": "Use None as default value and initialize mutable objects inside the function.",
            "global-statement": "Avoid global variables. Pass values as parameters or use classes.",
        }
        return suggestions.get(symbol, "Review and fix the Pylint issue.")

    def _get_cvss_score(self, severity: str) -> float:
        """Get CVSS score."""
        scores = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.0}
        return scores.get(severity, 2.0)
