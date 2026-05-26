"""
Bandit JSON output parser for CodeShield AI.

Parses Bandit JSON results into standardized Vulnerability objects.
"""

import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from models.vulnerability import Vulnerability
from utils.constants import CWE_MAPPING, SEVERITY_MAP
from utils.helpers import read_file_snippet
from utils.logger import get_logger

logger = get_logger(__name__)

# Bandit test ID to CWE mapping
BANDIT_CWE_MAP = {
    "B101": "CWE-754",  # assert_used
    "B102": "CWE-78",   # exec_used
    "B103": "CWE-22",   # set_bad_file_permissions
    "B104": "CWE-200",  # hardcoded_bind_all_interfaces
    "B105": "CWE-798",  # hardcoded_password_string
    "B106": "CWE-798",  # hardcoded_password_funcarg
    "B107": "CWE-798",  # hardcoded_password_default
    "B108": "CWE-22",   # tmpdir_race
    "B110": "CWE-391",  # try_except_pass
    "B112": "CWE-391",  # try_except_continue
    "B301": "CWE-502",  # pickle
    "B302": "CWE-94",   # marshal
    "B303": "CWE-327",  # md5, sha1
    "B304": "CWE-331",  # ciphers
    "B305": "CWE-326",  # cipher_modes
    "B306": "CWE-295",  # mktemp
    "B307": "CWE-78",   # eval
    "B308": "CWE-91",   # mark_safe
    "B309": "CWE-319",  # httpsconnection
    "B310": "CWE-22",   # urllib_urlopen
    "B311": "CWE-330",  # random
    "B312": "CWE-78",   # telnetlib
    "B313": "CWE-20",   # xml_bad_cElementTree
    "B314": "CWE-20",   # xml_bad_ElementTree
    "B315": "CWE-20",   # xml_bad_expatreader
    "B316": "CWE-20",   # xml_bad_expatbuilder
    "B317": "CWE-20",   # xml_bad_sax
    "B318": "CWE-20",   # xml_bad_minidom
    "B319": "CWE-20",   # xml_bad_pulldom
    "B320": "CWE-20",   # xml_bad_etree
    "B321": "CWE-319",  # ftplib
    "B323": "CWE-295",  # unverified_context
    "B324": "CWE-326",  # hashlib_new_insecure_functions
    "B325": "CWE-378",  # tempnam
    "B401": "CWE-319",  # import_ftplib
    "B402": "CWE-319",  # import_ftplib
    "B403": "CWE-20",   # import_pickle
    "B404": "CWE-78",   # import_subprocess
    "B405": "CWE-20",   # import_xml_etree
    "B406": "CWE-20",   # import_xml_sax
    "B407": "CWE-20",   # import_xml_expat
    "B408": "CWE-20",   # import_xml_minidom
    "B409": "CWE-20",   # import_xml_pulldom
    "B410": "CWE-20",   # import_lxml
    "B411": "CWE-20",   # import_xmlrpclib
    "B412": "CWE-400",  # httpoxy
    "B413": "CWE-20",   # import_pycrypto
    "B501": "CWE-295",  # request_with_no_cert_validation
    "B502": "CWE-295",  # ssl_with_bad_version
    "B503": "CWE-295",  # ssl_with_bad_defaults
    "B504": "CWE-295",  # ssl_with_no_version
    "B505": "CWE-326",  # weak_cryptographic_key
    "B506": "CWE-91",   # yaml_load
    "B507": "CWE-295",  # ssh_no_host_key_verification
    "B601": "CWE-78",   # paramiko_calls
    "B602": "CWE-78",   # subprocess_popen_with_shell
    "B603": "CWE-78",   # subprocess_without_shell_equals_true
    "B604": "CWE-78",   # any_other_function_with_shell_equals_true
    "B605": "CWE-78",   # start_process_with_a_shell
    "B606": "CWE-78",   # start_process_with_no_shell
    "B607": "CWE-78",   # start_process_with_partial_path
    "B608": "CWE-89",   # hardcoded_sql_expressions
    "B609": "CWE-78",   # linux_commands_wildcard_injection
    "B610": "CWE-89",   # django_extra_used
    "B611": "CWE-89",   # django_rawsql_used
    "B612": "CWE-287",  # logging_config_insecure_listen
    "B701": "CWE-94",   # jinja2_autoescape_false
    "B702": "CWE-94",   # use_of_mako_templates
    "B703": "CWE-79",   # django_mark_safe
}


class BanditParser:
    """
    Parser for Bandit JSON output.

    Converts Bandit findings into standardized Vulnerability models.
    """

    def __init__(self) -> None:
        """Initialize the Bandit parser."""
        self.tool_name = "bandit"

    def parse(self, data: Dict[str, Any], scan_id: str, source_path: str) -> List[Vulnerability]:
        """
        Parse Bandit JSON output into Vulnerability objects.

        Args:
            data: Bandit JSON output
            scan_id: Scan identifier
            source_path: Source code directory

        Returns:
            List of parsed Vulnerability objects
        """
        vulnerabilities: List[Vulnerability] = []

        if not isinstance(data, dict):
            logger.warning("Bandit output is not a dictionary")
            return vulnerabilities

        results = data.get("results", [])
        if not isinstance(results, list):
            logger.warning("Bandit results is not a list")
            return vulnerabilities

        for result in results:
            try:
                vuln = self._parse_result(result, scan_id, source_path)
                if vuln:
                    vulnerabilities.append(vuln)
            except Exception as e:
                logger.debug("Failed to parse Bandit result: %s", e)

        logger.info("Parsed %d Bandit findings", len(vulnerabilities))
        return vulnerabilities

    def _parse_result(
        self, result: Dict[str, Any], scan_id: str, source_path: str
    ) -> Optional[Vulnerability]:
        """Parse a single Bandit result."""
        file_path = result.get("filename", "")
        line_number = result.get("line_number", 1)
        column = result.get("col_offset", 1)
        issue_text = result.get("issue_text", "")
        issue_severity = result.get("issue_severity", "LOW")
        issue_confidence = result.get("issue_confidence", "MEDIUM")
        test_id = result.get("test_id", "")
        test_name = result.get("test_name", "")
        code = result.get("code", "")

        # Normalize severity
        severity = SEVERITY_MAP.get(issue_severity.upper(), issue_severity.upper())

        # Get CWE mapping
        cwe_id = BANDIT_CWE_MAP.get(test_id)
        cwe_name = CWE_MAPPING.get(cwe_id) if cwe_id else None

        # Make file path relative
        if os.path.isabs(file_path):
            try:
                file_path = os.path.relpath(file_path, source_path)
            except ValueError:
                pass

        # Get code snippet
        code_snippet = code if code else None
        if not code_snippet:
            abs_path = os.path.join(source_path, file_path) if not os.path.isabs(file_path) else file_path
            if os.path.exists(abs_path):
                code_snippet = read_file_snippet(abs_path, line_number, context=2)

        return Vulnerability(
            scan_id=scan_id,
            file_path=file_path,
            line_number=line_number,
            column=column,
            severity=severity,
            category=self._get_category(test_name),
            cwe_id=cwe_id,
            cwe_name=cwe_name or self._get_category(test_name),
            title=f"Bandit {test_id}: {test_name}",
            description=issue_text,
            code_snippet=code_snippet,
            fix_suggestion=self._get_fix_suggestion(test_name),
            tool_source=self.tool_name,
            cvss_score=self._get_cvss_score(severity),
            owasp_category=self._get_owasp_category(cwe_id),
            confidence=issue_confidence.upper(),
            created_at=datetime.now(timezone.utc),
        )

    def _get_category(self, test_name: str) -> str:
        """Get vulnerability category from test name."""
        category_map = {
            "hardcoded_password": "Hardcoded Password",
            "hardcoded_tmp_directory": "Insecure Temporary File",
            "blacklist": "Dangerous Function",
            "call": "Dangerous Call",
            "subprocess": "Command Injection",
            "sql": "SQL Injection",
            "pickle": "Insecure Deserialization",
            "yaml": "Insecure Deserialization",
            "crypto": "Weak Cryptography",
            "ssl": "SSL/TLS Issue",
            "random": "Insecure Randomness",
            "shell": "Shell Injection",
            "eval": "Code Injection",
            "exec": "Code Injection",
            "jinja2": "Template Injection",
            "mark_safe": "XSS",
            "xml": "XML Vulnerability",
            "assert": "Assert Usage",
            "ftp": "Insecure Protocol",
        }

        test_lower = test_name.lower()
        for key, value in category_map.items():
            if key in test_lower:
                return value

        return "Security Issue"

    def _get_fix_suggestion(self, test_name: str) -> str:
        """Get fix suggestion for a Bandit test."""
        suggestions = {
            "hardcoded_password": "Move passwords to environment variables or use a secrets manager.",
            "subprocess_popen_with_shell": "Use subprocess with shell=False and pass arguments as a list.",
            "hardcoded_sql_expressions": "Use parameterized queries. Never concatenate user input into SQL.",
            "pickle": "Use JSON for serialization. Avoid pickle on untrusted data.",
            "yaml_load": "Use yaml.safe_load() instead of yaml.load().",
            "md5": "Use SHA-256 or bcrypt for hashing. MD5 is cryptographically broken.",
            "ssh_no_host_key_verification": "Enable host key verification for SSH connections.",
            "request_with_no_cert_validation": "Enable SSL certificate verification. Set verify=True.",
            "eval": "Remove eval() usage. Use ast.literal_eval() for safe parsing.",
            "jinja2_autoescape_false": "Enable autoescape in Jinja2 templates: autoescape=True.",
            "assert_used": "Remove assert statements. Use proper error handling for production code.",
            "random": "Use secrets module or SystemRandom for cryptographic purposes.",
        }

        test_lower = test_name.lower()
        for key, value in suggestions.items():
            if key in test_lower:
                return value

        return "Review the Bandit finding and apply the recommended fix."

    def _get_owasp_category(self, cwe_id: Optional[str]) -> Optional[str]:
        """Map CWE to OWASP category."""
        from utils.constants import CWE_TO_OWASP
        return CWE_TO_OWASP.get(cwe_id)

    def _get_cvss_score(self, severity: str) -> float:
        """Get CVSS score."""
        scores = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.0}
        return scores.get(severity.upper(), 5.0)
