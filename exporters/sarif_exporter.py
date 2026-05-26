"""
SARIF 2.1.0 Exporter for CodeShield AI.

Generates fully compliant SARIF 2.1.0 output for scan results.
Compatible with GitHub Code Scanning, Visual Studio, and other SARIF consumers.

Specification: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
"""

import json
import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from models.vulnerability import ScanResult, Vulnerability
from utils.logger import get_logger

logger = get_logger(__name__)

# SARIF 2.1.0 schema URI
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
SARIF_VERSION = "2.1.0"

# Tool metadata for each scanner
toolComponent = Dict[str, Any]


class SARIFExporter:
    """
    Export scan results to SARIF 2.1.0 format.

    Features:
    - Full SARIF 2.1.0 spec compliance
    - toolComponent for each scanner
    - Rules with help URIs (CWE links)
    - Results with codeFlows, locations, fixes
    - GitHub Code Scanning compatible
    """

    def __init__(self) -> None:
        """Initialize the SARIF exporter."""
        self.tool_components: Dict[str, toolComponent] = {}
        self.rules: Dict[str, Dict[str, Any]] = {}
        self._init_tool_components()

    def _init_tool_components(self) -> None:
        """Initialize toolComponent metadata for all scanners."""
        self.tool_components = {
            "bandit": {
                "name": "bandit",
                "fullName": "Bandit Python Security Scanner",
                "informationUri": "https://bandit.readthedocs.io/",
                "version": "1.7.0",
                "organization": "OpenStack",
                "description": {
                    "text": "Bandit is a tool designed to find common security issues in Python code."
                },
            },
            "semgrep": {
                "name": "semgrep",
                "fullName": "Semgrep SAST Scanner",
                "informationUri": "https://semgrep.dev/",
                "version": "1.50.0",
                "organization": "Semgrep Inc.",
                "description": {
                    "text": "Semgrep is a fast, open-source, static analysis tool for searching code, finding bugs, and enforcing code standards."
                },
            },
            "eslint": {
                "name": "eslint",
                "fullName": "ESLint JavaScript/TypeScript Linter",
                "informationUri": "https://eslint.org/",
                "version": "8.50.0",
                "organization": "OpenJS Foundation",
                "description": {
                    "text": "ESLint is a pluggable JavaScript/TypeScript linting utility."
                },
            },
            "pylint": {
                "name": "pylint",
                "fullName": "Pylint Python Code Analyzer",
                "informationUri": "https://pylint.pycqa.org/",
                "version": "3.0.0",
                "organization": "PyCQA",
                "description": {
                    "text": "Pylint is a Python static code analysis tool."
                },
            },
            "pmd": {
                "name": "pmd",
                "fullName": "PMD Java Static Analyzer",
                "informationUri": "https://pmd.github.io/",
                "version": "7.0.0",
                "organization": "PMD Team",
                "description": {
                    "text": "PMD is a source code analyzer for Java and other languages."
                },
            },
            "gitleaks": {
                "name": "gitleaks",
                "fullName": "Gitleaks Secret Scanner",
                "informationUri": "https://github.com/gitleaks/gitleaks",
                "version": "8.18.0",
                "organization": "Gitleaks",
                "description": {
                    "text": "Gitleaks detects hardcoded secrets, API keys, passwords, and tokens in git repositories."
                },
            },
            "dependency_check": {
                "name": "dependency-check",
                "fullName": "OWASP Dependency-Check",
                "informationUri": "https://owasp.org/www-project-dependency-check/",
                "version": "8.4.0",
                "organization": "OWASP",
                "description": {
                    "text": "OWASP Dependency-Check identifies project dependencies and checks for known vulnerabilities."
                },
            },
            "custom_ai": {
                "name": "codeshield-custom-ai",
                "fullName": "CodeShield AI Custom Pattern Scanner",
                "informationUri": "https://codeshield.ai",
                "version": "1.0.0",
                "organization": "CodeShield AI",
                "description": {
                    "text": "CodeShield AI's built-in pattern scanner. Detects secrets, injections, XSS, path traversal, weak crypto, and more."
                },
            },
            "osv_scanner": {
                "name": "osv-scanner",
                "fullName": "OSV.dev Vulnerability Scanner",
                "informationUri": "https://osv.dev/",
                "version": "1.0.0",
                "organization": "Google",
                "description": {
                    "text": "OSV.dev scanner for detecting known vulnerabilities in open source dependencies."
                },
            },
        }

    def _get_or_create_rule(self, vuln: Vulnerability, tool_name: str) -> str:
        """
        Get or create a SARIF rule for a vulnerability.

        Args:
            vuln: The vulnerability
            tool_name: Name of the tool that found it

        Returns:
            Rule ID string
        """
        rule_id = f"{tool_name}/{vuln.cwe_id or 'GENERAL'}/{self._slugify(vuln.category)}"

        if rule_id not in self.rules:
            cwe_num = vuln.cwe_id.replace("CWE-", "") if vuln.cwe_id else ""
            help_uri = f"https://cwe.mitre.org/data/definitions/{cwe_num}.html" if cwe_num else ""

            self.rules[rule_id] = {
                "id": rule_id,
                "name": vuln.category,
                "shortDescription": {"text": vuln.title},
                "fullDescription": {"text": vuln.description},
                "defaultConfiguration": {
                    "level": self._severity_to_sarif_level(vuln.severity),
                },
                "helpUri": help_uri,
                "help": {
                    "text": vuln.fix_suggestion or "Review and fix this issue.",
                    "markdown": self._create_markdown_help(vuln),
                },
                "properties": {
                    "tags": ["security", vuln.severity.lower(), vuln.owasp_category or ""],
                    "precision": vuln.confidence.lower() if vuln.confidence else "medium",
                    "security-severity": str(vuln.cvss_score or self._severity_to_cvss(vuln.severity)),
                },
            }

        return rule_id

    def _create_markdown_help(self, vuln: Vulnerability) -> str:
        """Create markdown-formatted help text for a rule."""
        lines = [
            f"# {vuln.title}",
            "",
            f"**Category:** {vuln.category}",
            f"**CWE:** {vuln.cwe_id or 'N/A'} - {vuln.cwe_name or 'N/A'}",
            f"**OWASP:** {vuln.owasp_category or 'N/A'}",
            f"**CVSS Score:** {vuln.cvss_score or 'N/A'}",
            f"**Confidence:** {vuln.confidence}",
            "",
            "## Description",
            "",
            vuln.description,
            "",
            "## Fix",
            "",
            vuln.fix_suggestion or "Review and fix this issue based on CWE guidelines.",
        ]
        return "\n".join(lines)

    @staticmethod
    def _slugify(text: str) -> str:
        """Convert text to a slug suitable for rule IDs."""
        return text.lower().replace(" ", "-").replace("_", "-").replace("/", "-")[:50]

    @staticmethod
    def _severity_to_sarif_level(severity: str) -> str:
        """
        Map severity to SARIF notification level.

        SARIF levels: error, warning, note, none
        """
        mapping = {
            "CRITICAL": "error",
            "HIGH": "error",
            "MEDIUM": "warning",
            "LOW": "note",
            "INFO": "none",
        }
        return mapping.get(severity.upper(), "warning")

    @staticmethod
    def _severity_to_cvss(severity: str) -> float:
        """Map severity to approximate CVSS score."""
        mapping = {
            "CRITICAL": 9.5,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.0,
            "INFO": 0.0,
        }
        return mapping.get(severity.upper(), 5.0)

    def _build_locations(self, vuln: Vulnerability, source_path: str) -> List[Dict[str, Any]]:
        """Build SARIF location objects for a vulnerability."""
        location: Dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": vuln.file_path,
                    "uriBaseId": "%SRCROOT%",
                },
                "region": {
                    "startLine": vuln.line_number,
                    "startColumn": vuln.column if vuln.column else 1,
                },
            },
        }

        if vuln.code_snippet:
            location["physicalLocation"]["region"]["snippet"] = {
                "text": vuln.code_snippet,
            }

        return [location]

    def _build_fixes(self, vuln: Vulnerability) -> List[Dict[str, Any]]:
        """Build SARIF fix objects for a vulnerability."""
        if not vuln.fix_suggestion:
            return []

        return [
            {
                "description": {
                    "text": vuln.fix_suggestion,
                },
            }
        ]

    def _build_code_flow(self, vuln: Vulnerability) -> Optional[Dict[str, Any]]:
        """Build a simple codeFlow for the vulnerability location."""
        if not vuln.file_path or not vuln.line_number:
            return None

        return {
            "codeFlows": [
                {
                    "threadFlows": [
                        {
                            "locations": [
                                {
                                    "location": {
                                        "physicalLocation": {
                                            "artifactLocation": {
                                                "uri": vuln.file_path,
                                            },
                                            "region": {
                                                "startLine": vuln.line_number,
                                                "startColumn": vuln.column if vuln.column else 1,
                                                "message": {
                                                    "text": vuln.description,
                                                },
                                            },
                                        },
                                    },
                                    "kinds": ["execution"],
                                }
                            ]
                        }
                    ]
                }
            ]
        }

    def export(self, scan_result: ScanResult) -> str:
        """
        Export a ScanResult to SARIF 2.1.0 JSON string.

        Args:
            scan_result: The scan result to export

        Returns:
            JSON string in SARIF 2.1.0 format
        """
        logger.info("Generating SARIF 2.1.0 export for scan %s", scan_result.scan_id)

        # Build results and collect rules
        results: List[Dict[str, Any]] = []
        self.rules = {}

        for vuln in scan_result.vulnerabilities:
            tool_name = vuln.tool_source or "custom_ai"
            rule_id = self._get_or_create_rule(vuln, tool_name)

            result: Dict[str, Any] = {
                "ruleId": rule_id,
                "ruleIndex": list(self.rules.keys()).index(rule_id),
                "level": self._severity_to_sarif_level(vuln.severity),
                "message": {
                    "text": vuln.description,
                },
                "locations": self._build_locations(vuln, scan_result.source_path),
                "properties": {
                    "cweId": vuln.cwe_id,
                    "cweName": vuln.cwe_name,
                    "owaspCategory": vuln.owasp_category,
                    "cvssScore": vuln.cvss_score,
                    "confidence": vuln.confidence,
                    "toolSource": vuln.tool_source,
                },
            }

            # Add code flow if applicable
            code_flow = self._build_code_flow(vuln)
            if code_flow:
                result.update(code_flow)

            # Add fixes if available
            fixes = self._build_fixes(vuln)
            if fixes:
                result["fixes"] = fixes

            results.append(result)

        # Build tool component
        driver: Dict[str, Any] = {
            "name": "CodeShield AI",
            "fullName": "CodeShield AI Multi-Tool Security Scanner",
            "informationUri": "https://codeshield.ai",
            "version": "1.0.0",
            "organization": "CodeShield AI",
            "rules": list(self.rules.values()),
        }

        # Group extensions by tool
        extensions: List[Dict[str, Any]] = []
        for tool_name, component in self.tool_components.items():
            tool_rules = [
                r for r in self.rules.values() if r["properties"].get("toolSource") == tool_name
            ]
            if tool_rules:
                ext = dict(component)
                ext["rules"] = tool_rules
                extensions.append(ext)

        tool = {"driver": driver}
        if extensions:
            tool["extensions"] = extensions

        # Build the run
        run: Dict[str, Any] = {
            "tool": tool,
            "invocations": [
                {
                    "executionSuccessful": scan_result.status == "completed",
                    "startTimeUtc": scan_result.start_time.isoformat() if scan_result.start_time else None,
                    "endTimeUtc": scan_result.end_time.isoformat() if scan_result.end_time else None,
                }
            ],
            "results": results,
            "artifacts": self._build_artifacts(scan_result),
            "properties": {
                "scanId": scan_result.scan_id,
                "scanName": scan_result.name,
                "sourceType": scan_result.source_type,
                "riskScore": scan_result.risk_score,
                "stats": scan_result.stats,
                "languages": scan_result.languages,
                "totalFiles": scan_result.total_files,
                "totalLines": scan_result.total_lines,
                "scanDuration": scan_result.scan_duration,
            },
        }

        # Build the full SARIF log
        sarif_log = {
            "$schema": SARIF_SCHEMA,
            "version": SARIF_VERSION,
            "runs": [run],
        }

        return json.dumps(sarif_log, indent=2, default=str)

    def _build_artifacts(self, scan_result: ScanResult) -> List[Dict[str, Any]]:
        """Build artifact entries from scanned files."""
        artifacts: List[Dict[str, Any]] = []
        seen_files: set = set()

        for vuln in scan_result.vulnerabilities:
            if vuln.file_path not in seen_files:
                seen_files.add(vuln.file_path)
                artifacts.append(
                    {
                        "location": {
                            "uri": vuln.file_path,
                            "uriBaseId": "%SRCROOT%",
                        },
                        "sourceLanguage": self._detect_language(vuln.file_path),
                    }
                )

        return artifacts

    @staticmethod
    def _detect_language(file_path: str) -> str:
        """Detect source language from file extension."""
        ext_map = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "typescript",
            ".tsx": "typescript",
            ".java": "java",
            ".go": "go",
            ".rb": "ruby",
            ".php": "php",
            ".c": "c",
            ".cpp": "cpp",
            ".cs": "csharp",
            ".swift": "swift",
            ".kt": "kotlin",
            ".rs": "rust",
            ".html": "html",
        }
        import os

        ext = os.path.splitext(file_path)[1].lower()
        return ext_map.get(ext, "")

    def export_to_file(self, scan_result: ScanResult, file_path: str) -> None:
        """
        Export scan result to a SARIF file.

        Args:
            scan_result: The scan result to export
            file_path: Path to write the SARIF file
        """
        sarif_content = self.export(scan_result)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(sarif_content)
        logger.info("SARIF report written to %s", file_path)
