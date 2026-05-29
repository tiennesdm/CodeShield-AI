"""
JUnit XML Exporter for CodeShield AI.

Generates CI-friendly JUnit XML output from scan results.
Compatible with Jenkins, GitLab CI, CircleCI, GitHub Actions, and other CI systems.

Each vulnerability is represented as a <testcase> with the severity
encoded in the type attribute and full details in <failure> or <skipped> tags.
"""

import html
from datetime import datetime, timezone
from typing import Any, Dict, List
from xml.etree.ElementTree import Element, SubElement, tostring

from models.vulnerability import ScanResult, Vulnerability
from utils.logger import get_logger

logger = get_logger(__name__)


class JUnitExporter:
    """
    Export scan results to JUnit XML format.

    Maps vulnerabilities to test cases for CI integration:
    - CRITICAL/HIGH -> <failure> (test failed)
    - MEDIUM/LOW -> <failure> with type="warning"
    - INFO -> <skipped>

    Features:
    - CI-friendly format (Jenkins, GitLab CI, CircleCI, GitHub Actions)
    - Severity encoded in failure type
    - Full vulnerability details in CDATA
    - Test suite metadata with timing
    """

    # Severity to JUnit outcome mapping
    SEVERITY_TO_TYPE = {
        "CRITICAL": "critical-vulnerability",
        "HIGH": "high-vulnerability",
        "MEDIUM": "medium-vulnerability",
        "LOW": "low-vulnerability",
        "INFO": "info",
    }

    def export(self, scan_result: ScanResult) -> str:
        """
        Export a ScanResult to JUnit XML string.

        Args:
            scan_result: The scan result to export

        Returns:
            XML string in JUnit format
        """
        logger.info("Generating JUnit XML export for scan %s", scan_result.scan_id)

        testsuites = Element("testsuites")
        testsuite = SubElement(
            testsuites,
            "testsuite",
            attrib={
                "name": f"CodeShield AI - {scan_result.name}",
                "tests": str(len(scan_result.vulnerabilities)),
                "failures": str(self._count_failures(scan_result)),
                "errors": "0",
                "skipped": str(self._count_skipped(scan_result)),
                "time": str(scan_result.scan_duration or 0),
                "timestamp": (scan_result.start_time or datetime.now(timezone.utc)).isoformat(),
                "id": scan_result.scan_id,
            },
        )

        # Add properties
        properties = SubElement(testsuite, "properties")
        self._add_property(properties, "scan_id", scan_result.scan_id)
        self._add_property(properties, "scan_name", scan_result.name)
        self._add_property(properties, "source_type", scan_result.source_type)
        self._add_property(properties, "risk_score", str(scan_result.risk_score))
        self._add_property(properties, "total_files", str(scan_result.total_files))
        self._add_property(properties, "total_lines", str(scan_result.total_lines))
        self._add_property(properties, "tools_used", ",".join(scan_result.tools_used))
        self._add_property(properties, "languages", ",".join(scan_result.languages))

        # Add stats as properties
        for sev, count in (scan_result.stats or {}).items():
            self._add_property(properties, f"count_{sev}", str(count))

        # Add each vulnerability as a testcase
        for vuln in scan_result.vulnerabilities:
            testcase = self._build_testcase(testsuite, vuln, scan_result)

        # Prettify and return
        raw_xml = tostring(testsuites, encoding="unicode")
        return self._prettify_xml(raw_xml)

    def _build_testcase(
        self, testsuite: Element, vuln: Vulnerability, scan_result: ScanResult
    ) -> Element:
        """Build a <testcase> element for a vulnerability."""
        testcase_name = f"{vuln.category} - {vuln.file_path}:{vuln.line_number}"
        classname = vuln.file_path.replace("/", ".").replace("\\", ".") or "unknown"

        testcase = SubElement(
            testsuite,
            "testcase",
            attrib={
                "name": testcase_name,
                "classname": f"codeshield.{scan_result.scan_id}.{classname}",
                "time": "0",
            },
        )

        severity = vuln.severity.upper()

        if severity == "INFO":
            # Info-level findings are "skipped" tests
            skipped = SubElement(testcase, "skipped")
            skipped.set("message", vuln.description)
            skipped.text = self._build_cdata(vuln)
        else:
            # All other severities are "failures"
            failure_type = self.SEVERITY_TO_TYPE.get(severity, "vulnerability")
            failure = SubElement(
                testcase,
                "failure",
                attrib={
                    "type": failure_type,
                    "message": f"[{severity}] {vuln.title}",
                },
            )
            failure.text = self._build_cdata(vuln)

        # Add system-out with code snippet
        if vuln.code_snippet:
            system_out = SubElement(testcase, "system-out")
            system_out.text = f"<![CDATA[Code snippet:\n{html.escape(vuln.code_snippet)}]]>"

        return testcase

    def _build_cdata(self, vuln: Vulnerability) -> str:
        """Build CDATA content with full vulnerability details."""
        lines = [
            f"<![CDATA[",
            f"Vulnerability: {html.escape(vuln.title)}",
            f"Severity: {vuln.severity}",
            f"Category: {html.escape(vuln.category)}",
            f"CWE: {vuln.cwe_id or 'N/A'} - {html.escape(vuln.cwe_name or 'N/A')}",
            f"OWASP: {vuln.owasp_category or 'N/A'}",
            f"CVSS Score: {vuln.cvss_score}",
            f"Confidence: {vuln.confidence}",
            f"Tool: {vuln.tool_source}",
            f"Location: {html.escape(vuln.file_path)}:{vuln.line_number}",
            "",
            "Description:",
            html.escape(vuln.description),
            "",
        ]

        if vuln.code_snippet:
            lines.extend([
                "Code Snippet:",
                html.escape(vuln.code_snippet),
                "",
            ])

        if vuln.fix_suggestion:
            lines.extend([
                "Suggested Fix:",
                html.escape(vuln.fix_suggestion),
            ])

        lines.append("]]>")
        return "\n".join(lines)

    @staticmethod
    def _add_property(properties: Element, name: str, value: str) -> None:
        """Add a <property> element."""
        prop = SubElement(properties, "property")
        prop.set("name", name)
        prop.set("value", value)

    def _count_failures(self, scan_result: ScanResult) -> int:
        """Count vulnerabilities that map to failures (non-INFO)."""
        return sum(
            1
            for v in scan_result.vulnerabilities
            if v.severity.upper() != "INFO"
        )

    def _count_skipped(self, scan_result: ScanResult) -> int:
        """Count INFO-level vulnerabilities (mapped to skipped)."""
        return sum(
            1
            for v in scan_result.vulnerabilities
            if v.severity.upper() == "INFO"
        )

    def _prettify_xml(self, xml_string: str) -> str:
        """
        Simple XML prettification.

        Args:
            xml_string: Raw XML string

        Returns:
            Formatted XML string with proper indentation
        """
        # Add XML declaration
        result = '<?xml version="1.0" encoding="UTF-8"?>\n'

        # Simple indentation based on tags
        indent_level = 0
        indent_size = 2
        i = 0
        parts: List[str] = []

        while i < len(xml_string):
            if xml_string[i] == "<":
                if xml_string[i + 1] == "/":
                    # Closing tag - decrease indent
                    indent_level -= 1

                # Write indent + tag
                start = i
                end = xml_string.find(">", i) + 1
                tag = xml_string[start:end]

                # Check if self-closing
                is_self_closing = tag.endswith("/>")
                is_closing = tag.startswith("</")
                is_cdata = "<![CDATA[" in tag or "]]>" in tag

                if not is_cdata:
                    parts.append(" " * (indent_level * indent_size) + tag)
                else:
                    parts.append(tag)

                if not is_self_closing and not is_closing and not is_cdata:
                    indent_level += 1

                i = end
            else:
                # Text content
                start = i
                while i < len(xml_string) and xml_string[i] != "<":
                    i += 1
                text = xml_string[start:i].strip()
                if text:
                    parts.append(" " * (indent_level * indent_size) + text)

        return result + "\n".join(parts)

    def export_to_file(self, scan_result: ScanResult, file_path: str) -> None:
        """
        Export scan result to a JUnit XML file.

        Args:
            scan_result: The scan result to export
            file_path: Path to write the JUnit XML file
        """
        junit_content = self.export(scan_result)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(junit_content)
        logger.info("JUnit XML report written to %s", file_path)
