"""
Tina - Taint Analysis Agent for CodeShield AI Multi-Agent Swarm.

Wraps the Taint Analyzer for deep data flow analysis.
Builds call graphs, tracks taint from sources to sinks,
performs cross-file data flow analysis.
"""

import time
from typing import Any, Dict, List

from models.vulnerability import Vulnerability
from scanner.tools.taint_analyzer import TaintAnalyzer
from utils.logger import get_logger

from agents.base import BaseSecurityAgent
from agents.results import AgentResult, ScanContext, ToolExecutionSummary

logger = get_logger(__name__)


class TinaTaintAgent(BaseSecurityAgent):
    """
    Tina - Taint Analysis Agent.

    Performs deep data flow analysis to track vulnerabilities:
    - Builds call graphs from imports
    - Tracks taint from user-input sources to dangerous sinks
    - Cross-file data flow analysis
    - Detects SQL injection, XSS, command injection, path traversal, SSRF
    - Identifies sanitization gaps

    Supports Python (MVP), with architecture for multi-language.
    Priority: 25 (runs after SAST, provides deeper analysis)
    """

    name: str = "tina_taint"
    role: str = "Taint Analysis - tracks data flow from sources to sinks for deep vulnerability detection"
    tools: List[str] = ["taint_analyzer"]
    priority: int = 25

    def __init__(self, config: Dict[str, Any] = None) -> None:
        super().__init__(config)
        self._taint = TaintAnalyzer()

    async def scan(self, context: ScanContext) -> AgentResult:
        """
        Run taint analysis on source code.

        Args:
            context: ScanContext

        Returns:
            AgentResult with taint flow findings
        """
        start = time.time() * 1000
        logger.info("[%s] Tina Taint Agent starting", context.scan_id)

        all_findings: List[Vulnerability] = []
        errors: List[str] = []
        tool_summaries: List[ToolExecutionSummary] = []
        metadata: Dict[str, Any] = {
            "taint_summary": {},
            "data_flow_paths": [],
            "sanitized_flows": 0,
            "unsanitized_flows": 0,
        }

        # Determine languages to analyze
        langs = set(context.languages or [])

        # Python taint analysis
        if not langs or "python" in langs:
            t0 = time.time() * 1000
            try:
                logger.info("[%s] Running Python taint analysis", context.scan_id)
                findings = self._taint.analyze(context.source_path, context.scan_id)
                elapsed = int(time.time() * 1000 - t0)
                all_findings.extend(findings)

                # Get analysis summary
                summary = self._taint.get_analysis_summary()
                metadata["taint_summary"]["python"] = summary
                metadata["sanitized_flows"] = summary.get("sanitized_flows", 0)
                metadata["unsanitized_flows"] = summary.get("unsanitized_flows", 0)

                # Extract data flow paths
                for flow in self._taint.taint_flows[:50]:  # Limit for metadata
                    metadata["data_flow_paths"].append({
                        "source_var": flow.source_var,
                        "sink_type": flow.sink_type,
                        "sink_func": flow.sink_func,
                        "file_path": flow.file_path,
                        "source_line": flow.source_line,
                        "sink_line": flow.sink_line,
                        "severity": flow.severity,
                        "sanitized": flow.sanitized,
                        "data_path": flow.data_path,
                    })

                tool_summaries.append(
                    ToolExecutionSummary(
                        tool_name="taint_analyzer_python",
                        status="success",
                        findings_count=len(findings),
                        execution_time_ms=elapsed,
                    )
                )

                logger.info(
                    "[%s] Taint analysis found %d flows (%d unsanitized) in %d ms",
                    context.scan_id,
                    summary.get("total_flows", 0),
                    summary.get("unsanitized_flows", 0),
                    elapsed,
                )

            except Exception as e:
                elapsed = int(time.time() * 1000 - t0)
                errors.append(f"Taint analysis failed: {e}")
                tool_summaries.append(
                    ToolExecutionSummary(
                        tool_name="taint_analyzer_python",
                        status="failed",
                        findings_count=0,
                        execution_time_ms=elapsed,
                        error_message=str(e),
                    )
                )

        # Cross-reference with SAST findings if available
        if context.sast_findings:
            confirmations = self._cross_reference_sast(context, all_findings)
            metadata["sast_confirmations"] = confirmations

        logger.info(
            "[%s] Tina Taint complete: %d findings",
            context.scan_id,
            len(all_findings),
        )

        return self._build_result(
            context=context,
            findings=all_findings,
            start_time_ms=start,
            errors=errors,
            metadata=metadata,
            tool_summaries=tool_summaries,
        )

    def _cross_reference_sast(
        self, context: ScanContext, taint_findings: List[Vulnerability]
    ) -> List[Dict[str, Any]]:
        """
        Cross-reference taint findings with SAST findings for confirmation.

        When SAST and taint analysis both flag the same vulnerability,
        increase confidence and mark as confirmed.

        Args:
            context: ScanContext with sast_findings
            taint_findings: Findings from taint analysis

        Returns:
            List of confirmation results
        """
        confirmations: List[Dict[str, Any]] = []
        sast_injections = [
            f for f in context.sast_findings
            if any(cat in f.category.lower() for cat in [
                "injection", "sql", "command", "xss", "ssrf", "path traversal"
            ])
        ]

        for taint_finding in taint_findings:
            for sast_finding in sast_injections:
                # Check if findings point to the same general area
                same_file = (
                    taint_finding.file_path in sast_finding.file_path
                    or sast_finding.file_path in taint_finding.file_path
                )
                nearby_lines = abs(taint_finding.line_number - sast_finding.line_number) <= 5

                if same_file and nearby_lines:
                    confirmations.append({
                        "taint_finding_id": taint_finding.id,
                        "sast_finding_id": sast_finding.id,
                        "file_path": taint_finding.file_path,
                        "line": taint_finding.line_number,
                        "category": taint_finding.category,
                        "confirmation": "SAST+taint_agree",
                        "confidence": "HIGH",
                    })
                    # Boost the taint finding's confidence
                    taint_finding.confidence = "HIGH"
                    break

        return confirmations

    def _get_supported_languages(self) -> List[str]:
        return ["python"]  # MVP - Python only

    def _get_categories(self) -> List[str]:
        return [
            "SQL Injection", "XSS", "Command Injection", "Path Traversal",
            "SSRF", "LDAP Injection", "XPath Injection", "Code Injection",
            "Taint Flow",
        ]
