"""
Pam - SCA Agent for CodeShield AI Multi-Agent Swarm.

Wraps OSV Scanner, Reachability Analyzer, and SBOM Generator.
Parses dependency files, queries OSV.dev for CVEs, runs reachability
analysis, and generates SBOMs in SPDX and CycloneDX formats.
"""

import time
from typing import Any, Dict, List

from models.vulnerability import Vulnerability
from scanner.tools.osv_scanner import OSVScanner
from scanner.tools.reachability_analyzer import SCAAnalyzer
from utils.logger import get_logger

from agents.base import BaseSecurityAgent
from agents.results import AgentResult, ScanContext, ToolExecutionSummary

logger = get_logger(__name__)


class PamSCAAgent(BaseSecurityAgent):
    """
    Pam - Software Composition Analysis (SCA) Agent.

    Analyzes dependencies for known vulnerabilities:
    - OSV Scanner: Queries OSV.dev for CVEs in dependencies
    - Reachability Analyzer: Determines which vulns are actually reachable
    - SBOM Generator: Produces SPDX 2.3 and CycloneDX 1.5 SBOMs
    - EPSS scoring and CISA KEV flagging

    Priority: 15 (runs early, right after secrets)
    """

    name: str = "pam_sca"
    role: str = "Software Composition Analysis - finds vulnerable dependencies and generates SBOMs"
    tools: List[str] = ["osv_scanner", "reachability_analyzer", "sbom_generator"]
    priority: int = 15

    def __init__(self, config: Dict[str, Any] = None) -> None:
        super().__init__(config)
        self._osv = OSVScanner()
        self._sca = SCAAnalyzer()

    async def scan(self, context: ScanContext) -> AgentResult:
        """
        Run SCA analysis: OSV scanning + reachability + SBOM generation.

        Args:
            context: ScanContext

        Returns:
            AgentResult with dependency vulns, reachability scores, and SBOM
        """
        start = time.time() * 1000
        logger.info("[%s] Pam SCA Agent starting", context.scan_id)

        all_findings: List[Vulnerability] = []
        errors: List[str] = []
        tool_summaries: List[ToolExecutionSummary] = []
        metadata: Dict[str, Any] = {
            "sbom": {},
            "reachability": {},
            "dependency_stats": {},
        }

        # 1. Run OSV Scanner for known vulnerabilities
        t0 = time.time() * 1000
        try:
            logger.info("[%s] Running OSV vulnerability scan", context.scan_id)
            osv_findings = await self._osv.scan(context.source_path, context.scan_id)
            elapsed = int(time.time() * 1000 - t0)
            all_findings.extend(osv_findings)
            tool_summaries.append(
                ToolExecutionSummary(
                    tool_name="osv_scanner",
                    status="success",
                    findings_count=len(osv_findings),
                    execution_time_ms=elapsed,
                )
            )
            metadata["dependency_stats"]["osv_vulnerabilities"] = len(osv_findings)
        except Exception as e:
            elapsed = int(time.time() * 1000 - t0)
            errors.append(f"OSV scan failed: {e}")
            tool_summaries.append(
                ToolExecutionSummary(
                    tool_name="osv_scanner",
                    status="failed",
                    findings_count=0,
                    execution_time_ms=elapsed,
                    error_message=str(e),
                )
            )

        # 2. Run Reachability Analysis
        t0 = time.time() * 1000
        try:
            logger.info("[%s] Running reachability analysis", context.scan_id)
            sca_result = self._sca.analyze_project(context.source_path, context.scan_id)
            elapsed = int(time.time() * 1000 - t0)

            # Extract reachability scores
            reachability_scores = sca_result.get("reachability_scores", {})
            score_distribution = sca_result.get("score_distribution", {})

            metadata["reachability"] = {
                "total_dependencies": sca_result.get("total_dependencies", 0),
                "direct_dependencies": sca_result.get("direct_dependencies", 0),
                "transitive_dependencies": sca_result.get("transitive_dependencies", 0),
                "reachable_dependencies": sca_result.get("reachable_dependencies", 0),
                "score_distribution": score_distribution,
                "scores": {
                    name: score for name, score in list(reachability_scores.items())[:50]
                },
            }

            # Add reachability as metadata to existing findings
            for finding in all_findings:
                dep_name = self._extract_dep_name_from_finding(finding)
                if dep_name and dep_name in reachability_scores:
                    score = reachability_scores[dep_name]
                    finding.metadata = finding.metadata or {}
                    finding.metadata["reachability_score"] = score.score
                    finding.metadata["reachability_multiplier"] = score.multiplier

            tool_summaries.append(
                ToolExecutionSummary(
                    tool_name="reachability_analyzer",
                    status="success",
                    findings_count=0,
                    execution_time_ms=elapsed,
                )
            )
        except Exception as e:
            elapsed = int(time.time() * 1000 - t0)
            errors.append(f"Reachability analysis failed: {e}")
            tool_summaries.append(
                ToolExecutionSummary(
                    tool_name="reachability_analyzer",
                    status="failed",
                    findings_count=0,
                    execution_time_ms=elapsed,
                    error_message=str(e),
                )
            )

        # 3. Generate SBOM
        t0 = time.time() * 1000
        try:
            logger.info("[%s] Generating SBOM", context.scan_id)
            sbom_format = context.options.get("sbom_format", "both")
            if sbom_format == "both":
                sbom = self._sca.generate_sbom(context.scan_id, format="both")
            elif sbom_format in ("spdx", "cyclonedx"):
                sbom = self._sca.generate_sbom(context.scan_id, format=sbom_format)
            else:
                sbom = self._sca.generate_sbom(context.scan_id, format="both")

            elapsed = int(time.time() * 1000 - t0)
            metadata["sbom"] = sbom
            tool_summaries.append(
                ToolExecutionSummary(
                    tool_name="sbom_generator",
                    status="success",
                    findings_count=0,
                    execution_time_ms=elapsed,
                )
            )
        except Exception as e:
            elapsed = int(time.time() * 1000 - t0)
            errors.append(f"SBOM generation failed: {e}")
            tool_summaries.append(
                ToolExecutionSummary(
                    tool_name="sbom_generator",
                    status="failed",
                    findings_count=0,
                    execution_time_ms=elapsed,
                    error_message=str(e),
                )
            )

        # Close OSV client
        try:
            await self._osv.close()
        except Exception:
            pass

        logger.info(
            "[%s] Pam SCA complete: %d vulns, %d deps analyzed",
            context.scan_id,
            len(all_findings),
            metadata["reachability"].get("total_dependencies", 0),
        )

        return self._build_result(
            context=context,
            findings=all_findings,
            start_time_ms=start,
            errors=errors,
            metadata=metadata,
            tool_summaries=tool_summaries,
        )

    def _extract_dep_name_from_finding(self, finding: Vulnerability) -> str:
        """Extract dependency name from a vulnerability finding."""
        code = finding.code_snippet or ""
        if "Package:" in code:
            parts = code.split("\n")
            for part in parts:
                if part.startswith("Package:"):
                    return part.split(":", 1)[1].strip()
        return ""

    def _get_supported_languages(self) -> List[str]:
        return [
            "python", "javascript", "typescript", "java",
            "go", "ruby", "php", "rust", "csharp",
        ]

    def _get_categories(self) -> List[str]:
        return [
            "Vulnerable Dependency", "Known CVE", "Outdated Component",
            "Supply Chain", "SBOM",
        ]

    def _requires_network(self) -> bool:
        return True  # OSV API queries require network
