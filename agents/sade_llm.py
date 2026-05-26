"""
Sade - LLM Security Agent for CodeShield AI Multi-Agent Swarm.

Wraps the LLM Security Scanner and Container Scanner.
Detects AI-generated code patterns, scans for OWASP LLM Top 10,
checks MCP (Model Context Protocol) security, and performs
container/IaC scanning.
"""

import time
from typing import Any, Dict, List

from models.vulnerability import Vulnerability
from scanner.tools.container_scanner import ContainerScanner
from scanner.tools.llm_security_scanner import LLMSecurityScanner
from utils.logger import get_logger

from agents.base import BaseSecurityAgent
from agents.results import AgentResult, ScanContext, ToolExecutionSummary

logger = get_logger(__name__)


class SadeLLMSecurityAgent(BaseSecurityAgent):
    """
    Sade - LLM Security & Container Agent.

    Specialized security analysis for AI-related and deployment concerns:
    - AI-generated code pattern detection (Copilot/ChatGPT signatures)
    - OWASP LLM Top 10 compliance (LLM01-LLM10)
    - MCP (Model Context Protocol) security scanning
    - Prompt injection detection in RAG applications
    - Hardcoded LLM API key detection
    - Container/IaC scanning (Dockerfile, K8s, Terraform, Helm)

    Priority: 30 (runs after core code analysis)
    """

    name: str = "sade_llm"
    role: str = "LLM Security & Container Scanning - detects AI-specific vulnerabilities and container misconfigs"
    tools: List[str] = ["llm_security_scanner", "container_scanner"]
    priority: int = 30

    def __init__(self, config: Dict[str, Any] = None) -> None:
        super().__init__(config)
        self._llm_security = LLMSecurityScanner()
        self._container = ContainerScanner()
        self._scan_images = (config or {}).get("scan_images", False)

    async def scan(self, context: ScanContext) -> AgentResult:
        """
        Run LLM security and container scanning.

        Args:
            context: ScanContext

        Returns:
            AgentResult with LLM-specific and container findings
        """
        start = time.time() * 1000
        logger.info("[%s] Sade LLM Security Agent starting", context.scan_id)

        all_findings: List[Vulnerability] = []
        errors: List[str] = []
        tool_summaries: List[ToolExecutionSummary] = []
        metadata: Dict[str, Any] = {
            "llm_categories": {},
            "container_categories": {},
            "owasp_llm_summary": {},
            "mcp_summary": {},
        }

        # 1. Run LLM Security Scanner
        t0 = time.time() * 1000
        try:
            logger.info("[%s] Running LLM security scanner", context.scan_id)
            llm_findings = await self._llm_security.scan(
                context.source_path, context.scan_id
            )
            elapsed = int(time.time() * 1000 - t0)
            all_findings.extend(llm_findings)

            # Categorize LLM findings
            owasp_llm_counts: Dict[str, int] = {}
            mcp_counts: Dict[str, int] = {}
            ai_sig_counts: Dict[str, int] = {}

            for f in llm_findings:
                cat = f.category
                if cat.startswith("OWASP LLM"):
                    owasp_llm_counts[cat] = owasp_llm_counts.get(cat, 0) + 1
                elif cat.startswith("MCP"):
                    mcp_counts[cat] = mcp_counts.get(cat, 0) + 1
                elif "AI" in cat or "Hallucinated" in cat:
                    ai_sig_counts[cat] = ai_sig_counts.get(cat, 0) + 1

            metadata["owasp_llm_summary"] = owasp_llm_counts
            metadata["mcp_summary"] = mcp_counts
            metadata["llm_categories"] = {
                "owasp_llm_findings": sum(owasp_llm_counts.values()),
                "mcp_findings": sum(mcp_counts.values()),
                "ai_signature_findings": sum(ai_sig_counts.values()),
                "total_llm_findings": len(llm_findings),
            }

            tool_summaries.append(
                ToolExecutionSummary(
                    tool_name="llm_security_scanner",
                    status="success",
                    findings_count=len(llm_findings),
                    execution_time_ms=elapsed,
                )
            )
            logger.info(
                "[%s] LLM scanner found %d findings in %d ms",
                context.scan_id,
                len(llm_findings),
                elapsed,
            )

        except Exception as e:
            elapsed = int(time.time() * 1000 - t0)
            errors.append(f"LLM security scan failed: {e}")
            tool_summaries.append(
                ToolExecutionSummary(
                    tool_name="llm_security_scanner",
                    status="failed",
                    findings_count=0,
                    execution_time_ms=elapsed,
                    error_message=str(e),
                )
            )

        # 2. Run Container/IaC Scanner
        t0 = time.time() * 1000
        try:
            logger.info("[%s] Running container/IaC scanner", context.scan_id)
            container_findings = await self._container.scan(
                source_path=context.source_path,
                scan_id=context.scan_id,
                scan_images=self._scan_images,
            )
            elapsed = int(time.time() * 1000 - t0)
            all_findings.extend(container_findings)

            # Categorize container findings
            container_cats: Dict[str, int] = {}
            for f in container_findings:
                cat = f.category
                container_cats[cat] = container_cats.get(cat, 0) + 1

            metadata["container_categories"] = container_cats

            tool_summaries.append(
                ToolExecutionSummary(
                    tool_name="container_scanner",
                    status="success",
                    findings_count=len(container_findings),
                    execution_time_ms=elapsed,
                )
            )
            logger.info(
                "[%s] Container scanner found %d findings in %d ms",
                context.scan_id,
                len(container_findings),
                elapsed,
            )

        except Exception as e:
            elapsed = int(time.time() * 1000 - t0)
            errors.append(f"Container scan failed: {e}")
            tool_summaries.append(
                ToolExecutionSummary(
                    tool_name="container_scanner",
                    status="failed",
                    findings_count=0,
                    execution_time_ms=elapsed,
                    error_message=str(e),
                )
            )

        deduped = self._deduplicate(all_findings)
        logger.info(
            "[%s] Sade LLM Security complete: %d findings",
            context.scan_id,
            len(deduped),
        )

        return self._build_result(
            context=context,
            findings=deduped,
            start_time_ms=start,
            errors=errors,
            metadata=metadata,
            tool_summaries=tool_summaries,
        )

    def _deduplicate(self, findings: List[Vulnerability]) -> List[Vulnerability]:
        """Deduplicate findings."""
        seen: Dict[str, Vulnerability] = {}
        for f in findings:
            key = f"{f.file_path}:{f.line_number}:{f.category}"
            if key not in seen:
                seen[key] = f
            else:
                existing = seen[key]
                severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
                if severity_order.get(f.severity, 0) > severity_order.get(existing.severity, 0):
                    seen[key] = f
        return list(seen.values())

    def _get_supported_languages(self) -> List[str]:
        return ["*"]  # LLM patterns are language-agnostic; container scanning covers all

    def _get_categories(self) -> List[str]:
        return [
            # LLM categories
            "AI-Generated Code", "AI Insecure Default", "AI Placeholder Auth",
            "LLM Prompt Injection", "LLM Input Validation", "LLM Insecure Output",
            "OWASP LLM Top 10", "MCP Security",
            # Container categories
            "Container/IaC", "Dockerfile Security", "Kubernetes Security",
            "Terraform Security", "Helm Chart Security",
        ]

    def _can_run_standalone(self) -> bool:
        return True
