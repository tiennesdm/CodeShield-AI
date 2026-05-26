"""
John - SAST Agent for CodeShield AI Multi-Agent Swarm.

Wraps Semgrep, ESLint, Bandit, PMD, Custom AI Scanner, and LLM Security Scanner.
Runs all SAST tools in parallel, normalizes findings, enriches with CWE/OWASP data.
"""

import asyncio
import time
from typing import Any, Dict, List

from models.vulnerability import Vulnerability
from scanner.tools.bandit_scanner import BanditScanner
from scanner.tools.custom_ai_scanner import CustomAIScanner
from scanner.tools.eslint_scanner import ESLintScanner
from scanner.tools.llm_security_scanner import LLMSecurityScanner
from scanner.tools.pmd_scanner import PMDScanner
from scanner.tools.semgrep_scanner import SemgrepScanner
from utils.logger import get_logger

from agents.base import BaseSecurityAgent
from agents.results import AgentResult, ScanContext, ToolExecutionSummary

logger = get_logger(__name__)


class JohnSASTAgent(BaseSecurityAgent):
    """
    John - Static Application Security Testing (SAST) Agent.

    Runs multiple SAST tools in parallel to find code-level vulnerabilities:
    - Semgrep: Multi-language static analysis
    - ESLint: JavaScript/TypeScript security
    - Bandit: Python-specific security
    - PMD: Java security and best practices
    - Custom AI Scanner: Pattern-based detection (always available)
    - LLM Security Scanner: AI-generated code vulnerabilities

    Priority: 10 (runs early in the pipeline)
    """

    name: str = "john_sast"
    role: str = "Static Application Security Testing (SAST) - finds code-level vulnerabilities"
    tools: List[str] = [
        "semgrep",
        "eslint",
        "bandit",
        "pmd",
        "custom_ai_scanner",
        "llm_security_scanner",
    ]
    priority: int = 10

    def __init__(self, config: Dict[str, Any] = None) -> None:
        super().__init__(config)
        self._semgrep = SemgrepScanner()
        self._eslint = ESLintScanner()
        self._bandit = BanditScanner()
        self._pmd = PMDScanner()
        self._custom_ai = CustomAIScanner()
        self._llm_security = LLMSecurityScanner()

    async def scan(self, context: ScanContext) -> AgentResult:
        """
        Run all SAST tools in parallel and combine results.

        Args:
            context: ScanContext with source_path, scan_id, etc.

        Returns:
            AgentResult with all SAST findings
        """
        start = time.time() * 1000
        logger.info("[%s] John SAST Agent starting scan of %s", context.scan_id, context.source_path)

        all_findings: List[Vulnerability] = []
        errors: List[str] = []
        tool_summaries: List[ToolExecutionSummary] = []
        metadata: Dict[str, Any] = {"tools_ran": [], "tools_skipped": []}

        # Determine which tools to run based on config and detected languages
        tools_to_run = self._select_tools(context)
        metadata["tools_selected"] = list(tools_to_run.keys())

        # Run all selected tools concurrently
        coros = []
        for tool_name, tool_info in tools_to_run.items():
            coros.append(self._run_tool(tool_name, tool_info, context))

        results = await asyncio.gather(*coros, return_exceptions=True)

        for tool_name, result in zip(tools_to_run.keys(), results):
            if isinstance(result, Exception):
                error_msg = f"{tool_name} failed: {str(result)}"
                errors.append(error_msg)
                tool_summaries.append(
                    ToolExecutionSummary(
                        tool_name=tool_name,
                        status="failed",
                        findings_count=0,
                        error_message=str(result),
                    )
                )
                logger.error("[%s] %s", context.scan_id, error_msg)
            else:
                findings, summary = result
                all_findings.extend(findings)
                tool_summaries.append(summary)
                metadata["tools_ran"].append(tool_name)
                logger.info(
                    "[%s] %s found %d findings in %d ms",
                    context.scan_id,
                    tool_name,
                    summary.findings_count,
                    summary.execution_time_ms,
                )

        # Deduplicate findings
        deduped = self._deduplicate_findings(all_findings)
        metadata["findings_before_dedup"] = len(all_findings)
        metadata["findings_after_dedup"] = len(deduped)

        logger.info(
            "[%s] John SAST complete: %d findings (%d after dedup) from %d tools",
            context.scan_id,
            len(all_findings),
            len(deduped),
            len(tools_to_run),
        )

        return self._build_result(
            context=context,
            findings=deduped,
            start_time_ms=start,
            errors=errors,
            metadata=metadata,
            tool_summaries=tool_summaries,
        )

    def _select_tools(self, context: ScanContext) -> Dict[str, Any]:
        """Select which tools to run based on config and languages."""
        tools: Dict[str, Any] = {}
        langs = set((context.languages or []))
        config_tools = context.config.get("tools", [])

        # Always run custom_ai (no external deps, finds secrets + patterns)
        tools["custom_ai"] = {"scanner": self._custom_ai, "langs": "all"}

        # Always run llm_security (no external deps, finds AI-gen issues)
        tools["llm_security"] = {"scanner": self._llm_security, "langs": "all"}

        # Semgrep: multi-language
        if not config_tools or "semgrep" in config_tools:
            tools["semgrep"] = {"scanner": self._semgrep, "langs": "all"}

        # ESLint: JS/TS only
        if (not config_tools or "eslint" in config_tools) and (
            not langs or langs & {"javascript", "typescript", "jsx", "tsx"}
        ):
            tools["eslint"] = {"scanner": self._eslint, "langs": {"javascript", "typescript"}}

        # Bandit: Python only
        if (not config_tools or "bandit" in config_tools) and (
            not langs or "python" in langs
        ):
            tools["bandit"] = {"scanner": self._bandit, "langs": {"python"}}

        # PMD: Java only
        if (not config_tools or "pmd" in config_tools) and (
            not langs or "java" in langs
        ):
            tools["pmd"] = {"scanner": self._pmd, "langs": {"java"}}

        return tools

    async def _run_tool(
        self, tool_name: str, tool_info: Dict[str, Any], context: ScanContext
    ) -> tuple:
        """Run a single tool and return findings + summary."""
        scanner = tool_info["scanner"]
        t0 = time.time() * 1000

        try:
            findings = await scanner.scan(context.source_path, context.scan_id)
            elapsed = int(time.time() * 1000 - t0)
            return (
                findings,
                ToolExecutionSummary(
                    tool_name=tool_name,
                    status="success",
                    findings_count=len(findings),
                    execution_time_ms=elapsed,
                ),
            )
        except Exception as e:
            elapsed = int(time.time() * 1000 - t0)
            return (
                [],
                ToolExecutionSummary(
                    tool_name=tool_name,
                    status="failed",
                    findings_count=0,
                    execution_time_ms=elapsed,
                    error_message=str(e),
                ),
            )

    def _deduplicate_findings(self, findings: List[Vulnerability]) -> List[Vulnerability]:
        """Deduplicate findings by file_path + line_number + category."""
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
        return [
            "python", "javascript", "typescript", "java",
            "go", "ruby", "php", "csharp", "swift", "kotlin", "rust",
        ]

    def _get_categories(self) -> List[str]:
        return [
            "Injection", "XSS", "Secret Leak", "Insecure Configuration",
            "Weak Cryptography", "Path Traversal", "SQL Injection",
            "Command Injection", "Hardcoded Credentials", "AI-Generated Code",
            "LLM Security", "MCP Security",
        ]
