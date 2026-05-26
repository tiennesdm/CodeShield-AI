"""
Base class for all CodeShield AI security scanning agents.

Provides the abstract interface that every agent must implement,
along with common utility methods for result normalization,
health checking, and error handling.
"""

import time
from abc import ABC, abstractmethod
from typing import Any, Dict, List, Optional

from models.vulnerability import Vulnerability
from utils.constants import CWE_MAPPING, CWE_TO_OWASP
from utils.logger import get_logger

from agents.results import (
    AgentCapabilities,
    AgentResult,
    HealthState,
    HealthStatus,
    ScanContext,
    ScanSummary,
    ToolExecutionSummary,
)

logger = get_logger(__name__)


class BaseSecurityAgent(ABC):
    """
    Abstract base class for all security scanning agents.

    All concrete agents (John, Dave, Sam, Pam, Tina, Sade) must inherit
    from this class and implement the abstract methods.

    Attributes:
        name: Agent identifier (e.g., 'john_sast')
        role: Human-readable description of the agent's role
        tools: List of tool names this agent can invoke
        priority: Execution priority (lower = earlier in pipeline)
    """

    name: str = "base_agent"
    role: str = "Base security agent"
    tools: List[str] = []
    priority: int = 50

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the agent with optional configuration.

        Args:
            config: Agent-specific configuration dictionary
        """
        self.config = config or {}
        self._initialized = True
        logger.info("[%s] Agent initialized with config: %s", self.name, self.config)

    @abstractmethod
    async def scan(self, context: ScanContext) -> AgentResult:
        """
        Main scan method. Must be implemented by all subclasses.

        Args:
            context: ScanContext with scan parameters

        Returns:
            AgentResult with findings and metadata
        """

    async def health_check(self) -> HealthStatus:
        """
        Check if the agent is healthy.

        Default implementation checks that all required tools report available.
        Subclasses may override for more specific checks.

        Returns:
            HealthStatus indicating agent health
        """
        details: Dict[str, Any] = {"tools_checked": len(self.tools), "tools_available": 0}
        available = 0

        for tool_name in self.tools:
            is_avail = await self._check_tool_available(tool_name)
            details[f"tool_{tool_name}"] = "available" if is_avail else "unavailable"
            if is_avail:
                available += 1

        details["tools_available"] = available

        if available == len(self.tools) and len(self.tools) > 0:
            state = HealthState.HEALTHY
            message = f"All {available} tools available"
        elif available > 0:
            state = HealthState.DEGRADED
            message = f"{available}/{len(self.tools)} tools available"
        elif len(self.tools) == 0:
            state = HealthState.HEALTHY
            message = "No external tools required"
        else:
            state = HealthState.UNHEALTHY
            message = f"No tools available (expected {len(self.tools)})"

        return HealthStatus(
            agent_name=self.name,
            state=state,
            message=message,
            details=details,
        )

    def get_capabilities(self) -> AgentCapabilities:
        """
        Return what this agent can do.

        Returns:
            AgentCapabilities describing the agent's abilities
        """
        return AgentCapabilities(
            agent_name=self.name,
            agent_role=self.role,
            tools=self.tools,
            supported_languages=self._get_supported_languages(),
            categories=self._get_categories(),
            can_run_standalone=self._can_run_standalone(),
            requires_network=self._requires_network(),
            requires_external_tools=self._requires_external_tools(),
            priority=self.priority,
        )

    # ------------------------------------------------------------------
    # Protected helpers for subclasses
    # ------------------------------------------------------------------

    async def _run_tool_with_fallback(
        self,
        tool_callable,
        tool_name: str,
        context: ScanContext,
        fallback_result: Optional[List[Vulnerability]] = None,
    ) -> List[Vulnerability]:
        """
        Run a tool with error handling and fallback.

        Args:
            tool_callable: Async callable that returns List[Vulnerability]
            tool_name: Name of the tool for logging
            context: ScanContext
            fallback_result: Result to return on failure

        Returns:
            List of Vulnerability findings
        """
        if fallback_result is None:
            fallback_result = []

        try:
            logger.info("[%s] Running tool: %s", context.scan_id, tool_name)
            result = await tool_callable()
            logger.info(
                "[%s] Tool %s completed with %d findings",
                context.scan_id,
                tool_name,
                len(result),
            )
            return result if result is not None else fallback_result
        except Exception as e:
            logger.error("[%s] Tool %s failed: %s", context.scan_id, tool_name, e)
            return fallback_result

    def _enrich_findings(self, findings: List[Vulnerability]) -> List[Vulnerability]:
        """
        Enrich findings with CWE names and OWASP categories.

        Args:
            findings: Raw findings from tools

        Returns:
            Enriched findings
        """
        for finding in findings:
            if finding.cwe_id and not finding.cwe_name:
                finding.cwe_name = CWE_MAPPING.get(finding.cwe_id, finding.cwe_id)
            if finding.cwe_id and not finding.owasp_category:
                finding.owasp_category = CWE_TO_OWASP.get(finding.cwe_id)
        return findings

    def _build_result(
        self,
        context: ScanContext,
        findings: List[Vulnerability],
        start_time_ms: float,
        errors: List[str],
        metadata: Optional[Dict[str, Any]] = None,
        tool_summaries: Optional[List[ToolExecutionSummary]] = None,
    ) -> AgentResult:
        """
        Build a standardized AgentResult.

        Args:
            context: The scan context
            findings: All findings collected
            start_time_ms: Time when scan started (from time.time() * 1000)
            errors: Any error messages
            metadata: Agent-specific metadata
            tool_summaries: Per-tool execution summaries

        Returns:
            AgentResult
        """
        elapsed = int((time.time() * 1000) - start_time_ms)
        findings = self._enrich_findings(findings)

        summary = ScanSummary()
        summary.compute_from_findings(findings)
        if tool_summaries:
            summary.tool_summaries = tool_summaries
            summary.tools_executed = len(tool_summaries)
            summary.tools_successful = sum(
                1 for ts in tool_summaries if ts.status == "success"
            )
            summary.tools_failed = sum(
                1 for ts in tool_summaries if ts.status == "failed"
            )
            summary.tools_skipped = sum(
                1 for ts in tool_summaries if ts.status == "skipped"
            )

        status = "success"
        if errors:
            status = "partial" if findings else "failed"

        return AgentResult(
            agent_name=self.name,
            agent_role=self.role,
            scan_id=context.scan_id,
            findings=findings,
            summary=summary,
            execution_time_ms=elapsed,
            status=status,
            errors=errors,
            metadata=metadata or {},
        )

    async def _check_tool_available(self, tool_name: str) -> bool:
        """Check if a specific tool is available. Override in subclasses."""
        return True

    def _get_supported_languages(self) -> List[str]:
        """Return languages supported by this agent. Override in subclasses."""
        return []

    def _get_categories(self) -> List[str]:
        """Return vulnerability categories this agent detects. Override in subclasses."""
        return []

    def _can_run_standalone(self) -> bool:
        """Whether this agent can run without other agents."""
        return True

    def _requires_network(self) -> bool:
        """Whether this agent requires network access."""
        return False

    def _requires_external_tools(self) -> bool:
        """Whether this agent requires external CLI tools."""
        return bool(self.tools)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self.name!r}, role={self.role!r})>"
