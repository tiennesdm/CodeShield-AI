"""
Standardized result models for CodeShield AI scanning agents.

Defines AgentResult, ScanContext, HealthStatus, AgentCapabilities, and ScanSummary
used by all agents in the multi-agent swarm.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from models.vulnerability import Vulnerability


class AgentStatus(str, Enum):
    """Possible agent scan statuses."""

    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class HealthState(str, Enum):
    """Health check states for an agent."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class ScanContext:
    """Context passed to every agent scan invocation."""

    scan_id: str
    source_path: str
    source_type: str = "zip"  # zip, github, gitlab, etc.
    target_url: str = ""  # For DAST agents
    languages: List[str] = field(default_factory=list)
    config: Dict[str, Any] = field(default_factory=dict)
    sast_findings: List[Vulnerability] = field(default_factory=list)  # Cross-agent data
    previous_findings: List[Vulnerability] = field(default_factory=list)
    options: Dict[str, Any] = field(default_factory=dict)


@dataclass
class HealthStatus:
    """Health check result for an agent."""

    agent_name: str
    state: HealthState
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    checked_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def is_healthy(self) -> bool:
        return self.state in (HealthState.HEALTHY, HealthState.DEGRADED)


@dataclass
class AgentCapabilities:
    """Capabilities metadata for an agent."""

    agent_name: str
    agent_role: str
    tools: List[str]
    supported_languages: List[str]
    categories: List[str]
    can_run_standalone: bool = True
    requires_network: bool = False
    requires_external_tools: bool = False
    priority: int = 50


@dataclass
class ToolExecutionSummary:
    """Summary of a single tool's execution."""

    tool_name: str
    status: str  # success, failed, skipped
    findings_count: int = 0
    execution_time_ms: int = 0
    error_message: str = ""


@dataclass
class ScanSummary:
    """Summary statistics for a scan run."""

    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0
    tools_executed: int = 0
    tools_successful: int = 0
    tools_failed: int = 0
    tools_skipped: int = 0
    tool_summaries: List[ToolExecutionSummary] = field(default_factory=list)

    def compute_from_findings(self, findings: List[Vulnerability]) -> None:
        """Recompute counts from a list of findings."""
        self.total_findings = len(findings)
        self.critical = sum(1 for f in findings if f.severity == "CRITICAL")
        self.high = sum(1 for f in findings if f.severity == "HIGH")
        self.medium = sum(1 for f in findings if f.severity == "MEDIUM")
        self.low = sum(1 for f in findings if f.severity == "LOW")
        self.info = sum(1 for f in findings if f.severity == "INFO")


class AgentResult(BaseModel):
    """
    Standardized result format returned by every scanning agent.

    This is the universal envelope that HAL Orchestrator expects from
    all agents in the multi-agent swarm.
    """

    agent_name: str
    agent_role: str
    scan_id: str
    findings: List[Vulnerability] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)
    execution_time_ms: int = 0
    status: str = "success"  # success, partial, failed, skipped
    errors: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def compute_summary(self) -> None:
        """Recompute summary from findings."""
        self.summary.compute_from_findings(self.findings)

    def add_error(self, message: str) -> None:
        """Add an error message and update status if needed."""
        self.errors.append(message)
        if self.status == "success":
            self.status = "partial"

    def to_report_dict(self) -> Dict[str, Any]:
        """Convert to a plain dictionary suitable for JSON serialization."""
        return {
            "agent_name": self.agent_name,
            "agent_role": self.agent_role,
            "scan_id": self.scan_id,
            "status": self.status,
            "execution_time_ms": self.execution_time_ms,
            "findings_count": len(self.findings),
            "summary": {
                "total_findings": self.summary.total_findings,
                "critical": self.summary.critical,
                "high": self.summary.high,
                "medium": self.summary.medium,
                "low": self.summary.low,
                "info": self.summary.info,
                "tools_executed": self.summary.tools_executed,
                "tools_successful": self.summary.tools_successful,
                "tools_failed": self.summary.tools_failed,
                "tools_skipped": self.summary.tools_skipped,
            },
            "tool_summaries": [
                {
                    "tool_name": ts.tool_name,
                    "status": ts.status,
                    "findings_count": ts.findings_count,
                    "execution_time_ms": ts.execution_time_ms,
                    "error_message": ts.error_message,
                }
                for ts in self.summary.tool_summaries
            ],
            "errors": self.errors,
            "metadata": self.metadata,
        }
