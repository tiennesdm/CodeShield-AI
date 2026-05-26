"""
Agent Metrics Collector for CodeShield AI.

Tracks performance metrics across all agents in the multi-agent swarm:
- Execution time per agent
- Findings count per agent
- False positive rate per agent
- Agreement rate between agents
- Overall scan time vs single-agent scan time

Stores metrics for analysis and reporting.
"""

import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


class MetricType(str, Enum):
    """Types of metrics collected."""

    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    TIMER = "timer"


@dataclass
class AgentRunRecord:
    """A single execution record for an agent."""

    agent_name: str
    scan_id: str
    start_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    end_time: Optional[datetime] = None
    duration_ms: float = 0.0
    findings_count: int = 0
    severity_counts: Dict[str, int] = field(default_factory=dict)
    error_count: int = 0
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    def complete(self, findings_count: int = 0, error: Optional[str] = None) -> None:
        """Mark the run as complete."""
        self.end_time = datetime.now(timezone.utc)
        self.duration_ms = (self.end_time - self.start_time).total_seconds() * 1000
        self.findings_count = findings_count
        if error:
            self.error_count = 1
            self.error_message = error

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "agent_name": self.agent_name,
            "scan_id": self.scan_id,
            "start_time": self.start_time.isoformat() if self.start_time else None,
            "end_time": self.end_time.isoformat() if self.end_time else None,
            "duration_ms": round(self.duration_ms, 2),
            "findings_count": self.findings_count,
            "severity_counts": self.severity_counts,
            "error_count": self.error_count,
            "error_message": self.error_message,
            "metadata": self.metadata,
        }


@dataclass
class AgentMetrics:
    """Aggregated metrics for a single agent."""

    agent_name: str
    total_runs: int = 0
    total_findings: int = 0
    total_errors: int = 0
    avg_duration_ms: float = 0.0
    min_duration_ms: float = float("inf")
    max_duration_ms: float = 0.0
    avg_findings_per_run: float = 0.0
    findings_by_severity: Dict[str, int] = field(default_factory=dict)
    findings_by_category: Dict[str, int] = field(default_factory=dict)
    recent_runs: List[AgentRunRecord] = field(default_factory=list)

    def add_run(self, record: AgentRunRecord) -> None:
        """Add a run record to the metrics."""
        self.total_runs += 1
        self.total_findings += record.findings_count
        self.total_errors += record.error_count

        # Update duration stats
        self.min_duration_ms = min(self.min_duration_ms, record.duration_ms)
        self.max_duration_ms = max(self.max_duration_ms, record.duration_ms)

        # Running average
        self.avg_duration_ms = (
            (self.avg_duration_ms * (self.total_runs - 1)) + record.duration_ms
        ) / self.total_runs

        self.avg_findings_per_run = self.total_findings / self.total_runs

        # Update severity counts
        for sev, count in record.severity_counts.items():
            self.findings_by_severity[sev] = (
                self.findings_by_severity.get(sev, 0) + count
            )

        self.recent_runs.append(record)
        # Keep only last 100 runs
        if len(self.recent_runs) > 100:
            self.recent_runs = self.recent_runs[-100:]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "agent_name": self.agent_name,
            "total_runs": self.total_runs,
            "total_findings": self.total_findings,
            "total_errors": self.total_errors,
            "avg_duration_ms": round(self.avg_duration_ms, 2),
            "min_duration_ms": round(self.min_duration_ms, 2) if self.min_duration_ms != float("inf") else 0,
            "max_duration_ms": round(self.max_duration_ms, 2),
            "avg_findings_per_run": round(self.avg_findings_per_run, 2),
            "findings_by_severity": self.findings_by_severity,
            "findings_by_category": self.findings_by_category,
            "error_rate": round(self.total_errors / self.total_runs, 4) if self.total_runs > 0 else 0,
        }


class AgentMetricsCollector:
    """
    Agent Metrics Collector for CodeShield AI.

    Tracks performance across all agents in the multi-agent swarm:
    - Execution time per agent
    - Findings count per agent
    - False positive rate per agent
    - Agreement rate between agents
    - Overall scan time vs single-agent scan time
    """

    def __init__(self) -> None:
        """Initialize the metrics collector."""
        self._agent_metrics: Dict[str, AgentMetrics] = {}
        self._run_records: List[AgentRunRecord] = []
        self._scan_records: Dict[str, Dict[str, Any]] = {}
        self._fp_feedback: Dict[str, Dict[str, int]] = defaultdict(
            lambda: {"confirmed_fp": 0, "confirmed_tp": 0, "total": 0}
        )
        self._active_runs: Dict[str, AgentRunRecord] = {}  # key: scan_id:agent_name
        logger.info("AgentMetricsCollector initialized")

    # ========================================================================
    # Run Tracking
    # ========================================================================

    def start_run(self, agent_name: str, scan_id: str, metadata: Optional[Dict[str, Any]] = None) -> AgentRunRecord:
        """
        Start tracking an agent run.

        Args:
            agent_name: Name of the agent
            scan_id: Scan ID
            metadata: Optional metadata

        Returns:
            AgentRunRecord
        """
        key = f"{scan_id}:{agent_name}"
        record = AgentRunRecord(
            agent_name=agent_name,
            scan_id=scan_id,
            metadata=metadata or {},
        )
        self._active_runs[key] = record
        return record

    def end_run(
        self,
        agent_name: str,
        scan_id: str,
        findings_count: int = 0,
        severity_counts: Optional[Dict[str, int]] = None,
        error: Optional[str] = None,
    ) -> AgentRunRecord:
        """
        End tracking an agent run.

        Args:
            agent_name: Name of the agent
            scan_id: Scan ID
            findings_count: Number of findings
            severity_counts: Count by severity
            error: Optional error message

        Returns:
            Completed AgentRunRecord
        """
        key = f"{scan_id}:{agent_name}"
        record = self._active_runs.pop(key, None)

        if record is None:
            # Create a new record if not tracked
            record = AgentRunRecord(
                agent_name=agent_name,
                scan_id=scan_id,
            )

        record.complete(findings_count=findings_count, error=error)
        if severity_counts:
            record.severity_counts = severity_counts

        # Add to metrics
        if agent_name not in self._agent_metrics:
            self._agent_metrics[agent_name] = AgentMetrics(agent_name=agent_name)

        self._agent_metrics[agent_name].add_run(record)
        self._run_records.append(record)

        logger.debug(
            "Agent %s completed in %.0fms with %d findings",
            agent_name,
            record.duration_ms,
            findings_count,
        )

        return record

    def record_scan_start(self, scan_id: str, tool_count: int) -> None:
        """
        Record the start of a full scan.

        Args:
            scan_id: Scan ID
            tool_count: Number of tools/agents running
        """
        self._scan_records[scan_id] = {
            "start_time": time.time(),
            "tool_count": tool_count,
            "end_time": None,
            "total_duration_ms": 0,
        }

    def record_scan_end(self, scan_id: str) -> None:
        """
        Record the end of a full scan.

        Args:
            scan_id: Scan ID
        """
        if scan_id in self._scan_records:
            self._scan_records[scan_id]["end_time"] = time.time()
            self._scan_records[scan_id]["total_duration_ms"] = (
                self._scan_records[scan_id]["end_time"]
                - self._scan_records[scan_id]["start_time"]
            ) * 1000

    # ========================================================================
    # Metrics Queries
    # ========================================================================

    def get_agent_metrics(self, agent_name: Optional[str] = None) -> Dict[str, Any]:
        """
        Get metrics for a specific agent or all agents.

        Args:
            agent_name: Optional agent name filter

        Returns:
            Metrics dict
        """
        if agent_name:
            metrics = self._agent_metrics.get(agent_name)
            if metrics:
                return {agent_name: metrics.to_dict()}
            return {}

        return {name: metrics.to_dict() for name, metrics in self._agent_metrics.items()}

    def get_execution_times(self) -> Dict[str, Dict[str, float]]:
        """
        Get execution time statistics per agent.

        Returns:
            Dict of agent_name -> timing stats
        """
        result = {}
        for name, metrics in self._agent_metrics.items():
            result[name] = {
                "avg_ms": round(metrics.avg_duration_ms, 2),
                "min_ms": round(metrics.min_duration_ms, 2) if metrics.min_duration_ms != float("inf") else 0,
                "max_ms": round(metrics.max_duration_ms, 2),
                "total_runs": metrics.total_runs,
            }
        return result

    def get_findings_counts(self) -> Dict[str, Dict[str, Any]]:
        """
        Get findings count per agent.

        Returns:
            Dict of agent_name -> findings stats
        """
        result = {}
        for name, metrics in self._agent_metrics.items():
            result[name] = {
                "total_findings": metrics.total_findings,
                "avg_per_run": round(metrics.avg_findings_per_run, 2),
                "by_severity": metrics.findings_by_severity,
            }
        return result

    def get_false_positive_rates(self) -> Dict[str, Dict[str, float]]:
        """
        Get false positive rate per agent.

        Returns:
            Dict of agent_name -> FP rate stats
        """
        result = {}
        for agent_name, feedback in self._fp_feedback.items():
            total = feedback["total"]
            if total > 0:
                fp_rate = feedback["confirmed_fp"] / total
                tp_rate = feedback["confirmed_tp"] / total
            else:
                fp_rate = 0.0
                tp_rate = 0.0

            result[agent_name] = {
                "false_positive_rate": round(fp_rate, 4),
                "true_positive_rate": round(tp_rate, 4),
                "confirmed_fp": feedback["confirmed_fp"],
                "confirmed_tp": feedback["confirmed_tp"],
                "total_reviewed": total,
            }
        return result

    def get_agent_agreement_rate(self, scan_id: Optional[str] = None) -> Dict[str, Any]:
        """
        Calculate agreement rate between agents.

        Finds that were detected by multiple agents are considered
        "agreed upon". Computes the percentage of multi-agent findings.

        Args:
            scan_id: Optional scan ID to filter

        Returns:
            Agreement rate stats
        """
        # Group findings by location+category
        location_groups: Dict[str, List[AgentRunRecord]] = defaultdict(list)

        records = self._run_records
        if scan_id:
            records = [r for r in records if r.scan_id == scan_id]

        for record in records:
            if record.findings_count > 0:
                # Use scan_id as proxy for grouping
                key = record.scan_id
                location_groups[key].append(record)

        multi_agent_scans = 0
        single_agent_scans = 0
        total_findings_multi = 0

        for scan_id_key, group in location_groups.items():
            unique_agents = len(set(r.agent_name for r in group))
            if unique_agents > 1:
                multi_agent_scans += 1
                total_findings_multi += sum(r.findings_count for r in group)
            else:
                single_agent_scans += 1

        total = multi_agent_scans + single_agent_scans
        agreement_rate = (multi_agent_scans / total) if total > 0 else 0.0

        return {
            "agreement_rate": round(agreement_rate, 4),
            "multi_agent_scans": multi_agent_scans,
            "single_agent_scans": single_agent_scans,
            "total_findings_from_multi_agent": total_findings_multi,
        }

    def get_scan_efficiency(self) -> Dict[str, Any]:
        """
        Compare multi-agent scan time vs single-agent scan time.

        Returns:
            Efficiency stats
        """
        total_multi_time = 0
        total_single_time = 0
        multi_count = 0
        single_count = 0

        for scan_id, record in self._scan_records.items():
            if record.get("end_time") and record.get("start_time"):
                duration = record["total_duration_ms"]
                tool_count = record.get("tool_count", 1)

                if tool_count > 1:
                    total_multi_time += duration
                    multi_count += 1

                    # Estimate single-agent time (sum of individual agent times)
                    agent_records = [
                        r for r in self._run_records if r.scan_id == scan_id
                    ]
                    single_estimate = sum(r.duration_ms for r in agent_records)
                    total_single_time += single_estimate
                else:
                    total_single_time += duration
                    single_count += 1

        avg_multi = total_multi_time / multi_count if multi_count > 0 else 0
        avg_single = total_single_time / single_count if single_count > 0 else 0

        savings = 0
        if avg_single > 0:
            savings = ((avg_single - avg_multi) / avg_single) * 100

        return {
            "avg_multi_agent_scan_ms": round(avg_multi, 2),
            "avg_single_agent_scan_ms": round(avg_single, 2),
            "time_savings_percent": round(savings, 2),
            "multi_agent_scans": multi_count,
            "single_agent_scans": single_count,
        }

    # ========================================================================
    # Feedback Recording
    # ========================================================================

    def record_feedback(
        self,
        agent_name: str,
        vuln_id: str,
        is_false_positive: bool,
    ) -> None:
        """
        Record user feedback for a finding.

        Args:
            agent_name: Agent that found the vulnerability
            vuln_id: Vulnerability ID
            is_false_positive: Whether it's a false positive
        """
        if agent_name not in self._fp_feedback:
            self._fp_feedback[agent_name] = {
                "confirmed_fp": 0,
                "confirmed_tp": 0,
                "total": 0,
            }

        self._fp_feedback[agent_name]["total"] += 1
        if is_false_positive:
            self._fp_feedback[agent_name]["confirmed_fp"] += 1
        else:
            self._fp_feedback[agent_name]["confirmed_tp"] += 1

    # ========================================================================
    # Main API
    # ========================================================================

    async def get_all_metrics(self) -> Dict[str, Any]:
        """
        Get all collected metrics.

        Returns:
            Complete metrics dictionary
        """
        return {
            "agents": self.get_agent_metrics(),
            "execution_times": self.get_execution_times(),
            "findings_counts": self.get_findings_counts(),
            "false_positive_rates": self.get_false_positive_rates(),
            "agent_agreement_rate": self.get_agent_agreement_rate(),
            "scan_efficiency": self.get_scan_efficiency(),
            "total_runs_recorded": len(self._run_records),
            "total_scans_recorded": len(self._scan_records),
            "active_runs": len(self._active_runs),
        }

    async def get_stats(self) -> Dict[str, Any]:
        """Get metrics collector statistics."""
        return {
            "tracked_agents": list(self._agent_metrics.keys()),
            "total_runs": len(self._run_records),
            "total_scans": len(self._scan_records),
            "active_runs": len(self._active_runs),
        }
