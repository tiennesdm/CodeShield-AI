"""
Agent Health Monitor - Health Monitoring System for Agents.

Tracks agent health with:
- Heartbeat tracking per agent
- Timeout detection and agent restart triggers
- Fallback routing to alternative agents
- Metrics: response time, success rate, finding count per agent
"""

import asyncio
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


class HealthStatus(str, Enum):
    """Health status for agents."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class AgentMetrics:
    """Metrics tracked for each agent."""

    agent_id: str
    agent_name: str
    total_tasks: int = 0
    successful_tasks: int = 0
    failed_tasks: int = 0
    total_findings: int = 0
    avg_response_time_ms: float = 0.0
    p95_response_time_ms: float = 0.0
    p99_response_time_ms: float = 0.0
    last_task_time: Optional[float] = None
    response_times: List[float] = field(default_factory=list)
    max_response_times: int = 100
    uptime_seconds: float = 0.0
    last_heartbeat: Optional[float] = None
    consecutive_failures: int = 0
    restart_count: int = 0

    @property
    def success_rate(self) -> float:
        """Calculate success rate as percentage."""
        if self.total_tasks == 0:
            return 100.0
        return (self.successful_tasks / self.total_tasks) * 100

    @property
    def failure_rate(self) -> float:
        """Calculate failure rate as percentage."""
        if self.total_tasks == 0:
            return 0.0
        return (self.failed_tasks / self.total_tasks) * 100

    @property
    def findings_per_task(self) -> float:
        """Average findings per task."""
        if self.total_tasks == 0:
            return 0.0
        return self.total_findings / self.total_tasks

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "total_tasks": self.total_tasks,
            "successful_tasks": self.successful_tasks,
            "failed_tasks": self.failed_tasks,
            "success_rate": round(self.success_rate, 2),
            "failure_rate": round(self.failure_rate, 2),
            "total_findings": self.total_findings,
            "findings_per_task": round(self.findings_per_task, 2),
            "avg_response_time_ms": round(self.avg_response_time_ms, 2),
            "p95_response_time_ms": round(self.p95_response_time_ms, 2),
            "p99_response_time_ms": round(self.p99_response_time_ms, 2),
            "last_task_time": self.last_task_time,
            "uptime_seconds": round(self.uptime_seconds, 2),
            "last_heartbeat": self.last_heartbeat,
            "consecutive_failures": self.consecutive_failures,
            "restart_count": self.restart_count,
        }

    def record_response_time(self, response_time_ms: float) -> None:
        """Record a response time sample."""
        self.response_times.append(response_time_ms)
        if len(self.response_times) > self.max_response_times:
            self.response_times = self.response_times[-self.max_response_times :]

        # Recalculate stats
        times = sorted(self.response_times)
        self.avg_response_time_ms = sum(times) / len(times)
        if len(times) >= 20:
            p95_idx = int(len(times) * 0.95)
            p99_idx = int(len(times) * 0.99)
            self.p95_response_time_ms = times[min(p95_idx, len(times) - 1)]
            self.p99_response_time_ms = times[min(p99_idx, len(times) - 1)]


class AgentHealthMonitor:
    """
    Monitors health of all agents in the system.

    Provides heartbeat tracking, timeout detection, automatic restart triggers,
    fallback routing, and comprehensive metrics collection.
    """

    def __init__(
        self,
        heartbeat_timeout: float = 60.0,
        metrics_window_size: int = 100,
        restart_threshold: int = 3,
        check_interval: float = 10.0,
    ) -> None:
        self._metrics: Dict[str, AgentMetrics] = {}
        self._health_status: Dict[str, HealthStatus] = {}
        self._restart_callbacks: Dict[
            str, Callable[[str], Coroutine[Any, Any, bool]]
        ] = {}
        self._fallback_map: Dict[str, List[str]] = {}  # agent_id -> fallback agent_ids
        self._lock = asyncio.Lock()
        self._heartbeat_timeout = heartbeat_timeout
        self._metrics_window_size = metrics_window_size
        self._restart_threshold = restart_threshold
        self._check_interval = check_interval
        self._running = False
        self._monitor_task: Optional[asyncio.Task] = None
        self._status_change_callbacks: List[
            Callable[[str, HealthStatus, HealthStatus], Coroutine[Any, Any, None]]
        ] = []

    async def start(self) -> None:
        """Start the health monitor."""
        if self._running:
            return
        self._running = True
        self._monitor_task = asyncio.create_task(self._monitor_loop())
        logger.info("Agent health monitor started")

    async def stop(self) -> None:
        """Stop the health monitor."""
        self._running = False
        if self._monitor_task:
            self._monitor_task.cancel()
            try:
                await self._monitor_task
            except asyncio.CancelledError:
                pass
        logger.info("Agent health monitor stopped")

    async def register_agent(self, agent_id: str, agent_name: str) -> None:
        """Register an agent for health monitoring."""
        newly_registered = False
        async with self._lock:
            if agent_id not in self._metrics:
                self._metrics[agent_id] = AgentMetrics(
                    agent_id=agent_id,
                    agent_name=agent_name,
                    last_heartbeat=time.time(),
                )
                self._health_status[agent_id] = HealthStatus.HEALTHY
                newly_registered = True
        if newly_registered:
            # Surface the UNKNOWN -> HEALTHY transition to listeners.
            await self._notify_status_change(
                agent_id, HealthStatus.UNKNOWN, HealthStatus.HEALTHY
            )
        logger.debug("Agent %s registered for health monitoring", agent_id)

    async def unregister_agent(self, agent_id: str) -> None:
        """Unregister an agent from health monitoring."""
        async with self._lock:
            self._metrics.pop(agent_id, None)
            self._health_status.pop(agent_id, None)
            self._restart_callbacks.pop(agent_id, None)
            self._fallback_map.pop(agent_id, None)

    async def record_heartbeat(
        self,
        agent_id: str,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Record a heartbeat from an agent."""
        async with self._lock:
            metrics = self._metrics.get(agent_id)
            if not metrics:
                logger.warning("Heartbeat from unmonitored agent %s", agent_id)
                return

            metrics.last_heartbeat = time.time()
            metrics.consecutive_failures = 0

            # Update uptime if this is the first heartbeat
            if metadata:
                if "uptime_seconds" in metadata:
                    metrics.uptime_seconds = metadata["uptime_seconds"]

            # Update health status
            old_status = self._health_status.get(agent_id, HealthStatus.UNKNOWN)
            new_status = HealthStatus.HEALTHY
            self._health_status[agent_id] = new_status

        if old_status != new_status:
            await self._notify_status_change(agent_id, old_status, new_status)

    async def record_task_result(
        self,
        agent_id: str,
        success: bool,
        findings: int = 0,
        response_time_ms: float = 0.0,
    ) -> None:
        """Record the result of a task execution."""
        async with self._lock:
            metrics = self._metrics.get(agent_id)
            if not metrics:
                return

            metrics.total_tasks += 1
            metrics.last_task_time = time.time()

            if success:
                metrics.successful_tasks += 1
                metrics.consecutive_failures = 0
            else:
                metrics.failed_tasks += 1
                metrics.consecutive_failures += 1

            metrics.total_findings += findings

            if response_time_ms > 0:
                metrics.record_response_time(response_time_ms)

            # Check if restart threshold reached
            if metrics.consecutive_failures >= self._restart_threshold:
                logger.warning(
                    "Agent %s reached restart threshold (%d consecutive failures)",
                    agent_id,
                    metrics.consecutive_failures,
                )
                # Trigger restart if callback registered
                restart_callback = self._restart_callbacks.get(agent_id)
                if restart_callback:
                    metrics.restart_count += 1
                    asyncio.create_task(self._trigger_restart(agent_id, restart_callback))

    async def _trigger_restart(
        self,
        agent_id: str,
        callback: Callable[[str], Coroutine[Any, Any, bool]],
    ) -> None:
        """Trigger agent restart."""
        try:
            success = await callback(agent_id)
            if success:
                logger.info("Agent %s restarted successfully", agent_id)
                async with self._lock:
                    metrics = self._metrics.get(agent_id)
                    if metrics:
                        metrics.consecutive_failures = 0
            else:
                logger.error("Agent %s restart failed", agent_id)
        except Exception as e:
            logger.error("Agent %s restart error: %s", agent_id, e)

    async def get_health_status(self, agent_id: str) -> HealthStatus:
        """Get current health status for an agent."""
        return self._health_status.get(agent_id, HealthStatus.UNKNOWN)

    async def get_metrics(self, agent_id: str) -> Optional[AgentMetrics]:
        """Get metrics for an agent."""
        return self._metrics.get(agent_id)

    async def get_all_metrics(self) -> Dict[str, AgentMetrics]:
        """Get metrics for all agents."""
        return dict(self._metrics)

    async def get_all_health_status(self) -> Dict[str, HealthStatus]:
        """Get health status for all agents."""
        return dict(self._health_status)

    async def set_restart_callback(
        self,
        agent_id: str,
        callback: Callable[[str], Coroutine[Any, Any, bool]],
    ) -> None:
        """Set a callback to trigger when an agent needs restarting."""
        self._restart_callbacks[agent_id] = callback

    async def set_fallback_agents(
        self, agent_id: str, fallback_ids: List[str]
    ) -> None:
        """Set fallback agents for a given agent."""
        self._fallback_map[agent_id] = fallback_ids

    async def get_fallback_agent(self, agent_id: str) -> Optional[str]:
        """
        Get the best fallback agent for a failed agent.

        Returns the first healthy fallback agent, or None if none available.
        """
        fallback_ids = self._fallback_map.get(agent_id, [])
        for fallback_id in fallback_ids:
            status = self._health_status.get(fallback_id, HealthStatus.UNKNOWN)
            if status == HealthStatus.HEALTHY:
                return fallback_id
        return None

    async def add_status_change_listener(
        self,
        callback: Callable[[str, HealthStatus, HealthStatus], Coroutine[Any, Any, None]],
    ) -> None:
        """Add a callback for health status changes."""
        self._status_change_callbacks.append(callback)

    async def _notify_status_change(
        self, agent_id: str, old_status: HealthStatus, new_status: HealthStatus
    ) -> None:
        """Notify all listeners of a status change."""
        for callback in self._status_change_callbacks:
            try:
                await callback(agent_id, old_status, new_status)
            except Exception as e:
                logger.error("Status change callback error: %s", e)

    async def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self._running:
            try:
                await self._check_all_agents()
                # Sleep in small slices so runtime changes to _check_interval
                # (e.g. in tests) take effect promptly instead of being stuck
                # in one long sleep.
                slept = 0.0
                while self._running and slept < self._check_interval:
                    step = min(0.05, max(0.0, self._check_interval - slept))
                    if step <= 0:
                        break
                    await asyncio.sleep(step)
                    slept += step
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Monitor loop error: %s", e)
                await asyncio.sleep(min(self._check_interval, 0.5))

    async def _check_all_agents(self) -> None:
        """Check health of all monitored agents."""
        current_time = time.time()

        agents_to_check: Dict[str, AgentMetrics] = {}
        async with self._lock:
            agents_to_check = dict(self._metrics)

        for agent_id, metrics in agents_to_check.items():
            old_status = self._health_status.get(agent_id, HealthStatus.UNKNOWN)
            new_status = old_status

            # Check heartbeat timeout
            if metrics.last_heartbeat:
                time_since_hb = current_time - metrics.last_heartbeat
                if time_since_hb > self._heartbeat_timeout:
                    new_status = HealthStatus.UNHEALTHY
                elif time_since_hb > self._heartbeat_timeout / 2:
                    if old_status == HealthStatus.HEALTHY:
                        new_status = HealthStatus.DEGRADED

            # Check failure rate
            if metrics.total_tasks > 10 and metrics.failure_rate > 50:
                new_status = HealthStatus.UNHEALTHY

            if old_status != new_status:
                async with self._lock:
                    self._health_status[agent_id] = new_status
                await self._notify_status_change(agent_id, old_status, new_status)
                logger.info(
                    "Agent %s health: %s -> %s",
                    agent_id,
                    old_status.value,
                    new_status.value,
                )

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of all agent health."""
        total = len(self._metrics)
        healthy = sum(1 for s in self._health_status.values() if s == HealthStatus.HEALTHY)
        degraded = sum(1 for s in self._health_status.values() if s == HealthStatus.DEGRADED)
        unhealthy = sum(1 for s in self._health_status.values() if s == HealthStatus.UNHEALTHY)
        unknown = sum(1 for s in self._health_status.values() if s == HealthStatus.UNKNOWN)

        return {
            "total_monitored": total,
            "healthy": healthy,
            "degraded": degraded,
            "unhealthy": unhealthy,
            "unknown": unknown,
            "agent_statuses": {
                agent_id: {
                    "health": status.value,
                    "metrics": self._metrics.get(agent_id, AgentMetrics(agent_id=agent_id, agent_name="unknown")).to_dict(),
                }
                for agent_id, status in self._health_status.items()
            },
        }


# Global health monitor instance
_health_monitor: Optional[AgentHealthMonitor] = None


def get_health_monitor() -> AgentHealthMonitor:
    """Get or create the global health monitor instance."""
    global _health_monitor
    if _health_monitor is None:
        _health_monitor = AgentHealthMonitor()
    return _health_monitor


async def reset_health_monitor() -> None:
    """Reset the global health monitor instance (for testing)."""
    global _health_monitor
    if _health_monitor:
        await _health_monitor.stop()
    _health_monitor = None
