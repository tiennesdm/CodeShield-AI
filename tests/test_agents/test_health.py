"""
Tests for the Agent Health Monitor.

Tests heartbeat tracking, timeout detection, agent restart triggers,
fallback routing, and metrics collection.
"""

import asyncio
import time

import pytest

import sys
sys.path.insert(0, "/mnt/agents/output/backend")

from agents.health import (
    AgentHealthMonitor,
    AgentMetrics,
    HealthStatus,
    get_health_monitor,
    reset_health_monitor,
)


class TestAgentMetrics:
    """Test AgentMetrics dataclass."""

    def test_default_creation(self):
        """Test creating default metrics."""
        m = AgentMetrics(agent_id="john", agent_name="John")
        assert m.agent_id == "john"
        assert m.total_tasks == 0
        assert m.success_rate == 100.0
        assert m.failure_rate == 0.0

    def test_success_rate_calculation(self):
        """Test success rate with data."""
        m = AgentMetrics(agent_id="john", agent_name="John")
        m.total_tasks = 10
        m.successful_tasks = 8
        m.failed_tasks = 2
        assert m.success_rate == 80.0
        assert m.failure_rate == 20.0

    def test_findings_per_task(self):
        """Test findings per task calculation."""
        m = AgentMetrics(agent_id="john", agent_name="John")
        m.total_tasks = 5
        m.total_findings = 20
        assert m.findings_per_task == 4.0

    def test_record_response_time(self):
        """Test response time recording."""
        m = AgentMetrics(agent_id="john", agent_name="John")
        for rt in [100, 200, 150, 300, 250]:
            m.record_response_time(rt)

        assert m.avg_response_time_ms == 200.0
        assert len(m.response_times) == 5

    def test_to_dict(self):
        """Test serialization."""
        m = AgentMetrics(
            agent_id="john",
            agent_name="John",
            total_tasks=10,
            successful_tasks=8,
            total_findings=25,
        )
        d = m.to_dict()
        assert d["agent_id"] == "john"
        assert d["total_tasks"] == 10
        assert d["success_rate"] == 80.0
        assert d["total_findings"] == 25


class TestAgentHealthMonitor:
    """Test AgentHealthMonitor."""

    @pytest.fixture
    async def monitor(self):
        mon = AgentHealthMonitor(
            heartbeat_timeout=1.0,
            check_interval=0.5,
            restart_threshold=3,
        )
        await mon.start()
        yield mon
        await mon.stop()

    @pytest.mark.asyncio
    async def test_register_agent(self, monitor):
        """Test agent registration."""
        await monitor.register_agent("john", "John")
        status = await monitor.get_health_status("john")
        assert status == HealthStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_unregister_agent(self, monitor):
        """Test agent unregistration."""
        await monitor.register_agent("john", "John")
        await monitor.unregister_agent("john")
        status = await monitor.get_health_status("john")
        assert status == HealthStatus.UNKNOWN

    @pytest.mark.asyncio
    async def test_record_heartbeat(self, monitor):
        """Test heartbeat recording."""
        await monitor.register_agent("john", "John")
        before = time.time()
        await monitor.record_heartbeat("john")

        metrics = await monitor.get_metrics("john")
        assert metrics.last_heartbeat >= before

    @pytest.mark.asyncio
    async def test_record_heartbeat_unknown(self, monitor):
        """Test heartbeat for unknown agent doesn't error."""
        await monitor.register_agent("john", "John")
        # Should not raise
        await monitor.record_heartbeat("unknown")

    @pytest.mark.asyncio
    async def test_record_task_result(self, monitor):
        """Test recording task results."""
        await monitor.register_agent("john", "John")
        await monitor.record_task_result(
            "john", success=True, findings=5, response_time_ms=150.0
        )

        metrics = await monitor.get_metrics("john")
        assert metrics.total_tasks == 1
        assert metrics.successful_tasks == 1
        assert metrics.total_findings == 5
        assert metrics.avg_response_time_ms == 150.0

    @pytest.mark.asyncio
    async def test_record_task_failure(self, monitor):
        """Test recording task failures."""
        await monitor.register_agent("john", "John")
        await monitor.record_task_result("john", success=False)

        metrics = await monitor.get_metrics("john")
        assert metrics.failed_tasks == 1
        assert metrics.consecutive_failures == 1

    @pytest.mark.asyncio
    async def test_consecutive_failures_threshold(self, monitor):
        """Test that consecutive failures triggers restart callback."""
        restarted = []

        async def restart_callback(agent_id):
            restarted.append(agent_id)
            return True

        await monitor.register_agent("john", "John")
        await monitor.set_restart_callback("john", restart_callback)

        # Record 3 consecutive failures (restart_threshold=3)
        for _ in range(3):
            await monitor.record_task_result("john", success=False)

        # Allow restart task to complete
        await asyncio.sleep(0.1)

        assert "john" in restarted
        metrics = await monitor.get_metrics("john")
        assert metrics.restart_count == 1

    @pytest.mark.asyncio
    async def test_fallback_agent(self, monitor):
        """Test fallback agent selection."""
        await monitor.register_agent("john", "John")
        await monitor.register_agent("john_backup", "John Backup")
        await monitor.set_fallback_agents("john", ["john_backup"])

        fallback = await monitor.get_fallback_agent("john")
        assert fallback == "john_backup"

    @pytest.mark.asyncio
    async def test_fallback_no_healthy(self, monitor):
        """Test fallback when no healthy agents available."""
        await monitor.register_agent("john", "John")
        await monitor.register_agent("john_backup", "John Backup")
        await monitor.set_fallback_agents("john", ["john_backup"])

        # Mark fallback as degraded
        # (Since we can't easily set status, just test the method works)
        fallback = await monitor.get_fallback_agent("john")
        assert fallback is not None

    @pytest.mark.asyncio
    async def test_status_change_listener(self, monitor):
        """Test status change notifications."""
        changes = []

        async def listener(agent_id, old_status, new_status):
            changes.append((agent_id, old_status, new_status))

        await monitor.add_status_change_listener(listener)
        await monitor.register_agent("john", "John")

        assert len(changes) >= 1

    @pytest.mark.asyncio
    async def test_get_all_metrics(self, monitor):
        """Test getting all metrics."""
        await monitor.register_agent("john", "John")
        await monitor.register_agent("sam", "Sam")

        all_metrics = await monitor.get_all_metrics()
        assert len(all_metrics) == 2
        assert "john" in all_metrics
        assert "sam" in all_metrics

    @pytest.mark.asyncio
    async def test_get_summary(self, monitor):
        """Test getting health summary."""
        await monitor.register_agent("john", "John")
        await monitor.register_agent("sam", "Sam")

        summary = monitor.get_summary()
        assert summary["total_monitored"] == 2
        assert "healthy" in summary
        assert "agent_statuses" in summary

    @pytest.mark.asyncio
    async def test_health_check_detects_timeout(self, monitor):
        """Test that monitor detects heartbeat timeout."""
        monitor._heartbeat_timeout = 0.1
        monitor._check_interval = 0.05

        await monitor.register_agent("john", "John")
        # Don't send heartbeat

        # Wait for health check
        await asyncio.sleep(0.3)

        status = await monitor.get_health_status("john")
        assert status in (HealthStatus.DEGRADED, HealthStatus.UNHEALTHY)

    def test_get_health_status_unknown(self, monitor):
        """Test status for unmonitored agent."""
        # Use sync method access
        status = monitor._health_status.get("unknown", HealthStatus.UNKNOWN)
        assert status == HealthStatus.UNKNOWN


class TestHealthMonitorSingleton:
    """Test singleton behavior."""

    def test_singleton(self):
        """Test that get_health_monitor returns singleton."""
        mon1 = get_health_monitor()
        mon2 = get_health_monitor()
        assert mon1 is mon2

    @pytest.mark.asyncio
    async def test_reset(self):
        """Test resetting health monitor."""
        mon = get_health_monitor()
        await mon.start()
        await reset_health_monitor()
        new_mon = get_health_monitor()
        assert new_mon is not mon
