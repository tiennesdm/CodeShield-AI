"""
Tests for the Agent Registry.

Tests agent registration, unregistration, health checks, heartbeat,
capabilities advertisement, load balancing, and metadata tracking.
"""

import asyncio
import time

import pytest

import sys
sys.path.insert(0, "/mnt/agents/output/backend")

from agents.registry import (
    AgentCapabilities,
    AgentInfo,
    AgentRegistry,
    AgentStatus,
    get_registry,
    reset_registry,
)


class TestAgentCapabilities:
    """Test AgentCapabilities dataclass."""

    def test_default_creation(self):
        """Test creating default capabilities."""
        caps = AgentCapabilities()
        assert caps.tools == []
        assert caps.languages == []
        assert caps.max_concurrent_tasks == 1
        assert caps.supports_async is True

    def test_custom_creation(self):
        """Test creating capabilities with values."""
        caps = AgentCapabilities(
            tools=["semgrep", "bandit"],
            languages=["python", "javascript"],
            max_concurrent_tasks=5,
        )
        assert caps.tools == ["semgrep", "bandit"]
        assert caps.languages == ["python", "javascript"]
        assert caps.max_concurrent_tasks == 5

    def test_to_dict(self):
        """Test serialization."""
        caps = AgentCapabilities(tools=["scanner"], languages=["python"])
        d = caps.to_dict()
        assert d["tools"] == ["scanner"]
        assert d["languages"] == ["python"]


class TestAgentInfo:
    """Test AgentInfo dataclass."""

    def test_creation(self):
        """Test creating agent info."""
        info = AgentInfo(
            agent_id="john",
            name="John",
            role="Static Code Security Analyst",
            goal="Find vulnerabilities",
        )
        assert info.agent_id == "john"
        assert info.status == AgentStatus.STARTING
        assert info.failure_count == 0

    def test_to_dict(self):
        """Test serialization."""
        info = AgentInfo(
            agent_id="john",
            name="John",
            role="SAST",
            goal="Find vulns",
            status=AgentStatus.HEALTHY,
            capabilities=AgentCapabilities(tools=["semgrep"]),
        )
        d = info.to_dict()
        assert d["agent_id"] == "john"
        assert d["status"] == "healthy"
        assert d["capabilities"]["tools"] == ["semgrep"]


class TestAgentRegistry:
    """Test AgentRegistry."""

    @pytest.fixture
    async def registry(self):
        reg = AgentRegistry(heartbeat_timeout=1.0, health_check_interval=0.5)
        await reg.start()
        yield reg
        await reg.stop()

    @pytest.mark.asyncio
    async def test_register_agent(self, registry):
        """Test agent registration."""
        info = await registry.register(
            agent_id="john",
            name="John",
            role="SAST",
            goal="Find vulnerabilities",
            capabilities=AgentCapabilities(tools=["semgrep"]),
        )
        assert info.agent_id == "john"
        assert info.status == AgentStatus.HEALTHY

    @pytest.mark.asyncio
    async def test_unregister_agent(self, registry):
        """Test agent unregistration."""
        await registry.register("john", "John", "SAST", "Find vulns")
        result = await registry.unregister("john")
        assert result is True

        # Check it's gone
        agent = await registry.get_agent("john")
        assert agent is None

    @pytest.mark.asyncio
    async def test_unregister_unknown(self, registry):
        """Test unregistering unknown agent."""
        result = await registry.unregister("unknown")
        assert result is False

    @pytest.mark.asyncio
    async def test_heartbeat(self, registry):
        """Test heartbeat updates last_heartbeat."""
        await registry.register("john", "John", "SAST", "Find vulns")
        before = time.time()
        result = await registry.heartbeat("john")
        assert result is True

        agent = await registry.get_agent("john")
        assert agent.last_heartbeat >= before

    @pytest.mark.asyncio
    async def test_heartbeat_unknown_agent(self, registry):
        """Test heartbeat for unknown agent returns False."""
        result = await registry.heartbeat("unknown")
        assert result is False

    @pytest.mark.asyncio
    async def test_get_healthy_agents(self, registry):
        """Test filtering healthy agents."""
        await registry.register("john", "John", "SAST", "Find vulns")
        await registry.register("sam", "Sam", "Secrets", "Find secrets")
        await registry.register("dave", "Dave", "DAST", "Test runtime")

        # All should be healthy
        healthy = await registry.get_healthy_agents()
        assert len(healthy) == 3

        # Mark one as failed
        await registry.update_status("dave", AgentStatus.FAILED)
        healthy = await registry.get_healthy_agents()
        assert len(healthy) == 2
        assert all(a.status == AgentStatus.HEALTHY for a in healthy)

    @pytest.mark.asyncio
    async def test_get_healthy_agents_by_role(self, registry):
        """Test filtering healthy agents by role."""
        await registry.register("john", "John", "SAST", "Find vulns")
        await registry.register("sam", "Sam", "Secrets", "Find secrets")

        healthy = await registry.get_healthy_agents(role="SAST")
        assert len(healthy) == 1
        assert healthy[0].agent_id == "john"

    @pytest.mark.asyncio
    async def test_select_agent_for_task(self, registry):
        """Test load balancing agent selection."""
        await registry.register(
            "john",
            "John",
            "SAST",
            "Find vulns",
            capabilities=AgentCapabilities(
                tools=["semgrep", "bandit"],
                languages=["python"],
                max_concurrent_tasks=3,
            ),
            instance_count=2,
        )

        # Select agent for python task
        selected = await registry.select_agent_for_task(
            role="SAST",
            required_tools=["semgrep"],
            preferred_languages=["python"],
        )
        assert selected is not None
        assert selected.agent_id == "john"

        # Select with unmet requirements
        selected = await registry.select_agent_for_task(
            role="SAST",
            required_tools=["nonexistent_tool"],
        )
        assert selected is None

    @pytest.mark.asyncio
    async def test_task_tracking(self, registry):
        """Test task start/completion tracking."""
        await registry.register(
            "john",
            "John",
            "SAST",
            "Find vulns",
            capabilities=AgentCapabilities(max_concurrent_tasks=2),
        )

        # Start task
        await registry.record_task_start("john")
        agent = await registry.get_agent("john")
        assert agent.current_load == 1

        # Complete task
        await registry.record_task_complete("john", findings=5, response_time=100.0)
        agent = await registry.get_agent("john")
        assert agent.current_load == 0
        assert agent.total_tasks_completed == 1
        assert agent.total_findings == 5

    @pytest.mark.asyncio
    async def test_task_failure_tracking(self, registry):
        """Test that repeated failures mark agent as failed."""
        await registry.register(
            "john",
            "John",
            "SAST",
            "Find vulns",
            capabilities=AgentCapabilities(max_concurrent_tasks=1),
        )

        # Simulate 5 failures (default max_failures is 5)
        for _ in range(5):
            await registry.record_task_complete("john", success=False)

        agent = await registry.get_agent("john")
        assert agent.status == AgentStatus.FAILED

    @pytest.mark.asyncio
    async def test_get_agents_by_role(self, registry):
        """Test getting agents by role."""
        await registry.register("john1", "John 1", "SAST", "Find vulns")
        await registry.register("john2", "John 2", "SAST", "Find vulns")
        await registry.register("sam", "Sam", "Secrets", "Find secrets")

        sast_agents = await registry.get_agents_by_role("SAST")
        assert len(sast_agents) == 2

    @pytest.mark.asyncio
    async def test_get_agents_by_tag(self, registry):
        """Test getting agents by tag."""
        await registry.register(
            "john", "John", "SAST", "Find vulns", tags=["scanner", "sast"]
        )
        await registry.register(
            "sam", "Sam", "Secrets", "Find secrets", tags=["scanner", "secrets"]
        )

        scanner_agents = await registry.get_agents_by_tag("scanner")
        assert len(scanner_agents) == 2

        sast_agents = await registry.get_agents_by_tag("sast")
        assert len(sast_agents) == 1

    @pytest.mark.asyncio
    async def test_list_agents(self, registry):
        """Test listing all agents."""
        await registry.register("john", "John", "SAST", "Find vulns")
        await registry.register("sam", "Sam", "Secrets", "Find secrets")

        all_agents = await registry.list_agents()
        assert len(all_agents) == 2

        # Filter by status
        await registry.update_status("john", AgentStatus.FAILED)
        failed = await registry.list_agents(status_filter=AgentStatus.FAILED)
        assert len(failed) == 1
        assert failed[0].agent_id == "john"

    @pytest.mark.asyncio
    async def test_update_status(self, registry):
        """Test manual status update."""
        await registry.register("john", "John", "SAST", "Find vulns")

        result = await registry.update_status("john", AgentStatus.DEGRADED)
        assert result is True

        agent = await registry.get_agent("john")
        assert agent.status == AgentStatus.DEGRADED

    @pytest.mark.asyncio
    async def test_status_change_listener(self, registry):
        """Test status change notifications."""
        changes = []

        async def listener(agent_id, old_status, new_status):
            changes.append((agent_id, old_status.value, new_status.value))

        await registry.add_status_listener(listener)
        await registry.register("john", "John", "SAST", "Find vulns")
        await registry.update_status("john", AgentStatus.DEGRADED)

        assert len(changes) >= 1

    def test_get_stats(self, registry):
        """Test getting registry statistics."""
        stats = registry.get_stats()
        assert "total_agents" in stats
        assert "healthy" in stats
        assert "degraded" in stats
        assert "failed" in stats
        assert "by_role" in stats

    @pytest.mark.asyncio
    async def test_health_check_timeout(self, registry):
        """Test that agents are marked degraded on heartbeat timeout."""
        registry._heartbeat_timeout = 0.1
        registry._health_check_interval = 0.05

        await registry.register("john", "John", "SAST", "Find vulns")

        # Wait for health check to run
        await asyncio.sleep(0.3)

        agent = await registry.get_agent("john")
        assert agent.status in (AgentStatus.DEGRADED, AgentStatus.FAILED)


class TestAgentRegistrySingleton:
    """Test singleton behavior."""

    def test_singleton(self):
        """Test that get_registry returns singleton."""
        reg1 = get_registry()
        reg2 = get_registry()
        assert reg1 is reg2

    @pytest.mark.asyncio
    async def test_reset(self):
        """Test resetting registry."""
        reg = get_registry()
        await reg.start()
        await reset_registry()
        new_reg = get_registry()
        assert new_reg is not reg
