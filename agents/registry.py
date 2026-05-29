"""
Agent Registry - Dynamic Agent Registration System.

Manages agent lifecycle:
- Register/unregister agents at runtime
- Health checks via periodic heartbeat
- Agent capabilities advertisement
- Load balancing across multiple instances
- Agent metadata tracking (name, role, tools, status)
"""

import asyncio
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


class AgentStatus(str, Enum):
    """Possible statuses for an agent."""

    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    UNREGISTERED = "unregistered"
    STARTING = "starting"
    BUSY = "busy"


@dataclass
class AgentCapabilities:
    """Capabilities advertised by an agent."""

    tools: List[str] = field(default_factory=list)
    languages: List[str] = field(default_factory=list)
    vulnerability_types: List[str] = field(default_factory=list)
    max_concurrent_tasks: int = 1
    supports_async: bool = True
    custom_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tools": self.tools,
            "languages": self.languages,
            "vulnerability_types": self.vulnerability_types,
            "max_concurrent_tasks": self.max_concurrent_tasks,
            "supports_async": self.supports_async,
            "custom_metadata": self.custom_metadata,
        }


@dataclass
class AgentInfo:
    """Complete metadata for a registered agent."""

    agent_id: str
    name: str
    role: str
    goal: str
    status: AgentStatus = AgentStatus.STARTING
    capabilities: AgentCapabilities = field(default_factory=AgentCapabilities)
    registered_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    last_heartbeat: float = field(default_factory=time.time)
    heartbeat_interval: float = 30.0  # seconds
    failure_count: int = 0
    max_failures: int = 5
    instance_count: int = 1
    current_load: int = 0
    total_tasks_completed: int = 0
    total_findings: int = 0
    avg_response_time: float = 0.0
    version: str = "1.0.0"
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "name": self.name,
            "role": self.role,
            "goal": self.goal,
            "status": self.status.value,
            "capabilities": self.capabilities.to_dict(),
            "registered_at": self.registered_at,
            "last_heartbeat": self.last_heartbeat,
            "heartbeat_interval": self.heartbeat_interval,
            "failure_count": self.failure_count,
            "max_failures": self.max_failures,
            "instance_count": self.instance_count,
            "current_load": self.current_load,
            "total_tasks_completed": self.total_tasks_completed,
            "total_findings": self.total_findings,
            "avg_response_time": self.avg_response_time,
            "version": self.version,
            "tags": self.tags,
        }


class AgentRegistry:
    """
    Dynamic agent registration and management system.

    Handles agent lifecycle, health monitoring, load balancing,
    and capability discovery.
    """

    def __init__(
        self,
        heartbeat_timeout: float = 60.0,
        health_check_interval: float = 15.0,
    ) -> None:
        self._agents: Dict[str, AgentInfo] = {}
        self._agents_by_role: Dict[str, List[str]] = {}
        self._agents_by_tag: Dict[str, List[str]] = {}
        self._lock = asyncio.Lock()
        self._heartbeat_timeout = heartbeat_timeout
        self._health_check_interval = health_check_interval
        self._running = False
        self._health_check_task: Optional[asyncio.Task] = None
        self._listeners: List[
            Callable[[str, AgentStatus, AgentStatus], Coroutine[Any, Any, None]]
        ] = []

    @property
    def agents(self) -> Dict[str, AgentInfo]:
        """Get all registered agents."""
        return dict(self._agents)

    async def start(self) -> None:
        """Start the health check loop."""
        if self._running:
            return
        self._running = True
        self._health_check_task = asyncio.create_task(self._health_check_loop())
        logger.info("Agent registry started")

    async def stop(self) -> None:
        """Stop the health check loop."""
        self._running = False
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        logger.info("Agent registry stopped")

    async def register(
        self,
        agent_id: str,
        name: str,
        role: str,
        goal: str,
        capabilities: Optional[AgentCapabilities] = None,
        instance_count: int = 1,
        version: str = "1.0.0",
        tags: Optional[List[str]] = None,
    ) -> AgentInfo:
        """
        Register a new agent.

        Args:
            agent_id: Unique agent identifier
            name: Human-readable agent name
            role: Agent's role in the system
            goal: Agent's primary goal
            capabilities: Agent capabilities
            instance_count: Number of instances for load balancing
            version: Agent version
            tags: Optional tags for grouping

        Returns:
            The registered AgentInfo
        """
        async with self._lock:
            if agent_id in self._agents:
                logger.warning("Agent %s already registered, updating info", agent_id)

            agent_info = AgentInfo(
                agent_id=agent_id,
                name=name,
                role=role,
                goal=goal,
                status=AgentStatus.HEALTHY,
                capabilities=capabilities or AgentCapabilities(),
                instance_count=instance_count,
                version=version,
                tags=tags or [],
            )

            self._agents[agent_id] = agent_info

            # Index by role
            if role not in self._agents_by_role:
                self._agents_by_role[role] = []
            if agent_id not in self._agents_by_role[role]:
                self._agents_by_role[role].append(agent_id)

            # Index by tags
            for tag in (tags or []):
                if tag not in self._agents_by_tag:
                    self._agents_by_tag[tag] = []
                if agent_id not in self._agents_by_tag[tag]:
                    self._agents_by_tag[tag].append(agent_id)

        logger.info(
            "Agent %s (%s) registered with role=%s, instances=%d",
            agent_id,
            name,
            role,
            instance_count,
        )

        # Notify listeners
        await self._notify_status_change(agent_id, AgentStatus.UNREGISTERED, AgentStatus.HEALTHY)

        return agent_info

    async def unregister(self, agent_id: str) -> bool:
        """
        Unregister an agent.

        Args:
            agent_id: The agent to unregister

        Returns:
            True if agent was found and removed
        """
        async with self._lock:
            agent = self._agents.pop(agent_id, None)
            if not agent:
                return False

            # Remove from role index
            if agent.role in self._agents_by_role:
                if agent_id in self._agents_by_role[agent.role]:
                    self._agents_by_role[agent.role].remove(agent_id)

            # Remove from tag index
            for tag in agent.tags:
                if tag in self._agents_by_tag:
                    if agent_id in self._agents_by_tag[tag]:
                        self._agents_by_tag[tag].remove(agent_id)

        old_status = agent.status
        await self._notify_status_change(agent_id, old_status, AgentStatus.UNREGISTERED)
        logger.info("Agent %s (%s) unregistered", agent_id, agent.name)
        return True

    async def heartbeat(self, agent_id: str, metadata: Optional[Dict[str, Any]] = None) -> bool:
        """
        Process a heartbeat from an agent.

        Args:
            agent_id: The agent sending the heartbeat
            metadata: Optional metadata about current state

        Returns:
            True if agent is known and heartbeat accepted
        """
        async with self._lock:
            agent = self._agents.get(agent_id)
            if not agent:
                logger.warning("Heartbeat from unknown agent %s", agent_id)
                return False

            old_status = agent.status
            agent.last_heartbeat = time.time()
            agent.failure_count = 0

            # Update status from degraded/failed back to healthy
            if agent.status in (AgentStatus.DEGRADED, AgentStatus.FAILED):
                agent.status = AgentStatus.HEALTHY
                logger.info("Agent %s recovered to HEALTHY", agent_id)

            # Update metadata if provided
            if metadata:
                if "current_load" in metadata:
                    agent.current_load = metadata["current_load"]
                if "total_tasks_completed" in metadata:
                    agent.total_tasks_completed = metadata["total_tasks_completed"]
                if "total_findings" in metadata:
                    agent.total_findings = metadata["total_findings"]
                if "avg_response_time" in metadata:
                    agent.avg_response_time = metadata["avg_response_time"]

            if old_status != agent.status:
                await self._notify_status_change(agent_id, old_status, agent.status)

        return True

    async def get_agent(self, agent_id: str) -> Optional[AgentInfo]:
        """Get agent info by ID."""
        return self._agents.get(agent_id)

    async def get_agents_by_role(self, role: str) -> List[AgentInfo]:
        """Get all agents with a specific role."""
        async with self._lock:
            agent_ids = self._agents_by_role.get(role, [])
            return [self._agents[aid] for aid in agent_ids if aid in self._agents]

    async def get_agents_by_tag(self, tag: str) -> List[AgentInfo]:
        """Get all agents with a specific tag."""
        async with self._lock:
            agent_ids = self._agents_by_tag.get(tag, [])
            return [self._agents[aid] for aid in agent_ids if aid in self._agents]

    async def get_healthy_agents(
        self, role: Optional[str] = None
    ) -> List[AgentInfo]:
        """Get all healthy agents, optionally filtered by role."""
        async with self._lock:
            agents = list(self._agents.values())

        healthy = [a for a in agents if a.status == AgentStatus.HEALTHY]

        if role:
            healthy = [a for a in healthy if a.role == role]

        return healthy

    async def select_agent_for_task(
        self,
        role: str,
        required_tools: Optional[List[str]] = None,
        preferred_languages: Optional[List[str]] = None,
    ) -> Optional[AgentInfo]:
        """
        Select the best agent for a task using load balancing.

        Selection criteria:
        1. Must be healthy
        2. Must match the role
        3. Must have required tools (if specified)
        4. Prefer agent with lowest current load
        5. Prefer agent that supports preferred languages

        Args:
            role: Required agent role
            required_tools: Tools the agent must have
            preferred_languages: Languages the agent should support

        Returns:
            Best matching agent or None
        """
        candidates = await self.get_healthy_agents(role=role)

        if not candidates:
            return None

        # Filter by required tools
        if required_tools:
            candidates = [
                a
                for a in candidates
                if all(t in a.capabilities.tools for t in required_tools)
            ]

        if not candidates:
            return None

        # Filter by preferred languages
        if preferred_languages:
            lang_candidates = [
                a
                for a in candidates
                if any(
                    lang in a.capabilities.languages
                    for lang in preferred_languages
                )
            ]
            if lang_candidates:
                candidates = lang_candidates

        # Select agent with lowest load ratio
        def load_ratio(agent: AgentInfo) -> float:
            max_tasks = max(agent.capabilities.max_concurrent_tasks, 1)
            return agent.current_load / (max_tasks * agent.instance_count)

        return min(candidates, key=load_ratio)

    async def update_status(self, agent_id: str, status: AgentStatus) -> bool:
        """Manually update an agent's status."""
        async with self._lock:
            agent = self._agents.get(agent_id)
            if not agent:
                return False

            old_status = agent.status
            agent.status = status

            if status == AgentStatus.FAILED:
                agent.failure_count += 1

        if old_status != status:
            await self._notify_status_change(agent_id, old_status, status)

        logger.info("Agent %s status updated: %s -> %s", agent_id, old_status.value, status.value)
        return True

    async def record_task_start(self, agent_id: str) -> bool:
        """Record that an agent has started a task."""
        async with self._lock:
            agent = self._agents.get(agent_id)
            if not agent:
                return False
            agent.current_load += 1
            if agent.current_load >= agent.capabilities.max_concurrent_tasks * agent.instance_count:
                agent.status = AgentStatus.BUSY
        return True

    async def record_task_complete(
        self,
        agent_id: str,
        findings: int = 0,
        response_time: float = 0.0,
        success: bool = True,
    ) -> bool:
        """Record that an agent has completed a task."""
        async with self._lock:
            agent = self._agents.get(agent_id)
            if not agent:
                return False

            agent.current_load = max(0, agent.current_load - 1)
            agent.total_tasks_completed += 1
            agent.total_findings += findings

            # Update average response time
            if response_time > 0:
                n = agent.total_tasks_completed
                agent.avg_response_time = (
                    (agent.avg_response_time * (n - 1)) + response_time
                ) / n

            # Update status if was busy
            if agent.status == AgentStatus.BUSY and agent.current_load < (
                agent.capabilities.max_concurrent_tasks * agent.instance_count
            ):
                agent.status = AgentStatus.HEALTHY

            if not success:
                agent.failure_count += 1
                if agent.failure_count >= agent.max_failures:
                    agent.status = AgentStatus.FAILED
                    logger.error(
                        "Agent %s marked as FAILED after %d consecutive failures",
                        agent_id,
                        agent.failure_count,
                    )

        return True

    async def add_status_listener(
        self,
        listener: Callable[[str, AgentStatus, AgentStatus], Coroutine[Any, Any, None]],
    ) -> None:
        """Add a listener for agent status changes."""
        self._listeners.append(listener)

    async def _notify_status_change(
        self, agent_id: str, old_status: AgentStatus, new_status: AgentStatus
    ) -> None:
        """Notify all listeners of a status change."""
        for listener in self._listeners:
            try:
                await listener(agent_id, old_status, new_status)
            except Exception as e:
                logger.error("Status listener error: %s", e)

    async def _health_check_loop(self) -> None:
        """Periodic health check loop."""
        while self._running:
            try:
                await self._check_health()
                await asyncio.sleep(self._health_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Health check error: %s", e)
                await asyncio.sleep(self._health_check_interval)

    async def _check_health(self) -> None:
        """Check health of all registered agents."""
        current_time = time.time()
        agents_to_check: List[AgentInfo] = []

        async with self._lock:
            agents_to_check = list(self._agents.values())

        for agent in agents_to_check:
            time_since_heartbeat = current_time - agent.last_heartbeat

            if time_since_heartbeat > self._heartbeat_timeout:
                old_status = agent.status
                if agent.status == AgentStatus.HEALTHY:
                    agent.status = AgentStatus.DEGRADED
                    logger.warning(
                        "Agent %s (%s) degraded - no heartbeat for %.0fs",
                        agent.agent_id,
                        agent.name,
                        time_since_heartbeat,
                    )
                    await self._notify_status_change(
                        agent.agent_id, old_status, AgentStatus.DEGRADED
                    )
                elif agent.status == AgentStatus.DEGRADED:
                    agent.status = AgentStatus.FAILED
                    agent.failure_count += 1
                    logger.error(
                        "Agent %s (%s) FAILED - no heartbeat for %.0fs",
                        agent.agent_id,
                        agent.name,
                        time_since_heartbeat,
                    )
                    await self._notify_status_change(
                        agent.agent_id, old_status, AgentStatus.FAILED
                    )

    def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics."""
        total = len(self._agents)
        healthy = sum(1 for a in self._agents.values() if a.status == AgentStatus.HEALTHY)
        degraded = sum(1 for a in self._agents.values() if a.status == AgentStatus.DEGRADED)
        failed = sum(1 for a in self._agents.values() if a.status == AgentStatus.FAILED)
        busy = sum(1 for a in self._agents.values() if a.status == AgentStatus.BUSY)

        return {
            "total_agents": total,
            "healthy": healthy,
            "degraded": degraded,
            "failed": failed,
            "busy": busy,
            "by_role": {
                role: len(aids)
                for role, aids in self._agents_by_role.items()
            },
            "by_tag": {
                tag: len(aids)
                for tag, aids in self._agents_by_tag.items()
            },
        }

    async def list_agents(
        self, status_filter: Optional[AgentStatus] = None
    ) -> List[AgentInfo]:
        """List all registered agents, optionally filtered by status."""
        agents = list(self._agents.values())
        if status_filter:
            agents = [a for a in agents if a.status == status_filter]
        return agents


# Global registry instance
_registry: Optional[AgentRegistry] = None


def get_registry() -> AgentRegistry:
    """Get or create the global agent registry instance."""
    global _registry
    if _registry is None:
        _registry = AgentRegistry()
    return _registry


async def reset_registry() -> None:
    """Reset the global registry instance (for testing)."""
    global _registry
    if _registry:
        await _registry.stop()
    _registry = None
