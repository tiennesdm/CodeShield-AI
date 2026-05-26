"""
Tests for the Agent Communication Bus.

Tests message creation, pub/sub, priority queue, circuit breaker,
message persistence, and thread safety.
"""

import asyncio
import json
import os
import tempfile
from pathlib import Path

import pytest

# Ensure backend is on path
import sys
sys.path.insert(0, "/mnt/agents/output/backend")

from agents.bus import (
    AgentCommunicationBus,
    AgentMessage,
    CircuitBreaker,
    MessageType,
    Priority,
    get_message_bus,
    reset_message_bus,
)


class TestAgentMessage:
    """Test AgentMessage dataclass."""

    def test_message_creation(self):
        """Test creating a basic message."""
        msg = AgentMessage(
            agent_id="john",
            message_type=MessageType.FINDING,
            payload={"file": "test.py", "line": 10},
            priority=Priority.HIGH,
        )
        assert msg.agent_id == "john"
        assert msg.message_type == MessageType.FINDING
        assert msg.payload["file"] == "test.py"
        assert msg.priority == Priority.HIGH
        assert msg.correlation_id is not None
        assert msg.message_id is not None
        assert msg.timestamp is not None

    def test_message_to_dict(self):
        """Test message serialization."""
        msg = AgentMessage(
            agent_id="john",
            message_type=MessageType.FINDING,
            payload={"severity": "HIGH"},
            priority=Priority.CRITICAL,
        )
        d = msg.to_dict()
        assert d["agent_id"] == "john"
        assert d["message_type"] == "finding"
        assert d["priority"] == 1
        assert d["payload"]["severity"] == "HIGH"

    def test_message_from_dict(self):
        """Test message deserialization."""
        data = {
            "agent_id": "sam",
            "message_type": "finding",
            "payload": {"secret": "AWS_KEY"},
            "timestamp": "2024-01-01T00:00:00+00:00",
            "correlation_id": "abc123",
            "priority": 1,
            "message_id": "msg001",
        }
        msg = AgentMessage.from_dict(data)
        assert msg.agent_id == "sam"
        assert msg.message_type == MessageType.FINDING
        assert msg.priority == Priority.CRITICAL
        assert msg.correlation_id == "abc123"


class TestCircuitBreaker:
    """Test CircuitBreaker pattern."""

    @pytest.fixture
    def cb(self):
        return CircuitBreaker(failure_threshold=3, recovery_timeout=0.1)

    @pytest.mark.asyncio
    async def test_initially_closed(self, cb):
        """Circuit breaker starts closed (allowing execution)."""
        assert await cb.can_execute("agent1") is True
        assert cb.get_state("agent1") == "closed"

    @pytest.mark.asyncio
    async def test_opens_after_failures(self, cb):
        """Circuit breaker opens after threshold failures."""
        for _ in range(3):
            await cb.record_failure("agent1")
        assert cb.get_state("agent1") == "open"
        assert await cb.can_execute("agent1") is False

    @pytest.mark.asyncio
    async def test_resets_on_success(self, cb):
        """Circuit breaker resets on success."""
        await cb.record_failure("agent1")
        await cb.record_success("agent1")
        assert cb.get_state("agent1") == "closed"
        assert await cb.can_execute("agent1") is True

    @pytest.mark.asyncio
    async def test_half_open_after_timeout(self, cb):
        """Circuit breaker transitions to half-open after timeout."""
        for _ in range(3):
            await cb.record_failure("agent1")
        assert cb.get_state("agent1") == "open"
        # Wait for recovery timeout
        await asyncio.sleep(0.15)
        assert await cb.can_execute("agent1") is True
        assert cb.get_state("agent1") == "half_open"

    @pytest.mark.asyncio
    async def test_manual_reset(self, cb):
        """Manual reset works."""
        for _ in range(3):
            await cb.record_failure("agent1")
        assert cb.get_state("agent1") == "open"
        await cb.reset("agent1")
        assert cb.get_state("agent1") == "closed"
        assert await cb.can_execute("agent1") is True

    def test_get_all_states(self, cb):
        """Test getting all circuit breaker states."""
        states = cb.get_all_states()
        assert isinstance(states, dict)


class TestAgentCommunicationBus:
    """Test AgentCommunicationBus."""

    @pytest.fixture
    async def bus(self):
        bus = AgentCommunicationBus(
            persistence_dir=tempfile.mkdtemp(),
            max_queue_size=100,
        )
        yield bus
        await bus.stop()

    @pytest.mark.asyncio
    async def test_bus_start_stop(self):
        """Test bus lifecycle."""
        bus = AgentCommunicationBus(max_queue_size=10)
        await bus.start()
        assert bus._running is True
        await bus.stop()
        assert bus._running is False

    @pytest.mark.asyncio
    async def test_publish_and_subscribe(self):
        """Test publish/subscribe pattern."""
        bus = AgentCommunicationBus(max_queue_size=100)
        await bus.start()

        received = []

        async def handler(msg):
            received.append(msg)

        await bus.subscribe(MessageType.FINDING, handler)

        msg = AgentMessage(
            agent_id="john",
            message_type=MessageType.FINDING,
            payload={"file": "test.py"},
            priority=Priority.HIGH,
        )
        await bus.publish(msg)

        # Allow dispatch loop to process
        await asyncio.sleep(0.1)

        assert len(received) == 1
        assert received[0].agent_id == "john"
        assert received[0].payload["file"] == "test.py"

        await bus.stop()

    @pytest.mark.asyncio
    async def test_priority_queue_ordering(self):
        """Test that higher priority messages are processed first."""
        bus = AgentCommunicationBus(max_queue_size=100)
        await bus.start()

        received_order = []

        async def handler(msg):
            received_order.append(msg.priority.value)

        await bus.subscribe(MessageType.FINDING, handler)

        # Publish in reverse priority order
        for priority in [Priority.LOW, Priority.MEDIUM, Priority.HIGH, Priority.CRITICAL]:
            msg = AgentMessage(
                agent_id="john",
                message_type=MessageType.FINDING,
                payload={"priority": priority.name},
                priority=priority,
            )
            await bus.publish(msg)

        await asyncio.sleep(0.1)

        # Should be processed in priority order (lower value = higher priority)
        assert received_order[0] == Priority.CRITICAL.value
        assert received_order[-1] == Priority.LOW.value

        await bus.stop()

    @pytest.mark.asyncio
    async def test_message_persistence(self):
        """Test that messages are persisted to disk."""
        tmpdir = tempfile.mkdtemp()
        bus = AgentCommunicationBus(persistence_dir=tmpdir, persistence_enabled=True)
        await bus.start()

        msg = AgentMessage(
            agent_id="sam",
            message_type=MessageType.FINDING,
            payload={"secret": "AWS_KEY_123"},
            priority=Priority.CRITICAL,
        )
        await bus.publish(msg)
        await asyncio.sleep(0.1)

        await bus.stop()

        # Check persistence file exists
        from datetime import datetime, timezone
        date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        persist_file = Path(tmpdir) / f"messages_{date_str}.jsonl"
        assert persist_file.exists()

        # Read and verify content
        lines = persist_file.read_text().strip().split("\n")
        assert len(lines) >= 1
        data = json.loads(lines[0])
        assert data["agent_id"] == "sam"
        assert data["payload"]["secret"] == "AWS_KEY_123"

    @pytest.mark.asyncio
    async def test_circuit_breaker_drops_messages(self):
        """Test that open circuit breaker drops messages."""
        bus = AgentCommunicationBus(max_queue_size=100)
        await bus.start()

        # Open circuit breaker for agent
        for _ in range(5):
            await bus.circuit_breaker.record_failure("john")

        received = []

        async def handler(msg):
            received.append(msg)

        await bus.subscribe(MessageType.FINDING, handler)

        msg = AgentMessage(
            agent_id="john",
            message_type=MessageType.FINDING,
            payload={"file": "test.py"},
        )
        await bus.publish(msg)
        await asyncio.sleep(0.1)

        # Message should be dropped due to open circuit
        assert len(received) == 0

        await bus.stop()

    @pytest.mark.asyncio
    async def test_wildcard_subscription(self):
        """Test wildcard subscription receives all messages."""
        bus = AgentCommunicationBus(max_queue_size=100)
        await bus.start()

        received = []

        async def handler(msg):
            received.append((msg.agent_id, msg.message_type.value))

        await bus.subscribe_all(handler)

        for msg_type in [MessageType.FINDING, MessageType.STATUS, MessageType.ERROR]:
            msg = AgentMessage(
                agent_id="john",
                message_type=msg_type,
                payload={},
            )
            await bus.publish(msg)

        await asyncio.sleep(0.1)

        assert len(received) == 3

        await bus.stop()

    @pytest.mark.asyncio
    async def test_get_message_history(self):
        """Test retrieving message history."""
        bus = AgentCommunicationBus(max_queue_size=100)
        await bus.start()

        async def handler(msg):
            pass

        await bus.subscribe(MessageType.FINDING, handler)

        for i in range(5):
            msg = AgentMessage(
                agent_id="john" if i % 2 == 0 else "sam",
                message_type=MessageType.FINDING,
                payload={"index": i},
            )
            await bus.publish(msg)

        await asyncio.sleep(0.1)

        # Filter by agent
        history = await bus.get_message_history(agent_id="john")
        assert len(history) == 3  # indices 0, 2, 4

        # Filter by type
        history = await bus.get_message_history(message_type=MessageType.FINDING)
        assert len(history) == 5

        await bus.stop()

    def test_get_stats(self):
        """Test getting bus statistics."""
        bus = AgentCommunicationBus(max_queue_size=100)
        stats = bus.get_stats()
        assert "queue_size" in stats
        assert "history_size" in stats
        assert "subscriber_counts" in stats
        assert "running" in stats


class TestMessageBusIntegration:
    """Integration tests for the message bus."""

    @pytest.mark.asyncio
    async def test_concurrent_publishers(self):
        """Test concurrent message publishing from multiple agents."""
        bus = AgentCommunicationBus(max_queue_size=1000)
        await bus.start()

        received_count = 0
        lock = asyncio.Lock()

        async def handler(msg):
            nonlocal received_count
            async with lock:
                received_count += 1

        await bus.subscribe_all(handler)

        async def publish_agent(agent_id, count):
            for i in range(count):
                msg = AgentMessage(
                    agent_id=agent_id,
                    message_type=MessageType.FINDING,
                    payload={"index": i},
                )
                await bus.publish(msg)

        # Launch 5 agents publishing 10 messages each
        agents = [publish_agent(f"agent{i}", 10) for i in range(5)]
        await asyncio.gather(*agents)
        await asyncio.sleep(0.2)

        assert received_count == 50

        await bus.stop()

    @pytest.mark.asyncio
    async def test_message_types(self):
        """Test all message types are handled correctly."""
        bus = AgentCommunicationBus(max_queue_size=100)
        await bus.start()

        received_types = set()

        async def handler(msg):
            received_types.add(msg.message_type.value)

        await bus.subscribe_all(handler)

        for msg_type in MessageType:
            msg = AgentMessage(
                agent_id="hal",
                message_type=msg_type,
                payload={"type": msg_type.value},
            )
            await bus.publish(msg)

        await asyncio.sleep(0.1)

        assert len(received_types) == len(MessageType)

        await bus.stop()

    @pytest.mark.asyncio
    async def test_get_message_bus_singleton(self):
        """Test that get_message_bus returns a singleton."""
        bus1 = get_message_bus()
        bus2 = get_message_bus()
        assert bus1 is bus2

        # Reset for clean state
        await reset_message_bus()

    @pytest.mark.asyncio
    async def test_reset_message_bus(self):
        """Test resetting the message bus."""
        bus = get_message_bus()
        await bus.start()
        assert bus._running is True

        await reset_message_bus()

        new_bus = get_message_bus()
        assert new_bus is not bus
