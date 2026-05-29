"""
Agent Communication Bus - Async Message Bus for Inter-Agent Communication.

Implements a pub/sub pattern for agent communication with:
- Priority queue for critical findings
- Message persistence for audit trails
- Circuit breaker for unhealthy agents
- Thread-safe async operations
"""

import asyncio
import itertools
import json
import os
import time
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)


class MessageType(str, Enum):
    """Types of messages exchanged between agents."""

    SCAN_START = "scan_start"
    FINDING = "finding"
    VALIDATION = "validation"
    FIX = "fix"
    REPORT = "report"
    STATUS = "status"
    ERROR = "error"
    HEARTBEAT = "heartbeat"
    TRIAGE_RESULT = "triage_result"
    FIX_RESULT = "fix_result"
    PRIORITY_CHANGE = "priority_change"
    HUMAN_APPROVAL = "human_approval"


class Priority(int, Enum):
    """Message priority levels."""

    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5


@dataclass
class AgentMessage:
    """Schema for messages exchanged between agents."""

    agent_id: str
    message_type: MessageType
    payload: Dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    correlation_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    priority: Priority = Priority.MEDIUM
    message_id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])

    def to_dict(self) -> Dict[str, Any]:
        """Convert message to dictionary."""
        return {
            "message_id": self.message_id,
            "agent_id": self.agent_id,
            "message_type": self.message_type.value,
            "payload": self.payload,
            "timestamp": self.timestamp,
            "correlation_id": self.correlation_id,
            "priority": self.priority.value,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentMessage":
        """Create message from dictionary."""
        return cls(
            message_id=data.get("message_id", str(uuid.uuid4())[:8]),
            agent_id=data["agent_id"],
            message_type=MessageType(data["message_type"]),
            payload=data.get("payload", {}),
            timestamp=data.get("timestamp", datetime.now(timezone.utc).isoformat()),
            correlation_id=data.get("correlation_id", str(uuid.uuid4())[:8]),
            priority=Priority(data.get("priority", 3)),
        )


class CircuitBreaker:
    """
    Circuit breaker pattern for agent failure handling.

    If an agent fails N times within a time window, mark it as unhealthy.
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        half_open_max_calls: int = 2,
    ) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.half_open_max_calls = half_open_max_calls

        # Track failures per agent
        self._failures: Dict[str, int] = {}
        self._last_failure_time: Dict[str, float] = {}
        self._states: Dict[str, str] = {}  # "closed", "open", "half_open"
        self._half_open_calls: Dict[str, int] = {}
        self._lock = asyncio.Lock()

    async def record_success(self, agent_id: str) -> None:
        """Record a successful operation for an agent."""
        async with self._lock:
            if agent_id in self._failures:
                del self._failures[agent_id]
            self._states[agent_id] = "closed"
            self._half_open_calls.pop(agent_id, None)

    async def record_failure(self, agent_id: str) -> None:
        """Record a failure for an agent."""
        async with self._lock:
            current_time = time.time()
            self._failures[agent_id] = self._failures.get(agent_id, 0) + 1
            self._last_failure_time[agent_id] = current_time

            if self._failures[agent_id] >= self.failure_threshold:
                self._states[agent_id] = "open"
                logger.warning(
                    "Circuit breaker OPEN for agent %s after %d failures",
                    agent_id,
                    self._failures[agent_id],
                )

    async def can_execute(self, agent_id: str) -> bool:
        """Check if an agent is allowed to execute."""
        async with self._lock:
            state = self._states.get(agent_id, "closed")

            if state == "closed":
                return True

            if state == "open":
                last_fail = self._last_failure_time.get(agent_id, 0)
                if time.time() - last_fail > self.recovery_timeout:
                    self._states[agent_id] = "half_open"
                    self._half_open_calls[agent_id] = 0
                    logger.info(
                        "Circuit breaker HALF-OPEN for agent %s", agent_id
                    )
                    return True
                return False

            if state == "half_open":
                calls = self._half_open_calls.get(agent_id, 0)
                if calls < self.half_open_max_calls:
                    self._half_open_calls[agent_id] = calls + 1
                    return True
                return False

            return True

    def get_state(self, agent_id: str) -> str:
        """Get current circuit breaker state for an agent."""
        return self._states.get(agent_id, "closed")

    async def reset(self, agent_id: str) -> None:
        """Manually reset circuit breaker for an agent."""
        async with self._lock:
            self._failures.pop(agent_id, None)
            self._last_failure_time.pop(agent_id, None)
            self._states.pop(agent_id, None)
            self._half_open_calls.pop(agent_id, None)

    def get_all_states(self) -> Dict[str, Dict[str, Any]]:
        """Get circuit breaker states for all agents."""
        return {
            agent_id: {
                "state": state,
                "failures": self._failures.get(agent_id, 0),
                "last_failure": self._last_failure_time.get(agent_id),
            }
            for agent_id, state in self._states.items()
        }


class AgentCommunicationBus:
    """
    Async message bus for inter-agent communication.

    Implements pub/sub pattern with priority queues, message persistence,
    and circuit breaker integration.
    """

    def __init__(
        self,
        persistence_dir: Optional[str] = None,
        max_queue_size: int = 10000,
        persistence_enabled: bool = True,
    ) -> None:
        self._subscribers: Dict[
            MessageType, List[Callable[[AgentMessage], Coroutine[Any, Any, None]]]
        ] = {msg_type: [] for msg_type in MessageType}
        self._wildcard_subscribers: List[
            Callable[[AgentMessage], Coroutine[Any, Any, None]]
        ] = []
        self._priority_queue: asyncio.PriorityQueue = asyncio.PriorityQueue(
            maxsize=max_queue_size
        )
        # Monotonic tiebreaker so equal-priority messages are never compared
        # against each other (AgentMessage is not orderable).
        self._seq = itertools.count()
        self._message_history: List[AgentMessage] = []
        self._max_history = 5000
        self._lock = asyncio.Lock()
        self._running = False
        self._dispatch_task: Optional[asyncio.Task] = None
        self._circuit_breaker = CircuitBreaker()
        self._persistence_enabled = persistence_enabled

        settings = get_settings()
        if persistence_dir:
            self._persistence_dir = Path(persistence_dir)
        else:
            self._persistence_dir = settings.data_dir / "messages"
        self._persistence_dir.mkdir(parents=True, exist_ok=True)

    @property
    def circuit_breaker(self) -> CircuitBreaker:
        """Access the circuit breaker."""
        return self._circuit_breaker

    async def start(self) -> None:
        """Start the message bus dispatch loop."""
        if self._running:
            return
        self._running = True
        self._dispatch_task = asyncio.create_task(self._dispatch_loop())
        logger.info("Agent communication bus started")

    async def stop(self) -> None:
        """Stop the message bus dispatch loop."""
        self._running = False
        if self._dispatch_task:
            self._dispatch_task.cancel()
            try:
                await self._dispatch_task
            except asyncio.CancelledError:
                pass
        logger.info("Agent communication bus stopped")

    async def publish(self, message: AgentMessage) -> None:
        """
        Publish a message to the bus.

        Messages are placed in a priority queue and dispatched asynchronously.
        """
        # Check circuit breaker
        can_execute = await self._circuit_breaker.can_execute(message.agent_id)
        if not can_execute:
            logger.warning(
                "Agent %s circuit breaker OPEN, message %s dropped",
                message.agent_id,
                message.message_id,
            )
            return

        # Add to priority queue (lower priority number = higher urgency)
        try:
            await self._priority_queue.put((message.priority.value, next(self._seq), message))
            logger.debug(
                "Message %s from %s queued (type=%s, priority=%s)",
                message.message_id,
                message.agent_id,
                message.message_type.value,
                message.priority.name,
            )
        except asyncio.QueueFull:
            logger.error("Message queue full, dropping message %s", message.message_id)

    async def subscribe(
        self,
        message_type: MessageType,
        handler: Callable[[AgentMessage], Coroutine[Any, Any, None]],
    ) -> None:
        """Subscribe to messages of a specific type."""
        async with self._lock:
            if message_type not in self._subscribers:
                self._subscribers[message_type] = []
            self._subscribers[message_type].append(handler)
        logger.debug("Subscriber registered for message type %s", message_type.value)

    async def subscribe_all(
        self, handler: Callable[[AgentMessage], Coroutine[Any, Any, None]]
    ) -> None:
        """Subscribe to all message types (wildcard)."""
        async with self._lock:
            self._wildcard_subscribers.append(handler)
        logger.debug("Wildcard subscriber registered")

    async def unsubscribe(
        self,
        message_type: MessageType,
        handler: Callable[[AgentMessage], Coroutine[Any, Any, None]],
    ) -> None:
        """Unsubscribe a handler from a message type."""
        async with self._lock:
            if message_type in self._subscribers:
                if handler in self._subscribers[message_type]:
                    self._subscribers[message_type].remove(handler)

    async def _dispatch_loop(self) -> None:
        """Main dispatch loop that processes the priority queue."""
        while self._running:
            try:
                _, _, message = await asyncio.wait_for(
                    self._priority_queue.get(), timeout=1.0
                )
                await self._dispatch(message)
            except asyncio.TimeoutError:
                continue
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error("Error in dispatch loop: %s", e, exc_info=True)
                await asyncio.sleep(0.05)

    async def _dispatch(self, message: AgentMessage) -> None:
        """Dispatch a message to all relevant subscribers."""
        # Record in history
        async with self._lock:
            self._message_history.append(message)
            if len(self._message_history) > self._max_history:
                self._message_history = self._message_history[-self._max_history :]

        # Persist message
        if self._persistence_enabled:
            await self._persist_message(message)

        # Get subscribers for this message type
        handlers: List[Callable[[AgentMessage], Coroutine[Any, Any, None]]] = []
        async with self._lock:
            handlers.extend(self._subscribers.get(message.message_type, []))
            handlers.extend(self._wildcard_subscribers)

        # Dispatch to all handlers concurrently
        if handlers:
            tasks = [self._safe_handler_call(handler, message) for handler in handlers]
            await asyncio.gather(*tasks, return_exceptions=True)

    async def _safe_handler_call(
        self,
        handler: Callable[[AgentMessage], Coroutine[Any, Any, None]],
        message: AgentMessage,
    ) -> None:
        """Call a handler with error protection."""
        try:
            await handler(message)
            await self._circuit_breaker.record_success(message.agent_id)
        except Exception as e:
            logger.error(
                "Handler error for message %s: %s", message.message_id, e
            )
            await self._circuit_breaker.record_failure(message.agent_id)

    async def _persist_message(self, message: AgentMessage) -> None:
        """Persist a message to disk for audit trail."""
        try:
            date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
            file_path = self._persistence_dir / f"messages_{date_str}.jsonl"

            with open(file_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(message.to_dict()) + "\n")
        except Exception as e:
            logger.error("Failed to persist message %s: %s", message.message_id, e)

    async def get_message_history(
        self,
        agent_id: Optional[str] = None,
        message_type: Optional[MessageType] = None,
        correlation_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[AgentMessage]:
        """Get filtered message history."""
        async with self._lock:
            messages = list(self._message_history)

        if agent_id:
            messages = [m for m in messages if m.agent_id == agent_id]
        if message_type:
            messages = [m for m in messages if m.message_type == message_type]
        if correlation_id:
            messages = [m for m in messages if m.correlation_id == correlation_id]

        return messages[-limit:]

    async def get_persisted_messages(
        self,
        date_str: Optional[str] = None,
        agent_id: Optional[str] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Get persisted messages from disk."""
        date_str = date_str or datetime.now(timezone.utc).strftime("%Y-%m-%d")
        file_path = self._persistence_dir / f"messages_{date_str}.jsonl"

        if not file_path.exists():
            return []

        messages = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    msg = json.loads(line.strip())
                    if agent_id is None or msg.get("agent_id") == agent_id:
                        messages.append(msg)
                    if len(messages) >= limit:
                        break
        except Exception as e:
            logger.error("Failed to read persisted messages: %s", e)

        return messages

    def get_stats(self) -> Dict[str, Any]:
        """Get message bus statistics."""
        return {
            "queue_size": self._priority_queue.qsize(),
            "history_size": len(self._message_history),
            "subscriber_counts": {
                msg_type.value: len(handlers)
                for msg_type, handlers in self._subscribers.items()
            },
            "wildcard_subscribers": len(self._wildcard_subscribers),
            "running": self._running,
            "circuit_breaker": self._circuit_breaker.get_all_states(),
            "persistence_dir": str(self._persistence_dir),
        }


# Global message bus instance
_message_bus: Optional[AgentCommunicationBus] = None


def get_message_bus() -> AgentCommunicationBus:
    """Get or create the global message bus instance."""
    global _message_bus
    if _message_bus is None:
        _message_bus = AgentCommunicationBus()
    return _message_bus


async def reset_message_bus() -> None:
    """Reset the global message bus instance (for testing)."""
    global _message_bus
    if _message_bus:
        await _message_bus.stop()
    _message_bus = None
