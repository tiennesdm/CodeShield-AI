"""
Core data models and the abstract base class for LLM providers.

Keeping these dataclass-based (rather than tied to any vendor SDK) means the
abstraction has no hard third-party dependency and is trivial to unit test.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class LLMRole(str, Enum):
    """Conversation roles understood by all providers."""

    SYSTEM = "system"
    USER = "user"
    ASSISTANT = "assistant"


class LLMError(Exception):
    """Raised when an LLM call fails in a non-recoverable way."""


@dataclass
class LLMMessage:
    """A single chat message."""

    role: LLMRole
    content: str

    def to_dict(self) -> Dict[str, str]:
        role = self.role.value if isinstance(self.role, LLMRole) else str(self.role)
        return {"role": role, "content": self.content}

    @staticmethod
    def system(content: str) -> "LLMMessage":
        return LLMMessage(role=LLMRole.SYSTEM, content=content)

    @staticmethod
    def user(content: str) -> "LLMMessage":
        return LLMMessage(role=LLMRole.USER, content=content)

    @staticmethod
    def assistant(content: str) -> "LLMMessage":
        return LLMMessage(role=LLMRole.ASSISTANT, content=content)


@dataclass
class LLMUsage:
    """Token accounting for a single completion (best-effort)."""

    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def to_dict(self) -> Dict[str, int]:
        return {
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
        }


@dataclass
class LLMResponse:
    """Standardized response returned by every provider."""

    content: str
    provider: str
    model: str
    usage: LLMUsage = field(default_factory=LLMUsage)
    latency_ms: int = 0
    finish_reason: str = "stop"
    raw: Dict[str, Any] = field(default_factory=dict)
    is_fallback: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "content": self.content,
            "provider": self.provider,
            "model": self.model,
            "usage": self.usage.to_dict(),
            "latency_ms": self.latency_ms,
            "finish_reason": self.finish_reason,
            "is_fallback": self.is_fallback,
        }


class LLMProvider(ABC):
    """
    Abstract base class for all LLM providers.

    Concrete providers only need to implement :meth:`_complete`. The public
    :meth:`complete` wrapper adds timing, basic validation, and a uniform
    error surface, so individual providers stay small.
    """

    name: str = "base"
    default_model: str = "unknown"

    def __init__(
        self,
        model: Optional[str] = None,
        *,
        temperature: float = 0.2,
        max_tokens: int = 1024,
        timeout: float = 60.0,
        config: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.model = model or self.default_model
        self.temperature = temperature
        self.max_tokens = max_tokens
        self.timeout = timeout
        self.config = config or {}

    @abstractmethod
    async def _complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        """Provider-specific completion. Implemented by subclasses."""

    @abstractmethod
    async def is_available(self) -> bool:
        """Return True if the provider can currently service requests."""

    def is_available_sync(self) -> bool:
        """
        Cheap, synchronous availability check used by the factory.

        Defaults to True; providers with local prerequisites (a CLI binary, an
        API key) override this so selection works even inside a running event
        loop.
        """
        return True

    async def complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        """
        Run a chat completion.

        Args:
            messages: Ordered conversation messages.
            **kwargs: Optional per-call overrides (e.g. ``temperature``,
                ``max_tokens``, ``model``).

        Returns:
            A populated :class:`LLMResponse`.
        """
        if not messages:
            raise LLMError("complete() requires at least one message")

        start = time.time()
        response = await self._complete(messages, **kwargs)
        if not response.latency_ms:
            response.latency_ms = int((time.time() - start) * 1000)
        return response

    async def ask(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        **kwargs: Any,
    ) -> LLMResponse:
        """Convenience helper for a single-turn prompt."""
        messages: List[LLMMessage] = []
        if system:
            messages.append(LLMMessage.system(system))
        messages.append(LLMMessage.user(prompt))
        return await self.complete(messages, **kwargs)

    @staticmethod
    def _estimate_tokens(text: str) -> int:
        """Rough token estimate (~4 chars/token) for providers lacking usage."""
        return max(1, len(text) // 4)

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(name={self.name!r}, model={self.model!r})>"
