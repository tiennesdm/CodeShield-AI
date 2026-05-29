"""
CodeShield AI - LLM Provider Abstraction Layer.

A thin, dependency-light abstraction over multiple LLM backends so that the
rest of the platform (agents, AI triage, the AI Team, etc.) can call language
models through a single, swappable interface.

Supported providers:
  - ClaudeCLIProvider: shells out to the local ``claude`` CLI (Claude Code).
  - AnthropicAPIProvider: calls the Anthropic Messages HTTP API via httpx.
  - OpenAIAPIProvider: calls the OpenAI Chat Completions HTTP API via httpx.
  - MockLLMProvider: deterministic, offline provider for tests and demos.

Every provider implements the same :class:`LLMProvider` interface and returns
the same :class:`LLMResponse`, which keeps integration and testing simple.

Use :func:`get_llm_provider` to obtain a provider based on environment/config,
with an automatic, graceful fallback to the mock provider when no real backend
is configured or reachable.
"""

from llm.base import (
    LLMError,
    LLMMessage,
    LLMProvider,
    LLMResponse,
    LLMRole,
    LLMUsage,
)
from llm.factory import available_providers, get_llm_provider
from llm.mock import MockLLMProvider

__all__ = [
    "LLMProvider",
    "LLMMessage",
    "LLMResponse",
    "LLMRole",
    "LLMUsage",
    "LLMError",
    "MockLLMProvider",
    "get_llm_provider",
    "available_providers",
]
