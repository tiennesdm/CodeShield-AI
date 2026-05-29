"""
Deterministic, offline LLM provider.

The mock provider never makes a network call, which makes it ideal for unit
tests, CI, demos without credentials, and as the universal fallback when no
real backend is configured. Its responses are deterministic functions of the
input so tests can assert on them.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, List

from llm.base import LLMMessage, LLMProvider, LLMResponse, LLMRole, LLMUsage


class MockLLMProvider(LLMProvider):
    """A canned LLM useful for testing and offline operation."""

    name = "mock"
    default_model = "mock-1"

    async def is_available(self) -> bool:
        return True

    async def _complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        system = next(
            (m.content for m in messages if m.role == LLMRole.SYSTEM), ""
        )
        last_user = next(
            (m.content for m in reversed(messages) if m.role == LLMRole.USER),
            "",
        )

        content = self._respond(system, last_user)
        prompt_text = "\n".join(m.content for m in messages)
        usage = LLMUsage(
            prompt_tokens=self._estimate_tokens(prompt_text),
            completion_tokens=self._estimate_tokens(content),
        )
        return LLMResponse(
            content=content,
            provider=self.name,
            model=kwargs.get("model", self.model),
            usage=usage,
            finish_reason="stop",
            is_fallback=True,
        )

    def _respond(self, system: str, user: str) -> str:
        """
        Produce a deterministic but plausible answer.

        If the system prompt asks for JSON, return a small JSON object so that
        JSON-parsing callers still work offline.
        """
        wants_json = "json" in system.lower() or "json" in user.lower()
        digest = hashlib.sha256((system + "\n" + user).encode("utf-8")).hexdigest()[:8]

        if wants_json:
            return json.dumps(
                {
                    "summary": f"Deterministic mock response ({digest}).",
                    "confidence": "low",
                    "source": "MockLLMProvider",
                    "input_chars": len(user),
                }
            )

        snippet = user.strip().splitlines()[0][:160] if user.strip() else "(empty)"
        return (
            f"[mock:{digest}] This is a deterministic offline response generated "
            f"without a real LLM. It echoes the request so the pipeline can be "
            f"exercised end-to-end.\n\nRequest summary: {snippet}"
        )
