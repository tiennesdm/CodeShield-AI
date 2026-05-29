"""
Anthropic Messages API provider.

Uses the HTTP API directly via ``httpx`` (already a project dependency) so we
don't require the vendor SDK. Reads the API key from the ``ANTHROPIC_API_KEY``
environment variable unless one is passed explicitly.
"""

from __future__ import annotations

import os
import time
from typing import Any, List, Optional

from utils.logger import get_logger

from llm.base import LLMError, LLMMessage, LLMProvider, LLMResponse, LLMRole, LLMUsage

logger = get_logger(__name__)

ANTHROPIC_API_URL = "https://api.anthropic.com/v1/messages"
ANTHROPIC_VERSION = "2023-06-01"


class AnthropicAPIProvider(LLMProvider):
    """Provider backed by the Anthropic Messages HTTP API."""

    name = "anthropic_api"
    default_model = "claude-sonnet-4-5"

    def __init__(
        self,
        model: Optional[str] = None,
        *,
        api_key: Optional[str] = None,
        base_url: str = ANTHROPIC_API_URL,
        temperature: float = 0.2,
        max_tokens: int = 1024,
        timeout: float = 60.0,
        config: Optional[dict] = None,
    ) -> None:
        super().__init__(
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
            config=config,
        )
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")
        self.base_url = base_url

    async def is_available(self) -> bool:
        if not self.api_key:
            return False
        try:
            import httpx  # noqa: F401
        except ImportError:
            return False
        return True

    def is_available_sync(self) -> bool:
        if not self.api_key:
            return False
        try:
            import httpx  # noqa: F401
        except ImportError:
            return False
        return True

    @staticmethod
    def _split_messages(messages: List[LLMMessage]) -> tuple[str, list]:
        """Anthropic expects system separately and a user/assistant turn list."""
        system_parts: List[str] = []
        turns: list = []
        for m in messages:
            if m.role == LLMRole.SYSTEM:
                system_parts.append(m.content)
            else:
                role = "assistant" if m.role == LLMRole.ASSISTANT else "user"
                turns.append({"role": role, "content": m.content})
        return "\n\n".join(system_parts), turns

    async def _complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        if not self.api_key:
            raise LLMError("ANTHROPIC_API_KEY is not set")

        try:
            import httpx
        except ImportError as exc:  # pragma: no cover
            raise LLMError("httpx is required for AnthropicAPIProvider") from exc

        model = kwargs.get("model", self.model)
        system_prompt, turns = self._split_messages(messages)
        body: dict = {
            "model": model,
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            "temperature": kwargs.get("temperature", self.temperature),
            "messages": turns,
        }
        if system_prompt:
            body["system"] = system_prompt

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": ANTHROPIC_VERSION,
            "content-type": "application/json",
        }

        start = time.time()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.base_url, json=body, headers=headers)
        except Exception as exc:
            raise LLMError(f"Anthropic API request failed: {exc}") from exc
        latency_ms = int((time.time() - start) * 1000)

        if resp.status_code >= 400:
            raise LLMError(
                f"Anthropic API error {resp.status_code}: {resp.text[:500]}"
            )

        payload = resp.json()
        blocks = payload.get("content", [])
        content = "".join(
            b.get("text", "") for b in blocks if isinstance(b, dict)
        )
        usage_block = payload.get("usage", {})
        usage = LLMUsage(
            prompt_tokens=int(usage_block.get("input_tokens", 0) or 0),
            completion_tokens=int(usage_block.get("output_tokens", 0) or 0),
        )
        return LLMResponse(
            content=content,
            provider=self.name,
            model=model,
            usage=usage,
            latency_ms=latency_ms,
            finish_reason=payload.get("stop_reason", "stop"),
            raw=payload,
        )
