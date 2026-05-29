"""
OpenAI Chat Completions API provider.

Uses the HTTP API directly via ``httpx`` so we don't require the vendor SDK.
Reads the API key from ``OPENAI_API_KEY`` unless one is passed explicitly.
This complements the existing ``openai`` usage in ``ai_triage.py`` and gives
the LLM abstraction a second real backend.
"""

from __future__ import annotations

import os
import time
from typing import Any, List, Optional

from utils.logger import get_logger

from llm.base import LLMError, LLMMessage, LLMProvider, LLMResponse, LLMUsage

logger = get_logger(__name__)

OPENAI_API_URL = "https://api.openai.com/v1/chat/completions"


class OpenAIAPIProvider(LLMProvider):
    """Provider backed by the OpenAI Chat Completions HTTP API."""

    name = "openai_api"
    default_model = "gpt-4o-mini"

    def __init__(
        self,
        model: Optional[str] = None,
        *,
        api_key: Optional[str] = None,
        base_url: str = OPENAI_API_URL,
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
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
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

    async def _complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        if not self.api_key:
            raise LLMError("OPENAI_API_KEY is not set")

        try:
            import httpx
        except ImportError as exc:  # pragma: no cover
            raise LLMError("httpx is required for OpenAIAPIProvider") from exc

        model = kwargs.get("model", self.model)
        body = {
            "model": model,
            "max_tokens": kwargs.get("max_tokens", self.max_tokens),
            "temperature": kwargs.get("temperature", self.temperature),
            "messages": [m.to_dict() for m in messages],
        }
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "content-type": "application/json",
        }

        start = time.time()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.base_url, json=body, headers=headers)
        except Exception as exc:
            raise LLMError(f"OpenAI API request failed: {exc}") from exc
        latency_ms = int((time.time() - start) * 1000)

        if resp.status_code >= 400:
            raise LLMError(f"OpenAI API error {resp.status_code}: {resp.text[:500]}")

        payload = resp.json()
        choices = payload.get("choices", [])
        content = ""
        finish_reason = "stop"
        if choices:
            content = choices[0].get("message", {}).get("content", "") or ""
            finish_reason = choices[0].get("finish_reason", "stop")
        usage_block = payload.get("usage", {})
        usage = LLMUsage(
            prompt_tokens=int(usage_block.get("prompt_tokens", 0) or 0),
            completion_tokens=int(usage_block.get("completion_tokens", 0) or 0),
        )
        return LLMResponse(
            content=content,
            provider=self.name,
            model=model,
            usage=usage,
            latency_ms=latency_ms,
            finish_reason=finish_reason,
            raw=payload,
        )
