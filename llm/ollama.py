"""
Ollama Local API provider.

Uses the HTTP API directly via ``httpx`` to connect to a local Ollama instance.
Auto-detects available models and defaults to the first available model, falling back
to 'qwen2.5:0.5b' or 'llama3' if none are listed.
"""

from __future__ import annotations

import os
import socket
import time
from typing import Any, List, Optional

from utils.logger import get_logger

from llm.base import LLMError, LLMMessage, LLMProvider, LLMResponse, LLMUsage

logger = get_logger(__name__)

OLLAMA_API_URL = "http://localhost:11434/api/chat"
OLLAMA_TAGS_URL = "http://localhost:11434/api/tags"


class OllamaProvider(LLMProvider):
    """Provider backed by a local Ollama service."""

    name = "ollama"
    default_model = "qwen2.5:0.5b"

    def __init__(
        self,
        model: Optional[str] = None,
        *,
        base_url: str = OLLAMA_API_URL,
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
        self.base_url = base_url

    def _check_ollama_port(self) -> bool:
        """Quick synchronous TCP connection check to see if Ollama is listening."""
        try:
            with socket.create_connection(("localhost", 11434), timeout=0.5):
                return True
        except OSError:
            return False

    async def is_available(self) -> bool:
        try:
            import httpx  # noqa: F401
        except ImportError:
            return False
        return self._check_ollama_port()

    def is_available_sync(self) -> bool:
        try:
            import httpx  # noqa: F401
        except ImportError:
            return False
        return self._check_ollama_port()

    async def _detect_model(self) -> str:
        """Query Ollama tags endpoint to discover available models."""
        try:
            import httpx
            async with httpx.AsyncClient(timeout=2.0) as client:
                resp = await client.get(OLLAMA_TAGS_URL)
                if resp.status_code == 200:
                    models = [m.get("name") for m in resp.json().get("models", [])]
                    if models:
                        # If our configured model is available, use it
                        if self.model in models:
                            return self.model
                        # If a coder-specific model is present, prioritize it
                        coder_models = [m for m in models if "coder" in m or "code" in m]
                        if coder_models:
                            return coder_models[0]
                        # Otherwise fall back to the first active model
                        return models[0]
        except Exception as e:
            logger.debug("Failed to auto-detect Ollama models: %s", e)
        return self.model

    async def _complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover
            raise LLMError("httpx is required for OllamaProvider") from exc

        # Auto-resolve target model from tags if it's the default or unspecified
        model = kwargs.get("model", self.model)
        if model == self.default_model or not model:
            model = await self._detect_model()

        # Optimize message prompts for local coder models
        optimized_messages = []
        is_coder_model = any(preset in model.lower() for preset in ["coder", "code", "llama3", "qwen2.5"])
        
        for msg in messages:
            content = msg.content
            # If it's a system message and we are targeting a coder model, add strict syntax instructions
            if msg.role == "system" and is_coder_model:
                content += "\nStrict compliance instructions: Return ONLY valid, syntactically correct outputs (e.g., JSON, YAML, or unified diffs) when requested. Avoid any preamble, conversational greeting, or explanations. If writing code or diffs, ensure no markdown formatting errors."
            optimized_messages.append(LLMMessage(role=msg.role, content=content))

        body = {
            "model": model,
            "messages": [m.to_dict() for m in optimized_messages],
            "stream": False,
            "options": {
                "temperature": kwargs.get("temperature", self.temperature),
            }
        }

        start = time.time()
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                resp = await client.post(self.base_url, json=body)
        except Exception as exc:
            raise LLMError(f"Ollama API request failed: {exc}") from exc
        latency_ms = int((time.time() - start) * 1000)

        if resp.status_code >= 400:
            raise LLMError(f"Ollama API error {resp.status_code}: {resp.text[:500]}")

        payload = resp.json()
        message = payload.get("message", {})
        content = message.get("content", "") or ""
        
        # Best-effort token estimation or extraction
        prompt_eval_count = payload.get("prompt_eval_count", 0) or 0
        eval_count = payload.get("eval_count", 0) or 0
        usage = LLMUsage(
            prompt_tokens=prompt_eval_count if prompt_eval_count > 0 else self._estimate_tokens(content),
            completion_tokens=eval_count if eval_count > 0 else self._estimate_tokens(content),
        )

        return LLMResponse(
            content=content,
            provider=self.name,
            model=model,
            usage=usage,
            latency_ms=latency_ms,
            finish_reason="stop",
            raw=payload,
        )
