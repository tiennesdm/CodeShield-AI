"""
Claude CLI provider.

Shells out to the local ``claude`` command-line tool (Claude Code / Claude CLI)
so the platform can use a developer's existing Claude login and tooling instead
of managing API keys directly. This is the recommended path for the hands-on
"experiment with the Claude CLI" workflow, including running on an AWS EC2 box.

The CLI is invoked in non-interactive ("print") mode:

    claude -p "<prompt>" --output-format json --model <model>

If the CLI is not installed, not on PATH, or returns an error, the provider
raises :class:`LLMError`; the factory then falls back to another provider so
the system degrades gracefully rather than crashing.
"""

from __future__ import annotations

import asyncio
import json
import shutil
import time
from typing import Any, List, Optional

from utils.logger import get_logger

from llm.base import LLMError, LLMMessage, LLMProvider, LLMResponse, LLMRole, LLMUsage

logger = get_logger(__name__)


class ClaudeCLIProvider(LLMProvider):
    """Provider that delegates to the local ``claude`` CLI binary."""

    name = "claude_cli"
    default_model = "claude-sonnet-4-5"

    def __init__(
        self,
        model: Optional[str] = None,
        *,
        binary: str = "claude",
        temperature: float = 0.2,
        max_tokens: int = 1024,
        timeout: float = 120.0,
        config: Optional[dict] = None,
    ) -> None:
        super().__init__(
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
            config=config,
        )
        self.binary = binary

    def _resolve_binary(self) -> Optional[str]:
        return shutil.which(self.binary)

    async def is_available(self) -> bool:
        """True only if the ``claude`` binary is discoverable on PATH."""
        return self._resolve_binary() is not None

    def is_available_sync(self) -> bool:
        return self._resolve_binary() is not None

    @staticmethod
    def _flatten_messages(messages: List[LLMMessage]) -> tuple[str, str]:
        """
        Collapse messages into (system_prompt, user_prompt).

        The CLI's print mode takes a single prompt plus an optional system
        prompt, so multi-turn history is folded into the user prompt with
        clear role markers.
        """
        system_parts: List[str] = []
        convo_parts: List[str] = []
        for m in messages:
            if m.role == LLMRole.SYSTEM:
                system_parts.append(m.content)
            elif m.role == LLMRole.ASSISTANT:
                convo_parts.append(f"Assistant: {m.content}")
            else:
                convo_parts.append(f"User: {m.content}")
        return "\n\n".join(system_parts), "\n\n".join(convo_parts)

    async def _complete(
        self, messages: List[LLMMessage], **kwargs: Any
    ) -> LLMResponse:
        binary = self._resolve_binary()
        if not binary:
            raise LLMError(
                f"Claude CLI binary '{self.binary}' not found on PATH. "
                "Install it from https://docs.anthropic.com/en/docs/claude-code "
                "or configure a different LLM provider."
            )

        model = kwargs.get("model", self.model)
        system_prompt, user_prompt = self._flatten_messages(messages)

        cmd = [binary, "-p", user_prompt, "--output-format", "json"]
        if model:
            cmd += ["--model", model]
        if system_prompt:
            cmd += ["--append-system-prompt", system_prompt]

        start = time.time()
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(
                proc.communicate(), timeout=self.timeout
            )
        except asyncio.TimeoutError as exc:
            raise LLMError(f"Claude CLI timed out after {self.timeout}s") from exc
        except Exception as exc:  # pragma: no cover - depends on local env
            raise LLMError(f"Failed to invoke Claude CLI: {exc}") from exc

        latency_ms = int((time.time() - start) * 1000)

        if proc.returncode != 0:
            err = stderr.decode("utf-8", "replace").strip()
            raise LLMError(f"Claude CLI exited with code {proc.returncode}: {err}")

        return self._parse_output(
            stdout.decode("utf-8", "replace"), model, latency_ms
        )

    def _parse_output(
        self, raw_stdout: str, model: str, latency_ms: int
    ) -> LLMResponse:
        """Parse the CLI's JSON output, tolerating plain-text fallback."""
        text = raw_stdout.strip()
        content = text
        usage = LLMUsage()
        finish_reason = "stop"
        raw: dict = {}

        try:
            payload = json.loads(text)
            raw = payload if isinstance(payload, dict) else {}
            # Claude CLI json output uses "result" for the assistant text.
            content = (
                raw.get("result")
                or raw.get("response")
                or raw.get("content")
                or text
            )
            usage_block = raw.get("usage") or {}
            usage = LLMUsage(
                prompt_tokens=int(usage_block.get("input_tokens", 0) or 0),
                completion_tokens=int(usage_block.get("output_tokens", 0) or 0),
            )
            finish_reason = raw.get("stop_reason") or raw.get("subtype") or "stop"
        except (json.JSONDecodeError, TypeError, ValueError):
            logger.debug("Claude CLI output was not JSON; treating as plain text")

        if not usage.total_tokens:
            usage.completion_tokens = self._estimate_tokens(content)

        return LLMResponse(
            content=content if isinstance(content, str) else str(content),
            provider=self.name,
            model=model,
            usage=usage,
            latency_ms=latency_ms,
            finish_reason=str(finish_reason),
            raw=raw,
        )
