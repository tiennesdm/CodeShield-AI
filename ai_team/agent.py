"""
A single AI Team member.

Each :class:`TeamAgent` wraps a :class:`RoleSpec` and an
:class:`governance.governor.AIGovernor`. It builds a prompt from the goal and
any upstream context, runs a governed LLM call, and returns a structured
result that includes the governance trace for that step.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

from utils.logger import get_logger

from ai_team.roles import RoleSpec
from governance.governor import AIGovernor, GovernanceError
from llm.base import LLMMessage

logger = get_logger(__name__)


@dataclass
class AgentRunResult:
    """Outcome of one agent's turn."""

    role_key: str
    title: str
    output: str
    status: str = "success"  # success | blocked | error
    requires_human_review: bool = False
    governance: Dict[str, Any] = field(default_factory=dict)
    latency_ms: int = 0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "role_key": self.role_key,
            "title": self.title,
            "output": self.output,
            "status": self.status,
            "requires_human_review": self.requires_human_review,
            "governance": self.governance,
            "latency_ms": self.latency_ms,
            "error": self.error,
        }


class TeamAgent:
    """An LLM-backed, role-specialized team member."""

    def __init__(self, role: RoleSpec, governor: AIGovernor) -> None:
        self.role = role
        self.governor = governor

    def _build_prompt(self, goal: str, context: Dict[str, str]) -> str:
        parts = [f"GOAL:\n{goal}"]
        for dep in self.role.depends_on:
            if dep in context and context[dep].strip():
                parts.append(f"\nINPUT FROM {dep.upper()}:\n{context[dep]}")
        parts.append(f"\nYOUR TASK ({self.role.title}): respond now.")
        return "\n".join(parts)

    async def run(self, goal: str, context: Dict[str, str]) -> AgentRunResult:
        start = time.time()
        prompt = self._build_prompt(goal, context)
        logger.info("[ai_team] %s starting", self.role.key)
        try:
            governed = await self.governor.ask(
                prompt,
                system=self.role.system_prompt,
                sensitivity=self.role.sensitivity,
                actor=f"ai_team:{self.role.key}",
            )
        except GovernanceError as exc:
            logger.warning("[ai_team] %s blocked: %s", self.role.key, exc.reason)
            return AgentRunResult(
                role_key=self.role.key,
                title=self.role.title,
                output="",
                status="blocked",
                governance=exc.trace,
                error=f"{exc.reason}: {exc}",
                latency_ms=int((time.time() - start) * 1000),
            )
        except Exception as exc:  # pragma: no cover - defensive
            logger.error("[ai_team] %s error: %s", self.role.key, exc)
            return AgentRunResult(
                role_key=self.role.key,
                title=self.role.title,
                output="",
                status="error",
                error=str(exc),
                latency_ms=int((time.time() - start) * 1000),
            )

        trace = governed.trace
        return AgentRunResult(
            role_key=self.role.key,
            title=self.role.title,
            output=governed.content,
            status="success",
            requires_human_review=trace.requires_human_review,
            governance=trace.to_dict(),
            latency_ms=governed.response.latency_ms,
        )
