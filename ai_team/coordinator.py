"""
The Team Coordinator.

Orchestrates the AI Team to accomplish a goal. The coordinator:
  - Instantiates one :class:`TeamAgent` per role.
  - Runs them in dependency order, threading each agent's output into the
    context of downstream agents (a simple, explainable DAG execution).
  - Aggregates a structured transcript, an executive summary, and a roll-up of
    the governance signals (PII redacted, risks flagged, human-review needs).

It is intentionally transparent: the full run can be serialized to a dict and
shown to a non-technical stakeholder.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

from ai_team.agent import AgentRunResult, TeamAgent
from ai_team.roles import RoleSpec, build_default_team
from governance.governor import AIGovernor
from governance.policy import ResponsibleAIPolicy
from llm.base import LLMProvider
from llm.factory import get_llm_provider

logger = get_logger(__name__)


@dataclass
class Task:
    """A unit of work assigned to a role (for reporting / future scheduling)."""

    role_key: str
    title: str
    status: str = "pending"

    def to_dict(self) -> Dict[str, Any]:
        return {"role_key": self.role_key, "title": self.title, "status": self.status}


@dataclass
class TeamRunResult:
    """The full result of an AI Team run."""

    goal: str
    steps: List[AgentRunResult] = field(default_factory=list)
    tasks: List[Task] = field(default_factory=list)
    duration_ms: int = 0
    provider: str = ""
    model: str = ""

    @property
    def final_output(self) -> str:
        for step in reversed(self.steps):
            if step.status == "success" and step.output.strip():
                return step.output
        return ""

    def governance_rollup(self) -> Dict[str, Any]:
        total_pii = sum(s.governance.get("pii_redacted", 0) for s in self.steps)
        flagged = [s.role_key for s in self.steps if s.requires_human_review]
        blocked = [s.role_key for s in self.steps if s.status == "blocked"]
        return {
            "total_pii_redacted": total_pii,
            "roles_requiring_human_review": flagged,
            "roles_blocked": blocked,
            "human_review_required": bool(flagged or blocked),
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "goal": self.goal,
            "provider": self.provider,
            "model": self.model,
            "duration_ms": self.duration_ms,
            "tasks": [t.to_dict() for t in self.tasks],
            "steps": [s.to_dict() for s in self.steps],
            "final_output": self.final_output,
            "governance": self.governance_rollup(),
        }


class TeamCoordinator:
    """Coordinates a team of role-specialized agents to achieve a goal."""

    def __init__(
        self,
        *,
        provider: Optional[LLMProvider] = None,
        policy: Optional[ResponsibleAIPolicy] = None,
        roles: Optional[List[RoleSpec]] = None,
        provider_name: Optional[str] = None,
    ) -> None:
        self.provider = provider or get_llm_provider(provider_name)
        self.policy = policy or ResponsibleAIPolicy()
        self.governor = AIGovernor(self.provider, policy=self.policy)
        self.roles = roles or build_default_team()
        self.agents = [TeamAgent(role, self.governor) for role in self.roles]

    async def run(self, goal: str) -> TeamRunResult:
        """Execute the full team workflow for a goal."""
        start = time.time()
        result = TeamRunResult(
            goal=goal,
            provider=self.provider.name,
            model=self.provider.model,
            tasks=[Task(role_key=a.role.key, title=a.role.title) for a in self.agents],
        )
        context: Dict[str, str] = {}

        for agent, task in zip(self.agents, result.tasks):
            task.status = "running"
            step = await agent.run(goal, context)
            result.steps.append(step)
            context[agent.role.key] = step.output
            task.status = "done" if step.status == "success" else step.status
            logger.info(
                "[ai_team] %s -> %s (%dms)",
                agent.role.key,
                step.status,
                step.latency_ms,
            )

        result.duration_ms = int((time.time() - start) * 1000)
        logger.info(
            "[ai_team] run complete: %d steps in %dms via %s",
            len(result.steps),
            result.duration_ms,
            self.provider.name,
        )
        return result
