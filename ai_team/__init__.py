"""
CodeShield AI - Agentic "AI Team" framework.

A small, self-contained multi-agent system that demonstrates agentic AI
patterns end-to-end: a team of role-specialized agents (Planner, Researcher,
Engineer, Reviewer, and a Responsible-AI Officer) coordinated to accomplish a
single high-level goal.

Design goals:
  - Every agent talks to the LLM exclusively through the Responsible-AI
    :class:`governance.governor.AIGovernor`, so safety, data protection,
    fairness and audit controls apply uniformly.
  - It works offline out of the box (via the mock LLM provider) and upgrades
    transparently to the Claude CLI or Anthropic/OpenAI APIs when configured.
  - The orchestration is explicit and inspectable, producing a structured
    transcript suitable for review by non-engineers.

This complements the platform's existing security-scanning swarm (the HAL
orchestrator); it is a general-purpose "AI team" you can point at any goal.
"""

from ai_team.agent import AgentRunResult, TeamAgent
from ai_team.coordinator import TeamCoordinator, TeamRunResult, Task
from ai_team.roles import ROLE_REGISTRY, RoleSpec, build_default_team

__all__ = [
    "TeamAgent",
    "AgentRunResult",
    "TeamCoordinator",
    "TeamRunResult",
    "Task",
    "RoleSpec",
    "ROLE_REGISTRY",
    "build_default_team",
]
