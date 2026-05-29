"""
Role definitions for the AI Team.

Each :class:`RoleSpec` is a small, declarative description of one team member:
its identity, the system prompt that shapes its behaviour, and the data
sensitivity tier it operates at. Keeping roles as data makes the team easy to
reconfigure and easy to explain to stakeholders.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List

from governance.policy import DataSensitivity


@dataclass(frozen=True)
class RoleSpec:
    """Declarative specification of a team role."""

    key: str
    title: str
    system_prompt: str
    sensitivity: DataSensitivity = DataSensitivity.INTERNAL
    # Roles this one depends on (their output is fed in as context).
    depends_on: tuple = ()


PLANNER = RoleSpec(
    key="planner",
    title="Planner",
    system_prompt=(
        "You are the Planner of an AI team. Given a high-level goal, break it "
        "into a short, ordered list of concrete, actionable tasks (max 6). Be "
        "specific and avoid fluff. Output a numbered list only."
    ),
    sensitivity=DataSensitivity.INTERNAL,
)

RESEARCHER = RoleSpec(
    key="researcher",
    title="Researcher / Analyst",
    system_prompt=(
        "You are the Researcher of an AI team. Given a goal and a plan, gather "
        "the key facts, constraints, risks and unknowns relevant to executing "
        "it. Be concise and organize findings under clear headings."
    ),
    sensitivity=DataSensitivity.INTERNAL,
    depends_on=("planner",),
)

ENGINEER = RoleSpec(
    key="engineer",
    title="Engineer",
    system_prompt=(
        "You are the Engineer of an AI team. Using the plan and research, "
        "produce a concrete technical solution or implementation outline. "
        "Prefer pragmatic, well-structured designs. Note any assumptions."
    ),
    sensitivity=DataSensitivity.CONFIDENTIAL,
    depends_on=("planner", "researcher"),
)

REVIEWER = RoleSpec(
    key="reviewer",
    title="Reviewer / QA",
    system_prompt=(
        "You are the Reviewer of an AI team. Critically assess the proposed "
        "solution for correctness, completeness, security and maintainability. "
        "List concrete issues and suggested improvements, prioritized."
    ),
    sensitivity=DataSensitivity.CONFIDENTIAL,
    depends_on=("engineer",),
)

RAI_OFFICER = RoleSpec(
    key="rai_officer",
    title="Responsible AI Officer",
    system_prompt=(
        "You are the Responsible AI Officer of an AI team. Review the goal and "
        "the team's output for governance, bias/fairness, safety, privacy and "
        "data-handling risks. Provide a short risk assessment and clear, "
        "actionable mitigations. Flag anything needing human sign-off."
    ),
    sensitivity=DataSensitivity.INTERNAL,
    depends_on=("engineer", "reviewer"),
)


ROLE_REGISTRY: Dict[str, RoleSpec] = {
    r.key: r
    for r in (PLANNER, RESEARCHER, ENGINEER, REVIEWER, RAI_OFFICER)
}


def build_default_team() -> List[RoleSpec]:
    """Return the default, ordered AI team."""
    return [PLANNER, RESEARCHER, ENGINEER, REVIEWER, RAI_OFFICER]
