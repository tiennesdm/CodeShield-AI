"""Tests for the agentic AI Team framework."""

import pytest

from ai_team import TeamCoordinator, build_default_team
from ai_team.agent import TeamAgent
from ai_team.cli import main as cli_main
from ai_team.roles import ROLE_REGISTRY, PLANNER
from governance.governor import AIGovernor
from governance.policy import DataSensitivity, ResponsibleAIPolicy
from llm.mock import MockLLMProvider


def test_default_team_has_five_roles():
    team = build_default_team()
    keys = [r.key for r in team]
    assert keys == ["planner", "researcher", "engineer", "reviewer", "rai_officer"]


def test_role_registry_complete():
    assert set(ROLE_REGISTRY) == {
        "planner", "researcher", "engineer", "reviewer", "rai_officer"
    }


async def test_single_agent_run():
    governor = AIGovernor(MockLLMProvider(), policy=ResponsibleAIPolicy())
    agent = TeamAgent(PLANNER, governor)
    result = await agent.run("Build a todo app", context={})
    assert result.status == "success"
    assert result.output
    assert result.role_key == "planner"


async def test_coordinator_runs_full_team():
    coordinator = TeamCoordinator(
        provider=MockLLMProvider(), policy=ResponsibleAIPolicy()
    )
    result = await coordinator.run("Design a caching layer")
    assert len(result.steps) == 5
    assert all(s.status == "success" for s in result.steps)
    assert result.final_output
    assert result.provider == "mock"
    assert result.duration_ms >= 0


async def test_coordinator_governance_rollup_redacts_pii():
    coordinator = TeamCoordinator(
        provider=MockLLMProvider(), policy=ResponsibleAIPolicy()
    )
    result = await coordinator.run("Email the plan to alice@example.com")
    roll = result.governance_rollup()
    # The email appears in the goal threaded into every step's prompt.
    assert roll["total_pii_redacted"] >= 1


async def test_coordinator_to_dict_serializable():
    coordinator = TeamCoordinator(
        provider=MockLLMProvider(), policy=ResponsibleAIPolicy()
    )
    result = await coordinator.run("Plan a migration")
    data = result.to_dict()
    assert "steps" in data and "governance" in data and "final_output" in data
    assert len(data["tasks"]) == 5


async def test_engineer_uses_confidential_sensitivity():
    # Engineer role is CONFIDENTIAL; default policy still allows it externally.
    assert ROLE_REGISTRY["engineer"].sensitivity == DataSensitivity.CONFIDENTIAL


async def test_strict_policy_blocks_confidential_roles():
    # Under the strict policy, CONFIDENTIAL data cannot leave -> engineer and
    # reviewer get blocked, but the team still completes without crashing.
    coordinator = TeamCoordinator(
        provider=MockLLMProvider(), policy=ResponsibleAIPolicy.strict()
    )
    result = await coordinator.run("Design something sensitive")
    statuses = {s.role_key: s.status for s in result.steps}
    assert statuses["engineer"] == "blocked"
    assert statuses["reviewer"] == "blocked"
    assert statuses["planner"] == "success"
    assert result.governance_rollup()["human_review_required"] is True


def test_cli_runs_offline(capsys):
    rc = cli_main(["--provider", "mock", "Plan a hello world service"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "AI TEAM RUN" in out
    assert "GOVERNANCE SUMMARY" in out


def test_cli_json_output(capsys):
    rc = cli_main(["--provider", "mock", "--json", "Plan a hello world service"])
    assert rc == 0
    import json

    data = json.loads(capsys.readouterr().out)
    assert data["provider"] == "mock"
    assert len(data["steps"]) == 5
