"""
Command-line entrypoint for the AI Team.

Run a whole governed AI team against a goal straight from the terminal -- the
hands-on, "experiment with the Claude CLI / agentic setup" workflow described
in the project goals. Works offline with the mock provider and upgrades to the
Claude CLI or an API backend automatically when configured.

Examples:
    python -m ai_team.cli "Design a rate limiter for our public API"
    python -m ai_team.cli --provider claude_cli "Audit our login flow"
    python -m ai_team.cli --strict --json "Plan a data migration" > run.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from typing import Optional

from ai_team.coordinator import TeamCoordinator
from governance.policy import ResponsibleAIPolicy
from llm.factory import available_providers


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai_team",
        description="Run a governed, role-based AI team against a goal.",
    )
    parser.add_argument("goal", nargs="+", help="The high-level goal for the team")
    parser.add_argument(
        "--provider",
        choices=available_providers(),
        default=None,
        help="LLM provider (default: auto-detect, falls back to mock)",
    )
    parser.add_argument("--model", default=None, help="Model override")
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Use the strict Responsible AI policy",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Emit the full run as JSON",
    )
    return parser


def _render_human(result) -> str:
    lines = []
    lines.append("=" * 70)
    lines.append(f"AI TEAM RUN  |  provider={result.provider}  model={result.model}")
    lines.append(f"GOAL: {result.goal}")
    lines.append("=" * 70)
    for step in result.steps:
        flag = " [NEEDS HUMAN REVIEW]" if step.requires_human_review else ""
        lines.append(f"\n### {step.title} ({step.status}){flag}")
        if step.error:
            lines.append(f"  error: {step.error}")
        if step.output:
            lines.append(step.output)
    roll = result.governance_rollup()
    lines.append("\n" + "-" * 70)
    lines.append("GOVERNANCE SUMMARY")
    lines.append(f"  PII redacted across run : {roll['total_pii_redacted']}")
    lines.append(f"  Roles needing review    : {roll['roles_requiring_human_review'] or 'none'}")
    lines.append(f"  Roles blocked           : {roll['roles_blocked'] or 'none'}")
    lines.append(f"  Human review required   : {roll['human_review_required']}")
    lines.append(f"  Duration                : {result.duration_ms} ms")
    return "\n".join(lines)


async def _run(goal: str, provider: Optional[str], model: Optional[str], strict: bool):
    policy = ResponsibleAIPolicy.strict() if strict else ResponsibleAIPolicy()
    coordinator = TeamCoordinator(
        provider_name=provider,
        policy=policy,
    )
    if model:
        coordinator.provider.model = model
    return await coordinator.run(goal)


def main(argv: Optional[list] = None) -> int:
    args = _build_parser().parse_args(argv)
    goal = " ".join(args.goal)
    result = asyncio.run(_run(goal, args.provider, args.model, args.strict))

    if args.as_json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(_render_human(result))
    return 0


if __name__ == "__main__":
    sys.exit(main())
