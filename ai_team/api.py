"""
FastAPI router exposing the AI Team and Responsible AI governance.

Mounted by ``main.py`` under the ``/api/ai-team`` and ``/api/governance``
prefixes. Designed to be safe to import even if optional dependencies are
missing -- it only depends on the in-repo ``llm``, ``governance`` and
``ai_team`` packages plus pydantic/fastapi (already required).
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from ai_team.coordinator import TeamCoordinator
from ai_team.roles import ROLE_REGISTRY
from governance.audit import get_audit_trail
from governance.bias import BiasScanner
from governance.governor import AIGovernor
from governance.pii import PIIRedactor
from governance.policy import DataSensitivity, ResponsibleAIPolicy
from governance.prompt_guard import PromptGuard
from llm.base import LLMMessage
from llm.factory import available_providers, get_llm_provider

router = APIRouter(tags=["AI Team & Responsible AI"])


# --------------------------------------------------------------------------- #
# Request / response models
# --------------------------------------------------------------------------- #
class TeamRunRequest(BaseModel):
    goal: str = Field(..., min_length=1, description="High-level goal for the team")
    provider: Optional[str] = Field(None, description="LLM provider name")
    model: Optional[str] = Field(None, description="Model override")
    strict: bool = Field(False, description="Use the strict Responsible AI policy")


class GovernedAskRequest(BaseModel):
    prompt: str = Field(..., min_length=1)
    system: Optional[str] = None
    provider: Optional[str] = None
    model: Optional[str] = None
    sensitivity: str = Field("internal", description="public|internal|confidential|restricted")
    strict: bool = False


class InspectRequest(BaseModel):
    text: str = Field(..., min_length=1)


# --------------------------------------------------------------------------- #
# AI Team endpoints
# --------------------------------------------------------------------------- #
@router.get("/api/ai-team/info")
async def ai_team_info() -> Dict[str, Any]:
    """Describe the team composition and available providers."""
    return {
        "providers": available_providers(),
        "roles": [
            {
                "key": r.key,
                "title": r.title,
                "sensitivity": r.sensitivity.value,
                "depends_on": list(r.depends_on),
            }
            for r in ROLE_REGISTRY.values()
        ],
    }


@router.post("/api/ai-team/run")
async def run_ai_team(req: TeamRunRequest) -> Dict[str, Any]:
    """Run the full governed AI team against a goal."""
    policy = ResponsibleAIPolicy.strict() if req.strict else ResponsibleAIPolicy()
    coordinator = TeamCoordinator(provider_name=req.provider, policy=policy)
    if req.model:
        coordinator.provider.model = req.model
    result = await coordinator.run(req.goal)
    return result.to_dict()


# --------------------------------------------------------------------------- #
# Governance endpoints
# --------------------------------------------------------------------------- #
@router.post("/api/governance/ask")
async def governed_ask(req: GovernedAskRequest) -> Dict[str, Any]:
    """Run a single governed LLM completion with full Responsible AI controls."""
    try:
        sensitivity = DataSensitivity(req.sensitivity.lower())
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid sensitivity: {exc}")

    policy = ResponsibleAIPolicy.strict() if req.strict else ResponsibleAIPolicy()
    provider = get_llm_provider(req.provider, model=req.model)
    governor = AIGovernor(provider, policy=policy, actor="api")

    try:
        governed = await governor.ask(
            req.prompt, system=req.system, sensitivity=sensitivity
        )
    except Exception as exc:
        # GovernanceError carries a structured reason/trace.
        reason = getattr(exc, "reason", "error")
        raise HTTPException(
            status_code=403 if reason != "error" else 500,
            detail={"reason": reason, "message": str(exc),
                    "trace": getattr(exc, "trace", {})},
        )
    return governed.to_dict()


@router.post("/api/governance/redact")
async def redact_text(req: InspectRequest) -> Dict[str, Any]:
    """Detect and redact PII/secrets from text."""
    result = PIIRedactor().redact(req.text)
    return {
        "redacted_text": result.redacted_text,
        "has_pii": result.has_pii,
        "counts_by_type": result.counts_by_type(),
        "findings": [f.to_dict() for f in result.findings],
    }


@router.post("/api/governance/inspect-prompt")
async def inspect_prompt(req: InspectRequest) -> Dict[str, Any]:
    """Screen text for prompt-injection / jailbreak signals."""
    return PromptGuard().inspect_input(req.text).to_dict()


@router.post("/api/governance/bias-scan")
async def bias_scan(req: InspectRequest) -> Dict[str, Any]:
    """Screen text for bias / toxicity / fairness signals."""
    return BiasScanner().scan(req.text).to_dict()


@router.get("/api/governance/policy")
async def get_policy(strict: bool = False) -> Dict[str, Any]:
    """Return the active Responsible AI policy (default or strict)."""
    policy = ResponsibleAIPolicy.strict() if strict else ResponsibleAIPolicy()
    return policy.to_dict()


@router.get("/api/governance/audit")
async def get_audit(limit: int = 100) -> Dict[str, Any]:
    """Return recent audit records and chain-integrity status."""
    trail = get_audit_trail()
    records = trail.read_all()
    return {
        "total": len(records),
        "chain_intact": trail.verify(),
        "records": records[-max(0, limit):],
    }
