"""
Convenience bridge so existing engines (AI triage, auto-fix, etc.) can make a
governed LLM call through the :class:`governance.governor.AIGovernor` using
whatever provider is configured (Anthropic, OpenAI, Claude CLI, ...).

The single entry point :func:`governed_complete` returns ``None`` when no real
backend is configured (i.e. the factory would only give the offline mock) or
when the request is blocked/failed, so callers can cleanly fall back to their
legacy path or local heuristics.
"""

from __future__ import annotations

from typing import Optional

from utils.logger import get_logger

from governance.governor import AIGovernor, GovernedResponse
from governance.policy import DataSensitivity, ResponsibleAIPolicy
from llm.factory import get_llm_provider

logger = get_logger(__name__)


async def governed_complete(
    prompt: str,
    *,
    system: Optional[str] = None,
    sensitivity: DataSensitivity = DataSensitivity.CONFIDENTIAL,
    actor: str = "codeshield",
    provider_name: Optional[str] = None,
    policy: Optional[ResponsibleAIPolicy] = None,
    max_tokens: Optional[int] = None,
) -> Optional[GovernedResponse]:
    """
    Run a governed single-turn LLM completion.

    Returns the :class:`GovernedResponse` on success, or ``None`` when no real
    LLM backend is available or the call is blocked/fails (so the caller can
    fall back gracefully).
    """
    provider = get_llm_provider(provider_name)
    # The mock provider returns canned text; never use it for real decisions.
    if provider.name == "mock":
        return None

    governor = AIGovernor(provider, policy=policy or ResponsibleAIPolicy(), actor=actor)
    kwargs = {}
    if max_tokens:
        kwargs["max_tokens"] = max_tokens
    try:
        return await governor.ask(
            prompt, system=system, sensitivity=sensitivity, **kwargs
        )
    except Exception as exc:  # GovernanceError or provider/network error
        logger.debug("Governed LLM call unavailable/blocked: %s", exc)
        return None


def governed_backend_available(provider_name: Optional[str] = None) -> bool:
    """True when a real (non-mock) LLM backend is configured and usable."""
    try:
        return get_llm_provider(provider_name).name != "mock"
    except Exception:
        return False
