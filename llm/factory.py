"""
Provider factory and selection logic.

``get_llm_provider`` resolves a provider from an explicit name, then from the
``CODESHIELD_LLM_PROVIDER`` environment variable, and finally via an
auto-detection order. If the requested/selected provider is not actually
usable (missing binary, missing key, missing dependency), it falls back to the
mock provider so callers never hit a hard failure simply because a backend is
unconfigured.
"""

from __future__ import annotations

import os
from typing import Dict, List, Optional, Type

from utils.logger import get_logger

from llm.anthropic_api import AnthropicAPIProvider
from llm.base import LLMProvider
from llm.claude_cli import ClaudeCLIProvider
from llm.mock import MockLLMProvider
from llm.openai_api import OpenAIAPIProvider

logger = get_logger(__name__)

PROVIDER_REGISTRY: Dict[str, Type[LLMProvider]] = {
    "claude_cli": ClaudeCLIProvider,
    "anthropic_api": AnthropicAPIProvider,
    "openai_api": OpenAIAPIProvider,
    "mock": MockLLMProvider,
}

# Order used when no provider is explicitly requested.
AUTODETECT_ORDER: List[str] = ["claude_cli", "anthropic_api", "openai_api", "mock"]


def get_llm_provider(
    name: Optional[str] = None,
    *,
    model: Optional[str] = None,
    check_availability: bool = True,
    **kwargs,
) -> LLMProvider:
    """
    Resolve and instantiate an LLM provider.

    Args:
        name: Explicit provider name. Falls back to the
            ``CODESHIELD_LLM_PROVIDER`` env var, then auto-detection.
        model: Optional model override passed to the provider.
        check_availability: When True, verify the provider is usable and fall
            back to the next candidate (ultimately ``mock``) if not.
        **kwargs: Extra keyword args forwarded to the provider constructor.

    Returns:
        A ready-to-use :class:`LLMProvider`.
    """
    requested = name or os.environ.get("CODESHIELD_LLM_PROVIDER")

    if requested:
        requested = requested.lower()
        candidates = [requested] if requested in PROVIDER_REGISTRY else []
        if not candidates:
            logger.warning(
                "Unknown LLM provider '%s'; falling back to auto-detect", requested
            )
            candidates = list(AUTODETECT_ORDER)
        else:
            # Always keep mock as a final safety net.
            candidates += [c for c in AUTODETECT_ORDER if c not in candidates]
    else:
        candidates = list(AUTODETECT_ORDER)

    for candidate in candidates:
        provider_cls = PROVIDER_REGISTRY[candidate]
        provider = provider_cls(model=model, **kwargs)

        if not check_availability or candidate == "mock":
            if candidate != "mock" or not check_availability:
                logger.info("Using LLM provider: %s", candidate)
            else:
                logger.info("Falling back to mock LLM provider")
            return provider

        if provider.is_available_sync():
            logger.info("Using LLM provider: %s", candidate)
            return provider
        logger.debug("Provider '%s' unavailable, trying next", candidate)

    logger.info("Falling back to mock LLM provider")
    return MockLLMProvider(model=model)


def available_providers() -> List[str]:
    """Return the list of registered provider names."""
    return list(PROVIDER_REGISTRY.keys())
