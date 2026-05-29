"""
Prompt-injection and jailbreak guardrails.

Implements the "safety" pillar of Responsible AI by screening both inbound
prompts (to detect attempts to subvert the agent) and model outputs (to detect
leaked system instructions or unsafe content directives).

The scoring is heuristic and explainable: each matched signal contributes to a
risk score and is recorded, so decisions can be audited and tuned.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Pattern, Tuple


class PromptRiskLevel(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class PromptRisk:
    """Result of guarding a prompt or output."""

    level: PromptRiskLevel
    score: int
    signals: List[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.level == PromptRiskLevel.HIGH

    def to_dict(self) -> dict:
        return {
            "level": self.level.value,
            "score": self.score,
            "signals": self.signals,
            "blocked": self.blocked,
        }


# (weight, label, pattern) - higher weight = stronger signal.
_INJECTION_SIGNALS: List[Tuple[int, str, Pattern[str]]] = [
    (3, "ignore_previous_instructions", re.compile(r"(?i)ignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above)\s+(?:instructions|prompts?|rules)")),
    (3, "disregard_instructions", re.compile(r"(?i)disregard\s+(?:all\s+)?(?:previous|prior|the)\s+")),
    (3, "reveal_system_prompt", re.compile(r"(?i)(?:reveal|show|print|repeat|leak)\s+(?:your|the)\s+(?:system\s+)?(?:prompt|instructions)")),
    (3, "developer_mode", re.compile(r"(?i)(?:developer|dev|god|sudo|admin)\s+mode")),
    (3, "jailbreak", re.compile(r"(?i)\b(?:jailbreak|dan\s+mode|do\s+anything\s+now)\b")),
    (2, "act_as_unfiltered", re.compile(r"(?i)you\s+are\s+(?:now\s+)?(?:an?\s+)?(?:unfiltered|uncensored|unrestricted)")),
    (2, "pretend_no_rules", re.compile(r"(?i)pretend\s+(?:you\s+have\s+)?no\s+(?:rules|restrictions|guidelines)")),
    (2, "override_safety", re.compile(r"(?i)(?:bypass|override|disable|turn\s+off)\s+(?:your\s+)?(?:safety|guardrails|filters|moderation)")),
    (2, "new_instructions", re.compile(r"(?i)(?:new|updated)\s+(?:system\s+)?instructions\s*:")),
    (1, "role_switch", re.compile(r"(?i)from\s+now\s+on\s+you\s+(?:are|will)")),
    (1, "exfiltrate", re.compile(r"(?i)(?:send|post|exfiltrate|upload)\s+(?:the\s+)?(?:data|secrets|credentials)\s+to")),
]

# Signals that a model OUTPUT may have been compromised.
_OUTPUT_SIGNALS: List[Tuple[int, str, Pattern[str]]] = [
    (3, "leaked_system_prompt", re.compile(r"(?i)my\s+(?:system\s+)?(?:prompt|instructions)\s+(?:are|is|say)")),
    (2, "confirms_jailbreak", re.compile(r"(?i)(?:sure|ok|okay)[,!.]?\s+(?:i\s+(?:will|can)\s+)?ignore")),
    (2, "unrestricted_persona", re.compile(r"(?i)as\s+an?\s+(?:unfiltered|uncensored|unrestricted|dan)")),
]


class PromptGuard:
    """Heuristic guard for prompt-injection / jailbreak attempts."""

    def __init__(self, *, high_threshold: int = 3, medium_threshold: int = 2) -> None:
        self.high_threshold = high_threshold
        self.medium_threshold = medium_threshold

    def inspect_input(self, text: str) -> PromptRisk:
        return self._score(text, _INJECTION_SIGNALS)

    def inspect_output(self, text: str) -> PromptRisk:
        return self._score(text, _OUTPUT_SIGNALS)

    def _score(
        self, text: str, signals: List[Tuple[int, str, Pattern[str]]]
    ) -> PromptRisk:
        if not text:
            return PromptRisk(level=PromptRiskLevel.NONE, score=0)

        score = 0
        matched: List[str] = []
        for weight, label, pattern in signals:
            if pattern.search(text):
                score += weight
                matched.append(label)

        if score >= self.high_threshold:
            level = PromptRiskLevel.HIGH
        elif score >= self.medium_threshold:
            level = PromptRiskLevel.MEDIUM
        elif score > 0:
            level = PromptRiskLevel.LOW
        else:
            level = PromptRiskLevel.NONE

        return PromptRisk(level=level, score=score, signals=matched)
