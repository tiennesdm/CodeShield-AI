"""
Bias, toxicity and fairness screening for model outputs.

Implements the "fairness / bias" pillar of Responsible AI. This is a
lightweight, lexicon-and-pattern based screen designed to flag obviously
problematic output (slurs, demographic generalizations, toxic language) for
review. It is explainable and dependency-free; for production use it should be
complemented by a dedicated content-moderation model.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Pattern, Tuple


class BiasSeverity(str, Enum):
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class BiasFinding:
    """A single fairness/toxicity signal detected in text."""

    category: str
    severity: BiasSeverity
    excerpt: str

    def to_dict(self) -> dict:
        return {
            "category": self.category,
            "severity": self.severity.value,
            "excerpt": self.excerpt,
        }


@dataclass
class BiasReport:
    """Aggregated fairness assessment of a piece of text."""

    findings: List[BiasFinding] = field(default_factory=list)

    @property
    def severity(self) -> BiasSeverity:
        order = {
            BiasSeverity.NONE: 0,
            BiasSeverity.LOW: 1,
            BiasSeverity.MEDIUM: 2,
            BiasSeverity.HIGH: 3,
        }
        worst = BiasSeverity.NONE
        for f in self.findings:
            if order[f.severity] > order[worst]:
                worst = f.severity
        return worst

    @property
    def flagged(self) -> bool:
        return self.severity in (BiasSeverity.MEDIUM, BiasSeverity.HIGH)

    def to_dict(self) -> dict:
        return {
            "severity": self.severity.value,
            "flagged": self.flagged,
            "findings": [f.to_dict() for f in self.findings],
        }


# Demographic descriptors used to detect over-generalizations.
_GROUP_TERMS = (
    r"men|women|males?|females?|whites?|blacks?|asians?|hispanics?|latinos?|"
    r"jews?|muslims?|christians?|immigrants?|foreigners?|gays?|lesbians?|"
    r"old\s+people|young\s+people|the\s+elderly|teenagers?"
)

# (category, severity, pattern)
_SIGNALS: List[Tuple[str, BiasSeverity, Pattern[str]]] = [
    (
        "generalization",
        BiasSeverity.MEDIUM,
        re.compile(rf"(?i)\b(?:all|every|most|typical)\s+(?:{_GROUP_TERMS})\s+(?:are|can'?t|cannot|never|always)\b"),
    ),
    (
        "inferiority_superiority",
        BiasSeverity.HIGH,
        re.compile(rf"(?i)\b(?:{_GROUP_TERMS})\s+are\s+(?:inferior|superior|less\s+intelligent|smarter|dumber|worse|better)\b"),
    ),
    (
        "toxic_language",
        BiasSeverity.HIGH,
        re.compile(r"(?i)\b(?:idiot|stupid|moron|worthless|disgusting|hate\s+you|kill\s+yourself)\b"),
    ),
    (
        "exclusionary",
        BiasSeverity.MEDIUM,
        re.compile(rf"(?i)\b(?:{_GROUP_TERMS})\s+(?:should\s+not|shouldn'?t|don'?t\s+belong|aren'?t\s+welcome)\b"),
    ),
    (
        "stereotype_role",
        BiasSeverity.LOW,
        re.compile(r"(?i)\b(?:women\s+belong\s+in|men\s+should\s+be|a\s+real\s+man)\b"),
    ),
]


class BiasScanner:
    """Heuristic fairness/toxicity screen."""

    def scan(self, text: str) -> BiasReport:
        report = BiasReport()
        if not text:
            return report
        for category, severity, pattern in _SIGNALS:
            match = pattern.search(text)
            if match:
                excerpt = match.group(0).strip()
                report.findings.append(
                    BiasFinding(category=category, severity=severity, excerpt=excerpt)
                )
        return report
