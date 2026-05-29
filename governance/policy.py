"""
Declarative Responsible AI policy.

A single object that captures the governance decisions an organization makes
about how LLMs may be used. The :class:`governance.governor.AIGovernor`
enforces it at runtime. Keeping policy as data (not scattered ``if`` statements)
makes it auditable and easy to show stakeholders.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import List, Optional


class DataSensitivity(str, Enum):
    """Sensitivity tier of the data being sent to a model."""

    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


@dataclass
class ResponsibleAIPolicy:
    """
    Runtime governance policy for LLM usage.

    Defaults are deliberately conservative ("secure by default").
    """

    # --- Data protection ---
    redact_pii: bool = True
    redact_ip_addresses: bool = False
    # Sensitivity tiers that are NOT permitted to leave for an external model.
    block_external_for: List[DataSensitivity] = field(
        default_factory=lambda: [DataSensitivity.RESTRICTED]
    )

    # --- Safety ---
    enforce_prompt_guard: bool = True
    block_on_prompt_injection: bool = True
    scan_output_for_injection: bool = True

    # --- Fairness ---
    enforce_bias_screen: bool = True
    block_on_bias: bool = False  # flag-and-log by default, don't hard-block

    # --- Accountability ---
    audit_enabled: bool = True
    # Whether the audit log may store raw (un-redacted) prompts. Default off.
    audit_store_raw_text: bool = False

    # --- Human-in-the-loop ---
    # Output risk levels that require human review before being acted upon.
    human_review_on: List[str] = field(default_factory=lambda: ["high"])

    # --- Cost / limits ---
    max_output_tokens: int = 2048
    allowed_models: Optional[List[str]] = None  # None = allow any

    def model_allowed(self, model: str) -> bool:
        if not self.allowed_models:
            return True
        return model in self.allowed_models

    def allows_external(self, sensitivity: DataSensitivity) -> bool:
        return sensitivity not in self.block_external_for

    def to_dict(self) -> dict:
        data = asdict(self)
        data["block_external_for"] = [s.value for s in self.block_external_for]
        return data

    @classmethod
    def from_dict(cls, data: dict) -> "ResponsibleAIPolicy":
        data = dict(data)
        if "block_external_for" in data:
            data["block_external_for"] = [
                DataSensitivity(s) if not isinstance(s, DataSensitivity) else s
                for s in data["block_external_for"]
            ]
        valid = {f for f in cls.__dataclass_fields__}  # type: ignore[attr-defined]
        return cls(**{k: v for k, v in data.items() if k in valid})

    @classmethod
    def strict(cls) -> "ResponsibleAIPolicy":
        """A maximally cautious policy for sensitive environments."""
        return cls(
            redact_ip_addresses=True,
            block_external_for=[
                DataSensitivity.CONFIDENTIAL,
                DataSensitivity.RESTRICTED,
            ],
            block_on_bias=True,
            human_review_on=["medium", "high"],
        )

    @classmethod
    def load(cls, path: str) -> "ResponsibleAIPolicy":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    def save(self, path: str) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=2), encoding="utf-8")
