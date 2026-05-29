"""
CodeShield AI - Responsible AI Governance Layer.

A safety and governance gateway that every LLM interaction in the platform can
route through. It operationalizes Responsible AI principles so they are
enforced in code rather than living only in a policy document:

  - Data protection: PII/secret detection and redaction before prompts leave
    the trust boundary (:mod:`governance.pii`).
  - Safety: prompt-injection / jailbreak guardrails on inputs and outputs
    (:mod:`governance.prompt_guard`).
  - Fairness: bias / toxicity screening of model outputs
    (:mod:`governance.bias`).
  - Accountability: an append-only audit trail of every governed call
    (:mod:`governance.audit`).
  - Policy: a single declarative policy object (:mod:`governance.policy`).
  - Enforcement: :class:`governance.governor.AIGovernor` wraps any
    :class:`llm.base.LLMProvider` and applies all of the above.
"""

from governance.assist import governed_backend_available, governed_complete
from governance.audit import AuditTrail, get_audit_trail
from governance.bias import BiasFinding, BiasScanner
from governance.governor import AIGovernor, GovernedResponse, GovernanceError
from governance.pii import PIIFinding, PIIRedactor
from governance.policy import DataSensitivity, ResponsibleAIPolicy
from governance.prompt_guard import PromptGuard, PromptRisk

__all__ = [
    "AIGovernor",
    "GovernedResponse",
    "GovernanceError",
    "ResponsibleAIPolicy",
    "DataSensitivity",
    "PIIRedactor",
    "PIIFinding",
    "PromptGuard",
    "PromptRisk",
    "BiasScanner",
    "BiasFinding",
    "AuditTrail",
    "get_audit_trail",
    "governed_complete",
    "governed_backend_available",
]
