"""
The AI Governor: a Responsible-AI enforcement wrapper around any LLM provider.

This is the single choke point through which agents should make LLM calls. It
composes the data-protection, safety, fairness, and accountability controls and
applies them in a defined order:

  1. Policy / model allow-list check.
  2. Data-sensitivity gate (block restricted data from leaving).
  3. Prompt-injection guard on the input.
  4. PII/secret redaction of the input.
  5. The underlying LLM call.
  6. Prompt-injection + bias screening of the output.
  7. Audit logging of the whole decision (hash-chained).

The result is a :class:`GovernedResponse` that carries the model output plus a
full governance trace, so callers (and a director reviewing the system) can see
exactly what controls fired.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List, Optional

from utils.logger import get_logger

from governance.audit import AuditTrail, get_audit_trail
from governance.bias import BiasReport, BiasScanner
from governance.pii import PIIRedactor, RedactionResult
from governance.policy import DataSensitivity, ResponsibleAIPolicy
from governance.prompt_guard import PromptGuard, PromptRisk, PromptRiskLevel
from llm.base import LLMMessage, LLMProvider, LLMResponse, LLMRole

logger = get_logger(__name__)


class GovernanceError(Exception):
    """Raised when a request is blocked by Responsible AI policy."""

    def __init__(self, message: str, *, reason: str, trace: Optional[dict] = None):
        super().__init__(message)
        self.reason = reason
        self.trace = trace or {}


@dataclass
class GovernanceTrace:
    """Record of which controls fired during a governed call."""

    input_prompt_risk: Optional[dict] = None
    output_prompt_risk: Optional[dict] = None
    pii_redacted: int = 0
    pii_types: dict = field(default_factory=dict)
    bias: Optional[dict] = None
    requires_human_review: bool = False
    decision: str = "allowed"
    audit_record_id: Optional[str] = None

    def to_dict(self) -> dict:
        return {
            "input_prompt_risk": self.input_prompt_risk,
            "output_prompt_risk": self.output_prompt_risk,
            "pii_redacted": self.pii_redacted,
            "pii_types": self.pii_types,
            "bias": self.bias,
            "requires_human_review": self.requires_human_review,
            "decision": self.decision,
            "audit_record_id": self.audit_record_id,
        }


@dataclass
class GovernedResponse:
    """An LLM response plus its governance trace."""

    response: LLMResponse
    trace: GovernanceTrace

    @property
    def content(self) -> str:
        return self.response.content

    def to_dict(self) -> dict:
        return {
            "response": self.response.to_dict(),
            "governance": self.trace.to_dict(),
        }


class AIGovernor:
    """Responsible-AI enforcement wrapper around an :class:`LLMProvider`."""

    def __init__(
        self,
        provider: LLMProvider,
        *,
        policy: Optional[ResponsibleAIPolicy] = None,
        audit_trail: Optional[AuditTrail] = None,
        actor: str = "system",
    ) -> None:
        self.provider = provider
        self.policy = policy or ResponsibleAIPolicy()
        self.audit = audit_trail or get_audit_trail()
        self.actor = actor
        self._redactor = PIIRedactor(redact_ip=self.policy.redact_ip_addresses)
        self._guard = PromptGuard()
        self._bias = BiasScanner()

    async def complete(
        self,
        messages: List[LLMMessage],
        *,
        sensitivity: DataSensitivity = DataSensitivity.INTERNAL,
        actor: Optional[str] = None,
        **kwargs: Any,
    ) -> GovernedResponse:
        """Run a governed chat completion. See module docstring for the order."""
        actor = actor or self.actor
        trace = GovernanceTrace()
        model = kwargs.get("model", self.provider.model)

        # 1. Model allow-list.
        if not self.policy.model_allowed(model):
            self._audit("blocked", actor, model, "model_not_allowed", trace)
            raise GovernanceError(
                f"Model '{model}' is not on the allow-list",
                reason="model_not_allowed",
                trace=trace.to_dict(),
            )

        # 2. Data-sensitivity gate.
        if not self.policy.allows_external(sensitivity):
            trace.decision = "blocked"
            self._audit("blocked", actor, model, "data_sensitivity", trace,
                        sensitivity=sensitivity.value)
            raise GovernanceError(
                f"Data classified '{sensitivity.value}' may not be sent to an "
                f"external model under the current policy",
                reason="data_sensitivity",
                trace=trace.to_dict(),
            )

        # 3. Prompt-injection guard on combined user input.
        joined_input = "\n".join(
            m.content for m in messages if m.role != LLMRole.SYSTEM
        )
        if self.policy.enforce_prompt_guard:
            risk = self._guard.inspect_input(joined_input)
            trace.input_prompt_risk = risk.to_dict()
            if self.policy.block_on_prompt_injection and risk.blocked:
                trace.decision = "blocked"
                self._audit("blocked", actor, model, "prompt_injection", trace)
                raise GovernanceError(
                    "Input blocked: prompt-injection attempt detected",
                    reason="prompt_injection",
                    trace=trace.to_dict(),
                )

        # 4. PII / secret redaction.
        governed_messages = messages
        if self.policy.redact_pii:
            governed_messages, redactions = self._redact_messages(messages)
            total = sum(len(r.findings) for r in redactions)
            trace.pii_redacted = total
            merged: dict = {}
            for r in redactions:
                for k, v in r.counts_by_type().items():
                    merged[k] = merged.get(k, 0) + v
            trace.pii_types = merged

        # 5. Underlying LLM call. Cap output tokens per policy.
        kwargs.setdefault("max_tokens", self.policy.max_output_tokens)
        response = await self.provider.complete(governed_messages, **kwargs)

        # 6. Output screening.
        if self.policy.scan_output_for_injection:
            out_risk = self._guard.inspect_output(response.content)
            trace.output_prompt_risk = out_risk.to_dict()
            if out_risk.level.value in self.policy.human_review_on:
                trace.requires_human_review = True

        if self.policy.enforce_bias_screen:
            bias_report = self._bias.scan(response.content)
            trace.bias = bias_report.to_dict()
            if bias_report.flagged:
                if self.policy.block_on_bias:
                    trace.decision = "blocked"
                    self._audit("blocked", actor, model, "bias_output", trace)
                    raise GovernanceError(
                        "Output blocked: fairness/bias screen flagged the response",
                        reason="bias_output",
                        trace=trace.to_dict(),
                    )
                trace.decision = "flagged"
            if bias_report.severity.value in self.policy.human_review_on:
                trace.requires_human_review = True

        # 7. Audit + return.
        decision = trace.decision if trace.decision != "allowed" else (
            "flagged" if trace.requires_human_review else "allowed"
        )
        trace.decision = decision
        self._audit(decision, actor, model, "completed", trace,
                    sensitivity=sensitivity.value,
                    latency_ms=response.latency_ms,
                    total_tokens=response.usage.total_tokens)
        return GovernedResponse(response=response, trace=trace)

    async def ask(
        self,
        prompt: str,
        *,
        system: Optional[str] = None,
        sensitivity: DataSensitivity = DataSensitivity.INTERNAL,
        **kwargs: Any,
    ) -> GovernedResponse:
        """Convenience single-turn governed prompt."""
        messages: List[LLMMessage] = []
        if system:
            messages.append(LLMMessage.system(system))
        messages.append(LLMMessage.user(prompt))
        return await self.complete(messages, sensitivity=sensitivity, **kwargs)

    def _redact_messages(
        self, messages: List[LLMMessage]
    ) -> tuple[List[LLMMessage], List[RedactionResult]]:
        new_messages: List[LLMMessage] = []
        redactions: List[RedactionResult] = []
        for m in messages:
            result = self._redactor.redact(m.content)
            redactions.append(result)
            new_messages.append(LLMMessage(role=m.role, content=result.redacted_text))
        return new_messages, redactions

    def _audit(
        self,
        decision: str,
        actor: str,
        model: str,
        event: str,
        trace: GovernanceTrace,
        **details: Any,
    ) -> None:
        if not self.policy.audit_enabled:
            return
        payload = dict(details)
        payload.update(
            {
                "pii_redacted": trace.pii_redacted,
                "pii_types": trace.pii_types,
                "input_prompt_risk": trace.input_prompt_risk,
                "output_prompt_risk": trace.output_prompt_risk,
                "bias": trace.bias,
                "requires_human_review": trace.requires_human_review,
            }
        )
        rec = self.audit.record(
            event,
            actor=actor,
            provider=self.provider.name,
            model=model,
            decision=decision,
            details=payload,
        )
        trace.audit_record_id = rec.record_id
