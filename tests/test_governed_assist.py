"""Tests for the governed-LLM bridge used by AI triage and auto-fix."""

from typing import Any, List

import pytest

from governance.assist import governed_backend_available, governed_complete
from llm import factory
from llm.base import LLMMessage, LLMProvider, LLMResponse, LLMRole, LLMUsage


class _StubProvider(LLMProvider):
    """A non-mock provider that echoes a fixed answer (for tests)."""

    name = "stub"
    default_model = "stub-1"
    last_prompt = ""

    async def is_available(self) -> bool:
        return True

    def is_available_sync(self) -> bool:
        return True

    async def _complete(self, messages: List[LLMMessage], **kwargs: Any) -> LLMResponse:
        user = next(
            (m.content for m in reversed(messages) if m.role == LLMRole.USER), ""
        )
        _StubProvider.last_prompt = user
        return LLMResponse(
            content='{"verdict": "true_positive", "reason": "ok"}',
            provider=self.name,
            model=self.model,
            usage=LLMUsage(prompt_tokens=5, completion_tokens=5),
        )


@pytest.fixture
def stub_registered(monkeypatch):
    monkeypatch.setitem(factory.PROVIDER_REGISTRY, "stub", _StubProvider)
    monkeypatch.setenv("CODESHIELD_LLM_PROVIDER", "stub")
    yield


async def test_governed_complete_uses_real_provider(stub_registered, tmp_path, monkeypatch):
    # Keep the audit log out of the repo working dir.
    from governance import audit
    monkeypatch.setattr(
        audit, "_audit_trail", audit.AuditTrail(str(tmp_path / "a.jsonl"))
    )
    resp = await governed_complete("Is this a real finding?", system="Reply JSON")
    assert resp is not None
    assert resp.content.startswith("{")
    assert resp.response.provider == "stub"


async def test_governed_complete_redacts_pii(stub_registered, tmp_path, monkeypatch):
    from governance import audit
    monkeypatch.setattr(
        audit, "_audit_trail", audit.AuditTrail(str(tmp_path / "a.jsonl"))
    )
    await governed_complete("contact me at secret@corp.com about this")
    # The provider must have received a redacted prompt (no raw email).
    assert "secret@corp.com" not in _StubProvider.last_prompt
    assert "REDACTED_EMAIL" in _StubProvider.last_prompt


async def test_governed_complete_returns_none_for_mock(monkeypatch):
    monkeypatch.setenv("CODESHIELD_LLM_PROVIDER", "mock")
    resp = await governed_complete("anything")
    assert resp is None


def test_backend_available_flag(stub_registered):
    assert governed_backend_available() is True


def test_backend_unavailable_with_mock(monkeypatch):
    monkeypatch.setenv("CODESHIELD_LLM_PROVIDER", "mock")
    assert governed_backend_available() is False


async def test_ai_triage_uses_governed_path(stub_registered, tmp_path, monkeypatch):
    from governance import audit
    monkeypatch.setattr(
        audit, "_audit_trail", audit.AuditTrail(str(tmp_path / "a.jsonl"))
    )
    from ai_triage import AITriageEngine

    engine = AITriageEngine()
    content = await engine._llm_complete("prompt", "system", max_tokens=50)
    assert content is not None
    assert "verdict" in content
