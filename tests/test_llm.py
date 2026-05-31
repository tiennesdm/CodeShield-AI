"""Tests for the LLM provider abstraction layer."""

import json

import pytest

from llm import LLMMessage, LLMRole, MockLLMProvider, available_providers, get_llm_provider
from llm.base import LLMError, LLMProvider, LLMUsage
from llm.claude_cli import ClaudeCLIProvider


async def test_mock_provider_is_available():
    provider = MockLLMProvider()
    assert await provider.is_available() is True


async def test_mock_provider_ask_returns_response():
    provider = MockLLMProvider()
    resp = await provider.ask("What is 2 + 2?")
    assert resp.provider == "mock"
    assert resp.content
    assert resp.usage.total_tokens > 0
    assert resp.is_fallback is True


async def test_mock_provider_json_mode():
    provider = MockLLMProvider()
    resp = await provider.ask("anything", system="Reply in JSON only")
    parsed = json.loads(resp.content)
    assert parsed["source"] == "MockLLMProvider"


async def test_mock_provider_is_deterministic():
    provider = MockLLMProvider()
    a = await provider.ask("same prompt")
    b = await provider.ask("same prompt")
    assert a.content == b.content


async def test_complete_requires_messages():
    provider = MockLLMProvider()
    with pytest.raises(LLMError):
        await provider.complete([])


async def test_message_helpers():
    assert LLMMessage.system("x").role == LLMRole.SYSTEM
    assert LLMMessage.user("x").role == LLMRole.USER
    assert LLMMessage.assistant("x").role == LLMRole.ASSISTANT
    assert LLMMessage.user("hi").to_dict() == {"role": "user", "content": "hi"}


def test_usage_totals():
    usage = LLMUsage(prompt_tokens=10, completion_tokens=5)
    assert usage.total_tokens == 15
    assert usage.to_dict()["total_tokens"] == 15


def test_available_providers():
    names = available_providers()
    assert {"claude_cli", "anthropic_api", "openai_api", "ollama", "mock"} <= set(names)


def test_factory_falls_back_to_mock(monkeypatch):
    # No real backend configured -> mock.
    monkeypatch.delenv("CODESHIELD_LLM_PROVIDER", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = get_llm_provider("mock")
    assert isinstance(provider, LLMProvider)
    assert provider.name == "mock"


def test_factory_unknown_provider_falls_back(monkeypatch):
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    provider = get_llm_provider("does_not_exist")
    # Should still return a usable provider (mock at worst).
    assert provider is not None


async def test_claude_cli_unavailable_without_binary(monkeypatch):
    provider = ClaudeCLIProvider(binary="definitely-not-a-real-binary-xyz")
    assert await provider.is_available() is False
    with pytest.raises(LLMError):
        await provider.ask("hello")


def test_claude_cli_flatten_messages():
    msgs = [
        LLMMessage.system("be terse"),
        LLMMessage.user("hi"),
        LLMMessage.assistant("hello"),
        LLMMessage.user("bye"),
    ]
    system, convo = ClaudeCLIProvider._flatten_messages(msgs)
    assert system == "be terse"
    assert "User: hi" in convo
    assert "Assistant: hello" in convo
    assert "User: bye" in convo


def test_claude_cli_parse_json_output():
    provider = ClaudeCLIProvider()
    out = json.dumps(
        {"result": "the answer", "usage": {"input_tokens": 3, "output_tokens": 2},
         "stop_reason": "end_turn"}
    )
    resp = provider._parse_output(out, "claude-x", 100)
    assert resp.content == "the answer"
    assert resp.usage.prompt_tokens == 3
    assert resp.usage.completion_tokens == 2
    assert resp.finish_reason == "end_turn"


def test_claude_cli_parse_plaintext_output():
    provider = ClaudeCLIProvider()
    resp = provider._parse_output("just text", "claude-x", 100)
    assert resp.content == "just text"
    assert resp.usage.completion_tokens > 0


from unittest.mock import AsyncMock, MagicMock, patch
from llm.ollama import OllamaProvider


async def test_ollama_provider_availability(monkeypatch):
    provider = OllamaProvider()
    
    with patch.object(provider, "_check_ollama_port", return_value=True):
        assert await provider.is_available() is True
        assert provider.is_available_sync() is True

    with patch.object(provider, "_check_ollama_port", return_value=False):
        assert await provider.is_available() is False
        assert provider.is_available_sync() is False


async def test_ollama_provider_complete():
    provider = OllamaProvider()
    
    mock_resp_tags = MagicMock()
    mock_resp_tags.status_code = 200
    mock_resp_tags.json.return_value = {
        "models": [
            {"name": "qwen2.5:0.5b"},
            {"name": "llama3:latest"}
        ]
    }
    
    mock_resp_chat = MagicMock()
    mock_resp_chat.status_code = 200
    mock_resp_chat.json.return_value = {
        "message": {"content": "Hello from local Ollama"},
        "prompt_eval_count": 10,
        "eval_count": 5
    }
    
    async_client_mock = AsyncMock()
    async_client_mock.get.return_value = mock_resp_tags
    async_client_mock.post.return_value = mock_resp_chat
    
    # Enter the async context manager mock
    async_client_mock.__aenter__.return_value = async_client_mock
    async_client_mock.__aexit__.return_value = None
    
    with patch("httpx.AsyncClient", return_value=async_client_mock):
        resp = await provider.ask("Hello", system="Act like a helper")
        assert resp.content == "Hello from local Ollama"
        assert resp.provider == "ollama"
        assert resp.model == "qwen2.5:0.5b"
        assert resp.usage.prompt_tokens == 10
        assert resp.usage.completion_tokens == 5

        async_client_mock.post.assert_called_once()
        args, kwargs = async_client_mock.post.call_args
        assert kwargs["json"]["model"] == "qwen2.5:0.5b"
        assert "Act like a helper" in kwargs["json"]["messages"][0]["content"]

