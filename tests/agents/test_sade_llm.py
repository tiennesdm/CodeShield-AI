"""
Tests for Sade LLM Security Agent.
"""

import pytest

from agents.results import ScanContext
from agents.sade_llm import SadeLLMSecurityAgent


@pytest.fixture
def sade_agent():
    return SadeLLMSecurityAgent()


@pytest.fixture
def llm_context(tmp_path):
    # Create files with AI-generated code patterns
    py_file = tmp_path / "app.py"
    py_file.write_text('''
# This function is used to handle user authentication
# Import necessary libraries
import openai

API_KEY = "sk-abc123openaikeyhere456"

def get_ai_response(user_input):
    # TODO: Add error handling
    client = openai.OpenAI(api_key=API_KEY)
    response = client.chat.completions.create(
        model="gpt-4",
        messages=[
            {"role": "system", "content": "You are helpful."},
            {"role": "user", "content": user_input}
        ]
    )
    # Use the response directly
    result = response.choices[0].message.content
    return result

def insecure_render(user_input):
    result = get_ai_response(user_input)
    # LLM02: Insecure output handling
    return f"<div>{result}</div>"

# AI-generated permissive CORS
CORS_ORIGIN = "*"

# DEBUG mode
DEBUG = True
SECRET_KEY = "change-me-in-production"
''')
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("""
FROM python:latest
RUN pip install -r requirements.txt
COPY . /app
CMD ["python", "app.py"]
""")
    return ScanContext(
        scan_id="llm-test-001",
        source_path=str(tmp_path),
        source_type="zip",
    )


class TestSadeLLMSecurityAgent:
    """Test the Sade LLM Security Agent."""

    def test_agent_identity(self, sade_agent):
        assert sade_agent.name == "sade_llm"
        assert "LLM" in sade_agent.role
        assert sade_agent.priority == 30

    def test_tools_list(self, sade_agent):
        assert "llm_security_scanner" in sade_agent.tools
        assert "container_scanner" in sade_agent.tools

    def test_supported_languages(self, sade_agent):
        assert sade_agent._get_supported_languages() == ["*"]

    def test_categories(self, sade_agent):
        cats = sade_agent._get_categories()
        assert "OWASP LLM Top 10" in cats
        assert "MCP Security" in cats
        assert "Dockerfile Security" in cats

    def test_deduplicate(self, sade_agent):
        from models.vulnerability import Vulnerability

        v1 = Vulnerability(
            scan_id="t", file_path="a.py", line_number=1,
            severity="HIGH", category="AI", title="T", description="D", tool_source="t",
        )
        v2 = Vulnerability(
            scan_id="t", file_path="a.py", line_number=1,
            severity="MEDIUM", category="AI", title="T", description="D", tool_source="t",
        )
        result = sade_agent._deduplicate([v1, v2])
        assert len(result) == 1
        assert result[0].severity == "HIGH"

    def test_config_scan_images(self):
        agent = SadeLLMSecurityAgent(config={"scan_images": True})
        assert agent._scan_images is True

    @pytest.mark.asyncio
    async def test_scan_finds_patterns(self, sade_agent, llm_context):
        result = await sade_agent.scan(llm_context)
        assert result.agent_name == "sade_llm"
        assert result.scan_id == "llm-test-001"
        assert result.status in ("success", "partial")
        assert result.execution_time_ms >= 0

    @pytest.mark.asyncio
    async def test_health_check(self, sade_agent):
        health = await sade_agent.health_check()
        assert health.agent_name == "sade_llm"

    @pytest.mark.asyncio
    async def test_scan_empty_dir(self, sade_agent, tmp_path):
        ctx = ScanContext(scan_id="empty", source_path=str(tmp_path))
        result = await sade_agent.scan(ctx)
        assert result.status in ("success", "partial")
