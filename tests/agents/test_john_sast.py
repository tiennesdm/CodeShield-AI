"""
Tests for John SAST Agent.
"""

import pytest

from agents.john_sast import JohnSASTAgent
from agents.results import ScanContext


@pytest.fixture
def john_agent():
    return JohnSASTAgent()


@pytest.fixture
def sast_context(tmp_path):
    # Create a simple Python file with a vulnerability
    py_file = tmp_path / "test_app.py"
    py_file.write_text("""
import os

def unsafe(user_input):
    # SQL injection
    query = f"SELECT * FROM users WHERE id = {user_input}"
    os.system(user_input)  # Command injection
    eval(user_input)  # Code injection
""")
    return ScanContext(
        scan_id="sast-test-001",
        source_path=str(tmp_path),
        source_type="zip",
        languages=["python"],
    )


class TestJohnSASTAgent:
    """Test the John SAST Agent."""

    def test_agent_identity(self, john_agent):
        assert john_agent.name == "john_sast"
        assert "SAST" in john_agent.role
        assert john_agent.priority == 10

    def test_tools_list(self, john_agent):
        assert "semgrep" in john_agent.tools
        assert "bandit" in john_agent.tools
        assert "custom_ai_scanner" in john_agent.tools
        assert "llm_security_scanner" in john_agent.tools

    def test_supported_languages(self, john_agent):
        langs = john_agent._get_supported_languages()
        assert "python" in langs
        assert "javascript" in langs
        assert "java" in langs

    def test_categories(self, john_agent):
        cats = john_agent._get_categories()
        assert "Injection" in cats
        assert "Secret Leak" in cats

    def test_select_tools_python(self, john_agent, sast_context):
        tools = john_agent._select_tools(sast_context)
        assert "custom_ai" in tools
        assert "llm_security" in tools
        assert "bandit" in tools

    def test_select_tools_javascript(self, john_agent, tmp_path):
        ctx = ScanContext(
            scan_id="test",
            source_path=str(tmp_path),
            languages=["javascript"],
        )
        tools = john_agent._select_tools(ctx)
        assert "eslint" in tools
        assert "bandit" not in tools

    def test_deduplicate_findings(self, john_agent):
        from models.vulnerability import Vulnerability

        v1 = Vulnerability(
            scan_id="t", file_path="a.py", line_number=1,
            severity="HIGH", category="SQL", title="T", description="D", tool_source="t",
        )
        v2 = Vulnerability(
            scan_id="t", file_path="a.py", line_number=1,
            severity="CRITICAL", category="SQL", title="T", description="D", tool_source="t",
        )
        result = john_agent._deduplicate_findings([v1, v2])
        assert len(result) == 1
        assert result[0].severity == "CRITICAL"

    @pytest.mark.asyncio
    async def test_scan_runs(self, john_agent, sast_context):
        result = await john_agent.scan(sast_context)
        assert result.agent_name == "john_sast"
        assert result.scan_id == "sast-test-001"
        assert result.status in ("success", "partial")
        assert result.execution_time_ms >= 0
        assert len(result.summary.tool_summaries) >= 2

    @pytest.mark.asyncio
    async def test_health_check(self, john_agent):
        health = await john_agent.health_check()
        assert health.agent_name == "john_sast"
        assert health.is_healthy()
