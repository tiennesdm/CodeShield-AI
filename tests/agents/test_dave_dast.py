"""
Tests for Dave DAST Agent.
"""

import pytest

from agents.dave_dast import DaveDASTAgent
from agents.results import ScanContext


@pytest.fixture
def dave_agent():
    return DaveDASTAgent()


@pytest.fixture
def dast_context(tmp_path):
    return ScanContext(
        scan_id="dast-test-001",
        source_path=str(tmp_path),
        source_type="zip",
        target_url="https://httpbin.org",
    )


class TestDaveDASTAgent:
    """Test the Dave DAST Agent."""

    def test_agent_identity(self, dave_agent):
        assert dave_agent.name == "dave_dast"
        assert "DAST" in dave_agent.role
        assert dave_agent.priority == 20

    def test_requires_network(self, dave_agent):
        assert dave_agent._requires_network() is True

    def test_supported_languages(self, dave_agent):
        assert dave_agent._get_supported_languages() == ["*"]

    def test_extract_url_empty(self, dave_agent, tmp_path):
        ctx = ScanContext(scan_id="t", source_path=str(tmp_path))
        url = dave_agent._extract_url_from_source(ctx)
        assert url == ""

    def test_cross_validate_sast(self, dave_agent, tmp_path):
        from models.vulnerability import Vulnerability

        sast_finding = Vulnerability(
            scan_id="t", file_path="app.py", line_number=10,
            severity="HIGH", category="SQL Injection",
            title="SQLi", description="D", tool_source="bandit",
        )
        ctx = ScanContext(
            scan_id="t", source_path=str(tmp_path),
            sast_findings=[sast_finding],
        )
        validations = dave_agent._cross_validate_sast(ctx)
        assert len(validations) == 1
        assert validations[0]["category"] == "SQL Injection"
        assert validations[0]["validation_type"] == "dynamic_confirmation"

    @pytest.mark.asyncio
    async def test_scan_without_url(self, dave_agent, tmp_path):
        ctx = ScanContext(scan_id="t", source_path=str(tmp_path))
        result = await dave_agent.scan(ctx)
        assert result.agent_name == "dave_dast"
        assert result.status == "failed"
        assert len(result.errors) > 0

    @pytest.mark.asyncio
    async def test_scan_with_url(self, dave_agent, dast_context):
        result = await dave_agent.scan(dast_context)
        assert result.agent_name == "dave_dast"
        assert result.status in ("success", "partial")
        assert result.execution_time_ms >= 0
        assert len(result.summary.tool_summaries) >= 1

    @pytest.mark.asyncio
    async def test_health_check(self, dave_agent):
        health = await dave_agent.health_check()
        assert health.agent_name == "dave_dast"
