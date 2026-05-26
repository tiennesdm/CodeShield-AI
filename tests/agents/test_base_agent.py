"""
Tests for BaseSecurityAgent abstract class.
"""

import pytest

from agents.base import BaseSecurityAgent
from agents.results import (
    AgentCapabilities,
    HealthState,
    HealthStatus,
    ScanContext,
    ScanSummary,
    ToolExecutionSummary,
)


class MockAgent(BaseSecurityAgent):
    """Concrete agent for testing the base class."""

    name: str = "mock_agent"
    role: str = "Mock agent for testing"
    tools: list = ["mock_tool"]
    priority: int = 42

    async def scan(self, context: ScanContext):
        from agents.results import AgentResult

        return AgentResult(
            agent_name=self.name,
            agent_role=self.role,
            scan_id=context.scan_id,
            findings=[],
            status="success",
        )

    async def _check_tool_available(self, tool_name: str) -> bool:
        return tool_name == "mock_tool"


@pytest.fixture
def mock_agent():
    return MockAgent()


@pytest.fixture
def sample_context(tmp_path):
    return ScanContext(
        scan_id="test-scan-001",
        source_path=str(tmp_path),
        source_type="zip",
        languages=["python"],
    )


class TestBaseSecurityAgent:
    """Test the BaseSecurityAgent abstract base class."""

    def test_agent_initialization(self, mock_agent):
        assert mock_agent.name == "mock_agent"
        assert mock_agent.role == "Mock agent for testing"
        assert mock_agent.priority == 42
        assert mock_agent.config == {}
        assert mock_agent._initialized is True

    def test_agent_with_config(self):
        config = {"key": "value", "timeout": 30}
        agent = MockAgent(config=config)
        assert agent.config == config

    def test_get_capabilities(self, mock_agent):
        caps = mock_agent.get_capabilities()
        assert isinstance(caps, AgentCapabilities)
        assert caps.agent_name == "mock_agent"
        assert caps.agent_role == "Mock agent for testing"
        assert caps.tools == ["mock_tool"]
        assert caps.priority == 42
        assert caps.can_run_standalone is True

    def test_get_supported_languages_default(self, mock_agent):
        langs = mock_agent._get_supported_languages()
        assert langs == []

    def test_get_categories_default(self, mock_agent):
        cats = mock_agent._get_categories()
        assert cats == []

    def test_can_run_standalone(self, mock_agent):
        assert mock_agent._can_run_standalone() is True

    def test_requires_network_default(self, mock_agent):
        assert mock_agent._requires_network() is False

    def test_requires_external_tools(self, mock_agent):
        assert mock_agent._requires_external_tools() is True

    @pytest.mark.asyncio
    async def test_health_check(self, mock_agent):
        health = await mock_agent.health_check()
        assert health.agent_name == "mock_agent"
        assert health.state == HealthState.HEALTHY
        assert health.is_healthy() is True
        assert "tool_mock_tool" in health.details

    @pytest.mark.asyncio
    async def test_scan_method(self, mock_agent, sample_context):
        result = await mock_agent.scan(sample_context)
        assert result.agent_name == "mock_agent"
        assert result.status == "success"
        assert result.scan_id == "test-scan-001"

    def test_enrich_findings(self, mock_agent):
        from models.vulnerability import Vulnerability

        vuln = Vulnerability(
            scan_id="test",
            file_path="test.py",
            line_number=1,
            severity="HIGH",
            category="SQL Injection",
            title="Test",
            description="Test desc",
            tool_source="test",
            cwe_id="CWE-89",
        )
        enriched = mock_agent._enrich_findings([vuln])
        assert enriched[0].cwe_name == "SQL Injection"
        assert enriched[0].owasp_category == "A03"

    def test_build_result(self, mock_agent, sample_context):
        import time

        from models.vulnerability import Vulnerability

        start = time.time() * 1000
        vuln = Vulnerability(
            scan_id="test",
            file_path="test.py",
            line_number=1,
            severity="CRITICAL",
            category="Test",
            title="Test",
            description="Test",
            tool_source="test",
        )
        result = mock_agent._build_result(
            context=sample_context,
            findings=[vuln],
            start_time_ms=start,
            errors=[],
            metadata={"key": "value"},
        )
        assert result.agent_name == "mock_agent"
        assert result.status == "success"
        assert result.summary.critical == 1
        assert result.metadata == {"key": "value"}
        assert result.execution_time_ms >= 0

    def test_build_result_with_errors(self, mock_agent, sample_context):
        import time

        start = time.time() * 1000
        result = mock_agent._build_result(
            context=sample_context,
            findings=[],
            start_time_ms=start,
            errors=["Something failed"],
        )
        assert result.status == "failed"
        assert len(result.errors) == 1

    def test_build_result_with_tool_summaries(self, mock_agent, sample_context):
        import time

        start = time.time() * 1000
        summaries = [
            ToolExecutionSummary(tool_name="tool1", status="success", findings_count=3),
            ToolExecutionSummary(tool_name="tool2", status="failed", findings_count=0),
        ]
        result = mock_agent._build_result(
            context=sample_context,
            findings=[],
            start_time_ms=start,
            errors=[],
            tool_summaries=summaries,
        )
        assert result.summary.tools_executed == 2
        assert result.summary.tools_successful == 1
        assert result.summary.tools_failed == 1

    def test_repr(self, mock_agent):
        assert repr(mock_agent) == "<MockAgent(name='mock_agent', role='Mock agent for testing')>"


class TestScanContext:
    """Test ScanContext dataclass."""

    def test_default_creation(self):
        ctx = ScanContext(scan_id="test", source_path="/tmp")
        assert ctx.scan_id == "test"
        assert ctx.source_path == "/tmp"
        assert ctx.source_type == "zip"
        assert ctx.languages == []
        assert ctx.config == {}

    def test_full_creation(self):
        ctx = ScanContext(
            scan_id="test",
            source_path="/tmp",
            source_type="github",
            target_url="https://example.com",
            languages=["python"],
            config={"key": "val"},
            options={"opt": True},
        )
        assert ctx.target_url == "https://example.com"
        assert ctx.languages == ["python"]


class TestHealthStatus:
    """Test HealthStatus dataclass."""

    def test_healthy(self):
        h = HealthStatus(agent_name="test", state=HealthState.HEALTHY)
        assert h.is_healthy() is True

    def test_degraded(self):
        h = HealthStatus(agent_name="test", state=HealthState.DEGRADED)
        assert h.is_healthy() is True

    def test_unhealthy(self):
        h = HealthStatus(agent_name="test", state=HealthState.UNHEALTHY)
        assert h.is_healthy() is False


class TestAgentCapabilities:
    """Test AgentCapabilities dataclass."""

    def test_creation(self):
        caps = AgentCapabilities(
            agent_name="test",
            agent_role="test role",
            tools=["t1"],
            supported_languages=["python"],
            categories=["cat"],
        )
        assert caps.priority == 50  # default
        assert caps.can_run_standalone is True
