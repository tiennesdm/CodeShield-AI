"""
Tests for Pam SCA Agent.
"""

import pytest

from agents.pam_sca import PamSCAAgent
from agents.results import ScanContext


@pytest.fixture
def pam_agent():
    return PamSCAAgent()


@pytest.fixture
def sca_context(tmp_path):
    # Create a requirements.txt with known vulnerable packages
    req_file = tmp_path / "requirements.txt"
    req_file.write_text("""
django==3.2.0
requests==2.25.0
flask==1.0.0
numpy==1.19.0
""")
    return ScanContext(
        scan_id="sca-test-001",
        source_path=str(tmp_path),
        source_type="zip",
        languages=["python"],
    )


class TestPamSCAAgent:
    """Test the Pam SCA Agent."""

    def test_agent_identity(self, pam_agent):
        assert pam_agent.name == "pam_sca"
        assert "SCA" in pam_agent.role or "Composition" in pam_agent.role
        assert pam_agent.priority == 15

    def test_tools_list(self, pam_agent):
        assert "osv_scanner" in pam_agent.tools
        assert "reachability_analyzer" in pam_agent.tools
        assert "sbom_generator" in pam_agent.tools

    def test_requires_network(self, pam_agent):
        assert pam_agent._requires_network() is True

    def test_supported_languages(self, pam_agent):
        langs = pam_agent._get_supported_languages()
        assert "python" in langs
        assert "javascript" in langs

    def test_extract_dep_name(self, pam_agent):
        from models.vulnerability import Vulnerability

        v = Vulnerability(
            scan_id="t", file_path="req.txt", line_number=0,
            severity="HIGH", category="Vuln Dep", title="Django CVE",
            description="D", tool_source="osv",
            code_snippet="Package: django\nVersion: 3.2.0",
        )
        name = pam_agent._extract_dep_name_from_finding(v)
        assert name == "django"

    def test_extract_dep_name_empty(self, pam_agent):
        from models.vulnerability import Vulnerability

        v = Vulnerability(
            scan_id="t", file_path="x", line_number=0,
            severity="HIGH", category="X", title="T",
            description="D", tool_source="t",
        )
        name = pam_agent._extract_dep_name_from_finding(v)
        assert name == ""

    @pytest.mark.asyncio
    async def test_scan_runs(self, pam_agent, sca_context):
        result = await pam_agent.scan(sca_context)
        assert result.agent_name == "pam_sca"
        assert result.scan_id == "sca-test-001"
        assert result.status in ("success", "partial")
        assert result.execution_time_ms >= 0
        assert "sbom" in result.metadata

    @pytest.mark.asyncio
    async def test_health_check(self, pam_agent):
        health = await pam_agent.health_check()
        assert health.agent_name == "pam_sca"

    def test_categories(self, pam_agent):
        cats = pam_agent._get_categories()
        assert "Vulnerable Dependency" in cats
        assert "SBOM" in cats
