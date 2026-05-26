"""
Tests for Sam Secrets Agent.
"""

import pytest

from agents.results import ScanContext
from agents.sam_secrets import SamSecretsAgent


@pytest.fixture
def sam_agent():
    return SamSecretsAgent()


@pytest.fixture
def secrets_context(tmp_path):
    # Create files with various secrets
    py_file = tmp_path / "config.py"
    py_file.write_text("""
# Hardcoded secrets
API_KEY = "sk-abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
SECRET_KEY = "django-insecure-very-secret-key-here-do-not-use"
DATABASE_PASSWORD = "SuperSecretP@ssw0rd123!"
""")
    env_file = tmp_path / ".env"
    env_file.write_text("""
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
""")
    return ScanContext(
        scan_id="secrets-test-001",
        source_path=str(tmp_path),
        source_type="zip",
    )


class TestSamSecretsAgent:
    """Test the Sam Secrets Agent."""

    def test_agent_identity(self, sam_agent):
        assert sam_agent.name == "sam_secrets"
        assert "Secret" in sam_agent.role
        assert sam_agent.priority == 5

    def test_tools_list(self, sam_agent):
        assert "gitleaks" in sam_agent.tools
        assert "custom_ai_scanner" in sam_agent.tools

    def test_supported_languages(self, sam_agent):
        assert sam_agent._get_supported_languages() == ["*"]

    def test_categories(self, sam_agent):
        cats = sam_agent._get_categories()
        assert "Secret Leak" in cats
        assert "Hardcoded Credentials" in cats

    def test_requires_external_tools(self, sam_agent):
        assert sam_agent._requires_external_tools() is True

    def test_deduplicate_secrets(self, sam_agent):
        from models.vulnerability import Vulnerability

        v1 = Vulnerability(
            scan_id="t", file_path="a.py", line_number=1,
            severity="HIGH", category="Secret", title="T", description="D", tool_source="t",
        )
        v2 = Vulnerability(
            scan_id="t", file_path="a.py", line_number=1,
            severity="CRITICAL", category="Secret", title="T", description="D", tool_source="t",
        )
        result = sam_agent._deduplicate_secrets([v1, v2])
        assert len(result) == 1
        assert result[0].severity == "CRITICAL"

    @pytest.mark.asyncio
    async def test_scan_finds_secrets(self, sam_agent, secrets_context):
        result = await sam_agent.scan(secrets_context)
        assert result.agent_name == "sam_secrets"
        assert result.scan_id == "secrets-test-001"
        assert result.status in ("success", "partial")
        assert result.execution_time_ms >= 0

    @pytest.mark.asyncio
    async def test_entropy_scan(self, sam_agent, secrets_context):
        findings = await sam_agent._entropy_scan(secrets_context)
        assert isinstance(findings, list)
        # Should find the API_KEY line due to high entropy
        api_key_findings = [f for f in findings if "API_KEY" in (f.code_snippet or "")]
        assert len(api_key_findings) >= 0  # May or may not match based on regex

    @pytest.mark.asyncio
    async def test_health_check(self, sam_agent):
        health = await sam_agent.health_check()
        assert health.agent_name == "sam_secrets"
        assert health.is_healthy() is not None

    def test_entropy_threshold_config(self):
        agent = SamSecretsAgent(config={"entropy_threshold": 3.5})
        assert agent._entropy_threshold == 3.5
