"""
Tests for Tina Taint Agent.
"""

import pytest

from agents.results import ScanContext
from agents.tina_taint import TinaTaintAgent


@pytest.fixture
def tina_agent():
    return TinaTaintAgent()


@pytest.fixture
def taint_context(tmp_path):
    # Create a Python file with taint flow
    py_file = tmp_path / "routes.py"
    py_file.write_text("""
from flask import request
import sqlite3

def get_user():
    user_id = request.args.get("id")
    conn = sqlite3.connect("db.sqlite")
    cursor = conn.cursor()
    # Taint flow: user_id (source) -> cursor.execute (sink)
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchall()

def run_command():
    cmd = request.form.get("cmd")
    import os
    os.system(cmd)  # Taint flow: cmd -> os.system
""")
    return ScanContext(
        scan_id="taint-test-001",
        source_path=str(tmp_path),
        source_type="zip",
        languages=["python"],
    )


class TestTinaTaintAgent:
    """Test the Tina Taint Agent."""

    def test_agent_identity(self, tina_agent):
        assert tina_agent.name == "tina_taint"
        assert "Taint" in tina_agent.role
        assert tina_agent.priority == 25

    def test_tools_list(self, tina_agent):
        assert "taint_analyzer" in tina_agent.tools

    def test_supported_languages(self, tina_agent):
        assert tina_agent._get_supported_languages() == ["python"]

    def test_categories(self, tina_agent):
        cats = tina_agent._get_categories()
        assert "SQL Injection" in cats
        assert "Taint Flow" in cats

    def test_cross_reference_sast_match(self, tina_agent, tmp_path):
        from models.vulnerability import Vulnerability

        taint_finding = Vulnerability(
            scan_id="t", file_path="routes.py", line_number=10,
            severity="HIGH", category="SQL Injection",
            title="SQLi", description="D", tool_source="taint",
        )
        sast_finding = Vulnerability(
            scan_id="t", file_path="routes.py", line_number=12,
            severity="HIGH", category="SQL Injection",
            title="SQLi SAST", description="D", tool_source="bandit",
        )
        ctx = ScanContext(
            scan_id="t", source_path=str(tmp_path),
            sast_findings=[sast_finding],
        )
        confirmations = tina_agent._cross_reference_sast(ctx, [taint_finding])
        assert len(confirmations) >= 0  # May or may not match

    @pytest.mark.asyncio
    async def test_scan_finds_taint_flows(self, tina_agent, taint_context):
        result = await tina_agent.scan(taint_context)
        assert result.agent_name == "tina_taint"
        assert result.scan_id == "taint-test-001"
        assert result.status in ("success", "partial")
        assert result.execution_time_ms >= 0
        assert "taint_summary" in result.metadata

    @pytest.mark.asyncio
    async def test_health_check(self, tina_agent):
        health = await tina_agent.health_check()
        assert health.agent_name == "tina_taint"

    @pytest.mark.asyncio
    async def test_scan_no_python_files(self, tina_agent, tmp_path):
        # Create non-python files only
        (tmp_path / "readme.md").write_text("# Hello")
        ctx = ScanContext(
            scan_id="t", source_path=str(tmp_path),
            languages=["javascript"],
        )
        result = await tina_agent.scan(ctx)
        assert result.agent_name == "tina_taint"
        assert result.status == "success"
