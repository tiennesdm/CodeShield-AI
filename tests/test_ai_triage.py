"""
Tests for the AI False Positive Reduction Engine (ai_triage.py).

Covers:
- Hybrid SAST+LLM triage workflow
- Context-aware analysis (test files, validation, user input)
- Confidence scoring adjustments
- Organizational learning (feedback recording)
- Local heuristic fallback when LLM unavailable
- Known false positive pattern detection
"""

import asyncio
import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Ensure backend is importable
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ai_triage import AITriageEngine, TriageVerdict
from models.vulnerability import Vulnerability


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def triage_engine_no_llm() -> AITriageEngine:
    """Triage engine without LLM (local heuristics only)."""
    return AITriageEngine(openai_api_key="")


@pytest.fixture
def sample_vulnerability_sql() -> Vulnerability:
    """Sample SQL injection vulnerability."""
    return Vulnerability(
        scan_id="scan-001",
        file_path="src/app.py",
        line_number=42,
        severity="HIGH",
        category="SQL Injection",
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        title="SQL Injection via f-string",
        description="User input used directly in SQL query",
        code_snippet="user_id = request.args['id']\ncursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        fix_suggestion="Use parameterized queries",
        tool_source="bandit",
        confidence="HIGH",
    )


@pytest.fixture
def sample_vulnerability_xss() -> Vulnerability:
    """Sample XSS vulnerability."""
    return Vulnerability(
        scan_id="scan-001",
        file_path="src/templates/index.html",
        line_number=15,
        severity="MEDIUM",
        category="XSS",
        cwe_id="CWE-79",
        cwe_name="Cross-site Scripting (XSS)",
        title="Reflected XSS",
        description="User input rendered without escaping",
        code_snippet="element.innerHTML = userInput",
        fix_suggestion="Use textContent instead of innerHTML",
        tool_source="semgrep",
        confidence="HIGH",
    )


@pytest.fixture
def sample_vulnerability_secret() -> Vulnerability:
    """Sample hardcoded secret vulnerability."""
    return Vulnerability(
        scan_id="scan-001",
        file_path="src/config.py",
        line_number=5,
        severity="CRITICAL",
        category="Hardcoded Secret",
        cwe_id="CWE-798",
        cwe_name="Hardcoded Credentials",
        title="Hardcoded API Key",
        description="API key hardcoded in source",
        code_snippet="API_KEY = 'sk-test1234567890abcdef'",
        fix_suggestion="Use environment variables",
        tool_source="gitleaks",
        confidence="HIGH",
    )


@pytest.fixture
def mock_vulnerability_test_file() -> Vulnerability:
    """Vulnerability in a test file (should be flagged as FP)."""
    return Vulnerability(
        scan_id="scan-001",
        file_path="tests/test_auth.py",
        line_number=30,
        severity="HIGH",
        category="SQL Injection",
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        title="SQL Injection in test",
        description="Potential SQL injection",
        code_snippet="cursor.execute('SELECT * FROM mock_users')",
        fix_suggestion="Use parameterized queries",
        tool_source="bandit",
        confidence="HIGH",
    )


@pytest.fixture
def mock_vulnerability_with_validation() -> Vulnerability:
    """Vulnerability where validation already exists (likely FP)."""
    return Vulnerability(
        scan_id="scan-001",
        file_path="src/api.py",
        line_number=25,
        severity="HIGH",
        category="SQL Injection",
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        title="SQL Injection false positive",
        description="Potential SQL injection",
        code_snippet="""
    sanitized = escape(user_input)
    cursor.execute('SELECT * FROM users WHERE name = ?', (sanitized,))
""",
        fix_suggestion="Already uses parameterized query",
        tool_source="semgrep",
        confidence="HIGH",
    )


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

class TestAITriageEngineInit:
    """Test AITriageEngine initialization."""

    def test_init_without_api_key(self) -> None:
        """Engine should work without API key (local heuristics)."""
        engine = AITriageEngine(openai_api_key="")
        assert engine.openai_api_key == ""
        assert engine._openai_client is None

    def test_init_with_api_key_from_env(self, monkeypatch: Any) -> None:
        """Engine should read API key from environment."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
        engine = AITriageEngine()
        assert engine.openai_api_key == "sk-test-key"

    def test_init_with_explicit_key(self) -> None:
        """Engine should use explicitly provided API key."""
        engine = AITriageEngine(openai_api_key="sk-explicit")
        assert engine.openai_api_key == "sk-explicit"


class TestFeedbackSystem:
    """Test organizational learning feedback system."""

    def test_record_feedback_fp(self, triage_engine_no_llm: AITriageEngine, tmp_path: Path) -> None:
        """Test recording false positive feedback."""
        with patch("ai_triage.FEEDBACK_FILE", tmp_path / "test_feedback.json"):
            result = triage_engine_no_llm.record_feedback("vuln-123", "confirmed_fp")
            assert result["vuln_id"] == "vuln-123"
            assert result["verdict"] == "confirmed_fp"

    def test_record_feedback_tp(self, triage_engine_no_llm: AITriageEngine, tmp_path: Path) -> None:
        """Test recording true positive feedback."""
        with patch("ai_triage.FEEDBACK_FILE", tmp_path / "test_feedback.json"):
            result = triage_engine_no_llm.record_feedback("vuln-456", "confirmed_tp")
            assert result["verdict"] == "confirmed_tp"

    def test_feedback_persistence(self, triage_engine_no_llm: AITriageEngine, tmp_path: Path) -> None:
        """Feedback should persist across engine instances."""
        feedback_file = tmp_path / "test_feedback.json"
        with patch("ai_triage.FEEDBACK_FILE", feedback_file):
            triage_engine_no_llm.record_feedback("vuln-789", "confirmed_fp")

            # Create new engine instance
            engine2 = AITriageEngine(openai_api_key="")
            engine2._feedback_data = None  # Force reload
            feedback = engine2._load_feedback()
            assert "vuln-789" in feedback.get("fp_vuln_ids", [])


class TestKnownFPDetection:
    """Test known false positive pattern detection."""

    def test_test_file_detection(self, triage_engine_no_llm: AITriageEngine) -> None:
        """Should flag vulnerabilities in test files as likely FP."""
        assert triage_engine_no_llm._is_test_file("tests/test_auth.py") is True
        assert triage_engine_no_llm._is_test_file("src/main.py") is False
        assert triage_engine_no_llm._is_test_file("app/spec_helper.rb") is True

    def test_known_fp_pattern_in_code(self, triage_engine_no_llm: AITriageEngine) -> None:
        """Should detect known FP patterns in code."""
        assert triage_engine_no_llm._has_known_fp_pattern("password = 'changeme'") is True
        assert triage_engine_no_llm._has_known_fp_pattern("api_key = '<YOUR_KEY_HERE>'") is True
        assert triage_engine_no_llm._has_known_fp_pattern("result = compute(x, y)") is False

    def test_mock_data_detection(self, triage_engine_no_llm: AITriageEngine) -> None:
        """Should detect mock data patterns."""
        code = "mock_user = {'name': 'test', 'role': 'admin'}  # mock data"
        assert triage_engine_no_llm._has_known_fp_pattern(code) is True


class TestValidationDetection:
    """Test validation/sanitization pattern detection."""

    def test_has_validation_positive(self, triage_engine_no_llm: AITriageEngine) -> None:
        """Should detect existing validation."""
        code = """
def handle_request(user_input):
    sanitized = bleach.clean(user_input)
    return render(sanitized)
"""
        assert triage_engine_no_llm._has_validation(code) is True

    def test_has_validation_negative(self, triage_engine_no_llm: AITriageEngine) -> None:
        """Should not detect validation when absent."""
        code = "result = process(data)"
        assert triage_engine_no_llm._has_validation(code) is False


class TestUserInputDetection:
    """Test user input source detection."""

    def test_user_input_detected(self, triage_engine_no_llm: AITriageEngine) -> None:
        """Should detect user-controlled input."""
        code = "user_id = request.args.get('id')"
        assert triage_engine_no_llm._is_user_controlled(code) is True

    def test_user_input_not_detected(self, triage_engine_no_llm: AITriageEngine) -> None:
        """Should not flag internal variables."""
        code = "internal_id = 42"
        assert triage_engine_no_llm._is_user_controlled(code) is False


class TestVulnerabilitySpecificChecks:
    """Test vulnerability-type-specific checks."""

    def test_sql_with_parameterization(self, triage_engine_no_llm: AITriageEngine) -> None:
        """Should flag SQL with existing parameterization as sanitized."""
        vuln = Vulnerability(
            scan_id="s1", file_path="app.py", line_number=1,
            severity="HIGH", category="SQL Injection", cwe_id="CWE-89",
            cwe_name="SQL Injection", title="SQLi", description="SQLi",
            code_snippet="cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
            fix_suggestion="Use parameterized queries", tool_source="bandit",
        )
        result = triage_engine_no_llm._check_vulnerability_specific(vuln, vuln.code_snippet)
        assert result["is_sanitized"] is True

    def test_xss_with_escaping(self, triage_engine_no_llm: AITriageEngine) -> None:
        """Should detect XSS sanitization via escape functions."""
        vuln = Vulnerability(
            scan_id="s1", file_path="app.py", line_number=1,
            severity="MEDIUM", category="XSS", cwe_id="CWE-79",
            cwe_name="XSS", title="XSS", description="XSS",
            code_snippet="element.innerHTML = DOMPurify.sanitize(userInput)",
            fix_suggestion="Use textContent", tool_source="semgrep",
        )
        result = triage_engine_no_llm._check_vulnerability_specific(vuln, vuln.code_snippet)
        assert result["is_sanitized"] is True

    def test_secret_with_env_var(self, triage_engine_no_llm: AITriageEngine) -> None:
        """Should detect secrets with env var usage nearby."""
        vuln = Vulnerability(
            scan_id="s1", file_path="config.py", line_number=1,
            severity="CRITICAL", category="Hardcoded Secret", cwe_id="CWE-798",
            cwe_name="Secret", title="Secret", description="Secret",
            code_snippet="API_KEY = os.environ.get('API_KEY')",
            fix_suggestion="Use env vars", tool_source="gitleaks",
        )
        result = triage_engine_no_llm._check_vulnerability_specific(vuln, vuln.code_snippet)
        assert result["has_safe_alternative"] is True


class TestTriageWorkflow:
    """Test the full triage workflow."""

    @pytest.mark.asyncio
    async def test_triage_empty_list(
        self, triage_engine_no_llm: AITriageEngine
    ) -> None:
        """Triage on empty list should return empty list."""
        result = await triage_engine_no_llm.triage_vulnerabilities([], source_path=None)
        assert result == []

    @pytest.mark.asyncio
    async def test_triage_test_file_flagged_as_fp(
        self,
        triage_engine_no_llm: AITriageEngine,
        mock_vulnerability_test_file: Vulnerability,
    ) -> None:
        """Vulnerability in test file should be flagged as likely FP."""
        result = await triage_engine_no_llm.triage_vulnerabilities(
            [mock_vulnerability_test_file], source_path=None
        )
        assert len(result) == 1
        assert "LIKELY FALSE POSITIVE" in result[0].description
        assert result[0].confidence == "LOW"

    @pytest.mark.asyncio
    async def test_triage_with_validation_flagged_as_fp(
        self,
        triage_engine_no_llm: AITriageEngine,
        mock_vulnerability_with_validation: Vulnerability,
    ) -> None:
        """Vulnerability with existing validation should be flagged as FP."""
        result = await triage_engine_no_llm.triage_vulnerabilities(
            [mock_vulnerability_with_validation], source_path=None
        )
        assert len(result) == 1
        assert result[0].confidence == "LOW"

    @pytest.mark.asyncio
    async def test_triage_keeps_tp_intact(
        self,
        triage_engine_no_llm: AITriageEngine,
        sample_vulnerability_sql: Vulnerability,
    ) -> None:
        """True positive vulnerabilities should retain high confidence."""
        result = await triage_engine_no_llm.triage_vulnerabilities(
            [sample_vulnerability_sql], source_path=None
        )
        assert len(result) == 1
        assert "LIKELY FALSE POSITIVE" not in result[0].description
        assert result[0].confidence in ("HIGH", "MEDIUM")

    @pytest.mark.asyncio
    async def test_triage_multiple_vulns(
        self,
        triage_engine_no_llm: AITriageEngine,
        sample_vulnerability_sql: Vulnerability,
        mock_vulnerability_test_file: Vulnerability,
    ) -> None:
        """Triage should handle multiple vulnerabilities."""
        result = await triage_engine_no_llm.triage_vulnerabilities(
            [sample_vulnerability_sql, mock_vulnerability_test_file],
            source_path=None,
        )
        assert len(result) == 2
        # Test file vuln should be flagged
        assert "LIKELY FALSE POSITIVE" in result[1].description


class TestConfidenceAdjustment:
    """Test confidence score adjustment."""

    def test_adjust_confidence_up(self, triage_engine_no_llm: AITriageEngine) -> None:
        """Should increase confidence."""
        result = triage_engine_no_llm._adjust_confidence("MEDIUM", 1)
        assert result == "HIGH"

    def test_adjust_confidence_down(self, triage_engine_no_llm: AITriageEngine) -> None:
        """Should decrease confidence."""
        result = triage_engine_no_llm._adjust_confidence("HIGH", -1)
        assert result == "MEDIUM"

    def test_adjust_confidence_clamped_low(self, triage_engine_no_llm: AITriageEngine) -> None:
        """Should not go below LOW."""
        result = triage_engine_no_llm._adjust_confidence("LOW", -5)
        assert result == "LOW"

    def test_adjust_confidence_clamped_high(self, triage_engine_no_llm: AITriageEngine) -> None:
        """Should not go above HIGH."""
        result = triage_engine_no_llm._adjust_confidence("HIGH", 5)
        assert result == "HIGH"


class TestTriageStats:
    """Test triage statistics."""

    @pytest.mark.asyncio
    async def test_get_triage_stats(self, triage_engine_no_llm: AITriageEngine) -> None:
        """Should return triage statistics."""
        stats = await triage_engine_no_llm.get_triage_stats()
        assert "total_confirmations" in stats
        assert "total_false_positives_flagged" in stats
        assert "llm_available" in stats
        assert stats["llm_available"] is False


class TestLLMTriageFallback:
    """Test LLM fallback behavior."""

    @pytest.mark.asyncio
    async def test_llm_fallback_on_error(
        self,
        triage_engine_no_llm: AITriageEngine,
        sample_vulnerability_sql: Vulnerability,
    ) -> None:
        """Should gracefully handle missing LLM."""
        with patch("governance.assist.governed_complete", side_effect=Exception("No LLM available")):
            result = await triage_engine_no_llm._llm_triage(
                sample_vulnerability_sql, sample_vulnerability_sql.code_snippet or ""
            )
            assert result is None  # No LLM client available


class TestBuildPrompt:
    """Test LLM prompt building."""

    def test_prompt_contains_required_info(
        self,
        triage_engine_no_llm: AITriageEngine,
        sample_vulnerability_sql: Vulnerability,
    ) -> None:
        """Prompt should contain vulnerability details."""
        code = sample_vulnerability_sql.code_snippet or ""
        prompt = triage_engine_no_llm._build_triage_prompt(sample_vulnerability_sql, code)
        assert sample_vulnerability_sql.category in prompt
        assert sample_vulnerability_sql.file_path in prompt
        assert "Code Context" in prompt
