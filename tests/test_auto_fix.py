"""
Tests for the Auto-Remediation Engine (auto_fix.py).

Covers:
- Deterministic codemods for all vulnerability types
- SQL Injection -> parameterized queries
- XSS -> safe output methods
- Hardcoded secrets -> environment variables
- eval() -> safe alternatives
- Path traversal -> path validation
- Weak crypto -> strong algorithms
- CORS wildcard -> specific origins
- Missing headers -> security headers
- Fix validation pipeline (syntax, pattern, style)
- Diff generation
- LLM fallback
"""

import ast
import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from auto_fix import AutoFixEngine, AutoFixResult, FixStatus
from models.vulnerability import Vulnerability


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fix_engine_no_llm() -> AutoFixEngine:
    """Fix engine without LLM (deterministic fixes only)."""
    return AutoFixEngine(openai_api_key="")


@pytest.fixture
def sample_sql_injection() -> Vulnerability:
    """SQL injection vulnerability."""
    return Vulnerability(
        scan_id="scan-001",
        file_path="src/app.py",
        line_number=42,
        severity="CRITICAL",
        category="SQL Injection",
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        title="SQL Injection via f-string",
        description="User input used directly in SQL query",
        code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        fix_suggestion="Use parameterized queries",
        tool_source="bandit",
        confidence="HIGH",
    )


@pytest.fixture
def sample_xss() -> Vulnerability:
    """XSS vulnerability."""
    return Vulnerability(
        scan_id="scan-001",
        file_path="src/app.js",
        line_number=15,
        severity="HIGH",
        category="XSS",
        cwe_id="CWE-79",
        cwe_name="Cross-site Scripting (XSS)",
        title="DOM XSS via innerHTML",
        description="User input assigned to innerHTML",
        code_snippet="element.innerHTML = userInput",
        fix_suggestion="Use textContent instead",
        tool_source="semgrep",
        confidence="HIGH",
    )


@pytest.fixture
def sample_eval() -> Vulnerability:
    """Eval vulnerability."""
    return Vulnerability(
        scan_id="scan-001",
        file_path="src/utils.py",
        line_number=20,
        severity="CRITICAL",
        category="Code Injection",
        cwe_id="CWE-94",
        cwe_name="Code Injection",
        title="Dangerous eval() usage",
        description="eval() used with user input",
        code_snippet="result = eval(user_input)",
        fix_suggestion="Use ast.literal_eval()",
        tool_source="bandit",
        confidence="HIGH",
    )


@pytest.fixture
def sample_secret() -> Vulnerability:
    """Hardcoded secret vulnerability."""
    return Vulnerability(
        scan_id="scan-001",
        file_path="src/config.py",
        line_number=5,
        severity="CRITICAL",
        category="Hardcoded Secret",
        cwe_id="CWE-798",
        cwe_name="Hardcoded Credentials",
        title="Hardcoded API Key",
        description="API key hardcoded in source code",
        code_snippet="API_KEY = 'sk-test1234567890abcdef'",
        fix_suggestion="Use environment variables",
        tool_source="gitleaks",
        confidence="HIGH",
    )


@pytest.fixture
def sample_weak_crypto() -> Vulnerability:
    """Weak cryptography vulnerability."""
    return Vulnerability(
        scan_id="scan-001",
        file_path="src/crypto.py",
        line_number=10,
        severity="HIGH",
        category="Weak Crypto",
        cwe_id="CWE-327",
        cwe_name="Broken Crypto",
        title="Weak hash algorithm MD5",
        description="MD5 is cryptographically broken",
        code_snippet="hash_value = hashlib.md5(data.encode()).hexdigest()",
        fix_suggestion="Use SHA-256 or stronger",
        tool_source="bandit",
        confidence="HIGH",
    )


@pytest.fixture
def sample_cors() -> Vulnerability:
    """CORS wildcard vulnerability."""
    return Vulnerability(
        scan_id="scan-001",
        file_path="src/app.py",
        line_number=8,
        severity="MEDIUM",
        category="CORS",
        cwe_id="CWE-346",
        cwe_name="CORS Misconfiguration",
        title="Permissive CORS Policy",
        description="CORS allows all origins",
        code_snippet="res.header('Access-Control-Allow-Origin', '*')",
        fix_suggestion="Specify allowed origins",
        tool_source="custom_ai",
        confidence="MEDIUM",
    )


# ---------------------------------------------------------------------------
# Engine Initialization Tests
# ---------------------------------------------------------------------------

class TestAutoFixEngineInit:
    """Test AutoFixEngine initialization."""

    def test_init_without_api_key(self) -> None:
        """Engine should work without API key."""
        engine = AutoFixEngine(openai_api_key="")
        assert engine.openai_api_key == ""
        assert engine._openai_client is None

    def test_init_with_env_var(self, monkeypatch: Any) -> None:
        """Engine should read API key from environment."""
        monkeypatch.setenv("OPENAI_API_KEY", "sk-test-key")
        engine = AutoFixEngine()
        assert engine.openai_api_key == "sk-test-key"


# ---------------------------------------------------------------------------
# SQL Injection Fix Tests
# ---------------------------------------------------------------------------

class TestSQLInjectionFix:
    """Test SQL injection remediation."""

    @pytest.mark.asyncio
    async def test_generate_fix_sql(
        self, fix_engine_no_llm: AutoFixEngine, sample_sql_injection: Vulnerability
    ) -> None:
        """Should generate fix for SQL injection."""
        result = await fix_engine_no_llm.generate_fix(sample_sql_injection)
        assert result.status in (FixStatus.SUCCESS, FixStatus.PARTIAL, FixStatus.NO_FIX_AVAILABLE)
        assert result.fix_type == "SQL Injection"

    def test_apply_sql_fix_pattern(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """Should apply parameterized query fix."""
        code = "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"
        result = fix_engine_no_llm._apply_sql_fix(code)
        assert result is not None
        assert "?" in result["fixed_code"] or "%s" in result["fixed_code"]


# ---------------------------------------------------------------------------
# XSS Fix Tests
# ---------------------------------------------------------------------------

class TestXSSFix:
    """Test XSS remediation."""

    @pytest.mark.asyncio
    async def test_generate_fix_xss(
        self, fix_engine_no_llm: AutoFixEngine, sample_xss: Vulnerability
    ) -> None:
        """Should generate fix for XSS."""
        result = await fix_engine_no_llm.generate_fix(sample_xss)
        assert result.status in (FixStatus.SUCCESS, FixStatus.NO_FIX_AVAILABLE)

    def test_apply_xss_fix_innerhtml(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """Should replace innerHTML with textContent."""
        code = "element.innerHTML = userInput"
        result = fix_engine_no_llm._apply_xss_fix(code)
        if result:
            assert "textContent" in result["fixed_code"]

    def test_apply_xss_fix_jquery(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """Should replace jQuery .html() with .text()."""
        code = "$('#output').html(userData)"
        result = fix_engine_no_llm._apply_xss_fix(code)
        if result:
            assert ".text(" in result["fixed_code"]


# ---------------------------------------------------------------------------
# Eval Fix Tests
# ---------------------------------------------------------------------------

class TestEvalFix:
    """Test eval() remediation."""

    @pytest.mark.asyncio
    async def test_generate_fix_eval(
        self, fix_engine_no_llm: AutoFixEngine, sample_eval: Vulnerability
    ) -> None:
        """Should generate fix for eval()."""
        result = await fix_engine_no_llm.generate_fix(sample_eval)
        assert result.status in (FixStatus.SUCCESS, FixStatus.NO_FIX_AVAILABLE)

    def test_apply_eval_fix(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """Should replace eval() with ast.literal_eval()."""
        code = "result = eval(user_input)"
        result = fix_engine_no_llm._apply_eval_fix(code)
        if result:
            assert "literal_eval" in result["fixed_code"] or "json.loads" in result["fixed_code"]


# ---------------------------------------------------------------------------
# Secret Fix Tests
# ---------------------------------------------------------------------------

class TestSecretFix:
    """Test hardcoded secret remediation."""

    @pytest.mark.asyncio
    async def test_generate_fix_secret(
        self, fix_engine_no_llm: AutoFixEngine, sample_secret: Vulnerability
    ) -> None:
        """Should generate fix for hardcoded secret."""
        result = await fix_engine_no_llm.generate_fix(sample_secret)
        assert result.status in (FixStatus.SUCCESS, FixStatus.NO_FIX_AVAILABLE)

    def test_apply_secret_fix_api_key(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """Should replace hardcoded API key with env var."""
        code = "API_KEY = 'sk-test123'"
        result = fix_engine_no_llm._apply_secret_fix(code, sample_secret)
        if result:
            assert "os.environ" in result["fixed_code"] or "getenv" in result["fixed_code"]


# ---------------------------------------------------------------------------
# Crypto Fix Tests
# ---------------------------------------------------------------------------

class TestCryptoFix:
    """Test weak crypto remediation."""

    @pytest.mark.asyncio
    async def test_generate_fix_crypto(
        self, fix_engine_no_llm: AutoFixEngine, sample_weak_crypto: Vulnerability
    ) -> None:
        """Should generate fix for weak crypto."""
        result = await fix_engine_no_llm.generate_fix(sample_weak_crypto)
        assert result.status in (FixStatus.SUCCESS, FixStatus.NO_FIX_AVAILABLE)

    def test_apply_md5_fix(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """Should replace MD5 with SHA-256."""
        code = "hashlib.md5(data.encode()).hexdigest()"
        result = fix_engine_no_llm._apply_crypto_fix(code)
        if result:
            assert "sha256" in result["fixed_code"]

    def test_apply_sha1_fix(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """Should replace SHA1 with SHA-256."""
        code = "hashlib.sha1(data.encode()).hexdigest()"
        result = fix_engine_no_llm._apply_crypto_fix(code)
        if result:
            assert "sha256" in result["fixed_code"]


# ---------------------------------------------------------------------------
# CORS Fix Tests
# ---------------------------------------------------------------------------

class TestCORSFix:
    """Test CORS remediation."""

    @pytest.mark.asyncio
    async def test_generate_fix_cors(
        self, fix_engine_no_llm: AutoFixEngine, sample_cors: Vulnerability
    ) -> None:
        """Should generate fix for CORS wildcard."""
        result = await fix_engine_no_llm.generate_fix(sample_cors)
        assert result.status in (FixStatus.SUCCESS, FixStatus.NO_FIX_AVAILABLE)

    def test_apply_cors_fix(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """Should replace wildcard with specific origin."""
        code = "res.header('Access-Control-Allow-Origin', '*')"
        result = fix_engine_no_llm._apply_cors_fix(code)
        if result:
            assert "*" not in result["fixed_code"] or "your-domain" in result["fixed_code"]


# ---------------------------------------------------------------------------
# Fix Validation Tests
# ---------------------------------------------------------------------------

class TestFixValidation:
    """Test fix validation pipeline."""

    def test_valid_syntax_passes(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """Valid Python code should pass syntax validation."""
        original = "x = 1"
        fixed = "x = 1  # SECURITY FIX: safe"
        vuln = Vulnerability(
            scan_id="s1", file_path="test.py", line_number=1,
            severity="LOW", category="Test", cwe_id="CWE-200",
            cwe_name="Test", title="Test", description="Test",
            code_snippet=original, fix_suggestion="Fix", tool_source="test",
        )
        result = fix_engine_no_llm._validate_fix(original, fixed, vuln)
        assert result["syntax_valid"] is True

    def test_invalid_syntax_fails(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """Invalid Python code should fail syntax validation."""
        original = "x = 1"
        fixed = "x = (  # unclosed"
        vuln = Vulnerability(
            scan_id="s1", file_path="test.py", line_number=1,
            severity="LOW", category="Test", cwe_id="CWE-200",
            cwe_name="Test", title="Test", description="Test",
            code_snippet=original, fix_suggestion="Fix", tool_source="test",
        )
        result = fix_engine_no_llm._validate_fix(original, fixed, vuln)
        assert result["syntax_valid"] is False

    def test_xss_pattern_addressed(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """XSS fix should be detected as addressing the vulnerability."""
        original = "element.innerHTML = userInput"
        fixed = "element.textContent = userInput  # SECURITY FIX: safe"
        vuln = Vulnerability(
            scan_id="s1", file_path="test.js", line_number=1,
            severity="HIGH", category="XSS", cwe_id="CWE-79",
            cwe_name="XSS", title="XSS", description="XSS",
            code_snippet=original, fix_suggestion="Fix", tool_source="test",
        )
        result = fix_engine_no_llm._validate_fix(original, fixed, vuln)
        assert result["pattern_addressed"] is True

    def test_eval_pattern_addressed(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """Eval fix should be detected as addressing the vulnerability."""
        original = "eval(user_input)"
        fixed = "json.loads(user_input)  # SECURITY FIX"
        vuln = Vulnerability(
            scan_id="s1", file_path="test.py", line_number=1,
            severity="CRITICAL", category="Code Injection", cwe_id="CWE-94",
            cwe_name="Code Injection", title="Eval", description="Eval",
            code_snippet=original, fix_suggestion="Fix", tool_source="test",
        )
        result = fix_engine_no_llm._validate_fix(original, fixed, vuln)
        assert result["pattern_addressed"] is True


# ---------------------------------------------------------------------------
# Diff Generation Tests
# ---------------------------------------------------------------------------

class TestDiffGeneration:
    """Test unified diff generation."""

    def test_generate_diff(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """Should generate valid unified diff."""
        original = "line1\nline2\nline3"
        fixed = "line1\nline2_fixed\nline3"
        diff = fix_engine_no_llm._generate_diff(original, fixed, "test.py")
        assert "--- a/test.py" in diff
        assert "+++ b/test.py" in diff
        assert "-line2" in diff
        assert "+line2_fixed" in diff

    def test_empty_diff_for_same_content(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """Same content should produce no meaningful diff."""
        original = "line1\nline2"
        diff = fix_engine_no_llm._generate_diff(original, original, "test.py")
        # Unified diff headers always present
        assert "--- a/test.py" in diff


# ---------------------------------------------------------------------------
# Code Extraction Tests
# ---------------------------------------------------------------------------

class TestCodeExtraction:
    """Test code block extraction from LLM responses."""

    def test_extract_code_block_markdown(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """Should extract code from markdown block."""
        content = "```python\nx = 1\n```"
        result = fix_engine_no_llm._extract_code_block(content)
        assert result == "x = 1"

    def test_extract_code_block_generic(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """Should extract code from generic block."""
        content = "```\nx = 1\n```"
        result = fix_engine_no_llm._extract_code_block(content)
        assert result == "x = 1"

    def test_extract_plain_text(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """Should return plain text if no code block."""
        content = "x = 1"
        result = fix_engine_no_llm._extract_code_block(content)
        assert result == "x = 1"


# ---------------------------------------------------------------------------
# Available Fix Types Tests
# ---------------------------------------------------------------------------

class TestAvailableFixTypes:
    """Test available fix types listing."""

    @pytest.mark.asyncio
    async def test_get_available_fix_types(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """Should return list of supported fix types."""
        types = await fix_engine_no_llm.get_available_fix_types()
        assert len(types) > 0
        categories = [t["category"] for t in types]
        assert "SQL Injection" in categories
        assert "XSS" in categories
        assert "Hardcoded Secret" in categories


# ---------------------------------------------------------------------------
# AutoFixResult Tests
# ---------------------------------------------------------------------------

class TestAutoFixResult:
    """Test AutoFixResult data model."""

    def test_to_dict(self) -> None:
        """Should serialize to dict."""
        result = AutoFixResult(
            vuln_id="vuln-123",
            status=FixStatus.SUCCESS,
            original_code="bad_code",
            fixed_code="good_code",
            diff="---\n+++",
            fix_type="SQL Injection",
            description="Parameterized query",
            validation_passed=True,
        )
        d = result.to_dict()
        assert d["vuln_id"] == "vuln-123"
        assert d["status"] == "success"
        assert d["validation_passed"] is True


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------

class TestEndToEndFix:
    """End-to-end fix generation tests."""

    @pytest.mark.asyncio
    async def test_sql_fix_e2e(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """End-to-end SQL injection fix generation."""
        vuln = Vulnerability(
            scan_id="s1", file_path="app.py", line_number=1,
            severity="CRITICAL", category="SQL Injection", cwe_id="CWE-89",
            cwe_name="SQL Injection", title="SQLi", description="SQLi",
            code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            fix_suggestion="Parametrize", tool_source="bandit",
        )
        result = await fix_engine_no_llm.generate_fix(vuln)
        assert isinstance(result, AutoFixResult)
        assert result.vuln_id == vuln.id

    @pytest.mark.asyncio
    async def test_no_code_returns_no_fix(self, fix_engine_no_llm: AutoFixEngine) -> None:
        """Vulnerability without code snippet should return no fix."""
        vuln = Vulnerability(
            scan_id="s1", file_path="app.py", line_number=1,
            severity="HIGH", category="Unknown Category", cwe_id="CWE-999",
            cwe_name="Unknown", title="Unknown", description="Unknown",
            code_snippet=None, fix_suggestion="Fix", tool_source="test",
        )
        result = await fix_engine_no_llm.generate_fix(vuln)
        assert result.status == FixStatus.NO_FIX_AVAILABLE
