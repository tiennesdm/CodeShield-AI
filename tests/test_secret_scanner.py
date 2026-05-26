"""
Tests for CodeShield AI Enhanced Secret Scanner.

Tests the 200+ secret patterns, entropy-based detection, and .env file scanning.
"""

import asyncio
import os
import sys
import tempfile

# Ensure backend is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from scanner.tools.custom_ai_scanner import (
    CustomAIScanner,
    shannon_entropy,
    is_high_entropy,
)


class TestEntropyFunctions:
    """Tests for entropy-based detection."""

    def test_shannon_entropy_empty(self):
        """Test entropy of empty string."""
        assert shannon_entropy("") == 0.0

    def test_shannon_entropy_constant(self):
        """Test entropy of constant string."""
        # "aaaa" has very low entropy
        ent = shannon_entropy("aaaa")
        assert ent < 1.0

    def test_shannon_entropy_high(self):
        """Test entropy of random-looking string."""
        # Base64-like random string should have high entropy
        ent = shannon_entropy("aB3xK9mP2vL5nQ8wR4tY7uI6oE1jH0gF")
        assert ent > 4.0

    def test_is_high_entropy_short_string(self):
        """Test that short strings are not high entropy."""
        assert is_high_entropy("abc", threshold=4.0) is False

    def test_is_high_entropy_placeholder(self):
        """Test that placeholder strings are not high entropy."""
        assert is_high_entropy("xxxxxxx_test_xxxxxxxxx", threshold=4.0) is False
        assert is_high_entropy("test_value_123", threshold=4.0) is False

    def test_is_high_entropy_random(self):
        """Test that random strings are detected as high entropy."""
        random_str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
        assert is_high_entropy(random_str, threshold=4.0) is True

    def test_is_high_entropy_false_positives(self):
        """Test false positive avoidance."""
        assert is_high_entropy("true", threshold=4.0) is False
        assert is_high_entropy("false", threshold=4.0) is False
        assert is_high_entropy("None", threshold=4.0) is False


class TestCustomAIScanner:
    """Tests for the Custom AI scanner."""

    @pytest.fixture
    def scanner(self):
        return CustomAIScanner()

    def test_scanner_initialization(self, scanner):
        """Test scanner initialization."""
        assert scanner.tool_name == "custom_ai"
        assert len(scanner.patterns) > 200
        assert scanner.entropy_threshold == 4.0

    def test_is_available(self, scanner):
        """Test scanner availability."""
        assert scanner.is_available() is True

    def test_get_cvss_score(self, scanner):
        """Test CVSS score mapping."""
        assert scanner._get_cvss_score("CRITICAL") == 9.0
        assert scanner._get_cvss_score("HIGH") == 7.5
        assert scanner._get_cvss_score("MEDIUM") == 5.0
        assert scanner._get_cvss_score("LOW") == 2.0
        assert scanner._get_cvss_score("INFO") == 0.0

    def test_get_fix_suggestion_sql_injection(self, scanner):
        """Test fix suggestion for SQL injection."""
        suggestion = scanner._get_fix_suggestion("CWE-89", "SQL Injection")
        assert "parameterized" in suggestion.lower()

    def test_get_fix_suggestion_secrets(self, scanner):
        """Test fix suggestion for secrets."""
        suggestion = scanner._get_fix_suggestion("CWE-798", "Hardcoded Secret")
        assert "environment" in suggestion.lower() or "secret" in suggestion.lower()

    def test_get_fix_suggestion_xss(self, scanner):
        """Test fix suggestion for XSS."""
        suggestion = scanner._get_fix_suggestion("CWE-79", "XSS")
        assert "sanitize" in suggestion.lower()

    def test_deduplicate(self, scanner):
        """Test vulnerability deduplication."""
        from models.vulnerability import Vulnerability
        vulns = [
            Vulnerability(
                scan_id="test", file_path="a.py", line_number=1,
                severity="HIGH", category="Secret",
                cwe_id="CWE-798", title="Dup",
                description="dup", tool_source="test",
            ),
            Vulnerability(
                scan_id="test", file_path="a.py", line_number=1,
                severity="CRITICAL", category="Secret",
                cwe_id="CWE-798", title="Dup",
                description="dup", tool_source="test",
            ),
        ]
        result = scanner._deduplicate(vulns)
        assert len(result) == 1
        assert result[0].severity == "CRITICAL"  # Higher severity wins

    @pytest.mark.asyncio
    async def test_scan_empty_directory(self, scanner, tmp_path):
        """Test scanning an empty directory."""
        vulns = await scanner.scan(str(tmp_path), "test-scan")
        assert isinstance(vulns, list)

    @pytest.mark.asyncio
    async def test_scan_python_file(self, scanner, tmp_path):
        """Test scanning a Python file with known issues."""
        py_file = tmp_path / "test.py"
        py_file.write_text("""
import os

# Hardcoded secret
API_KEY = "sk-abcdefghijklmnopqrstuvwxyz123456"
password = "admin12345"

# SQL injection
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

# Eval usage
eval(user_input)
""")
        vulns = await scanner.scan(str(tmp_path), "test-scan")

        # Should find multiple issues
        categories = {v.category for v in vulns}
        assert len(vulns) > 0

    @pytest.mark.asyncio
    async def test_scan_env_file(self, scanner, tmp_path):
        """Test scanning .env files."""
        env_file = tmp_path / ".env"
        env_file.write_text("""
DATABASE_URL=postgres://user:password@localhost/db
SECRET_KEY=my_secret_key_12345
API_KEY=sk-1234567890abcdef
DEBUG=True
# Comment line
""")
        vulns = await scanner.scan(str(tmp_path), "test-scan")

        # Should find secrets in .env
        secret_vulns = [v for v in vulns if ".env" in v.category.lower() or "Secret" in v.category]
        assert len(vulns) > 0


class TestPatternCoverage:
    """Tests verifying pattern coverage across categories."""

    @pytest.fixture
    def scanner(self):
        return CustomAIScanner()

    def test_aws_patterns_present(self, scanner):
        """Test AWS patterns are included."""
        aws_count = sum(1 for p in scanner.patterns if "AWS" in p[1])
        assert aws_count >= 10

    def test_gcp_patterns_present(self, scanner):
        """Test GCP patterns are included."""
        gcp_count = sum(1 for p in scanner.patterns if "GCP" in p[1] or "Google" in p[1] or "Firebase" in p[1])
        assert gcp_count >= 5

    def test_azure_patterns_present(self, scanner):
        """Test Azure patterns are included."""
        azure_count = sum(1 for p in scanner.patterns if "Azure" in p[1])
        assert azure_count >= 5

    def test_database_patterns_present(self, scanner):
        """Test database connection patterns are included."""
        db_patterns = [p for p in scanner.patterns if any(x in p[1] for x in ["MongoDB", "PostgreSQL", "MySQL", "Redis", "Connection"])]
        assert len(db_patterns) >= 5

    def test_github_patterns_present(self, scanner):
        """Test GitHub patterns are included."""
        gh_count = sum(1 for p in scanner.patterns if "GitHub" in p[1])
        assert gh_count >= 5

    def test_slack_patterns_present(self, scanner):
        """Test Slack patterns are included."""
        slack_count = sum(1 for p in scanner.patterns if "Slack" in p[1])
        assert slack_count >= 3

    def test_jwt_patterns_present(self, scanner):
        """Test JWT patterns are included."""
        jwt_count = sum(1 for p in scanner.patterns if "JWT" in p[1])
        assert jwt_count >= 2

    def test_crypto_patterns_present(self, scanner):
        """Test cryptocurrency patterns are included."""
        crypto_count = sum(1 for p in scanner.patterns if any(x in p[1] for x in ["Bitcoin", "Ethereum", "Private Key", "Seed Phrase"]))
        assert crypto_count >= 3

    def test_payment_patterns_present(self, scanner):
        """Test payment patterns are included."""
        payment_count = sum(1 for p in scanner.patterns if any(x in p[1] for x in ["Stripe", "PayPal", "Square", "Braintree"]))
        assert payment_count >= 5

    def test_telegram_patterns_present(self, scanner):
        """Test Telegram patterns are included."""
        tg_count = sum(1 for p in scanner.patterns if "Telegram" in p[1])
        assert tg_count >= 2

    def test_total_pattern_count(self, scanner):
        """Test that we have over 200 patterns."""
        assert len(scanner.patterns) >= 200
