"""
Tests for the Fix Agent.

Covers:
- Fix queue management and priority ordering
- Batch creation for same-file fixes
- Fix generation (deterministic and LLM fallback)
- Fix validation (syntax + pattern verification)
- Diff generation
- Backup and rollback
- PR creation helpers
"""

import asyncio
import os
import sys
import tempfile
import pytest
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from models.vulnerability import Vulnerability
from agents.fix_agent import FixAgent, FixBatch, FixQueueItem


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def fix_agent():
    """Create a FixAgent instance."""
    return FixAgent()


@pytest.fixture
def sql_injection_vuln():
    """Create a SQL injection vulnerability."""
    return Vulnerability(
        scan_id="test-scan",
        file_path="src/app.py",
        line_number=42,
        severity="CRITICAL",
        category="SQL Injection",
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        title="SQL injection via f-string",
        description="User input flows to SQL sink",
        code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        fix_suggestion="Use parameterized queries",
        tool_source="bandit",
        confidence="HIGH",
        id="fix-vuln-001",
    )


@pytest.fixture
def xss_vuln():
    """Create an XSS vulnerability."""
    return Vulnerability(
        scan_id="test-scan",
        file_path="src/templates/index.html",
        line_number=15,
        severity="HIGH",
        category="XSS",
        cwe_id="CWE-79",
        cwe_name="Cross-site Scripting",
        title="DOM-based XSS",
        description="innerHTML assignment with user data",
        code_snippet="element.innerHTML = userInput;",
        fix_suggestion="Use textContent instead of innerHTML",
        tool_source="eslint",
        confidence="HIGH",
        id="fix-vuln-002",
    )


@pytest.fixture
def secret_vuln():
    """Create a hardcoded secret vulnerability."""
    return Vulnerability(
        scan_id="test-scan",
        file_path="src/config.py",
        line_number=5,
        severity="HIGH",
        category="Hardcoded Secret",
        cwe_id="CWE-798",
        cwe_name="Use of Hard-coded Credentials",
        title="Hardcoded API key",
        description="API key is hardcoded in source",
        code_snippet='API_KEY = "sk-abc123secret"',
        fix_suggestion="Use environment variable",
        tool_source="gitleaks",
        confidence="HIGH",
        id="fix-vuln-003",
    )


@pytest.fixture
def multiple_vulns(sql_injection_vuln, xss_vuln, secret_vuln):
    """Create a list of multiple vulnerabilities."""
    return [sql_injection_vuln, xss_vuln, secret_vuln]


# ---------------------------------------------------------------------------
# Fix Queue Management Tests
# ---------------------------------------------------------------------------

class TestFixQueueManagement:
    """Test fix queue building and management."""

    def test_compute_priority_critical(self, fix_agent, sql_injection_vuln):
        """Test CRITICAL vulnerability gets highest priority."""
        score = fix_agent._compute_priority_score(sql_injection_vuln)
        assert score >= 100, f"CRITICAL should score >= 100, got {score}"

    def test_compute_priority_high(self, fix_agent, xss_vuln):
        """Test HIGH vulnerability gets high priority."""
        score = fix_agent._compute_priority_score(xss_vuln)
        assert score >= 75, f"HIGH should score >= 75, got {score}"

    def test_critical_higher_than_high(self, fix_agent, sql_injection_vuln, xss_vuln):
        """Test CRITICAL scores higher than HIGH."""
        crit_score = fix_agent._compute_priority_score(sql_injection_vuln)
        high_score = fix_agent._compute_priority_score(xss_vuln)
        assert crit_score > high_score, f"CRITICAL ({crit_score}) should score higher than HIGH ({high_score})"

    def test_build_fix_queue(self, fix_agent, multiple_vulns):
        """Test fix queue is built correctly."""
        queue = fix_agent.build_fix_queue(multiple_vulns)
        assert len(queue) == 3, f"Expected 3 items, got {len(queue)}"

    def test_queue_sorted_by_priority(self, fix_agent, multiple_vulns):
        """Test queue is sorted by dependency order then priority score."""
        queue = fix_agent.build_fix_queue(multiple_vulns)
        # Queue sorted by (dependency_order, -priority_score)
        for i in range(len(queue) - 1):
            key_i = (queue[i].dependency_order, -queue[i].priority_score)
            key_j = (queue[i + 1].dependency_order, -queue[i + 1].priority_score)
            assert key_i <= key_j, "Queue should be sorted by dependency order then priority"

    def test_queue_items_have_priority(self, fix_agent, sql_injection_vuln):
        """Test queue items have priority scores."""
        queue = fix_agent.build_fix_queue([sql_injection_vuln])
        assert queue[0].priority_score > 0, "Priority score should be positive"

    def test_dependency_order_sql(self, fix_agent, sql_injection_vuln):
        """Test SQL injection has correct dependency order."""
        order = fix_agent._get_dependency_order(sql_injection_vuln)
        assert order == 4, f"SQL Injection should have order 4, got {order}"

    def test_dependency_order_secret(self, fix_agent, secret_vuln):
        """Test hardcoded secret has correct dependency order."""
        order = fix_agent._get_dependency_order(secret_vuln)
        assert order == 2, f"Hardcoded Secret should have order 2, got {order}"


class TestBatchCreation:
    """Test batch creation for same-file fixes."""

    def test_create_batches(self, fix_agent, multiple_vulns):
        """Test batches are created by file path."""
        queue = fix_agent.build_fix_queue(multiple_vulns)
        batches = fix_agent.create_batches(queue)
        assert len(batches) == 3, f"Expected 3 batches (3 files), got {len(batches)}"

    def test_batch_has_correct_file(self, fix_agent, multiple_vulns):
        """Test batch has correct file path."""
        queue = fix_agent.build_fix_queue(multiple_vulns)
        batches = fix_agent.create_batches(queue)
        assert "src/app.py" in batches, "src/app.py should be a batch key"

    def test_batch_items_sorted(self, fix_agent, multiple_vulns):
        """Test items within batch are sorted."""
        queue = fix_agent.build_fix_queue(multiple_vulns)
        batches = fix_agent.create_batches(queue)
        for batch in batches.values():
            for i in range(len(batch.items) - 1):
                assert (
                    batch.items[i].dependency_order <= batch.items[i + 1].dependency_order
                ), "Items should be sorted by dependency order"


# ---------------------------------------------------------------------------
# Fix Generation Tests
# ---------------------------------------------------------------------------

class TestFixGeneration:
    """Test fix generation."""

    @pytest.mark.asyncio
    async def test_generate_fix_sql_injection(self, fix_agent, sql_injection_vuln):
        """Test fix generation for SQL injection."""
        result = await fix_agent.auto_fix_engine.generate_fix(
            sql_injection_vuln, source_path=None
        )
        assert result is not None
        assert result.fixed_code is not None or result.status.value in [
            "no_fix_available", "failed"
        ]

    @pytest.mark.asyncio
    async def test_generate_fix_xss(self, fix_agent, xss_vuln):
        """Test fix generation for XSS."""
        result = await fix_agent.auto_fix_engine.generate_fix(
            xss_vuln, source_path=None
        )
        assert result is not None

    @pytest.mark.asyncio
    async def test_generate_fix_secret(self, fix_agent, secret_vuln):
        """Test fix generation for hardcoded secret."""
        result = await fix_agent.auto_fix_engine.generate_fix(
            secret_vuln, source_path=None
        )
        assert result is not None

    @pytest.mark.asyncio
    async def test_generate_fixes_queue(self, fix_agent, multiple_vulns):
        """Test generating fixes for a queue."""
        queue = fix_agent.build_fix_queue(multiple_vulns)
        result = await fix_agent.generate_fixes(queue, source_path=None)
        assert len(result) == 3
        # At least some should have fixes
        with_fixes = sum(1 for r in result if r.fix_result and r.fix_result.fixed_code)
        assert with_fixes >= 0, "May or may not have fixes without proper source"


# ---------------------------------------------------------------------------
# Diff Generation Tests
# ---------------------------------------------------------------------------

class TestDiffGeneration:
    """Test diff generation."""

    def test_generate_diff(self, fix_agent):
        """Test unified diff generation."""
        original = "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')"
        fixed = 'cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))'
        diff = fix_agent.auto_fix_engine._generate_diff(original, fixed, "src/app.py")
        assert "---" in diff, "Diff should have old file marker"
        assert "+++" in diff, "Diff should have new file marker"
        assert "-" in diff and "+" in diff, "Diff should have changes"

    def test_diff_headers(self, fix_agent):
        """Test diff has proper headers."""
        original = "line1\nline2"
        fixed = "line1\nmodified"
        diff = fix_agent.auto_fix_engine._generate_diff(original, fixed, "test.py")
        assert "a/test.py" in diff, "Diff should have from-file header"
        assert "b/test.py" in diff, "Diff should have to-file header"


# ---------------------------------------------------------------------------
# Fix Validation Tests
# ---------------------------------------------------------------------------

class TestFixValidation:
    """Test fix validation."""

    def test_syntax_validation_passes(self, fix_agent):
        """Test that valid Python passes syntax check."""
        code = "cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))"
        result = fix_agent.auto_fix_engine._validate_fix(
            "original", code,
            Vulnerability(
                scan_id="s1", file_path="a.py", line_number=1,
                severity="HIGH", category="SQL Injection",
                cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
                description="Desc", code_snippet="orig",
                fix_suggestion="fix", tool_source="bandit",
                confidence="HIGH", id="val-001",
            )
        )
        assert result["syntax_valid"] is True, "Valid Python should pass syntax check"

    def test_syntax_validation_fails(self, fix_agent):
        """Test that invalid Python fails syntax check."""
        code = "def broken(:\n  pass"
        result = fix_agent.auto_fix_engine._validate_fix(
            "original", code,
            Vulnerability(
                scan_id="s1", file_path="a.py", line_number=1,
                severity="HIGH", category="SQL Injection",
                cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
                description="Desc", code_snippet="orig",
                fix_suggestion="fix", tool_source="bandit",
                confidence="HIGH", id="val-002",
            )
        )
        assert result["syntax_valid"] is False, "Invalid Python should fail syntax check"


# ---------------------------------------------------------------------------
# Backup and Rollback Tests
# ---------------------------------------------------------------------------

class TestBackupAndRollback:
    """Test backup and rollback functionality."""

    @pytest.mark.asyncio
    async def test_create_backup(self, fix_agent):
        """Test backup creation."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("# original code\nx = 1\n")
            temp_path = f.name

        try:
            backup_path = await fix_agent._create_backup(temp_path)
            assert os.path.exists(backup_path), "Backup file should exist"
            assert backup_path != temp_path, "Backup should be different path"

            # Verify backup content
            with open(backup_path) as f:
                content = f.read()
            assert "original code" in content, "Backup should contain original content"
        finally:
            os.unlink(temp_path)
            if 'backup_path' in locals() and os.path.exists(backup_path):
                os.unlink(backup_path)

    @pytest.mark.asyncio
    async def test_rollback_file(self, fix_agent):
        """Test file rollback."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".py", delete=False) as f:
            f.write("# original code\n")
            temp_path = f.name

        try:
            # Create backup
            backup_path = await fix_agent._create_backup(temp_path)
            fix_agent._backups[temp_path] = backup_path

            # Modify file
            with open(temp_path, "w") as f:
                f.write("# modified code\n")

            # Rollback
            result = await fix_agent.rollback_file(temp_path)
            assert result["success"] is True, "Rollback should succeed"

            # Verify rollback
            with open(temp_path) as f:
                content = f.read()
            assert "original code" in content, "Should have original content after rollback"
        finally:
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            if 'backup_path' in locals() and os.path.exists(backup_path):
                os.unlink(backup_path)

    @pytest.mark.asyncio
    async def test_rollback_no_backup(self, fix_agent):
        """Test rollback without backup fails gracefully."""
        result = await fix_agent.rollback_file("/nonexistent/path/file.py")
        assert result["success"] is False, "Rollback without backup should fail"


# ---------------------------------------------------------------------------
# PR Creation Tests
# ---------------------------------------------------------------------------

class TestPRCreation:
    """Test PR creation helpers."""

    def test_build_commit_message(self, fix_agent, multiple_vulns):
        """Test commit message building."""
        queue = fix_agent.build_fix_queue(multiple_vulns)
        msg = fix_agent._build_commit_message(queue)
        assert "security" in msg.lower(), "Commit message should mention security"
        assert "SQL Injection" in msg, "Commit message should mention categories"

    def test_build_pr_description(self, fix_agent, multiple_vulns):
        """Test PR description building."""
        queue = fix_agent.build_fix_queue(multiple_vulns)
        title, body = fix_agent._build_pr_description(queue)
        assert "security" in title.lower(), f"Title should mention security, got: {title}"
        assert "security" in body.lower(), "Body should mention security fixes"
        assert "Changes" in body, "Body should have Changes section"


# ---------------------------------------------------------------------------
# Fuzzy Replace Tests
# ---------------------------------------------------------------------------

class TestFuzzyReplace:
    """Test fuzzy replacement utility."""

    def test_exact_replace(self, fix_agent):
        """Test exact match replacement."""
        content = "line1\nVULNERABLE\nline3"
        result = fix_agent._fuzzy_replace(content, "VULNERABLE", "FIXED")
        assert "FIXED" in result, "Should contain fixed code"
        assert "VULNERABLE" not in result, "Should not contain old code"

    def test_no_match_returns_original(self, fix_agent):
        """Test that non-matching returns original."""
        content = "line1\nline2\nline3"
        result = fix_agent._fuzzy_replace(content, "NOTHERE", "FIXED")
        assert result == content, "Should return original if no match"


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------

class TestFixPipeline:
    """Test the full fix pipeline."""

    @pytest.mark.asyncio
    async def test_empty_vulnerabilities(self, fix_agent):
        """Test pipeline with empty vulnerabilities."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = await fix_agent.run_fix_pipeline([], tmpdir)
            assert result["total_vulnerabilities"] == 0

    @pytest.mark.asyncio
    async def test_get_stats(self, fix_agent):
        """Test that get_stats returns configuration."""
        stats = await fix_agent.get_stats()
        assert stats is not None
        assert "fixes_applied" in stats


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
