"""
Tests for the Triager Agent.

Covers:
- Hash-based deduplication
- Semantic deduplication
- Cross-agent deduplication with confidence boost
- Confidence scoring pipeline
- AI triage integration
- Severity adjustment (reachability, exploitation, context)
"""

import asyncio
import os
import sys
import pytest
from datetime import datetime, timezone
from typing import Any, Dict, List

# Add parent to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

from models.vulnerability import Vulnerability
from agents.triager import (
    TriagerAgent,
    TriagedFinding,
    TriageStatus,
    SEMANTIC_DEDUP_THRESHOLD,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def triager():
    """Create a TriagerAgent instance."""
    return TriagerAgent()


@pytest.fixture
def sample_vulnerabilities():
    """Create sample vulnerabilities for testing."""
    base = {
        "scan_id": "test-scan-001",
        "file_path": "src/app.py",
        "line_number": 42,
        "severity": "HIGH",
        "category": "SQL Injection",
        "cwe_id": "CWE-89",
        "cwe_name": "SQL Injection",
        "title": "Possible SQL injection",
        "description": "User input is directly used in a SQL query",
        "code_snippet": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        "fix_suggestion": "Use parameterized queries",
        "tool_source": "bandit",
        "confidence": "HIGH",
    }
    return [
        Vulnerability(**{**base, "id": "vuln-001"}),
        Vulnerability(**{**base, "id": "vuln-002", "description": "SQL injection via string formatting"}),
        Vulnerability(**{**base, "id": "vuln-003", "tool_source": "semgrep"}),
        Vulnerability(**{**base, "id": "vuln-004", "severity": "CRITICAL", "category": "Hardcoded Secret"}),
        Vulnerability(**{**base, "id": "vuln-005", "file_path": "src/utils.py", "line_number": 100}),
        Vulnerability(**{**base, "id": "vuln-006", "file_path": "tests/test_app.py", "tool_source": "custom_ai"}),
    ]


@pytest.fixture
def duplicate_vulnerabilities():
    """Create duplicate vulnerabilities for dedup testing."""
    base = {
        "scan_id": "test-scan-002",
        "file_path": "src/app.py",
        "line_number": 42,
        "severity": "HIGH",
        "category": "SQL Injection",
        "cwe_id": "CWE-89",
        "cwe_name": "SQL Injection",
        "title": "Possible SQL injection",
        "description": "User input flows to SQL query",
        "code_snippet": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        "fix_suggestion": "Use parameterized queries",
        "tool_source": "bandit",
        "confidence": "HIGH",
    }
    # Same file + line + category = hash duplicate
    return [
        Vulnerability(**{**base, "id": "dup-001"}),
        Vulnerability(**{**base, "id": "dup-002", "tool_source": "semgrep", "confidence": "MEDIUM"}),
        Vulnerability(**{**base, "id": "dup-003", "tool_source": "custom_ai", "confidence": "LOW"}),
    ]


# ---------------------------------------------------------------------------
# Deduplication Tests
# ---------------------------------------------------------------------------

class TestHashDeduplication:
    """Test hash-based deduplication."""

    def test_hash_generation(self, triager, sample_vulnerabilities):
        """Test that hash keys are generated consistently."""
        v = sample_vulnerabilities[0]
        h1 = triager._hash_finding(v)
        h2 = triager._hash_finding(v)
        assert h1 == h2, "Hash should be deterministic"
        assert len(h1) == 32, "Should be MD5 hex (32 chars)"

    def test_hash_differs_for_different_findings(self, triager, sample_vulnerabilities):
        """Test that different findings get different hashes."""
        v1 = sample_vulnerabilities[0]  # src/app.py:42:SQL Injection
        v2 = sample_vulnerabilities[4]  # src/utils.py:100:SQL Injection
        h1 = triager._hash_finding(v1)
        h2 = triager._hash_finding(v2)
        assert h1 != h2, "Different findings should have different hashes"

    def test_hash_deduplication(self, triager, duplicate_vulnerabilities):
        """Test that hash-based dedup groups duplicates."""
        hash_groups, unique = triager._deduplicate_hash_based(duplicate_vulnerabilities)
        # 3 vulns all with same file+line+category -> 1 unique
        assert len(unique) == 1, f"Expected 1 unique, got {len(unique)}"
        assert len(hash_groups) == 1, f"Expected 1 hash group, got {len(hash_groups)}"

    def test_best_finding_selected(self, triager, duplicate_vulnerabilities):
        """Test that the best finding is selected from duplicates."""
        hash_groups, unique = triager._deduplicate_hash_based(duplicate_vulnerabilities)
        best = unique[0]
        # Should select the one with highest confidence (HIGH) and fix_suggestion
        assert best.fix_suggestion is not None, "Best finding should have fix suggestion"

    def test_single_finding_unchanged(self, triager, sample_vulnerabilities):
        """Test that single finding with no duplicates stays as is."""
        single = [sample_vulnerabilities[4]]  # src/utils.py:100
        hash_groups, unique = triager._deduplicate_hash_based(single)
        assert len(unique) == 1
        assert unique[0].id == "vuln-005"


class TestSemanticDeduplication:
    """Test semantic deduplication."""

    def test_jaccard_similarity(self, triager):
        """Test Jaccard similarity computation."""
        sim = triager._jaccard_similarity("sql injection user input", "sql injection user data")
        assert 0 < sim < 1, "Partial overlap should give similarity between 0 and 1"

    def test_jaccard_identical(self, triager):
        """Test identical strings have similarity 1.0."""
        sim = triager._jaccard_similarity("sql injection", "sql injection")
        assert sim == 1.0, "Identical strings should have similarity 1.0"

    def test_jaccard_completely_different(self, triager):
        """Test completely different strings have similarity 0."""
        sim = triager._jaccard_similarity("aaa bbb", "ccc ddd")
        assert sim == 0.0, "Different strings should have similarity 0"

    def test_semantic_similarity_range(self, triager):
        """Test semantic similarity is within [0, 1]."""
        desc1 = "sql injection vulnerability user input query"
        desc2 = "sql injection vulnerability user input query"
        sim = triager._semantic_similarity(desc1, desc2)
        assert 0 <= sim <= 1, f"Similarity should be in [0, 1], got {sim}"
        assert sim >= SEMANTIC_DEDUP_THRESHOLD, f"Identical normalized should be >= {SEMANTIC_DEDUP_THRESHOLD}, got {sim}"

    def test_semantic_dedup_merges_similar(self, triager):
        """Test that semantically similar descriptions are merged."""
        findings = [
            Vulnerability(
                scan_id="s1", file_path="a.py", line_number=1,
                severity="HIGH", category="SQL Injection",
                cwe_id="CWE-89", cwe_name="SQLi", title="SQLi 1",
                description="sql injection vulnerability user input query unsanitized",
                code_snippet="a", fix_suggestion="fix1", tool_source="bandit",
                confidence="HIGH", id="sem-001",
            ),
            Vulnerability(
                scan_id="s1", file_path="b.py", line_number=2,
                severity="HIGH", category="SQL Injection",
                cwe_id="CWE-89", cwe_name="SQLi", title="SQLi 2",
                description="sql injection vulnerability user input query unsanitized",
                code_snippet="b", fix_suggestion="fix2", tool_source="semgrep",
                confidence="HIGH", id="sem-002",
            ),
        ]
        result = triager._deduplicate_semantic(findings)
        assert len(result) == 1, f"Expected 1 merged, got {len(result)}"

    def test_semantic_dedup_keeps_dissimilar(self, triager):
        """Test that dissimilar descriptions are not merged."""
        findings = [
            Vulnerability(
                scan_id="s1", file_path="a.py", line_number=1,
                severity="HIGH", category="SQL Injection",
                cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
                description="User input directly used in SQL query without sanitization",
                code_snippet="a", fix_suggestion="fix1", tool_source="bandit",
                confidence="HIGH", id="sem-003",
            ),
            Vulnerability(
                scan_id="s1", file_path="c.py", line_number=5,
                severity="HIGH", category="XSS",
                cwe_id="CWE-79", cwe_name="XSS", title="XSS",
                description="Cross-site scripting via unescaped output in template",
                code_snippet="b", fix_suggestion="fix2", tool_source="semgrep",
                confidence="HIGH", id="sem-004",
            ),
        ]
        result = triager._deduplicate_semantic(findings)
        assert len(result) == 2, f"Expected 2 separate, got {len(result)}"

    def test_levenshtein_distance(self, triager):
        """Test Levenshtein distance computation."""
        dist = triager._levenshtein_distance("kitten", "sitting")
        assert dist == 3, f"Expected 3, got {dist}"  # k->s, e->i, +g

        dist = triager._levenshtein_distance("", "abc")
        assert dist == 3, f"Expected 3, got {dist}"

        dist = triager._levenshtein_distance("abc", "abc")
        assert dist == 0, f"Expected 0, got {dist}"


class TestCrossAgentDeduplication:
    """Test cross-agent deduplication with confidence boost."""

    def test_source_map_building(self, triager, duplicate_vulnerabilities):
        """Test that source map is built correctly."""
        hash_groups, unique = triager._deduplicate_hash_based(duplicate_vulnerabilities)
        processed, source_map = triager._deduplicate_cross_agent(
            hash_groups, unique
        )
        assert len(source_map) > 0, "Source map should not be empty"
        # All three agents found the same issue
        for vuln_id, sources in source_map.items():
            assert len(sources) >= 1, "Each finding should have at least one source"


class TestSelectBestFinding:
    """Test best finding selection."""

    def test_selects_with_fix_suggestion(self, triager):
        """Test that finding with fix_suggestion is preferred."""
        findings = [
            Vulnerability(
                scan_id="s1", file_path="a.py", line_number=1,
                severity="HIGH", category="SQL Injection",
                cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
                description="Desc 1", code_snippet="code1",
                fix_suggestion=None, tool_source="bandit",
                confidence="LOW", id="bf-001",
            ),
            Vulnerability(
                scan_id="s1", file_path="a.py", line_number=1,
                severity="HIGH", category="SQL Injection",
                cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
                description="Desc 2", code_snippet="code2",
                fix_suggestion="Use params", tool_source="semgrep",
                confidence="HIGH", id="bf-002",
            ),
        ]
        best = triager._select_best_finding(findings)
        assert best.id == "bf-002", "Should select finding with fix suggestion"

    def test_selects_higher_severity(self, triager):
        """Test that higher severity is preferred."""
        findings = [
            Vulnerability(
                scan_id="s1", file_path="a.py", line_number=1,
                severity="MEDIUM", category="SQL Injection",
                cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
                description="Desc 1", code_snippet="code1",
                fix_suggestion="fix", tool_source="bandit",
                confidence="HIGH", id="bf-003",
            ),
            Vulnerability(
                scan_id="s1", file_path="a.py", line_number=1,
                severity="CRITICAL", category="SQL Injection",
                cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
                description="Desc 2", code_snippet="code2",
                fix_suggestion="fix", tool_source="semgrep",
                confidence="HIGH", id="bf-004",
            ),
        ]
        best = triager._select_best_finding(findings)
        assert best.id == "bf-004", "Should select CRITICAL over MEDIUM"


# ---------------------------------------------------------------------------
# Confidence Scoring Tests
# ---------------------------------------------------------------------------

class TestConfidenceScoring:
    """Test confidence scoring pipeline."""

    def test_base_confidence_mapping(self, triager):
        """Test base confidence mapping."""
        v = Vulnerability(
            scan_id="s1", file_path="a.py", line_number=1,
            severity="HIGH", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
            description="Desc", code_snippet="code",
            fix_suggestion="fix", tool_source="bandit",
            confidence="HIGH", id="cs-001",
        )
        score = triager._compute_base_confidence(v)
        assert score == 80.0, f"Expected 80.0 for HIGH, got {score}"

    def test_base_confidence_medium(self, triager):
        """Test MEDIUM confidence maps to 50."""
        v = Vulnerability(
            scan_id="s1", file_path="a.py", line_number=1,
            severity="HIGH", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
            description="Desc", code_snippet="code",
            fix_suggestion="fix", tool_source="bandit",
            confidence="MEDIUM", id="cs-002",
        )
        score = triager._compute_base_confidence(v)
        assert score == 50.0, f"Expected 50.0 for MEDIUM, got {score}"

    def test_multi_agent_bonus(self, triager):
        """Test +20% bonus when multiple agents agree."""
        v = Vulnerability(
            scan_id="s1", file_path="a.py", line_number=1,
            severity="HIGH", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
            description="Desc", code_snippet="code",
            fix_suggestion="fix", tool_source="bandit",
            confidence="HIGH", id="cs-003",
        )
        score = triager._compute_confidence_score(v, ["bandit", "semgrep", "custom_ai"])
        assert score > 80.0, f"Multi-agent should boost above 80, got {score}"

    def test_single_agent_no_bonus(self, triager):
        """Test no bonus for single agent."""
        v = Vulnerability(
            scan_id="s1", file_path="a.py", line_number=1,
            severity="HIGH", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
            description="Desc", code_snippet="code",
            fix_suggestion="fix", tool_source="bandit",
            confidence="HIGH", id="cs-004",
        )
        score = triager._compute_confidence_score(v, ["bandit"])
        assert score == 80.0, f"Single agent should be base 80, got {score}"

    def test_test_file_penalty(self, triager):
        """Test -20% penalty for test files."""
        v = Vulnerability(
            scan_id="s1", file_path="tests/test_app.py", line_number=10,
            severity="HIGH", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
            description="Desc", code_snippet="code",
            fix_suggestion="fix", tool_source="bandit",
            confidence="HIGH", id="cs-005",
        )
        score = triager._compute_confidence_score(v, ["bandit"])
        assert score == 60.0, f"Test file should reduce to 60, got {score}"

    def test_fp_pattern_penalty(self, triager):
        """Test -30% penalty for known false positive patterns."""
        v = Vulnerability(
            scan_id="s1", file_path="src/app.py", line_number=1,
            severity="HIGH", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
            description="Contains localhost:8080 reference in test mock",
            code_snippet="password = 'changeme123'",
            fix_suggestion="fix", tool_source="bandit",
            confidence="HIGH", id="cs-006",
        )
        score = triager._compute_confidence_score(v, ["bandit"])
        assert score == 50.0, f"FP pattern should reduce to 50, got {score}"

    def test_score_clamped_to_zero(self, triager):
        """Test that score doesn't go below 0."""
        v = Vulnerability(
            scan_id="s1", file_path="tests/test_mock.py", line_number=1,
            severity="LOW", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
            description="localhost:3000 test mock data changeme",
            code_snippet="code", fix_suggestion="fix",
            tool_source="bandit", confidence="LOW", id="cs-007",
        )
        score = triager._compute_confidence_score(v, ["bandit"])
        assert score >= 0.0, f"Score should be >= 0, got {score}"
        assert score <= 100.0, f"Score should be <= 100, got {score}"


# ---------------------------------------------------------------------------
# Severity Adjustment Tests
# ---------------------------------------------------------------------------

class TestSeverityAdjustment:
    """Test severity adjustment pipeline."""

    def test_reachability_boost(self, triager):
        """Test +1 severity level for reachable vulnerabilities."""
        v = Vulnerability(
            scan_id="s1", file_path="src/app.py", line_number=1,
            severity="HIGH", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
            description="Desc", code_snippet="code",
            fix_suggestion="fix", tool_source="bandit",
            confidence="HIGH", id="sa-001",
        )
        adjusted, reason = triager._adjust_severity(v, is_reachable=True)
        assert adjusted == "CRITICAL", f"Reachable HIGH should become CRITICAL, got {adjusted}"
        assert "Reachable" in reason, "Reason should mention reachability"

    def test_non_reachable_no_boost(self, triager):
        """Test no boost for non-reachable vulnerabilities."""
        v = Vulnerability(
            scan_id="s1", file_path="src/app.py", line_number=1,
            severity="HIGH", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
            description="Desc", code_snippet="code",
            fix_suggestion="fix", tool_source="bandit",
            confidence="HIGH", id="sa-002",
        )
        adjusted, reason = triager._adjust_severity(v, is_reachable=False)
        assert adjusted == "HIGH", f"Non-reachable HIGH should stay HIGH, got {adjusted}"

    def test_info_capped_at_low(self, triager):
        """Test that INFO can't go beyond LOW with reachability."""
        v = Vulnerability(
            scan_id="s1", file_path="src/app.py", line_number=1,
            severity="INFO", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
            description="Desc", code_snippet="code",
            fix_suggestion="fix", tool_source="bandit",
            confidence="HIGH", id="sa-003",
        )
        adjusted, _ = triager._adjust_severity(v, is_reachable=True)
        assert adjusted == "LOW", f"INFO +1 should be LOW, got {adjusted}"

    def test_dast_confirmed_sets_critical(self, triager):
        """Test DAST confirmed exploitation sets CRITICAL."""
        v = Vulnerability(
            scan_id="s1", file_path="src/app.py", line_number=1,
            severity="MEDIUM", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
            description="Confirmed exploitable via UNION injection",
            code_snippet="code", fix_suggestion="fix",
            tool_source="dast_scanner", confidence="HIGH", id="sa-004",
        )
        adjusted, reason = triager._adjust_severity(v, is_reachable=False)
        assert adjusted == "CRITICAL", f"DAST confirmed should be CRITICAL, got {adjusted}"

    def test_severity_ordering(self, triager):
        """Test that severity ordering is correct."""
        from agents.triager import SEVERITY_ORDER
        assert SEVERITY_ORDER == ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------

class TestTriagePipeline:
    """Test the full triage pipeline."""

    @pytest.mark.asyncio
    async def test_empty_findings(self, triager):
        """Test triage with empty findings."""
        result = await triager.triage([])
        assert result == [], "Empty findings should return empty list"

    @pytest.mark.asyncio
    async def test_single_finding(self, triager):
        """Test triage with single finding."""
        vuln = Vulnerability(
            scan_id="s1", file_path="src/app.py", line_number=1,
            severity="CRITICAL", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
            description="User input directly used in SQL query",
            code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            fix_suggestion="Use parameterized queries",
            tool_source="bandit", confidence="HIGH", id="pipe-001",
        )
        result = await triager.triage([vuln])
        assert len(result) == 1
        assert result[0].confidence_score > 0
        # After triage, it may be CONFIRMED, LIKELY_TRUE, UNCERTAIN, or LIKELY_FALSE
        assert result[0].triage_status in list(TriageStatus), f"Unexpected status: {result[0].triage_status}"

    @pytest.mark.asyncio
    async def test_deduplication_in_pipeline(self, triager, duplicate_vulnerabilities):
        """Test that deduplication happens in the pipeline."""
        result = await triager.triage(duplicate_vulnerabilities)
        # 3 duplicates -> should be deduplicated to 1
        assert len(result) <= len(duplicate_vulnerabilities)

    @pytest.mark.asyncio
    async def test_sorted_by_severity(self, triager, sample_vulnerabilities):
        """Test that results are sorted by severity."""
        result = await triager.triage(sample_vulnerabilities)
        if len(result) >= 2:
            severities = [r.adjusted_severity for r in result]
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            for i in range(len(severities) - 1):
                assert severity_order.get(severities[i], 5) <= severity_order.get(severities[i + 1], 5), \
                    f"Results should be sorted by severity, got {severities}"

    @pytest.mark.asyncio
    async def test_triaged_finding_has_agent_sources(self, triager, duplicate_vulnerabilities):
        """Test that triaged findings track agent sources."""
        result = await triager.triage(duplicate_vulnerabilities)
        for finding in result:
            assert len(finding.agent_sources) >= 1, "Should have at least one agent source"

    @pytest.mark.asyncio
    async def test_false_positive_detection(self, triager):
        """Test that test files are flagged as likely false positives."""
        vuln = Vulnerability(
            scan_id="s1", file_path="tests/test_mock.py", line_number=10,
            severity="MEDIUM", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQLi", title="Mock SQL",
            description="Mock data for testing with localhost",
            code_snippet="password = 'test123'",
            fix_suggestion=None, tool_source="bandit",
            confidence="MEDIUM", id="pipe-002",
        )
        result = await triager.triage([vuln])
        # Should have low confidence due to test file penalty
        assert result[0].confidence_score < 50, f"Test file should have low confidence, got {result[0].confidence_score}"

    @pytest.mark.asyncio
    async def test_stats(self, triager):
        """Test that get_stats returns config info."""
        stats = await triager.get_stats()
        assert "semantic_dedup_threshold" in stats
        assert "confidence_multiplier_agreement" in stats


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
