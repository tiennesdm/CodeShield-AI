"""
Tests for the Intelligent Vulnerability Prioritization Engine (prioritizer.py).

Covers:
- Context-aware scoring (endpoint exposure, auth requirements, user input)
- Threat intelligence integration (CISA KEV, EPSS)
- Business impact analysis (production indicators, PII, regulatory)
- Priority band mapping (P0-P4)
- Priority score calculation (0-100)
- ContextAnalyzer utility methods
- BusinessImpactAnalyzer utility methods
- ThreatIntelProvider utility methods
"""

import asyncio
import os
import tempfile
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from prioritizer import (
    BusinessImpactAnalyzer,
    ContextAnalyzer,
    PriorityBand,
    PrioritizationEngine,
    PrioritizedVulnerability,
    ThreatIntelProvider,
)
from models.vulnerability import Vulnerability


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def prioritization_engine() -> PrioritizationEngine:
    """Fresh prioritization engine."""
    return PrioritizationEngine()


@pytest.fixture
def context_analyzer() -> ContextAnalyzer:
    """Fresh context analyzer."""
    return ContextAnalyzer()


@pytest.fixture
def business_analyzer() -> BusinessImpactAnalyzer:
    """Fresh business impact analyzer."""
    return BusinessImpactAnalyzer()


@pytest.fixture
def threat_provider() -> ThreatIntelProvider:
    """Fresh threat intel provider."""
    return ThreatIntelProvider()


@pytest.fixture
def sample_critical_vuln() -> Vulnerability:
    """Critical severity vulnerability."""
    return Vulnerability(
        scan_id="scan-001",
        file_path="src/api.py",
        line_number=42,
        severity="CRITICAL",
        category="SQL Injection",
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        title="Critical SQL Injection",
        description="User input directly in SQL query",
        code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
        fix_suggestion="Use parameterized queries",
        tool_source="bandit",
        confidence="HIGH",
    )


@pytest.fixture
def sample_high_vuln() -> Vulnerability:
    """High severity vulnerability."""
    return Vulnerability(
        scan_id="scan-001",
        file_path="src/auth.py",
        line_number=25,
        severity="HIGH",
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
def sample_low_vuln() -> Vulnerability:
    """Low severity vulnerability."""
    return Vulnerability(
        scan_id="scan-001",
        file_path="src/utils.py",
        line_number=100,
        severity="LOW",
        category="Information Disclosure",
        cwe_id="CWE-200",
        cwe_name="Information Exposure",
        title="Verbose error message",
        description="Error message reveals internal details",
        code_snippet="return {'error': str(e), 'traceback': tb}",
        fix_suggestion="Return generic error messages",
        tool_source="bandit",
        confidence="MEDIUM",
    )


# ---------------------------------------------------------------------------
# ThreatIntelProvider Tests
# ---------------------------------------------------------------------------

class TestThreatIntelProvider:
    """Test threat intelligence provider."""

    @pytest.mark.asyncio
    async def test_check_cisa_kev_known_cve(self, threat_provider: ThreatIntelProvider) -> None:
        """Should detect known CVEs in CISA KEV."""
        result = await threat_provider.check_cisa_kev("CVE-2023-32629")
        assert result is True

    @pytest.mark.asyncio
    async def test_check_cisa_kev_unknown_cve(self, threat_provider: ThreatIntelProvider) -> None:
        """Should not flag unknown CVEs."""
        result = await threat_provider.check_cisa_kev("CVE-1900-00001")
        assert result is False

    @pytest.mark.asyncio
    async def test_get_epss_score_critical(self, threat_provider: ThreatIntelProvider) -> None:
        """EPSS score should be between 0 and 1."""
        score = await threat_provider.get_epss_score("CVE-2023-99999")
        assert 0.0 <= score <= 1.0

    @pytest.mark.asyncio
    async def test_exploit_availability(self, threat_provider: ThreatIntelProvider) -> None:
        """Should return exploit availability info."""
        result = await threat_provider.check_exploit_availability("CVE-2023-32629")
        assert isinstance(result, dict)
        assert "exploit_available" in result
        assert "in_cisa_kev" in result

    def test_cache_load(self, threat_provider: ThreatIntelProvider) -> None:
        """Should load cache without errors."""
        cache = threat_provider._load_cache()
        assert "kev" in cache
        assert isinstance(cache["kev"], list)


# ---------------------------------------------------------------------------
# ContextAnalyzer Tests
# ---------------------------------------------------------------------------

class TestContextAnalyzer:
    """Test context analysis utilities."""

    def test_detect_exposed_endpoint_python(self, context_analyzer: ContextAnalyzer) -> None:
        """Should detect Flask route as exposed endpoint."""
        code = "@app.route('/api/users')\ndef get_users():\n    pass"
        result = context_analyzer.analyze_endpoint_exposure(code, "app.py", "python")
        assert result is True

    def test_detect_exposed_endpoint_js(self, context_analyzer: ContextAnalyzer) -> None:
        """Should detect Express route as exposed endpoint."""
        code = "app.get('/api/users', (req, res) => { });"
        result = context_analyzer.analyze_endpoint_exposure(code, "server.js", "javascript")
        assert result is True

    def test_no_endpoint_in_utility(self, context_analyzer: ContextAnalyzer) -> None:
        """Should not flag utility files as endpoints."""
        code = "def helper_function():\n    return 42"
        result = context_analyzer.analyze_endpoint_exposure(code, "utils.py", "python")
        assert result is False

    def test_detect_auth_decorator(self, context_analyzer: ContextAnalyzer) -> None:
        """Should detect auth decorator."""
        code = "@login_required\ndef admin_page():\n    pass"
        result = context_analyzer.analyze_auth_requirement(code, 2)
        assert result is True

    def test_no_auth_decorator(self, context_analyzer: ContextAnalyzer) -> None:
        """Should not detect auth when absent."""
        code = "def public_page():\n    return 'hello'"
        result = context_analyzer.analyze_auth_requirement(code, 2)
        assert result is False

    def test_detect_user_input(self, context_analyzer: ContextAnalyzer) -> None:
        """Should detect user input reachability."""
        code = "user_id = request.args.get('id')\nresult = query(user_id)"
        result = context_analyzer.analyze_user_input_reachability(code, 2)
        assert result is True

    def test_no_user_input(self, context_analyzer: ContextAnalyzer) -> None:
        """Should not flag when user input is absent."""
        code = "result = compute(internal_variable)"
        result = context_analyzer.analyze_user_input_reachability(code, 1)
        assert result is False

    def test_detect_language_python(self, context_analyzer: ContextAnalyzer) -> None:
        """Should detect Python from .py extension."""
        assert context_analyzer._detect_language("test.py") == "python"

    def test_detect_language_js(self, context_analyzer: ContextAnalyzer) -> None:
        """Should detect JavaScript from .js extension."""
        assert context_analyzer._detect_language("test.js") == "javascript"

    def test_detect_language_java(self, context_analyzer: ContextAnalyzer) -> None:
        """Should detect Java from .java extension."""
        assert context_analyzer._detect_language("Test.java") == "java"


# ---------------------------------------------------------------------------
# BusinessImpactAnalyzer Tests
# ---------------------------------------------------------------------------

class TestBusinessImpactAnalyzer:
    """Test business impact analysis utilities."""

    def test_production_indicator_high(self, business_analyzer: BusinessImpactAnalyzer) -> None:
        """Should detect production path."""
        score = business_analyzer.analyze_production_indicator("src/prod/app.py")
        assert score >= 0.7

    def test_production_indicator_low_for_test(self, business_analyzer: BusinessImpactAnalyzer) -> None:
        """Should score low for test files."""
        score = business_analyzer.analyze_production_indicator("tests/test_app.py")
        assert score < 0.5

    def test_data_sensitivity_pii(self, business_analyzer: BusinessImpactAnalyzer) -> None:
        """Should detect PII handling."""
        code = "user_ssn = form['social_security']\nemail = form['email']"
        result = business_analyzer.analyze_data_sensitivity(code)
        assert result["handles_pii"] is True
        assert result["sensitivity_score"] > 0

    def test_data_sensitivity_none(self, business_analyzer: BusinessImpactAnalyzer) -> None:
        """Should not flag non-sensitive code."""
        code = "x = 1 + 2\nprint('hello')"
        result = business_analyzer.analyze_data_sensitivity(code)
        assert result["handles_pii"] is False
        assert result["sensitivity_score"] == 0.0

    def test_data_sensitivity_financial(self, business_analyzer: BusinessImpactAnalyzer) -> None:
        """Should detect financial data handling."""
        code = "process_payment(stripe_token)\nbalance = account.balance"
        result = business_analyzer.analyze_data_sensitivity(code)
        assert result["handles_financial"] is True

    def test_regulatory_gdpr(self, business_analyzer: BusinessImpactAnalyzer) -> None:
        """Should detect GDPR exposure."""
        code = "consent = user.data_subject_request()\nright_to_erasure(request)"
        result = business_analyzer.analyze_regulatory_exposure(code, "app.py")
        assert "GDPR" in result["regulations"]
        assert result["regulatory_score"] > 0

    def test_regulatory_pci(self, business_analyzer: BusinessImpactAnalyzer) -> None:
        """Should detect PCI DSS exposure."""
        code = "charge = process_cardholder_data(token)"
        result = business_analyzer.analyze_regulatory_exposure(code, "payment.py")
        assert "PCI DSS" in result["regulations"]

    def test_regulatory_none(self, business_analyzer: BusinessImpactAnalyzer) -> None:
        """Should not flag non-regulated code."""
        code = "x = compute_sum(a, b)"
        result = business_analyzer.analyze_regulatory_exposure(code, "utils.py")
        assert len(result["regulations"]) == 0


# ---------------------------------------------------------------------------
# Score Calculation Tests
# ---------------------------------------------------------------------------

class TestScoreCalculation:
    """Test priority score calculation."""

    def test_severity_to_base_score_critical(self, prioritization_engine: PrioritizationEngine) -> None:
        """CRITICAL should map to 10.0."""
        assert prioritization_engine._severity_to_base_score("CRITICAL") == 10.0

    def test_severity_to_base_score_high(self, prioritization_engine: PrioritizationEngine) -> None:
        """HIGH should map to 7.5."""
        assert prioritization_engine._severity_to_base_score("HIGH") == 7.5

    def test_severity_to_base_score_medium(self, prioritization_engine: PrioritizationEngine) -> None:
        """MEDIUM should map to 5.0."""
        assert prioritization_engine._severity_to_base_score("MEDIUM") == 5.0

    def test_severity_to_base_score_low(self, prioritization_engine: PrioritizationEngine) -> None:
        """LOW should map to 2.5."""
        assert prioritization_engine._severity_to_base_score("LOW") == 2.5

    def test_severity_to_base_score_info(self, prioritization_engine: PrioritizationEngine) -> None:
        """INFO should map to 1.0."""
        assert prioritization_engine._severity_to_base_score("INFO") == 1.0

    def test_severity_to_base_score_unknown(self, prioritization_engine: PrioritizationEngine) -> None:
        """Unknown severity should default to 5.0."""
        assert prioritization_engine._severity_to_base_score("UNKNOWN") == 5.0


class TestPriorityBands:
    """Test priority band mapping."""

    def test_p0_band(self, prioritization_engine: PrioritizationEngine) -> None:
        """Score >= 80 should be P0."""
        assert prioritization_engine._score_to_band(80) == PriorityBand.P0
        assert prioritization_engine._score_to_band(95) == PriorityBand.P0

    def test_p1_band(self, prioritization_engine: PrioritizationEngine) -> None:
        """Score 60-79 should be P1."""
        assert prioritization_engine._score_to_band(60) == PriorityBand.P1
        assert prioritization_engine._score_to_band(75) == PriorityBand.P1

    def test_p2_band(self, prioritization_engine: PrioritizationEngine) -> None:
        """Score 40-59 should be P2."""
        assert prioritization_engine._score_to_band(40) == PriorityBand.P2
        assert prioritization_engine._score_to_band(55) == PriorityBand.P2

    def test_p3_band(self, prioritization_engine: PrioritizationEngine) -> None:
        """Score 20-39 should be P3."""
        assert prioritization_engine._score_to_band(20) == PriorityBand.P3
        assert prioritization_engine._score_to_band(35) == PriorityBand.P3

    def test_p4_band(self, prioritization_engine: PrioritizationEngine) -> None:
        """Score < 20 should be P4."""
        assert prioritization_engine._score_to_band(0) == PriorityBand.P4
        assert prioritization_engine._score_to_band(19) == PriorityBand.P4


class TestContextScore:
    """Test context factor score computation."""

    def test_exposed_endpoint_high_score(self, prioritization_engine: PrioritizationEngine) -> None:
        """Exposed endpoint with user input should score high."""
        factors = {
            "is_exposed_endpoint": True,
            "user_input_reachable": True,
            "requires_auth": False,
            "is_in_dependency": False,
        }
        score = prioritization_engine._compute_context_score(factors)
        assert score > 0.5

    def test_no_exposure_low_score(self, prioritization_engine: PrioritizationEngine) -> None:
        """No exposure factors should score low."""
        factors = {
            "is_exposed_endpoint": False,
            "user_input_reachable": False,
            "requires_auth": True,
            "is_in_dependency": False,
        }
        score = prioritization_engine._compute_context_score(factors)
        assert score < 0.5

    def test_dependency_reduces_score(self, prioritization_engine: PrioritizationEngine) -> None:
        """Dependency status should reduce score."""
        factors = {
            "is_exposed_endpoint": True,
            "user_input_reachable": False,
            "requires_auth": False,
            "is_in_dependency": True,
        }
        score = prioritization_engine._compute_context_score(factors)
        # Dependency reduces score
        assert score < 0.5


class TestThreatScore:
    """Test threat score computation."""

    def test_kev_and_exploit_high(self, prioritization_engine: PrioritizationEngine) -> None:
        """KEV + exploit available should score high."""
        threat = {"in_cisa_kev": True, "exploit_available": True, "epss_score": 0.8}
        score = prioritization_engine._compute_threat_score(threat)
        assert score > 0.5

    def test_no_threat_low(self, prioritization_engine: PrioritizationEngine) -> None:
        """No threat indicators should score low."""
        threat = {"in_cisa_kev": False, "exploit_available": False, "epss_score": 0.01}
        score = prioritization_engine._compute_threat_score(threat)
        assert score < 0.3


# ---------------------------------------------------------------------------
# PrioritizedVulnerability Tests
# ---------------------------------------------------------------------------

class TestPrioritizedVulnerability:
    """Test PrioritizedVulnerability data model."""

    def test_to_dict(self, sample_critical_vuln: Vulnerability) -> None:
        """Should serialize to dict."""
        pv = PrioritizedVulnerability(
            vulnerability=sample_critical_vuln,
            priority_score=85.5,
            priority_band=PriorityBand.P0,
            context_factors={"is_exposed_endpoint": True},
            threat_intel={"in_cisa_kev": True},
            business_impact={"production_score": 0.9},
        )
        d = pv.to_dict()
        assert d["priority_score"] == 85.5
        assert d["priority_band"] == "P0"
        assert d["context_factors"]["is_exposed_endpoint"] is True


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------

class TestPrioritizationWorkflow:
    """End-to-end prioritization tests."""

    @pytest.mark.asyncio
    async def test_prioritize_empty_list(self, prioritization_engine: PrioritizationEngine) -> None:
        """Empty list should return empty."""
        result = await prioritization_engine.prioritize_vulnerabilities([], None)
        assert result == []

    @pytest.mark.asyncio
    async def test_prioritize_single_vuln(
        self,
        prioritization_engine: PrioritizationEngine,
        sample_critical_vuln: Vulnerability,
    ) -> None:
        """Single vulnerability should be prioritized."""
        result = await prioritization_engine.prioritize_vulnerabilities(
            [sample_critical_vuln], None
        )
        assert len(result) == 1
        assert result[0].priority_score > 0
        assert isinstance(result[0].priority_band, PriorityBand)

    @pytest.mark.asyncio
    async def test_prioritize_multiple_vulns(
        self,
        prioritization_engine: PrioritizationEngine,
        sample_critical_vuln: Vulnerability,
        sample_low_vuln: Vulnerability,
    ) -> None:
        """Multiple vulnerabilities should be sorted by priority."""
        result = await prioritization_engine.prioritize_vulnerabilities(
            [sample_low_vuln, sample_critical_vuln], None
        )
        assert len(result) == 2
        # Critical should come first
        assert result[0].priority_score >= result[1].priority_score

    @pytest.mark.asyncio
    async def test_critical_sql_in_endpoint_is_p0(
        self,
        prioritization_engine: PrioritizationEngine,
    ) -> None:
        """Critical SQL injection in exposed endpoint should be P0."""
        vuln = Vulnerability(
            scan_id="s1", file_path="src/routes.py", line_number=10,
            severity="CRITICAL", category="SQL Injection", cwe_id="CWE-89",
            cwe_name="SQL Injection", title="SQLi in route", description="SQLi",
            code_snippet="@app.route('/api/data')\ndef data():\n    cursor.execute(f'...{user_input}')",
            fix_suggestion="Fix", tool_source="bandit",
        )
        result = await prioritization_engine.prioritize_vulnerabilities([vuln], None)
        assert len(result) == 1
        assert result[0].priority_band in (PriorityBand.P0, PriorityBand.P1)


class TestPriorityGuidelines:
    """Test priority guidelines."""

    def test_guidelines_structure(self, prioritization_engine: PrioritizationEngine) -> None:
        """Guidelines should have expected structure."""
        guidelines = prioritization_engine.get_priority_guidelines()
        for band in ["P0", "P1", "P2", "P3", "P4"]:
            assert band in guidelines
            assert "name" in guidelines[band]
            assert "score_range" in guidelines[band]
            assert "sla" in guidelines[band]

    def test_p0_is_highest(self, prioritization_engine: PrioritizationEngine) -> None:
        """P0 should be critical."""
        guidelines = prioritization_engine.get_priority_guidelines()
        assert "Critical" in guidelines["P0"]["name"] or "critical" in guidelines["P0"]["name"].lower()
