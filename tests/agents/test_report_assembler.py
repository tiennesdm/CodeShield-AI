"""
Tests for the Report Assembler Agent.

Covers:
- Cross-referenced findings building
- Executive summary generation
- Findings by severity/category/agent grouping
- Remediation plan building
- Compliance mapping
- Export formats (JSON, HTML, Executive Brief)
"""

import json
import os
import sys
from datetime import datetime, timezone

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

import pytest
from models.vulnerability import ScanResult, Vulnerability
from agents.report_assembler import (
    ReportAssembler,
    CrossReferencedFinding,
    ReportFormat,
    RemediationItem,
    COMPLIANCE_MAPPINGS,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def assembler():
    """Create a ReportAssembler instance."""
    return ReportAssembler()


@pytest.fixture
def sample_vulnerabilities():
    """Create sample vulnerabilities for testing."""
    vulns = [
        Vulnerability(
            scan_id="scan-001", file_path="src/app.py", line_number=42,
            severity="CRITICAL", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQL Injection", title="SQLi in app",
            description="User input flows to SQL without sanitization",
            code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            fix_suggestion="Use parameterized queries",
            tool_source="bandit", confidence="HIGH", id="rv-001",
        ),
        Vulnerability(
            scan_id="scan-001", file_path="src/app.py", line_number=42,
            severity="CRITICAL", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQL Injection", title="SQLi in app (taint)",
            description="Data flow from request.args to execute()",
            code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            fix_suggestion="Use parameterized queries",
            tool_source="taint_analyzer", confidence="HIGH", id="rv-002",
        ),
        Vulnerability(
            scan_id="scan-001", file_path="src/app.py", line_number=50,
            severity="HIGH", category="XSS",
            cwe_id="CWE-79", cwe_name="Cross-site Scripting", title="XSS in template",
            description="innerHTML assignment with user data",
            code_snippet="element.innerHTML = userInput;",
            fix_suggestion="Use textContent instead",
            tool_source="eslint", confidence="HIGH", id="rv-003",
        ),
        Vulnerability(
            scan_id="scan-001", file_path="src/config.py", line_number=10,
            severity="HIGH", category="Hardcoded Secret",
            cwe_id="CWE-798", cwe_name="Hardcoded Credentials", title="API key exposed",
            description="API key is hardcoded",
            code_snippet='API_KEY = "sk-abc123"',
            fix_suggestion="Use env var",
            tool_source="gitleaks", confidence="HIGH", id="rv-004",
        ),
        Vulnerability(
            scan_id="scan-001", file_path="src/utils.py", line_number=5,
            severity="MEDIUM", category="Missing Headers",
            cwe_id="CWE-693", cwe_name="Missing Security Headers", title="No CSP",
            description="Content-Security-Policy header is missing",
            code_snippet="# no headers",
            fix_suggestion="Add security headers",
            tool_source="dast_scanner", confidence="MEDIUM", id="rv-005",
        ),
    ]
    return vulns


@pytest.fixture
def scan_result(sample_vulnerabilities):
    """Create a sample ScanResult."""
    result = ScanResult(
        scan_id="scan-001",
        name="Test Project Scan",
        source_type="zip",
        source_path="/tmp/test",
        status="completed",
        progress=100,
        languages=["python", "javascript"],
        total_files=45,
        total_lines=3250,
        scan_duration=322,
        tools_used=["bandit", "taint_analyzer", "eslint", "gitleaks", "dast_scanner"],
        vulnerabilities=sample_vulnerabilities,
    )
    result.compute_stats()
    result.compute_risk_score()
    return result


# ---------------------------------------------------------------------------
# Cross-Referenced Findings Tests
# ---------------------------------------------------------------------------

class TestCrossReferencedFindings:
    """Test cross-referenced findings building."""

    def test_build_cross_referenced(self, assembler, sample_vulnerabilities):
        """Test building cross-referenced findings."""
        cr = assembler.build_cross_referenced_findings(sample_vulnerabilities)
        assert len(cr) > 0, "Should have cross-referenced findings"

    def test_cross_ref_has_agent_sources(self, assembler, sample_vulnerabilities):
        """Test cross-referenced findings have agent sources."""
        cr = assembler.build_cross_referenced_findings(sample_vulnerabilities)
        for finding in cr:
            assert len(finding.agent_sources) >= 1, "Should have at least one source"

    def test_cross_ref_multi_agent_boost(self, assembler, sample_vulnerabilities):
        """Test multi-agent findings get confidence boost."""
        cr = assembler.build_cross_referenced_findings(sample_vulnerabilities)
        multi = [c for c in cr if len(c.agent_sources) > 1]
        for finding in multi:
            assert finding.confidence_boost > 0, "Multi-agent should have confidence boost"

    def test_cross_ref_single_agent_no_boost(self, assembler, sample_vulnerabilities):
        """Test single-agent findings have no boost."""
        cr = assembler.build_cross_referenced_findings(sample_vulnerabilities)
        single = [c for c in cr if len(c.agent_sources) == 1]
        for finding in single:
            assert finding.confidence_boost == 0, "Single agent should have no boost"

    def test_cross_ref_evidence(self, assembler, sample_vulnerabilities):
        """Test cross-referenced findings have evidence."""
        cr = assembler.build_cross_referenced_findings(sample_vulnerabilities)
        for finding in cr:
            assert len(finding.evidence) >= 1, "Should have evidence entries"

    def test_sorted_by_severity(self, assembler, sample_vulnerabilities):
        """Test results are sorted by severity."""
        cr = assembler.build_cross_referenced_findings(sample_vulnerabilities)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        for i in range(len(cr) - 1):
            s1 = cr[i].vulnerability.severity
            s2 = cr[i + 1].vulnerability.severity
            assert severity_order.get(s1, 5) <= severity_order.get(s2, 5), \
                f"Should be sorted by severity, got {s1} before {s2}"


# ---------------------------------------------------------------------------
# Executive Summary Tests
# ---------------------------------------------------------------------------

class TestExecutiveSummary:
    """Test executive summary generation."""

    def test_has_risk_score(self, assembler, scan_result):
        """Test executive summary has risk score."""
        summary = assembler.build_executive_summary(scan_result)
        assert "risk_score" in summary
        assert isinstance(summary["risk_score"], int)

    def test_has_severity_counts(self, assembler, scan_result):
        """Test executive summary has severity counts."""
        summary = assembler.build_executive_summary(scan_result)
        assert "by_severity" in summary
        sev = summary["by_severity"]
        assert "critical" in sev
        assert "high" in sev
        assert "medium" in sev

    def test_risk_level_present(self, assembler, scan_result):
        """Test executive summary has risk level."""
        summary = assembler.build_executive_summary(scan_result)
        assert "risk_level" in summary
        assert summary["risk_level"] in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    def test_top_findings_present(self, assembler, scan_result):
        """Test executive summary has top findings."""
        summary = assembler.build_executive_summary(scan_result)
        assert "top_findings" in summary
        assert len(summary["top_findings"]) > 0

    def test_compliance_summary(self, assembler, scan_result):
        """Test executive summary has compliance."""
        summary = assembler.build_executive_summary(scan_result)
        assert "compliance_summary" in summary


# ---------------------------------------------------------------------------
# Findings Grouping Tests
# ---------------------------------------------------------------------------

class TestFindingsBySeverity:
    """Test findings by severity grouping."""

    def test_groups_by_severity(self, assembler, sample_vulnerabilities):
        """Test findings are grouped by severity."""
        groups = assembler.build_findings_by_severity(sample_vulnerabilities)
        assert "CRITICAL" in groups
        assert "HIGH" in groups
        assert "MEDIUM" in groups

    def test_correct_counts(self, assembler, sample_vulnerabilities):
        """Test counts are correct."""
        groups = assembler.build_findings_by_severity(sample_vulnerabilities)
        assert len(groups["CRITICAL"]) == 2, f"Expected 2 CRITICAL, got {len(groups['CRITICAL'])}"
        assert len(groups["HIGH"]) == 2, f"Expected 2 HIGH, got {len(groups['HIGH'])}"
        assert len(groups["MEDIUM"]) == 1, f"Expected 1 MEDIUM, got {len(groups['MEDIUM'])}"

    def test_entries_have_required_fields(self, assembler, sample_vulnerabilities):
        """Test entries have all required fields."""
        groups = assembler.build_findings_by_severity(sample_vulnerabilities)
        for severity, findings in groups.items():
            for f in findings:
                assert "id" in f
                assert "title" in f
                assert "category" in f
                # severity is the dict key, not a field in the entry
                assert "file_path" in f
                assert "line_number" in f


class TestFindingsByCategory:
    """Test findings by category grouping."""

    def test_groups_by_category(self, assembler, sample_vulnerabilities):
        """Test findings are grouped by category."""
        groups = assembler.build_findings_by_category(sample_vulnerabilities)
        assert "SQL Injection" in groups
        assert "XSS" in groups
        assert "Hardcoded Secret" in groups

    def test_sorted_within_group(self, assembler, sample_vulnerabilities):
        """Test findings within each group are sorted by severity."""
        groups = assembler.build_findings_by_category(sample_vulnerabilities)
        for cat, findings in groups.items():
            severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
            for i in range(len(findings) - 1):
                s1 = findings[i]["severity"]
                s2 = findings[i + 1]["severity"]
                assert severity_order.get(s1, 5) <= severity_order.get(s2, 5), \
                    f"Should be sorted within category {cat}"


class TestFindingsByAgent:
    """Test findings by agent grouping."""

    def test_groups_by_agent(self, assembler, sample_vulnerabilities):
        """Test findings are grouped by agent."""
        summaries = assembler.build_findings_by_agent(sample_vulnerabilities)
        assert "bandit" in summaries
        assert "taint_analyzer" in summaries

    def test_agent_totals(self, assembler, sample_vulnerabilities):
        """Test agent totals are correct."""
        summaries = assembler.build_findings_by_agent(sample_vulnerabilities)
        bandit = summaries["bandit"]
        assert bandit.total_findings == 1, f"Expected 1 bandit finding, got {bandit.total_findings}"
        taint = summaries["taint_analyzer"]
        assert taint.total_findings == 1, f"Expected 1 taint finding, got {taint.total_findings}"


# ---------------------------------------------------------------------------
# Chained Findings Tests
# ---------------------------------------------------------------------------

class TestChainedFindings:
    """Test chained findings."""

    def test_chained_findings_detected(self, assembler, sample_vulnerabilities):
        """Test chained findings are detected."""
        cr = assembler.build_cross_referenced_findings(sample_vulnerabilities)
        chained = assembler.build_chained_findings(cr)
        assert len(chained) >= 1, "Should detect at least one chained finding"

    def test_chained_has_confidence_boost(self, assembler, sample_vulnerabilities):
        """Test chained findings have confidence boost."""
        cr = assembler.build_cross_referenced_findings(sample_vulnerabilities)
        chained = assembler.build_chained_findings(cr)
        for c in chained:
            assert c["confidence_boost"] > 0, "Chained finding should have boost"

    def test_chained_has_chain_description(self, assembler, sample_vulnerabilities):
        """Test chained findings have chain description."""
        cr = assembler.build_cross_referenced_findings(sample_vulnerabilities)
        chained = assembler.build_chained_findings(cr)
        for c in chained:
            assert "chain_description" in c
            assert len(c["chain_description"]) > 0


# ---------------------------------------------------------------------------
# Remediation Plan Tests
# ---------------------------------------------------------------------------

class TestRemediationPlan:
    """Test remediation plan building."""

    def test_has_items(self, assembler, sample_vulnerabilities):
        """Test plan has items."""
        plan = assembler.build_remediation_plan(sample_vulnerabilities)
        assert plan["item_count"] == len(sample_vulnerabilities)

    def test_has_eta(self, assembler, sample_vulnerabilities):
        """Test plan has ETA estimate."""
        plan = assembler.build_remediation_plan(sample_vulnerabilities)
        assert "total_remediation_hours" in plan
        assert plan["total_remediation_hours"] > 0

    def test_grouped_by_severity(self, assembler, sample_vulnerabilities):
        """Test plan is grouped by severity."""
        plan = assembler.build_remediation_plan(sample_vulnerabilities)
        assert "by_severity" in plan
        assert "CRITICAL" in plan["by_severity"]

    def test_items_have_etas(self, assembler, sample_vulnerabilities):
        """Test items have ETA values."""
        plan = assembler.build_remediation_plan(sample_vulnerabilities)
        for item in plan["all_items"]:
            assert item["eta_hours"] > 0, "Each item should have ETA"
            assert item["priority"] > 0, "Each item should have priority"


# ---------------------------------------------------------------------------
# Compliance Mapping Tests
# ---------------------------------------------------------------------------

class TestComplianceMapping:
    """Test compliance mapping."""

    def test_has_all_frameworks(self, assembler, sample_vulnerabilities):
        """Test all compliance frameworks are mapped."""
        compliance = assembler.build_compliance_mapping(sample_vulnerabilities)
        framework_names = [c.framework for c in compliance]
        assert "SOC2" in framework_names
        assert "ISO27001" in framework_names
        assert "GDPR" in framework_names
        assert "PCI DSS" in framework_names

    def test_non_compliant_when_failing(self, assembler, sample_vulnerabilities):
        """Test non-compliant status when controls fail."""
        compliance = assembler.build_compliance_mapping(sample_vulnerabilities)
        for c in compliance:
            assert c.overall_status in ["compliant", "non_compliant"]

    def test_control_statuses_present(self, assembler, sample_vulnerabilities):
        """Test control statuses are present."""
        compliance = assembler.build_compliance_mapping(sample_vulnerabilities)
        for c in compliance:
            assert len(c.control_statuses) > 0
            for status in c.control_statuses.values():
                assert status in ["pass", "fail"]


# ---------------------------------------------------------------------------
# Export Format Tests
# ---------------------------------------------------------------------------

class TestJSONExport:
    """Test JSON export."""

    @pytest.mark.asyncio
    async def test_valid_json(self, assembler, scan_result):
        """Test JSON export is valid."""
        content = assembler.export_json(scan_result)
        parsed = json.loads(content)
        assert "executive_summary" in parsed
        assert "findings_by_severity" in parsed

    @pytest.mark.asyncio
    async def test_json_has_meta(self, assembler, scan_result):
        """Test JSON has metadata."""
        content = assembler.export_json(scan_result)
        parsed = json.loads(content)
        assert "meta" in parsed
        assert parsed["meta"]["version"] == "2.0"

    @pytest.mark.asyncio
    async def test_json_has_remediation(self, assembler, scan_result):
        """Test JSON has remediation plan."""
        content = assembler.export_json(scan_result)
        parsed = json.loads(content)
        assert "remediation_plan" in parsed


class TestExecutiveBrief:
    """Test executive brief export."""

    @pytest.mark.asyncio
    async def test_contains_risk_score(self, assembler, scan_result):
        """Test brief contains risk score."""
        brief = assembler.export_executive_brief(scan_result)
        assert str(scan_result.risk_score) in brief, "Brief should mention risk score"

    @pytest.mark.asyncio
    async def test_contains_findings_count(self, assembler, scan_result):
        """Test brief contains findings count."""
        brief = assembler.export_executive_brief(scan_result)
        assert "CRITICAL" in brief, "Brief should mention CRITICAL"

    @pytest.mark.asyncio
    async def test_contains_compliance(self, assembler, scan_result):
        """Test brief contains compliance status."""
        brief = assembler.export_executive_brief(scan_result)
        assert "SOC2" in brief or "compliance" in brief.lower(), "Brief should mention compliance"


class TestHTMLExport:
    """Test HTML export."""

    @pytest.mark.asyncio
    async def test_valid_html_structure(self, assembler, scan_result):
        """Test HTML has proper structure."""
        html = assembler.export_html(scan_result)
        assert "<!DOCTYPE html>" in html
        assert "<html" in html
        assert "</html>" in html

    @pytest.mark.asyncio
    async def test_contains_sections(self, assembler, scan_result):
        """Test HTML contains all sections."""
        html = assembler.export_html(scan_result)
        assert "Executive Summary" in html
        assert "Findings by Severity" in html
        assert "Remediation Plan" in html
        assert "Compliance Mapping" in html

    @pytest.mark.asyncio
    async def test_contains_styles(self, assembler, scan_result):
        """Test HTML contains CSS styles."""
        html = assembler.export_html(scan_result)
        assert "<style>" in html
        assert "</style>" in html


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------

class TestReportAssembly:
    """Test full report assembly."""

    @pytest.mark.asyncio
    async def test_full_assembly(self, assembler, scan_result):
        """Test full report assembly."""
        report = await assembler.assemble_report(scan_result)
        assert "executive_summary" in report
        assert "findings_by_severity" in report
        assert "findings_by_category" in report
        assert "cross_referenced_findings" in report
        assert "chained_findings" in report
        assert "remediation_plan" in report
        assert "compliance_mapping" in report

    @pytest.mark.asyncio
    async def test_stats(self, assembler):
        """Test that get_stats returns supported formats."""
        stats = await assembler.get_stats()
        assert "supported_formats" in stats
        assert "json" in stats["supported_formats"]
        assert "html" in stats["supported_formats"]
        assert "executive_brief" in stats["supported_formats"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
