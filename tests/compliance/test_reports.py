"""
Tests for compliance.reports module.
"""

import pytest
from datetime import datetime, timezone, timedelta

from compliance.frameworks import ComplianceFrameworkRegistry
from compliance.reports import ComplianceReportGenerator


class TestComplianceReportGenerator:
    def setup_method(self):
        self.registry = ComplianceFrameworkRegistry()
        self.generator = ComplianceReportGenerator(self.registry)

    def _sample_scan_results(self):
        return [
            {
                "scan_id": "scan-001",
                "name": "Frontend Scan",
                "end_time": datetime.now(timezone.utc).isoformat(),
                "risk_score": 45,
                "stats": {"total": 12, "critical": 1, "high": 3, "medium": 5, "low": 3, "info": 0},
                "tools_used": ["semgrep", "bandit"],
                "languages": ["javascript", "python"],
                "total_files": 50,
                "total_lines": 5000,
                "vulnerabilities": [
                    {"id": "v1", "title": "SQL Injection", "severity": "HIGH",
                     "category": "Injection", "cwe_id": "CWE-89"},
                    {"id": "v2", "title": "XSS", "severity": "HIGH",
                     "category": "XSS", "cwe_id": "CWE-79"},
                ],
            },
            {
                "scan_id": "scan-002",
                "name": "Backend Scan",
                "end_time": datetime.now(timezone.utc).isoformat(),
                "risk_score": 30,
                "stats": {"total": 8, "critical": 0, "high": 2, "medium": 3, "low": 3, "info": 0},
                "tools_used": ["bandit", "pylint"],
                "languages": ["python"],
                "total_files": 30,
                "total_lines": 3000,
                "vulnerabilities": [
                    {"id": "v3", "title": "Hardcoded Secret", "severity": "HIGH",
                     "category": "Secret Leak", "cwe_id": "CWE-798"},
                ],
            },
        ]

    def test_generate_report_soc2(self):
        scans = self._sample_scan_results()
        report = self.generator.generate_report("soc2_type2", scans)
        assert report.framework_id == "soc2_type2"
        assert report.total_controls > 0
        assert report.executive_summary["total_controls"] > 0
        assert "control_evidence" in report.to_dict()

    def test_generate_report_iso27001(self):
        scans = self._sample_scan_results()
        report = self.generator.generate_report("iso27001_2022", scans)
        assert report.framework_id == "iso27001_2022"
        assert report.total_controls > 0

    def test_generate_report_with_no_scans(self):
        report = self.generator.generate_report("soc2_type2", [])
        assert report.overall_compliance_percentage == 0.0

    def test_gap_analysis(self):
        scans = self._sample_scan_results()
        gap = self.generator.gap_analysis("soc2_type2", scans)
        assert "gaps" in gap
        assert "total_controls" in gap
        assert "coverage_percentage" in gap

    def test_executive_summary(self):
        scans = self._sample_scan_results()
        summary = self.generator.executive_summary(
            framework_ids=["soc2_type2", "iso27001_2022"],
            scan_results=scans,
        )
        assert "overall_compliance_percentage" in summary
        assert "framework_breakdown" in summary
        assert "recommendations" in summary

    def test_report_markdown_export(self):
        scans = self._sample_scan_results()
        report = self.generator.generate_report("soc2_type2", scans)
        md = report.to_markdown()
        assert "Compliance Report" in md
        assert report.framework_name in md

    def test_maturity_score_calculation(self):
        scans = self._sample_scan_results()
        report = self.generator.generate_report("soc2_type2", scans)
        assert 0 <= report.maturity_score <= 100

    def test_risk_level_mapping(self):
        assert self.generator._determine_risk_level_from_score(95) == "low"
        assert self.generator._determine_risk_level_from_score(75) == "medium"
        assert self.generator._determine_risk_level_from_score(55) == "high"
        assert self.generator._determine_risk_level_from_score(30) == "critical"

    def test_invalid_framework(self):
        with pytest.raises(ValueError):
            self.generator.generate_report("nonexistent", [])
