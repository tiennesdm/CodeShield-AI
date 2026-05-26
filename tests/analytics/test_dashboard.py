"""
Tests for analytics.dashboard module.
"""

import pytest
from datetime import datetime, timezone, timedelta

from analytics.dashboard import DashboardDataProvider
from analytics.metrics import MetricsEngine


class TestDashboardDataProvider:
    def setup_method(self):
        self.dashboard = DashboardDataProvider(MetricsEngine())

    def _sample_scans(self, count=5):
        scans = []
        now = datetime.now(timezone.utc)
        for i in range(count):
            scans.append({
                "scan_id": f"scan-{i}",
                "name": f"Project {i}",
                "end_time": (now - timedelta(days=i)).isoformat(),
                "risk_score": 40 - i * 3,
                "stats": {
                    "total": 15 - i,
                    "critical": 1 if i < 2 else 0,
                    "high": 2 if i < 3 else 1,
                    "medium": 5,
                    "low": 5,
                    "info": 2,
                },
                "tools_used": ["semgrep", "bandit"],
                "languages": ["python", "javascript"],
                "total_files": 50 + i * 10,
                "total_lines": 5000 + i * 1000,
                "vulnerabilities": [
                    {
                        "id": f"v-{i}-1", "title": f"Vuln {i}",
                        "severity": "HIGH" if i % 2 == 0 else "MEDIUM",
                        "category": "Injection", "cwe_id": f"CWE-{79 + i}",
                        "file_path": f"src/file{i}.py", "line_number": 10 + i,
                    },
                ],
            })
        return scans

    def test_executive_summary(self):
        scans = self._sample_scans()
        summary = self.dashboard.executive_summary(scans)
        assert "posture" in summary
        assert "vulnerabilities" in summary
        assert "risk" in summary
        assert "activity" in summary
        assert "benchmarks" in summary
        assert "recommendations" in summary
        assert "generated_at" in summary

    def test_trend_data(self):
        scans = self._sample_scans()
        trends = self.dashboard.trend_data(scans, period="30d", granularity="day")
        assert "period" in trends
        assert "charts" in trends
        assert "vulnerability_trends" in trends["charts"]
        assert "risk_trend" in trends["charts"]
        assert "scan_activity" in trends["charts"]

    def test_team_breakdown(self):
        scans = self._sample_scans()
        teams_data = [
            {"id": "team-1", "name": "Backend", "project_ids": [], "scan_ids": []},
            {"id": "team-2", "name": "Frontend", "project_ids": [], "scan_ids": []},
        ]
        result = self.dashboard.team_breakdown(scans, teams_data)
        assert "teams" in result
        assert "team_count" in result
        assert result["team_count"] == 2

    def test_project_breakdown(self):
        scans = self._sample_scans()
        projects_data = [
            {"id": "proj-1", "name": "Web App"},
            {"id": "proj-2", "name": "API Service"},
        ]
        result = self.dashboard.project_breakdown(scans, projects_data)
        assert "projects" in result
        assert "project_count" in result

    def test_dashboard_metrics(self):
        scans = self._sample_scans()
        result = self.dashboard.dashboard_metrics(scans)
        assert "executive_summary" in result
        assert "trends" in result
        assert "top_vulnerable_files" in result
        assert "top_vulnerable_repos" in result
        assert "top_categories" in result
        assert "coverage" in result

    def test_posture_label(self):
        assert self.dashboard._posture_label(90) == "Excellent"
        assert self.dashboard._posture_label(75) == "Good"
        assert self.dashboard._posture_label(60) == "Fair"
        assert self.dashboard._posture_label(45) == "Poor"
        assert self.dashboard._posture_label(30) == "Critical"

    def test_quick_security_score(self):
        sev_counts = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        score = self.dashboard._quick_security_score(sev_counts, 2)
        assert 0 <= score <= 100

    def test_recommendations_for_critical(self):
        sev_counts = {"CRITICAL": 5, "HIGH": 10, "MEDIUM": 5, "LOW": 0}
        recs = self.dashboard._executive_recommendations(30, sev_counts, 60)
        assert len(recs) > 0
        assert any("critical" in r.lower() for r in recs)

    def test_empty_scans(self):
        summary = self.dashboard.executive_summary([])
        assert summary["posture"]["score"] == 0
