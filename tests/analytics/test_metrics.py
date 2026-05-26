"""
Tests for analytics.metrics module.
"""

import pytest
from datetime import datetime, timezone, timedelta

from analytics.metrics import MetricsEngine, TimeSeries, TrendDirection


class TestMetricsEngine:
    def setup_method(self):
        self.engine = MetricsEngine()

    def _sample_scans(self, count=5):
        scans = []
        now = datetime.now(timezone.utc)
        for i in range(count):
            scans.append({
                "scan_id": f"scan-{i}",
                "name": f"Project {i}",
                "end_time": (now - timedelta(days=i)).isoformat(),
                "risk_score": 30 + i * 5,
                "stats": {
                    "total": 10 + i * 2,
                    "critical": i % 2,
                    "high": 1 + i % 3,
                    "medium": 3 + i,
                    "low": 5,
                    "info": 1,
                },
                "tools_used": ["semgrep", "bandit"],
                "languages": ["python", "javascript"],
                "total_files": 50 + i * 10,
                "total_lines": 5000 + i * 1000,
                "vulnerabilities": [
                    {
                        "id": f"v-{i}-1",
                        "title": f"Vuln {i}-1",
                        "severity": "HIGH" if i % 2 == 0 else "MEDIUM",
                        "category": "Injection" if i % 2 == 0 else "XSS",
                        "cwe_id": f"CWE-{79 + i}",
                        "file_path": f"src/file{i}.py",
                        "line_number": 10 + i,
                        "tool_source": "semgrep",
                    },
                    {
                        "id": f"v-{i}-2",
                        "title": f"Vuln {i}-2",
                        "severity": "CRITICAL" if i == 0 else "LOW",
                        "category": "Secret Leak" if i == 0 else "Config",
                        "cwe_id": f"CWE-{798 + i}",
                        "file_path": f"src/file{i}.py",
                        "line_number": 20 + i,
                        "tool_source": "bandit",
                    },
                ],
            })
        return scans

    def test_vulnerability_trends(self):
        scans = self._sample_scans()
        trends = self.engine.vulnerability_trends(scans, period="30d")
        assert "CRITICAL" in trends
        assert "HIGH" in trends
        assert "MEDIUM" in trends
        assert "LOW" in trends
        for ts in trends.values():
            assert isinstance(ts, TimeSeries)
            assert len(ts.points) > 0

    def test_risk_score_trend(self):
        scans = self._sample_scans()
        trend = self.engine.risk_score_trend(scans, period="30d")
        assert isinstance(trend, TimeSeries)
        assert trend.metric_name == "risk_score"
        assert len(trend.points) > 0

    def test_top_vulnerable_files(self):
        scans = self._sample_scans()
        top_files = self.engine.top_vulnerable_files(scans, limit=10)
        assert len(top_files) > 0
        # All vulns go to src/file{i}.py, so should have entries
        assert top_files[0].vulnerability_count > 0
        assert top_files[0].risk_score > 0

    def test_top_vulnerable_repositories(self):
        scans = self._sample_scans()
        repos = self.engine.top_vulnerable_repositories(scans)
        assert len(repos) > 0
        assert "name" in repos[0]
        assert "risk_score" in repos[0]

    def test_top_vulnerability_categories(self):
        scans = self._sample_scans()
        cats = self.engine.top_vulnerability_categories(scans)
        assert len(cats) > 0
        assert "category" in cats[0]
        assert "count" in cats[0]

    def test_scan_coverage(self):
        scans = self._sample_scans()
        coverage = self.engine.scan_coverage(scans)
        assert coverage["total_scans"] == 5
        assert coverage["total_files_scanned"] > 0
        assert coverage["total_lines_scanned"] > 0
        assert "python" in coverage["languages_detected"]
        assert len(coverage["tools_used"]) > 0

    def test_remediation_velocity(self):
        sla_records = [
            {
                "vulnerability_id": f"v-{i}",
                "status": "remediated",
                "remediated_at": (datetime.now(timezone.utc) - timedelta(days=i*2)).isoformat(),
                "time_to_remediate_hours": (i + 1) * 24,
                "severity": "HIGH",
            }
            for i in range(5)
        ]
        velocity = self.engine.remediation_velocity(sla_records, period_weeks=12)
        assert velocity["total_fixed"] == 5
        assert velocity["avg_per_week"] > 0

    def test_security_debt(self):
        scans = self._sample_scans()
        debt = self.engine.security_debt(scans)
        assert debt["total_debt_score"] > 0
        assert debt["total_vulnerabilities"] > 0
        assert debt["estimated_remediation_hours"] > 0
        assert "by_severity" in debt
        assert "debt_rating" in debt
        assert debt["debt_rating"] in ["A+", "A", "B", "C", "D", "E", "F"]

    def test_calculate_security_score(self):
        scans = self._sample_scans()
        score = self.engine.calculate_security_score(scans)
        assert "overall_score" in score
        assert 0 <= score["overall_score"] <= 100
        assert "rating" in score
        assert "factors" in score
        assert "vulnerability_density" in score["factors"]
        assert "severity_distribution" in score["factors"]

    def test_security_score_empty(self):
        score = self.engine.calculate_security_score([])
        assert score["overall_score"] == 0

    def test_trend_direction(self):
        from analytics.metrics import MetricPoint
        # Improving trend (values decreasing)
        points_improving = [
            MetricPoint(timestamp=datetime.now(timezone.utc), value=100),
            MetricPoint(timestamp=datetime.now(timezone.utc), value=80),
            MetricPoint(timestamp=datetime.now(timezone.utc), value=60),
        ]
        direction = self.engine._calculate_trend_direction(points_improving)
        assert direction == TrendDirection.IMPROVING.value

        # Declining trend (values increasing)
        points_declining = [
            MetricPoint(timestamp=datetime.now(timezone.utc), value=10),
            MetricPoint(timestamp=datetime.now(timezone.utc), value=50),
            MetricPoint(timestamp=datetime.now(timezone.utc), value=100),
        ]
        direction = self.engine._calculate_trend_direction(points_declining)
        assert direction == TrendDirection.DECLINING.value

    def test_change_percentage(self):
        from analytics.metrics import MetricPoint
        points = [
            MetricPoint(timestamp=datetime.now(timezone.utc), value=100),
            MetricPoint(timestamp=datetime.now(timezone.utc), value=150),
        ]
        pct = self.engine._calculate_change_percentage(points)
        assert pct == 50.0
