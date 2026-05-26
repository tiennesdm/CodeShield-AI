"""
Enterprise ASPM Dashboard & Trend Analytics

Provides executive summary metrics, security posture scoring,
industry benchmark comparisons, and team/project-level breakdowns
with time-series data for frontend charts.

Usage:
    dashboard = DashboardDataProvider(metrics_engine)
    exec_summary = dashboard.executive_summary(scan_results, sla_records)
    team_breakdown = dashboard.team_breakdown(scan_results, teams_data)
    trends = dashboard.trend_data(scan_results, period="30d")
"""

from __future__ import annotations

from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from analytics.metrics import MetricsEngine


# Industry benchmarks (approximate industry averages)
INDUSTRY_BENCHMARKS = {
    "avg_vulns_per_1000_loc": {
        "all": 2.5,
        "financial": 1.8,
        "healthcare": 2.0,
        "technology": 3.0,
        "government": 1.5,
    },
    "avg_mttr_days": {
        "all": 45,
        "critical": 7,
        "high": 21,
        "medium": 60,
        "low": 120,
    },
    "security_score": {
        "excellent": 85,
        "good": 70,
        "average": 55,
        "poor": 40,
    },
    "scan_frequency_weeks": {
        "excellent": 1,
        "good": 2,
        "average": 4,
        "poor": 12,
    },
}


class DashboardDataProvider:
    """
    Provides data for the enterprise security dashboard.

    Aggregates metrics, computes executive summaries, generates
    time-series chart data, and compares against industry benchmarks.
    """

    def __init__(self, metrics_engine: Optional[MetricsEngine] = None) -> None:
        self._metrics = metrics_engine or MetricsEngine()

    # ------------------------------------------------------------------
    # Executive Summary
    # ------------------------------------------------------------------

    def executive_summary(
        self,
        scan_results: List[Dict[str, Any]],
        sla_records: Optional[List[Dict[str, Any]]] = None,
        organization_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Generate executive summary for the security dashboard.

        Returns key metrics, posture score, trends, and recommendations
        suitable for C-level reporting.
        """
        now = datetime.now(timezone.utc)

        # Security score
        score_data = self._metrics.calculate_security_score(scan_results, sla_records)

        # Overall vulnerability counts
        total_vulns = 0
        severity_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        total_risk_score = 0

        for scan in scan_results:
            stats = scan.get("stats", {})
            for sev in severity_counts:
                sev_lower = sev.lower()
                severity_counts[sev] += stats.get(sev_lower, 0)
            total_vulns += stats.get("total", 0)
            total_risk_score += scan.get("risk_score", 0)

        avg_risk = total_risk_score / len(scan_results) if scan_results else 0

        # Recent activity (last 7 days)
        last_7d_cutoff = now - timedelta(days=7)
        scans_last_7d = sum(
            1 for s in scan_results
            if self._parse_ts(s.get("end_time") or s.get("start_time"), now) >= last_7d_cutoff
        )

        # Security debt
        debt = self._metrics.security_debt(scan_results)

        # MTTR
        mttr = {"mttr_days": 0, "count": 0}
        if sla_records:
            mttr = self._metrics.calculate_mttr_from_records(sla_records)

        # Posture score
        posture_score = score_data.get("overall_score", 0)
        posture_rating = self._posture_label(posture_score)

        # Benchmark comparison
        benchmarks = self._compare_to_benchmarks(
            vuln_count=total_vulns,
            loc=self._total_lines(scan_results),
            security_score=posture_score,
            mttr_days=mttr.get("mttr_days", 0),
        )

        # Trend indicators
        trends = self._quick_trends(scan_results)

        return {
            "generated_at": now.isoformat(),
            "organization_id": organization_id,
            "posture": {
                "score": round(posture_score, 1),
                "rating": posture_rating,
                "rating_label": self._rating_description(score_data.get("rating", "F")),
                "trend": trends.get("overall", "stable"),
            },
            "vulnerabilities": {
                "total_open": total_vulns,
                "by_severity": severity_counts,
                "critical_and_high": severity_counts["CRITICAL"] + severity_counts["HIGH"],
                "security_debt_score": debt["total_debt_score"],
                "debt_rating": debt["debt_rating"],
            },
            "risk": {
                "average_risk_score": round(avg_risk, 1),
                "max_risk_score": max((s.get("risk_score", 0) for s in scan_results), default=0),
                "risk_trend": trends.get("risk", "stable"),
            },
            "remediation": {
                "mttr_days": round(mttr.get("mttr_days", 0), 1) if mttr.get("count") else None,
                "mttr_hours": round(mttr.get("mttr_hours", 0), 1) if mttr.get("count") else None,
                "remediated_count": mttr.get("count", 0),
                "remediation_trend": trends.get("remediation", "stable"),
            },
            "activity": {
                "total_scans": len(scan_results),
                "scans_last_7_days": scans_last_7d,
                "total_files_scanned": self._total_files(scan_results),
                "total_lines_scanned": self._total_lines(scan_results),
                "languages_covered": len(self._all_languages(scan_results)),
            },
            "benchmarks": benchmarks,
            "factors": score_data.get("factors", {}),
            "recommendations": self._executive_recommendations(
                posture_score, severity_counts, mttr.get("mttr_days", 0)
            ),
        }

    # ------------------------------------------------------------------
    # Trend Data (for Charts)
    # ------------------------------------------------------------------

    def trend_data(
        self,
        scan_results: List[Dict[str, Any]],
        period: str = "30d",
        granularity: str = "day",
    ) -> Dict[str, Any]:
        """
        Generate time-series data for frontend charts.

        Returns vulnerability trends, risk trends, and scan activity
        formatted for Chart.js / D3.js / Recharts consumption.
        """
        # Vulnerability trends by severity
        vuln_trends = self._metrics.vulnerability_trends(scan_results, period, granularity)

        # Risk score trend
        risk_trend = self._metrics.risk_score_trend(scan_results, period)

        # Format for chart consumption
        chart_data = {
            "vulnerability_trends": {
                sev: ts.to_dict()
                for sev, ts in vuln_trends.items()
            },
            "risk_trend": risk_trend.to_dict(),
        }

        # Add scan activity timeline
        chart_data["scan_activity"] = self._scan_activity_timeline(scan_results, period)

        return {
            "period": period,
            "granularity": granularity,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "charts": chart_data,
        }

    # ------------------------------------------------------------------
    # Team / Project Breakdown
    # ------------------------------------------------------------------

    def team_breakdown(
        self,
        scan_results: List[Dict[str, Any]],
        teams_data: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Generate security metrics broken down by team.

        Args:
            scan_results: All scan results
            teams_data: List of team dicts with id, name, project_ids, etc.
        """
        team_metrics: List[Dict[str, Any]] = []

        for team in teams_data:
            team_id = team.get("id", "unknown")
            team_name = team.get("name", "Unknown Team")
            project_ids = set(team.get("project_ids", []))
            scan_ids = set(team.get("scan_ids", []))

            # Filter scans for this team
            team_scans = [
                s for s in scan_results
                if s.get("scan_id") in scan_ids or s.get("project_id") in project_ids
            ]

            # If no direct mapping, use scan name heuristic
            if not team_scans and team.get("name"):
                team_lower = team.get("name", "").lower()
                team_scans = [
                    s for s in scan_results
                    if team_lower in (s.get("name") or "").lower()
                ]

            if not team_scans:
                team_metrics.append({
                    "team_id": team_id,
                    "team_name": team_name,
                    "scan_count": 0,
                    "vulnerabilities": {"total": 0},
                    "risk_score": 0,
                    "security_score": 0,
                })
                continue

            # Calculate metrics for this team
            total_vulns = sum(s.get("stats", {}).get("total", 0) for s in team_scans)
            sev_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for s in team_scans:
                stats = s.get("stats", {})
                for sev in sev_counts:
                    sev_counts[sev] += stats.get(sev.lower(), 0)

            avg_risk = (sum(s.get("risk_score", 0) for s in team_scans) /
                        len(team_scans)) if team_scans else 0

            team_metrics.append({
                "team_id": team_id,
                "team_name": team_name,
                "scan_count": len(team_scans),
                "vulnerabilities": {
                    "total": total_vulns,
                    "by_severity": sev_counts,
                    "critical_and_high": sev_counts["CRITICAL"] + sev_counts["HIGH"],
                },
                "risk_score": round(avg_risk, 1),
                "security_score": self._quick_security_score(sev_counts, len(team_scans)),
            })

        # Sort by risk score descending
        team_metrics.sort(key=lambda t: t["risk_score"], reverse=True)

        return {
            "teams": team_metrics,
            "team_count": len(team_metrics),
            "highest_risk_team": team_metrics[0]["team_name"] if team_metrics else None,
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def project_breakdown(
        self,
        scan_results: List[Dict[str, Any]],
        projects_data: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """Generate security metrics broken down by project."""
        project_metrics: List[Dict[str, Any]] = []

        for project in projects_data:
            project_id = project.get("id", "unknown")
            project_name = project.get("name", "Unknown Project")

            # Filter scans for this project
            project_scans = [
                s for s in scan_results
                if s.get("project_id") == project_id or
                project_name.lower() in (s.get("name") or "").lower()
            ]

            if not project_scans:
                project_metrics.append({
                    "project_id": project_id,
                    "project_name": project_name,
                    "scan_count": 0,
                    "vulnerabilities": {"total": 0},
                    "risk_score": 0,
                })
                continue

            total_vulns = sum(s.get("stats", {}).get("total", 0) for s in project_scans)
            sev_counts: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
            for s in project_scans:
                stats = s.get("stats", {})
                for sev in sev_counts:
                    sev_counts[sev] += stats.get(sev.lower(), 0)

            avg_risk = (sum(s.get("risk_score", 0) for s in project_scans) /
                        len(project_scans)) if project_scans else 0

            project_metrics.append({
                "project_id": project_id,
                "project_name": project_name,
                "scan_count": len(project_scans),
                "repository_url": project.get("repository_url"),
                "vulnerabilities": {
                    "total": total_vulns,
                    "by_severity": sev_counts,
                },
                "risk_score": round(avg_risk, 1),
            })

        project_metrics.sort(key=lambda p: p["risk_score"], reverse=True)

        return {
            "projects": project_metrics,
            "project_count": len(project_metrics),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    # ------------------------------------------------------------------
    # Dashboard Metrics
    # ------------------------------------------------------------------

    def dashboard_metrics(
        self,
        scan_results: List[Dict[str, Any]],
        sla_records: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Generate all dashboard metrics in a single call.

        Returns a comprehensive payload for the frontend dashboard.
        """
        now = datetime.now(timezone.utc)

        exec_summary = self.executive_summary(scan_results, sla_records)
        trends_30d = self.trend_data(scan_results, period="30d")

        # Top vulnerable files
        top_files = self._metrics.top_vulnerable_files(scan_results, limit=10)
        top_repos = self._metrics.top_vulnerable_repositories(scan_results, limit=10)
        top_categories = self._metrics.top_vulnerability_categories(scan_results, limit=10)
        coverage = self._metrics.scan_coverage(scan_results)

        return {
            "generated_at": now.isoformat(),
            "executive_summary": exec_summary,
            "trends": trends_30d,
            "top_vulnerable_files": [f.to_dict() for f in top_files],
            "top_vulnerable_repos": top_repos,
            "top_categories": top_categories,
            "coverage": coverage,
            "metadata": {
                "version": "2.0",
                "data_source": "CodeShield AI Analytics Engine",
            },
        }

    # ------------------------------------------------------------------
    # Internal Helpers
    # ------------------------------------------------------------------

    def _scan_activity_timeline(
        self,
        scan_results: List[Dict[str, Any]],
        period: str,
    ) -> Dict[str, Any]:
        """Build scan activity timeline for charts."""
        days = int(period.replace("d", "").replace("w", "0").replace("m", "00"))
        if "w" in period:
            days = int(period.replace("w", "")) * 7
        elif "m" in period:
            days = int(period.replace("m", "")) * 30

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        # Group scans by day
        from collections import defaultdict
        daily: Dict[str, Dict[str, int]] = defaultdict(lambda: {"scan_count": 0, "vuln_count": 0})

        for scan in scan_results:
            ts = self._parse_ts(scan.get("end_time") or scan.get("start_time"))
            if not ts or ts < cutoff:
                continue
            day = ts.strftime("%Y-%m-%d")
            daily[day]["scan_count"] += 1
            daily[day]["vuln_count"] += len(scan.get("vulnerabilities", []))

        sorted_days = sorted(daily.keys())
        return {
            "labels": sorted_days,
            "datasets": [
                {"label": "Scans", "data": [daily[d]["scan_count"] for d in sorted_days]},
                {"label": "Vulnerabilities Found",
                 "data": [daily[d]["vuln_count"] for d in sorted_days]},
            ],
        }

    @staticmethod
    def _compare_to_benchmarks(
        vuln_count: int,
        loc: int,
        security_score: float,
        mttr_days: float,
    ) -> Dict[str, Any]:
        """Compare organization metrics against industry benchmarks."""
        benchmarks = []

        # Vulnerability density benchmark
        if loc > 0:
            density = (vuln_count / loc) * 1000
            industry_avg = INDUSTRY_BENCHMARKS["avg_vulns_per_1000_loc"]["all"]
            benchmarks.append({
                "metric": "vulnerability_density",
                "unit": "per 1000 LOC",
                "value": round(density, 2),
                "industry_average": industry_avg,
                "percentile": "above_average" if density < industry_avg else "below_average",
                "description": f"Your density ({density:.2f}) is "
                               f"{'better' if density < industry_avg else 'worse'} than "
                               f"industry average ({industry_avg})",
            })

        # Security score benchmark
        benchmarks.append({
            "metric": "security_score",
            "unit": "score",
            "value": round(security_score, 1),
            "industry_average": INDUSTRY_BENCHMARKS["security_score"]["average"],
            "percentile": "above_average" if security_score >= 70 else
                          "average" if security_score >= 55 else "below_average",
            "description": f"Security score of {security_score:.1f} is "
                           f"rated '{DashboardDataProvider._posture_label(security_score)}'",
        })

        # MTTR benchmark
        if mttr_days > 0:
            avg_mttr = INDUSTRY_BENCHMARKS["avg_mttr_days"]["all"]
            benchmarks.append({
                "metric": "mttr",
                "unit": "days",
                "value": round(mttr_days, 1),
                "industry_average": avg_mttr,
                "percentile": "above_average" if mttr_days < avg_mttr else "below_average",
                "description": f"MTTR of {mttr_days:.1f} days is "
                               f"{'better' if mttr_days < avg_mttr else 'worse'} than "
                               f"industry average ({avg_mttr})",
            })

        return {
            "comparisons": benchmarks,
            "overall_percentile": "above_average" if security_score >= 70 else
                                   "average" if security_score >= 55 else "below_average",
        }

    @staticmethod
    def _quick_trends(scan_results: List[Dict[str, Any]]) -> Dict[str, str]:
        """Quick trend calculation from recent vs older scans."""
        if len(scan_results) < 4:
            return {"overall": "stable", "risk": "stable", "remediation": "stable"}

        # Sort by timestamp
        sorted_scans = sorted(
            scan_results,
            key=lambda s: DashboardDataProvider._parse_ts(
                s.get("end_time") or s.get("start_time"), datetime.now(timezone.utc)
            ) or datetime.min.replace(tzinfo=timezone.utc),
        )

        mid = len(sorted_scans) // 2
        older = sorted_scans[:mid]
        newer = sorted_scans[mid:]

        def avg_vulns(scans):
            return sum(s.get("stats", {}).get("total", 0) for s in scans) / max(1, len(scans))

        def avg_risk(scans):
            return sum(s.get("risk_score", 0) for s in scans) / max(1, len(scans))

        older_vuln_avg = avg_vulns(older)
        newer_vuln_avg = avg_vulns(newer)
        older_risk_avg = avg_risk(older)
        newer_risk_avg = avg_risk(newer)

        vuln_change = ((newer_vuln_avg - older_vuln_avg) / max(1, older_vuln_avg)) * 100
        risk_change = ((newer_risk_avg - older_risk_avg) / max(1, older_risk_avg)) * 100

        return {
            "overall": "improving" if vuln_change < -10 else "declining" if vuln_change > 10 else "stable",
            "risk": "improving" if risk_change < -5 else "declining" if risk_change > 5 else "stable",
            "remediation": "stable",
        }

    @staticmethod
    def _quick_security_score(sev_counts: Dict[str, int], scan_count: int) -> int:
        """Quick security score calculation for a team/project."""
        if scan_count == 0:
            return 0
        weights = {"CRITICAL": 25, "HIGH": 10, "MEDIUM": 4, "LOW": 1}
        score = sum(sev_counts.get(s, 0) * w for s, w in weights.items())
        # Normalize to 0-100 (inverse: lower score = better)
        return max(0, min(100, 100 - score))

    @staticmethod
    def _posture_label(score: float) -> str:
        """Convert posture score to label."""
        if score >= 85:
            return "Excellent"
        elif score >= 70:
            return "Good"
        elif score >= 55:
            return "Fair"
        elif score >= 40:
            return "Poor"
        else:
            return "Critical"

    @staticmethod
    def _rating_description(rating: str) -> str:
        """Get description for a rating."""
        descriptions = {
            "A": "Strong security posture. Maintain current practices.",
            "B": "Good security posture. Minor improvements recommended.",
            "C": "Average security posture. Several areas need attention.",
            "D": "Below average. Significant improvements needed.",
            "E": "Poor. Urgent security improvements required.",
            "F": "Critical. Immediate security overhaul needed.",
        }
        return descriptions.get(rating, "Unknown rating")

    @staticmethod
    def _executive_recommendations(
        posture_score: float,
        severity_counts: Dict[str, int],
        mttr_days: float,
    ) -> List[str]:
        """Generate executive-level recommendations."""
        recs = []
        if posture_score < 50:
            recs.append("CRITICAL: Security posture requires immediate executive attention. "
                       "Establish a security improvement program within 14 days.")
        elif posture_score < 70:
            recs.append("Security posture needs improvement. Prioritize high/critical vulnerability remediation.")

        if severity_counts.get("CRITICAL", 0) > 0:
            recs.append(f"Address {severity_counts['CRITICAL']} critical vulnerabilities immediately.")
        if severity_counts.get("HIGH", 0) > 10:
            recs.append(f"{severity_counts['HIGH']} high-severity vulnerabilities require attention within 30 days.")

        if mttr_days > 30:
            recs.append(f"MTTR of {mttr_days:.0f} days exceeds industry average. "
                       "Optimize remediation workflows.")

        if not recs:
            recs.append("Security posture is strong. Continue current practices and schedule quarterly reviews.")

        return recs

    @staticmethod
    def _total_files(scan_results: List[Dict[str, Any]]) -> int:
        return sum(s.get("total_files", 0) for s in scan_results)

    @staticmethod
    def _total_lines(scan_results: List[Dict[str, Any]]) -> int:
        return sum(s.get("total_lines", 0) for s in scan_results)

    @staticmethod
    def _all_languages(scan_results: List[Dict[str, Any]]) -> set:
        langs = set()
        for s in scan_results:
            langs.update(s.get("languages", []))
        return langs

    @staticmethod
    def _parse_ts(ts: Any, default: Optional[datetime] = None) -> Optional[datetime]:
        """Parse timestamp safely."""
        if not ts:
            return default
        if isinstance(ts, datetime):
            return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return default
