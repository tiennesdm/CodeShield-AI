"""
Enterprise Analytics Metrics Engine

Calculates comprehensive security metrics from scan results:
- Vulnerability trend over time (per severity)
- MTTR trends
- Risk score trend
- Scan coverage (files, languages)
- Top vulnerable files/repositories
- Most common vulnerability categories
- Remediation velocity (fixed per week)
- Security debt quantification

Usage:
    metrics = MetricsEngine()
    trends = metrics.vulnerability_trends(scan_results, period="30d")
    top_files = metrics.top_vulnerable_files(scan_results)
    debt = metrics.security_debt(scan_results)
"""

from __future__ import annotations

import math
from collections import Counter, defaultdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from pydantic import BaseModel, Field


class TrendDirection(str, Enum):
    """Direction of a metric trend."""
    IMPROVING = "improving"
    DECLINING = "declining"
    STABLE = "stable"


class MetricPoint(BaseModel):
    """A single data point in a time series."""
    timestamp: datetime
    value: float
    label: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class TimeSeries(BaseModel):
    """A time series of metric points."""
    metric_name: str
    unit: str = "count"
    points: List[MetricPoint] = Field(default_factory=list)
    trend_direction: str = TrendDirection.STABLE.value
    change_percentage: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metric_name": self.metric_name,
            "unit": self.unit,
            "trend_direction": self.trend_direction,
            "change_percentage": round(self.change_percentage, 2),
            "point_count": len(self.points),
            "latest_value": self.points[-1].value if self.points else 0,
            "points": [
                {
                    "timestamp": p.timestamp.isoformat(),
                    "value": round(p.value, 2),
                    "label": p.label,
                }
                for p in self.points
            ],
        }


class VulnerableFile(BaseModel):
    """A file ranked by vulnerability count."""
    file_path: str
    scan_id: Optional[str] = None
    repository: Optional[str] = None
    vulnerability_count: int = 0
    by_severity: Dict[str, int] = Field(default_factory=dict)
    categories: List[str] = Field(default_factory=list)
    risk_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class SecurityDebtItem(BaseModel):
    """A component of security debt."""
    category: str
    severity: str
    count: int
    estimated_effort_hours: float = 0.0
    estimated_effort_label: str = ""


class MetricsEngine:
    """
    Calculates security metrics and trends from scan data.

    Provides quantitative analytics for the dashboard and executive reports.
    """

    SEVERITY_WEIGHTS = {
        "CRITICAL": 25,
        "HIGH": 10,
        "MEDIUM": 4,
        "LOW": 1,
        "INFO": 0,
    }

    def __init__(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Vulnerability Trends
    # ------------------------------------------------------------------

    def vulnerability_trends(
        self,
        scan_results: List[Dict[str, Any]],
        period: str = "30d",
        granularity: str = "day",
    ) -> Dict[str, TimeSeries]:
        """
        Calculate vulnerability trends over time per severity.

        Args:
            scan_results: List of scan result dicts
            period: Time period (e.g., "7d", "30d", "90d")
            granularity: "day" or "week"

        Returns:
            Dict mapping severity -> TimeSeries
        """
        days = int(period.replace("d", "").replace("w", "0").replace("m", "00"))
        if "w" in period:
            days = int(period.replace("w", "")) * 7
        elif "m" in period:
            days = int(period.replace("m", "")) * 30

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        # Filter scans in period and group by date
        filtered_scans = []
        for scan in scan_results:
            ts = self._parse_timestamp(scan.get("end_time") or scan.get("start_time"))
            if ts and ts >= cutoff:
                filtered_scans.append((ts, scan))

        if not filtered_scans:
            return {}

        # Group by date bucket
        buckets: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for ts, scan in filtered_scans:
            if granularity == "week":
                bucket = ts.strftime("%Y-W%W")
            else:
                bucket = ts.strftime("%Y-%m-%d")

            stats = scan.get("stats", {})
            for sev in ["critical", "high", "medium", "low", "info"]:
                buckets[bucket][sev] += stats.get(sev, 0)

        # Build time series per severity
        severity_keys = ["critical", "high", "medium", "low", "info"]
        result: Dict[str, TimeSeries] = {}

        for sev_key in severity_keys:
            sev_upper = sev_key.upper()
            points: List[MetricPoint] = []
            for bucket in sorted(buckets.keys()):
                val = buckets[bucket].get(sev_key, 0)
                ts = datetime.strptime(bucket, "%Y-%m-%d" if granularity == "day" else "%Y-W%W")
                ts = ts.replace(tzinfo=timezone.utc)
                points.append(MetricPoint(timestamp=ts, value=float(val), label=bucket))

            ts_obj = TimeSeries(
                metric_name=f"vulnerabilities_{sev_key}",
                unit="count",
                points=points,
            )
            ts_obj.trend_direction = self._calculate_trend_direction(points)
            ts_obj.change_percentage = self._calculate_change_percentage(points)
            result[sev_upper] = ts_obj

        return result

    def risk_score_trend(
        self,
        scan_results: List[Dict[str, Any]],
        period: str = "30d",
    ) -> TimeSeries:
        """Calculate risk score trend over time."""
        days = int(period.replace("d", "").replace("w", "0"))
        if "w" in period:
            days = int(period.replace("w", "")) * 7
        elif "m" in period:
            days = int(period.replace("m", "")) * 30

        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        filtered = []
        for scan in scan_results:
            ts = self._parse_timestamp(scan.get("end_time") or scan.get("start_time"))
            if ts and ts >= cutoff:
                filtered.append((ts, scan))

        points: List[MetricPoint] = []
        for ts, scan in sorted(filtered, key=lambda x: x[0]):
            risk = scan.get("risk_score", 0)
            points.append(MetricPoint(
                timestamp=ts,
                value=float(risk),
                label=ts.strftime("%Y-%m-%d"),
            ))

        ts_obj = TimeSeries(metric_name="risk_score", unit="score", points=points)
        ts_obj.trend_direction = self._calculate_trend_direction(points)
        ts_obj.change_percentage = self._calculate_change_percentage(points)
        return ts_obj

    # ------------------------------------------------------------------
    # Top Vulnerable Files / Repositories
    # ------------------------------------------------------------------

    def top_vulnerable_files(
        self,
        scan_results: List[Dict[str, Any]],
        limit: int = 20,
    ) -> List[VulnerableFile]:
        """
        Rank files by vulnerability count across all scans.

        Returns the most vulnerable files with severity breakdowns.
        """
        file_map: Dict[str, VulnerableFile] = {}

        for scan in scan_results:
            scan_id = scan.get("scan_id", "unknown")
            repo = scan.get("name", scan.get("source_path", "unknown"))
            for vuln in scan.get("vulnerabilities", []):
                file_path = vuln.get("file_path", "unknown")
                severity = (vuln.get("severity", "INFO") or "INFO").upper()
                category = vuln.get("category", "Unknown")

                if file_path not in file_map:
                    file_map[file_path] = VulnerableFile(
                        file_path=file_path,
                        scan_id=scan_id,
                        repository=repo,
                    )

                vf = file_map[file_path]
                vf.vulnerability_count += 1
                vf.by_severity[severity] = vf.by_severity.get(severity, 0) + 1
                if category not in vf.categories:
                    vf.categories.append(category)

        # Calculate risk score for each file
        for vf in file_map.values():
            vf.risk_score = self._calculate_file_risk_score(vf.by_severity)

        # Sort by risk score descending
        sorted_files = sorted(file_map.values(), key=lambda f: f.risk_score, reverse=True)
        return sorted_files[:limit]

    def top_vulnerable_repositories(
        self,
        scan_results: List[Dict[str, Any]],
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Rank repositories/projects by total vulnerability risk score."""
        repo_stats: Dict[str, Dict[str, Any]] = defaultdict(
            lambda: {"name": "", "total_vulns": 0, "by_severity": {}, "risk_score": 0.0, "scan_count": 0}
        )

        for scan in scan_results:
            name = scan.get("name", scan.get("source_path", "unknown"))
            stats = scan.get("stats", {})
            if name not in repo_stats:
                repo_stats[name]["name"] = name
            repo_stats[name]["total_vulns"] += stats.get("total", 0)
            repo_stats[name]["scan_count"] += 1
            for sev in ["critical", "high", "medium", "low", "info"]:
                repo_stats[name]["by_severity"][sev.upper()] = (
                    repo_stats[name]["by_severity"].get(sev.upper(), 0) + stats.get(sev, 0)
                )

        # Calculate risk scores
        for name, data in repo_stats.items():
            data["risk_score"] = self._calculate_risk_score_from_counts(data["by_severity"])

        sorted_repos = sorted(repo_stats.values(), key=lambda r: r["risk_score"], reverse=True)
        return sorted_repos[:limit]

    # ------------------------------------------------------------------
    # Vulnerability Categories
    # ------------------------------------------------------------------

    def top_vulnerability_categories(
        self,
        scan_results: List[Dict[str, Any]],
        limit: int = 10,
    ) -> List[Dict[str, Any]]:
        """Get the most common vulnerability categories across all scans."""
        category_counts: Dict[str, Dict[str, Any]] = {}

        for scan in scan_results:
            for vuln in scan.get("vulnerabilities", []):
                cat = vuln.get("category", "Unknown") or "Unknown"
                severity = (vuln.get("severity", "INFO") or "INFO").upper()
                if cat not in category_counts:
                    category_counts[cat] = {"category": cat, "count": 0, "by_severity": {}}
                category_counts[cat]["count"] += 1
                category_counts[cat]["by_severity"][severity] = (
                    category_counts[cat]["by_severity"].get(severity, 0) + 1
                )

        sorted_cats = sorted(category_counts.values(), key=lambda c: c["count"], reverse=True)
        return sorted_cats[:limit]

    # ------------------------------------------------------------------
    # Scan Coverage
    # ------------------------------------------------------------------

    def scan_coverage(
        self,
        scan_results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Calculate scan coverage metrics.

        Returns file counts, line counts, language coverage, etc.
        """
        total_files = 0
        total_lines = 0
        all_languages: set = set()
        total_vulns = 0
        tool_usage: Counter = Counter()
        scans_by_language: Dict[str, int] = defaultdict(int)

        for scan in scan_results:
            total_files += scan.get("total_files", 0)
            total_lines += scan.get("total_lines", 0)
            langs = scan.get("languages", [])
            all_languages.update(langs)
            for lang in langs:
                scans_by_language[lang] += scan.get("total_files", 0)
            total_vulns += len(scan.get("vulnerabilities", []))
            for tool in scan.get("tools_used", []):
                tool_usage[tool] += 1

        return {
            "total_scans": len(scan_results),
            "total_files_scanned": total_files,
            "total_lines_scanned": total_lines,
            "languages_detected": sorted(all_languages),
            "language_coverage": [
                {"language": lang, "files": count}
                for lang, count in sorted(scans_by_language.items(), key=lambda x: x[1], reverse=True)
            ],
            "total_vulnerabilities_found": total_vulns,
            "tools_used": [
                {"tool": tool, "scan_count": count}
                for tool, count in tool_usage.most_common()
            ],
            "avg_files_per_scan": round(total_files / len(scan_results), 1) if scan_results else 0,
            "avg_lines_per_scan": round(total_lines / len(scan_results), 1) if scan_results else 0,
        }

    # ------------------------------------------------------------------
    # Remediation Velocity
    # ------------------------------------------------------------------

    def remediation_velocity(
        self,
        sla_records: List[Dict[str, Any]],
        period_weeks: int = 12,
    ) -> Dict[str, Any]:
        """
        Calculate remediation velocity: fixes per week.

        Args:
            sla_records: List of SLA tracking record dicts
            period_weeks: Number of weeks to analyze

        Returns:
            Dict with weekly velocity metrics
        """
        cutoff = datetime.now(timezone.utc) - timedelta(weeks=period_weeks)

        # Group remediated vulnerabilities by week
        weekly_fixed: Dict[str, int] = defaultdict(int)
        weekly_by_severity: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        total_ttr: List[float] = []
        ttr_by_severity: Dict[str, List[float]] = defaultdict(list)

        for record in sla_records:
            if record.get("status") != "remediated":
                continue
            remediated_at = self._parse_timestamp(record.get("remediated_at"))
            if not remediated_at or remediated_at < cutoff:
                continue

            week_key = remediated_at.strftime("%Y-W%W")
            weekly_fixed[week_key] += 1

            sev = record.get("severity", "UNKNOWN")
            weekly_by_severity[week_key][sev] += 1

            ttr = record.get("time_to_remediate_hours")
            if ttr is not None:
                total_ttr.append(ttr)
                ttr_by_severity[sev].append(ttr)

        # Calculate velocity trend
        weeks = sorted(weekly_fixed.keys())
        total_fixed = sum(weekly_fixed.values())
        avg_per_week = total_fixed / period_weeks if period_weeks > 0 else 0

        # Build weekly points
        points = []
        for week in weeks:
            points.append({
                "week": week,
                "fixed": weekly_fixed[week],
                "by_severity": dict(weekly_by_severity[week]),
            })

        # MTTR
        mttr_hours = sum(total_ttr) / len(total_ttr) if total_ttr else 0

        return {
            "period_weeks": period_weeks,
            "total_fixed": total_fixed,
            "avg_per_week": round(avg_per_week, 2),
            "mttr_hours": round(mttr_hours, 2),
            "mttr_days": round(mttr_hours / 24, 2),
            "mttr_by_severity": {
                sev: round(sum(times) / len(times), 2) if times else 0
                for sev, times in ttr_by_severity.items()
            },
            "weekly_breakdown": points,
            "trend": "improving" if len(weeks) >= 2 and weekly_fixed[weeks[-1]] >= weekly_fixed[weeks[0]] else "stable",
        }

    # ------------------------------------------------------------------
    # Security Debt Quantification
    # ------------------------------------------------------------------

    def security_debt(
        self,
        scan_results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Quantify security debt: the accumulation of unremediated vulnerabilities.

        Returns total debt score, debt by severity, estimated remediation effort,
        and debt trend indicators.
        """
        all_vulns: List[Dict[str, Any]] = []
        for scan in scan_results:
            for vuln in scan.get("vulnerabilities", []):
                vuln["_scan_date"] = scan.get("end_time") or scan.get("start_time")
                vuln["_scan_name"] = scan.get("name", "unknown")
            all_vulns.extend(scan.get("vulnerabilities", []))

        if not all_vulns:
            return {
                "total_debt_score": 0,
                "total_vulnerabilities": 0,
                "estimated_remediation_hours": 0,
                "estimated_remediation_days": 0,
                "by_severity": {},
                "by_category": [],
                "debt_rating": "A",
                "risk_level": "low",
            }

        # Count by severity
        by_severity: Dict[str, Dict[str, Any]] = {}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = sum(1 for v in all_vulns if (v.get("severity") or "INFO").upper() == sev)
            weight = self.SEVERITY_WEIGHTS.get(sev, 0)
            by_severity[sev] = {
                "count": count,
                "weight": weight,
                "debt_contribution": count * weight,
                "avg_effort_hours": self._effort_hours_for_severity(sev),
                "total_effort_hours": count * self._effort_hours_for_severity(sev),
            }

        total_debt_score = sum(s["debt_contribution"] for s in by_severity.values())
        total_effort = sum(s["total_effort_hours"] for s in by_severity.values())

        # Debt categories (CWE-based grouping)
        cwe_counter: Counter = Counter()
        for vuln in all_vulns:
            cwe = vuln.get("cwe_id") or vuln.get("category", "Unknown")
            cwe_counter[cwe] += 1

        top_cwes = [
            {"cwe": cwe, "count": count}
            for cwe, count in cwe_counter.most_common(10)
        ]

        # Debt rating
        rating, risk = self._debt_rating(total_debt_score, len(all_vulns))

        return {
            "total_debt_score": total_debt_score,
            "total_vulnerabilities": len(all_vulns),
            "estimated_remediation_hours": round(total_effort, 1),
            "estimated_remediation_days": round(total_effort / 8, 1),  # 8 hours/day
            "estimated_remediation_weeks": round(total_effort / 40, 1),  # 40 hours/week
            "by_severity": by_severity,
            "by_category": top_cwes,
            "debt_rating": rating,
            "risk_level": risk,
            "avg_fix_effort_hours": round(total_effort / len(all_vulns), 1) if all_vulns else 0,
        }

    # ------------------------------------------------------------------
    # Composite Security Score
    # ------------------------------------------------------------------

    def calculate_security_score(
        self,
        scan_results: List[Dict[str, Any]],
        sla_records: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Calculate a composite security score (0-100) for the organization.

        Factors:
        - Vulnerability density (vulns per 1000 LOC)
        - Severity distribution
        - Remediation speed (MTTR)
        - Scan coverage
        - Policy compliance rate
        """
        if not scan_results:
            return {"overall_score": 0, "rating": "F", "factors": {}}

        # Factor 1: Vulnerability density (lower is better)
        total_vulns = 0
        total_lines = 0
        severity_counts = Counter()
        for scan in scan_results:
            stats = scan.get("stats", {})
            total_vulns += stats.get("total", 0)
            total_lines += scan.get("total_lines", 0)
            for sev in ["critical", "high", "medium", "low"]:
                severity_counts[sev.upper()] += stats.get(sev, 0)

        density_score = 100.0
        if total_lines > 0:
            density_per_1k = (total_vulns / total_lines) * 1000
            density_score = max(0, 100 - density_per_1k * 5)

        # Factor 2: Severity distribution (lower critical/high is better)
        sev_score = 100.0
        if total_vulns > 0:
            critical_pct = severity_counts["CRITICAL"] / total_vulns
            high_pct = severity_counts["HIGH"] / total_vulns
            sev_score = max(0, 100 - (critical_pct * 80) - (high_pct * 30))

        # Factor 3: Remediation speed
        mttr_score = 50.0  # Default neutral
        if sla_records:
            mttr_data = self._calculate_mttr_from_records(sla_records)
            if mttr_data["count"] > 0:
                avg_days = mttr_data["mttr_days"]
                # < 7 days = excellent, > 90 days = poor
                if avg_days <= 7:
                    mttr_score = 100
                elif avg_days >= 90:
                    mttr_score = 0
                else:
                    mttr_score = max(0, 100 - ((avg_days - 7) / 83) * 100)

        # Factor 4: Scan coverage
        unique_langs = set()
        for scan in scan_results:
            unique_langs.update(scan.get("languages", []))
        coverage_score = min(100, len(unique_langs) * 15 + len(scan_results) * 2)

        # Weighted composite
        weights = {"density": 0.3, "severity": 0.25, "mttr": 0.25, "coverage": 0.2}
        overall = (
            density_score * weights["density"] +
            sev_score * weights["severity"] +
            mttr_score * weights["mttr"] +
            coverage_score * weights["coverage"]
        )

        rating = self._score_to_rating(overall)

        return {
            "overall_score": round(overall, 1),
            "rating": rating,
            "factors": {
                "vulnerability_density": {
                    "score": round(density_score, 1),
                    "weight": weights["density"],
                    "vulns_per_1000_loc": round((total_vulns / total_lines) * 1000, 2) if total_lines else 0,
                },
                "severity_distribution": {
                    "score": round(sev_score, 1),
                    "weight": weights["severity"],
                    "severity_counts": dict(severity_counts),
                },
                "remediation_speed": {
                    "score": round(mttr_score, 1),
                    "weight": weights["mttr"],
                    "mttr_days": round(mttr_data.get("mttr_days", 0), 1) if sla_records else None,
                },
                "scan_coverage": {
                    "score": round(coverage_score, 1),
                    "weight": weights["coverage"],
                    "languages_covered": len(unique_langs),
                    "total_scans": len(scan_results),
                },
            },
        }

    # ------------------------------------------------------------------
    # Helper Methods
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_timestamp(ts: Any) -> Optional[datetime]:
        """Parse a timestamp string to datetime."""
        if not ts:
            return None
        if isinstance(ts, datetime):
            return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
        try:
            dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _calculate_trend_direction(points: List[MetricPoint]) -> str:
        """Calculate trend direction from time series points."""
        if len(points) < 3:
            return TrendDirection.STABLE.value
        # Compare first third vs last third
        n = len(points)
        early_avg = sum(p.value for p in points[:n // 3]) / max(1, n // 3)
        late_avg = sum(p.value for p in points[2 * n // 3:]) / max(1, n - 2 * n // 3)
        if early_avg == 0:
            return TrendDirection.STABLE.value
        change = (late_avg - early_avg) / early_avg
        if change < -0.1:
            return TrendDirection.IMPROVING.value  # Fewer vulns = improving
        elif change > 0.1:
            return TrendDirection.DECLINING.value
        return TrendDirection.STABLE.value

    @staticmethod
    def _calculate_change_percentage(points: List[MetricPoint]) -> float:
        """Calculate percentage change from first to last point."""
        if len(points) < 2:
            return 0.0
        first = points[0].value
        last = points[-1].value
        if first == 0:
            return 100.0 if last > 0 else 0.0
        return ((last - first) / first) * 100

    @classmethod
    def _calculate_file_risk_score(cls, by_severity: Dict[str, int]) -> float:
        """Calculate risk score for a file from severity counts."""
        score = 0.0
        for sev, count in by_severity.items():
            weight = cls.SEVERITY_WEIGHTS.get(sev, 0)
            score += count * weight
        return score

    @classmethod
    def _calculate_risk_score_from_counts(cls, by_severity: Dict[str, int]) -> float:
        """Calculate risk score from severity count dict."""
        score = 0.0
        for sev, count in by_severity.items():
            weight = cls.SEVERITY_WEIGHTS.get(sev, cls.SEVERITY_WEIGHTS.get(sev.upper(), 0))
            score += count * weight
        return score

    @staticmethod
    def _effort_hours_for_severity(severity: str) -> float:
        """Estimate remediation effort hours for a severity level."""
        effort_map = {
            "CRITICAL": 8.0,
            "HIGH": 4.0,
            "MEDIUM": 2.0,
            "LOW": 0.5,
            "INFO": 0.25,
        }
        return effort_map.get(severity.upper(), 1.0)

    @staticmethod
    def _debt_rating(debt_score: float, vuln_count: int) -> Tuple[str, str]:
        """Map debt score to a letter rating."""
        if debt_score == 0:
            return "A+", "low"
        elif debt_score < 10:
            return "A", "low"
        elif debt_score < 30:
            return "B", "low"
        elif debt_score < 60:
            return "C", "medium"
        elif debt_score < 100:
            return "D", "high"
        elif debt_score < 200:
            return "E", "high"
        else:
            return "F", "critical"

    @staticmethod
    def _score_to_rating(score: float) -> str:
        """Convert numeric score to letter rating."""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        elif score >= 50:
            return "E"
        else:
            return "F"

    @staticmethod
    def _calculate_mttr_from_records(sla_records: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate MTTR from SLA records."""
        remediated = [r for r in sla_records
                      if r.get("status") == "remediated"
                      and r.get("time_to_remediate_hours") is not None]
        if not remediated:
            return {"mttr_hours": 0, "mttr_days": 0, "count": 0}
        total = sum(r["time_to_remediate_hours"] for r in remediated)
        count = len(remediated)
        return {
            "mttr_hours": total / count,
            "mttr_days": total / count / 24,
            "count": count,
        }
