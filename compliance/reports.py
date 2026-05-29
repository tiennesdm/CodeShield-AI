"""
Enterprise Compliance Report Generator

Automated compliance report generation per framework with:
- Evidence collection from scan results
- Control mapping (which scans satisfy which control)
- Gap analysis (missing controls vs implemented)
- Executive summary with compliance posture
- Export formats: JSON, Markdown (PDF/DOCX stubs)

Usage:
    generator = ComplianceReportGenerator(framework_registry, sla_tracker)
    report = generator.generate_report("soc2_type2", scan_results, org_id="org-123")
    gap_analysis = generator.gap_analysis("iso27001_2022", scan_results)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional
from uuid import uuid4

from pydantic import BaseModel, Field

from compliance.frameworks import (
    ComplianceControl,
    ComplianceFramework,
    ComplianceFrameworkRegistry,
    ControlStatus,
    get_framework_registry,
)


class ReportStatus(str, Enum):
    """Status of a compliance report."""
    GENERATING = "generating"
    COMPLETED = "completed"
    FAILED = "failed"


class ControlEvidence(BaseModel):
    """Evidence that a control is satisfied by scan results."""
    control_id: str
    control_name: str
    control_reference: str
    scan_id: Optional[str] = None
    scan_name: Optional[str] = None
    evidence_type: str = "unknown"  # scan_result, policy, configuration, manual
    evidence_description: str = ""
    scan_date: Optional[datetime] = None
    tool_versions: List[str] = Field(default_factory=list)
    findings_count: int = 0
    findings_summary: Dict[str, int] = Field(default_factory=dict)
    meets_requirement: bool = False
    gaps: List[str] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class ComplianceGap(BaseModel):
    """A gap between a required control and actual implementation."""
    control_id: str
    control_name: str
    control_reference: str
    severity: str = "medium"  # low, medium, high, critical
    description: str
    impact: str
    remediation_steps: List[str] = Field(default_factory=list)
    estimated_effort: str = "unknown"  # hours, days, weeks
    assigned_to: Optional[str] = None
    due_date: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class ComplianceReport(BaseModel):
    """A complete compliance report for a framework."""
    id: str = Field(default_factory=lambda: str(uuid4())[:12])
    framework_id: str
    framework_name: str
    organization_id: Optional[str] = None
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    generated_by: Optional[str] = None
    status: str = ReportStatus.COMPLETED.value
    report_period_start: Optional[datetime] = None
    report_period_end: Optional[datetime] = None

    # Executive Summary
    overall_compliance_percentage: float = 0.0
    total_controls: int = 0
    compliant_controls: int = 0
    partial_controls: int = 0
    non_compliant_controls: int = 0
    not_applicable_controls: int = 0

    # Scoring
    maturity_score: int = 0  # 0-100
    risk_level: str = "unknown"  # low, medium, high, critical
    trend_direction: str = "stable"  # improving, declining, stable
    previous_score: Optional[float] = None

    # Details
    control_evidence: List[ControlEvidence] = Field(default_factory=list)
    gaps: List[ComplianceGap] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    scan_summary: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def executive_summary(self) -> Dict[str, Any]:
        """High-level summary of the report (also embedded in to_dict)."""
        return {
            "overall_compliance_percentage": round(self.overall_compliance_percentage, 1),
            "total_controls": self.total_controls,
            "compliant_controls": self.compliant_controls,
            "partial_controls": self.partial_controls,
            "non_compliant_controls": self.non_compliant_controls,
            "not_applicable_controls": self.not_applicable_controls,
            "maturity_score": self.maturity_score,
            "risk_level": self.risk_level,
            "trend_direction": self.trend_direction,
            "previous_score": self.previous_score,
        }

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "framework_id": self.framework_id,
            "framework_name": self.framework_name,
            "organization_id": self.organization_id,
            "generated_at": self.generated_at.isoformat(),
            "generated_by": self.generated_by,
            "status": self.status,
            "report_period": {
                "start": self.report_period_start.isoformat() if self.report_period_start else None,
                "end": self.report_period_end.isoformat() if self.report_period_end else None,
            },
            "executive_summary": self.executive_summary,
            "control_evidence": [e.to_dict() for e in self.control_evidence],
            "gaps": [g.to_dict() for g in self.gaps],
            "recommendations": self.recommendations,
            "scan_summary": self.scan_summary,
            "metadata": self.metadata,
        }

    def to_markdown(self) -> str:
        """Generate a Markdown version of the report for human reading."""
        lines = [
            f"# Compliance Report: {self.framework_name}",
            f"",
            f"**Report ID:** {self.id}",
            f"**Generated:** {self.generated_at.strftime('%Y-%m-%d %H:%M UTC')}",
            f"**Period:** {self.report_period_start.strftime('%Y-%m-%d') if self.report_period_start else 'N/A'} "
            f"to {self.report_period_end.strftime('%Y-%m-%d') if self.report_period_end else 'N/A'}",
            f"",
            f"---",
            f"",
            f"## Executive Summary",
            f"",
            f"| Metric | Value |",
            f"|--------|-------|",
            f"| Overall Compliance | {self.overall_compliance_percentage:.1f}% |",
            f"| Total Controls | {self.total_controls} |",
            f"| Compliant | {self.compliant_controls} |",
            f"| Partial | {self.partial_controls} |",
            f"| Non-Compliant | {self.non_compliant_controls} |",
            f"| Not Applicable | {self.not_applicable_controls} |",
            f"| Maturity Score | {self.maturity_score}/100 |",
            f"| Risk Level | {self.risk_level.upper()} |",
            f"| Trend | {self.trend_direction} |",
            f"",
            f"---",
            f"",
            f"## Control Evidence",
            f"",
        ]

        for ev in self.control_evidence:
            status_icon = "[PASS]" if ev.meets_requirement else "[FAIL]"
            lines.extend([
                f"### {status_icon} {ev.control_name} ({ev.control_reference})",
                f"",
                f"**Type:** {ev.evidence_type}",
                f"**Description:** {ev.evidence_description}",
                f"**Findings:** {ev.findings_count}",
                f"",
            ])
            if ev.gaps:
                lines.extend(["**Gaps:**", ""])
                for gap in ev.gaps:
                    lines.append(f"- {gap}")
                lines.append("")

        if self.gaps:
            lines.extend([
                f"---",
                f"",
                f"## Gap Analysis",
                f"",
                f"**Total Gaps:** {len(self.gaps)}",
                f"",
            ])
            for gap in self.gaps:
                lines.extend([
                    f"### {gap.severity.upper()}: {gap.control_name}",
                    f"",
                    f"**Description:** {gap.description}",
                    f"**Impact:** {gap.impact}",
                    f"**Effort:** {gap.estimated_effort}",
                    f"",
                    f"**Remediation Steps:**",
                    f"",
                ])
                for step in gap.remediation_steps:
                    lines.append(f"1. {step}")
                lines.append("")

        if self.recommendations:
            lines.extend([
                f"---",
                f"",
                f"## Recommendations",
                f"",
            ])
            for rec in self.recommendations:
                lines.append(f"- {rec}")
            lines.append("")

        lines.append("---\n\n*Generated by CodeShield AI Compliance Engine*")
        return "\n".join(lines)


class ComplianceReportGenerator:
    """
    Generates automated compliance reports by mapping scan results
    to framework controls and performing gap analysis.
    """

    def __init__(
        self,
        framework_registry: Optional[ComplianceFrameworkRegistry] = None,
    ) -> None:
        self._registry = framework_registry or get_framework_registry()
        self._report_history: List[ComplianceReport] = []

    def generate_report(
        self,
        framework_id: str,
        scan_results: List[Dict[str, Any]],
        organization_id: Optional[str] = None,
        generated_by: Optional[str] = None,
        period_start: Optional[datetime] = None,
        period_end: Optional[datetime] = None,
    ) -> ComplianceReport:
        """
        Generate a compliance report for a framework based on scan results.

        Args:
            framework_id: ID of the compliance framework
            scan_results: List of scan result dictionaries
            organization_id: Optional organization scope
            generated_by: User ID who generated the report
            period_start: Report period start
            period_end: Report period end
        """
        framework = self._registry.get_framework(framework_id)
        if not framework:
            raise ValueError(f"Unknown framework: {framework_id}")

        report = ComplianceReport(
            framework_id=framework_id,
            framework_name=f"{framework.name} ({framework.version})",
            organization_id=organization_id,
            generated_by=generated_by,
            report_period_start=period_start,
            report_period_end=period_end or datetime.now(timezone.utc),
        )

        # Evaluate each control against scan evidence
        for control in framework.controls:
            evidence = self._evaluate_control(control, scan_results)
            report.control_evidence.append(evidence)

            # Categorize control status
            if evidence.meets_requirement:
                report.compliant_controls += 1
            elif evidence.gaps:
                if evidence.findings_count > 0:
                    report.partial_controls += 1
                else:
                    report.non_compliant_controls += 1
            else:
                report.not_applicable_controls += 1

        report.total_controls = len(framework.controls)

        # Calculate overall metrics
        applicable = report.compliant_controls + report.partial_controls + report.non_compliant_controls
        if applicable > 0:
            report.overall_compliance_percentage = (report.compliant_controls / applicable) * 100

        # Calculate maturity score (0-100)
        report.maturity_score = self._calculate_maturity_score(report)

        # Determine risk level
        report.risk_level = self._determine_risk_level(report)

        # Generate gap analysis
        report.gaps = self._generate_gaps(report.control_evidence, framework)

        # Generate recommendations
        report.recommendations = self._generate_recommendations(report, framework)

        # Build scan summary
        report.scan_summary = self._build_scan_summary(scan_results)

        self._report_history.append(report)
        return report

    def gap_analysis(
        self,
        framework_id: str,
        scan_results: List[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Perform gap analysis: identify missing controls vs implemented.

        Returns a detailed breakdown of compliance gaps with remediation guidance.
        """
        framework = self._registry.get_framework(framework_id)
        if not framework:
            raise ValueError(f"Unknown framework: {framework_id}")

        gaps: List[Dict[str, Any]] = []
        covered_controls = set()

        for control in framework.controls:
            evidence = self._evaluate_control(control, scan_results)
            if not evidence.meets_requirement:
                severity = "critical" if control.auto_verifiable else "medium"
                gap = {
                    "control_id": control.id,
                    "control_name": control.name,
                    "control_reference": control.control_reference,
                    "severity": severity,
                    "description": f"Control {control.control_reference} is not fully satisfied",
                    "impact": "Security compliance requirement not met",
                    "remediation_steps": control.scanner_capabilities + control.required_evidence,
                    "current_status": "non_compliant" if not evidence.findings_count else "partial",
                    "gaps_found": evidence.gaps,
                }
                gaps.append(gap)
            else:
                covered_controls.add(control.id)

        return {
            "framework_id": framework_id,
            "framework_name": framework.name,
            "total_controls": len(framework.controls),
            "covered_controls": len(covered_controls),
            "missing_controls": len(framework.controls) - len(covered_controls),
            "coverage_percentage": (len(covered_controls) / len(framework.controls)) * 100 if framework.controls else 0,
            "gaps": gaps,
            "top_priority_gaps": [g for g in gaps if g["severity"] == "critical"][:5],
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }

    def executive_summary(
        self,
        framework_ids: Optional[List[str]] = None,
        scan_results: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Generate executive summary across multiple frameworks.

        Returns a high-level compliance posture overview for leadership.
        """
        frameworks = (self._registry.list_frameworks()
                      if framework_ids is None
                      else [self._registry.get_framework(fid)
                            for fid in framework_ids
                            if self._registry.get_framework(fid)])

        framework_scores = []
        overall_total = 0
        overall_compliant = 0

        for fw in frameworks:
            if scan_results:
                report = self.generate_report(fw.id, scan_results)
                score = report.overall_compliance_percentage
                total = report.total_controls
                compliant = report.compliant_controls
            else:
                score = 0.0
                total = len(fw.controls)
                compliant = 0

            overall_total += total
            overall_compliant += compliant

            framework_scores.append({
                "framework_id": fw.id,
                "framework_name": fw.name,
                "compliance_percentage": round(score, 1),
                "total_controls": total,
                "compliant_controls": compliant,
                "risk_level": self._determine_risk_level_from_score(score),
            })

        overall_percentage = ((overall_compliant / overall_total) * 100
                              if overall_total > 0 else 0)

        # Generate trend from history
        trend = "stable"
        if self._report_history:
            recent = [r.overall_compliance_percentage for r in self._report_history[-10:]]
            if len(recent) >= 2:
                if recent[-1] > recent[0]:
                    trend = "improving"
                elif recent[-1] < recent[0]:
                    trend = "declining"

        return {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overall_compliance_percentage": round(overall_percentage, 1),
            "total_controls_across_frameworks": overall_total,
            "compliant_controls": overall_compliant,
            "frameworks_assessed": len(framework_scores),
            "risk_posture": self._determine_risk_level_from_score(overall_percentage),
            "trend_direction": trend,
            "framework_breakdown": framework_scores,
            "recommendations": self._generate_exec_recommendations(framework_scores),
        }

    # -- Internal helpers --

    def _evaluate_control(
        self,
        control: ComplianceControl,
        scan_results: List[Dict[str, Any]],
    ) -> ControlEvidence:
        """Evaluate a single control against scan results."""
        evidence = ControlEvidence(
            control_id=control.id,
            control_name=control.name,
            control_reference=control.control_reference,
            evidence_type="scan_result",
            evidence_description=f"Evaluated against {len(scan_results)} scan result(s)",
        )

        if not scan_results:
            evidence.meets_requirement = False
            evidence.gaps = ["No scan results available"]
            return evidence

        # Aggregate evidence from all scans
        total_findings = 0
        tools_used: set = set()
        latest_scan_date: Optional[datetime] = None

        for scan in scan_results:
            findings = scan.get("vulnerabilities", scan.get("vulnerabilities", []))
            if isinstance(findings, list):
                total_findings += len(findings)

            scan_date_str = scan.get("end_time") or scan.get("start_time")
            if scan_date_str:
                try:
                    sd = datetime.fromisoformat(scan_date_str.replace("Z", "+00:00"))
                    if latest_scan_date is None or sd > latest_scan_date:
                        latest_scan_date = sd
                except (ValueError, TypeError):
                    pass

            for tool in scan.get("tools_used", []):
                tools_used.add(tool)

            # Check for relevant scan types that satisfy control requirements
            if control.id.startswith("asvs"):
                # ASVS controls need SAST findings
                if scan.get("tools_used"):
                    tools_used.update(scan.get("tools_used", []))

        evidence.findings_count = total_findings
        evidence.tool_versions = sorted(tools_used)
        evidence.scan_date = latest_scan_date
        evidence.evidence_type = "scan_result"

        # Determine if the control is satisfied
        # For auto-verifiable controls, we need recent scans with relevant findings
        if control.auto_verifiable:
            has_recent_scan = latest_scan_date is not None
            has_findings = total_findings > 0
            has_tools = len(tools_used) > 0

            if has_recent_scan and has_tools:
                evidence.meets_requirement = True
                evidence.evidence_description = (
                    f"Scanned with {len(tools_used)} tools, "
                    f"{total_findings} findings detected as of "
                    f"{latest_scan_date.strftime('%Y-%m-%d')}"
                )
            else:
                evidence.meets_requirement = False
                evidence.evidence_description = "Insufficient scan evidence"
                if not has_recent_scan:
                    evidence.gaps.append("No recent scan data available")
                if not has_tools:
                    evidence.gaps.append("No scanning tools were used")
        else:
            evidence.meets_requirement = False
            evidence.evidence_type = "manual"
            evidence.evidence_description = "Requires manual verification"
            evidence.gaps.append("This control requires manual evidence")

        # Check for specific gaps based on control type
        required_caps = control.scanner_capabilities
        if required_caps and not tools_used:
            evidence.gaps.append("No security scanning tools were configured")

        control.status = (ControlStatus.COMPLIANT.value if evidence.meets_requirement
                          else ControlStatus.NON_COMPLIANT.value)
        control.last_evaluated = datetime.now(timezone.utc)
        control.evidence_count = total_findings

        return evidence

    def _calculate_maturity_score(self, report: ComplianceReport) -> int:
        """Calculate a maturity score (0-100) based on compliance posture."""
        if report.total_controls == 0:
            return 0

        score = report.overall_compliance_percentage

        # Boost for having more than basic scanning
        if report.scan_summary.get("tools_used_count", 0) >= 3:
            score = min(100, score + 5)
        if report.scan_summary.get("total_scans", 0) >= 5:
            score = min(100, score + 5)

        # Penalty for critical gaps
        critical_gaps = sum(1 for g in report.gaps if g.severity == "critical")
        score = max(0, score - critical_gaps * 10)

        return int(score)

    def _determine_risk_level(self, report: ComplianceReport) -> str:
        """Determine overall risk level from report data."""
        return self._determine_risk_level_from_score(report.overall_compliance_percentage)

    @staticmethod
    def _determine_risk_level_from_score(score: float) -> str:
        """Map a compliance score to a risk level."""
        if score >= 90:
            return "low"
        elif score >= 70:
            return "medium"
        elif score >= 50:
            return "high"
        else:
            return "critical"

    def _generate_gaps(
        self,
        evidence_list: List[ControlEvidence],
        framework: ComplianceFramework,
    ) -> List[ComplianceGap]:
        """Generate gap items from control evidence."""
        gaps: List[ComplianceGap] = []
        control_map = {c.id: c for c in framework.controls}

        for ev in evidence_list:
            if ev.meets_requirement:
                continue

            control = control_map.get(ev.control_id)
            if not control:
                continue

            severity = "medium"
            if not control.auto_verifiable:
                severity = "low"
            elif not ev.findings_count:
                severity = "critical" if "PCI" in framework.name or "SOC" in framework.name else "high"

            gap = ComplianceGap(
                control_id=ev.control_id,
                control_name=ev.control_name,
                control_reference=ev.control_reference,
                severity=severity,
                description=f"{ev.control_name} ({ev.control_reference}) is not satisfied. "
                            f"{ev.evidence_description}",
                impact=f"Non-compliance with {framework.name} requirement {ev.control_reference}",
                remediation_steps=(control.scanner_capabilities[:3]
                                   if control.scanner_capabilities
                                   else ["Implement required security controls"]),
                estimated_effort="1-2 weeks" if severity in ("high", "critical") else "3-5 days",
            )
            gaps.append(gap)

        return sorted(gaps, key=lambda g: {"critical": 0, "high": 1, "medium": 2, "low": 3}.get(g.severity, 4))

    def _generate_recommendations(
        self,
        report: ComplianceReport,
        framework: ComplianceFramework,
    ) -> List[str]:
        """Generate actionable recommendations from the report."""
        recommendations: List[str] = []

        if report.overall_compliance_percentage < 50:
            recommendations.append(
                f"CRITICAL: Immediate action needed. {framework.name} compliance is below 50%. "
                "Implement automated security scanning across all projects immediately."
            )
        elif report.overall_compliance_percentage < 75:
            recommendations.append(
                f"HIGH: {framework.name} compliance needs improvement. "
                "Expand scan coverage and address identified gaps within 30 days."
            )

        if report.non_compliant_controls > 0:
            recommendations.append(
                f"Address {report.non_compliant_controls} non-compliant controls. "
                "Prioritize controls marked as auto-verifiable for quickest improvement."
            )

        if report.scan_summary.get("tools_used_count", 0) < 2:
            recommendations.append(
                "Add additional scanning tools (e.g., SCA, secret scanning) to improve coverage."
            )

        if not recommendations:
            recommendations.append(
                "Maintain current security scanning practices. Schedule regular reviews."
            )

        return recommendations

    @staticmethod
    def _generate_exec_recommendations(framework_scores: List[Dict[str, Any]]) -> List[str]:
        """Generate executive-level recommendations."""
        recommendations = []
        low_compliance = [f for f in framework_scores if f["compliance_percentage"] < 60]

        if low_compliance:
            frameworks_str = ", ".join(f["framework_name"] for f in low_compliance)
            recommendations.append(
                f"Priority focus needed for: {frameworks_str}. "
                f"Establish remediation program within 30 days."
            )

        avg_score = (sum(f["compliance_percentage"] for f in framework_scores)
                     / len(framework_scores)) if framework_scores else 0
        if avg_score < 70:
            recommendations.append(
                "Overall compliance posture is below target. Consider security program maturity assessment."
            )

        recommendations.append(
            "Implement continuous compliance monitoring with automated scan scheduling."
        )

        return recommendations

    @staticmethod
    def _build_scan_summary(scan_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build a summary of scan results used in the report."""
        if not scan_results:
            return {"total_scans": 0, "tools_used_count": 0}

        total_vulns = 0
        tools: set = set()
        severity_counts: Dict[str, int] = {}

        for scan in scan_results:
            stats = scan.get("stats", {})
            for sev in ["critical", "high", "medium", "low", "info"]:
                severity_counts[sev] = severity_counts.get(sev, 0) + stats.get(sev, 0)
                total_vulns += stats.get(sev, 0)
            for tool in scan.get("tools_used", []):
                tools.add(tool)

        return {
            "total_scans": len(scan_results),
            "tools_used_count": len(tools),
            "tools": sorted(tools),
            "total_vulnerabilities": total_vulns,
            "severity_breakdown": severity_counts,
        }


# Singleton
_report_generator: Optional[ComplianceReportGenerator] = None


def get_report_generator() -> ComplianceReportGenerator:
    """Get or create the global compliance report generator."""
    global _report_generator
    if _report_generator is None:
        _report_generator = ComplianceReportGenerator()
    return _report_generator
