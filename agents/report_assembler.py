"""
Report Assembler Agent - Final Report Compilation for CodeShield AI.

Compiles findings from all scanning agents into comprehensive reports
with cross-referenced findings, chain visualization, and multiple export formats.

Features:
- Cross-referenced findings (which agents detected each finding)
- Chain visualization (SAST -> Taint -> DAST confirmation)
- Executive Summary with risk scoring and compliance status
- Findings grouped by severity, category, and agent
- Remediation plan with prioritized recommendations
- Compliance mapping (SOC2, ISO27001, GDPR, PCI DSS)
- Export: PDF, SARIF, HTML, JSON, Executive Brief
- CrewAI-compatible Agent interface
"""

import asyncio
import json
import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from models.vulnerability import ScanResult, SeverityLevel, Vulnerability
from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPORT_COMPANY_NAME = os.environ.get("CS_REPORT_COMPANY", "CodeShield AI")
REPORT_LOGO_URL = os.environ.get("CS_REPORT_LOGO", "")

# Compliance framework mappings
COMPLIANCE_MAPPINGS: Dict[str, Dict[str, List[str]]] = {
    "SOC2": {
        "CC6.1": ["SQL Injection", "XSS", "Code Injection", "Command Injection"],
        "CC6.2": ["Hardcoded Secret", "Weak Crypto", "Missing Headers"],
        "CC6.3": ["Authentication Bypass", "Authorization Bypass", "Privilege Escalation"],
        "CC7.1": ["Path Traversal", "Information Disclosure"],
        "CC7.2": ["CORS", "Insecure Deserialization", "XXE"],
        "CC8.1": ["Input Validation", "SSRF"],
    },
    "ISO27001": {
        "A.8.24": ["SQL Injection", "XSS", "Code Injection"],
        "A.8.25": ["Hardcoded Secret", "Weak Crypto"],
        "A.8.26": ["Authentication Bypass", "Authorization Bypass"],
        "A.8.28": ["Missing Headers", "CORS"],
        "A.8.29": ["Path Traversal", "Information Disclosure"],
        "A.8.31": ["Input Validation", "SSRF"],
        "A.8.33": ["Insecure Deserialization", "XXE"],
    },
    "GDPR": {
        "Art.25": ["Hardcoded Secret", "Weak Crypto", "Information Disclosure"],
        "Art.32": ["SQL Injection", "XSS", "Code Injection", "Missing Headers"],
        "Art.35": ["Authentication Bypass", "Authorization Bypass"],
    },
    "PCI DSS": {
        "6.5.1": ["SQL Injection", "Command Injection"],
        "6.5.7": ["XSS"],
        "6.5.8": ["Authentication Bypass"],
        "6.5.9": ["Hardcoded Secret", "Weak Crypto"],
        "6.5.10": ["Missing Headers"],
        "2.1": ["Insecure Configuration", "CORS"],
    },
}

# OWASP Top 10 category mapping
OWASP_CATEGORY_MAP: Dict[str, str] = {
    "SQL Injection": "A03 - Injection",
    "Code Injection": "A03 - Injection",
    "Command Injection": "A03 - Injection",
    "XSS": "A03 - Injection",
    "Hardcoded Secret": "A07 - Identification & Authentication Failures",
    "Weak Crypto": "A02 - Cryptographic Failures",
    "Authentication Bypass": "A07 - Identification & Authentication Failures",
    "Authorization Bypass": "A01 - Broken Access Control",
    "Path Traversal": "A01 - Broken Access Control",
    "Missing Headers": "A05 - Security Misconfiguration",
    "CORS": "A05 - Security Misconfiguration",
    "Insecure Deserialization": "A08 - Software & Data Integrity Failures",
    "XXE": "A04 - Insecure Design",
    "SSRF": "A10 - Server-Side Request Forgery",
    "Input Validation": "A03 - Injection",
}

# Severity weights for risk calculation
SEVERITY_WEIGHTS = {
    "CRITICAL": 25,
    "HIGH": 10,
    "MEDIUM": 4,
    "LOW": 1,
    "INFO": 0,
}

# ETA estimates for remediation (in hours)
REMEDIATION_ETA = {
    "CRITICAL": 4,
    "HIGH": 24,
    "MEDIUM": 72,
    "LOW": 168,
    "INFO": 336,
}


class ReportFormat(str, Enum):
    """Available report export formats."""

    PDF = "pdf"
    SARIF = "sarif"
    HTML = "html"
    JSON = "json"
    EXECUTIVE_BRIEF = "executive_brief"


@dataclass
class CrossReferencedFinding:
    """A finding with cross-references from multiple agents."""

    finding_id: str
    vulnerability: Vulnerability
    agent_sources: List[str] = field(default_factory=list)
    chain_ids: List[str] = field(default_factory=list)
    evidence: List[Dict[str, Any]] = field(default_factory=list)
    confidence_boost: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "finding_id": self.finding_id,
            "vulnerability": self.vulnerability.model_dump(),
            "agent_sources": self.agent_sources,
            "chain_ids": self.chain_ids,
            "evidence": self.evidence,
            "confidence_boost": self.confidence_boost,
        }


@dataclass
class ComplianceStatus:
    """Compliance status for a framework."""

    framework: str
    control_statuses: Dict[str, str] = field(default_factory=dict)
    overall_status: str = "unknown"
    passing_controls: int = 0
    failing_controls: int = 0
    total_controls: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "framework": self.framework,
            "overall_status": self.overall_status,
            "passing_controls": self.passing_controls,
            "failing_controls": self.failing_controls,
            "total_controls": self.total_controls,
            "control_statuses": self.control_statuses,
        }


@dataclass
class RemediationItem:
    """An item in the remediation plan."""

    vuln_id: str
    title: str
    severity: str
    category: str
    recommendation: str
    eta_hours: int = 0
    priority: int = 0
    effort: str = "medium"
        
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "vuln_id": self.vuln_id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "recommendation": self.recommendation,
            "eta_hours": self.eta_hours,
            "priority": self.priority,
            "effort": self.effort,
        }


@dataclass
class AgentFindingSummary:
    """Summary of findings per agent."""

    agent_name: str
    total_findings: int = 0
    by_severity: Dict[str, int] = field(default_factory=dict)
    by_category: Dict[str, int] = field(default_factory=dict)
    avg_confidence: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "agent_name": self.agent_name,
            "total_findings": self.total_findings,
            "by_severity": self.by_severity,
            "by_category": self.by_category,
            "avg_confidence": round(self.avg_confidence, 2),
        }


class ReportAssembler:
    """
    Report Assembler Agent - Final Report Compilation.

    Compiles findings from all scanning agents into comprehensive,
    cross-referenced reports with multiple export formats.

    Compatible with CrewAI agent interfaces.
    """

    def __init__(self) -> None:
        """Initialize the Report Assembler."""
        logger.info("ReportAssembler initialized")

    # ========================================================================
    # A. Cross-Referenced Findings
    # ========================================================================

    def build_cross_referenced_findings(
        self,
        vulnerabilities: List[Vulnerability],
        chain_data: Optional[List[Dict[str, Any]]] = None,
    ) -> List[CrossReferencedFinding]:
        """
        Build cross-referenced findings showing which agents detected each.

        Args:
            vulnerabilities: All vulnerabilities
            chain_data: Optional chain visualization data

        Returns:
            List of cross-referenced findings
        """
        # Group by file+line+category
        groups: Dict[str, List[Vulnerability]] = defaultdict(list)
        for v in vulnerabilities:
            key = f"{v.file_path}:{v.line_number}:{v.category}"
            groups[key].append(v)

        results: List[CrossReferencedFinding] = []
        for key, group in groups.items():
            best = max(group, key=lambda v: {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(v.confidence, 0))
            sources = sorted(set(v.tool_source for v in group))

            evidence = []
            for v in group:
                evidence.append(
                    {
                        "agent": v.tool_source,
                        "confidence": v.confidence,
                        "description": v.description,
                        "code_snippet": v.code_snippet,
                    }
                )

            # Compute confidence boost from multi-agent agreement
            confidence_boost = (len(sources) - 1) * 20.0 if len(sources) > 1 else 0.0

            # Find chain IDs
            chain_ids = []
            if chain_data:
                for chain in chain_data:
                    if any(c.get("vuln_id") == best.id for c in chain.get("nodes", [])):
                        chain_ids.append(chain.get("chain_id", ""))

            results.append(
                CrossReferencedFinding(
                    finding_id=best.id,
                    vulnerability=best,
                    agent_sources=sources,
                    chain_ids=chain_ids,
                    evidence=evidence,
                    confidence_boost=confidence_boost,
                )
            )

        # Sort by severity descending
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        results.sort(
            key=lambda r: severity_order.get(r.vulnerability.severity.upper(), 5)
        )

        logger.info("Built %d cross-referenced findings", len(results))
        return results

    # ========================================================================
    # B. Report Sections
    # ========================================================================

    def build_executive_summary(
        self,
        scan_result: ScanResult,
        triaged_findings: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        """
        Build the Executive Summary section.

        Args:
            scan_result: Scan result
            triaged_findings: Optional triaged findings

        Returns:
            Executive summary dict
        """
        stats = scan_result.stats
        risk_score = scan_result.risk_score

        # Determine risk level
        if risk_score >= 75:
            risk_level = "CRITICAL"
            risk_color = "#DC2626"
        elif risk_score >= 50:
            risk_level = "HIGH"
            risk_color = "#EA580C"
        elif risk_score >= 25:
            risk_level = "MEDIUM"
            risk_color = "#D97706"
        else:
            risk_level = "LOW"
            risk_color = "#65A30D"

        # Top findings
        sorted_vulns = sorted(
            scan_result.vulnerabilities,
            key=lambda v: (
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
                    v.severity.upper(), 5
                ),
            ),
        )[:10]

        top_findings = []
        for v in sorted_vulns:
            top_findings.append(
                {
                    "id": v.id,
                    "title": v.title,
                    "severity": v.severity,
                    "category": v.category,
                    "file": f"{v.file_path}:{v.line_number}",
                }
            )

        # Compliance status
        compliance = self._compute_compliance_summary(scan_result.vulnerabilities)

        return {
            "scan_name": scan_result.name,
            "scan_id": scan_result.scan_id,
            "scan_date": scan_result.start_time.isoformat() if scan_result.start_time else None,
            "risk_score": risk_score,
            "risk_level": risk_level,
            "risk_color": risk_color,
            "total_vulnerabilities": stats.get("total", 0),
            "by_severity": {
                "critical": stats.get("critical", 0),
                "high": stats.get("high", 0),
                "medium": stats.get("medium", 0),
                "low": stats.get("low", 0),
                "info": stats.get("info", 0),
            },
            "files_scanned": scan_result.total_files,
            "tools_used": scan_result.tools_used,
            "top_findings": top_findings,
            "compliance_summary": [c.to_dict() for c in compliance],
            "remediation_priority": self._get_remediation_priority(scan_result.vulnerabilities),
        }

    def build_findings_by_severity(
        self, vulnerabilities: List[Vulnerability]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group findings by severity level.

        Args:
            vulnerabilities: Vulnerabilities

        Returns:
            Dict of severity -> findings
        """
        result: Dict[str, List[Dict[str, Any]]] = {
            "CRITICAL": [],
            "HIGH": [],
            "MEDIUM": [],
            "LOW": [],
            "INFO": [],
        }

        for v in sorted(
            vulnerabilities,
            key=lambda x: x.line_number,
        ):
            entry = {
                "id": v.id,
                "title": v.title,
                "category": v.category,
                "cwe_id": v.cwe_id,
                "cwe_name": v.cwe_name,
                "file_path": v.file_path,
                "line_number": v.line_number,
                "column": v.column,
                "description": v.description,
                "code_snippet": v.code_snippet,
                "fix_suggestion": v.fix_suggestion,
                "tool_source": v.tool_source,
                "confidence": v.confidence,
                "cvss_score": v.cvss_score,
                "owasp_category": OWASP_CATEGORY_MAP.get(v.category, "Unknown"),
            }
            sev = v.severity.upper()
            if sev in result:
                result[sev].append(entry)

        return result

    def build_findings_by_category(
        self, vulnerabilities: List[Vulnerability]
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group findings by vulnerability category.

        Args:
            vulnerabilities: Vulnerabilities

        Returns:
            Dict of category -> findings
        """
        groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)

        for v in vulnerabilities:
            entry = {
                "id": v.id,
                "title": v.title,
                "severity": v.severity,
                "file_path": v.file_path,
                "line_number": v.line_number,
                "description": v.description,
                "code_snippet": v.code_snippet,
                "fix_suggestion": v.fix_suggestion,
                "tool_source": v.tool_source,
                "cwe_id": v.cwe_id,
            }
            groups[v.category].append(entry)

        # Sort each group by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        for cat in groups:
            groups[cat].sort(
                key=lambda x: severity_order.get(x["severity"].upper(), 5)
            )

        return dict(groups)

    def build_findings_by_agent(
        self, vulnerabilities: List[Vulnerability]
    ) -> Dict[str, AgentFindingSummary]:
        """
        Build summary of findings per agent.

        Args:
            vulnerabilities: Vulnerabilities

        Returns:
            Dict of agent_name -> summary
        """
        summaries: Dict[str, AgentFindingSummary] = {}

        for v in vulnerabilities:
            agent = v.tool_source
            if agent not in summaries:
                summaries[agent] = AgentFindingSummary(agent_name=agent)

            summary = summaries[agent]
            summary.total_findings += 1
            sev = v.severity.upper()
            summary.by_severity[sev] = summary.by_severity.get(sev, 0) + 1
            summary.by_category[v.category] = summary.by_category.get(v.category, 0) + 1

        # Compute average confidence per agent
        for agent, summary in summaries.items():
            agent_vulns = [v for v in vulnerabilities if v.tool_source == agent]
            conf_scores = []
            for v in agent_vulns:
                conf_scores.append(
                    {"HIGH": 1.0, "MEDIUM": 0.5, "LOW": 0.25}.get(v.confidence.upper(), 0.5)
                )
            if conf_scores:
                summary.avg_confidence = sum(conf_scores) / len(conf_scores)

        return summaries

    def build_chained_findings(
        self,
        cross_referenced: List[CrossReferencedFinding],
    ) -> List[Dict[str, Any]]:
        """
        Build list of cross-validated (chained) high-confidence findings.

        Args:
            cross_referenced: Cross-referenced findings

        Returns:
            List of chained findings
        """
        chained = []
        for cr in cross_referenced:
            if len(cr.agent_sources) > 1 and cr.confidence_boost > 0:
                chain_info = {
                    "finding_id": cr.finding_id,
                    "title": cr.vulnerability.title,
                    "severity": cr.vulnerability.severity,
                    "category": cr.vulnerability.category,
                    "file": f"{cr.vulnerability.file_path}:{cr.vulnerability.line_number}",
                    "confidence_boost": cr.confidence_boost,
                    "agent_chain": cr.agent_sources,
                    "chain_description": " -> ".join(cr.agent_sources),
                    "evidence_count": len(cr.evidence),
                }
                chained.append(chain_info)

        # Sort by confidence boost descending
        chained.sort(key=lambda x: -x["confidence_boost"])
        return chained

    def build_remediation_plan(
        self, vulnerabilities: List[Vulnerability]
    ) -> Dict[str, Any]:
        """
        Build prioritized remediation plan with ETA estimates.

        Args:
            vulnerabilities: Vulnerabilities

        Returns:
            Remediation plan dict
        """
        # Sort by severity
        sorted_vulns = sorted(
            vulnerabilities,
            key=lambda v: (
                {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
                    v.severity.upper(), 5
                ),
            ),
        )

        items: List[RemediationItem] = []
        for i, v in enumerate(sorted_vulns):
            eta = REMEDIATION_ETA.get(v.severity.upper(), 72)

            # Determine effort level
            if v.fix_suggestion:
                effort = "low"
            elif v.category in ["Hardcoded Secret", "Missing Headers"]:
                effort = "low"
            elif v.category in ["SQL Injection", "XSS"]:
                effort = "medium"
            else:
                effort = "high"

            items.append(
                RemediationItem(
                    vuln_id=v.id,
                    title=v.title,
                    severity=v.severity,
                    category=v.category,
                    recommendation=v.fix_suggestion or f"Review and fix {v.category.lower()} vulnerability",
                    eta_hours=eta,
                    priority=i + 1,
                    effort=effort,
                )
            )

        # Group by severity
        by_severity: Dict[str, List[RemediationItem]] = defaultdict(list)
        for item in items:
            by_severity[item.severity].append(item)

        total_eta = sum(item.eta_hours for item in items)

        return {
            "total_remediation_hours": total_eta,
            "total_remediation_days": round(total_eta / 24, 1),
            "item_count": len(items),
            "by_severity": {
                sev: [item.to_dict() for item in group]
                for sev, group in sorted(
                    by_severity.items(),
                    key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(
                        x[0], 5
                    ),
                )
            },
            "all_items": [item.to_dict() for item in items],
        }

    def build_compliance_mapping(
        self, vulnerabilities: List[Vulnerability]
    ) -> List[ComplianceStatus]:
        """
        Build compliance mapping for all frameworks.

        Args:
            vulnerabilities: Vulnerabilities

        Returns:
            List of compliance statuses
        """
        categories = set(v.category for v in vulnerabilities)
        results = []

        for framework, controls in COMPLIANCE_MAPPINGS.items():
            status = ComplianceStatus(framework=framework, total_controls=len(controls))
            control_statuses = {}

            for control_id, control_categories in controls.items():
                # Check if any vulnerability category matches
                matches = categories & set(control_categories)
                if matches:
                    control_statuses[control_id] = "fail"
                    status.failing_controls += 1
                else:
                    control_statuses[control_id] = "pass"
                    status.passing_controls += 1

            status.control_statuses = control_statuses

            # Overall status
            if status.failing_controls > 0:
                status.overall_status = "non_compliant"
            else:
                status.overall_status = "compliant"

            results.append(status)

        return results

    # ========================================================================
    # C. Export Formats
    # ========================================================================

    def export_json(
        self,
        scan_result: ScanResult,
        triaged_findings: Optional[List[Any]] = None,
        cross_referenced: Optional[List[CrossReferencedFinding]] = None,
        chain_data: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """
        Export report as JSON.

        Args:
            scan_result: Scan result
            triaged_findings: Optional triaged findings
            cross_referenced: Optional cross-referenced findings
            chain_data: Optional chain data

        Returns:
            JSON string
        """
        report = {
            "meta": {
                "version": "2.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "generated_by": "CodeShield AI Report Assembler",
                "company": REPORT_COMPANY_NAME,
            },
            "executive_summary": self.build_executive_summary(
                scan_result, triaged_findings
            ),
            "findings_by_severity": self.build_findings_by_severity(
                scan_result.vulnerabilities
            ),
            "findings_by_category": self.build_findings_by_category(
                scan_result.vulnerabilities
            ),
            "findings_by_agent": {
                k: v.to_dict()
                for k, v in self.build_findings_by_agent(
                    scan_result.vulnerabilities
                ).items()
            },
            "cross_referenced_findings": [
                cr.to_dict() for cr in (cross_referenced or [])
            ],
            "chained_findings": self.build_chained_findings(
                cross_referenced or []
            ),
            "remediation_plan": self.build_remediation_plan(
                scan_result.vulnerabilities
            ),
            "compliance_mapping": [
                c.to_dict() for c in self.build_compliance_mapping(
                    scan_result.vulnerabilities
                )
            ],
            "tool_versions": {
                tool: "latest" for tool in scan_result.tools_used
            },
            "scan_config": {
                "languages": scan_result.languages,
                "tools_used": scan_result.tools_used,
            },
        }

        return json.dumps(report, indent=2, default=str)

    def export_executive_brief(
        self,
        scan_result: ScanResult,
    ) -> str:
        """
        Generate a 1-page executive brief as plain text.

        Args:
            scan_result: Scan result

        Returns:
            Executive brief text
        """
        summary = self.build_executive_summary(scan_result)
        compliance = self.build_compliance_mapping(scan_result.vulnerabilities)

        lines = [
            "=" * 72,
            f"  {REPORT_COMPANY_NAME} - SECURITY SCAN EXECUTIVE BRIEF",
            "=" * 72,
            "",
            f"Scan:      {summary['scan_name']} ({summary['scan_id']})",
            f"Date:      {summary['scan_date']}",
            f"Risk Score: {summary['risk_score']}/100 [{summary['risk_level']}]",
            "",
            "-" * 72,
            "  FINDINGS SUMMARY",
            "-" * 72,
            f"  CRITICAL:  {summary['by_severity']['critical']:>4}",
            f"  HIGH:      {summary['by_severity']['high']:>4}",
            f"  MEDIUM:    {summary['by_severity']['medium']:>4}",
            f"  LOW:       {summary['by_severity']['low']:>4}",
            f"  INFO:      {summary['by_severity']['info']:>4}",
            f"  TOTAL:     {summary['total_vulnerabilities']:>4}",
            "",
            "-" * 72,
            "  TOP PRIORITY FINDINGS",
            "-" * 72,
        ]

        for i, finding in enumerate(summary["top_findings"][:5], 1):
            lines.append(
                f"  {i}. [{finding['severity']}] {finding['title']}"
            )
            lines.append(f"     File: {finding['file']}")

        lines.extend([
            "",
            "-" * 72,
            "  COMPLIANCE STATUS",
            "-" * 72,
        ])

        for c in compliance:
            status_icon = "PASS" if c.overall_status == "compliant" else "FAIL"
            lines.append(
                f"  {c.framework:<15} {status_icon} ({c.passing_controls}/{c.total_controls} controls)"
            )

        lines.extend([
            "",
            "-" * 72,
            "  RECOMMENDED ACTIONS",
            "-" * 72,
        ])

        priority = summary.get("remediation_priority", [])
        for i, action in enumerate(priority[:3], 1):
            lines.append(f"  {i}. {action}")

        lines.extend([
            "",
            "=" * 72,
            f"Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
            "For full details, access the complete report.",
            "=" * 72,
        ])

        return "\n".join(lines)

    def export_html(
        self,
        scan_result: ScanResult,
        triaged_findings: Optional[List[Any]] = None,
        cross_referenced: Optional[List[CrossReferencedFinding]] = None,
        chain_data: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """
        Export report as interactive HTML.

        Args:
            scan_result: Scan result
            triaged_findings: Optional triaged findings
            cross_referenced: Optional cross-referenced findings
            chain_data: Optional chain data

        Returns:
            HTML string
        """
        summary = self.build_executive_summary(scan_result, triaged_findings)
        by_severity = self.build_findings_by_severity(scan_result.vulnerabilities)
        by_category = self.build_findings_by_category(scan_result.vulnerabilities)
        by_agent = self.build_findings_by_agent(scan_result.vulnerabilities)
        chained = self.build_chained_findings(cross_referenced or [])
        remediation = self.build_remediation_plan(scan_result.vulnerabilities)
        compliance = self.build_compliance_mapping(scan_result.vulnerabilities)

        # Severity color mapping
        severity_colors = {
            "CRITICAL": "#DC2626",
            "HIGH": "#EA580C",
            "MEDIUM": "#D97706",
            "LOW": "#65A30D",
            "INFO": "#2563EB",
        }

        html_parts = [
            "<!DOCTYPE html>",
            '<html lang="en">',
            "<head>",
            '    <meta charset="UTF-8">',
            '    <meta name="viewport" content="width=device-width, initial-scale=1.0">',
            f"    <title>Security Report - {scan_result.name}</title>",
            "    <style>",
            self._html_styles(),
            "    </style>",
            "</head>",
            "<body>",
            '    <div class="container">',
            self._html_header(summary),
            self._html_executive_summary(summary),
            self._html_findings_by_severity(by_severity, severity_colors),
            self._html_findings_by_category(by_category, severity_colors),
            self._html_findings_by_agent(by_agent),
            self._html_chained_findings(chained),
            self._html_remediation_plan(remediation),
            self._html_compliance(compliance),
            self._html_appendix(scan_result),
            "    </div>",
            self._html_scripts(),
            "</body>",
            "</html>",
        ]

        return "\n".join(html_parts)

    # ========================================================================
    # HTML Component Generators
    # ========================================================================

    @staticmethod
    def _html_styles() -> str:
        """Generate CSS styles for HTML report."""
        return """
        :root { --bg: #0f172a; --card: #1e293b; --text: #e2e8f0; --muted: #94a3b8; --border: #334155; }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: var(--bg); color: var(--text); line-height: 1.6; }
        .container { max-width: 1200px; margin: 0 auto; padding: 2rem; }
        .header { text-align: center; padding: 2rem 0; border-bottom: 2px solid var(--border); margin-bottom: 2rem; }
        .header h1 { font-size: 2rem; margin-bottom: 0.5rem; }
        .header .subtitle { color: var(--muted); }
        .card { background: var(--card); border-radius: 12px; padding: 1.5rem; margin-bottom: 1.5rem; border: 1px solid var(--border); }
        .card h2 { margin-bottom: 1rem; font-size: 1.4rem; }
        .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; }
        .stat-box { text-align: center; padding: 1rem; border-radius: 8px; }
        .stat-box .number { font-size: 2rem; font-weight: bold; }
        .stat-box .label { color: var(--muted); font-size: 0.85rem; }
        .severity-badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 0.75rem; font-weight: bold; text-transform: uppercase; }
        .finding-item { padding: 1rem; border-bottom: 1px solid var(--border); }
        .finding-item:last-child { border-bottom: none; }
        .finding-title { font-weight: 600; margin-bottom: 0.25rem; }
        .finding-meta { color: var(--muted); font-size: 0.85rem; }
        .code-snippet { background: #0d1117; padding: 1rem; border-radius: 6px; overflow-x: auto; font-family: 'Courier New', monospace; font-size: 0.85rem; margin-top: 0.5rem; }
        .tabs { display: flex; gap: 0.5rem; margin-bottom: 1rem; flex-wrap: wrap; }
        .tab { padding: 0.5rem 1rem; border-radius: 6px; cursor: pointer; background: var(--bg); border: 1px solid var(--border); }
        .tab.active { background: #2563eb; border-color: #2563eb; }
        .tab-content { display: none; }
        .tab-content.active { display: block; }
        .compliance-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; }
        .compliance-item { padding: 1rem; border-radius: 8px; }
        .compliance-pass { background: rgba(101, 163, 13, 0.2); border: 1px solid rgba(101, 163, 13, 0.4); }
        .compliance-fail { background: rgba(220, 38, 38, 0.2); border: 1px solid rgba(220, 38, 38, 0.4); }
        .chain-item { padding: 0.75rem; border-left: 3px solid #2563eb; margin-bottom: 0.5rem; background: rgba(37, 99, 235, 0.1); }
        .risk-score { font-size: 3rem; font-weight: bold; text-align: center; }
        .risk-critical { color: #DC2626; }
        .risk-high { color: #EA580C; }
        .risk-medium { color: #D97706; }
        .risk-low { color: #65A30D; }
        @media print { body { background: white; color: black; } .card { break-inside: avoid; } }
        """

    @staticmethod
    def _html_header(summary: Dict[str, Any]) -> str:
        """Generate HTML header."""
        return f"""
        <div class="header">
            <h1>Security Scan Report</h1>
            <p class="subtitle">{summary['scan_name']} - {summary.get('scan_date', 'N/A')}</p>
        </div>
        """

    @staticmethod
    def _html_executive_summary(summary: Dict[str, Any]) -> str:
        """Generate executive summary HTML."""
        risk_class = f"risk-{summary['risk_level'].lower()}"
        sev = summary.get("by_severity", {})

        return f"""
        <div class="card">
            <h2>Executive Summary</h2>
            <div class="risk-score {risk_class}">{summary['risk_score']}/100</div>
            <div class="stats-grid">
                <div class="stat-box" style="background: rgba(220,38,38,0.2)">
                    <div class="number" style="color: #DC2626">{sev.get('critical', 0)}</div>
                    <div class="label">CRITICAL</div>
                </div>
                <div class="stat-box" style="background: rgba(234,88,12,0.2)">
                    <div class="number" style="color: #EA580C">{sev.get('high', 0)}</div>
                    <div class="label">HIGH</div>
                </div>
                <div class="stat-box" style="background: rgba(217,119,6,0.2)">
                    <div class="number" style="color: #D97706">{sev.get('medium', 0)}</div>
                    <div class="label">MEDIUM</div>
                </div>
                <div class="stat-box" style="background: rgba(101,163,13,0.2)">
                    <div class="number" style="color: #65A30D">{sev.get('low', 0)}</div>
                    <div class="label">LOW</div>
                </div>
                <div class="stat-box" style="background: rgba(37,99,235,0.2)">
                    <div class="number" style="color: #2563EB">{sev.get('info', 0)}</div>
                    <div class="label">INFO</div>
                </div>
            </div>
        </div>
        """

    @staticmethod
    def _html_findings_by_severity(
        by_severity: Dict[str, List[Dict[str, Any]]], colors: Dict[str, str]
    ) -> str:
        """Generate findings by severity HTML."""
        html = ['<div class="card">', '<h2>Findings by Severity</h2>']

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            findings = by_severity.get(severity, [])
            if not findings:
                continue

            color = colors.get(severity, "#666")
            html.append(
                f'<div style="margin-bottom: 1rem;">'
                f'<h3><span class="severity-badge" style="background: {color}20; color: {color}; border: 1px solid {color}">'
                f'{severity}</span> ({len(findings)})</h3>'
            )

            for f in findings[:10]:  # Limit to 10 per severity
                html.append(
                    f'<div class="finding-item">'
                    f'<div class="finding-title">{f["title"]}</div>'
                    f'<div class="finding-meta">{f["category"]} | {f["file_path"]}:{f["line_number"]} | {f["tool_source"]}</div>'
                    f'</div>'
                )

            if len(findings) > 10:
                html.append(
                    f'<div style="text-align: center; padding: 0.5rem; color: #94a3b8;">'
                    f'... and {len(findings) - 10} more ...</div>'
                )

            html.append("</div>")

        html.append("</div>")
        return "\n".join(html)

    @staticmethod
    def _html_findings_by_category(
        by_category: Dict[str, List[Dict[str, Any]]], colors: Dict[str, str]
    ) -> str:
        """Generate findings by category HTML."""
        html = ['<div class="card">', '<h2>Findings by Category</h2>', '<div class="tabs">']

        for i, cat in enumerate(sorted(by_category.keys())):
            active = " active" if i == 0 else ""
            html.append(f'<div class="tab{active}" onclick="showTab(this, \"cat-{i}\")">{cat} ({len(by_category[cat])})</div>')

        html.append("</div>")

        for i, (cat, findings) in enumerate(sorted(by_category.items())):
            active = " active" if i == 0 else ""
            html.append(f'<div class="tab-content{active}" id="cat-{i}">')
            for f in findings[:5]:
                sev_color = colors.get(f["severity"].upper(), "#666")
                html.append(
                    f'<div class="finding-item">'
                    f'<span class="severity-badge" style="background: {sev_color}20; color: {sev_color}; border: 1px solid {sev_color}">'
                    f'{f["severity"]}</span> '
                    f'<strong>{f["title"]}</strong><br>'
                    f'<span class="finding-meta">{f["file_path"]}:{f["line_number"]}</span>'
                    f'</div>'
                )
            html.append("</div>")

        html.append("</div>")
        return "\n".join(html)

    @staticmethod
    def _html_findings_by_agent(
        by_agent: Dict[str, Any]
    ) -> str:
        """Generate findings by agent HTML."""
        html = ['<div class="card">', '<h2>Findings by Agent</h2>']

        for agent_name, summary in sorted(by_agent.items()):
            html.append(
                f'<div class="finding-item">'
                f'<strong>{agent_name}</strong>: {summary.total_findings} findings '
                f'(CRIT:{summary.by_severity.get("CRITICAL", 0)} '
                f'HIGH:{summary.by_severity.get("HIGH", 0)} '
                f'MED:{summary.by_severity.get("MEDIUM", 0)}) '
                f'- Avg Confidence: {round(summary.avg_confidence * 100, 0):.0f}%'
                f'</div>'
            )

        html.append("</div>")
        return "\n".join(html)

    @staticmethod
    def _html_chained_findings(chained: List[Dict[str, Any]]) -> str:
        """Generate chained findings HTML."""
        if not chained:
            return ""

        html = [
            '<div class="card">',
            '<h2>Cross-Validated Findings</h2>',
            f'<p style="color: #94a3b8; margin-bottom: 1rem;">{len(chained)} findings confirmed by multiple agents</p>',
        ]

        for c in chained[:10]:
            html.append(
                f'<div class="chain-item">'
                f'<strong>[{c["severity"]}] {c["title"]}</strong><br>'
                f'<span class="finding-meta">Chain: {c["chain_description"]} | '
                f'Confidence boost: +{c["confidence_boost"]:.0f}% | '
                f'Evidence: {c["evidence_count"]} sources</span>'
                f'</div>'
            )

        html.append("</div>")
        return "\n".join(html)

    @staticmethod
    def _html_remediation_plan(remediation: Dict[str, Any]) -> str:
        """Generate remediation plan HTML."""
        html = [
            '<div class="card">',
            '<h2>Remediation Plan</h2>',
            f'<p>Estimated total effort: <strong>{remediation["total_remediation_days"]} days</strong> ({remediation["total_remediation_hours"]} hours)</p>',
        ]

        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            items = remediation.get("by_severity", {}).get(severity, [])
            if not items:
                continue

            color = {"CRITICAL": "#DC2626", "HIGH": "#EA580C", "MEDIUM": "#D97706", "LOW": "#65A30D"}.get(severity, "#666")
            html.append(f'<h3 style="color: {color}; margin-top: 1rem;">{severity} ({len(items)} items)</h3>')

            for item in items[:3]:
                html.append(
                    f'<div class="finding-item">'
                    f'<div class="finding-title">{item["title"]}</div>'
                    f'<div class="finding-meta">ETA: {item["eta_hours"]}h | Effort: {item["effort"]} | {item["category"]}</div>'
                    f'<div style="margin-top: 0.5rem; color: #94a3b8;">{item["recommendation"][:150]}...</div>'
                    f'</div>'
                )

        html.append("</div>")
        return "\n".join(html)

    @staticmethod
    def _html_compliance(compliance: List[Any]) -> str:
        """Generate compliance section HTML."""
        html = [
            '<div class="card">',
            '<h2>Compliance Mapping</h2>',
            '<div class="compliance-grid">',
        ]

        for c in compliance:
            css_class = "compliance-pass" if c.overall_status == "compliant" else "compliance-fail"
            status_text = "PASS" if c.overall_status == "compliant" else "FAIL"
            html.append(
                f'<div class="compliance-item {css_class}">'
                f'<strong>{c.framework}</strong><br>'
                f'<span style="font-size: 1.5rem;">{status_text}</span><br>'
                f'<span style="font-size: 0.85rem; color: #94a3b8;">'
                f'{c.passing_controls}/{c.total_controls} controls passing</span>'
                f'</div>'
            )

        html.extend(["</div>", "</div>"])
        return "\n".join(html)

    @staticmethod
    def _html_appendix(scan_result: ScanResult) -> str:
        """Generate appendix HTML."""
        return f"""
        <div class="card">
            <h2>Appendix</h2>
            <h3>Tool Versions</h3>
            <ul>
                {''.join(f'<li>{tool}: latest</li>' for tool in scan_result.tools_used)}
            </ul>
            <h3>Scan Configuration</h3>
            <ul>
                <li>Languages: {', '.join(scan_result.languages)}</li>
                <li>Files Scanned: {scan_result.total_files}</li>
                <li>Lines Scanned: {scan_result.total_lines}</li>
                <li>Duration: {scan_result.scan_duration}s</li>
            </ul>
        </div>
        """

    @staticmethod
    def _html_scripts() -> str:
        """Generate JavaScript for interactive features."""
        return """
        <script>
        function showTab(tabEl, contentId) {
            document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
            document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));
            tabEl.classList.add('active');
            document.getElementById(contentId).classList.add('active');
        }
        </script>
        """

    # ========================================================================
    # Helper Methods
    # ========================================================================

    def _compute_compliance_summary(
        self, vulnerabilities: List[Vulnerability]
    ) -> List[ComplianceStatus]:
        """Compute compliance summary (alias for build_compliance_mapping)."""
        return self.build_compliance_mapping(vulnerabilities)

    @staticmethod
    def _get_remediation_priority(
        vulnerabilities: List[Vulnerability],
    ) -> List[str]:
        """Get top remediation priority actions."""
        actions = []
        severities = ["CRITICAL", "HIGH"]
        for sev in severities:
            count = sum(1 for v in vulnerabilities if v.severity.upper() == sev)
            if count > 0:
                actions.append(f"Address all {sev} findings ({count} items)")
        return actions

    # ========================================================================
    # Main Pipeline
    # ========================================================================

    async def assemble_report(
        self,
        scan_result: ScanResult,
        triaged_findings: Optional[List[Any]] = None,
        chain_data: Optional[List[Dict[str, Any]]] = None,
    ) -> Dict[str, Any]:
        """
        Assemble the complete report.

        Args:
            scan_result: Scan result
            triaged_findings: Optional triaged findings
            chain_data: Optional chain data

        Returns:
            Complete report dict
        """
        logger.info("Assembling report for scan %s", scan_result.scan_id)
        start_time = datetime.now(timezone.utc)

        # Build cross-referenced findings
        cross_referenced = self.build_cross_referenced_findings(
            scan_result.vulnerabilities, chain_data
        )

        # Build all sections
        report = {
            "meta": {
                "version": "2.0",
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "generated_by": "CodeShield AI Report Assembler",
            },
            "executive_summary": self.build_executive_summary(
                scan_result, triaged_findings
            ),
            "findings_by_severity": self.build_findings_by_severity(
                scan_result.vulnerabilities
            ),
            "findings_by_category": self.build_findings_by_category(
                scan_result.vulnerabilities
            ),
            "findings_by_agent": {
                k: v.to_dict()
                for k, v in self.build_findings_by_agent(
                    scan_result.vulnerabilities
                ).items()
            },
            "cross_referenced_findings": [
                cr.to_dict() for cr in cross_referenced
            ],
            "chained_findings": self.build_chained_findings(cross_referenced),
            "remediation_plan": self.build_remediation_plan(
                scan_result.vulnerabilities
            ),
            "compliance_mapping": [
                c.to_dict()
                for c in self.build_compliance_mapping(
                    scan_result.vulnerabilities
                )
            ],
        }

        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        logger.info("Report assembled in %.2fs", elapsed)

        return report

    async def export(
        self,
        scan_result: ScanResult,
        format: ReportFormat,
        triaged_findings: Optional[List[Any]] = None,
        chain_data: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """
        Export report in the specified format.

        Args:
            scan_result: Scan result
            format: Export format
            triaged_findings: Optional triaged findings
            chain_data: Optional chain data

        Returns:
            Report content as string
        """
        cross_referenced = self.build_cross_referenced_findings(
            scan_result.vulnerabilities, chain_data
        )

        if format == ReportFormat.JSON:
            return self.export_json(scan_result, triaged_findings, cross_referenced, chain_data)
        elif format == ReportFormat.HTML:
            return self.export_html(scan_result, triaged_findings, cross_referenced, chain_data)
        elif format == ReportFormat.EXECUTIVE_BRIEF:
            return self.export_executive_brief(scan_result)
        elif format == ReportFormat.SARIF:
            # Delegate to existing SARIF exporter
            from exporters.sarif_exporter import SARIFExporter
            exporter = SARIFExporter()
            return exporter.export(scan_result)
        elif format == ReportFormat.PDF:
            # PDF is handled separately via the PDF generator
            raise ValueError("PDF export should use /api/scan/{scan_id}/report/pdf endpoint")
        else:
            raise ValueError(f"Unsupported format: {format}")

    async def get_stats(self) -> Dict[str, Any]:
        """Get report assembler statistics."""
        return {
            "supported_formats": [f.value for f in ReportFormat],
            "compliance_frameworks": list(COMPLIANCE_MAPPINGS.keys()),
            "company_name": REPORT_COMPANY_NAME,
        }
