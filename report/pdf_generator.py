"""
PDF report generator for CodeShield AI.

Generates professional PDF reports with:
- Cover page with branding
- Executive summary with risk score and stats
- Severity distribution charts
- Vulnerability details with code snippets
- OWASP Top 10 compliance matrix
- Fix recommendations
- Appendix with tool versions
"""

import io
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import matplotlib
import matplotlib.pyplot as plt

matplotlib.use("Agg")

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import inch
from reportlab.platypus import (
    HRFlowable,
    Image,
    PageBreak,
    Paragraph,
    SimpleDocTemplate,
    Spacer,
    Table,
    TableStyle,
)

from models.vulnerability import ScanResult, Vulnerability
from utils.constants import OWASP_TOP10
from utils.logger import get_logger

logger = get_logger(__name__)

# CodeShield AI Branding Colors
BRAND_PRIMARY = colors.HexColor("#1E3A5F")
BRAND_SECONDARY = colors.HexColor("#2563EB")
BRAND_ACCENT = colors.HexColor("#10B981")
BRAND_DANGER = colors.HexColor("#DC2626")
BRAND_WARNING = colors.HexColor("#D97706")

# Severity colors
SEVERITY_COLORS = {
    "CRITICAL": colors.HexColor("#DC2626"),
    "HIGH": colors.HexColor("#EA580C"),
    "MEDIUM": colors.HexColor("#D97706"),
    "LOW": colors.HexColor("#65A30D"),
    "INFO": colors.HexColor("#2563EB"),
}


def _color_hex(c: colors.Color) -> str:
    """Convert a reportlab color to #RRGGBB hex string."""
    return "#{:02x}{:02x}{:02x}".format(
        int(c.red * 255), int(c.green * 255), int(c.blue * 255)
    )


class PDFGenerator:
    """
    Professional PDF report generator for scan results.

    Creates comprehensive security reports with charts, vulnerability details,
    and actionable recommendations.
    """

    def __init__(self) -> None:
        """Initialize the PDF generator."""
        self.styles = getSampleStyleSheet()
        self._setup_styles()

    def _setup_styles(self) -> None:
        """Set up custom paragraph styles."""
        self.styles.add(
            ParagraphStyle(
                "BrandTitle",
                parent=self.styles["Title"],
                fontSize=32,
                textColor=BRAND_PRIMARY,
                spaceAfter=20,
                alignment=TA_CENTER,
                fontName="Helvetica-Bold",
            )
        )

        self.styles.add(
            ParagraphStyle(
                "BrandSubtitle",
                parent=self.styles["Normal"],
                fontSize=14,
                textColor=colors.HexColor("#64748B"),
                spaceAfter=30,
                alignment=TA_CENTER,
            )
        )

        self.styles.add(
            ParagraphStyle(
                "SectionHeader",
                parent=self.styles["Heading2"],
                fontSize=16,
                textColor=BRAND_PRIMARY,
                spaceAfter=12,
                spaceBefore=16,
                fontName="Helvetica-Bold",
                borderWidth=0,
                borderColor=BRAND_SECONDARY,
                borderPadding=5,
            )
        )

        self.styles.add(
            ParagraphStyle(
                "VulnTitle",
                parent=self.styles["Normal"],
                fontSize=11,
                textColor=BRAND_PRIMARY,
                fontName="Helvetica-Bold",
                spaceAfter=4,
            )
        )

        self.styles.add(
            ParagraphStyle(
                "CodeStyle",
                parent=self.styles["Code"],
                fontSize=8,
                fontName="Courier",
                textColor=colors.HexColor("#374151"),
                backColor=colors.HexColor("#F3F4F6"),
                leftIndent=10,
                rightIndent=10,
                spaceAfter=8,
                borderWidth=1,
                borderColor=colors.HexColor("#E5E7EB"),
                borderPadding=8,
            )
        )

        self.styles.add(
            ParagraphStyle(
                "RiskScore",
                parent=self.styles["Normal"],
                fontSize=48,
                textColor=BRAND_DANGER,
                alignment=TA_CENTER,
                fontName="Helvetica-Bold",
            )
        )

        self.styles.add(
            ParagraphStyle(
                "RiskLabel",
                parent=self.styles["Normal"],
                fontSize=12,
                textColor=colors.HexColor("#64748B"),
                alignment=TA_CENTER,
            )
        )

    def generate(self, scan_result: ScanResult) -> bytes:
        """
        Generate a complete PDF report for a scan result.

        Args:
            scan_result: The scan result to generate a report for

        Returns:
            PDF file content as bytes
        """
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(
            buffer,
            pagesize=letter,
            rightMargin=50,
            leftMargin=50,
            topMargin=50,
            bottomMargin=50,
        )

        story: List[Any] = []

        # Build report sections
        story.extend(self._build_cover_page(scan_result))
        story.append(PageBreak())
        story.extend(self._build_executive_summary(scan_result))
        story.append(PageBreak())
        story.extend(self._build_severity_chart(scan_result))
        story.extend(self._build_category_chart(scan_result))
        story.append(PageBreak())
        story.extend(self._build_owasp_matrix(scan_result))
        story.append(PageBreak())
        story.extend(self._build_vulnerability_details(scan_result))
        story.append(PageBreak())
        story.extend(self._build_appendix(scan_result))

        doc.build(story)
        pdf_content = buffer.getvalue()
        buffer.close()

        logger.info("Generated PDF report for scan %s", scan_result.scan_id)
        return pdf_content

    def _build_cover_page(self, scan_result: ScanResult) -> List[Any]:
        """Build the report cover page."""
        elements: List[Any] = []

        # Top spacing
        elements.append(Spacer(1, 2 * inch))

        # Logo placeholder / Title
        elements.append(Paragraph("CodeShield AI", self.styles["BrandTitle"]))
        elements.append(Paragraph("Security Assessment Report", self.styles["BrandSubtitle"]))

        # Decorative line
        elements.append(Spacer(1, 0.3 * inch))
        elements.append(
            HRFlowable(
                width="60%",
                thickness=2,
                color=BRAND_SECONDARY,
                spaceAfter=20,
                hAlign="CENTER",
            )
        )

        # Scan info
        elements.append(Spacer(1, 0.5 * inch))

        info_data = [
            ["Scan Name:", scan_result.name],
            ["Scan ID:", scan_result.scan_id],
            ["Source Type:", scan_result.source_type.upper()],
            ["Date:", scan_result.start_time.strftime("%Y-%m-%d %H:%M UTC") if scan_result.start_time else "N/A"],
            ["Duration:", f"{scan_result.scan_duration or 0} seconds"],
            ["Total Files:", str(scan_result.total_files)],
            ["Languages:", ", ".join(scan_result.languages) if scan_result.languages else "N/A"],
        ]

        info_table = Table(info_data, colWidths=[2 * inch, 3.5 * inch])
        info_table.setStyle(
            TableStyle([
                ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
                ("FONTNAME", (1, 0), (1, -1), "Helvetica"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("TEXTCOLOR", (0, 0), (0, -1), BRAND_PRIMARY),
                ("TEXTCOLOR", (1, 0), (1, -1), colors.HexColor("#374151")),
                ("ALIGN", (0, 0), (0, -1), "RIGHT"),
                ("ALIGN", (1, 0), (1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
            ])
        )
        elements.append(info_table)

        # Footer
        elements.append(Spacer(1, 1.5 * inch))
        elements.append(
            Paragraph(
                f"Generated on {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}",
                self.styles["BrandSubtitle"],
            )
        )
        elements.append(
            Paragraph(
                "Confidential - For authorized use only",
                self.styles["BrandSubtitle"],
            )
        )

        return elements

    def _build_executive_summary(self, scan_result: ScanResult) -> List[Any]:
        """Build the executive summary section."""
        elements: List[Any] = []

        elements.append(Paragraph("Executive Summary", self.styles["SectionHeader"]))
        elements.append(Spacer(1, 12))

        # Risk score box
        risk_score = scan_result.risk_score
        risk_color = self._get_risk_color(risk_score)
        risk_hex = _color_hex(risk_color)

        elements.append(Paragraph("Overall Risk Score", self.styles["RiskLabel"]))
        elements.append(
            Paragraph(
                f'<font color="{risk_hex}">{risk_score}/100</font>',
                self.styles["RiskScore"],
            )
        )

        # Risk level text
        risk_level = self._get_risk_level(risk_score)
        elements.append(
            Paragraph(
                f'<font color="{risk_hex}"><b>{risk_level}</b></font>',
                ParagraphStyle(
                    "RiskLevelText",
                    parent=self.styles["Normal"],
                    fontSize=14,
                    alignment=TA_CENTER,
                    spaceAfter=20,
                ),
            )
        )

        elements.append(Spacer(1, 12))

        # Summary text
        total_vulns = len(scan_result.vulnerabilities)
        summary_text = (
            f"This security assessment identified <b>{total_vulns}</b> potential security "
            f"issues across <b>{scan_result.total_files}</b> files. "
            f"The overall risk level is <b>{risk_level}</b> with a risk score of "
            f"<b>{risk_score}/100</b>."
        )
        elements.append(Paragraph(summary_text, self.styles["Normal"]))
        elements.append(Spacer(1, 12))

        # Severity breakdown table
        elements.append(Paragraph("Severity Breakdown", self.styles["Heading3"]))
        elements.append(Spacer(1, 8))

        stats = scan_result.stats
        severity_data = [
            ["Severity", "Count", "Status"],
        ]

        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            count = stats.get(sev.lower(), 0)
            status = "Action Required" if sev in ("CRITICAL", "HIGH") else "Review"
            if count == 0:
                status = "None"
            sev_color = SEVERITY_COLORS.get(sev, colors.black)
            severity_data.append([
                Paragraph(f'<font color="{_color_hex(sev_color)}"><b>{sev}</b></font>', self.styles["Normal"]),
                str(count),
                status,
            ])

        sev_table = Table(severity_data, colWidths=[1.5 * inch, 1 * inch, 1.5 * inch])
        sev_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), BRAND_PRIMARY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 10),
                ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
                ("TOPPADDING", (0, 0), (-1, -1), 10),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
            ])
        )
        elements.append(sev_table)

        # Key findings
        if total_vulns > 0:
            elements.append(Spacer(1, 16))
            elements.append(Paragraph("Key Findings", self.styles["Heading3"]))

            # Top 5 most severe findings
            sorted_vulns = sorted(
                scan_result.vulnerabilities,
                key=lambda v: ({"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}.get(v.severity, 5)),
            )[:5]

            for i, vuln in enumerate(sorted_vulns, 1):
                sev_color = SEVERITY_COLORS.get(vuln.severity, colors.black)
                finding_text = (
                    f"{i}. <font color='{_color_hex(sev_color)}'><b>[{vuln.severity}]</b></font> "
                    f"{vuln.title} in <i>{vuln.file_path}:{vuln.line_number}</i>"
                )
                elements.append(Paragraph(finding_text, self.styles["Normal"]))

        return elements

    def _build_severity_chart(self, scan_result: ScanResult) -> List[Any]:
        """Build severity distribution chart."""
        elements: List[Any] = []
        fig = None

        elements.append(Paragraph("Severity Distribution", self.styles["SectionHeader"]))

        try:
            # Create matplotlib chart
            fig, ax = plt.subplots(figsize=(6, 3.5))

            stats = scan_result.stats
            severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            counts = [stats.get(s.lower(), 0) for s in severities]
            colors_list = [str(SEVERITY_COLORS[s]) for s in severities]

            if sum(counts) > 0:
                bars = ax.bar(severities, counts, color=colors_list, edgecolor="white", linewidth=1.5)
                ax.set_ylabel("Count")
                ax.set_title("Vulnerabilities by Severity")

                # Add value labels on bars
                for bar, count in zip(bars, counts):
                    if count > 0:
                        ax.text(
                            bar.get_x() + bar.get_width() / 2,
                            bar.get_height() + 0.1,
                            str(count),
                            ha="center",
                            va="bottom",
                            fontweight="bold",
                        )

                ax.spines["top"].set_visible(False)
                ax.spines["right"].set_visible(False)
                plt.tight_layout()

                # Save to buffer
                chart_buffer = io.BytesIO()
                plt.savefig(chart_buffer, format="png", dpi=150, bbox_inches="tight")
                chart_buffer.seek(0)

                elements.append(Image(chart_buffer, width=5.5 * inch, height=3.2 * inch))
            else:
                elements.append(Paragraph("No vulnerabilities found.", self.styles["Normal"]))
        finally:
            if fig is not None:
                plt.close(fig)

        elements.append(Spacer(1, 16))
        return elements

    def _build_category_chart(self, scan_result: ScanResult) -> List[Any]:
        """Build vulnerability category distribution chart."""
        elements: List[Any] = []
        fig = None

        if not scan_result.vulnerabilities:
            return elements

        elements.append(Paragraph("Vulnerability Categories", self.styles["SectionHeader"]))

        try:
            # Count by category
            from collections import Counter

            category_counts = Counter(v.category for v in scan_result.vulnerabilities)
            top_categories = category_counts.most_common(10)

            if top_categories:
                categories = [c[0][:25] for c in top_categories]
                counts = [c[1] for c in top_categories]

                fig, ax = plt.subplots(figsize=(6, 3.5))
                ax.barh(categories, counts, color=BRAND_SECONDARY)
                ax.set_xlabel("Count")
                ax.set_title("Top Vulnerability Categories")
                ax.invert_yaxis()

                for i, count in enumerate(counts):
                    ax.text(count + 0.1, i, str(count), va="center", fontweight="bold")

                ax.spines["top"].set_visible(False)
                ax.spines["right"].set_visible(False)
                plt.tight_layout()

                chart_buffer = io.BytesIO()
                plt.savefig(chart_buffer, format="png", dpi=150, bbox_inches="tight")
                chart_buffer.seek(0)

                elements.append(Image(chart_buffer, width=5.5 * inch, height=3.2 * inch))
        finally:
            if fig is not None:
                plt.close(fig)

        elements.append(Spacer(1, 16))
        return elements

    def _build_owasp_matrix(self, scan_result: ScanResult) -> List[Any]:
        """Build OWASP Top 10 compliance matrix."""
        elements: List[Any] = []

        elements.append(Paragraph("OWASP Top 10 Compliance", self.styles["SectionHeader"]))
        elements.append(Spacer(1, 8))

        # Count vulnerabilities by OWASP category
        owasp_counts: Dict[str, int] = {}
        for vuln in scan_result.vulnerabilities:
            if vuln.owasp_category:
                owasp_counts[vuln.owasp_category] = owasp_counts.get(vuln.owasp_category, 0) + 1

        # Build matrix table
        matrix_data = [["ID", "Category", "Description", "Findings", "Status"]]

        for owasp_id, info in OWASP_TOP10.items():
            count = owasp_counts.get(owasp_id, 0)
            if count > 0:
                status = "At Risk"
                status_color = BRAND_DANGER
            else:
                status = "Compliant"
                status_color = BRAND_ACCENT

            matrix_data.append([
                owasp_id,
                info["name"],
                info["description"][:80] + "..." if len(info["description"]) > 80 else info["description"],
                str(count),
                Paragraph(
                    f'<font color="{_color_hex(status_color)}"><b>{status}</b></font>',
                    self.styles["Normal"],
                ),
            ])

        matrix_table = Table(
            matrix_data,
            colWidths=[0.5 * inch, 1.4 * inch, 3 * inch, 0.6 * inch, 0.8 * inch],
        )
        matrix_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), BRAND_PRIMARY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("FONTSIZE", (0, 0), (-1, -1), 8),
                ("ALIGN", (0, 0), (-1, -1), "LEFT"),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
                ("TOPPADDING", (0, 0), (-1, -1), 8),
                ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9FAFB")]),
            ])
        )
        elements.append(matrix_table)

        return elements

    def _build_vulnerability_details(self, scan_result: ScanResult) -> List[Any]:
        """Build detailed vulnerability listings."""
        elements: List[Any] = []

        elements.append(Paragraph("Vulnerability Details", self.styles["SectionHeader"]))
        elements.append(Spacer(1, 8))

        if not scan_result.vulnerabilities:
            elements.append(
                Paragraph(
                    "No vulnerabilities were detected in this scan.",
                    self.styles["Normal"],
                )
            )
            return elements

        # Group by severity
        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        grouped: Dict[str, List[Vulnerability]] = {s: [] for s in severity_order}
        for vuln in scan_result.vulnerabilities:
            grouped[vuln.severity] = grouped.get(vuln.severity, []) + [vuln]

        for severity in severity_order:
            vulns = grouped.get(severity, [])
            if not vulns:
                continue

            sev_color = SEVERITY_COLORS.get(severity, colors.black)
            elements.append(
                Paragraph(
                    f'<font color="{_color_hex(sev_color)}">{severity} ({len(vulns)})</font>',
                    self.styles["Heading3"],
                )
            )
            elements.append(Spacer(1, 6))

            # Show first 20 per severity to keep PDF manageable
            for vuln in vulns[:20]:
                elements.extend(self._build_vuln_detail(vuln))
                elements.append(Spacer(1, 4))
                elements.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#E5E7EB")))

            if len(vulns) > 20:
                elements.append(
                    Paragraph(
                        f"<i>... and {len(vulns) - 20} more {severity.lower()} severity issues</i>",
                        self.styles["Normal"],
                    )
                )

        return elements

    def _build_vuln_detail(self, vuln: Vulnerability) -> List[Any]:
        """Build detail section for a single vulnerability."""
        elements: List[Any] = []

        # Title and severity
        sev_color = SEVERITY_COLORS.get(vuln.severity, colors.black)
        title_text = (
            f'<font color="{_color_hex(sev_color)}">[{vuln.severity}]</font> '
            f"{vuln.title}"
        )
        elements.append(Paragraph(title_text, self.styles["VulnTitle"]))

        # Metadata
        meta_text = f"<b>File:</b> {vuln.file_path}:{vuln.line_number}"
        if vuln.cwe_id:
            meta_text += f" | <b>CWE:</b> {vuln.cwe_id}"
        if vuln.owasp_category:
            meta_text += f" | <b>OWASP:</b> {vuln.owasp_category}"
        meta_text += f" | <b>Tool:</b> {vuln.tool_source}"
        elements.append(Paragraph(meta_text, self.styles["Normal"]))

        # Description
        if vuln.description:
            elements.append(Paragraph(f"<b>Description:</b> {vuln.description}", self.styles["Normal"]))

        # Code snippet
        if vuln.code_snippet:
            # Escape HTML in code snippet
            escaped_code = (
                vuln.code_snippet.replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace('"', "&quot;")
            )
            elements.append(Paragraph("<b>Code:</b>", self.styles["Normal"]))
            elements.append(Paragraph(escaped_code, self.styles["CodeStyle"]))

        # Fix suggestion
        if vuln.fix_suggestion:
            elements.append(
                Paragraph(
                    f'<font color="{_color_hex(BRAND_ACCENT)}"><b>Fix:</b></font> {vuln.fix_suggestion}',
                    self.styles["Normal"],
                )
            )

        return elements

    def _build_appendix(self, scan_result: ScanResult) -> List[Any]:
        """Build report appendix."""
        elements: List[Any] = []

        elements.append(Paragraph("Appendix", self.styles["SectionHeader"]))
        elements.append(Spacer(1, 12))

        # Tools used
        elements.append(Paragraph("Scanning Tools Used", self.styles["Heading3"]))
        tools_data = [["Tool", "Description"]]
        tool_descriptions = {
            "semgrep": "Multi-language SAST with security rules",
            "eslint": "JavaScript/TypeScript linting and security",
            "pylint": "Python code quality analysis",
            "bandit": "Python security vulnerability scanner",
            "pmd": "Java static code analysis",
            "gitleaks": "Secret detection in source code",
            "dependency-check": "OWASP dependency vulnerability scanner",
            "custom_ai": "Pattern-based security detection engine",
        }

        for tool in scan_result.tools_used:
            tools_data.append([tool, tool_descriptions.get(tool, "Security scanner")])

        tools_table = Table(tools_data, colWidths=[2 * inch, 4 * inch])
        tools_table.setStyle(
            TableStyle([
                ("BACKGROUND", (0, 0), (-1, 0), BRAND_PRIMARY),
                ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#E5E7EB")),
                ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
                ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
            ])
        )
        elements.append(tools_table)

        elements.append(Spacer(1, 16))

        # About
        elements.append(Paragraph("About CodeShield AI", self.styles["Heading3"]))
        about_text = (
            "CodeShield AI is an automated security scanning platform that integrates "
            "multiple open-source security tools to provide comprehensive code analysis. "
            "This report was generated automatically and should be reviewed by security "
            "professionals for context and prioritization."
        )
        elements.append(Paragraph(about_text, self.styles["Normal"]))

        return elements

    def _get_risk_color(self, score: int) -> colors.Color:
        """Get color based on risk score."""
        if score >= 75:
            return BRAND_DANGER
        elif score >= 50:
            return BRAND_WARNING
        elif score >= 25:
            return colors.HexColor("#D97706")
        else:
            return BRAND_ACCENT

    def _get_risk_level(self, score: int) -> str:
        """Get risk level text based on score."""
        if score >= 75:
            return "CRITICAL RISK"
        elif score >= 50:
            return "HIGH RISK"
        elif score >= 25:
            return "MEDIUM RISK"
        elif score > 0:
            return "LOW RISK"
        else:
            return "NO RISK DETECTED"
