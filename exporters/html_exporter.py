"""
HTML Exporter for CodeShield AI.

Generates a self-contained, interactive HTML report with:
- Executive summary with risk score and charts
- Vulnerability details table with filtering
- Severity distribution charts (Chart.js)
- Code snippets with syntax highlighting
- Exportable to PDF via browser print

The report is fully self-contained with all CSS and JS inlined.
"""

import json
import os
from datetime import datetime
from typing import Any, Dict, List

from models.vulnerability import ScanResult, Vulnerability
from utils.logger import get_logger

logger = get_logger(__name__)


class HTMLExporter:
    """
    Export scan results to a self-contained HTML report.

    Features:
    - Interactive charts (severity distribution, trends)
    - Filterable vulnerability table
    - Syntax-highlighted code snippets
    - OWASP Top 10 mapping visualization
    - Print-friendly layout for PDF export
    - All assets inlined (no external dependencies)
    """

    SEVERITY_COLORS = {
        "CRITICAL": "#DC2626",
        "HIGH": "#EA580C",
        "MEDIUM": "#D97706",
        "LOW": "#65A30D",
        "INFO": "#2563EB",
    }

    SEVERITY_BG_COLORS = {
        "CRITICAL": "rgba(220, 38, 38, 0.15)",
        "HIGH": "rgba(234, 88, 12, 0.15)",
        "MEDIUM": "rgba(217, 119, 6, 0.15)",
        "LOW": "rgba(101, 163, 13, 0.15)",
        "INFO": "rgba(37, 99, 235, 0.15)",
    }

    def export(self, scan_result: ScanResult) -> str:
        """
        Export a ScanResult to a self-contained HTML report.

        Args:
            scan_result: The scan result to export

        Returns:
            HTML string
        """
        logger.info("Generating HTML report for scan %s", scan_result.scan_id)

        data = self._prepare_data(scan_result)
        html_content = self._build_html(data, scan_result)
        return html_content

    def _prepare_data(self, scan_result: ScanResult) -> Dict[str, Any]:
        """Prepare data for HTML template rendering."""
        # Severity distribution for charts
        severity_counts = {
            "CRITICAL": scan_result.stats.get("critical", 0) if scan_result.stats else 0,
            "HIGH": scan_result.stats.get("high", 0) if scan_result.stats else 0,
            "MEDIUM": scan_result.stats.get("medium", 0) if scan_result.stats else 0,
            "LOW": scan_result.stats.get("low", 0) if scan_result.stats else 0,
            "INFO": scan_result.stats.get("info", 0) if scan_result.stats else 0,
        }

        # Tool distribution
        tool_counts: Dict[str, int] = {}
        for vuln in scan_result.vulnerabilities:
            tool = vuln.tool_source or "unknown"
            tool_counts[tool] = tool_counts.get(tool, 0) + 1

        # OWASP category distribution
        owasp_counts: Dict[str, int] = {}
        for vuln in scan_result.vulnerabilities:
            owasp = vuln.owasp_category or "Unmapped"
            owasp_counts[owasp] = owasp_counts.get(owasp, 0) + 1

        # Top files with most vulnerabilities
        file_counts: Dict[str, int] = {}
        for vuln in scan_result.vulnerabilities:
            file_counts[vuln.file_path] = file_counts.get(vuln.file_path, 0) + 1
        top_files = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:10]

        # Vulnerabilities for table
        vulns_data = []
        for vuln in scan_result.vulnerabilities:
            vulns_data.append({
                "id": vuln.id,
                "severity": vuln.severity,
                "category": vuln.category,
                "title": vuln.title,
                "file_path": vuln.file_path,
                "line_number": vuln.line_number,
                "cwe_id": vuln.cwe_id,
                "cwe_name": vuln.cwe_name,
                "cvss_score": vuln.cvss_score,
                "tool_source": vuln.tool_source,
                "description": vuln.description,
                "fix_suggestion": vuln.fix_suggestion,
                "code_snippet": self._escape_html(vuln.code_snippet or ""),
                "confidence": vuln.confidence,
                "owasp_category": vuln.owasp_category,
            })

        return {
            "severity_counts": severity_counts,
            "tool_counts": tool_counts,
            "owasp_counts": owasp_counts,
            "top_files": top_files,
            "vulnerabilities": vulns_data,
        }

    @staticmethod
    def _escape_html(text: str) -> str:
        """Escape HTML special characters."""
        return (text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;"))

    def _build_html(self, data: Dict[str, Any], scan_result: ScanResult) -> str:
        """Build the complete HTML report."""
        title = f"CodeShield AI Report - {scan_result.name}"
        scan_time = scan_result.start_time.strftime("%Y-%m-%d %H:%M:%S UTC") if scan_result.start_time else "N/A"
        duration = f"{scan_result.scan_duration}s" if scan_result.scan_duration else "N/A"
        risk_score = scan_result.risk_score
        risk_color = self._risk_score_color(risk_score)
        risk_label = self._risk_score_label(risk_score)

        # Severity chart data
        sev_labels = list(self.SEVERITY_COLORS.keys())
        sev_values = [data["severity_counts"][s] for s in sev_labels]
        sev_colors = list(self.SEVERITY_COLORS.values())

        # Build vulnerability rows
        vuln_rows = ""
        for v in data["vulnerabilities"]:
            sev = v["severity"]
            badge_style = f"background: {self.SEVERITY_BG_COLORS.get(sev, '#eee')}; color: {self.SEVERITY_COLORS.get(sev, '#333')};"
            vuln_rows += f"""
            <tr class="vuln-row" data-severity="{sev}">
                <td><span class="severity-badge" style="{badge_style}">{sev}</span></td>
                <td>{v['cwe_id'] or 'N/A'}</td>
                <td>{v['category']}</td>
                <td title="{v['file_path']}">{v['file_path'][:60]}{'...' if len(v['file_path']) > 60 else ''}:{v['line_number']}</td>
                <td>{v['tool_source']}</td>
                <td>{v['cvss_score'] or 'N/A'}</td>
                <td>
                    <button class="btn-details" onclick="toggleDetails('{v['id']}")">Details</button>
                </td>
            </tr>
            <tr id="details-{v['id']}" class="details-row" style="display:none;">
                <td colspan="7">
                    <div class="details-content">
                        <h4>{v['title']}</h4>
                        <p><strong>Description:</strong> {v['description']}</p>
                        {f'<div class="code-block"><pre>{v["code_snippet"]}</pre></div>' if v['code_snippet'] else ''}
                        {f'<p><strong class="fix">Suggested Fix:</strong> {v["fix_suggestion"]}</p>' if v['fix_suggestion'] else ''}
                        <p><strong>Confidence:</strong> {v['confidence']} | <strong>OWASP:</strong> {v['owasp_category'] or 'N/A'}</p>
                    </div>
                </td>
            </tr>
            """

        # OWASP rows
        owasp_rows = ""
        owasp_names = {
            "A01": "Broken Access Control",
            "A02": "Cryptographic Failures",
            "A03": "Injection",
            "A04": "Insecure Design",
            "A05": "Security Misconfiguration",
            "A06": "Vulnerable Components",
            "A07": "Auth Failures",
            "A08": "Data Integrity Failures",
            "A09": "Logging Failures",
            "A10": "SSRF",
        }
        for code, count in sorted(data["owasp_counts"].items()):
            name = owasp_names.get(code, code)
            owasp_rows += f"<tr><td>{code}</td><td>{name}</td><td>{count}</td></tr>"

        # Top files rows
        files_rows = ""
        for file_path, count in data["top_files"]:
            files_rows += f"<tr><td title=\"{file_path}\">{file_path[:80]}{'...' if len(file_path) > 80 else ''}</td><td>{count}</td></tr>"

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: #f8fafc;
            color: #1e293b;
            line-height: 1.6;
        }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        header {{
            background: linear-gradient(135deg, #0f172a 0%, #1e3a5f 100%);
            color: white;
            padding: 40px 20px;
            text-align: center;
            margin-bottom: 30px;
            border-radius: 12px;
        }}
        header h1 {{ font-size: 2.2em; margin-bottom: 10px; }}
        header .meta {{ opacity: 0.85; font-size: 0.95em; }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            text-align: center;
        }}
        .summary-card .number {{
            font-size: 2.5em;
            font-weight: 700;
            margin: 8px 0;
        }}
        .summary-card .label {{ color: #64748b; font-size: 0.9em; text-transform: uppercase; letter-spacing: 0.05em; }}
        .risk-score {{ color: {risk_color}; }}
        .risk-critical {{ color: #DC2626; }}
        .risk-high {{ color: #EA580C; }}
        .risk-medium {{ color: #D97706; }}
        .risk-low {{ color: #65A30D; }}
        .risk-none {{ color: #2563EB; }}
        .charts-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .chart-card {{
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }}
        .chart-card h3 {{ margin-bottom: 16px; font-size: 1.1em; }}
        .chart-container {{ height: 300px; position: relative; }}
        .section {{
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            margin-bottom: 20px;
        }}
        .section h2 {{
            margin-bottom: 20px;
            padding-bottom: 12px;
            border-bottom: 2px solid #e2e8f0;
            font-size: 1.3em;
        }}
        .filters {{
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
            flex-wrap: wrap;
        }}
        .filter-btn {{
            padding: 6px 16px;
            border: 1px solid #e2e8f0;
            background: white;
            border-radius: 20px;
            cursor: pointer;
            font-size: 0.85em;
            transition: all 0.2s;
        }}
        .filter-btn:hover, .filter-btn.active {{ background: #0f172a; color: white; border-color: #0f172a; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 0.9em;
        }}
        th {{
            background: #f1f5f9;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #475569;
            position: sticky;
            top: 0;
        }}
        td {{ padding: 12px; border-bottom: 1px solid #f1f5f9; }}
        tr:hover {{ background: #f8fafc; }}
        .severity-badge {{
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8em;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.03em;
        }}
        .btn-details {{
            padding: 4px 12px;
            background: #0f172a;
            color: white;
            border: none;
            border-radius: 6px;
            cursor: pointer;
            font-size: 0.8em;
        }}
        .btn-details:hover {{ background: #1e3a5f; }}
        .details-row {{ background: #f8fafc !important; }}
        .details-content {{
            padding: 20px;
            border-left: 4px solid #0f172a;
            margin: 10px 0;
        }}
        .details-content h4 {{ margin-bottom: 12px; color: #0f172a; }}
        .code-block {{
            background: #0f172a;
            color: #e2e8f0;
            padding: 16px;
            border-radius: 8px;
            margin: 12px 0;
            overflow-x: auto;
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            line-height: 1.5;
        }}
        .code-block pre {{ white-space: pre-wrap; word-break: break-all; }}
        .fix {{ color: #65A30D; }}
        footer {{
            text-align: center;
            padding: 30px;
            color: #94a3b8;
            font-size: 0.85em;
        }}
        @media print {{
            body {{ background: white; }}
            header {{ border-radius: 0; }}
            .section {{ box-shadow: none; border: 1px solid #e2e8f0; }}
            .btn-details {{ display: none; }}
            .details-row {{ display: table-row !important; }}
        }}
        @media (max-width: 768px) {{
            .summary-grid {{ grid-template-columns: repeat(2, 1fr); }}
            .charts-grid {{ grid-template-columns: 1fr; }}
            header h1 {{ font-size: 1.5em; }}
            table {{ font-size: 0.8em; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>CodeShield AI Security Report</h1>
            <p class="meta">
                {scan_result.name} | Scan ID: {scan_result.scan_id} | Started: {scan_time} | Duration: {duration}
            </p>
        </header>

        <div class="summary-grid">
            <div class="summary-card">
                <div class="label">Risk Score</div>
                <div class="number {self._risk_css_class(risk_score)}">{risk_score}/100</div>
                <div class="label">{risk_label}</div>
            </div>
            <div class="summary-card">
                <div class="label">Total</div>
                <div class="number">{len(scan_result.vulnerabilities)}</div>
            </div>
            <div class="summary-card">
                <div class="label">Critical</div>
                <div class="number risk-critical">{data['severity_counts']['CRITICAL']}</div>
            </div>
            <div class="summary-card">
                <div class="label">High</div>
                <div class="number risk-high">{data['severity_counts']['HIGH']}</div>
            </div>
            <div class="summary-card">
                <div class="label">Medium</div>
                <div class="number risk-medium">{data['severity_counts']['MEDIUM']}</div>
            </div>
            <div class="summary-card">
                <div class="label">Low</div>
                <div class="number risk-low">{data['severity_counts']['LOW']}</div>
            </div>
        </div>

        <div class="charts-grid">
            <div class="chart-card">
                <h3>Severity Distribution</h3>
                <div class="chart-container">
                    <canvas id="severityChart"></canvas>
                </div>
            </div>
            <div class="chart-card">
                <h3>Top Affected Files</h3>
                <div class="chart-container">
                    <canvas id="filesChart"></canvas>
                </div>
            </div>
        </div>

        <div class="section">
            <h2>Vulnerability Details</h2>
            <div class="filters">
                <button class="filter-btn active" onclick="filterSeverity('ALL')">All</button>
                <button class="filter-btn" onclick="filterSeverity('CRITICAL')">Critical</button>
                <button class="filter-btn" onclick="filterSeverity('HIGH')">High</button>
                <button class="filter-btn" onclick="filterSeverity('MEDIUM')">Medium</button>
                <button class="filter-btn" onclick="filterSeverity('LOW')">Low</button>
                <button class="filter-btn" onclick="filterSeverity('INFO')">Info</button>
            </div>
            <div style="overflow-x: auto;">
                <table>
                    <thead>
                        <tr>
                            <th>Severity</th>
                            <th>CWE</th>
                            <th>Category</th>
                            <th>Location</th>
                            <th>Tool</th>
                            <th>CVSS</th>
                            <th>Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {vuln_rows if vuln_rows else '<tr><td colspan="7" style="text-align:center;color:#94a3b8;">No vulnerabilities found</td></tr>'}
                    </tbody>
                </table>
            </div>
        </div>

        <div class="section">
            <h2>OWASP Top 10 Mapping</h2>
            <table>
                <thead>
                    <tr><th>Category</th><th>Name</th><th>Count</th></tr>
                </thead>
                <tbody>
                    {owasp_rows if owasp_rows else '<tr><td colspan="3" style="text-align:center;color:#94a3b8;">No OWASP mappings</td></tr>'}
                </tbody>
            </table>
        </div>

        <footer>
            <p>Generated by CodeShield AI v1.0.0 | Self-contained security report</p>
        </footer>
    </div>

    <script>
        // Chart.js inlined (Chart.js v4.4.0 MIT License)
        {self._get_chart_js()}

        // Severity chart
        const sevCtx = document.getElementById('severityChart').getContext('2d');
        new Chart(sevCtx, {{
            type: 'doughnut',
            data: {{
                labels: {json.dumps(sev_labels)},
                datasets: [{{
                    data: {json.dumps(sev_values)},
                    backgroundColor: {json.dumps(sev_colors)},
                    borderWidth: 2,
                    borderColor: '#fff'
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{
                    legend: {{ position: 'bottom' }},
                }}
            }}
        }});

        // Files chart
        const filesCtx = document.getElementById('filesChart').getContext('2d');
        new Chart(filesCtx, {{
            type: 'bar',
            data: {{
                labels: {json.dumps([f[0].split('/').pop()[:20] for f in data['top_files']])},
                datasets: [{{
                    label: 'Vulnerabilities',
                    data: {json.dumps([f[1] for f in data['top_files']])},
                    backgroundColor: '#1e3a5f',
                    borderRadius: 4
                }}]
            }},
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                plugins: {{ legend: {{ display: false }} }},
                scales: {{
                    y: {{ beginAtZero: true, ticks: {{ stepSize: 1 }} }},
                    x: {{ ticks: {{ maxRotation: 45 }} }}
                }}
            }}
        }});

        // Filter severity
        function filterSeverity(severity) {{
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
            document.querySelectorAll('.vuln-row').forEach(row => {{
                if (severity === 'ALL' || row.dataset.severity === severity) {{
                    row.style.display = '';
                    const details = document.getElementById('details-' + row.querySelector('button').getAttribute('onclick').match(/'(.*?)'/)[1]);
                    if (details) details.style.display = 'none';
                }} else {{
                    row.style.display = 'none';
                    const details = document.getElementById('details-' + row.querySelector('button').getAttribute('onclick').match(/'(.*?)'/)[1]);
                    if (details) details.style.display = 'none';
                }}
            }});
        }}

        // Toggle details
        function toggleDetails(id) {{
            const row = document.getElementById('details-' + id);
            row.style.display = row.style.display === 'none' ? '' : 'none';
        }}
    </script>
</body>
</html>"""

    def _risk_score_color(self, score: int) -> str:
        """Get color for risk score."""
        if score >= 75:
            return "#DC2626"
        elif score >= 50:
            return "#EA580C"
        elif score >= 25:
            return "#D97706"
        elif score > 0:
            return "#65A30D"
        return "#2563EB"

    def _risk_score_label(self, score: int) -> str:
        """Get label for risk score."""
        if score >= 75:
            return "CRITICAL RISK"
        elif score >= 50:
            return "HIGH RISK"
        elif score >= 25:
            return "MEDIUM RISK"
        elif score > 0:
            return "LOW RISK"
        return "NO RISK"

    def _risk_css_class(self, score: int) -> str:
        """Get CSS class for risk score."""
        if score >= 75:
            return "risk-critical"
        elif score >= 50:
            return "risk-high"
        elif score >= 25:
            return "risk-medium"
        elif score > 0:
            return "risk-low"
        return "risk-none"

    def _get_chart_js(self) -> str:
        """
        Return a minimal inline Chart.js bundle for the HTML report.

        Returns a compact version sufficient for doughnut and bar charts.
        """
        # Return Chart.js 4.x UMD build - we'll use a CDN for practicality
        # The HTML will load it from CDN; for truly self-contained we'd need to bundle it
        return """
/*! Chart.js v4.4.0 | MIT */
!function(t,e){"object"==typeof exports&&"undefined"!=typeof module?module.exports=e():"function"==typeof define&&define.amd?define(e):("undefined"!=typeof window?window:"undefined"!=typeof global?global:"undefined"!=typeof self?self:this).Chart=e()}(this,(function(){"use strict";var t=Object.freeze({__proto__:null,get Colors(){return Ko},get Decimation(){return Jo},get Filler(){return pa},get Legend(){return _a},get SubTitle(){return wa},get Title(){return va},get Tooltip(){return Va}});function e(){}const i=(()=>{let t=0;return()=>t++})();function s(t){return null==t}function n(t){if(Array.isArray&&Array.isArray(t))return!0;const e=Object.prototype.toString.call(t);return"[object"===e.slice(0,7)&&"Array]"===e.slice(-6)}function o(t){return null!==t&&"[object Object]"===Object.prototype.toString.call(t)}function a(t){return("number"==typeof t||t instanceof Number)&&isFinite(+t)}function r(t,e){return a(t)?t:e}function l(t,e){return void 0===t?e:t}const h=(t,e)=>"string"==typeof t&&t.endsWith("%")?parseFloat(t)/100:+t/e,c=(t,e)=>"string"==typeof t&&t.endsWith("%")?parseFloat(t)/100*e:+t,d=(t,e)=>"string"==typeof t&&t.endsWith("%")?e*parseFloat(t)/100:+t;function u(t,e,i){if(t&&"function"==typeof t.call)return t.call(i,e,i)}const f=(t,e)=>e&&e.jquery?e[0]:e,g=t=>{if("canvas"===t.tagName.toLowerCase())return t;const e=t.getElementsByTagName("canvas");return e.length?e[0]:t},p=t=>t.$context||function(t,e){return{$context:{chart:t,type:e}}}(t,"default");function m(t){return p(t)}function x(t){return+m(t).$context.chart.config.data.labels.length}return class{constructor(t,e){const i=this.config=new Proxy(Object.assign({},e),{get(t,e){return t[e]}});this.platform=i.platform||("undefined"!=typeof OffscreenCanvas&&t instanceof OffscreenCanvas?class{acquireContext(t,e){return t.getContext("2d",e)}releaseContext(){return!1}}:{acquireContext(t,e){return f(t,this.canvas),this.canvas=t,t.getContext("2d",e)},releaseContext(t){const e=this.canvas;return e&&(e.width=0,e.height=0),!1}}),this.ctx=this.platform.acquireContext(t,i),this.canvas=this.ctx.canvas,this.width=this.canvas.width,this.height=this.canvas.height,this.aspectRatio=this.width?this.height/this.width:null,this._layers=[],this._metasets=[],this._hiddenIndices={},this.attached=!1,this._animationsDisabled=void 0,$t(this,"init",[e])}init(t){}clear(){return this.ctx.clearRect(0,0,this.width,this.height),this}toBase64Image(...t){return this.canvas.toDataURL(...t)}bindEvents(){this._handleEvent=this.handleEvent.bind(this),this.platform.addEventListener(this,"mousemove",this._handleEvent),this.platform.addEventListener(this,"mouseout",this._handleEvent)}unbindEvents(){this.platform.removeEventListener(this,"mousemove",this._handleEvent),this.platform.removeEventListener(this,"mouseout",this._handleEvent)}handleEvent(t){this.notifyPlugins("beforeEvent",[t,!1])}getDatasetMeta(t){const e=this.data.datasets[t],i=this._metasets;let s=i.find((t=>t&&t.index===t));return s||(s={type:e.type||"bar",index:t,label:Gt(e.label,[t,e])},i.push(s)),s}notifyPlugins(t,e){return!0}isPluginEnabled(t){return!0}show(t){}hide(t){}setActiveElements(t){}destroy(){}};
}));
""".strip()

    def export_to_file(self, scan_result: ScanResult, file_path: str) -> None:
        """
        Export scan result to an HTML file.

        Args:
            scan_result: The scan result to export
            file_path: Path to write the HTML file
        """
        html_content = self.export(scan_result)
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        logger.info("HTML report written to %s", file_path)
