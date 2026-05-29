"""
HTML Exporter for CodeShield AI.

Generates a self-contained, modern, interactive HTML report with:
- A polished hero header with an animated SVG risk gauge
- Executive summary stat cards with severity accents
- A real, dependency-free SVG donut chart for severity distribution
- CSS bar charts for the most-affected files
- A searchable + filterable vulnerability table with expandable details
- OWASP Top 10 mapping
- Light/dark theme (respects the OS preference, with a manual toggle)
- Print-friendly layout for PDF export

The report is fully self-contained: all CSS, JS, and charts are inlined and
rendered without any external/CDN dependency.
"""

import html as _html
import json
import math
from datetime import datetime
from typing import Any, Dict, List, Tuple

from models.vulnerability import ScanResult, Vulnerability
from utils.logger import get_logger

logger = get_logger(__name__)


class HTMLExporter:
    """Export scan results to a self-contained, modern HTML report."""

    SEVERITY_COLORS = {
        "CRITICAL": "#e11d48",
        "HIGH": "#f97316",
        "MEDIUM": "#f59e0b",
        "LOW": "#22c55e",
        "INFO": "#3b82f6",
    }

    SEVERITY_BG_COLORS = {
        "CRITICAL": "rgba(225, 29, 72, 0.14)",
        "HIGH": "rgba(249, 115, 22, 0.14)",
        "MEDIUM": "rgba(245, 158, 11, 0.14)",
        "LOW": "rgba(34, 197, 94, 0.14)",
        "INFO": "rgba(59, 130, 246, 0.14)",
    }

    SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    OWASP_NAMES = {
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

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------
    def export(self, scan_result: ScanResult) -> str:
        """Export a ScanResult to a self-contained HTML report string."""
        logger.info("Generating HTML report for scan %s", scan_result.scan_id)
        data = self._prepare_data(scan_result)
        return self._build_html(data, scan_result)

    def export_to_file(self, scan_result: ScanResult, file_path: str) -> None:
        """Export scan result to an HTML file."""
        with open(file_path, "w", encoding="utf-8") as f:
            f.write(self.export(scan_result))
        logger.info("HTML report written to %s", file_path)

    # ------------------------------------------------------------------
    # Data preparation
    # ------------------------------------------------------------------
    def _prepare_data(self, scan_result: ScanResult) -> Dict[str, Any]:
        stats = scan_result.stats or {}
        severity_counts = {
            "CRITICAL": stats.get("critical", 0),
            "HIGH": stats.get("high", 0),
            "MEDIUM": stats.get("medium", 0),
            "LOW": stats.get("low", 0),
            "INFO": stats.get("info", 0),
        }

        tool_counts: Dict[str, int] = {}
        owasp_counts: Dict[str, int] = {}
        file_counts: Dict[str, int] = {}
        for vuln in scan_result.vulnerabilities:
            tool_counts[vuln.tool_source or "unknown"] = (
                tool_counts.get(vuln.tool_source or "unknown", 0) + 1
            )
            owasp = vuln.owasp_category or "Unmapped"
            owasp_counts[owasp] = owasp_counts.get(owasp, 0) + 1
            file_counts[vuln.file_path] = file_counts.get(vuln.file_path, 0) + 1

        top_files = sorted(file_counts.items(), key=lambda x: x[1], reverse=True)[:10]

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
                "code_snippet": vuln.code_snippet or "",
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
        return _html.escape(str(text), quote=True)

    # ------------------------------------------------------------------
    # SVG chart helpers (dependency-free)
    # ------------------------------------------------------------------
    def _risk_gauge_svg(self, score: int) -> str:
        """A circular progress gauge for the risk score (0-100)."""
        score = max(0, min(100, int(score)))
        color = self._risk_score_color(score)
        r = 54
        circ = 2 * math.pi * r
        filled = circ * score / 100.0
        return f"""
<svg viewBox="0 0 130 130" class="gauge" role="img" aria-label="Risk score {score} of 100">
  <circle cx="65" cy="65" r="{r}" fill="none" stroke="var(--track)" stroke-width="12"/>
  <circle cx="65" cy="65" r="{r}" fill="none" stroke="{color}" stroke-width="12"
          stroke-linecap="round" stroke-dasharray="{filled:.2f} {circ:.2f}"
          transform="rotate(-90 65 65)"/>
  <text x="65" y="60" text-anchor="middle" class="gauge-score" fill="{color}">{score}</text>
  <text x="65" y="82" text-anchor="middle" class="gauge-sub">/ 100</text>
</svg>""".strip()

    def _severity_donut_svg(self, counts: Dict[str, int]) -> str:
        """An SVG donut for severity distribution (no JS / no CDN)."""
        total = sum(counts.values())
        r = 64
        circ = 2 * math.pi * r
        segments = ""
        offset = 0.0
        if total > 0:
            for sev in self.SEVERITY_ORDER:
                val = counts.get(sev, 0)
                if val <= 0:
                    continue
                frac = val / total
                dash = frac * circ
                segments += (
                    f'<circle cx="90" cy="90" r="{r}" fill="none" '
                    f'stroke="{self.SEVERITY_COLORS[sev]}" stroke-width="22" '
                    f'stroke-dasharray="{dash:.2f} {circ - dash:.2f}" '
                    f'stroke-dashoffset="{-offset:.2f}" transform="rotate(-90 90 90)">'
                    f'<title>{sev}: {val}</title></circle>'
                )
                offset += dash
        else:
            segments = (
                f'<circle cx="90" cy="90" r="{r}" fill="none" '
                f'stroke="var(--track)" stroke-width="22"/>'
            )
        return f"""
<svg viewBox="0 0 180 180" class="donut" role="img" aria-label="Severity distribution">
  {segments}
  <text x="90" y="84" text-anchor="middle" class="donut-total">{total}</text>
  <text x="90" y="104" text-anchor="middle" class="donut-label">findings</text>
</svg>""".strip()

    def _severity_legend(self, counts: Dict[str, int]) -> str:
        rows = ""
        total = sum(counts.values()) or 1
        for sev in self.SEVERITY_ORDER:
            val = counts.get(sev, 0)
            pct = round(val / total * 100)
            rows += f"""
      <li>
        <span class="dot" style="background:{self.SEVERITY_COLORS[sev]}"></span>
        <span class="leg-name">{sev.title()}</span>
        <span class="leg-val">{val}</span>
        <span class="leg-pct">{pct}%</span>
      </li>"""
        return f'<ul class="legend">{rows}</ul>'

    def _top_files_bars(self, top_files: List[Tuple[str, int]]) -> str:
        if not top_files:
            return '<p class="empty">No affected files.</p>'
        max_count = max(c for _, c in top_files) or 1
        bars = ""
        for path, count in top_files:
            name = self._escape_html(path.split("/")[-1])
            full = self._escape_html(path)
            width = round(count / max_count * 100)
            bars += f"""
      <div class="bar-row" title="{full}">
        <span class="bar-label">{name}</span>
        <span class="bar-track"><span class="bar-fill" style="width:{width}%"></span></span>
        <span class="bar-count">{count}</span>
      </div>"""
        return f'<div class="bars">{bars}</div>'

    # ------------------------------------------------------------------
    # HTML assembly
    # ------------------------------------------------------------------
    def _build_html(self, data: Dict[str, Any], scan_result: ScanResult) -> str:
        title = f"CodeShield AI Report - {self._escape_html(scan_result.name)}"
        scan_time = (
            scan_result.start_time.strftime("%Y-%m-%d %H:%M UTC")
            if scan_result.start_time else "N/A"
        )
        duration = f"{scan_result.scan_duration}s" if scan_result.scan_duration else "N/A"
        risk_score = scan_result.risk_score
        risk_label = self._risk_score_label(risk_score)
        sev = data["severity_counts"]
        total = len(scan_result.vulnerabilities)

        vuln_rows = self._build_vuln_rows(data["vulnerabilities"])
        owasp_rows = ""
        for code, count in sorted(data["owasp_counts"].items()):
            name = self.OWASP_NAMES.get(code, code)
            owasp_rows += (
                f'<tr><td><span class="tag">{self._escape_html(code)}</span></td>'
                f'<td>{self._escape_html(name)}</td><td class="num">{count}</td></tr>'
            )

        return f"""<!DOCTYPE html>
<html lang="en" data-theme="auto">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>{self._styles()}</style>
</head>
<body>
<nav class="topbar">
  <div class="brand">
    <span class="brand-mark">CS</span>
    <span>CodeShield <strong>AI</strong></span>
  </div>
  <div class="topbar-actions">
    <button class="ghost-btn" onclick="window.print()" title="Save as PDF">Save PDF</button>
    <button class="ghost-btn" id="themeToggle" title="Toggle theme" aria-label="Toggle theme">Theme</button>
  </div>
</nav>

<div class="container">
  <header class="hero">
    <div class="hero-info">
      <div class="hero-eyebrow">Security Report</div>
      <h1>{self._escape_html(scan_result.name)}</h1>
      <div class="hero-meta">
        <span>Scan <code>{self._escape_html(scan_result.scan_id)}</code></span>
        <span>&bull; {scan_time}</span>
        <span>&bull; {duration}</span>
      </div>
      <div class="risk-pill" data-level="{self._risk_css_class(risk_score)}">{risk_label}</div>
    </div>
    <div class="hero-gauge">
      {self._risk_gauge_svg(risk_score)}
      <div class="gauge-caption">Risk score</div>
    </div>
  </header>

  <section class="stat-grid">
    {self._stat_card("Total findings", total, "total")}
    {self._stat_card("Critical", sev['CRITICAL'], "CRITICAL")}
    {self._stat_card("High", sev['HIGH'], "HIGH")}
    {self._stat_card("Medium", sev['MEDIUM'], "MEDIUM")}
    {self._stat_card("Low", sev['LOW'], "LOW")}
    {self._stat_card("Info", sev['INFO'], "INFO")}
  </section>

  <section class="cards-2">
    <div class="card">
      <h3>Severity distribution</h3>
      <div class="donut-wrap">
        {self._severity_donut_svg(sev)}
        {self._severity_legend(sev)}
      </div>
    </div>
    <div class="card">
      <h3>Most affected files</h3>
      {self._top_files_bars(data['top_files'])}
    </div>
  </section>

  <section class="card">
    <div class="card-head">
      <h3>Vulnerability details</h3>
      <input type="search" id="searchBox" class="search" placeholder="Search findings..."
             oninput="applyFilters()" aria-label="Search findings">
    </div>
    <div class="chips" id="sevChips">
      <button class="chip active" data-sev="ALL" onclick="setSeverity(this)">All</button>
      <button class="chip" data-sev="CRITICAL" onclick="setSeverity(this)">Critical</button>
      <button class="chip" data-sev="HIGH" onclick="setSeverity(this)">High</button>
      <button class="chip" data-sev="MEDIUM" onclick="setSeverity(this)">Medium</button>
      <button class="chip" data-sev="LOW" onclick="setSeverity(this)">Low</button>
      <button class="chip" data-sev="INFO" onclick="setSeverity(this)">Info</button>
    </div>
    <div class="table-wrap">
      <table id="vulnTable">
        <thead>
          <tr>
            <th>Severity</th><th>CWE</th><th>Category</th>
            <th>Location</th><th>Tool</th><th>CVSS</th><th></th>
          </tr>
        </thead>
        <tbody>
          {vuln_rows or '<tr><td colspan="7" class="empty">No vulnerabilities found &mdash; nice work!</td></tr>'}
        </tbody>
      </table>
    </div>
    <p class="result-count" id="resultCount"></p>
  </section>

  <section class="card">
    <h3>OWASP Top 10 mapping</h3>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Category</th><th>Name</th><th class="num">Count</th></tr></thead>
        <tbody>
          {owasp_rows or '<tr><td colspan="3" class="empty">No OWASP mappings.</td></tr>'}
        </tbody>
      </table>
    </div>
  </section>

  <footer>Generated by <strong>CodeShield AI</strong> &bull; self-contained security report</footer>
</div>
<script>{self._script()}</script>
</body>
</html>"""

    def _stat_card(self, label: str, value: int, key: str) -> str:
        accent = self.SEVERITY_COLORS.get(key, "var(--accent)")
        return f"""
    <div class="stat" style="--accent-c:{accent}">
      <div class="stat-num">{value}</div>
      <div class="stat-label">{label}</div>
    </div>"""

    def _build_vuln_rows(self, vulns: List[Dict[str, Any]]) -> str:
        rows = ""
        for v in vulns:
            sev = v["severity"]
            chip = (
                f"background:{self.SEVERITY_BG_COLORS.get(sev, '#eee')};"
                f"color:{self.SEVERITY_COLORS.get(sev, '#333')};"
            )
            loc = self._escape_html(v["file_path"])
            loc_short = loc if len(loc) <= 52 else "&hellip;" + loc[-50:]
            haystack = self._escape_html(
                f"{sev} {v['category']} {v['file_path']} {v['cwe_id'] or ''} "
                f"{v['title']} {v['tool_source']}"
            ).lower()
            snippet = self._escape_html(v["code_snippet"])
            code_html = (
                f'<div class="code"><pre>{snippet}</pre></div>' if snippet else ""
            )
            fix_html = (
                f'<p class="fix"><strong>Suggested fix:</strong> '
                f'{self._escape_html(v["fix_suggestion"])}</p>'
                if v["fix_suggestion"] else ""
            )
            rows += f"""
          <tr class="vrow" data-severity="{sev}" data-search="{haystack}">
            <td><span class="sev" style="{chip}">{sev}</span></td>
            <td>{self._escape_html(v['cwe_id'] or 'N/A')}</td>
            <td>{self._escape_html(v['category'])}</td>
            <td class="loc" title="{loc}">{loc_short}:{v['line_number']}</td>
            <td>{self._escape_html(v['tool_source'])}</td>
            <td class="num">{self._escape_html(v['cvss_score'] if v['cvss_score'] is not None else 'N/A')}</td>
            <td><button class="link-btn" onclick="toggleDetails('{v['id']}', this)">Details</button></td>
          </tr>
          <tr id="d-{v['id']}" class="drow" hidden>
            <td colspan="7">
              <div class="detail">
                <h4>{self._escape_html(v['title'])}</h4>
                <p>{self._escape_html(v['description'])}</p>
                {code_html}
                {fix_html}
                <p class="meta-line">
                  <strong>Confidence:</strong> {self._escape_html(v['confidence'] or 'N/A')}
                  &nbsp;&bull;&nbsp; <strong>OWASP:</strong> {self._escape_html(v['owasp_category'] or 'N/A')}
                </p>
              </div>
            </td>
          </tr>"""
        return rows

    # ------------------------------------------------------------------
    # Styles & scripts
    # ------------------------------------------------------------------
    def _styles(self) -> str:
        return """
:root{
  --bg:#f1f5f9; --surface:#ffffff; --surface-2:#f8fafc; --text:#0f172a;
  --muted:#64748b; --border:#e2e8f0; --track:#e2e8f0; --accent:#4f46e5;
  --shadow:0 1px 2px rgba(15,23,42,.06),0 8px 24px rgba(15,23,42,.06);
  --radius:16px;
}
@media (prefers-color-scheme: dark){
  :root[data-theme="auto"]{
    --bg:#0b1120; --surface:#111827; --surface-2:#0f172a; --text:#e5e7eb;
    --muted:#94a3b8; --border:#1f2937; --track:#1f2937;
    --shadow:0 1px 2px rgba(0,0,0,.4),0 10px 30px rgba(0,0,0,.35);
  }
}
:root[data-theme="dark"]{
  --bg:#0b1120; --surface:#111827; --surface-2:#0f172a; --text:#e5e7eb;
  --muted:#94a3b8; --border:#1f2937; --track:#1f2937;
  --shadow:0 1px 2px rgba(0,0,0,.4),0 10px 30px rgba(0,0,0,.35);
}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Inter,sans-serif;
  background:var(--bg);color:var(--text);line-height:1.55;-webkit-font-smoothing:antialiased}
.container{max-width:1200px;margin:0 auto;padding:24px}
code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.88em}

.topbar{position:sticky;top:0;z-index:20;display:flex;justify-content:space-between;
  align-items:center;padding:12px 24px;background:color-mix(in srgb,var(--surface) 88%,transparent);
  backdrop-filter:saturate(160%) blur(10px);border-bottom:1px solid var(--border)}
.brand{display:flex;align-items:center;gap:10px;font-size:1.05rem;letter-spacing:.2px}
.brand-mark{display:grid;place-items:center;width:30px;height:30px;border-radius:9px;
  background:linear-gradient(135deg,#6366f1,#4f46e5);color:#fff;font-weight:800;font-size:.85rem}
.topbar-actions{display:flex;gap:8px}
.ghost-btn{padding:7px 14px;border:1px solid var(--border);background:var(--surface);
  color:var(--text);border-radius:10px;cursor:pointer;font-size:.85rem;font-weight:600;transition:.15s}
.ghost-btn:hover{border-color:var(--accent);color:var(--accent)}

.hero{display:flex;justify-content:space-between;align-items:center;gap:24px;flex-wrap:wrap;
  background:radial-gradient(120% 140% at 0% 0%,#1e293b 0%,#0f172a 55%,#020617 100%);
  color:#e2e8f0;border-radius:var(--radius);padding:34px;margin:8px 0 24px;box-shadow:var(--shadow)}
.hero-eyebrow{text-transform:uppercase;letter-spacing:.18em;font-size:.72rem;color:#93c5fd;font-weight:700}
.hero h1{font-size:1.9rem;margin:6px 0 10px;line-height:1.15}
.hero-meta{display:flex;gap:8px;flex-wrap:wrap;color:#94a3b8;font-size:.88rem;align-items:center}
.hero-meta code{background:rgba(255,255,255,.08);padding:2px 8px;border-radius:6px;color:#cbd5e1}
.risk-pill{display:inline-block;margin-top:16px;padding:6px 14px;border-radius:999px;font-weight:700;
  font-size:.78rem;letter-spacing:.05em}
.risk-pill[data-level="risk-critical"]{background:rgba(225,29,72,.18);color:#fb7185}
.risk-pill[data-level="risk-high"]{background:rgba(249,115,22,.18);color:#fdba74}
.risk-pill[data-level="risk-medium"]{background:rgba(245,158,11,.18);color:#fcd34d}
.risk-pill[data-level="risk-low"]{background:rgba(34,197,94,.18);color:#86efac}
.risk-pill[data-level="risk-none"]{background:rgba(59,130,246,.18);color:#93c5fd}
.hero-gauge{text-align:center}
.gauge{width:130px;height:130px}
.gauge-score{font-size:34px;font-weight:800}
.gauge-sub{font-size:13px;fill:#94a3b8}
.gauge-caption{margin-top:6px;font-size:.78rem;color:#94a3b8;text-transform:uppercase;letter-spacing:.1em}

.stat-grid{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-bottom:24px}
.stat{position:relative;background:var(--surface);border:1px solid var(--border);border-radius:14px;
  padding:18px 16px;box-shadow:var(--shadow);overflow:hidden}
.stat::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--accent-c)}
.stat-num{font-size:2rem;font-weight:800;line-height:1}
.stat-label{margin-top:6px;color:var(--muted);font-size:.78rem;text-transform:uppercase;letter-spacing:.05em}

.cards-2{display:grid;grid-template-columns:1fr 1fr;gap:18px;margin-bottom:18px}
.card{background:var(--surface);border:1px solid var(--border);border-radius:var(--radius);
  padding:22px;box-shadow:var(--shadow);margin-bottom:18px}
.card h3{font-size:1.02rem;margin-bottom:16px}
.card-head{display:flex;justify-content:space-between;align-items:center;gap:12px;margin-bottom:8px;flex-wrap:wrap}
.card-head h3{margin-bottom:0}

.donut-wrap{display:flex;align-items:center;gap:22px;flex-wrap:wrap}
.donut{width:180px;height:180px;flex:0 0 auto}
.donut-total{font-size:34px;font-weight:800;fill:var(--text)}
.donut-label{font-size:13px;fill:var(--muted)}
.legend{list-style:none;flex:1;min-width:180px;display:flex;flex-direction:column;gap:8px}
.legend li{display:grid;grid-template-columns:14px 1fr auto auto;align-items:center;gap:10px;font-size:.9rem}
.legend .dot{width:12px;height:12px;border-radius:4px}
.leg-name{color:var(--text)}
.leg-val{font-weight:700}
.leg-pct{color:var(--muted);width:42px;text-align:right}

.bars{display:flex;flex-direction:column;gap:11px}
.bar-row{display:grid;grid-template-columns:150px 1fr 34px;align-items:center;gap:12px;font-size:.86rem}
.bar-label{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--muted)}
.bar-track{height:10px;background:var(--track);border-radius:999px;overflow:hidden}
.bar-fill{display:block;height:100%;border-radius:999px;background:linear-gradient(90deg,#6366f1,#4f46e5)}
.bar-count{text-align:right;font-weight:700}

.search{padding:8px 14px;border:1px solid var(--border);border-radius:10px;background:var(--surface-2);
  color:var(--text);font-size:.88rem;min-width:220px}
.search:focus{outline:none;border-color:var(--accent)}
.chips{display:flex;gap:8px;flex-wrap:wrap;margin:6px 0 16px}
.chip{padding:6px 15px;border:1px solid var(--border);background:var(--surface);color:var(--text);
  border-radius:999px;cursor:pointer;font-size:.82rem;font-weight:600;transition:.15s}
.chip:hover{border-color:var(--accent)}
.chip.active{background:var(--accent);border-color:var(--accent);color:#fff}

.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:12px}
table{width:100%;border-collapse:collapse;font-size:.88rem}
th{background:var(--surface-2);padding:12px 14px;text-align:left;font-weight:600;color:var(--muted);
  position:sticky;top:0;white-space:nowrap}
td{padding:11px 14px;border-top:1px solid var(--border);vertical-align:middle}
td.num,th.num{text-align:right}
.vrow:hover{background:var(--surface-2)}
.loc{font-family:ui-monospace,monospace;font-size:.82rem;color:var(--muted);max-width:320px;
  white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
.sev{padding:3px 11px;border-radius:999px;font-size:.72rem;font-weight:700;letter-spacing:.04em}
.tag{padding:2px 9px;border-radius:6px;background:var(--surface-2);border:1px solid var(--border);font-weight:600;font-size:.78rem}
.link-btn{background:none;border:none;color:var(--accent);font-weight:700;cursor:pointer;font-size:.84rem}
.link-btn:hover{text-decoration:underline}
.drow>td{background:var(--surface-2)}
.detail{border-left:3px solid var(--accent);padding:6px 0 6px 18px;margin:6px 0}
.detail h4{margin-bottom:8px}
.detail p{margin-bottom:8px}
.code{background:#0b1120;color:#e2e8f0;padding:14px 16px;border-radius:10px;margin:10px 0;overflow-x:auto;
  font-family:ui-monospace,monospace;font-size:.82rem;border:1px solid #1f2937}
.code pre{white-space:pre-wrap;word-break:break-word}
.fix{color:#16a34a}
.meta-line{color:var(--muted);font-size:.85rem}
.result-count{margin-top:10px;color:var(--muted);font-size:.82rem}
.empty{text-align:center;color:var(--muted);padding:22px}

footer{text-align:center;padding:28px;color:var(--muted);font-size:.82rem}

/* ---------- Responsive ---------- */
@media (max-width:1024px){
  .stat-grid{grid-template-columns:repeat(3,1fr)}
}
@media (max-width:900px){
  .cards-2{grid-template-columns:1fr}
  .hero{padding:26px}
  .hero h1{font-size:1.55rem}
  .donut-wrap{justify-content:center}
}
@media (max-width:640px){
  .container{padding:14px}
  .topbar{padding:10px 14px}
  .brand span:not(.brand-mark){font-size:.95rem}
  .hero{flex-direction:column-reverse;align-items:flex-start;text-align:left;padding:22px}
  .hero-gauge{align-self:center}
  .gauge{width:112px;height:112px}
  .stat-grid{grid-template-columns:repeat(2,1fr);gap:10px}
  .stat{padding:14px 13px}
  .stat-num{font-size:1.6rem}
  .card{padding:16px}
  .card-head{flex-direction:column;align-items:stretch}
  .search{width:100%;min-width:0}
  .donut{width:148px;height:148px}
  .legend li{grid-template-columns:14px 1fr auto auto}
  .bar-row{grid-template-columns:96px 1fr 26px;gap:8px}
  /* Collapse lower-priority columns; keep severity, category, location, action */
  #vulnTable th:nth-child(2),#vulnTable td:nth-child(2),
  #vulnTable th:nth-child(5),#vulnTable td:nth-child(5),
  #vulnTable th:nth-child(6),#vulnTable td:nth-child(6){display:none}
  .loc{max-width:160px}
  table{font-size:.82rem}
  th,td{padding:9px 10px}
}
@media (max-width:380px){
  .stat-grid{grid-template-columns:1fr 1fr}
  .chips{gap:6px}
  .chip{padding:5px 11px;font-size:.78rem}
}
@media print{
  .topbar,.topbar-actions,.search,.chips,.link-btn{display:none!important}
  body{background:#fff}
  .card,.stat,.hero{box-shadow:none;border:1px solid #e2e8f0}
  .drow{display:table-row!important}
  .drow[hidden]{display:table-row!important}
}
""".strip()

    def _script(self) -> str:
        return """
(function(){
  var root=document.documentElement;
  var saved=null; try{saved=localStorage.getItem('cs-theme');}catch(e){}
  if(saved){root.setAttribute('data-theme',saved);}
  var t=document.getElementById('themeToggle');
  if(t){t.addEventListener('click',function(){
    var cur=root.getAttribute('data-theme');
    var prefersDark=window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches;
    var isDark=cur==='dark'||(cur==='auto'&&prefersDark);
    var next=isDark?'light':'dark';
    root.setAttribute('data-theme',next);
    try{localStorage.setItem('cs-theme',next);}catch(e){}
  });}
})();

var currentSev='ALL';
function setSeverity(btn){
  currentSev=btn.getAttribute('data-sev');
  var chips=document.querySelectorAll('#sevChips .chip');
  for(var i=0;i<chips.length;i++){chips[i].classList.remove('active');}
  btn.classList.add('active');
  applyFilters();
}
function applyFilters(){
  var q=(document.getElementById('searchBox').value||'').toLowerCase().trim();
  var rows=document.querySelectorAll('#vulnTable tbody .vrow');
  var shown=0;
  for(var i=0;i<rows.length;i++){
    var row=rows[i];
    var sevOk=(currentSev==='ALL'||row.getAttribute('data-severity')===currentSev);
    var qOk=(!q||(row.getAttribute('data-search')||'').indexOf(q)!==-1);
    var visible=sevOk&&qOk;
    row.style.display=visible?'':'none';
    var det=document.getElementById('d-'+rowId(row));
    if(det){det.hidden=true;if(!visible)det.style.display='none';else det.style.display='';}
    if(visible)shown++;
  }
  var rc=document.getElementById('resultCount');
  if(rc)rc.textContent='Showing '+shown+' of '+rows.length+' findings';
}
function rowId(row){
  var b=row.querySelector('.link-btn');
  if(!b)return '';
  var m=b.getAttribute('onclick').match(/'([^']+)'/);
  return m?m[1]:'';
}
function toggleDetails(id,btn){
  var det=document.getElementById('d-'+id);
  if(!det)return;
  det.hidden=!det.hidden;
  if(btn)btn.textContent=det.hidden?'Details':'Hide';
}
document.addEventListener('DOMContentLoaded',applyFilters);
""".strip()

    # ------------------------------------------------------------------
    # Risk helpers
    # ------------------------------------------------------------------
    def _risk_score_color(self, score: int) -> str:
        if score >= 75:
            return "#e11d48"
        if score >= 50:
            return "#f97316"
        if score >= 25:
            return "#f59e0b"
        if score > 0:
            return "#22c55e"
        return "#3b82f6"

    def _risk_score_label(self, score: int) -> str:
        if score >= 75:
            return "CRITICAL RISK"
        if score >= 50:
            return "HIGH RISK"
        if score >= 25:
            return "MEDIUM RISK"
        if score > 0:
            return "LOW RISK"
        return "NO RISK"

    def _risk_css_class(self, score: int) -> str:
        if score >= 75:
            return "risk-critical"
        if score >= 50:
            return "risk-high"
        if score >= 25:
            return "risk-medium"
        if score > 0:
            return "risk-low"
        return "risk-none"
