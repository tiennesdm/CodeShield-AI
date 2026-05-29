"""
Server-rendered web dashboard for CodeShield AI.

Produces a single, self-contained, responsive HTML page summarizing scan
history and aggregate stats (no frontend build, no external assets). It reuses
the report's modern design language (light/dark, cards) and is rendered by a
FastAPI route from the configured datastore.
"""

from __future__ import annotations

import html as _html
from datetime import datetime
from typing import Any, Dict, List

from models.vulnerability import ScanResult

_SEV_COLORS = {
    "critical": "#e11d48",
    "high": "#f97316",
    "medium": "#f59e0b",
    "low": "#22c55e",
    "info": "#3b82f6",
}
_STATUS_COLORS = {
    "completed": "#22c55e",
    "running": "#3b82f6",
    "pending": "#f59e0b",
    "failed": "#e11d48",
}


class DashboardRenderer:
    """Renders the dashboard HTML from stats + a list of scans."""

    def render(self, stats: Dict[str, Any], scans: List[ScanResult]) -> str:
        sev = stats.get("by_severity", {})
        by_status = stats.get("by_status", {})
        total_scans = stats.get("total_scans", 0)
        total_vulns = stats.get("total_vulnerabilities", 0)

        stat_cards = "".join([
            self._stat("Total scans", total_scans, "var(--accent)"),
            self._stat("Total findings", total_vulns, "var(--accent)"),
            self._stat("Critical", sev.get("critical", 0), _SEV_COLORS["critical"]),
            self._stat("High", sev.get("high", 0), _SEV_COLORS["high"]),
            self._stat("Medium", sev.get("medium", 0), _SEV_COLORS["medium"]),
            self._stat("Completed", by_status.get("completed", 0), _STATUS_COLORS["completed"]),
        ])

        rows = ""
        for s in scans:
            st = (s.status or "").lower()
            st_color = _STATUS_COLORS.get(st, "#64748b")
            findings = len(s.vulnerabilities)
            when = s.start_time.strftime("%Y-%m-%d %H:%M") if getattr(s, "start_time", None) else "-"
            rows += f"""
          <tr>
            <td class="mono">{_html.escape(s.scan_id)}</td>
            <td>{_html.escape(s.name or '')}</td>
            <td><span class="pill" style="background:{st_color}22;color:{st_color}">{_html.escape(s.status or '')}</span></td>
            <td class="num">{findings}</td>
            <td class="num">{getattr(s, 'risk_score', 0)}</td>
            <td class="muted">{when}</td>
          </tr>"""

        if not rows:
            rows = '<tr><td colspan="6" class="empty">No scans yet.</td></tr>'

        generated = datetime.now().strftime("%Y-%m-%d %H:%M")

        return f"""<!DOCTYPE html>
<html lang="en" data-theme="auto">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>CodeShield AI &mdash; Dashboard</title>
<style>{self._styles()}</style>
</head>
<body>
<nav class="topbar">
  <div class="brand"><span class="mark">CS</span><span>CodeShield <strong>AI</strong> &mdash; Dashboard</span></div>
  <button class="ghost" id="themeToggle">Theme</button>
</nav>
<div class="wrap">
  <section class="grid">{stat_cards}</section>
  <section class="card">
    <h3>Recent scans</h3>
    <div class="table-wrap">
      <table>
        <thead><tr><th>Scan ID</th><th>Name</th><th>Status</th><th class="num">Findings</th><th class="num">Risk</th><th>Started</th></tr></thead>
        <tbody>{rows}</tbody>
      </table>
    </div>
  </section>
  <footer>Generated {generated} &bull; CodeShield AI</footer>
</div>
<script>
(function(){{
  var root=document.documentElement, s=null;
  try{{s=localStorage.getItem('cs-theme');}}catch(e){{}}
  if(s)root.setAttribute('data-theme',s);
  document.getElementById('themeToggle').addEventListener('click',function(){{
    var cur=root.getAttribute('data-theme');
    var dark=cur==='dark'||(cur==='auto'&&window.matchMedia&&window.matchMedia('(prefers-color-scheme: dark)').matches);
    var next=dark?'light':'dark';root.setAttribute('data-theme',next);
    try{{localStorage.setItem('cs-theme',next);}}catch(e){{}}
  }});
}})();
</script>
</body>
</html>"""

    def _stat(self, label: str, value: Any, color: str) -> str:
        return f"""
    <div class="stat" style="--c:{color}">
      <div class="num">{value}</div><div class="label">{_html.escape(label)}</div>
    </div>"""

    def _styles(self) -> str:
        return """
:root{--bg:#f1f5f9;--surface:#fff;--surface2:#f8fafc;--text:#0f172a;--muted:#64748b;--border:#e2e8f0;--accent:#4f46e5;--shadow:0 1px 2px rgba(15,23,42,.06),0 8px 24px rgba(15,23,42,.06)}
@media (prefers-color-scheme:dark){:root[data-theme="auto"]{--bg:#0b1120;--surface:#111827;--surface2:#0f172a;--text:#e5e7eb;--muted:#94a3b8;--border:#1f2937;--shadow:0 10px 30px rgba(0,0,0,.35)}}
:root[data-theme="dark"]{--bg:#0b1120;--surface:#111827;--surface2:#0f172a;--text:#e5e7eb;--muted:#94a3b8;--border:#1f2937}
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Inter,sans-serif;background:var(--bg);color:var(--text)}
.topbar{position:sticky;top:0;display:flex;justify-content:space-between;align-items:center;padding:12px 22px;background:var(--surface);border-bottom:1px solid var(--border)}
.brand{display:flex;align-items:center;gap:10px}
.mark{display:grid;place-items:center;width:30px;height:30px;border-radius:9px;background:linear-gradient(135deg,#6366f1,#4f46e5);color:#fff;font-weight:800;font-size:.8rem}
.ghost{padding:7px 14px;border:1px solid var(--border);background:var(--surface);color:var(--text);border-radius:10px;cursor:pointer;font-weight:600;font-size:.85rem}
.wrap{max-width:1100px;margin:0 auto;padding:22px}
.grid{display:grid;grid-template-columns:repeat(6,1fr);gap:14px;margin-bottom:20px}
.stat{position:relative;background:var(--surface);border:1px solid var(--border);border-radius:14px;padding:18px;box-shadow:var(--shadow);overflow:hidden}
.stat::before{content:"";position:absolute;left:0;top:0;bottom:0;width:4px;background:var(--c)}
.stat .num{font-size:1.9rem;font-weight:800}
.stat .label{margin-top:6px;color:var(--muted);font-size:.76rem;text-transform:uppercase;letter-spacing:.05em}
.card{background:var(--surface);border:1px solid var(--border);border-radius:16px;padding:22px;box-shadow:var(--shadow)}
.card h3{margin-bottom:14px}
.table-wrap{overflow-x:auto;border:1px solid var(--border);border-radius:12px}
table{width:100%;border-collapse:collapse;font-size:.9rem}
th{background:var(--surface2);padding:11px 14px;text-align:left;color:var(--muted);font-weight:600}
td{padding:11px 14px;border-top:1px solid var(--border)}
td.num,th.num{text-align:right}
.mono{font-family:ui-monospace,monospace;font-size:.82rem}
.muted{color:var(--muted)}
.pill{padding:3px 11px;border-radius:999px;font-size:.74rem;font-weight:700;text-transform:capitalize}
.empty{text-align:center;color:var(--muted);padding:22px}
footer{text-align:center;color:var(--muted);font-size:.82rem;padding:24px}
@media (max-width:900px){.grid{grid-template-columns:repeat(3,1fr)}}
@media (max-width:560px){.grid{grid-template-columns:repeat(2,1fr)}.wrap{padding:14px}}
""".strip()
