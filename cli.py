"""
CodeShield AI - Command Line Interface (codeshield-cli).

A Click-based CLI for interacting with the CodeShield AI scanning engine.
Provides commands for scanning ZIP files, GitHub repositories, checking status,
retrieving results, viewing history, and generating reports.

Exit Codes:
    0 - No vulnerabilities found
    1 - Vulnerabilities found
    2 - Error occurred

Usage:
    codeshield-cli scan zip <file> [--severity-filter ...] [--tools ...] [--output-format json]
    codeshield-cli scan github <url> [--severity-filter ...] [--tools ...]
    codeshield-cli scan status <scan_id>
    codeshield-cli scan results <scan_id> [--severity-filter ...] [--output-format sarif]
    codeshield-cli scan history [--limit 50]
    codeshield-cli scan report <scan_id> [--output-file report.html]
"""

import io
import json
import os
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

import click
import httpx
import yaml
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.text import Text

# Default API base URL
DEFAULT_API_URL = "http://localhost:8000"

# Configuration directory and file
CONFIG_DIR = Path.home() / ".codeshield"
CONFIG_FILE = CONFIG_DIR / "config.yaml"

# Exit codes
EXIT_OK = 0
EXIT_VULNS_FOUND = 1
EXIT_ERROR = 2

console = Console()


def get_config() -> Dict[str, Any]:
    """
    Load CLI configuration from ~/.codeshield/config.yaml.

    Returns:
        Dictionary with configuration values. Returns defaults if file doesn't exist.
    """
    defaults = {
        "api_url": DEFAULT_API_URL,
        "default_output_format": "json",
        "severity_filter": ["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        "timeout": 60,
    }

    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                config = yaml.safe_load(f) or {}
                defaults.update(config)
        except Exception as e:
            console.print(f"[yellow]Warning: Could not read config file: {e}[/yellow]")

    return defaults


def get_api_url() -> str:
    """Get the configured API URL."""
    config = get_config()
    return config.get("api_url", DEFAULT_API_URL).rstrip("/")


def severity_color(severity: str) -> str:
    """Get Rich color for a severity level."""
    colors = {
        "CRITICAL": "red",
        "HIGH": "bright_red",
        "MEDIUM": "yellow",
        "LOW": "green",
        "INFO": "blue",
    }
    return colors.get(severity.upper(), "white")


def severity_icon(severity: str) -> str:
    """Get icon for a severity level."""
    icons = {
        "CRITICAL": "[!]",
        "HIGH": "[+]",
        "MEDIUM": "[~]",
        "LOW": "[-]",
        "INFO": "[i]",
    }
    return icons.get(severity.upper(), "[?]")


def print_vulnerability(vuln: Dict[str, Any], index: int) -> None:
    """Print a single vulnerability with color-coded severity."""
    severity = vuln.get("severity", "INFO")
    color = severity_color(severity)
    icon = severity_icon(severity)

    panel_title = f"{icon} #{index} [{severity}] {vuln.get('category', 'Unknown')}"
    content = (
        f"[bold]File:[/bold] {vuln.get('file_path', 'N/A')}:{vuln.get('line_number', 0)}\n"
        f"[bold]Title:[/bold] {vuln.get('title', 'N/A')}\n"
        f"[bold]CWE:[/bold] {vuln.get('cwe_id', 'N/A')} - {vuln.get('cwe_name', 'N/A')}\n"
        f"[bold]Tool:[/bold] {vuln.get('tool_source', 'N/A')}\n"
        f"[bold]CVSS:[/bold] {vuln.get('cvss_score', 'N/A')}\n"
    )

    if vuln.get("code_snippet"):
        content += f"\n[bold]Code:[/bold]\n[dim]{vuln['code_snippet']}[/dim]\n"

    if vuln.get("fix_suggestion"):
        content += f"\n[bold green]Fix:[/bold green] {vuln['fix_suggestion']}"

    console.print(Panel(content, title=panel_title, border_style=color, expand=False))


def print_results_table(vulnerabilities: List[Dict[str, Any]], title: str = "Scan Results") -> None:
    """Print vulnerabilities in a rich table format."""
    table = Table(title=title, show_lines=True)
    table.add_column("#", style="cyan", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Category", width=25)
    table.add_column("File", width=40)
    table.add_column("Line", justify="right", width=6)
    table.add_column("CWE", width=12)
    table.add_column("Tool", width=15)

    for i, vuln in enumerate(vulnerabilities, 1):
        severity = vuln.get("severity", "INFO")
        color = severity_color(severity)
        table.add_row(
            str(i),
            Text(severity, style=color),
            vuln.get("category", "N/A"),
            vuln.get("file_path", "N/A"),
            str(vuln.get("line_number", "N/A")),
            vuln.get("cwe_id", "N/A"),
            vuln.get("tool_source", "N/A"),
        )

    console.print(table)


def print_summary(stats: Dict[str, int], risk_score: int, scan_id: str) -> None:
    """Print scan summary with color-coded counts."""
    summary_table = Table(title=f"Scan Summary - {scan_id}", show_lines=False)
    summary_table.add_column("Metric", style="bold")
    summary_table.add_column("Count", justify="right")

    severity_colors = {"critical": "red", "high": "bright_red", "medium": "yellow", "low": "green", "info": "blue"}

    for sev in ["critical", "high", "medium", "low", "info"]:
        count = stats.get(sev, 0)
        color = severity_colors.get(sev, "white")
        summary_table.add_row(sev.upper(), Text(str(count), style=color))

    summary_table.add_row("TOTAL", Text(str(stats.get("total", 0)), style="bold white"))
    summary_table.add_row("Risk Score", Text(str(risk_score), style="bold magenta"))

    console.print(summary_table)


def poll_scan_status(scan_id: str, api_url: str, timeout: int = 600) -> Optional[Dict[str, Any]]:
    """
    Poll scan status until completion or timeout.

    Args:
        scan_id: The scan ID to poll
        api_url: Base API URL
        timeout: Maximum time to wait in seconds

    Returns:
        Final scan data or None if timed out
    """
    start_time = time.time()
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(bar_width=40),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console,
    )

    with progress:
        task = progress.add_task(f"Scanning {scan_id}...", total=100)

        while time.time() - start_time < timeout:
            try:
                resp = httpx.get(f"{api_url}/api/scan/{scan_id}/status", timeout=10)
                resp.raise_for_status()
                data = resp.json()

                status = data.get("status", "unknown")
                prog = data.get("progress", 0)
                progress.update(task, completed=prog, description=f"Scanning {scan_id} - {status}")

                if status in ("completed", "failed"):
                    return data

                time.sleep(2)

            except httpx.RequestError as e:
                console.print(f"[yellow]Connection error: {e}. Retrying...[/yellow]")
                time.sleep(3)
            except Exception as e:
                console.print(f"[red]Error polling status: {e}[/red]")
                return None

    console.print("[red]Polling timed out.[/red]")
    return None


# =============================================================================
# CLI Group
# =============================================================================

@click.group(name="codeshield-cli")
@click.option("--config", "-c", type=click.Path(), help="Path to config file")
@click.option("--api-url", "-a", help="API base URL (overrides config)")
@click.option("--verbose", "-v", is_flag=True, help="Enable verbose output")
@click.pass_context
def cli(ctx: click.Context, config: Optional[str], api_url: Optional[str], verbose: bool) -> None:
    """
    CodeShield AI - Command Line Interface for vulnerability scanning.

    Scan ZIP files and GitHub repositories for security vulnerabilities.
    Export results in SARIF, JUnit, JSON, or HTML formats.
    """
    ctx.ensure_object(dict)

    # Load config
    cfg = get_config()
    if config:
        try:
            with open(config, "r", encoding="utf-8") as f:
                cfg.update(yaml.safe_load(f) or {})
        except Exception as e:
            console.print(f"[yellow]Warning: Could not load config: {e}[/yellow]")

    ctx.obj["api_url"] = api_url or cfg.get("api_url", DEFAULT_API_URL)
    ctx.obj["config"] = cfg
    ctx.obj["verbose"] = verbose

    if verbose:
        console.print(f"[dim]API URL: {ctx.obj['api_url']}[/dim]")


# =============================================================================
# Scan Subgroup
# =============================================================================

@cli.group(name="scan")
@click.pass_context
def scan_group(ctx: click.Context) -> None:
    """Scan commands: zip, github, status, results, history, report."""
    pass


@scan_group.command(name="zip")
@click.argument("file", type=click.Path(exists=True, readable=True))
@click.option("--name", "-n", help="Scan name")
@click.option("--severity-filter", "-s", multiple=True, help="Severity levels to include (CRITICAL,HIGH,MEDIUM,LOW,INFO)")
@click.option("--tools", "-t", help="Comma-separated list of tools to run")
@click.option("--output-format", "-f", type=click.Choice(["json", "sarif", "junit", "html"]), default=None, help="Output format")
@click.option("--output-file", "-o", type=click.Path(), help="Write output to file")
@click.option("--wait/--no-wait", default=True, help="Wait for scan to complete")
@click.pass_context
def scan_zip(
    ctx: click.Context,
    file: str,
    name: Optional[str],
    severity_filter: tuple,
    tools: Optional[str],
    output_format: Optional[str],
    output_file: Optional[str],
    wait: bool,
) -> None:
    """Scan a ZIP file containing source code."""
    api_url = ctx.obj["api_url"]
    exit_code = EXIT_OK

    try:
        # Build config
        scan_config: Dict[str, Any] = {}
        if severity_filter:
            scan_config["severity_filters"] = list(severity_filter)
        if tools:
            scan_config["tools"] = [t.strip() for t in tools.split(",")]

        # Upload and start scan
        with console.status("[bold green]Uploading ZIP file..."):
            with open(file, "rb") as f:
                files = {"file": (os.path.basename(file), f, "application/zip")}
                data = {"name": name or os.path.basename(file)}
                if scan_config:
                    data["config"] = json.dumps(scan_config)

                resp = httpx.post(
                    f"{api_url}/api/scan/zip",
                    files=files,
                    data=data,
                    timeout=120,
                )
                resp.raise_for_status()

        result = resp.json()
        scan_id = result["scan_id"]
        console.print(f"[green]Scan started: {scan_id}[/green]")

        if not wait:
            return

        # Poll for completion
        final_status = poll_scan_status(scan_id, api_url)
        if not final_status:
            sys.exit(EXIT_ERROR)

        if final_status.get("status") == "failed":
            console.print(f"[red]Scan failed: {final_status.get('error', 'Unknown error')}[/red]")
            sys.exit(EXIT_ERROR)

        # Fetch results
        _fetch_and_display_results(ctx, scan_id, severity_filter, output_format, output_file)

    except httpx.HTTPStatusError as e:
        console.print(f"[red]API error: {e.response.status_code} - {e.response.text}[/red]")
        sys.exit(EXIT_ERROR)
    except httpx.RequestError as e:
        console.print(f"[red]Connection error: {e}[/red]")
        sys.exit(EXIT_ERROR)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(EXIT_ERROR)

    sys.exit(exit_code)


@scan_group.command(name="github")
@click.argument("url")
@click.option("--name", "-n", help="Scan name")
@click.option("--severity-filter", "-s", multiple=True, help="Severity levels to include")
@click.option("--tools", "-t", help="Comma-separated list of tools to run")
@click.option("--output-format", "-f", type=click.Choice(["json", "sarif", "junit", "html"]), default=None, help="Output format")
@click.option("--output-file", "-o", type=click.Path(), help="Write output to file")
@click.option("--wait/--no-wait", default=True, help="Wait for scan to complete")
@click.pass_context
def scan_github(
    ctx: click.Context,
    url: str,
    name: Optional[str],
    severity_filter: tuple,
    tools: Optional[str],
    output_format: Optional[str],
    output_file: Optional[str],
    wait: bool,
) -> None:
    """Scan a GitHub repository by URL."""
    api_url = ctx.obj["api_url"]

    try:
        # Build config
        scan_config: Dict[str, Any] = {}
        if severity_filter:
            scan_config["severity_filters"] = list(severity_filter)
        if tools:
            scan_config["tools"] = [t.strip() for t in tools.split(",")]

        payload: Dict[str, Any] = {
            "source_type": "github",
            "source_url": url,
            "name": name,
        }
        if scan_config:
            payload["config"] = scan_config

        with console.status("[bold green]Starting GitHub scan..."):
            resp = httpx.post(
                f"{api_url}/api/scan/github",
                json=payload,
                timeout=60,
            )
            resp.raise_for_status()

        result = resp.json()
        scan_id = result["scan_id"]
        console.print(f"[green]Scan started: {scan_id}[/green]")

        if not wait:
            return

        # Poll for completion
        final_status = poll_scan_status(scan_id, api_url)
        if not final_status:
            sys.exit(EXIT_ERROR)

        if final_status.get("status") == "failed":
            console.print(f"[red]Scan failed: {final_status.get('error', 'Unknown error')}[/red]")
            sys.exit(EXIT_ERROR)

        # Fetch results
        _fetch_and_display_results(ctx, scan_id, severity_filter, output_format, output_file)

    except httpx.HTTPStatusError as e:
        console.print(f"[red]API error: {e.response.status_code} - {e.response.text}[/red]")
        sys.exit(EXIT_ERROR)
    except httpx.RequestError as e:
        console.print(f"[red]Connection error: {e}[/red]")
        sys.exit(EXIT_ERROR)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(EXIT_ERROR)


@scan_group.command(name="status")
@click.argument("scan_id")
@click.pass_context
def scan_status(ctx: click.Context, scan_id: str) -> None:
    """Get the status of a scan."""
    api_url = ctx.obj["api_url"]

    try:
        resp = httpx.get(f"{api_url}/api/scan/{scan_id}/status", timeout=10)
        resp.raise_for_status()
        data = resp.json()

        status = data.get("status", "unknown")
        status_color = {
            "completed": "green",
            "running": "yellow",
            "failed": "red",
            "pending": "blue",
        }.get(status, "white")

        console.print(f"[bold]Scan ID:[/bold] {scan_id}")
        console.print(f"[bold]Status:[/bold]  [{status_color}]{status.upper()}[/{status_color}]")
        console.print(f"[bold]Progress:[/bold] {data.get('progress', 0)}%")
        console.print(f"[bold]Name:[/bold]    {data.get('name', 'N/A')}")

        if data.get("start_time"):
            console.print(f"[bold]Started:[/bold] {data['start_time']}")
        if data.get("duration"):
            console.print(f"[bold]Duration:[/bold] {data['duration']}s")
        if data.get("error"):
            console.print(f"[red]Error: {data['error']}[/red]")

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            console.print(f"[red]Scan {scan_id} not found[/red]")
        else:
            console.print(f"[red]API error: {e.response.status_code}[/red]")
        sys.exit(EXIT_ERROR)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(EXIT_ERROR)


@scan_group.command(name="results")
@click.argument("scan_id")
@click.option("--severity-filter", "-s", multiple=True, help="Filter by severity")
@click.option("--output-format", "-f", type=click.Choice(["json", "sarif", "junit", "html", "table"]), default="table", help="Output format")
@click.option("--output-file", "-o", type=click.Path(), help="Write output to file")
@click.option("--limit", "-l", type=int, default=100, help="Maximum results to show")
@click.pass_context
def scan_results(
    ctx: click.Context,
    scan_id: str,
    severity_filter: tuple,
    output_format: str,
    output_file: Optional[str],
    limit: int,
) -> None:
    """Get scan results with optional filtering and export."""
    _fetch_and_display_results(ctx, scan_id, severity_filter, output_format, output_file, limit)


@scan_group.command(name="history")
@click.option("--limit", "-l", type=int, default=50, help="Maximum number of scans")
@click.option("--offset", "-o", type=int, default=0, help="Skip N scans")
@click.option("--status", "-s", type=click.Choice(["pending", "running", "completed", "failed"]), help="Filter by status")
@click.pass_context
def scan_history(ctx: click.Context, limit: int, offset: int, status: Optional[str]) -> None:
    """List scan history."""
    api_url = ctx.obj["api_url"]

    try:
        params = {"limit": limit, "offset": offset}
        if status:
            params["status"] = status

        resp = httpx.get(f"{api_url}/api/history", params=params, timeout=10)
        resp.raise_for_status()
        data = resp.json()

        scans = data.get("scans", [])
        if not scans:
            console.print("[yellow]No scans found[/yellow]")
            return

        table = Table(title=f"Scan History ({len(scans)} scans)", show_lines=True)
        table.add_column("Scan ID", style="cyan", width=12)
        table.add_column("Name", width=30)
        table.add_column("Type", width=8)
        table.add_column("Status", width=12)
        table.add_column("Vulns", justify="right", width=6)
        table.add_column("Risk", justify="right", width=6)
        table.add_column("Duration", justify="right", width=8)
        table.add_column("Started", width=20)

        for scan in scans:
            status_val = scan.get("status", "unknown")
            status_color = {
                "completed": "green",
                "running": "yellow",
                "failed": "red",
                "pending": "blue",
            }.get(status_val, "white")

            risk = scan.get("risk_score", 0)
            risk_color = "green" if risk < 20 else "yellow" if risk < 60 else "red"

            table.add_row(
                scan.get("scan_id", "N/A"),
                scan.get("name", "N/A")[:28],
                scan.get("source_type", "N/A"),
                Text(status_val.upper(), style=status_color),
                str(scan.get("vulnerability_count", 0)),
                Text(str(risk), style=risk_color),
                f"{scan.get('stats', {}).get('total', 0)}s" if scan.get("stats") else "N/A",
                scan.get("start_time", "N/A")[:19] if scan.get("start_time") else "N/A",
            )

        console.print(table)

    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(EXIT_ERROR)


@scan_group.command(name="report")
@click.argument("scan_id")
@click.option("--format", "-f", type=click.Choice(["pdf", "html", "json", "sarif", "junit"]), default="html", help="Report format")
@click.option("--output-file", "-o", type=click.Path(), help="Output file path")
@click.pass_context
def scan_report(ctx: click.Context, scan_id: str, format: str, output_file: Optional[str]) -> None:
    """Generate a report for a scan."""
    api_url = ctx.obj["api_url"]

    try:
        if format == "pdf":
            resp = httpx.get(f"{api_url}/api/scan/{scan_id}/report/pdf", timeout=60)
            ext = "pdf"
        else:
            resp = httpx.get(
                f"{api_url}/api/export/{scan_id}?format={format}",
                timeout=60,
            )
            ext = format if format != "html" else "html"

        resp.raise_for_status()

        if not output_file:
            output_file = f"codeshield_report_{scan_id}.{ext}"

        with open(output_file, "wb") as f:
            f.write(resp.content)

        console.print(f"[green]Report saved: {output_file}[/green]")

    except httpx.HTTPStatusError as e:
        if e.response.status_code == 404:
            console.print(f"[red]Scan {scan_id} not found[/red]")
        else:
            console.print(f"[red]API error: {e.response.status_code} - {e.response.text[:200]}[/red]")
        sys.exit(EXIT_ERROR)
    except Exception as e:
        console.print(f"[red]Error: {e}[/red]")
        sys.exit(EXIT_ERROR)


# =============================================================================
# Helper Functions
# =============================================================================

def _fetch_and_display_results(
    ctx: click.Context,
    scan_id: str,
    severity_filter: tuple = (),
    output_format: Optional[str] = None,
    output_file: Optional[str] = None,
    limit: int = 100,
) -> int:
    """
    Fetch scan results and display/export them.

    Returns:
        Exit code (0 = no vulns, 1 = vulns found)
    """
    api_url = ctx.obj["api_url"]

    # Build query params
    params: Dict[str, Any] = {"limit": limit, "offset": 0}
    if severity_filter:
        params["severity"] = ",".join(severity_filter)

    # Get results
    resp = httpx.get(f"{api_url}/api/scan/{scan_id}/results", params=params, timeout=30)
    resp.raise_for_status()
    data = resp.json()

    vulnerabilities = data.get("vulnerabilities", [])
    stats = data.get("stats", {})
    risk_score = data.get("risk_score", 0)

    # Determine output format
    fmt = output_format or ctx.obj["config"].get("default_output_format", "table")

    if fmt == "table":
        console.print(f"\n[bold]Scan: {data.get('name', scan_id)}[/bold]")
        console.print(f"[bold]Status:[/bold] {data.get('status', 'N/A')}")
        console.print(f"[bold]Languages:[/bold] {', '.join(data.get('languages', []))}")
        console.print(f"[bold]Files:[/bold] {data.get('total_files', 0)}")
        console.print(f"[bold]Tools:[/bold] {', '.join(data.get('tools_used', []))}\n")

        print_summary(stats, risk_score, scan_id)

        if vulnerabilities:
            console.print(f"\n[bold]Vulnerabilities ({len(vulnerabilities)} shown):[/bold]\n")
            print_results_table(vulnerabilities)

            if ctx.obj.get("verbose"):
                for i, vuln in enumerate(vulnerabilities[:20], 1):
                    print_vulnerability(vuln, i)
        else:
            console.print("[green]No vulnerabilities found![/green]")

    elif fmt == "json":
        output = json.dumps(data, indent=2)
        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(output)
            console.print(f"[green]JSON report saved: {output_file}[/green]")
        else:
            console.print(output)

    elif fmt in ("sarif", "junit", "html"):
        # Fetch from export endpoint
        export_resp = httpx.get(
            f"{api_url}/api/export/{scan_id}?format={fmt}",
            timeout=60,
        )
        export_resp.raise_for_status()
        content = export_resp.content.decode("utf-8")

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                f.write(content)
            console.print(f"[green]{fmt.upper()} report saved: {output_file}[/green]")
        else:
            console.print(content)

    # Return exit code based on vulnerability count
    return EXIT_VULNS_FOUND if vulnerabilities else EXIT_OK


# =============================================================================
# Config Command
# =============================================================================

@cli.command(name="config")
@click.option("--show", is_flag=True, help="Show current configuration")
@click.option("--set-api-url", help="Set the API URL")
@click.option("--set-default-format", type=click.Choice(["json", "sarif", "junit", "html", "table"]), help="Set default output format")
def config_cmd(show: bool, set_api_url: Optional[str], set_default_format: Optional[str]) -> None:
    """Manage CLI configuration."""
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    cfg = get_config()

    if set_api_url:
        cfg["api_url"] = set_api_url
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            yaml.dump(cfg, f, default_flow_style=False)
        console.print(f"[green]API URL set to: {set_api_url}[/green]")

    if set_default_format:
        cfg["default_output_format"] = set_default_format
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            yaml.dump(cfg, f, default_flow_style=False)
        console.print(f"[green]Default format set to: {set_default_format}[/green]")

    if show or not (set_api_url or set_default_format):
        console.print("[bold]Current Configuration:[/bold]")
        for key, value in cfg.items():
            console.print(f"  {key}: {value}")
        console.print(f"\n[dim]Config file: {CONFIG_FILE}[/dim]")


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    cli()
