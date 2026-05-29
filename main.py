"""
CodeShield AI - FastAPI Backend Application

Main entry point for the code vulnerability scanning engine.
Provides REST API endpoints for:
- ZIP file upload scanning
- GitHub repository scanning
- Scan status and result retrieval
- PDF report generation
- Scan history management
- Tool configuration
"""

import asyncio
import io
import os
import re
import shutil
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, File, Form, HTTPException, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

from database.json_db import JSONDatabase
from database import get_database
from models.vulnerability import (
    ScanComparison,
    ScanConfig,
    ScanRequest,
    ScanResult,
    SeverityInfo,
    SeverityLevel,
    SourceType,
    ToolInfo,
    Vulnerability,
)
from exporters.html_exporter import HTMLExporter
from exporters.json_exporter import JSONExporter
from exporters.junit_exporter import JUnitExporter
from exporters.sarif_exporter import SARIFExporter
from ai_triage import AITriageEngine
from auto_fix import AutoFixEngine, FixStatus
from prioritizer import PrioritizationEngine
from report.pdf_generator import PDFGenerator
from risk_engine import RiskEngine

# Multi-Agent Swarm: Post-Processing Agents
from agents.triager import TriagerAgent
from agents.fix_agent import FixAgent
from agents.report_assembler import ReportAssembler, ReportFormat
from agents.chains import ChainsVisualizer
from agents.metrics import AgentMetricsCollector
from scanner.engine import ScanEngine
from scanner.github_handler import GitHubHandler
from scanner.tools.llm_security_scanner import LLMSecurityScanner
from scanner.tools.container_scanner import ContainerScanner
from scanner.tools.reachability_analyzer import SCAAnalyzer
from scanner.tools.dast_scanner import DASTScanner
from scanner.tools.taint_analyzer import TaintAnalyzer
from scanner.zip_handler import ZipHandler
from utils.config import get_settings
from utils.constants import (
    OWASP_TOP10,
    SEVERITY_LEVELS,
    SUPPORTED_LANGUAGES,
    TOOL_LANGUAGE_MAP,
)
from utils.helpers import get_temp_dir, sanitize_path
from utils.logger import get_logger

from cicd.github_action import GitHubActionGenerator
from cicd.gitlab_ci import GitLabCIGenerator
from cicd.jenkins_plugin import JenkinsPluginGenerator
from cicd.azure_devops import AzureDevOpsGenerator
from policy_engine import PolicyEngine, SecurityPolicy, PolicyScope, PolicyRule, PolicyRuleCondition, PolicyAction, PolicySeverity, PolicyEnforcementMode
from webhook_engine import WebhookEngine, WebhookEndpoint, WebhookEventType

# Enterprise Governance imports
from auth.models import (
    AuditAction, AuditResult, Organization, Permission,
    ResourceType, RoleName, User,
)
from auth.rbac import get_rbac_engine, PermissionDeniedError
from compliance.frameworks import (
    ComplianceFrameworkRegistry, ControlStatus, get_framework_registry,
)
from compliance.reports import ComplianceReportGenerator, get_report_generator
from compliance.sla_tracker import SLATracker, get_sla_tracker
from analytics.metrics import MetricsEngine
from analytics.dashboard import DashboardDataProvider
from integrations.sso import SSOIntegrationEngine, get_sso_engine
from integrations.siem import SIEMIntegrationEngine, get_siem_engine
from integrations.ticketing import TicketingIntegrationEngine, get_ticketing_engine
from integrations.notifications import NotificationEngine, get_notification_engine

# Multi-Agent Orchestration imports
from agents.orchestrator import HALOrchestrator, get_orchestrator
from agents.bus import AgentCommunicationBus, AgentMessage, MessageType, Priority, get_message_bus
from agents.registry import AgentRegistry, AgentCapabilities, AgentStatus, get_registry
from agents.health import AgentHealthMonitor, get_health_monitor
from agents.crew_definitions import get_all_agent_ids, get_scanning_agent_ids, get_agent_info
from agents.workflows import list_workflows, get_workflow

logger = get_logger(__name__)

# Initialize multi-agent orchestration components
hal_orchestrator = get_orchestrator()
agent_bus = get_message_bus()
agent_registry = get_registry()
agent_health_monitor = get_health_monitor()

# Initialize FastAPI app
settings = get_settings()
app = FastAPI(
    title="CodeShield AI API",
    description="Automated code vulnerability scanning engine integrating multiple open-source SAST tools",
    version=settings.app_version,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Optional rate limiting (no-op unless RATE_LIMIT_PER_MINUTE > 0)
try:
    from auth.api_key import RateLimitMiddleware

    app.add_middleware(RateLimitMiddleware)
except Exception as _rl_exc:  # pragma: no cover - defensive
    import logging as _logging

    _logging.getLogger(__name__).warning("Rate limiter not mounted: %s", _rl_exc)

# Serve static files and main dashboard route
app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def read_index():
    """Serve the main dashboard UI."""
    return FileResponse("static/index.html")

# Initialize components
db = get_database()
scan_engine = ScanEngine()
zip_handler = ZipHandler()
github_handler = GitHubHandler()
pdf_generator = PDFGenerator()

# Active scans tracking
active_scans: Dict[str, Any] = {}

# Webhook configurations storage
webhook_configs: Dict[str, Dict[str, Any]] = {}

# Initialize exporters
sarif_exporter = SARIFExporter()
json_exporter = JSONExporter()
junit_exporter = JUnitExporter()
html_exporter = HTMLExporter()
risk_engine = RiskEngine()

# Initialize AI engines
ai_triage_engine = AITriageEngine()
auto_fix_engine = AutoFixEngine()
prioritization_engine = PrioritizationEngine()
llm_security_scanner = LLMSecurityScanner()

# Initialize Platform Expansion scanners
container_scanner = ContainerScanner()
sca_analyzer = SCAAnalyzer()
dast_scanner = DASTScanner()
taint_analyzer = TaintAnalyzer()

# Initialize Multi-Agent Swarm post-processing agents
triager_agent = TriagerAgent(ai_triage_engine=ai_triage_engine)
fix_agent = FixAgent(auto_fix_engine=auto_fix_engine, ai_triage_engine=ai_triage_engine)
report_assembler = ReportAssembler()
chains_visualizer = ChainsVisualizer()
agent_metrics_collector = AgentMetricsCollector()

# Initialize DevSecOps engines
github_action_generator = GitHubActionGenerator(api_base_url=settings.api_url or "https://api.codeshield.ai")
gitlab_ci_generator = GitLabCIGenerator(api_base_url=settings.api_url or "https://api.codeshield.ai")
jenkins_plugin_generator = JenkinsPluginGenerator(api_base_url=settings.api_url or "https://api.codeshield.ai")
azure_devops_generator = AzureDevOpsGenerator(api_base_url=settings.api_url or "https://api.codeshield.ai")
policy_engine = PolicyEngine()
webhook_engine = WebhookEngine()

# Initialize Enterprise Governance engines
rbac_engine = get_rbac_engine()
framework_registry = get_framework_registry()
report_generator = get_report_generator()
sla_tracker = get_sla_tracker()
metrics_engine = MetricsEngine()
dashboard_provider = DashboardDataProvider(metrics_engine)
sso_engine = get_sso_engine()
siem_engine = get_siem_engine()
ticketing_engine = get_ticketing_engine()
notification_engine = get_notification_engine()


# =============================================================================
# Health & Info Endpoints
# =============================================================================

@app.get("/dashboard", response_class=HTMLResponse, include_in_schema=False)
async def dashboard_page() -> HTMLResponse:
    """Server-rendered scan history & stats dashboard."""
    try:
        from exporters.dashboard import DashboardRenderer
        stats = await db.get_stats()
        scans = await db.list_scans(limit=50)
        return HTMLResponse(DashboardRenderer().render(stats, scans))
    except Exception as e:  # pragma: no cover - defensive
        logger.error("Dashboard render failed: %s", e)
        return HTMLResponse("<h1>Dashboard unavailable</h1>", status_code=500)


@app.get("/api/health")
async def health_check() -> Dict[str, Any]:
    """
    Health check endpoint.

    Returns:
        Service status and version information
    """
    return {
        "status": "healthy",
        "service": "CodeShield AI",
        "version": settings.app_version,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


@app.get("/api/tools")
async def list_tools() -> List[ToolInfo]:
    """
    List available scanning tools.

    Returns:
        List of available scanning tools with descriptions
    """
    tools = [
        ToolInfo(
            name="semgrep",
            description="Multi-language SAST scanner with security-focused rulesets. Supports Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, and more.",
            languages=["python", "javascript", "typescript", "java", "go", "ruby", "php", "csharp", "swift", "kotlin", "rust"],
            categories=["SAST", "Security"],
            install_command="pip install semgrep",
            website="https://semgrep.dev",
        ),
        ToolInfo(
            name="eslint",
            description="JavaScript/TypeScript/React/React Native linter and security analyzer.",
            languages=["javascript", "typescript"],
            categories=["Linter", "Security"],
            install_command="npm install -g eslint",
            website="https://eslint.org",
        ),
        ToolInfo(
            name="pylint",
            description="Python code quality analyzer detecting security-adjacent issues.",
            languages=["python"],
            categories=["Linter", "Quality"],
            install_command="pip install pylint",
            website="https://pylint.pycqa.org",
        ),
        ToolInfo(
            name="bandit",
            description="Python-specific security vulnerability scanner from OpenStack.",
            languages=["python"],
            categories=["Security", "SAST"],
            install_command="pip install bandit",
            website="https://bandit.readthedocs.io",
        ),
        ToolInfo(
            name="pmd",
            description="Java static code analyzer with security rulesets.",
            languages=["java"],
            categories=["SAST", "Security"],
            install_command="Download from https://pmd.github.io",
            website="https://pmd.github.io",
        ),
        ToolInfo(
            name="gitleaks",
            description="Detects hardcoded secrets, API keys, passwords, and tokens.",
            languages=["*"],
            categories=["Secret Detection"],
            install_command="https://github.com/gitleaks/gitleaks",
            website="https://github.com/gitleaks/gitleaks",
        ),
        ToolInfo(
            name="dependency-check",
            description="OWASP Dependency-Check scans for known vulnerabilities in dependencies.",
            languages=["*"],
            categories=["SCA", "Dependencies"],
            install_command="https://owasp.org/www-project-dependency-check/",
            website="https://owasp.org/www-project-dependency-check/",
        ),
        ToolInfo(
            name="custom_ai",
            description="CodeShield AI's built-in pattern scanner. Detects secrets, injections, XSS, path traversal, weak crypto, and more using regex patterns and AST analysis. No external dependencies required.",
            languages=["*"],
            categories=["SAST", "Secret Detection", "Pattern Analysis"],
            install_command="Built-in - no installation required",
            website="https://codeshield.ai",
        ),
        ToolInfo(
            name="container_scanner",
            description="Container and IaC security scanner. Detects Dockerfile misconfigurations, Kubernetes security issues, Terraform misconfigurations, and Helm chart security problems. Integrates with Trivy for deep image scanning.",
            languages=["dockerfile", "yaml", "terraform", "helm"],
            categories=["Container Security", "IaC Security"],
            install_command="Built-in - no installation required",
            website="https://codeshield.ai",
        ),
        ToolInfo(
            name="dast_scanner",
            description="Dynamic Application Security Testing scanner. Checks security headers, SSL/TLS configuration, CORS policies, and information disclosure. Integrates with OWASP ZAP for advanced scanning.",
            languages=["*"],
            categories=["DAST", "Security Headers", "SSL/TLS"],
            install_command="Built-in - no installation required",
            website="https://codeshield.ai",
        ),
        ToolInfo(
            name="taint_analyzer",
            description="Advanced taint analysis engine using Python AST. Tracks data flow from sources (user input) to sinks (dangerous operations) to detect SQL injection, XSS, command injection, path traversal, and SSRF.",
            languages=["python"],
            categories=["SAST", "Taint Analysis", "Data Flow"],
            install_command="Built-in - no installation required",
            website="https://codeshield.ai",
        ),
        ToolInfo(
            name="sca_analyzer",
            description="Software Composition Analysis with reachability scoring. Builds dependency graphs from lock files, analyzes code imports, and determines actual vulnerability reachability. Generates SBOMs in SPDX and CycloneDX formats.",
            languages=["python", "javascript", "go", "java"],
            categories=["SCA", "SBOM", "Dependency Analysis"],
            install_command="Built-in - no installation required",
            website="https://codeshield.ai",
        ),
    ]
    return tools


@app.get("/api/severity-levels")
async def list_severity_levels() -> List[SeverityInfo]:
    """
    List severity levels with descriptions.

    Returns:
        List of severity level definitions
    """
    return [
        SeverityInfo(
            level="CRITICAL",
            description="Immediate action required. Critical vulnerabilities that can lead to system compromise.",
            color="#DC2626",
            icon="alert-circle",
        ),
        SeverityInfo(
            level="HIGH",
            description="Address as soon as possible. Significant security risks.",
            color="#EA580C",
            icon="alert-triangle",
        ),
        SeverityInfo(
            level="MEDIUM",
            description="Address in the next development cycle. Moderate security concerns.",
            color="#D97706",
            icon="alert-octagon",
        ),
        SeverityInfo(
            level="LOW",
            description="Address when convenient. Minor security improvements.",
            color="#65A30D",
            icon="info",
        ),
        SeverityInfo(
            level="INFO",
            description="Informational only. Best practice recommendations.",
            color="#2563EB",
            icon="info",
        ),
    ]


# =============================================================================
# Scan Endpoints
# =============================================================================

@app.post("/api/scan/zip")
async def scan_zip(
    file: UploadFile = File(..., description="ZIP file containing source code"),
    name: Optional[str] = Form(None, description="Optional scan name"),
    config: Optional[str] = Form(None, description="JSON scan configuration"),
) -> Dict[str, Any]:
    """
    Upload and scan a ZIP file containing source code.

    Args:
        file: ZIP file to scan
        name: Optional scan name
        config: Optional JSON configuration string

    Returns:
        Scan ID and initial status
    """
    import json

    # Validate file type
    if not file.filename or not file.filename.endswith(".zip"):
        raise HTTPException(status_code=400, detail="File must be a ZIP archive")

    # Parse config if provided
    scan_config = ScanConfig()
    if config:
        try:
            config_dict = json.loads(config)
            scan_config = ScanConfig(**config_dict)
        except (json.JSONDecodeError, Exception) as e:
            logger.warning("Invalid config provided: %s", e)

    # Validate scan_id format and regenerate if needed (collision protection)
    max_attempts = 5
    for _ in range(max_attempts):
        scan_id = str(uuid.uuid4())[:8]
        if not await db.scan_exists(scan_id):
            break

    # Create a persistent extraction directory (cleaned up by scan engine after completion)
    extract_dir = settings.temp_dir / f"extract_{scan_id}"
    extract_dir.mkdir(parents=True, exist_ok=True)

    zip_path = str(extract_dir / f"upload_{scan_id}.zip")

    try:
        with open(zip_path, "wb") as f:
            content = await file.read()
            if len(content) > settings.max_upload_size_mb * 1024 * 1024:
                shutil.rmtree(extract_dir, ignore_errors=True)
                raise HTTPException(
                    status_code=413,
                    detail=f"File too large. Max size: {settings.max_upload_size_mb}MB",
                )
            f.write(content)
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to save uploaded file: %s", e)
        raise HTTPException(status_code=500, detail="Failed to process upload")

    # Validate ZIP
    is_valid, error = zip_handler.validate_zip(zip_path)
    if not is_valid:
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail=f"Invalid ZIP file: {error}")

    # Extract ZIP
    try:
        source_path, file_count, _ = zip_handler.process_upload(zip_path, scan_id)
    except Exception as e:
        logger.error("Failed to extract ZIP: %s", e)
        shutil.rmtree(extract_dir, ignore_errors=True)
        raise HTTPException(status_code=400, detail=f"Failed to extract ZIP: {str(e)}")

    # Start scan
    scan_name = name or (file.filename.replace(".zip", "") if file.filename else f"scan_{scan_id}")

    # Create initial scan record
    result = ScanResult(
        scan_id=scan_id,
        name=scan_name,
        source_type="zip",
        source_path=source_path,
        status="running",
        progress=0,
    )
    await db.save_scan(result)

    # Run scan in background with exception tracking
    task = asyncio.create_task(
        _run_scan_with_cleanup(
            scan_engine=scan_engine,
            scan_id=scan_id,
            source_path=source_path,
            source_type="zip",
            name=scan_name,
            config=scan_config,
            db=db,
        )
    )
    active_scans[scan_id] = task

    def _on_task_done(t: asyncio.Task) -> None:
        active_scans.pop(scan_id, None)
        exc = t.exception()
        if exc:
            logger.error("Scan %s failed with exception: %s", scan_id, exc, exc_info=True)

    task.add_done_callback(_on_task_done)

    logger.info("Started ZIP scan %s for %s", scan_id, file.filename)

    return {
        "scan_id": scan_id,
        "status": "running",
        "message": "Scan started. Poll /api/scan/{scan_id}/status for progress.",
    }


@app.post("/api/scan/github")
async def scan_github(request: ScanRequest) -> Dict[str, Any]:
    """
    Scan a GitHub repository by URL.

    Args:
        request: Scan request with GitHub URL and optional config

    Returns:
        Scan ID and initial status
    """
    if request.source_type != SourceType.GITHUB:
        raise HTTPException(status_code=400, detail="source_type must be 'github'")

    if not request.source_url:
        raise HTTPException(status_code=400, detail="GitHub URL is required")

    # Validate GitHub URL
    is_valid, error = github_handler.validate_url(request.source_url)
    if not is_valid:
        raise HTTPException(status_code=400, detail=f"Invalid GitHub URL: {error}")

    # Generate scan ID
    scan_id = str(uuid.uuid4())[:8]

    # Clone repository
    try:
        source_path = await github_handler.clone_repository(
            request.source_url, scan_id
        )
    except Exception as e:
        logger.error("Failed to clone repository: %s", e)
        raise HTTPException(status_code=400, detail=f"Failed to clone repository: {str(e)}")

    # Get repo name for scan name
    owner, repo = github_handler.extract_repo_info(request.source_url)
    scan_name = request.name or f"{owner}/{repo}"

    # Create initial scan record
    result = ScanResult(
        scan_id=scan_id,
        name=scan_name,
        source_type="github",
        source_path=source_path,
        source_url=request.source_url,
        status="running",
        progress=0,
    )
    await db.save_scan(result)

    # Run scan in background with exception tracking
    task = asyncio.create_task(
        _run_scan_with_cleanup(
            scan_engine=scan_engine,
            scan_id=scan_id,
            source_path=source_path,
            source_type="github",
            name=scan_name,
            config=request.config,
            db=db,
            source_url=request.source_url,
        )
    )
    active_scans[scan_id] = task

    def _on_task_done(t: asyncio.Task) -> None:
        active_scans.pop(scan_id, None)
        exc = t.exception()
        if exc:
            logger.error("GitHub scan %s failed with exception: %s", scan_id, exc, exc_info=True)

    task.add_done_callback(_on_task_done)

    logger.info("Started GitHub scan %s for %s", scan_id, request.source_url)

    return {
        "scan_id": scan_id,
        "status": "running",
        "message": "Scan started. Poll /api/scan/{scan_id}/status for progress.",
    }


async def _run_scan_with_cleanup(
    scan_engine: ScanEngine,
    scan_id: str,
    source_path: str,
    source_type: str,
    name: str,
    config: Any,
    db: JSONDatabase,
    source_url: Optional[str] = None,
) -> None:
    """Run a scan and clean up temp files afterward."""
    try:
        await scan_engine.run_scan(
            scan_id=scan_id,
            source_path=source_path,
            source_type=source_type,
            name=name,
            config=config,
            db=db,
            source_url=source_url,
        )
    except Exception as e:
        # Clean up extracted source files on failure
        if source_path and os.path.exists(source_path):
            try:
                shutil.rmtree(source_path, ignore_errors=True)
                logger.debug("Cleaned up source path for failed scan %s: %s", scan_id, source_path)
            except Exception as ex:
                logger.warning("Failed to cleanup source path for failed scan %s: %s", scan_id, ex)
        raise e


def _validate_scan_id(scan_id: str) -> None:
    """Validate scan_id format to prevent path traversal."""
    if not scan_id or not re.match(r"^[a-f0-9]{8}$", scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")


@app.get("/api/scan/{scan_id}/status")
async def get_scan_status(scan_id: str) -> Dict[str, Any]:
    """
    Get the current status of a scan.

    Args:
        scan_id: The scan ID

    Returns:
        Scan status and progress
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return {
        "scan_id": scan.scan_id,
        "status": scan.status,
        "progress": scan.progress,
        "name": scan.name,
        "start_time": scan.start_time.isoformat() if scan.start_time else None,
        "end_time": scan.end_time.isoformat() if scan.end_time else None,
        "duration": scan.scan_duration,
        "error": scan.error_message,
    }


@app.websocket("/api/ws/scan/{scan_id}")
async def websocket_endpoint(websocket: WebSocket, scan_id: str):
    from fastapi import WebSocket, WebSocketDisconnect
    from utils.ws_manager import ws_manager
    try:
        _validate_scan_id(scan_id)
    except Exception:
        await websocket.close(code=4000)
        return

    await ws_manager.connect(scan_id, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            logger.debug("Received WebSocket message from client on scan %s: %s", scan_id, data)
    except WebSocketDisconnect:
        ws_manager.disconnect(scan_id, websocket)
    except Exception as e:
        logger.error("WebSocket error for scan %s: %s", scan_id, e)
        ws_manager.disconnect(scan_id, websocket)


@app.get("/api/scan/{scan_id}/results")
async def get_scan_results(
    scan_id: str,
    severity: Optional[str] = Query(None, description="Filter by severity"),
    category: Optional[str] = Query(None, description="Filter by category"),
    tool: Optional[str] = Query(None, description="Filter by tool source"),
    limit: int = Query(100, ge=1, le=1000, description="Max results"),
    offset: int = Query(0, ge=0, description="Skip N results"),
) -> Dict[str, Any]:
    """
    Get scan results with optional filtering.

    Args:
        scan_id: The scan ID
        severity: Filter by severity level
        category: Filter by vulnerability category
        tool: Filter by tool source
        limit: Maximum number of results
        offset: Number of results to skip

    Returns:
        Scan results with vulnerabilities
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Apply filters
    vulnerabilities = scan.vulnerabilities

    if severity:
        vulnerabilities = [v for v in vulnerabilities if v.severity.upper() == severity.upper()]

    if category:
        vulnerabilities = [v for v in vulnerabilities if category.lower() in v.category.lower()]

    if tool:
        vulnerabilities = [v for v in vulnerabilities if v.tool_source.lower() == tool.lower()]

    total_filtered = len(vulnerabilities)
    vulnerabilities = vulnerabilities[offset : offset + limit]

    return {
        "scan_id": scan.scan_id,
        "name": scan.name,
        "status": scan.status,
        "source_type": scan.source_type,
        "languages": scan.languages,
        "total_files": scan.total_files,
        "total_lines": scan.total_lines,
        "scan_duration": scan.scan_duration,
        "tools_used": scan.tools_used,
        "risk_score": scan.risk_score,
        "stats": scan.stats,
        "vulnerabilities": [v.model_dump() for v in vulnerabilities],
        "pagination": {
            "total": total_filtered,
            "limit": limit,
            "offset": offset,
        },
    }


@app.get("/api/scan/{scan_id}/report/pdf")
async def get_pdf_report(scan_id: str) -> StreamingResponse:
    """
    Download a PDF report for a scan.

    Args:
        scan_id: The scan ID

    Returns:
        PDF file as streaming response
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in ("completed", "failed"):
        raise HTTPException(status_code=400, detail="Scan is not yet complete")

    try:
        pdf_content = pdf_generator.generate(scan)

        return StreamingResponse(
            io.BytesIO(pdf_content),
            media_type="application/pdf",
            headers={
                "Content-Disposition": f'attachment; filename="codeshield_report_{scan_id}.pdf"'
            },
        )
    except Exception as e:
        logger.error("Failed to generate PDF for scan %s: %s", scan_id, e)
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF: {str(e)}")


@app.get("/api/scan/{scan_id}/download")
async def download_patched_code(scan_id: str):
    """
    Apply auto-fixes to all vulnerabilities and download the patched code as a ZIP file.

    Args:
        scan_id: The scan ID

    Returns:
        ZIP file containing patched code
    """
    import io
    import shutil
    import zipfile
    from pathlib import Path
    from fastapi.responses import FileResponse
    from scanner.zip_handler import ZipHandler

    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in ("completed", "failed"):
        raise HTTPException(status_code=400, detail="Scan is not yet complete")

    filename = f"patched_{scan.name.replace('/', '_').replace(' ', '_')}_{scan_id}.zip"
    cached_zip_path = settings.temp_dir / f"patched_cache_{scan_id}.zip"

    # Check cache first
    if cached_zip_path.exists():
        logger.info("Serving cached patched ZIP for scan %s", scan_id)
        return FileResponse(
            path=str(cached_zip_path),
            media_type="application/zip",
            filename=filename
        )

    source_dir_to_use = None
    temp_dir = None
    intermediate_dir = None

    if scan.source_type == "github":
        if not scan.source_url:
            raise HTTPException(
                status_code=400,
                detail="GitHub URL is not available in the scan details"
            )
        from scanner.github_handler import GitHubHandler
        gh = GitHubHandler()
        try:
            source_dir_to_use_str = await gh.clone_repository(scan.source_url, f"patched_download_{scan_id}")
            source_dir_to_use = Path(source_dir_to_use_str)
            temp_dir = source_dir_to_use
        except Exception as e:
            logger.error("Failed to re-clone repository for scan %s: %s", scan_id, e)
            raise HTTPException(status_code=500, detail=f"Failed to clone GitHub repository: {str(e)}")
    else:
        # Locate the original ZIP file
        zip_path = settings.temp_dir / f"extract_{scan_id}" / f"upload_{scan_id}.zip"
        if not zip_path.exists():
            # Fallback to check if the extracted dir exists (in case it wasn't cleaned up)
            extracted_dir = settings.temp_dir / f"zip_{scan_id}"
            if not extracted_dir.exists():
                raise HTTPException(
                    status_code=400,
                    detail="Original ZIP file or scanned source directory not found on server"
                )
            source_dir_to_use = extracted_dir
        else:
            # Re-extract the ZIP to a clean temporary directory for patching
            temp_dir = settings.temp_dir / f"patched_download_{scan_id}"
            temp_dir.mkdir(parents=True, exist_ok=True)
            try:
                zh = ZipHandler()
                source_dir_to_use_str, _, _ = zh.process_upload(str(zip_path), f"patched_download_{scan_id}")
                source_dir_to_use = Path(source_dir_to_use_str)
                intermediate_dir = settings.temp_dir / f"zip_patched_download_{scan_id}"
            except Exception as e:
                logger.error("Failed to re-extract ZIP for scan %s: %s", scan_id, e)
                shutil.rmtree(temp_dir, ignore_errors=True)
                raise HTTPException(status_code=500, detail=f"Failed to process source ZIP: {str(e)}")

    # Apply fixes to the extracted files in the temp directory
    try:
        for vuln in scan.vulnerabilities:
            try:
                # Generate fix (with fallback to LLM, or deterministic if LLM not configured)
                fix_result = await auto_fix_engine.generate_fix(vuln, source_path=str(source_dir_to_use))
                if fix_result and fix_result.fixed_code:
                    await auto_fix_engine.apply_fix_to_file(
                        vuln, fix_result, str(source_dir_to_use)
                    )
            except Exception as e:
                # Log error but continue applying other fixes
                logger.warning("Failed to generate/apply fix for vuln %s in download: %s", vuln.id, e)

        # Now, zip the patched directory
        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, _, files in os.walk(source_dir_to_use):
                for file in files:
                    file_path = os.path.join(root, file)
                    arcname = os.path.relpath(file_path, source_dir_to_use)
                    zf.write(file_path, arcname)

        # Write to cache file
        try:
            with open(cached_zip_path, "wb") as f:
                f.write(memory_file.getvalue())
            logger.info("Cached patched ZIP for scan %s to %s", scan_id, cached_zip_path)
        except Exception as e:
            logger.warning("Failed to cache patched ZIP for scan %s: %s", scan_id, e)

        memory_file.seek(0)
        return StreamingResponse(
            memory_file,
            media_type="application/zip",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            },
        )
    finally:
        # Clean up the re-extracted/patched temp directories
        if temp_dir and temp_dir.exists():
            shutil.rmtree(temp_dir, ignore_errors=True)
        if intermediate_dir and intermediate_dir.exists():
            shutil.rmtree(intermediate_dir, ignore_errors=True)


# =============================================================================
# History Endpoints
# =============================================================================

@app.get("/api/history")
async def list_scan_history(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    status: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """
    List scan history.

    Args:
        limit: Maximum number of results
        offset: Number of results to skip
        status: Filter by status

    Returns:
        List of scan summaries
    """
    scans = await db.list_scans(limit=limit, offset=offset, status=status)

    results = []
    for scan in scans:
        results.append({
            "scan_id": scan.scan_id,
            "name": scan.name,
            "source_type": scan.source_type,
            "status": scan.status,
            "progress": scan.progress,
            "start_time": scan.start_time.isoformat() if scan.start_time else None,
            "end_time": scan.end_time.isoformat() if scan.end_time else None,
            "languages": scan.languages,
            "total_files": scan.total_files,
            "stats": scan.stats,
            "risk_score": scan.risk_score,
            "vulnerability_count": len(scan.vulnerabilities),
        })

    return {
        "scans": results,
        "total": len(results),
    }


@app.delete("/api/history/{scan_id}")
async def delete_scan(scan_id: str) -> Dict[str, Any]:
    """
    Delete a scan and its results.

    Args:
        scan_id: The scan ID to delete

    Returns:
        Deletion confirmation
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Delete from database
    deleted = await db.delete_scan(scan_id)

    # Clean up temp files
    if scan.source_path and os.path.exists(scan.source_path):
        try:
            shutil.rmtree(scan.source_path, ignore_errors=True)
        except Exception as e:
            logger.warning("Failed to cleanup temp files for scan %s: %s", scan_id, e)

    if not deleted:
        raise HTTPException(status_code=500, detail="Failed to delete scan")

    return {
        "scan_id": scan_id,
        "deleted": True,
        "message": "Scan deleted successfully",
    }


@app.post("/api/history/compare")
async def compare_scans(request: ScanComparison) -> Dict[str, Any]:
    """
    Compare multiple scans.

    Args:
        request: Comparison request with list of scan IDs

    Returns:
        Comparison analysis
    """
    if len(request.scan_ids) < 2:
        raise HTTPException(status_code=400, detail="At least 2 scan IDs required for comparison")

    scans: List[ScanResult] = []
    for scan_id in request.scan_ids:
        scan = await db.get_scan(scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found")
        scans.append(scan)

    # Build comparison
    comparison = {
        "scans": [],
        "differences": [],
        "summary": {},
    }

    for scan in scans:
        comparison["scans"].append({
            "scan_id": scan.scan_id,
            "name": scan.name,
            "status": scan.status,
            "risk_score": scan.risk_score,
            "vulnerability_count": len(scan.vulnerabilities),
            "stats": scan.stats,
        })

    # Find differences
    if len(scans) == 2:
        vulns_1 = {(v.file_path, v.line_number, v.category) for v in scans[0].vulnerabilities}
        vulns_2 = {(v.file_path, v.line_number, v.category) for v in scans[1].vulnerabilities}

        new_in_second = vulns_2 - vulns_1
        fixed_in_second = vulns_1 - vulns_2

        comparison["differences"] = {
            "new_vulnerabilities": len(new_in_second),
            "fixed_vulnerabilities": len(fixed_in_second),
            "unchanged": len(vulns_1 & vulns_2),
        }

        comparison["summary"] = {
            "risk_score_change": scans[1].risk_score - scans[0].risk_score,
            "vulnerability_change": len(scans[1].vulnerabilities) - len(scans[0].vulnerabilities),
        }

    return comparison


# =============================================================================
# Additional Endpoints
# =============================================================================

@app.get("/api/scan/{scan_id}")
async def get_scan_summary(scan_id: str) -> Dict[str, Any]:
    """
    Get full scan summary.

    Args:
        scan_id: The scan ID

    Returns:
        Complete scan information
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    return scan.model_dump()


@app.get("/api/stats")
async def get_global_stats() -> Dict[str, Any]:
    """
    Get global scanning statistics.

    Returns:
        Aggregated statistics across all scans
    """
    stats = await db.get_stats()
    return {
        "total_scans": stats.get("total_scans", 0),
        "by_status": stats.get("by_status", {}),
        "total_vulnerabilities": stats.get("total_vulnerabilities", 0),
        "by_severity": stats.get("by_severity", {}),
        "supported_languages": list(SUPPORTED_LANGUAGES.keys()),
    }


@app.get("/api/owasp-top10")
async def get_owasp_top10() -> Dict[str, Any]:
    """
    Get OWASP Top 10 information.

    Returns:
        OWASP Top 10 categories with descriptions
    """
    return OWASP_TOP10


# =============================================================================
# Export Endpoints
# =============================================================================

@app.get("/api/export/{scan_id}")
async def export_scan_results(
    scan_id: str,
    format: str = Query(..., pattern="^(sarif|json|junit|html)$"),
) -> StreamingResponse:
    """
    Export scan results in the specified format.

    Args:
        scan_id: The scan ID
        format: Export format (sarif, json, junit, html)

    Returns:
        Streaming response with the exported file
    """
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in ("completed", "failed"):
        raise HTTPException(status_code=400, detail="Scan is not yet complete")

    content_type_map = {
        "sarif": ("application/sarif+json", f"codeshield_{scan_id}.sarif"),
        "json": ("application/json", f"codeshield_{scan_id}.json"),
        "junit": ("application/xml", f"codeshield_{scan_id}.xml"),
        "html": ("text/html", f"codeshield_{scan_id}.html"),
    }

    try:
        if format == "sarif":
            content = sarif_exporter.export(scan)
        elif format == "json":
            content = json_exporter.export(scan)
        elif format == "junit":
            content = junit_exporter.export(scan)
        elif format == "html":
            content = html_exporter.export(scan)
        else:
            raise HTTPException(status_code=400, detail=f"Unsupported format: {format}")

        mime_type, filename = content_type_map[format]

        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type=mime_type,
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )
    except Exception as e:
        logger.error("Failed to generate %s export for scan %s: %s", format, scan_id, e)
        raise HTTPException(status_code=500, detail=f"Failed to generate export: {str(e)}")


# =============================================================================
# Risk Endpoints
# =============================================================================

@app.get("/api/risk/{scan_id}")
async def get_risk_score(scan_id: str) -> Dict[str, Any]:
    """
    Get composite risk score for a scan.

    Args:
        scan_id: The scan ID

    Returns:
        Risk profile with composite score, factors, and recommendations
    """
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in ("completed", "failed"):
        raise HTTPException(status_code=400, detail="Scan is not yet complete")

    try:
        risk_profile = await risk_engine.calculate_scan_risk(scan)
        return risk_engine.to_dict(risk_profile)
    except Exception as e:
        logger.error("Failed to calculate risk for scan %s: %s", scan_id, e)
        raise HTTPException(status_code=500, detail=f"Failed to calculate risk: {str(e)}")


# =============================================================================
# Secret Endpoints
# =============================================================================

@app.get("/api/secrets")
async def list_detected_secrets(
    scan_id: str = Query(..., description="Scan ID to list secrets from"),
    severity: Optional[str] = Query(None, description="Filter by severity"),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """
    List all detected secrets in a scan.

    Args:
        scan_id: The scan ID
        severity: Filter by severity
        limit: Maximum number of results
        offset: Number of results to skip

    Returns:
        List of detected secrets
    """
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Filter to secret-related vulnerabilities
    secret_keywords = [
        "secret", "token", "password", "api key", "private key", "credential",
        "aws", "gcp", "azure", "jwt", "oauth", "bearer", "connection string",
        "mongodb", "redis", "postgres", "mysql", "seed phrase", "mnemonic",
        "webhook", "bot token", "auth",
    ]

    secrets = []
    for vuln in scan.vulnerabilities:
        if any(kw.lower() in vuln.category.lower() for kw in secret_keywords):
            if severity and vuln.severity.upper() != severity.upper():
                continue
            secrets.append(vuln.model_dump())

    total = len(secrets)
    secrets = secrets[offset : offset + limit]

    return {
        "scan_id": scan_id,
        "total_secrets": total,
        "limit": limit,
        "offset": offset,
        "secrets": secrets,
    }


# =============================================================================
# Dependency Endpoints
# =============================================================================

@app.get("/api/dependencies/{scan_id}")
async def get_dependency_report(scan_id: str) -> Dict[str, Any]:
    """
    Get dependency vulnerability report for a scan.

    Args:
        scan_id: The scan ID

    Returns:
        Dependency vulnerability report
    """
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    dep_vulns = [
        v.model_dump() for v in scan.vulnerabilities
        if v.tool_source == "osv_scanner" or "dependency" in v.category.lower()
        or "vulnerable" in v.category.lower()
    ]

    return {
        "scan_id": scan_id,
        "total_dependencies_affected": len(dep_vulns),
        "dependencies": dep_vulns,
    }


# =============================================================================
# Webhook Endpoints
# =============================================================================

@app.post("/api/webhook")
async def configure_webhook(config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Configure a webhook notification.

    Args:
        config: Webhook configuration with url, events, and optional secret

    Returns:
        Configuration confirmation
    """
    if "url" not in config:
        raise HTTPException(status_code=400, detail="Webhook URL is required")

    webhook_id = str(uuid.uuid4())[:8]
    webhook_configs[webhook_id] = {
        "id": webhook_id,
        "url": config["url"],
        "events": config.get("events", ["scan.completed"]),
        "secret": config.get("secret"),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "active": True,
    }

    logger.info("Webhook configured: %s -> %s", webhook_id, config["url"])

    return {
        "webhook_id": webhook_id,
        "url": config["url"],
        "events": webhook_configs[webhook_id]["events"],
        "status": "configured",
        "message": "Webhook configured successfully",
    }


@app.get("/api/webhook")
async def list_webhooks() -> Dict[str, Any]:
    """List all configured webhooks."""
    return {"webhooks": list(webhook_configs.values())}


@app.delete("/api/webhook/{webhook_id}")
async def delete_webhook(webhook_id: str) -> Dict[str, Any]:
    """Delete a webhook configuration."""
    if webhook_id not in webhook_configs:
        raise HTTPException(status_code=404, detail="Webhook not found")

    del webhook_configs[webhook_id]
    return {"webhook_id": webhook_id, "deleted": True}


# =============================================================================
# AI Triage Endpoints
# =============================================================================

@app.post("/api/scan/{scan_id}/triage")
async def run_ai_triage(scan_id: str) -> Dict[str, Any]:
    """
    Run AI triage on scan results to reduce false positives.

    Uses hybrid SAST+LLM architecture to validate findings with context-aware
    analysis. Falls back to local heuristics when LLM is unavailable.

    Args:
        scan_id: The scan ID

    Returns:
        Triage results with adjusted vulnerability list
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not scan.vulnerabilities:
        return {
            "scan_id": scan_id,
            "triage_status": "completed",
            "total_vulnerabilities": 0,
            "false_positives_flagged": 0,
            "vulnerabilities": [],
        }

    try:
        triaged = await ai_triage_engine.triage_vulnerabilities(
            scan.vulnerabilities,
            source_path=None,
        )

        # Update scan with triaged results
        scan.vulnerabilities = triaged
        scan.compute_stats()
        scan.compute_risk_score()
        await db.save_scan(scan)

        fp_count = sum(1 for v in triaged if "LIKELY FALSE POSITIVE" in v.description)

        return {
            "scan_id": scan_id,
            "triage_status": "completed",
            "total_vulnerabilities": len(triaged),
            "false_positives_flagged": fp_count,
            "llm_available": ai_triage_engine._openai_client is not None,
            "vulnerabilities": [v.model_dump() for v in triaged],
        }

    except Exception as e:
        logger.error("AI triage failed for scan %s: %s", scan_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"AI triage failed: {str(e)}")


@app.post("/api/triage/feedback")
async def record_triage_feedback(
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Record user triage feedback for organizational learning.
    """
    vuln_id = payload.get("vuln_id")
    verdict = payload.get("verdict")  # 'confirmed_tp' or 'confirmed_fp'
    comment = payload.get("comment", "")

    if not vuln_id or not verdict:
        raise HTTPException(status_code=400, detail="vuln_id and verdict are required")

    try:
        entry = ai_triage_engine.record_feedback(
            vuln_id=vuln_id,
            verdict=verdict,
            category=payload.get("category"),
            code_snippet=payload.get("code_snippet"),
            description=payload.get("description"),
            user_comment=comment,
        )
        return {"status": "success", "recorded": entry}
    except Exception as e:
        logger.error("Failed to record triage feedback: %s", e)
        raise HTTPException(status_code=500, detail=str(e))


# =============================================================================
# Auto-Fix Endpoints
# =============================================================================

@app.post("/api/vulnerabilities/{vuln_id}/fix")
async def generate_ai_fix(
    vuln_id: str,
    scan_id: str = Query(..., description="Scan ID containing the vulnerability"),
) -> Dict[str, Any]:
    """
    Generate an AI-powered fix for a vulnerability.

    Uses deterministic codemods for known vulnerability types, with
    LLM-powered fixes for novel or complex cases.

    Args:
        vuln_id: The vulnerability ID
        scan_id: The scan ID

    Returns:
        Fix result with diff, validation status, and fixed code
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Find the vulnerability
    vuln = None
    for v in scan.vulnerabilities:
        if v.id == vuln_id:
            vuln = v
            break

    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    try:
        fix_result = await auto_fix_engine.generate_fix(vuln, source_path=None)
        return fix_result.to_dict()

    except Exception as e:
        logger.error("Fix generation failed for %s: %s", vuln_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Fix generation failed: {str(e)}")


@app.get("/api/scan/{scan_id}/file")
async def get_scan_file(
    scan_id: str,
    file_path: str = Query(..., description="Relative path of the file"),
) -> Dict[str, Any]:
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    base_dir = os.path.abspath(scan.source_path)
    target_path = os.path.abspath(os.path.join(base_dir, file_path))
    if not target_path.startswith(base_dir):
        raise HTTPException(status_code=400, detail="Invalid file path")
        
    if not os.path.exists(target_path) or not os.path.isfile(target_path):
        if scan.source_type == "github" and scan.source_url:
            try:
                from scanner.github_handler import GitHubHandler
                gh = GitHubHandler()
                await gh.clone_repository(scan.source_url, scan_id)
            except Exception as e:
                logger.error("Failed to re-clone repository for file fetch: %s", e)
        
    if not os.path.exists(target_path) or not os.path.isfile(target_path):
        raise HTTPException(status_code=404, detail="File not found")
        
    try:
        with open(target_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
        return {"content": content, "file_path": file_path}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/scan/{scan_id}/file")
async def save_scan_file(
    scan_id: str,
    payload: Dict[str, Any],
) -> Dict[str, Any]:
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
        
    file_path = payload.get("file_path")
    content = payload.get("content")
    if not file_path or content is None:
        raise HTTPException(status_code=400, detail="file_path and content are required")
        
    base_dir = os.path.abspath(scan.source_path)
    target_path = os.path.abspath(os.path.join(base_dir, file_path))
    if not target_path.startswith(base_dir):
        raise HTTPException(status_code=400, detail="Invalid file path")
        
    try:
        with open(target_path, "w", encoding="utf-8") as f:
            f.write(content)
        return {"success": True, "message": "File saved successfully"}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/vulnerabilities/{vuln_id}/fix/apply")
async def apply_ai_fix(
    vuln_id: str,
    scan_id: str = Query(..., description="Scan ID containing the vulnerability"),
    source_path: Optional[str] = Query(None, description="Source code path"),
) -> Dict[str, Any]:
    """
    Apply an AI-generated fix to source code.

    Validates syntax before applying and supports auto-PR creation.

    Args:
        vuln_id: The vulnerability ID
        scan_id: The scan ID
        source_path: Path to source code directory

    Returns:
        Application result with success status
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    vuln = None
    for v in scan.vulnerabilities:
        if v.id == vuln_id:
            vuln = v
            break

    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    if not source_path or not os.path.exists(source_path):
        if scan.source_path and os.path.exists(scan.source_path):
            source_path = scan.source_path
        else:
            raise HTTPException(status_code=400, detail="Valid source path is required")

    try:
        fix_result = await auto_fix_engine.generate_fix(vuln, source_path=None)
        if fix_result.status == FixStatus.NO_FIX_AVAILABLE:
            return {
                "success": False,
                "error": "No fix available for this vulnerability type",
            }

        apply_result = await auto_fix_engine.apply_fix_to_file(
            vuln, fix_result, source_path
        )
        return apply_result

    except Exception as e:
        logger.error("Fix application failed for %s: %s", vuln_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Fix application failed: {str(e)}")


# =============================================================================
# Prioritization Endpoints
# =============================================================================

@app.post("/api/scan/{scan_id}/prioritize")
async def run_intelligent_prioritization(scan_id: str) -> Dict[str, Any]:
    """
    Run intelligent prioritization on scan results.

    Combines context analysis (endpoint exposure, auth requirements),
    threat intelligence (CISA KEV, EPSS), and business impact scoring.

    Args:
        scan_id: The scan ID

    Returns:
        Prioritized vulnerability list with P0-P4 bands
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not scan.vulnerabilities:
        return {
            "scan_id": scan_id,
            "prioritization_status": "completed",
            "total_vulnerabilities": 0,
            "prioritized_vulnerabilities": [],
            "priority_distribution": {},
        }

    try:
        source_path = scan.source_path if os.path.exists(str(scan.source_path)) else None

        prioritized = await prioritization_engine.prioritize_vulnerabilities(
            scan.vulnerabilities,
            source_path=source_path,
        )

        # Build priority distribution
        distribution: Dict[str, int] = {"P0": 0, "P1": 0, "P2": 0, "P3": 0, "P4": 0}
        for pv in prioritized:
            band = pv.priority_band.value
            distribution[band] = distribution.get(band, 0) + 1

        return {
            "scan_id": scan_id,
            "prioritization_status": "completed",
            "total_vulnerabilities": len(prioritized),
            "priority_distribution": distribution,
            "priority_guidelines": prioritization_engine.get_priority_guidelines(),
            "prioritized_vulnerabilities": [pv.to_dict() for pv in prioritized],
        }

    except Exception as e:
        logger.error("Prioritization failed for scan %s: %s", scan_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Prioritization failed: {str(e)}")


# =============================================================================
# LLM Security Endpoints
# =============================================================================

@app.get("/api/scan/{scan_id}/llm-security")
async def get_llm_security_findings(scan_id: str) -> Dict[str, Any]:
    """
    Get LLM-specific security findings for a scan.

    Returns AI-generated code patterns, AI-specific vulnerabilities,
    insecure LLM API usage, OWASP LLM Top 10 findings, and MCP issues.

    Args:
        scan_id: The scan ID

    Returns:
        LLM security findings grouped by category
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if scan.status not in ("completed", "failed"):
        raise HTTPException(status_code=400, detail="Scan is not yet complete")

    # Filter LLM security scanner findings
    llm_vulns = [v for v in scan.vulnerabilities if v.tool_source == "llm_security_scanner"]

    # Group by category
    categories: Dict[str, List[Dict[str, Any]]] = {}
    for vuln in llm_vulns:
        cat = vuln.category
        if cat not in categories:
            categories[cat] = []
        categories[cat].append(vuln.model_dump())

    # Count OWASP LLM findings
    owasp_llm_count = sum(
        1 for v in llm_vulns
        if v.owasp_category and v.owasp_category.startswith("LLM")
    )

    # Count MCP findings
    mcp_count = sum(1 for v in llm_vulns if "MCP" in v.category)

    return {
        "scan_id": scan_id,
        "total_llm_findings": len(llm_vulns),
        "owasp_llm_top10_findings": owasp_llm_count,
        "mcp_security_findings": mcp_count,
        "categories": categories,
        "findings": [v.model_dump() for v in llm_vulns],
    }


@app.post("/api/scan/{scan_id}/llm-security/scan")
async def run_llm_security_scan(scan_id: str) -> Dict[str, Any]:
    """
    Run LLM security scanner on an existing scan's source code.

    Scans for AI-generated code patterns, AI-specific vulnerabilities,
    insecure LLM API usage, OWASP LLM Top 10, and MCP security issues.

    Args:
        scan_id: The scan ID

    Returns:
        LLM security scan results
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    source_path = scan.source_path
    if not source_path or not os.path.exists(source_path):
        raise HTTPException(status_code=400, detail="Source code not available for scanning")

    try:
        llm_vulns = await llm_security_scanner.scan(source_path, scan_id)

        # Merge with existing vulnerabilities
        if llm_vulns:
            scan.vulnerabilities.extend(llm_vulns)
            scan.vulnerabilities = scan_engine._deduplicate_vulnerabilities(scan.vulnerabilities)
            scan.compute_stats()
            scan.compute_risk_score()
            await db.save_scan(scan)

        return {
            "scan_id": scan_id,
            "status": "completed",
            "llm_vulnerabilities_found": len(llm_vulns),
            "vulnerabilities": [v.model_dump() for v in llm_vulns],
        }

    except Exception as e:
        logger.error("LLM security scan failed for %s: %s", scan_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"LLM security scan failed: {str(e)}")


# =============================================================================
# AI Status Endpoint
# =============================================================================

@app.get("/api/ai/status")
async def get_ai_status() -> Dict[str, Any]:
    """
    Check AI service status and capabilities.

    Returns:
        Status of all AI services with availability info
    """
    triage_stats = await ai_triage_engine.get_triage_stats()
    fix_types = await auto_fix_engine.get_available_fix_types()

    return {
        "ai_triage": {
            "available": True,
            "llm_enabled": ai_triage_engine._openai_client is not None,
            "stats": triage_stats,
        },
        "auto_fix": {
            "available": True,
            "llm_enabled": auto_fix_engine._openai_client is not None,
            "supported_fix_types": fix_types,
        },
        "prioritization": {
            "available": True,
            "features": [
                "context_aware_scoring",
                "threat_intelligence",
                "business_impact_analysis",
            ],
        },
        "llm_security_scanning": {
            "available": True,
            "detection_capabilities": [
                "ai_generated_code_signatures",
                "ai_specific_vulnerabilities",
                "insecure_llm_api_usage",
                "owasp_llm_top_10",
                "mcp_security",
            ],
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# =============================================================================
# Error Handlers
# =============================================================================

@app.exception_handler(Exception)
async def generic_exception_handler(request, exc):
    """Handle unexpected exceptions, preserving HTTPException status codes."""
    if isinstance(exc, HTTPException):
        raise exc
    logger.error("Unhandled exception: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=500,
        content={"detail": "An internal error occurred. Please try again."},
    )


# =============================================================================
# Startup & Shutdown
# =============================================================================

@app.on_event("startup")
async def startup_event():
    """Application startup handler."""
    logger.info(
        "CodeShield AI v%s starting up on %s:%d",
        settings.app_version,
        settings.host,
        settings.port,
    )
    logger.info("Data directory: %s", settings.data_dir)
    logger.info("Temp directory: %s", settings.temp_dir)
    # Cancel any orphaned background tasks
    active_scans.clear()

    # Initialize multi-agent orchestration
    try:
        await hal_orchestrator.start()
        await agent_registry.start()
        await agent_health_monitor.start()
        await agent_bus.start()

        # Register all agents in the registry
        from agents.crew_definitions import AGENT_CREATORS, get_agent_info
        from agents.registry import AgentCapabilities

        for agent_id in AGENT_CREATORS:
            info = get_agent_info(agent_id)
            # Determine capabilities based on agent type
            tools = []
            languages = []
            vuln_types = []
            if info["category"] == "scanner":
                tools = [f"{agent_id}_scanner"]
                languages = ["python", "javascript", "java", "go", "dockerfile", "yaml"]
                vuln_types = ["injection", "xss", "secrets", "dependencies", "misconfiguration"]
            elif info["category"] == "processor":
                tools = [f"{agent_id}_processor"]
                languages = ["*"]
                vuln_types = ["triage", "fix"]
            else:
                tools = ["orchestrator", "dispatch", "report"]
                languages = ["*"]
                vuln_types = ["coordination"]

            await agent_registry.register(
                agent_id=agent_id,
                name=info["name"],
                role=info["role"],
                goal=f"Execute {info['role'].lower()} tasks",
                capabilities=AgentCapabilities(
                    tools=tools,
                    languages=languages,
                    vulnerability_types=vuln_types,
                    max_concurrent_tasks=3 if info["category"] == "scanner" else 1,
                ),
                tags=[info["category"]],
            )
            await agent_health_monitor.register_agent(agent_id, info["name"])

        logger.info(
            "Multi-agent orchestration initialized with %d agents",
            len(AGENT_CREATORS),
        )
    except Exception as e:
        logger.warning("Multi-agent orchestration init warning: %s", e)


@app.on_event("shutdown")
async def shutdown_event():
    """Application shutdown handler."""
    logger.info("CodeShield AI shutting down")
    # Cancel all active background scan tasks
    for scan_id, task in list(active_scans.items()):
        if not task.done():
            task.cancel()
            logger.info("Cancelled active scan %s on shutdown", scan_id)

    # Shutdown multi-agent orchestration
    try:
        await hal_orchestrator.stop()
        await agent_registry.stop()
        await agent_health_monitor.stop()
        await agent_bus.stop()
        logger.info("Multi-agent orchestration shutdown complete")
    except Exception as e:
        logger.warning("Error during multi-agent shutdown: %s", e)


# =============================================================================
# CI/CD Integration Endpoints
# =============================================================================

@app.get("/api/cicd/github-action")
async def download_github_action_template(
    scan_type: str = Query("full", description="Scan type"),
    languages: str = Query("python,javascript,java", description="Comma-separated languages"),
    severity_threshold: str = Query("MEDIUM", description="Severity threshold"),
    fail_on: str = Query("HIGH", description="Fail on severity"),
) -> StreamingResponse:
    """
    Download GitHub Action workflow template.

    Returns a ready-to-use GitHub Actions workflow file for
    integrating CodeShield AI into CI/CD pipelines.
    """
    try:
        generator = github_action_generator
        content = generator.generate_workflow_yaml(
            branches=["main", "develop"],
        )

        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="application/x-yaml",
            headers={
                "Content-Disposition": 'attachment; filename="codeshield-github-action.yml"'
            },
        )
    except Exception as e:
        logger.error("Failed to generate GitHub Action template: %s", e)
        raise HTTPException(status_code=500, detail=f"Template generation failed: {str(e)}")


@app.get("/api/cicd/gitlab-ci")
async def download_gitlab_ci_template(
    scan_type: str = Query("full", description="Scan type"),
    languages: str = Query("python,javascript", description="Comma-separated languages"),
    severity_threshold: str = Query("MEDIUM", description="Severity threshold"),
    fail_on: str = Query("HIGH", description="Fail on severity"),
) -> StreamingResponse:
    """
    Download GitLab CI/CD template.

    Returns a .gitlab-ci.yml with SARIF artifact reports for
    GitLab Security Dashboard integration.
    """
    try:
        from cicd.gitlab_ci import GitLabCIConfig
        config = GitLabCIConfig(
            scan_type=scan_type,
            languages=languages.split(","),
            severity_threshold=severity_threshold,
            fail_on=fail_on,
        )
        content = gitlab_ci_generator.generate_ci_template(config)

        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="application/x-yaml",
            headers={
                "Content-Disposition": 'attachment; filename=".gitlab-ci.yml"'
            },
        )
    except Exception as e:
        logger.error("Failed to generate GitLab CI template: %s", e)
        raise HTTPException(status_code=500, detail=f"Template generation failed: {str(e)}")


@app.get("/api/cicd/jenkins")
async def download_jenkins_template(
    pipeline_type: str = Query("declarative", pattern="^(declarative|scripted|stage)$"),
) -> StreamingResponse:
    """
    Download Jenkinsfile snippet.

    Returns a Jenkins pipeline template with Blue Ocean visualization
    support and quality gate integration.
    """
    try:
        generator = jenkins_plugin_generator

        if pipeline_type == "scripted":
            content = generator.generate_scripted_pipeline()
        elif pipeline_type == "stage":
            from cicd.jenkins_plugin import JenkinsConfig
            config = JenkinsConfig()
            content = generator.generate_stage_snippet(config)
        else:
            content = generator.generate_declarative_pipeline()

        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="text/plain",
            headers={
                "Content-Disposition": 'attachment; filename="Jenkinsfile"'
            },
        )
    except Exception as e:
        logger.error("Failed to generate Jenkins template: %s", e)
        raise HTTPException(status_code=500, detail=f"Template generation failed: {str(e)}")


@app.get("/api/cicd/azure-pipelines")
async def download_azure_pipelines_template() -> StreamingResponse:
    """
    Download Azure Pipelines YAML template.

    Returns an azure-pipelines.yml with Advanced Security SARIF
    upload and work item auto-creation.
    """
    try:
        content = azure_devops_generator.generate_pipeline_yaml()

        return StreamingResponse(
            io.BytesIO(content.encode("utf-8")),
            media_type="application/x-yaml",
            headers={
                "Content-Disposition": 'attachment; filename="azure-pipelines.yml"'
            },
        )
    except Exception as e:
        logger.error("Failed to generate Azure Pipelines template: %s", e)
        raise HTTPException(status_code=500, detail=f"Template generation failed: {str(e)}")


# =============================================================================
# Policy Engine Endpoints
# =============================================================================

class PolicyCreateRequest:
    """Request model for creating a policy."""
    name: str
    description: str
    enabled: bool = True
    enforcement_mode: str = "error"
    rules: List[Dict[str, Any]]
    scope: Dict[str, Any]
    phased_enforcement: bool = False


@app.post("/api/policy/evaluate")
async def evaluate_policy_against_scan(
    scan_id: str = Query(..., description="Scan ID to evaluate"),
    context: Optional[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """
    Evaluate all policies against a scan result.

    Returns a detailed evaluation report with pass/warn/fail status,
    violations, and suggested fixes.
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    try:
        report = policy_engine.evaluate_scan(scan, context)
        return report.to_dict()
    except Exception as e:
        logger.error("Policy evaluation failed: %s", e)
        raise HTTPException(status_code=500, detail=f"Policy evaluation failed: {str(e)}")


@app.post("/api/policy")
async def create_policy(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create a new security policy.

    Accepts a policy definition with rules, conditions, scope, and actions.
    """
    try:
        from policy_engine import SecurityPolicy, PolicyScope, PolicyRule, PolicyRuleCondition, PolicyAction, PolicySeverity

        # Parse scope
        scope_data = request.get("scope", {"level": "repository"})
        scope = PolicyScope(
            level=scope_data.get("level", "repository"),
            organization=scope_data.get("organization"),
            team=scope_data.get("team"),
            repository=scope_data.get("repository"),
            branch_patterns=scope_data.get("branch_patterns", ["*"]),
        )

        # Parse rules
        rules = []
        for rule_data in request.get("rules", []):
            conditions = []
            for cond_data in rule_data.get("conditions", []):
                conditions.append(PolicyRuleCondition(
                    type=cond_data.get("type", ""),
                    severity=cond_data.get("severity"),
                    count=cond_data.get("count"),
                    cwe_ids=cond_data.get("cwe_ids", []),
                    categories=cond_data.get("categories", []),
                    max_risk_score=cond_data.get("max_risk_score"),
                    min_risk_score=cond_data.get("min_risk_score"),
                    inverted=cond_data.get("inverted", False),
                ))

            rules.append(PolicyRule(
                name=rule_data.get("name", ""),
                description=rule_data.get("description", ""),
                conditions=conditions,
                action=PolicyAction(rule_data.get("action", "block")),
                severity=PolicySeverity(rule_data.get("severity", "HIGH")),
                message=rule_data.get("message", ""),
                enabled=rule_data.get("enabled", True),
            ))

        policy = SecurityPolicy(
            name=request.get("name", ""),
            description=request.get("description", ""),
            enabled=request.get("enabled", True),
            rules=rules,
            scope=scope,
            enforcement_mode=PolicyEnforcementMode(request.get("enforcement_mode", "error")),
            phased_enforcement=request.get("phased_enforcement", False),
            custom_metadata=request.get("custom_metadata", {}),
        )

        policy_id = policy_engine.create_policy(policy)

        return {
            "policy_id": policy_id,
            "status": "created",
            "policy": policy.to_dict(),
        }
    except Exception as e:
        logger.error("Failed to create policy: %s", e)
        raise HTTPException(status_code=500, detail=f"Policy creation failed: {str(e)}")


@app.put("/api/policy/{policy_id}")
async def update_policy(
    policy_id: str,
    request: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Update an existing security policy.
    """
    updated = policy_engine.update_policy(policy_id, request)
    if not updated:
        raise HTTPException(status_code=404, detail="Policy not found")

    return {
        "policy_id": policy_id,
        "status": "updated",
        "policy": updated.to_dict(),
    }


@app.get("/api/policy")
async def list_policies(
    enabled_only: bool = Query(False, description="Only return enabled policies"),
    scope_level: Optional[str] = Query(None, description="Filter by scope level"),
) -> Dict[str, Any]:
    """
    List all security policies.
    """
    policies = policy_engine.list_policies(
        enabled_only=enabled_only,
        scope_level=scope_level,
    )
    return {
        "policies": [p.to_dict() for p in policies],
        "total": len(policies),
        "built_in_count": sum(1 for p in policies if p.id.startswith("builtin-")),
    }


@app.delete("/api/policy/{policy_id}")
async def delete_policy(policy_id: str) -> Dict[str, Any]:
    """
    Delete a security policy.
    """
    # Prevent deletion of built-in policies
    if policy_id.startswith("builtin-"):
        raise HTTPException(status_code=403, detail="Cannot delete built-in policies")

    deleted = policy_engine.delete_policy(policy_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Policy not found")

    return {"policy_id": policy_id, "deleted": True}


# =============================================================================
# Webhook Engine Endpoints
# =============================================================================

@app.post("/api/webhook/endpoints")
async def register_webhook_endpoint(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Register a new webhook endpoint.
    """
    if "url" not in request:
        raise HTTPException(status_code=400, detail="Webhook URL is required")

    endpoint = WebhookEndpoint(
        url=request["url"],
        secret=request.get("secret"),
        events=request.get("events", ["scan.completed"]),
        headers=request.get("headers", {}),
        description=request.get("description", ""),
        timeout_seconds=request.get("timeout_seconds", 30),
        max_retries=request.get("max_retries", 5),
    )

    endpoint_id = webhook_engine.register_endpoint(endpoint)

    return {
        "endpoint_id": endpoint_id,
        "url": endpoint.url,
        "events": endpoint.events,
        "status": "registered",
    }


@app.get("/api/webhook/endpoints")
async def list_webhook_endpoints(
    active_only: bool = Query(False),
) -> Dict[str, Any]:
    """List registered webhook endpoints."""
    endpoints = webhook_engine.list_endpoints(active_only=active_only)
    return {
        "endpoints": [e.to_dict() for e in endpoints],
        "total": len(endpoints),
    }


@app.delete("/api/webhook/endpoints/{endpoint_id}")
async def unregister_webhook_endpoint(endpoint_id: str) -> Dict[str, Any]:
    """Unregister a webhook endpoint."""
    unregistered = webhook_engine.unregister_endpoint(endpoint_id)
    if not unregistered:
        raise HTTPException(status_code=404, detail="Webhook endpoint not found")
    return {"endpoint_id": endpoint_id, "unregistered": True}


@app.post("/api/webhook/deliver")
async def trigger_test_webhook_delivery(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Trigger a test webhook delivery.

    Sends a test event to a specified URL or registered endpoint.
    """
    event_type_str = request.get("event_type", "scan.completed")
    payload = request.get("payload", {"message": "Test webhook delivery"})
    url = request.get("url")
    endpoint_id = request.get("endpoint_id")

    try:
        event_type = WebhookEventType(event_type_str)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid event type: {event_type_str}")

    results = await webhook_engine.deliver_event(
        event_type=event_type,
        payload=payload,
        endpoint_id=endpoint_id,
        specific_url=url,
    )

    return {
        "event_type": event_type_str,
        "deliveries": [r.to_dict() for r in results],
        "total": len(results),
    }


@app.get("/api/webhook/delivery-log")
async def view_delivery_history(
    endpoint_id: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """
    View webhook delivery history.
    """
    entries = webhook_engine.get_delivery_log(
        endpoint_id=endpoint_id,
        event_type=event_type,
        limit=limit,
        offset=offset,
    )

    return {
        "entries": [e.to_dict() for e in entries],
        "total": len(entries),
        "limit": limit,
        "offset": offset,
    }


@app.get("/api/webhook/circuit-breakers")
async def get_circuit_breaker_status(
    endpoint_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Get circuit breaker status for webhook endpoints."""
    return webhook_engine.get_circuit_breaker_status(endpoint_id)


@app.get("/api/devsecops/status")
async def get_devsecops_status() -> Dict[str, Any]:
    """
    Get overall DevSecOps integration status.
    """
    return {
        "cicd": {
            "github_action": {"available": True, "template": "/api/cicd/github-action"},
            "gitlab_ci": {"available": True, "template": "/api/cicd/gitlab-ci"},
            "jenkins": {"available": True, "template": "/api/cicd/jenkins"},
            "azure_devops": {"available": True, "template": "/api/cicd/azure-pipelines"},
        },
        "policy_engine": {
            "policies_loaded": len(policy_engine.list_policies()),
            "built_in_policies": len([p for p in policy_engine.list_policies() if p.id.startswith("builtin-")]),
        },
        "webhook_engine": webhook_engine.to_dict(),
        "lsp_server": {
            "available": True,
            "port": 8211,
        },
    }


# =============================================================================
# Container & IaC Security Endpoints
# =============================================================================

@app.post("/api/scan/{scan_id}/container")
async def run_container_scan(scan_id: str) -> Dict[str, Any]:
    """
    Run container and IaC security scan on a scan's source code.

    Scans Dockerfiles, Kubernetes manifests, Terraform files, and Helm charts
    for security misconfigurations. Integrates with Trivy if available.

    Args:
        scan_id: The scan ID

    Returns:
        Container scan results with IaC misconfiguration findings
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    source_path = scan.source_path
    if not source_path or not os.path.exists(source_path):
        raise HTTPException(status_code=400, detail="Source code not available for scanning")

    try:
        container_vulns = await container_scanner.scan(
            source_path=source_path,
            scan_id=scan_id,
            scan_images=False,  # Safe default - no Docker daemon needed
        )

        # Merge with existing vulnerabilities
        if container_vulns:
            scan.vulnerabilities.extend(container_vulns)
            scan.vulnerabilities = scan_engine._deduplicate_vulnerabilities(
                scan.vulnerabilities
            )
            scan.compute_stats()
            scan.compute_risk_score()
            await db.save_scan(scan)

        # Group findings by category
        categories: Dict[str, int] = {}
        for v in container_vulns:
            cat = v.category.split(":")[0] if ":" in v.category else v.category
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "scan_id": scan_id,
            "status": "completed",
            "container_vulnerabilities_found": len(container_vulns),
            "categories": categories,
            "vulnerabilities": [v.model_dump() for v in container_vulns],
            "policies_applied": container_scanner.get_policy_summary(),
            "trivy_available": container_scanner.trivy_available,
        }

    except Exception as e:
        logger.error("Container scan failed for %s: %s", scan_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Container scan failed: {str(e)}")


# =============================================================================
# SBOM Generation Endpoints
# =============================================================================

@app.get("/api/scan/{scan_id}/sbom")
async def generate_sbom(
    scan_id: str,
    format: str = Query("spdx", pattern="^(spdx|cyclonedx|both)$"),
) -> Dict[str, Any]:
    """
    Generate SBOM for a scan in SPDX or CycloneDX format.

    Analyzes dependency lock files and generates a Software Bill of Materials
    with package names, versions, licenses, PURLs, and checksums.

    Args:
        scan_id: The scan ID
        format: SBOM format - 'spdx', 'cyclonedx', or 'both'

    Returns:
        SBOM in the requested format
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    source_path = scan.source_path
    if not source_path or not os.path.exists(source_path):
        raise HTTPException(status_code=400, detail="Source code not available for SBOM generation")

    try:
        # Run SCA analysis to build dependency graph
        analysis = sca_analyzer.analyze_project(source_path, scan_id)

        # Generate SBOM
        sbom = sca_analyzer.generate_sbom(scan_id, format)

        return {
            "scan_id": scan_id,
            "format": format,
            "total_dependencies": analysis.get("total_dependencies", 0),
            "direct_dependencies": analysis.get("direct_dependencies", 0),
            "transitive_dependencies": analysis.get("transitive_dependencies", 0),
            "sbom": sbom,
        }

    except Exception as e:
        logger.error("SBOM generation failed for %s: %s", scan_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"SBOM generation failed: {str(e)}")


# =============================================================================
# DAST Endpoints
# =============================================================================

@app.post("/api/scan/{scan_id}/dast")
async def run_dast_scan(
    scan_id: str,
    target_url: str = Query("", description="Target URL to scan (overrides auto-detection)"),
    use_zap: bool = Query(False, description="Use OWASP ZAP if available"),
    scan_type: str = Query("full", pattern="^(spider|active|api|full)$"),
) -> Dict[str, Any]:
    """
    Run DAST scan against a target URL.

    Performs dynamic application security testing including security headers
    validation, SSL/TLS checks, CORS policy validation, and information
    disclosure detection. Optionally integrates with OWASP ZAP.

    Args:
        scan_id: The scan ID
        target_url: Target URL to scan
        use_zap: Whether to use OWASP ZAP
        scan_type: Type of DAST scan

    Returns:
        DAST scan results
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    # Use provided target URL or auto-detect from source
    if not target_url:
        source_path = scan.source_path
        if source_path and os.path.exists(source_path):
            try:
                dast_vulns = await dast_scanner.scan_target_from_source(
                    source_path=source_path,
                    scan_id=scan_id,
                )
                return {
                    "scan_id": scan_id,
                    "status": "completed",
                    "scan_mode": "source_auto_detect",
                    "dast_vulnerabilities_found": len(dast_vulns),
                    "vulnerabilities": [v.model_dump() for v in dast_vulns],
                }
            except Exception as e:
                logger.error("Auto DAST scan failed: %s", e)

        raise HTTPException(
            status_code=400,
            detail="No target URL provided and auto-detection failed",
        )

    # Validate URL format
    if not target_url.startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Invalid URL format. Must start with http:// or https://")

    try:
        dast_vulns = await dast_scanner.scan(
            target_url=target_url,
            scan_id=scan_id,
            use_zap=use_zap,
            scan_type=scan_type,
        )

        # Merge with existing vulnerabilities
        if dast_vulns:
            scan.vulnerabilities.extend(dast_vulns)
            scan.vulnerabilities = scan_engine._deduplicate_vulnerabilities(
                scan.vulnerabilities
            )
            scan.compute_stats()
            scan.compute_risk_score()
            await db.save_scan(scan)

        # Group by category
        categories: Dict[str, int] = {}
        for v in dast_vulns:
            cat = v.category.split(":")[0] if ":" in v.category else v.category
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "scan_id": scan_id,
            "status": "completed",
            "target_url": target_url,
            "scan_mode": "direct_url",
            "zap_used": use_zap and dast_scanner.zap_scanner.zap_available,
            "dast_vulnerabilities_found": len(dast_vulns),
            "categories": categories,
            "vulnerabilities": [v.model_dump() for v in dast_vulns],
        }

    except Exception as e:
        logger.error("DAST scan failed for %s: %s", scan_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"DAST scan failed: {str(e)}")


# =============================================================================
# Reachability Analysis Endpoints
# =============================================================================

@app.get("/api/scan/{scan_id}/reachability")
async def get_reachability_analysis(scan_id: str) -> Dict[str, Any]:
    """
    Get reachability analysis for a scan's dependencies.

    Analyzes which vulnerable dependencies are actually reachable from source
    code through import statements. Scores: HIGH (1.5x), MEDIUM (1.0x),
    LOW (0.7x), INFORMATIONAL (0.3x).

    Args:
        scan_id: The scan ID

    Returns:
        Reachability analysis results
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    source_path = scan.source_path
    if not source_path or not os.path.exists(source_path):
        raise HTTPException(status_code=400, detail="Source code not available for reachability analysis")

    try:
        analysis = sca_analyzer.analyze_project(source_path, scan_id)

        return {
            "scan_id": scan_id,
            "status": "completed",
            **analysis,
        }

    except Exception as e:
        logger.error("Reachability analysis failed for %s: %s", scan_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Reachability analysis failed: {str(e)}")


# =============================================================================
# Taint Analysis Endpoints
# =============================================================================

@app.get("/api/scan/{scan_id}/taint")
async def get_taint_analysis_results(
    scan_id: str,
    include_sanitized: bool = Query(False, description="Include sanitized flows"),
) -> Dict[str, Any]:
    """
    Get taint analysis results for a scan.

    Performs intra-procedural taint tracking to detect data flow from
    user-controllable sources to dangerous sinks (SQL injection, XSS,
    command injection, path traversal, SSRF).

    Args:
        scan_id: The scan ID
        include_sanitized: Whether to include flows that pass through sanitizers

    Returns:
        Taint analysis results
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    source_path = scan.source_path
    if not source_path or not os.path.exists(source_path):
        raise HTTPException(status_code=400, detail="Source code not available for taint analysis")

    try:
        taint_vulns = await taint_analyzer.analyze(source_path, scan_id)

        # Merge with existing vulnerabilities
        if taint_vulns:
            scan.vulnerabilities.extend(taint_vulns)
            scan.vulnerabilities = scan_engine._deduplicate_vulnerabilities(
                scan.vulnerabilities
            )
            scan.compute_stats()
            scan.compute_risk_score()
            await db.save_scan(scan)

        # Filter if needed
        filtered_vulns = taint_vulns
        if not include_sanitized:
            summary = taint_analyzer.get_analysis_summary()
        else:
            summary = taint_analyzer.get_analysis_summary()

        # Group by category
        categories: Dict[str, int] = {}
        for v in taint_vulns:
            cat = v.category.split(":")[-1].strip() if ":" in v.category else v.category
            categories[cat] = categories.get(cat, 0) + 1

        return {
            "scan_id": scan_id,
            "status": "completed",
            "taint_vulnerabilities_found": len(taint_vulns),
            "categories": categories,
            "analysis_summary": summary,
            "vulnerabilities": [v.model_dump() for v in taint_vulns],
        }

    except Exception as e:
        logger.error("Taint analysis failed for %s: %s", scan_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Taint analysis failed: {str(e)}")


# =============================================================================
# Authentication & Authorization Endpoints
# =============================================================================

@app.post("/api/auth/login")
async def login(request: Dict[str, Any]) -> Dict[str, Any]:
    """
    Authenticate a user and record login.

    In production, this would validate credentials against a secure store.
    For the RBAC system, this records the login event and returns user info.
    """
    email = request.get("email", "").lower().strip()
    user = rbac_engine.get_user_by_email(email)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    rbac_engine.record_login(
        user.id,
        ip_address=request.get("ip_address"),
        user_agent=request.get("user_agent"),
    )
    return {
        "user": user.to_dict(),
        "permissions": rbac_engine.get_user_permissions(user),
    }


@app.get("/api/auth/me")
async def get_current_user(user_id: str = Query(..., description="User ID")) -> Dict[str, Any]:
    """Get current authenticated user info."""
    user = rbac_engine.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "user": user.to_dict(),
        "permissions": rbac_engine.get_user_permissions(user),
    }


@app.post("/api/auth/sso/saml")
async def sso_saml_login(request: Dict[str, Any]) -> Dict[str, Any]:
    """Initiate SAML SSO login."""
    provider_id = request.get("provider_id", "default")
    result = sso_engine.initiate_saml_login(provider_id)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.post("/api/auth/sso/saml/callback")
async def sso_saml_callback(request: Dict[str, Any]) -> Dict[str, Any]:
    """Process SAML SSO callback."""
    provider_id = request.get("provider_id", "default")
    saml_response = request.get("saml_response", "")
    try:
        sso_user = sso_engine.process_saml_response(provider_id, saml_response)
        provisioned = sso_engine.provision_user(sso_user)
        return {"user": sso_user.to_dict(), "provisioned": provisioned}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/auth/sso/oidc")
async def sso_oidc_login(request: Dict[str, Any]) -> Dict[str, Any]:
    """Initiate OIDC login."""
    provider_id = request.get("provider_id", "default")
    redirect_uri = request.get("redirect_uri", "")
    result = sso_engine.initiate_oidc_login(provider_id, redirect_uri)
    if "error" in result:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.post("/api/auth/sso/oidc/callback")
async def sso_oidc_callback(request: Dict[str, Any]) -> Dict[str, Any]:
    """Process OIDC callback."""
    provider_id = request.get("provider_id", "default")
    code = request.get("code", "")
    redirect_uri = request.get("redirect_uri", "")
    state = request.get("state")
    try:
        sso_user = sso_engine.process_oidc_callback(provider_id, code, redirect_uri, state)
        provisioned = sso_engine.provision_user(sso_user)
        return {"user": sso_user.to_dict(), "provisioned": provisioned}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/api/auth/ldap/login")
async def ldap_login(request: Dict[str, Any]) -> Dict[str, Any]:
    """Authenticate via LDAP."""
    provider_id = request.get("provider_id", "default")
    username = request.get("username", "")
    password = request.get("password", "")
    try:
        sso_user = sso_engine.authenticate_ldap(provider_id, username, password)
        provisioned = sso_engine.provision_user(sso_user)
        return {"user": sso_user.to_dict(), "provisioned": provisioned}
    except ValueError as e:
        raise HTTPException(status_code=401, detail=str(e))


# =============================================================================
# RBAC Endpoints
# =============================================================================

@app.get("/api/users")
async def list_users(
    organization_id: Optional[str] = Query(None),
    role: Optional[str] = Query(None),
    status: Optional[str] = Query("active"),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> Dict[str, Any]:
    """List users with filtering and pagination."""
    users = rbac_engine.list_users(
        organization_id=organization_id,
        role=role,
        status=status,
    )
    total = len(users)
    users = users[offset : offset + limit]
    return {
        "users": [u.to_dict() for u in users],
        "total": total,
        "limit": limit,
        "offset": offset,
    }


@app.post("/api/users")
async def create_user(request: Dict[str, Any]) -> Dict[str, Any]:
    """Create a new user account."""
    try:
        role = RoleName(request.get("role", "viewer"))
    except ValueError:
        role = RoleName.VIEWER
    user = rbac_engine.create_user(
        email=request.get("email", ""),
        role=role,
        organization_id=request.get("organization_id"),
        full_name=request.get("full_name"),
        username=request.get("username"),
        created_by=request.get("created_by"),
    )
    return {"user": user.to_dict(), "status": "created"}


@app.get("/api/users/{user_id}")
async def get_user(user_id: str) -> Dict[str, Any]:
    """Get a specific user."""
    user = rbac_engine.get_user(user_id)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {
        "user": user.to_dict(),
        "permissions": rbac_engine.get_user_permissions(user),
    }


@app.put("/api/users/{user_id}/role")
async def update_user_role(user_id: str, request: Dict[str, Any]) -> Dict[str, Any]:
    """Update a user's role."""
    new_role = request.get("role", "")
    updated_by = request.get("updated_by", "system")
    try:
        role_enum = RoleName(new_role)
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid role: {new_role}")
    user = rbac_engine.set_user_role(user_id, role_enum, updated_by)
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return {"user": user.to_dict(), "status": "role_updated"}


@app.get("/api/teams")
async def list_teams(
    organization_id: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """List teams with optional filtering."""
    teams = rbac_engine.list_teams(organization_id=organization_id, user_id=user_id)
    return {
        "teams": [t.to_dict() for t in teams],
        "total": len(teams),
    }


@app.post("/api/teams")
async def create_team(request: Dict[str, Any]) -> Dict[str, Any]:
    """Create a new team."""
    team = rbac_engine.create_team(
        name=request.get("name", ""),
        organization_id=request.get("organization_id", ""),
        description=request.get("description"),
        team_lead_id=request.get("team_lead_id"),
        created_by=request.get("created_by"),
    )
    return {"team": team.to_dict(), "status": "created"}


@app.get("/api/teams/{team_id}")
async def get_team(team_id: str) -> Dict[str, Any]:
    """Get a team with its members."""
    team = rbac_engine.get_team(team_id)
    if not team:
        raise HTTPException(status_code=404, detail="Team not found")
    members = rbac_engine.get_team_members(team_id)
    return {
        "team": team.to_dict(),
        "members": [m.to_dict() for m in members],
        "member_count": len(members),
    }


@app.post("/api/teams/{team_id}/members")
async def add_team_member(team_id: str, request: Dict[str, Any]) -> Dict[str, Any]:
    """Add a member to a team."""
    team = rbac_engine.add_team_member(
        team_id=team_id,
        user_id=request.get("user_id", ""),
        added_by=request.get("added_by"),
    )
    if not team:
        raise HTTPException(status_code=404, detail="Team or user not found")
    return {"team": team.to_dict(), "status": "member_added"}


@app.delete("/api/teams/{team_id}/members/{user_id}")
async def remove_team_member(team_id: str, user_id: str,
                             removed_by: str = Query("system")) -> Dict[str, Any]:
    """Remove a member from a team."""
    team = rbac_engine.remove_team_member(team_id, user_id, removed_by)
    if not team:
        raise HTTPException(status_code=404, detail="Team or user not found")
    return {"team": team.to_dict(), "status": "member_removed"}


@app.get("/api/organizations")
async def list_organizations(
    status: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """List organizations."""
    orgs = rbac_engine.list_organizations(status=status)
    return {
        "organizations": [o.to_dict() for o in orgs],
        "total": len(orgs),
    }


@app.post("/api/organizations")
async def create_organization(request: Dict[str, Any]) -> Dict[str, Any]:
    """Create a new organization."""
    org = rbac_engine.create_organization(
        name=request.get("name", ""),
        billing_email=request.get("billing_email"),
        description=request.get("description"),
        created_by=request.get("created_by"),
    )
    return {"organization": org.to_dict(), "status": "created"}


@app.get("/api/organizations/{org_id}")
async def get_organization(org_id: str) -> Dict[str, Any]:
    """Get an organization."""
    org = rbac_engine.get_organization(org_id)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    teams = rbac_engine.list_teams(organization_id=org_id)
    return {
        "organization": org.to_dict(),
        "teams": [t.to_dict() for t in teams],
        "team_count": len(teams),
    }


@app.get("/api/audit-log")
async def get_audit_log(
    organization_id: Optional[str] = Query(None),
    actor_id: Optional[str] = Query(None),
    action: Optional[str] = Query(None),
    resource_type: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    export_format: Optional[str] = Query(None, pattern="^(csv|json)$"),
) -> Any:
    """
    Get audit log with filtering.

    Optionally export as CSV or JSONL.
    """
    if export_format:
        audit_export = rbac_engine.export_audit_log(
            format=export_format,
            organization_id=organization_id,
        )
        if export_format == "csv":
            return StreamingResponse(
                io.StringIO(audit_export.to_csv()),
                media_type="text/csv",
                headers={"Content-Disposition": 'attachment; filename="audit_log.csv"'},
            )
        return StreamingResponse(
            io.StringIO(audit_export.to_jsonl()),
            media_type="application/jsonl",
            headers={"Content-Disposition": 'attachment; filename="audit_log.jsonl"'},
        )

    entries = rbac_engine.get_audit_log(
        organization_id=organization_id,
        actor_id=actor_id,
        action=action,
        resource_type=resource_type,
        limit=limit,
        offset=offset,
    )
    return {
        "entries": [e.to_dict() for e in entries],
        "total": len(entries),
        "limit": limit,
        "offset": offset,
        "hash_chain_valid": rbac_engine.verify_hash_chain()[0],
    }


@app.get("/api/audit-log/stats")
async def get_audit_log_stats() -> Dict[str, Any]:
    """Get audit log statistics."""
    return rbac_engine.get_audit_stats()


@app.get("/api/rbac/summary")
async def get_rbac_summary() -> Dict[str, Any]:
    """Get RBAC system summary."""
    return rbac_engine.get_summary()


# =============================================================================
# Compliance Endpoints
# =============================================================================

@app.get("/api/compliance/frameworks")
async def list_compliance_frameworks() -> Dict[str, Any]:
    """List all supported compliance frameworks."""
    frameworks = framework_registry.list_frameworks()
    return {
        "frameworks": [f.to_dict() for f in frameworks],
        "total": len(frameworks),
    }


@app.get("/api/compliance/frameworks/{framework_id}")
async def get_compliance_framework(framework_id: str) -> Dict[str, Any]:
    """Get a specific compliance framework with controls."""
    framework = framework_registry.get_framework(framework_id)
    if not framework:
        raise HTTPException(status_code=404, detail="Framework not found")
    return framework.to_dict()


@app.post("/api/compliance/report/{framework_id}")
async def generate_compliance_report(
    framework_id: str,
    request: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Generate a compliance report for a framework.

    Uses provided scan results to evaluate controls and produce gap analysis.
    """
    scan_results = request.get("scan_results", [])
    if not scan_results:
        # Use all available scan results from the database
        scans = await db.list_scans(limit=200)
        scan_results = [s.model_dump() for s in scans]

    try:
        report = report_generator.generate_report(
            framework_id=framework_id,
            scan_results=scan_results,
            organization_id=request.get("organization_id"),
            generated_by=request.get("generated_by"),
        )
        return report.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/compliance/gap-analysis/{framework_id}")
async def compliance_gap_analysis(
    framework_id: str,
    request: Dict[str, Any],
) -> Dict[str, Any]:
    """Perform gap analysis for a compliance framework."""
    scan_results = request.get("scan_results", [])
    if not scan_results:
        scans = await db.list_scans(limit=200)
        scan_results = [s.model_dump() for s in scans]

    try:
        return report_generator.gap_analysis(framework_id, scan_results)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/api/compliance/executive-summary")
async def compliance_executive_summary(
    framework_ids: Optional[str] = Query(None, description="Comma-separated framework IDs"),
) -> Dict[str, Any]:
    """Get executive compliance summary across frameworks."""
    ids = framework_ids.split(",") if framework_ids else None
    scans = await db.list_scans(limit=200)
    scan_results = [s.model_dump() for s in scans]
    return report_generator.executive_summary(ids, scan_results)


@app.get("/api/compliance/sla")
async def get_sla_dashboard() -> Dict[str, Any]:
    """Get SLA tracking dashboard data."""
    return sla_tracker.get_sla_dashboard()


@app.get("/api/compliance/sla/definitions")
async def list_sla_definitions() -> Dict[str, Any]:
    """List SLA definitions by severity."""
    return {
        "definitions": [d.to_dict() for d in sla_tracker.list_sla_definitions()],
    }


@app.get("/api/compliance/mttr")
async def get_mttr(
    severity: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Calculate Mean Time To Remediate."""
    return sla_tracker.calculate_mttr(severity=severity)


@app.get("/api/compliance/mttr/trend")
async def get_mttr_trend() -> Dict[str, Any]:
    """Get MTTR trend data."""
    return {
        "mttr_trend": metrics_engine.remediation_velocity(
            [r.to_dict() for r in sla_tracker._records.values()],
            period_weeks=12,
        ),
    }


@app.post("/api/compliance/sla/track")
async def track_vulnerability_sla(request: Dict[str, Any]) -> Dict[str, Any]:
    """Start SLA tracking for a vulnerability."""
    record = sla_tracker.track_vulnerability(
        vulnerability_id=request.get("vulnerability_id", ""),
        severity=request.get("severity", "MEDIUM"),
        scan_id=request.get("scan_id", ""),
        title=request.get("title"),
        category=request.get("category"),
        assigned_to=request.get("assigned_to"),
    )
    return {"record": record.to_dict(), "status": "tracking"}


@app.post("/api/compliance/sla/remediate")
async def mark_vulnerability_remediated(request: Dict[str, Any]) -> Dict[str, Any]:
    """Mark a vulnerability as remediated."""
    record = sla_tracker.mark_remediated(
        vulnerability_id=request.get("vulnerability_id", ""),
        actor_id=request.get("actor_id"),
    )
    if not record:
        raise HTTPException(status_code=404, detail="Vulnerability not found")
    return {"record": record.to_dict(), "status": "remediated"}


@app.get("/api/compliance/sla/alerts")
async def get_sla_alerts(
    acknowledged: Optional[bool] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
) -> Dict[str, Any]:
    """Get SLA breach alerts."""
    alerts = sla_tracker.get_alerts(acknowledged=acknowledged, limit=limit)
    return {
        "alerts": [a.to_dict() for a in alerts],
        "total": len(alerts),
    }


@app.post("/api/compliance/sla/check")
async def check_sla_breaches() -> Dict[str, Any]:
    """Check for SLA breaches and generate alerts."""
    new_alerts = sla_tracker.check_and_generate_alerts()
    return {
        "new_alerts": [a.to_dict() for a in new_alerts],
        "total_new": len(new_alerts),
    }


# =============================================================================
# Analytics Endpoints
# =============================================================================

@app.get("/api/analytics/dashboard")
async def get_dashboard(
    organization_id: Optional[str] = Query(None),
    period: str = Query("30d", pattern="^(7d|30d|90d)$"),
) -> Dict[str, Any]:
    """Get full dashboard data with all metrics."""
    scans = await db.list_scans(limit=200)
    scan_results = [s.model_dump() for s in scans]
    sla_records = [r.to_dict() for r in sla_tracker._records.values()]
    return dashboard_provider.dashboard_metrics(scan_results, sla_records)


@app.get("/api/analytics/trends")
async def get_trends(
    period: str = Query("30d", pattern="^(7d|30d|90d)$"),
    granularity: str = Query("day", pattern="^(day|week)$"),
) -> Dict[str, Any]:
    """Get trend data for charts."""
    scans = await db.list_scans(limit=200)
    scan_results = [s.model_dump() for s in scans]
    return dashboard_provider.trend_data(scan_results, period, granularity)


@app.get("/api/analytics/metrics")
async def get_detailed_metrics() -> Dict[str, Any]:
    """Get detailed security metrics."""
    scans = await db.list_scans(limit=200)
    scan_results = [s.model_dump() for s in scans]

    return {
        "vulnerability_trends": {
            k: v.to_dict() for k, v in metrics_engine.vulnerability_trends(scan_results).items()
        },
        "risk_score_trend": metrics_engine.risk_score_trend(scan_results).to_dict(),
        "top_vulnerable_files": [f.to_dict() for f in metrics_engine.top_vulnerable_files(scan_results)],
        "top_repositories": metrics_engine.top_vulnerable_repositories(scan_results),
        "top_categories": metrics_engine.top_vulnerability_categories(scan_results),
        "coverage": metrics_engine.scan_coverage(scan_results),
        "security_debt": metrics_engine.security_debt(scan_results),
        "security_score": metrics_engine.calculate_security_score(scan_results),
    }


@app.get("/api/analytics/executive-summary")
async def get_executive_summary(
    organization_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """Get executive summary for C-level reporting."""
    scans = await db.list_scans(limit=200)
    scan_results = [s.model_dump() for s in scans]
    sla_records = [r.to_dict() for r in sla_tracker._records.values()]
    return dashboard_provider.executive_summary(scan_results, sla_records, organization_id)


@app.get("/api/analytics/team-breakdown")
async def get_team_breakdown() -> Dict[str, Any]:
    """Get security metrics broken down by team."""
    scans = await db.list_scans(limit=200)
    scan_results = [s.model_dump() for s in scans]
    teams = rbac_engine.list_teams()
    teams_data = [t.to_dict() for t in teams]
    return dashboard_provider.team_breakdown(scan_results, teams_data)


@app.get("/api/analytics/project-breakdown")
async def get_project_breakdown() -> Dict[str, Any]:
    """Get security metrics broken down by project."""
    scans = await db.list_scans(limit=200)
    scan_results = [s.model_dump() for s in scans]
    projects = rbac_engine.list_projects()
    projects_data = [p.to_dict() for p in projects]
    return dashboard_provider.project_breakdown(scan_results, projects_data)


# =============================================================================
# Integration Endpoints
# =============================================================================

# -- SSO Configuration --

@app.post("/api/integrations/sso/saml/configure")
async def configure_saml_sso(request: Dict[str, Any]) -> Dict[str, Any]:
    """Configure a SAML 2.0 identity provider."""
    config = sso_engine.configure_saml(
        provider_id=request.get("provider_id", "default"),
        name=request.get("name", "SAML Provider"),
        metadata_url=request.get("metadata_url"),
        metadata_xml=request.get("metadata_xml"),
        entity_id=request.get("entity_id"),
        sso_url=request.get("sso_url"),
        x509_cert=request.get("x509_cert"),
        jit_provisioning=request.get("jit_provisioning", True),
        default_role=request.get("default_role", "viewer"),
        role_mappings=request.get("role_mappings"),
    )
    return {"provider": config.to_dict(), "status": "configured"}


@app.post("/api/integrations/sso/oidc/configure")
async def configure_oidc_sso(request: Dict[str, Any]) -> Dict[str, Any]:
    """Configure an OIDC identity provider."""
    config = sso_engine.configure_oidc(
        provider_id=request.get("provider_id", "default"),
        name=request.get("name", "OIDC Provider"),
        client_id=request.get("client_id", ""),
        client_secret=request.get("client_secret", ""),
        authorization_endpoint=request.get("authorization_endpoint", ""),
        token_endpoint=request.get("token_endpoint", ""),
        userinfo_endpoint=request.get("userinfo_endpoint", ""),
        issuer=request.get("issuer", ""),
        scopes=request.get("scopes"),
        jit_provisioning=request.get("jit_provisioning", True),
        default_role=request.get("default_role", "viewer"),
        role_mappings=request.get("role_mappings"),
    )
    return {"provider": config.to_dict(), "status": "configured"}


@app.post("/api/integrations/sso/ldap/configure")
async def configure_ldap_sso(request: Dict[str, Any]) -> Dict[str, Any]:
    """Configure an LDAP/AD identity provider."""
    config = sso_engine.configure_ldap(
        provider_id=request.get("provider_id", "default"),
        name=request.get("name", "LDAP Server"),
        ldap_server=request.get("ldap_server", ""),
        base_dn=request.get("base_dn", ""),
        bind_dn=request.get("bind_dn", ""),
        bind_password=request.get("bind_password", ""),
        ldap_port=request.get("ldap_port", 636),
        use_ssl=request.get("use_ssl", True),
        jit_provisioning=request.get("jit_provisioning", True),
        default_role=request.get("default_role", "viewer"),
    )
    return {"provider": config.to_dict(), "status": "configured"}


@app.get("/api/integrations/sso/providers")
async def list_sso_providers() -> Dict[str, Any]:
    """List configured SSO providers."""
    return {"providers": [p.to_dict() for p in sso_engine.list_providers()]}


# -- SIEM Configuration --

@app.post("/api/integrations/siem/splunk/configure")
async def configure_splunk_siem(request: Dict[str, Any]) -> Dict[str, Any]:
    """Configure Splunk HTTP Event Collector."""
    config = siem_engine.configure_splunk(
        hec_url=request.get("hec_url", ""),
        hec_token=request.get("hec_token", ""),
        index=request.get("index", "security"),
    )
    return {"provider": config.to_dict(), "status": "configured"}


@app.post("/api/integrations/siem/datadog/configure")
async def configure_datadog_siem(request: Dict[str, Any]) -> Dict[str, Any]:
    """Configure Datadog Logs API."""
    config = siem_engine.configure_datadog(
        api_key=request.get("api_key", ""),
        app_key=request.get("app_key"),
        site=request.get("site", "datadoghq.com"),
    )
    return {"provider": config.to_dict(), "status": "configured"}


@app.post("/api/integrations/siem/elastic/configure")
async def configure_elastic_siem(request: Dict[str, Any]) -> Dict[str, Any]:
    """Configure Elastic Security integration."""
    config = siem_engine.configure_elastic(
        elasticsearch_url=request.get("elasticsearch_url", ""),
        api_key=request.get("api_key"),
        username=request.get("username"),
        password=request.get("password"),
        index=request.get("index", "security-codeshield"),
    )
    return {"provider": config.to_dict(), "status": "configured"}


@app.post("/api/integrations/siem/syslog/configure")
async def configure_syslog_siem(request: Dict[str, Any]) -> Dict[str, Any]:
    """Configure Syslog export."""
    config = siem_engine.configure_syslog(
        host=request.get("host", ""),
        port=request.get("port", 514),
        protocol=request.get("protocol", "udp"),
        facility=request.get("facility", 16),
    )
    return {"provider": config.to_dict(), "status": "configured"}


@app.get("/api/integrations/siem/providers")
async def list_siem_providers() -> Dict[str, Any]:
    """List configured SIEM providers."""
    return {"providers": siem_engine.list_providers()}


@app.post("/api/integrations/siem/send-test")
async def send_test_siem_event(request: Dict[str, Any]) -> Dict[str, Any]:
    """Send a test event to configured SIEM providers."""
    providers = request.get("providers")
    from integrations.siem import SIEMEvent
    event = SIEMEvent(
        event_type="test.event",
        severity=5,
        message="CodeShield AI test event",
        fields={"test": True, "timestamp": datetime.now(timezone.utc).isoformat()},
    )
    return await siem_engine.send_event(event, providers)


@app.get("/api/integrations/siem/export/cef")
async def export_cef() -> StreamingResponse:
    """Export scan results as CEF."""
    scans = await db.list_scans(limit=200)
    scan_results = [s.model_dump() for s in scans]
    cef_events = siem_engine.export_cef(scan_results)
    content = "\n".join(cef_events)
    return StreamingResponse(
        io.StringIO(content),
        media_type="text/plain",
        headers={"Content-Disposition": 'attachment; filename="codeshield_events.cef"'},
    )


# -- Ticketing Configuration --

@app.post("/api/integrations/jira/configure")
async def configure_jira_integration(request: Dict[str, Any]) -> Dict[str, Any]:
    """Configure Jira integration."""
    config = ticketing_engine.configure_jira(
        url=request.get("url", ""),
        username=request.get("username", ""),
        api_token=request.get("api_token", ""),
        project_key=request.get("project_key", ""),
        issue_type=request.get("issue_type", "Security Vulnerability"),
    )
    return {"provider": config.to_dict(), "status": "configured"}


@app.post("/api/integrations/jira/create-ticket")
async def create_jira_ticket(request: Dict[str, Any]) -> Dict[str, Any]:
    """Create a Jira ticket for a vulnerability."""
    ticket = await ticketing_engine.create_jira_ticket(
        vulnerability=request.get("vulnerability", {}),
        project_key=request.get("project_key"),
        assignee=request.get("assignee"),
    )
    return ticket.to_dict()


@app.post("/api/integrations/github/configure")
async def configure_github_issues(request: Dict[str, Any]) -> Dict[str, Any]:
    """Configure GitHub Issues integration."""
    config = ticketing_engine.configure_github(
        token=request.get("token", ""),
        owner=request.get("owner", ""),
        default_repo=request.get("default_repo"),
    )
    return {"provider": config.to_dict(), "status": "configured"}


@app.post("/api/integrations/github/create-issue")
async def create_github_issue(request: Dict[str, Any]) -> Dict[str, Any]:
    """Create a GitHub issue for a vulnerability."""
    ticket = await ticketing_engine.create_github_issue(
        vulnerability=request.get("vulnerability", {}),
        repo=request.get("repo"),
    )
    return ticket.to_dict()


@app.post("/api/integrations/linear/configure")
async def configure_linear_integration(request: Dict[str, Any]) -> Dict[str, Any]:
    """Configure Linear integration."""
    config = ticketing_engine.configure_linear(
        api_key=request.get("api_key", ""),
        team_id=request.get("team_id", ""),
    )
    return {"provider": config.to_dict(), "status": "configured"}


@app.post("/api/integrations/pagerduty/configure")
async def configure_pagerduty_integration(request: Dict[str, Any]) -> Dict[str, Any]:
    """Configure PagerDuty integration."""
    config = ticketing_engine.configure_pagerduty(
        routing_key=request.get("routing_key", ""),
    )
    return {"provider": config.to_dict(), "status": "configured"}


@app.post("/api/integrations/ticketing/auto-create")
async def auto_create_tickets(request: Dict[str, Any]) -> Dict[str, Any]:
    """Automatically create tickets for critical/high vulnerabilities."""
    results = await ticketing_engine.acreate_for_critical(
        vulnerability=request.get("vulnerability", {}),
        providers=request.get("providers"),
    )
    return {k: v.to_dict() for k, v in results.items()}


@app.get("/api/integrations/ticketing/tickets")
async def list_tickets(
    provider: Optional[str] = Query(None),
    scan_id: Optional[str] = Query(None),
) -> Dict[str, Any]:
    """List created tickets."""
    tickets = ticketing_engine.list_tickets(provider=provider, scan_id=scan_id)
    return {
        "tickets": [t.to_dict() for t in tickets],
        "total": len(tickets),
    }


# -- Notification Configuration --

@app.post("/api/integrations/slack/webhook")
async def configure_slack_webhook(request: Dict[str, Any]) -> Dict[str, Any]:
    """Configure Slack webhook notifications."""
    config = notification_engine.configure_slack(
        webhook_url=request.get("webhook_url", ""),
        channel=request.get("channel"),
        username=request.get("username", "CodeShield AI"),
        severity_threshold=request.get("severity_threshold", "LOW"),
    )
    return {"channel": config.to_dict(), "status": "configured"}


@app.post("/api/integrations/slack/send")
async def send_slack_notification(request: Dict[str, Any]) -> Dict[str, Any]:
    """Send a Slack notification."""
    message = request.get("message", "")
    severity = request.get("severity", "INFO")
    return await notification_engine.send_notification(
        message=message, severity=severity, channels=["slack"]
    )


@app.post("/api/integrations/teams/webhook")
async def configure_teams_webhook(request: Dict[str, Any]) -> Dict[str, Any]:
    """Configure Microsoft Teams webhook notifications."""
    config = notification_engine.configure_teams(
        webhook_url=request.get("webhook_url", ""),
        severity_threshold=request.get("severity_threshold", "LOW"),
    )
    return {"channel": config.to_dict(), "status": "configured"}


@app.post("/api/integrations/email/configure")
async def configure_email_notifications(request: Dict[str, Any]) -> Dict[str, Any]:
    """Configure email (SMTP) notifications."""
    config = notification_engine.configure_smtp(
        host=request.get("host", ""),
        port=request.get("port", 587),
        username=request.get("username"),
        password=request.get("password"),
        from_address=request.get("from_address", "security@codeshield.ai"),
        recipients=request.get("recipients", []),
        severity_threshold=request.get("severity_threshold", "LOW"),
    )
    return {"channel": config.to_dict(), "status": "configured"}


@app.post("/api/integrations/email/recipients")
async def add_email_recipient(request: Dict[str, Any]) -> Dict[str, Any]:
    """Add an email recipient."""
    email = request.get("email", "")
    notification_engine.add_email_recipient(email)
    return {"recipient": email, "status": "added"}


@app.get("/api/integrations/status")
async def get_integrations_status() -> Dict[str, Any]:
    """Get overall integration status."""
    return {
        "sso": {
            "providers": [p.provider_id for p in sso_engine.list_providers()],
            "configured": len(sso_engine.list_providers()) > 0,
        },
        "siem": {
            "providers": [p["name"] for p in siem_engine.list_providers()],
            "configured": len(siem_engine.list_providers()) > 0,
        },
        "ticketing": {
            "configured_providers": list(ticketing_engine._configs.keys()),
            "total_tickets_created": len(ticketing_engine._ticket_history),
        },
        "notifications": {
            "channels": list(notification_engine._configs.keys()),
            "configured": len(notification_engine._configs) > 0,
        },
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }


# =============================================================================
# Multi-Agent Swarm Post-Processing Endpoints
# =============================================================================

@app.post("/api/agents/triage/{scan_id}")
async def run_triager_agent(
    scan_id: str,
    reachability_data: Optional[Dict[str, bool]] = None,
) -> Dict[str, Any]:
    """
    Run triage on scan findings via Triager Agent.

    Performs deduplication, confidence scoring, AI triage on HIGH/CRITICAL
    findings, and severity adjustment based on reachability and context.

    Args:
        scan_id: The scan ID
        reachability_data: Optional dict mapping vuln_id -> is_reachable

    Returns:
        Triaged findings with confidence scores and adjusted severity
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not scan.vulnerabilities:
        return {
            "scan_id": scan_id,
            "status": "completed",
            "total_findings": 0,
            "triaged_findings": [],
        }

    try:
        triaged = await triager_agent.triage(
            findings=scan.vulnerabilities,
            source_path=scan.source_path if os.path.exists(str(scan.source_path)) else None,
            reachability_data=reachability_data,
        )

        return {
            "scan_id": scan_id,
            "status": "completed",
            "total_findings": len(scan.vulnerabilities),
            "triaged_count": len(triaged),
            "confirmed": sum(1 for t in triaged if t.triage_status.value == "confirmed"),
            "likely_false_positives": sum(1 for t in triaged if t.triage_status.value == "likely_false_positive"),
            "deduplication_stats": {
                "original": len(scan.vulnerabilities),
                "after_dedup": len(triaged),
                "removed": len(scan.vulnerabilities) - len(triaged),
            },
            "triaged_findings": [t.to_dict() for t in triaged],
        }

    except Exception as e:
        logger.error("Triager agent failed for scan %s: %s", scan_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Triage failed: {str(e)}")


@app.post("/api/agents/fix/{scan_id}")
async def run_fix_agent(
    scan_id: str,
    severity_filter: Optional[str] = Query(None, description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW)"),
    create_pr: bool = Query(False, description="Create a PR after applying fixes"),
    repo_url: Optional[str] = Query(None, description="Repository URL for PR creation"),
) -> Dict[str, Any]:
    """
    Generate fixes for findings via Fix Agent.

    Builds a prioritized fix queue, generates deterministic or LLM-powered
    fixes, validates syntax, and optionally creates a pull request.

    Args:
        scan_id: The scan ID
        severity_filter: Only fix findings of this severity
        create_pr: Whether to create a PR
        repo_url: Repository URL for PR

    Returns:
        Fix results with generated diffs and application status
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    source_path = scan.source_path
    if not source_path or not os.path.exists(source_path):
        raise HTTPException(status_code=400, detail="Source code not available")

    vulnerabilities = scan.vulnerabilities
    if severity_filter:
        vulnerabilities = [v for v in vulnerabilities if v.severity.upper() == severity_filter.upper()]

    if not vulnerabilities:
        return {
            "scan_id": scan_id,
            "status": "completed",
            "message": "No vulnerabilities to fix",
            "fixes_generated": 0,
        }

    try:
        result = await fix_agent.run_fix_pipeline(
            vulnerabilities=vulnerabilities,
            source_path=source_path,
            create_pr=create_pr,
            repo_url=repo_url,
        )

        return {
            "scan_id": scan_id,
            "status": "completed",
            "fixes_generated": result.get("fixable_count", 0),
            "fixes_applied": result.get("applied", 0),
            "fixes_failed": result.get("failed", 0),
            "batches_processed": result.get("batches_processed", 0),
            "elapsed_seconds": result.get("elapsed_seconds", 0),
            "pr": result.get("pr"),
            "backups": result.get("backup_paths", {}),
        }

    except Exception as e:
        logger.error("Fix agent failed for scan %s: %s", scan_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Fix generation failed: {str(e)}")


@app.post("/api/agents/fix/{vuln_id}/apply")
async def apply_specific_fix(
    vuln_id: str,
    scan_id: str = Query(..., description="Scan ID containing the vulnerability"),
    source_path: Optional[str] = Query(None, description="Source code path"),
) -> Dict[str, Any]:
    """
    Apply a specific fix for a single vulnerability.

    Generates the fix, validates syntax, creates a backup, and applies
    it to the source file.

    Args:
        vuln_id: The vulnerability ID
        scan_id: The scan ID
        source_path: Path to source code

    Returns:
        Application result with diff and backup info
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    vuln = None
    for v in scan.vulnerabilities:
        if v.id == vuln_id:
            vuln = v
            break

    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnerability not found")

    actual_source = source_path or scan.source_path
    if not actual_source or not os.path.exists(actual_source):
        raise HTTPException(status_code=400, detail="Valid source path is required")

    try:
        # Build queue with single item
        queue = fix_agent.build_fix_queue([vuln])

        # Generate fix
        queue = await fix_agent.generate_fixes(queue, actual_source)

        if not queue or not queue[0].fix_result or not queue[0].fix_result.fixed_code:
            return {
                "success": False,
                "error": "No fix available for this vulnerability type",
                "vuln_id": vuln_id,
            }

        # Apply fix
        result = await fix_agent.apply_fix(queue[0], actual_source)

        return {
            "vuln_id": vuln_id,
            "success": result.get("success", False),
            "file_path": result.get("file_path"),
            "backup_path": result.get("backup_path"),
            "diff": queue[0].fix_result.diff,
            "fix_description": queue[0].fix_result.description,
        }

    except Exception as e:
        logger.error("Fix application failed for %s: %s", vuln_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Fix application failed: {str(e)}")


@app.get("/api/agents/chains/{scan_id}")
async def get_findings_chains(
    scan_id: str,
    include_visualization: bool = Query(True, description="Include visualization data"),
) -> Dict[str, Any]:
    """
    Get findings chains for a scan.

    Shows how findings chain across agents (SAST -> Taint -> DAST),
    with confidence propagation and chain status.

    Args:
        scan_id: The scan ID
        include_visualization: Whether to include D3.js-ready viz data

    Returns:
        Chain analysis with strongest chains, broken chains, and viz data
    """
    _validate_scan_id(scan_id)
    scan = await db.get_scan(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")

    if not scan.vulnerabilities:
        return {
            "scan_id": scan_id,
            "total_chains": 0,
            "chains": [],
            "strongest_chains": [],
            "broken_chains": [],
            "visualization_data": None,
        }

    try:
        result = await chains_visualizer.analyze_chains(
            vulnerabilities=scan.vulnerabilities,
        )

        if not include_visualization:
            result.pop("visualization_data", None)
            result.pop("text_report", None)

        result["scan_id"] = scan_id
        return result

    except Exception as e:
        logger.error("Chain analysis failed for scan %s: %s", scan_id, e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Chain analysis failed: {str(e)}")


@app.get("/api/agents/metrics")
async def get_agent_performance_metrics(
    agent_name: Optional[str] = Query(None, description="Filter by agent name"),
) -> Dict[str, Any]:
    """
    Get agent performance metrics.

    Returns execution times, findings counts, false positive rates,
    agreement rates between agents, and scan efficiency data.

    Args:
        agent_name: Optional agent name to filter

    Returns:
        Comprehensive agent metrics
    """
    try:
        metrics = await agent_metrics_collector.get_all_metrics()

        if agent_name and agent_name in metrics.get("agents", {}):
            return {
                "agent": metrics["agents"][agent_name],
                "execution_time": metrics["execution_times"].get(agent_name, {}),
                "findings_count": metrics["findings_counts"].get(agent_name, {}),
            }

        return metrics

    except Exception as e:
        logger.error("Failed to get agent metrics: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Metrics retrieval failed: {str(e)}")


@app.post("/api/agents/metrics/feedback")
async def record_agent_feedback(
    request: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Record feedback for an agent finding.

    Used to track false positive rates and improve accuracy.

    Args:
        request: Dict with agent_name, vuln_id, is_false_positive

    Returns:
        Confirmation with updated FP rate
    """
    agent_name = request.get("agent_name", "")
    vuln_id = request.get("vuln_id", "")
    is_fp = request.get("is_false_positive", False)

    if not agent_name or not vuln_id:
        raise HTTPException(status_code=400, detail="agent_name and vuln_id are required")

    agent_metrics_collector.record_feedback(agent_name, vuln_id, is_fp)
    fp_rates = agent_metrics_collector.get_false_positive_rates()

    return {
        "recorded": True,
        "agent_name": agent_name,
        "vuln_id": vuln_id,
        "is_false_positive": is_fp,
        "agent_fp_rate": fp_rates.get(agent_name, {}),
    }


# =============================================================================
# Multi-Agent Orchestration Endpoints
# =============================================================================

@app.post("/api/agents/scan")
async def start_multi_agent_scan(
    request: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Start a multi-agent security scan using the HAL orchestrator.

    Coordinates multiple specialized security agents through a configurable
    workflow with adaptive scanning, cross-referencing, and progress tracking.

    Args:
        request: Scan configuration with source_path, workflow_id, etc.

    Returns:
        Scan ID and initial status
    """
    source_path = request.get("source_path", "")
    workflow_id = request.get("workflow_id", "full_scan")
    name = request.get("name", f"Multi-Agent Scan {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}")

    if not source_path or not os.path.exists(source_path):
        raise HTTPException(status_code=400, detail="Valid source_path is required")

    # Validate workflow
    workflow = get_workflow(workflow_id)
    if not workflow:
        available = list_workflows()
        raise HTTPException(
            status_code=400,
            detail=f"Unknown workflow '{workflow_id}'. Available: {[w['workflow_id'] for w in available]}",
        )

    # Generate scan ID
    scan_id = str(uuid.uuid4())[:8]

    # Build context
    context = {
        "scan_id": scan_id,
        "source_path": source_path,
        "name": name,
        "workflow_id": workflow_id,
        "base_url": request.get("base_url"),
        "focus_files": request.get("focus_files", []),
        "approval_thresholds": request.get("approval_thresholds", ["CRITICAL"]),
        "config": request.get("config", {}),
    }

    try:
        # Start orchestrator if not running
        await hal_orchestrator.start()

        # Run workflow in background
        task = asyncio.create_task(
            _run_multi_agent_workflow(scan_id, workflow_id, source_path, context)
        )
        active_scans[scan_id] = task

        def _on_done(t: asyncio.Task) -> None:
            active_scans.pop(scan_id, None)
            exc = t.exception()
            if exc:
                logger.error("Multi-agent scan %s failed: %s", scan_id, exc)

        task.add_done_callback(_on_done)

        logger.info("Started multi-agent scan %s with workflow %s", scan_id, workflow_id)

        return {
            "scan_id": scan_id,
            "workflow_id": workflow_id,
            "status": "running",
            "phase": "initializing",
            "agents": workflow.get_required_agents(),
            "message": "Multi-agent scan started. Poll /api/agents/scan/{scan_id}/status for progress.",
        }

    except Exception as e:
        logger.error("Failed to start multi-agent scan: %s", e, exc_info=True)
        raise HTTPException(status_code=500, detail=f"Failed to start multi-agent scan: {str(e)}")


async def _run_multi_agent_workflow(
    scan_id: str, workflow_id: str, source_path: str, context: Dict[str, Any]
) -> None:
    """Run a multi-agent workflow in the background."""
    try:
        await hal_orchestrator.run_workflow(
            scan_id=scan_id,
            workflow_id=workflow_id,
            source_path=source_path,
            context=context,
        )
    except Exception as e:
        logger.error("Multi-agent workflow %s failed: %s", scan_id, e, exc_info=True)


@app.get("/api/agents/scan/{scan_id}/status")
async def get_multi_agent_scan_status(scan_id: str) -> Dict[str, Any]:
    """
    Get the status of a multi-agent scan.

    Args:
        scan_id: The multi-agent scan ID

    Returns:
        Current phase, progress, agent results, and findings summary
    """
    _validate_scan_id(scan_id)
    state = hal_orchestrator.get_state(scan_id)

    if not state:
        # Check if scan completed and was removed from active
        raise HTTPException(status_code=404, detail="Multi-agent scan not found")

    return state.to_dict()


@app.get("/api/agents/status")
async def get_all_agent_status() -> Dict[str, Any]:
    """
    Get health status for all agents in the system.

    Returns:
        Agent registry status, health monitor metrics, and circuit breaker states
    """
    try:
        registry_stats = agent_registry.get_stats()
        health_summary = agent_health_monitor.get_summary()
        bus_stats = agent_bus.get_stats()

        # Get all registered agents with their status
        agents_info = []
        for agent_id, agent_info in agent_registry.agents.items():
            health = agent_health_monitor._health_status.get(agent_id, "unknown")
            metrics = agent_health_monitor._metrics.get(agent_id)
            agents_info.append({
                **agent_info.to_dict(),
                "health": health,
                "metrics": metrics.to_dict() if metrics else None,
            })

        return {
            "agents": agents_info,
            "registry": registry_stats,
            "health_monitor": health_summary,
            "message_bus": bus_stats,
            "active_scans": len(hal_orchestrator.get_all_active_scans()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error("Failed to get agent status: %s", e)
        raise HTTPException(status_code=500, detail=f"Failed to get agent status: {str(e)}")


@app.post("/api/agents/{agent_id}/restart")
async def restart_agent(agent_id: str) -> Dict[str, Any]:
    """
    Restart a failed agent.

    Resets the agent's circuit breaker and health status,
    allowing it to process new tasks.

    Args:
        agent_id: The agent to restart

    Returns:
        Restart confirmation
    """
    try:
        # Reset circuit breaker
        await agent_bus.circuit_breaker.reset(agent_id)

        # Update registry status
        await agent_registry.update_status(agent_id, AgentStatus.HEALTHY)

        # Reset health monitor
        from agents.health import HealthStatus
        agent = await agent_registry.get_agent(agent_id)

        logger.info("Agent %s restarted", agent_id)

        return {
            "agent_id": agent_id,
            "status": "restarted",
            "previous_status": agent.status.value if agent else "unknown",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

    except Exception as e:
        logger.error("Failed to restart agent %s: %s", agent_id, e)
        raise HTTPException(status_code=500, detail=f"Failed to restart agent: {str(e)}")


@app.get("/api/agents/workflows")
async def list_available_workflows() -> Dict[str, Any]:
    """
    List all available multi-agent scan workflows.

    Returns:
        List of workflow definitions with their required agents
    """
    workflows = list_workflows()

    # Add agent info to each workflow
    for workflow in workflows:
        workflow["agents"] = [
            {**get_agent_info(agent_id), "agent_id": agent_id}
            for agent_id in workflow.get("required_agents", [])
        ]

    return {
        "workflows": workflows,
        "total": len(workflows),
        "available_agents": get_all_agent_ids(),
        "scanning_agents": get_scanning_agent_ids(),
    }


@app.post("/api/agents/workflow/{workflow_id}/run")
async def run_specific_workflow(
    workflow_id: str,
    request: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Run a specific multi-agent workflow.

    Args:
        workflow_id: Workflow identifier (full_scan, quick_scan, deep_scan, etc.)
        request: Scan configuration with source_path, etc.

    Returns:
        Scan ID and initial status
    """
    # Validate workflow
    workflow = get_workflow(workflow_id)
    if not workflow:
        available = list_workflows()
        raise HTTPException(
            status_code=404,
            detail=f"Workflow '{workflow_id}' not found. Available: {[w['workflow_id'] for w in available]}",
        )

    # Delegate to the main scan endpoint logic
    request["workflow_id"] = workflow_id
    return await start_multi_agent_scan(request)


@app.get("/api/agents/scan/{scan_id}/report")
async def get_multi_agent_scan_report(scan_id: str) -> Dict[str, Any]:
    """
    Get the final report from a multi-agent scan.

    Args:
        scan_id: The multi-agent scan ID

    Returns:
        Complete security report with findings, fix proposals, and metadata
    """
    _validate_scan_id(scan_id)
    state = hal_orchestrator.get_state(scan_id)

    if not state:
        raise HTTPException(status_code=404, detail="Multi-agent scan not found")

    if state.phase.value not in ("completed", "failed"):
        raise HTTPException(
            status_code=400,
            detail=f"Scan is not complete. Current phase: {state.phase.value}",
        )

    if not state.report:
        return {
            "scan_id": scan_id,
            "status": state.phase.value,
            "message": "Report not yet generated",
            "findings": state.triaged_findings,
        }

    return state.report


@app.post("/api/agents/scan/{scan_id}/approve")
async def approve_critical_findings(
    scan_id: str,
    request: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Approve or reject critical findings pending human approval.

    Args:
        scan_id: The multi-agent scan ID
        request: Approval decisions with finding_ids and approved flag

    Returns:
        Approval confirmation
    """
    _validate_scan_id(scan_id)
    state = hal_orchestrator.get_state(scan_id)

    if not state:
        raise HTTPException(status_code=404, detail="Multi-agent scan not found")

    finding_ids = request.get("finding_ids", [])
    approved = request.get("approved", True)

    if not finding_ids:
        raise HTTPException(status_code=400, detail="finding_ids is required")

    success = await hal_orchestrator.approve_findings(scan_id, finding_ids, approved)

    return {
        "scan_id": scan_id,
        "approved": approved,
        "finding_ids": finding_ids,
        "status": "processed",
    }


@app.get("/api/agents/definitions")
async def get_agent_definitions() -> Dict[str, Any]:
    """
    Get definitions for all 10 agents in the system.

    Returns:
        Agent definitions with roles, goals, and capabilities
    """
    from agents.crew_definitions import AGENT_CREATORS

    agents = []
    for agent_id in AGENT_CREATORS:
        info = get_agent_info(agent_id)
        agents.append(info)

    return {
        "agents": agents,
        "total": len(agents),
        "categories": {
            "orchestrator": [a for a in agents if a.get("category") == "orchestrator"],
            "scanner": [a for a in agents if a.get("category") == "scanner"],
            "processor": [a for a in agents if a.get("category") == "processor"],
        },
    }


# =============================================================================
# Main Entry Point
# =============================================================================

if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )
