"""
CodeShield AI - Language Server Protocol (LSP) Implementation.

Provides security diagnostics via LSP using pygls:
- Diagnostics on save (not real-time for accuracy)
- Severity mapping: CRITICAL→Error, HIGH→Error, MEDIUM→Warning, LOW→Information
- Code actions: "Apply Fix" quick fix action
- Hover information: vulnerability details on hover
- Configuration: severity thresholds, enabled tools, scan on save toggle
- Workspace notification: scan status updates

Usage:
    python lsp_server.py --port 8211
"""

import asyncio
import json
import logging
import re
import tempfile
import uuid
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from lsprotocol.types import (
    TEXT_DOCUMENT_CODE_ACTION,
    TEXT_DOCUMENT_DID_CHANGE,
    TEXT_DOCUMENT_DID_CLOSE,
    TEXT_DOCUMENT_DID_OPEN,
    TEXT_DOCUMENT_DID_SAVE,
    TEXT_DOCUMENT_HOVER,
    WORKSPACE_DID_CHANGE_CONFIGURATION,
    CodeAction,
    CodeActionKind,
    CodeActionOptions,
    CodeActionParams,
    Command,
    ConfigurationItem,
    Diagnostic,
    DiagnosticOptions,
    DiagnosticSeverity,
    DiagnosticTag,
    DidChangeConfigurationParams,
    DidChangeTextDocumentParams,
    DidCloseTextDocumentParams,
    DidOpenTextDocumentParams,
    DidSaveTextDocumentParams,
    Hover,
    HoverParams,
    MarkupContent,
    MarkupKind,
    MessageType,
    Position,
    Range,
    RegistrationParams,
    TextDocumentIdentifier,
    TextEdit,
    WorkspaceEdit,
)
from pygls.lsp.server import LanguageServer
from pygls.protocol import JsonRPCNotification, JsonRPCRequestMessage

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("codeshield-lsp")

# Severity mapping from CodeShield to LSP DiagnosticSeverity
SEVERITY_MAP = {
    "CRITICAL": DiagnosticSeverity.Error,
    "HIGH": DiagnosticSeverity.Error,
    "MEDIUM": DiagnosticSeverity.Warning,
    "LOW": DiagnosticSeverity.Information,
    "INFO": DiagnosticSeverity.Hint,
}

# Diagnostic tags for quick identification
SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "INFO": "🔵",
}

# Default configuration
DEFAULT_CONFIG = {
    "codeshield": {
        "apiUrl": "https://api.codeshield.ai",
        "apiToken": "",
        "severityThreshold": "LOW",
        "enabledTools": ["semgrep", "bandit", "eslint", "custom_ai"],
        "scanOnSave": True,
        "enableCodeActions": True,
        "enableHover": True,
        "maxDiagnosticsPerFile": 50,
        "showInlineDecorations": True,
        "ignorePatterns": ["test_*", "*_test.py", "tests/", "vendor/", "node_modules/"],
    }
}


class CodeShieldLSPServer(LanguageServer):
    """
    CodeShield AI Language Server Protocol implementation.

    Provides security-focused language features:
    - Document diagnostics on save
    - Code actions for vulnerability remediation
    - Hover information for security issues
    - Workspace configuration management
    """

    def __init__(self, name: str = "codeshield-lsp", version: str = "1.0.0") -> None:
        """Initialize the CodeShield LSP server."""
        super().__init__(name, version)
        self.config = dict(DEFAULT_CONFIG)
        self.diagnostics_cache: Dict[str, List[Diagnostic]] = {}  # uri -> diagnostics
        self.vulnerability_cache: Dict[str, List[Dict[str, Any]]] = {}  # uri -> vulns
        self._pending_scans: Dict[str, asyncio.Task] = {}
        self._workspace_folders: List[str] = []

    async def get_configuration(self) -> Dict[str, Any]:
        """Fetch configuration from client if supported."""
        try:
            if self.lsp.client_capabilities and hasattr(
                self.lsp.client_capabilities, "workspace"
            ):
                workspace = self.lsp.client_capabilities.workspace
                if workspace and getattr(workspace, "configuration", False):
                    items = [ConfigurationItem(section="codeshield")]
                    config = await self.lsp.get_configuration_async(
                        ConfigurationParams(items=items)
                    )
                    if config and len(config) > 0:
                        self.config["codeshield"].update(config[0])
        except Exception as e:
            logger.warning("Failed to fetch configuration: %s", e)
        return self.config

    def should_scan_file(self, uri: str) -> bool:
        """Check if a file should be scanned based on ignore patterns."""
        path = self._uri_to_path(uri)
        ignore_patterns = self.config["codeshield"].get("ignorePatterns", [])
        for pattern in ignore_patterns:
            if pattern in path:
                return False
        return True

    @staticmethod
    def _uri_to_path(uri: str) -> str:
        """Convert file URI to file path."""
        if uri.startswith("file://"):
            return uri[7:]
        return uri

    @staticmethod
    def _path_to_uri(path: str) -> str:
        """Convert file path to URI."""
        return f"file://{path}"

    def _is_scan_on_save_enabled(self) -> bool:
        """Check if scan on save is enabled."""
        return self.config["codeshield"].get("scanOnSave", True)

    def _get_severity_threshold(self) -> int:
        """Get severity threshold as numeric level."""
        threshold = self.config["codeshield"].get("severityThreshold", "LOW")
        order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        return order.get(threshold.upper(), 1)

    def _meets_threshold(self, severity: str) -> bool:
        """Check if a severity meets the configured threshold."""
        order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        vuln_level = order.get(severity.upper(), 0)
        threshold_level = self._get_severity_threshold()
        return vuln_level >= threshold_level


# =============================================================================
# Server Instance
# =============================================================================

server = CodeShieldLSPServer()


# =============================================================================
# Lifecycle Handlers
# =============================================================================

@server.feature("initialized")
def on_initialized(params: Any) -> None:
    """Handle server initialization completion."""
    logger.info("CodeShield LSP server initialized")
    server.show_message_log("CodeShield AI Security Scanner ready")

    # Register for configuration changes if client supports it
    if (
        server.lsp.client_capabilities
        and server.lsp.client_capabilities.workspace
        and getattr(server.lsp.client_capabilities.workspace, "did_change_configuration", False)
    ):
        server.lsp.register_capability(
            RegistrationParams(
                registrations=[
                    {
                        "id": "codeshield-config",
                        "method": "workspace/didChangeConfiguration",
                        "registerOptions": {"section": "codeshield"},
                    }
                ]
            )
        )


# =============================================================================
# Text Document Synchronization
# =============================================================================

@server.feature(TEXT_DOCUMENT_DID_OPEN)
async def on_document_open(params: DidOpenTextDocumentParams) -> None:
    """Handle document open - show cached diagnostics if available."""
    uri = params.text_document.uri
    logger.debug("Document opened: %s", uri)

    if uri in server.diagnostics_cache:
        server.lsp.publish_diagnostics(uri, server.diagnostics_cache[uri])


@server.feature(TEXT_DOCUMENT_DID_CHANGE)
def on_document_change(params: DidChangeTextDocumentParams) -> None:
    """Handle document change - we don't scan on change (only on save for accuracy)."""
    uri = params.text_document.uri
    logger.debug("Document changed: %s (diagnostics will update on save)", uri)
    # Intentionally no-op: we only scan on save for accuracy


@server.feature(TEXT_DOCUMENT_DID_SAVE)
async def on_document_save(params: DidSaveTextDocumentParams) -> None:
    """
    Handle document save - trigger security scan.

    This is the main scan entry point. We scan on save (not real-time)
    to ensure accurate, complete analysis.
    """
    uri = params.text_document.uri

    if not server._is_scan_on_save_enabled():
        logger.debug("Scan on save is disabled")
        return

    if not server.should_scan_file(uri):
        logger.debug("File ignored by pattern: %s", uri)
        return

    logger.info("Document saved, triggering scan: %s", uri)

    # Cancel any pending scan for this file
    if uri in server._pending_scans and not server._pending_scans[uri].done():
        server._pending_scans[uri].cancel()

    # Start new scan
    task = asyncio.create_task(_scan_document(uri))
    server._pending_scans[uri] = task


@server.feature(TEXT_DOCUMENT_DID_CLOSE)
def on_document_close(params: DidCloseTextDocumentParams) -> None:
    """Handle document close - clean up caches."""
    uri = params.text_document.uri
    logger.debug("Document closed: %s", uri)

    # Cancel pending scan
    if uri in server._pending_scans and not server._pending_scans[uri].done():
        server._pending_scans[uri].cancel()

    # Clear caches
    server.diagnostics_cache.pop(uri, None)
    server.vulnerability_cache.pop(uri, None)


# =============================================================================
# Diagnostics
# =============================================================================

async def _scan_document(uri: str) -> None:
    """
    Scan a document and publish diagnostics.

    This performs the actual security scan by:
    1. Collecting the file content
    2. Running security analysis (local or API)
    3. Converting results to LSP diagnostics
    4. Publishing diagnostics to the client
    """
    try:
        # Show scan started notification
        server.show_message(
            f"🔍 Scanning {Path(server._uri_to_path(uri)).name} for security issues...",
            MessageType.Info,
        )

        # Get file content and perform local pattern-based analysis
        # For the LSP server, we do quick local analysis
        path = server._uri_to_path(uri)

        try:
            content = Path(path).read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            logger.warning("Failed to read file %s: %s", path, e)
            return

        # Perform local pattern-based security analysis
        vulnerabilities = _local_security_scan(path, content)

        # Convert to diagnostics
        diagnostics = _vulnerabilities_to_diagnostics(vulnerabilities)

        # Cache results
        server.diagnostics_cache[uri] = diagnostics
        server.vulnerability_cache[uri] = vulnerabilities

        # Publish diagnostics
        server.lsp.publish_diagnostics(uri, diagnostics)

        # Show completion notification
        if diagnostics:
            critical = sum(1 for d in diagnostics if d.severity == DiagnosticSeverity.Error)
            warning = sum(1 for d in diagnostics if d.severity == DiagnosticSeverity.Warning)
            info = sum(1 for d in diagnostics if d.severity == DiagnosticSeverity.Information)

            msg_parts = []
            if critical:
                msg_parts.append(f"{critical} error(s)")
            if warning:
                msg_parts.append(f"{warning} warning(s)")
            if info:
                msg_parts.append(f"{info} info")

            server.show_message(
                f"⚠️ Found {' • '.join(msg_parts)} in {Path(path).name}",
                MessageType.Warning if critical > 0 else MessageType.Info,
            )
        else:
            server.show_message(
                f"✅ No security issues found in {Path(path).name}",
                MessageType.Info,
            )

    except asyncio.CancelledError:
        logger.debug("Scan cancelled for %s", uri)
    except Exception as e:
        logger.error("Scan failed for %s: %s", uri, e)
        server.show_message(f"❌ Scan failed: {e}", MessageType.Error)


def _local_security_scan(file_path: str, content: str) -> List[Dict[str, Any]]:
    """
    Perform a quick local security pattern scan.

    This uses regex patterns and heuristics for fast, local-only analysis.
    For comprehensive scanning, the CI/CD pipeline should be used.

    Args:
        file_path: Path to the file being scanned
        content: File content as string

    Returns:
        List of vulnerability dictionaries
    """
    vulnerabilities: List[Dict[str, Any]] = []
    lines = content.split("\n")
    file_ext = Path(file_path).suffix.lower()

    # Pattern definitions for common vulnerabilities
    patterns = _get_security_patterns(file_ext)

    for pattern_def in patterns:
        pattern = pattern_def["pattern"]
        for match in pattern.finditer(content):
            # Calculate line and column
            line_num = content[: match.start()].count("\n") + 1
            col = match.start() - content.rfind("\n", 0, match.start())

            line_content = lines[line_num - 1] if line_num <= len(lines) else ""

            vuln = {
                "id": f"local-{uuid.uuid4().hex[:8]}",
                "file_path": file_path,
                "line_number": line_num,
                "column": col,
                "severity": pattern_def["severity"],
                "category": pattern_def["category"],
                "cwe_id": pattern_def.get("cwe_id", ""),
                "cwe_name": pattern_def.get("cwe_name", ""),
                "title": pattern_def["title"],
                "description": pattern_def["description"],
                "code_snippet": line_content.strip(),
                "fix_suggestion": pattern_def.get("fix_suggestion", ""),
                "confidence": pattern_def.get("confidence", "MEDIUM"),
                "match_text": match.group()[:100],  # Truncate long matches
            }

            # Check threshold
            if server._meets_threshold(vuln["severity"]):
                vulnerabilities.append(vuln)

    # Limit diagnostics per file
    max_diag = server.config["codeshield"].get("maxDiagnosticsPerFile", 50)
    return vulnerabilities[:max_diag]


def _get_security_patterns(file_ext: str) -> List[Dict[str, Any]]:
    """Get security patterns for a given file extension."""
    # Common patterns for all languages
    common_patterns = [
        {
            "pattern": re.compile(
                r"password\s*=\s*[\"'][^\"']+[\"']|passwd\s*=\s*[\"'][^\"']+[\"']|pwd\s*=\s*[\"'][^\"']+[\"']",
                re.IGNORECASE,
            ),
            "severity": "HIGH",
            "category": "Hardcoded Password",
            "cwe_id": "CWE-798",
            "cwe_name": "Use of Hard-coded Credentials",
            "title": "Hardcoded password detected",
            "description": "A hardcoded password was found in the source code. Store credentials in environment variables or a secrets manager.",
            "fix_suggestion": "Use environment variables: password = os.environ.get('DB_PASSWORD')",
            "confidence": "MEDIUM",
        },
        {
            "pattern": re.compile(
                r"api[_-]?key\s*[:=]\s*[\"'][A-Za-z0-9_\\-]{20,}[\"']|apikey\s*[:=]\s*[\"'][A-Za-z0-9_\\-]{20,}[\"']",
                re.IGNORECASE,
            ),
            "severity": "HIGH",
            "category": "Hardcoded API Key",
            "cwe_id": "CWE-798",
            "cwe_name": "Use of Hard-coded Credentials",
            "title": "Hardcoded API key detected",
            "description": "A hardcoded API key was found. API keys should be stored in environment variables or a secrets manager.",
            "fix_suggestion": "Use environment variables: api_key = os.environ.get('API_KEY')",
            "confidence": "MEDIUM",
        },
        {
            "pattern": re.compile(
                r"secret\s*[:=]\s*[\"'][A-Za-z0-9_\\-]{20,}[\"']|token\s*[:=]\s*[\"'][A-Za-z0-9_\\-]{20,}[\"']",
                re.IGNORECASE,
            ),
            "severity": "HIGH",
            "category": "Hardcoded Secret",
            "cwe_id": "CWE-798",
            "cwe_name": "Use of Hard-coded Credentials",
            "title": "Hardcoded secret/token detected",
            "description": "A hardcoded secret or token was found. Secrets should be stored in environment variables.",
            "fix_suggestion": "Use environment variables or a secrets manager.",
            "confidence": "MEDIUM",
        },
        {
            "pattern": re.compile(
                r"eval\s*\(|exec\s*\(", re.IGNORECASE
            ),
            "severity": "HIGH",
            "category": "Code Injection",
            "cwe_id": "CWE-94",
            "cwe_name": "Improper Control of Generation of Code",
            "title": "Dangerous eval/exec usage",
            "description": "Use of eval() or exec() can lead to code injection vulnerabilities. Avoid executing dynamic code.",
            "fix_suggestion": "Use safer alternatives like ast.literal_eval() for parsing literals.",
            "confidence": "HIGH",
        },
        {
            "pattern": re.compile(
                r"http://[^\s\"']+", re.IGNORECASE
            ),
            "severity": "MEDIUM",
            "category": "Insecure Protocol",
            "cwe_id": "CWE-319",
            "cwe_name": "Cleartext Transmission of Sensitive Information",
            "title": "HTTP (non-HTTPS) URL detected",
            "description": "An HTTP URL was found. Use HTTPS for secure communication.",
            "fix_suggestion": "Replace http:// with https://",
            "confidence": "HIGH",
        },
    ]

    # Language-specific patterns
    lang_patterns: List[Dict[str, Any]] = []

    if file_ext in (".py",):
        lang_patterns = [
            {
                "pattern": re.compile(
                    r"\.execute\s*\(\s*[fF][\"']|\.execute\s*\(\s*\".*%s|\.execute\s*\(\s*'.*%s|\.raw\s*\(\s*[fF][\"']",
                    re.IGNORECASE,
                ),
                "severity": "CRITICAL",
                "category": "SQL Injection",
                "cwe_id": "CWE-89",
                "cwe_name": "SQL Injection",
                "title": "Possible SQL injection",
                "description": "Potential SQL injection vulnerability. User input may be directly concatenated into SQL queries.",
                "fix_suggestion": "Use parameterized queries: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                "confidence": "HIGH",
            },
            {
                "pattern": re.compile(
                    r"subprocess\.call\s*\(\s*[^,)]*\+|os\.system\s*\(|os\.popen\s*\("
                ),
                "severity": "HIGH",
                "category": "Command Injection",
                "cwe_id": "CWE-78",
                "cwe_name": "OS Command Injection",
                "title": "Potential command injection",
                "description": "User input may be passed to shell commands, leading to command injection.",
                "fix_suggestion": "Use subprocess with shell=False and pass arguments as a list.",
                "confidence": "MEDIUM",
            },
            {
                "pattern": re.compile(
                    r"pickle\.loads?\s*\(|yaml\.load\s*\([^)]*\)(?!.*Loader.*=.*yaml\.SafeLoader|.*Loader.*=.*yaml\.CSafeLoader)",
                    re.IGNORECASE,
                ),
                "severity": "HIGH",
                "category": "Insecure Deserialization",
                "cwe_id": "CWE-502",
                "cwe_name": "Deserialization of Untrusted Data",
                "title": "Insecure deserialization",
                "description": "pickle.loads() or yaml.load() without SafeLoader can lead to remote code execution.",
                "fix_suggestion": "Use yaml.safe_load() instead of yaml.load(). For pickle, validate data integrity.",
                "confidence": "HIGH",
            },
            {
                "pattern": re.compile(
                    r"hashlib\.md5\s*\(|\.md5\s*\("
                ),
                "severity": "MEDIUM",
                "category": "Weak Cryptography",
                "cwe_id": "CWE-328",
                "cwe_name": "Use of Weak Hash",
                "title": "Weak MD5 hash used",
                "description": "MD5 is cryptographically broken. Use SHA-256 or stronger for security-sensitive operations.",
                "fix_suggestion": "Use hashlib.sha256() instead of hashlib.md5()",
                "confidence": "HIGH",
            },
            {
                "pattern": re.compile(
                    r"render_template_string\s*\(|\.from_string\s*\(.*request\.|jinja2\.Template\(.*\+"
                ),
                "severity": "CRITICAL",
                "category": "Server-Side Template Injection",
                "cwe_id": "CWE-1336",
                "cwe_name": "Server-Side Template Injection",
                "title": "Potential SSTI vulnerability",
                "description": "User input is passed to a template rendering function, which can lead to server-side template injection.",
                "fix_suggestion": "Use render_template() with static template files instead of render_template_string().",
                "confidence": "MEDIUM",
            },
            {
                "pattern": re.compile(
                    r"debug\s*=\s*True|DEBUG\s*=\s*True|app\.run\s*\(.*debug\s*=\s*True"
                ),
                "severity": "MEDIUM",
                "category": "Debug Mode Enabled",
                "cwe_id": "CWE-489",
                "cwe_name": "Active Debug Code",
                "title": "Debug mode enabled",
                "description": "Debug mode should not be enabled in production as it can leak sensitive information.",
                "fix_suggestion": "Set debug=False in production: app.run(debug=os.environ.get('DEBUG', 'False') == 'True')",
                "confidence": "HIGH",
            },
        ]
    elif file_ext in (".js", ".ts", ".jsx", ".tsx"):
        lang_patterns = [
            {
                "pattern": re.compile(
                    r"innerHTML\s*=|document\.write\s*\("
                ),
                "severity": "HIGH",
                "category": "Cross-Site Scripting (XSS)",
                "cwe_id": "CWE-79",
                "cwe_name": "Cross-site Scripting",
                "title": "Potential XSS vulnerability",
                "description": "innerHTML and document.write can lead to XSS if user input is used without sanitization.",
                "fix_suggestion": "Use textContent instead of innerHTML, or sanitize input with DOMPurify.",
                "confidence": "MEDIUM",
            },
            {
                "pattern": re.compile(
                    r"eval\s*\(|new\s+Function\s*\("
                ),
                "severity": "CRITICAL",
                "category": "Code Injection",
                "cwe_id": "CWE-94",
                "cwe_name": "Code Injection",
                "title": "Dangerous eval/new Function usage",
                "description": "eval() and new Function() execute arbitrary code and should be avoided.",
                "fix_suggestion": "Use JSON.parse() for JSON data or safer alternatives.",
                "confidence": "HIGH",
            },
        ]
    elif file_ext in (".java",):
        lang_patterns = [
            {
                "pattern": re.compile(
                    r"Statement\.execute\s*\(\s*[^)]+\+|createStatement\s*\(\)"
                ),
                "severity": "CRITICAL",
                "category": "SQL Injection",
                "cwe_id": "CWE-89",
                "cwe_name": "SQL Injection",
                "title": "Potential SQL injection",
                "description": "Use PreparedStatement to prevent SQL injection.",
                "fix_suggestion": "Use PreparedStatement with parameterized queries.",
                "confidence": "HIGH",
            },
            {
                "pattern": re.compile(
                    r"ObjectInputStream|readObject\s*\("
                ),
                "severity": "HIGH",
                "category": "Insecure Deserialization",
                "cwe_id": "CWE-502",
                "cwe_name": "Deserialization of Untrusted Data",
                "title": "Java deserialization vulnerability",
                "description": "ObjectInputStream.readObject() can lead to remote code execution.",
                "fix_suggestion": "Use JSON for data interchange or implement look-ahead deserialization.",
                "confidence": "HIGH",
            },
        ]
    elif file_ext in (".go",):
        lang_patterns = [
            {
                "pattern": re.compile(
                    r"exec\.Command\s*\(\s*[^,)]*\+"
                ),
                "severity": "HIGH",
                "category": "Command Injection",
                "cwe_id": "CWE-78",
                "cwe_name": "OS Command Injection",
                "title": "Potential command injection",
                "description": "String concatenation in exec.Command can lead to command injection.",
                "fix_suggestion": "Use exec.Command() with separate arguments, not string concatenation.",
                "confidence": "MEDIUM",
            },
        ]

    return common_patterns + lang_patterns


def _vulnerabilities_to_diagnostics(vulnerabilities: List[Dict[str, Any]]) -> List[Diagnostic]:
    """Convert vulnerability dictionaries to LSP diagnostics."""
    diagnostics: List[Diagnostic] = []

    for vuln in vulnerabilities:
        severity = SEVERITY_MAP.get(vuln["severity"].upper(), DiagnosticSeverity.Warning)

        # Create diagnostic tags
        tags = []
        if vuln["category"] in ("Hardcoded Password", "Hardcoded API Key", "Hardcoded Secret"):
            tags.append(DiagnosticTag.Unnecessary)

        # Build diagnostic
        diagnostic = Diagnostic(
            range=Range(
                start=Position(
                    line=vuln["line_number"] - 1,  # LSP uses 0-based lines
                    character=max(0, vuln.get("column", 1) - 1),
                ),
                end=Position(
                    line=vuln["line_number"] - 1,
                    character=max(0, vuln.get("column", 1) - 1)
                    + len(vuln.get("match_text", vuln["code_snippet"])),
                ),
            ),
            message=f"[{vuln['severity']}] {vuln['title']}: {vuln['description']}",
            severity=severity,
            code=vuln.get("cwe_id", vuln["category"]),
            source="codeshield-ai",
            tags=tags if tags else None,
            related_information=None,
            data={
                "id": vuln["id"],
                "category": vuln["category"],
                "cwe_id": vuln.get("cwe_id"),
                "cwe_name": vuln.get("cwe_name"),
                "fix_suggestion": vuln.get("fix_suggestion"),
                "confidence": vuln.get("confidence"),
                "code_snippet": vuln.get("code_snippet"),
            },
        )
        diagnostics.append(diagnostic)

    return diagnostics


# =============================================================================
# Hover Information
# =============================================================================

@server.feature(TEXT_DOCUMENT_HOVER)
async def on_hover(params: HoverParams) -> Optional[Hover]:
    """
    Provide hover information for vulnerabilities.

    When hovering over a line with a vulnerability, show details
    about the security issue.
    """
    if not server.config["codeshield"].get("enableHover", True):
        return None

    uri = params.text_document.uri
    position = params.position

    if uri not in server.vulnerability_cache:
        return None

    # Find vulnerability at cursor position
    vulns = server.vulnerability_cache[uri]
    for vuln in vulns:
        vuln_line = vuln["line_number"] - 1  # Convert to 0-based
        if vuln_line == position.line:
            emoji = SEVERITY_EMOJI.get(vuln["severity"], "⚠️")

            hover_content = f"""### {emoji} {vuln['title']}

**Severity:** {vuln['severity']}
**Category:** {vuln['category']}
**CWE:** {vuln.get('cwe_id', 'N/A')} - {vuln.get('cwe_name', 'N/A')}
**Confidence:** {vuln.get('confidence', 'N/A')}

**Description:**
{vuln['description']}

**Fix Suggestion:**
{vuln.get('fix_suggestion', 'Review and fix based on CWE guidelines.')}

*Detected by CodeShield AI*"""

            return Hover(
                contents=MarkupContent(kind=MarkupKind.Markdown, value=hover_content)
            )

    return None


# =============================================================================
# Code Actions
# =============================================================================

@server.feature(
    TEXT_DOCUMENT_CODE_ACTION,
    CodeActionOptions(code_action_kinds=[CodeActionKind.QuickFix]),
)
async def on_code_action(params: CodeActionParams) -> Optional[List[CodeAction]]:
    """
    Provide code actions (quick fixes) for vulnerabilities.

    Currently supported actions:
    - "Apply Fix": Apply the suggested fix for a vulnerability
    - "Ignore Rule": Add a suppression comment
    """
    if not server.config["codeshield"].get("enableCodeActions", True):
        return None

    uri = params.text_document.uri
    range_ = params.range

    if uri not in server.vulnerability_cache:
        return None

    actions: List[CodeAction] = []

    # Find vulnerabilities in the requested range
    vulns = server.vulnerability_cache[uri]
    for vuln in vulns:
        vuln_line = vuln["line_number"] - 1
        if range_.start.line <= vuln_line <= range_.end.line:
            # "Apply Fix" action
            if vuln.get("fix_suggestion"):
                fix_title = f"🔧 Fix: {vuln['title'][:50]}"
                fix_action = CodeAction(
                    title=fix_title,
                    kind=CodeActionKind.QuickFix,
                    diagnostics=[
                        d
                        for d in server.diagnostics_cache.get(uri, [])
                        if d.range.start.line == vuln_line
                    ],
                    edit=WorkspaceEdit(
                        document_changes=None,
                        changes={
                            uri: [
                                TextEdit(
                                    range=Range(
                                        start=Position(line=vuln_line, character=0),
                                        end=Position(line=vuln_line + 1, character=0),
                                    ),
                                    new_text=f"# FIXME [{vuln['cwe_id'] or vuln['category']}]: {vuln['fix_suggestion']}\n{vuln.get('code_snippet', '')}\n",
                                )
                            ]
                        },
                    ),
                    command=None,
                    is_preferred=False,
                    disabled=None,
                )
                actions.append(fix_action)

            # "Ignore This" action
            ignore_title = f"🚫 Ignore: {vuln['title'][:50]}"
            ignore_action = CodeAction(
                title=ignore_title,
                kind=CodeActionKind.QuickFix,
                diagnostics=[
                    d
                    for d in server.diagnostics_cache.get(uri, [])
                    if d.range.start.line == vuln_line
                ],
                edit=WorkspaceEdit(
                    changes={
                        uri: [
                            TextEdit(
                                range=Range(
                                    start=Position(line=vuln_line, character=0),
                                    end=Position(line=vuln_line, character=0),
                                ),
                                new_text=f"# codeshield: ignore [{vuln.get('cwe_id', vuln['category'])}]\n",
                            )
                        ]
                    },
                ),
                command=None,
                is_preferred=False,
            )
            actions.append(ignore_action)

    return actions if actions else None


# =============================================================================
# Configuration
# =============================================================================

@server.feature(WORKSPACE_DID_CHANGE_CONFIGURATION)
def on_configuration_change(params: DidChangeConfigurationParams) -> None:
    """Handle workspace configuration changes."""
    settings = params.settings
    if settings and "codeshield" in settings:
        new_config = settings["codeshield"]
        server.config["codeshield"].update(new_config)
        logger.info("Configuration updated: %s", server.config["codeshield"])
        server.show_message("CodeShield configuration updated", MessageType.Info)


# =============================================================================
# Commands
# =============================================================================

@server.command("codeshield.scanNow")
async def cmd_scan_now(ls: CodeShieldLSPServer, params: Any) -> Dict[str, Any]:
    """Command: Manually trigger a scan on the current document."""
    if not params or not hasattr(params, "uri"):
        return {"status": "error", "message": "No document URI provided"}

    uri = params.uri
    await _scan_document(uri)
    vulns = server.vulnerability_cache.get(uri, [])
    return {
        "status": "completed",
        "vulnerabilities_found": len(vulns),
        "severity_breakdown": {
            "critical": sum(1 for v in vulns if v["severity"] == "CRITICAL"),
            "high": sum(1 for v in vulns if v["severity"] == "HIGH"),
            "medium": sum(1 for v in vulns if v["severity"] == "MEDIUM"),
            "low": sum(1 for v in vulns if v["severity"] == "LOW"),
        },
    }


@server.command("codeshield.scanWorkspace")
async def cmd_scan_workspace(ls: CodeShieldLSPServer, params: Any) -> Dict[str, Any]:
    """Command: Trigger a scan on the entire workspace."""
    server.show_message(
        "🔍 Workspace scan started... (scanning all open files)",
        MessageType.Info,
    )

    results = {"files_scanned": 0, "total_vulnerabilities": 0}

    for uri in list(server.diagnostics_cache.keys()):
        try:
            await _scan_document(uri)
            results["files_scanned"] += 1
            results["total_vulnerabilities"] += len(
                server.vulnerability_cache.get(uri, [])
            )
        except Exception as e:
            logger.error("Workspace scan failed for %s: %s", uri, e)

    server.show_message(
        f"✅ Workspace scan complete: {results['total_vulnerabilities']} issues in {results['files_scanned']} files",
        MessageType.Info,
    )

    return results


@server.command("codeshield.getStatus")
async def cmd_get_status(ls: CodeShieldLSPServer, params: Any) -> Dict[str, Any]:
    """Command: Get current scan status."""
    return {
        "server_status": "running",
        "config": {
            "scanOnSave": server.config["codeshield"].get("scanOnSave", True),
            "severityThreshold": server.config["codeshield"].get("severityThreshold", "LOW"),
        },
        "cached_files": len(server.diagnostics_cache),
        "pending_scans": sum(
            1 for t in server._pending_scans.values() if not t.done()
        ),
    }


@server.command("codeshield.clearDiagnostics")
async def cmd_clear_diagnostics(
    ls: CodeShieldLSPServer, params: Any
) -> Dict[str, Any]:
    """Command: Clear all diagnostics."""
    for uri in list(server.diagnostics_cache.keys()):
        server.lsp.publish_diagnostics(uri, [])

    server.diagnostics_cache.clear()
    server.vulnerability_cache.clear()

    return {"status": "cleared"}


# =============================================================================
# Main Entry Point
# =============================================================================

def main() -> None:
    """Run the LSP server."""
    import argparse

    parser = argparse.ArgumentParser(description="CodeShield AI LSP Server")
    parser.add_argument("--port", type=int, default=8211, help="Server port (TCP)")
    parser.add_argument(
        "--stdio", action="store_true", help="Use stdio for communication"
    )
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Server host")

    args = parser.parse_args()

    if args.stdio:
        server.start_io()
    else:
        server.start_tcp(args.host, args.port)


if __name__ == "__main__":
    main()
