"""
LLM-Generated Code Security Scanner for CodeShield AI.

Detects AI-generated code patterns (Copilot/ChatGPT signatures), AI-specific
vulnerabilities, insecure LLM API usage, OWASP LLM Top 10 issues, and MCP
(Model Context Protocol) security problems.

Detection categories:
- AI-generated code signatures (hallucinated APIs, insecure defaults, etc.)
- AI-specific vulnerabilities (missing error handling, placeholder auth, etc.)
- Insecure LLM API usage (hardcoded keys, prompt injection, etc.)
- OWASP LLM Top 10 (LLM01-LLM10)
- MCP security scanning (tool poisoning, privilege escalation)
"""

import ast
import math
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Pattern, Tuple

from models.vulnerability import Vulnerability
from utils.constants import CWE_MAPPING
from utils.helpers import read_file_snippet
from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# AI-Generated Code Signatures
# ---------------------------------------------------------------------------

# Patterns that suggest AI-generated code (Copilot/ChatGPT signatures)
AI_CODE_SIGNATURES = [
    # Overly verbose comments that explain obvious code
    (r"#\s*This function\s+(?:is used to|will|handles?|takes|accepts)",
     "Verbose AI-style comment"),
    # Generic function docstrings
    (r'"""\s*\n\s*(?:This (?:function|method|class)|A (?:function|method|class) that)',
     "Generic AI docstring pattern"),
    # Generic docstring summary line (AI often writes "A function that ...")
    (r"^\s*(?:This|A|An)\s+(?:function|method|class|module|script)\s+(?:that\s+)?(?:is\s+used\s+to|handles?|processes?|manages?|takes|accepts|returns|will)\b",
     "Generic AI docstring summary line"),
    # TODO comments left by AI
    (r"#\s*TODO:\s*(?:Add (?:error|validation|authentication|authorization)|Implement)",
     "AI-generated TODO placeholder"),
    # Common AI import patterns
    (r"#\s*Import necessary (?:libraries|modules|packages)",
     "AI-style import comment"),
    # Hallucinated/incorrect comments
    (r"#\s*Note: This (?:may|might|should) work",
     "Tentative AI comment"),
]

# ---------------------------------------------------------------------------
# AI-Specific Vulnerability Patterns
# ---------------------------------------------------------------------------

# Hallucinated API calls (functions that don't exist in popular libraries)
HALLUCINATED_API_PATTERNS = [
    # Python - common AI hallucinations
    (r"requests\.send_request\(", "requests does not have send_request()"),
    (r"json\.parse\(", "Python uses json.loads(), not json.parse()"),
    (r"os\.get_dir\(", "os does not have get_dir() - use os.listdir() or os.scandir()"),
    (r"datetime\.now\.format\(", "datetime.now() returns a datetime object, not a formattable string"),
    (r"flask\.create_app\(", "Flask does not have a create_app() function at module level"),
    (r"django\.setup_app\(", "Django does not have setup_app()"),
    (r"pandas\.Dataframe\(", "Correct class name is DataFrame (capital F)"),
    (r"numpy\.array\.tolist\(", "tolist() is called on array instances, not the array class"),
    (r"re\.find\(", "re module has findall() and search(), not find()"),
    (r"socket\.connect_to\(", "socket has connect(), not connect_to()"),
    # JavaScript/Node.js hallucinations
    (r"fs\.read\(", "fs has readFile() and readFileSync(), not read()"),
    (r"express\.createServer\(", "Express uses express() not createServer()"),
    (r"document\.find\(", "DOM has querySelector() and getElementById(), not find()"),
    (r"window\.fetchJSON\(", "Use fetch() with response.json()"),
    # Java hallucinations
    (r"ArrayList\.sortBy\(", "Use Collections.sort() or List.sort()"),
    (r"String\.isEmpty\s*\(\s*\)", "String.isEmpty() is correct but commonly misused context"),
]

# Over-permissive CORS patterns (AI often generates `*`)
AI_CORS_PATTERNS = [
    (r"(?i)(Access-Control-Allow-Origin\s*:\s*\*)",
     "AI-generated permissive CORS wildcard"),
    (r"(?i)(cors\s*\(\s*\{\s*origin\s*:\s*['\"]?\*['\"]?)",
     "AI-generated Express CORS wildcard"),
    (r"(?i)(@CrossOrigin\s*\(\s*origins\s*=\s*['\"]?\*['\"]?)",
     "AI-generated Spring CORS wildcard"),
    (r"(?i)(res\.header\s*\(\s*['\"]Access-Control-Allow-Origin['\"]\s*,\s*['\"]\*['\"])",
     "AI-generated manual CORS wildcard"),
    (r"(?i)(app\.use\s*\(\s*cors\s*\(\s*\)\s*\))",
     "AI-generated default CORS middleware (allows all origins)"),
    (r"(?i)(cors\.AllowAllOrigins\s*=\s*true)",
     "AI-generated Go CORS allow all"),
]

# Missing error handling (AI code often lacks try/catch)
MISSING_ERROR_HANDLING_PATTERNS = [
    # Database calls without try/catch
    (r"(cursor\.execute|session\.(query|add|commit)|Model\.query)",
     "Database operation without error handling"),
    # File operations without try/catch
    (r"(open\s*\(|fs\.(readFile|writeFile)|with\s+open)",
     "File operation that should have error handling"),
    # Network calls without error handling
    (r"(requests\.(get|post|put|delete)|fetch\s*\(|axios\.(get|post))",
     "Network call without error handling"),
    # LLM API calls without error handling
    (r"(openai\.(ChatCompletion|Completion)|anthropic|completion)",
     "LLM API call without error handling"),
]

# Insecure defaults (AI generates example/demo configs)
AI_INSECURE_DEFAULTS = [
    # Hardcoded demo secrets
    (r"(?i)(SECRET_KEY\s*=\s*['\"](?:secret|key|change-me|your-secret|example))",
     "AI-generated hardcoded demo secret key"),
    (r"(?i)(DEBUG\s*=\s*True)",
     "AI-generated DEBUG=True in production-like code"),
    (r"(?i)(ALLOWED_HOSTS\s*=\s*\[['\"]\*['\"]\])",
     "AI-generated Django ALLOWED_HOSTS wildcard"),
    # Insecure session config
    (r"(?i)(SESSION_COOKIE_SECURE\s*=\s*False)",
     "AI-generated insecure session cookie setting"),
    (r"(?i)(CSRF_COOKIE_SECURE\s*=\s*False)",
     "AI-generated insecure CSRF cookie setting"),
    # Admin credentials
    (r"(?i)(ADMIN_PASSWORD\s*=\s*['\"](?:admin|password|123456))",
     "AI-generated default admin password"),
    (r"(?i)(DEFAULT_PASSWORD\s*=\s*['\"](?:password|admin|1234))",
     "AI-generated default password"),
    # Insecure SSL/TLS
    (r"(?i)(verify\s*=\s*False)",
     "AI-generated SSL verification disabled"),
    (r"(?i)(ssl_verify\s*=\s*False)",
     "AI-generated SSL verification disabled"),
    # Docker insecure defaults
    (r"(?i)(FROM\s+python:.*\n.*RUN\s+pip\s+install.*--no-cache)",
     "Dockerfile may need security review"),
    # Kubernetes insecure
    (r"(?i)(privileged:\s*true)",
     "AI-generated privileged container"),
    (r"(?i)(runAsUser:\s*0)",
     "AI-generated container running as root"),
    (r"(?i)(allowPrivilegeEscalation:\s*true)",
     "AI-generated privilege escalation allowed"),
]

# Fake/mocked authentication (AI generates placeholder auth)
AI_PLACEHOLDER_AUTH = [
    # Always-true auth checks
    (r"(?i)(if\s+.*:\s*\n\s*return\s+True\s*\n\s*#\s*TODO.*auth)"
     r"|(def\s+is_authenticated\s*\(\s*\)\s*:\s*\n\s*return\s+True)",
     "AI-generated always-true authentication placeholder"),
    # Commented-out auth
    (r"(?i)(#\s*@login_required\n|#\s*@require_auth\n|#\s*auth_check\s*\()",
     "AI-generated commented-out authentication"),
    # Dummy auth middleware
    (r"(?i)(def\s+auth_middleware\s*\(.*\)\s*:\s*\n\s*pass\s*$"
     r"|class\s+AuthMiddleware\s*:\s*\n\s*def\s+__call__\s*\(\s*self.*\)\s*:\s*\n\s*return)",
     "AI-generated dummy auth middleware"),
    # Placeholder JWT verification
    (r"(?i)(jwt\.decode\s*\(\s*token\s*,\s*['\"](?:secret|key|placeholder))",
     "AI-generated placeholder JWT secret"),
    # No-op permission checks
    (r"(?i)(def\s+check_permission\s*\(.*\)\s*:\s*\n\s*return\s+True)"
     r"|(def\s+has_permission\s*\(.*\)\s*:\s*\n\s*return\s+True)",
     "AI-generated no-op permission check"),
]

# ---------------------------------------------------------------------------
# Insecure LLM API Usage Patterns
# ---------------------------------------------------------------------------

# Hardcoded LLM API keys
HARDCODED_LLM_KEY_PATTERNS = [
    (r"(?i)(openai[_-]?api[_-]?key\s*[:=]\s*['\"]sk-[a-zA-Z0-9]{20,}['\"])",
     "Hardcoded OpenAI API key"),
    (r"(?i)(anthropic[_-]?api[_-]?key\s*[:=]\s*['\"]sk-ant-[a-zA-Z0-9]{20,}['\"])",
     "Hardcoded Anthropic API key"),
    (r"(?i)(cohere[_-]?api[_-]?key\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"])",
     "Hardcoded Cohere API key"),
    (r"(?i)(huggingface[_-]?token\s*[:=]\s*['\"]hf_[a-zA-Z0-9]{20,}['\"])",
     "Hardcoded Hugging Face token"),
    (r"(?i)(google[_-]?api[_-]?key\s*[:=]\s*['\"]AIza[0-9A-Za-z_-]{33,}['\"])",
     "Hardcoded Google API key"),
    (r"(?i)(replicate[_-]?api[_-]?token\s*[:=]\s*['\"]r8_[a-zA-Z0-9]{20,}['\"])",
     "Hardcoded Replicate API token"),
    (r"(?i)(together[_-]?api[_-]?key\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"])",
     "Hardcoded Together AI API key"),
    (r"(?i)(mistral[_-]?api[_-]?key\s*[:=]\s*['\"][a-zA-Z0-9]{20,}['\"])",
     "Hardcoded Mistral API key"),
    (r"(?i)(groq[_-]?api[_-]?key\s*[:=]\s*['\"]gsk_[a-zA-Z0-9]{20,}['\"])",
     "Hardcoded Groq API key"),
    # Generic OpenAI-style key assigned to any *api*key/secret/token variable
    (r"(?i)(?:api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token)\s*[:=]\s*['\"]sk-[a-zA-Z0-9]{16,}['\"]",
     "Hardcoded OpenAI-style API key"),
]

# Missing input validation before LLM calls
LLM_INPUT_VALIDATION_PATTERNS = [
    (r"(?i)(openai\.(?:ChatCompletion|chat\.completions)\.create\s*\(\s*messages\s*=)"
     r"(?!.*(?:validate|sanitize|check|filter|length|limit))",
     "LLM API call without input validation"),
    (r"(?i)(anthropic\.(?:Client|messages)\.create\s*\(\s*)",
     "Anthropic API call - verify input validation exists"),
    (r"(?i)(requests\.(?:get|post)\s*\(\s*['\"]https://api\.openai\.com)"
     r"(?!.*(?:validate|sanitize|check))",
     "Direct OpenAI API HTTP call without input validation"),
]

# Unsanitized LLM output usage
LLM_OUTPUT_SANITIZATION_PATTERNS = [
    # LLM output used in eval/exec
    (r"(?i)(eval\s*\(\s*(?:response|completion|result|output)\s*\))",
     "LLM output used in eval() - prompt injection risk"),
    (r"(?i)(exec\s*\(\s*(?:response|completion|result|output)\s*\))",
     "LLM output used in exec() - prompt injection risk"),
    # LLM output used in SQL
    (r"(?i)(cursor\.execute\s*\(\s*(?:response|completion|result|output))",
     "LLM output used in SQL query - injection risk"),
    # LLM output rendered as HTML
    (r"(?i)((?:innerHTML|dangerouslySetInnerHTML|\.html\s*\(\s*)\s*=\s*(?:response|completion|result|output))",
     "LLM output rendered as HTML - XSS risk"),
    # LLM output used in system calls
    (r"(?i)(os\.system\s*\(\s*(?:response|completion|result|output))"
     r"|(subprocess\.(?:run|call|Popen)\s*\(\s*(?:response|completion|result|output))",
     "LLM output used in system command - RCE risk"),
    # LLM output written to file without validation
    (r"(?i)(open\s*\(\s*(?:response|completion|result|output)\s*,\s*['\"]w)"
     r"|(write|writelines)\s*\(\s*(?:response|completion|result|output)\s*\)",
     "LLM output written to file without validation"),
]

# Prompt injection vulnerabilities in RAG applications
RAG_PROMPT_INJECTION_PATTERNS = [
    # Direct prompt injection via user input in system prompt
    (r"(?i)(system_prompt\s*=\s*f?['\"].*\{.*(?:user_input|query|input|text|request).*)",
     "User input interpolated into system prompt - direct prompt injection"),
    # Context stuffing without sanitization
    (r"(?i)(context\s*=\s*f?['\"].*\{.*(?:document|chunk|retrieved|search).*)"
     r"(?!.*(?:sanitize|escape|filter))",
     "Retrieved documents injected into prompt without sanitization"),
    # No delimiter between system prompt and user content
    (r"(?i)(prompt\s*=\s*f?['\"].*System:.*User:.*)"
     r"(?!.*(?:delimiter|separator|<\|))",
     "No clear delimiter between system prompt and user content"),
    # Missing instruction boundaries
    (r"(?i)(f?['\"]You are.*helpful.*assistant['\"].*\+\s*(?:user_input|query))",
     "User input concatenated to system instruction without boundary"),
    # RAG with no context validation
    (r"(?i)(retriever\.(?:retrieve|search|get_relevant).*\n.*prompt\s*=)"
     r"(?!.*(?:validate|sanitize))",
     "RAG retrieval result used directly in prompt without validation"),
]

# Missing system prompt boundaries
SYSTEM_PROMPT_BOUNDARY_PATTERNS = [
    # System prompt without instruction defense
    (r"(?i)(system_prompt\s*=\s*['\"].{0,200}['\"])"
     r"(?!.*(?:ignore previous|disregard|do not follow))",
     "System prompt may lack instruction integrity defenses"),
    # No prompt sealing
    (r"(?i)(messages\s*=\s*\[.*\{.*['\"]system['\"].*\}.*\{.*['\"]user['\"].*\}\])"
     r"(?!.*(?:seal|delimiter|<\|))",
     "No prompt sealing or delimiters between message roles"),
]

# ---------------------------------------------------------------------------
# OWASP LLM Top 10 Patterns
# ---------------------------------------------------------------------------

OWASP_LLM_PATTERNS: Dict[str, List[Tuple[str, str]]] = {
    "LLM01": [  # Prompt Injection (Direct and Indirect)
        (r"(?i)(system.*prompt.*\{.*user|user.*input.*system.*prompt)"
         r"|(f['\"].*You are.*\{.*\}.*respond)",
         "LLM01: Potential direct prompt injection - user input in system prompt"),
        (r"(?i)(retrieved.*context.*user.*input|document.*inject.*prompt)"
         r"|(context.*data.*passed.*llm.*unsanitized)",
         "LLM01: Potential indirect prompt injection via context"),
    ],
    "LLM02": [  # Insecure Output Handling
        (r"(?i)(eval\s*\(\s*response|exec\s*\(\s*llm|response.*innerHTML)"
         r"|(llm_output.*system|completion.*subprocess)",
         "LLM02: Insecure handling of LLM output"),
        (r"(?i)(json\.loads\s*\(\s*(?:response|completion)\s*\).*(?:except\s*JSONDecodeError)?)"
         r"(?!.*except)",
         "LLM02: LLM JSON output parsed without error handling"),
    ],
    "LLM03": [  # Training Data Poisoning
        (r"(?i)(fine.?tune.*custom.*dataset|train.*on.*user.*data)"
         r"(?!.*(?:validate|sanitize|audit))",
         "LLM03: Training data source not validated"),
        (r"(?i)(load_dataset\s*\(\s*(?:url|path)\s*=.*(?!verify))",
         "LLM03: External dataset loaded without verification"),
    ],
    "LLM04": [  # Model Denial of Service
        (r"(?i)(max_tokens\s*=\s*\d{5,}|no.*token.*limit|unbounded.*request)"
         r"|(while\s+True.*llm|recursive.*call.*api)",
         "LLM04: Unbounded resource consumption - potential model DoS"),
        (r"(?i)(requests\.(?:get|post)\s*\(.*timeout\s*=\s*(?:None|0)\))"
         r"|(openai.*create.*(?!max_tokens))",
         "LLM04: API call without resource limits"),
    ],
    "LLM05": [  # Supply Chain Vulnerabilities
        (r"(?i)(pip\s+install\s+.*--index-url|npm\s+install\s+.*--registry)"
         r"(?!.*trusted|official)",
         "LLM05: Package installed from untrusted source"),
        (r"(?i)(pickle\.(?:load|loads)\s*\(|yaml\.load\s*\(.*Loader\s*=\s*yaml\.(?:Loader|UnsafeLoader))",
         "LLM05: Unsafe deserialization in ML pipeline"),
    ],
    "LLM06": [  # Sensitive Information Disclosure
        (r"(?i)(return\s+.*error.*traceback.*to.*client|send.*exception.*user)"
         r"|(debug\s*=\s*True.*production|log.*api_key|print\s*\(\s*(?:secret|token|key))",
         "LLM06: Sensitive information may be disclosed"),
        (r"(?i)(response.*include.*system.*prompt|reveal.*instructions.*to.*user)",
         "LLM06: System prompt/instructions may leak to user"),
        (r"(?i)((?:return|response|jsonify|render|send)\b.*traceback\.format_exc\s*\(\s*\))"
         r"|(traceback\.format_exc\s*\(\s*\).*(?:return|response|jsonify))",
         "LLM06: Exception traceback returned to client"),
    ],
    "LLM07": [  # Insecure Plugin Design
        (r"(?i)(plugin.*exec\s*\(|tool.*eval\s*\(|extension.*system.*call)"
         r"|(register.*tool\s*\(\s*function\s*=.*eval)",
         "LLM07: Plugin/Tool uses insecure code execution"),
        (r"(?i)(tool.*no.*validation|plugin.*input.*unsanitized)"
         r"|(allow_all.*tools|disable_security.*plugin)",
         "LLM07: Plugin input not validated"),
    ],
    "LLM08": [  # Excessive Agency
        (r"(?i)(auto.*execute|auto.*run|auto.*deploy|self.*acting)"
         r"|(allow.*llm.*write.*file|llm.*modify.*database)",
         "LLM08: Excessive agency - LLM can perform dangerous actions"),
        (r"(?i)(tool.*delete.*permission|llm.*admin.*access|grant.*all.*privileges)"
         r"|(bypass.*approval|skip.*confirmation)",
         "LLM08: LLM granted excessive permissions"),
    ],
    "LLM09": [  # Overreliance
        (r"(?i)(trust.*llm.*output|use.*llm.*for.*security.*decision)"
         r"|(llm.*authenticate|llm.*authorize|llm.*validate.*input)",
         "LLM09: Critical security decision delegated to LLM"),
        (r"(?i)(no.*human.*review|fully.*automated.*llm|blind.*trust)"
         r"|(skip.*verification.*llm.*output)",
         "LLM09: No human review of LLM outputs for critical operations"),
        (r"(?i)(?:auth\w*|authz|decision|verdict|access|permission|approv\w*)\s*=\s*[^=\n]*"
         r"\b(?:llm|model|gpt|openai|claude|chat|completion)\w*\.\s*"
         r"(?:evaluate|decide|predict|classify|complete|generate|judge|assess)",
         "LLM09: Security/auth decision delegated to LLM output"),
    ],
    "LLM10": [  # Model Theft
        (r"(?i)(model.*download.*endpoint|/download.*model|export.*weights)"
         r"(?!.*(?:auth|authenticate|authorize))",
         "LLM10: Model/weights accessible without authentication"),
        (r"(?i)(model.*served.*publicly|api.*expose.*architecture)"
         r"|(replicate\s*model|clone\s*weights)",
         "LLM10: Model architecture or weights may be exposed"),
    ],
}

# ---------------------------------------------------------------------------
# MCP (Model Context Protocol) Security Patterns
# ---------------------------------------------------------------------------

MCP_SECURITY_PATTERNS: List[Tuple[str, str, str]] = [
    # Tool poisoning attacks
    (r"(?i)(tool.*description\s*=\s*f?['\"].*\{.*user_input|"
     r"function.*docstring.*injected.*parameter)",
     "MCP: Tool description may be poisoned with user input",
     "MCP-Tool-Poisoning"),

    # Malicious tool descriptions
    (r"(?i)(tool.*description.*ignore.*previous|function.*schema.*override|"
     r"mcp.*tool.*redefined.*runtime)",
     "MCP: Tool description may contain malicious instructions",
     "MCP-Malicious-Description"),

    # Privilege escalation via MCP tools
    (r"(?i)(mcp.*tool.*admin|tool.*bypass.*auth|mcp.*escalate.*privilege|"
     r"tool.*grant.*permission.*higher)",
     "MCP: Potential privilege escalation through MCP tools",
     "MCP-Privilege-Escalation"),

    # Unrestricted MCP tool access
    (r"(?i)(mcp.*allow_all_tools|tool.*permission\s*=\s*['\"]?\*['\"]?|"
     r"all_tools.*enabled.*true|disable_tool_validation)",
     "MCP: All MCP tools allowed without restriction",
     "MCP-Unrestricted-Tools"),

    # MCP tool input not validated
    (r"(?i)(mcp.*call_tool.*\(.*\w+\s*=\s*(?!.*validate|sanitize).*\w+_input|"
     r"execute.*tool.*args.*raw)",
     "MCP: MCP tool arguments not validated before execution",
     "MCP-Unvalidated-Input"),

    # MCP server without auth
    (r"(?i)(mcp.*server.*no.*auth|mcp.*transport.*without.*verify|"
     r"mcp.*stdio.*no.*validation)",
     "MCP: MCP server connection without authentication",
     "MCP-Unauthenticated-Server"),

    # Tool result trust boundary violation
    (r"(?i)(tool.*result.*direct.*llm.*no.*filter|"
     r"mcp.*output.*passed.*to.*system.*unsanitized)",
     "MCP: Tool output crosses trust boundary without sanitization",
     "MCP-Trust-Boundary"),
]

# Mapping from OWASP LLM Top 10 to CWE IDs
OWASP_LLM_CWE_MAP: Dict[str, str] = {
    "LLM01": "CWE-94",   # Code Injection
    "LLM02": "CWE-89",   # SQL Injection (mapped)
    "LLM03": "CWE-506",  # Embedded Malicious Code
    "LLM04": "CWE-400",  # Uncontrolled Resource Consumption
    "LLM05": "CWE-829",  # Inclusion of Functionality from Untrusted Control Sphere
    "LLM06": "CWE-200",  # Information Exposure
    "LLM07": "CWE-749",  # Exposed Dangerous Method or Function
    "LLM08": "CWE-250",  # Execution with Unnecessary Privileges
    "LLM09": "CWE-345",  # Insufficient Verification of Data Authenticity
    "LLM10": "CWE-306",  # Missing Authentication for Critical Function
}

# Severity mapping for LLM-specific findings
LLM_SEVERITY_MAP: Dict[str, str] = {
    "LLM01": "CRITICAL",  # Prompt injection is critical
    "LLM02": "HIGH",
    "LLM03": "MEDIUM",
    "LLM04": "HIGH",
    "LLM05": "HIGH",
    "LLM06": "HIGH",
    "LLM07": "CRITICAL",
    "LLM08": "CRITICAL",
    "LLM09": "MEDIUM",
    "LLM10": "HIGH",
    "MCP-Tool-Poisoning": "HIGH",
    "MCP-Malicious-Description": "HIGH",
    "MCP-Privilege-Escalation": "CRITICAL",
    "MCP-Unrestricted-Tools": "HIGH",
    "MCP-Unvalidated-Input": "HIGH",
    "MCP-Unauthenticated-Server": "MEDIUM",
    "MCP-Trust-Boundary": "HIGH",
}


class LLMSecurityScanner:
    """
    LLM-Generated Code Security Scanner.

    Detects AI-specific security issues including:
    - AI-generated code patterns and signatures
    - AI-specific vulnerabilities (hallucinated APIs, insecure defaults)
    - Insecure LLM API usage (hardcoded keys, prompt injection)
    - OWASP LLM Top 10 compliance
    - MCP (Model Context Protocol) security issues
    """

    def __init__(self) -> None:
        """Initialize the LLM security scanner."""
        self.tool_name = "llm_security_scanner"

    async def scan(self, source_path: str, scan_id: str) -> List[Vulnerability]:
        """
        Run the LLM security scanner.

        Args:
            source_path: Path to the source code directory
            scan_id: Scan identifier

        Returns:
            List of vulnerabilities found
        """
        logger.info("Running LLM security scanner on %s", source_path)
        vulnerabilities: List[Vulnerability] = []

        files = self._get_scannable_files(source_path)
        logger.info("Scanning %d files for LLM-specific security issues", len(files))

        for file_path in files:
            try:
                file_vulns = self._scan_file(file_path, scan_id, source_path)
                vulnerabilities.extend(file_vulns)

                # Python-specific AST analysis for LLM API patterns
                if file_path.endswith(".py"):
                    ast_vulns = self._analyze_python_ast(file_path, scan_id, source_path)
                    vulnerabilities.extend(ast_vulns)

            except Exception as e:
                logger.debug("Error LLM-scanning %s: %s", file_path, e)

        # Deduplicate
        vulnerabilities = self._deduplicate(vulnerabilities)

        logger.info("LLM security scanner found %d issues", len(vulnerabilities))
        return vulnerabilities

    def _get_scannable_files(self, source_path: str) -> List[str]:
        """Get list of files to scan."""
        files = []
        skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build", ".tox"}

        for dirpath, dirnames, filenames in os.walk(source_path):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for filename in filenames:
                if any(filename.endswith(ext) for ext in [".min.js", ".min.css", ".map", ".lock"]):
                    continue
                if any(filename.endswith(ext) for ext in [
                    ".py", ".js", ".jsx", ".ts", ".tsx", ".java", ".go",
                    ".rb", ".php", ".c", ".cpp", ".cs", ".swift", ".kt",
                    ".rs", ".html", ".xml", ".json", ".yaml", ".yml", ".sh",
                    ".sql", ".cfg", ".ini", ".properties", ".gradle", ".tf",
                ]):
                    files.append(os.path.join(dirpath, filename))
                elif filename == ".env" or filename.startswith(".env."):
                    files.append(os.path.join(dirpath, filename))

        return files

    def _scan_file(
        self,
        file_path: str,
        scan_id: str,
        source_path: str,
    ) -> List[Vulnerability]:
        """Scan a single file for LLM-specific security patterns."""
        vulnerabilities: List[Vulnerability] = []

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                content = f.read()
                lines = content.splitlines()
        except Exception:
            return vulnerabilities

        relative_path = os.path.relpath(file_path, source_path)

        # 1. Check for AI-generated code signatures
        vulns = self._check_ai_signatures(content, lines, relative_path, scan_id, file_path)
        vulnerabilities.extend(vulns)

        # 2. Check for hallucinated APIs
        vulns = self._check_hallucinated_apis(content, lines, relative_path, scan_id, file_path)
        vulnerabilities.extend(vulns)

        # 3. Check for AI-generated insecure CORS
        vulns = self._check_ai_cors(content, lines, relative_path, scan_id, file_path)
        vulnerabilities.extend(vulns)

        # 4. Check for AI-generated insecure defaults
        vulns = self._check_insecure_defaults(content, lines, relative_path, scan_id, file_path)
        vulnerabilities.extend(vulns)

        # 5. Check for placeholder auth
        vulns = self._check_placeholder_auth(content, lines, relative_path, scan_id, file_path)
        vulnerabilities.extend(vulns)

        # 6. Check for hardcoded LLM API keys
        vulns = self._check_llm_api_keys(content, lines, relative_path, scan_id, file_path)
        vulnerabilities.extend(vulns)

        # 7. Check for LLM input validation
        vulns = self._check_llm_input_validation(content, lines, relative_path, scan_id, file_path)
        vulnerabilities.extend(vulns)

        # 8. Check for unsanitized LLM output
        vulns = self._check_llm_output_sanitization(content, lines, relative_path, scan_id, file_path)
        vulnerabilities.extend(vulns)

        # 9. Check for RAG prompt injection
        vulns = self._check_rag_prompt_injection(content, lines, relative_path, scan_id, file_path)
        vulnerabilities.extend(vulns)

        # 10. Check for system prompt boundaries
        vulns = self._check_system_prompt_boundaries(content, lines, relative_path, scan_id, file_path)
        vulnerabilities.extend(vulns)

        # 11. Check OWASP LLM Top 10
        vulns = self._check_owasp_llm(content, lines, relative_path, scan_id, file_path)
        vulnerabilities.extend(vulns)

        # 12. Check MCP security
        vulns = self._check_mcp_security(content, lines, relative_path, scan_id, file_path)
        vulnerabilities.extend(vulns)

        return vulnerabilities

    def _check_ai_signatures(
        self, content: str, lines: List[str], relative_path: str,
        scan_id: str, file_path: str,
    ) -> List[Vulnerability]:
        """Check for AI-generated code signatures."""
        vulnerabilities: List[Vulnerability] = []
        seen_lines: set = set()

        for pattern, description in AI_CODE_SIGNATURES:
            for line_num, line in enumerate(lines, 1):
                if line_num in seen_lines:
                    continue
                if re.search(pattern, line):
                    code_snippet = read_file_snippet(file_path, line_num, context=2)
                    vuln = self._create_vulnerability(
                        scan_id=scan_id, file_path=relative_path, line_number=line_num,
                        severity="INFO", category="AI-Generated Code Signature",
                        title=f"AI-Generated Code Pattern: {description}",
                        description=f"Detected AI-generated code pattern: {description} in {relative_path}:{line_num}",
                        code_snippet=code_snippet,
                        cwe_id="CWE-1104",
                        owasp_category=None,
                        fix_suggestion="Review AI-generated code carefully. Ensure all generated code is validated for security before deployment.",
                    )
                    vulnerabilities.append(vuln)
                    seen_lines.add(line_num)

        return vulnerabilities

    def _check_hallucinated_apis(
        self, content: str, lines: List[str], relative_path: str,
        scan_id: str, file_path: str,
    ) -> List[Vulnerability]:
        """Check for hallucinated API calls."""
        vulnerabilities: List[Vulnerability] = []
        seen: set = set()

        for pattern, description in HALLUCINATED_API_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                key = f"{line_num}:{pattern}"
                if key in seen:
                    continue
                match = re.search(pattern, line)
                if match:
                    code_snippet = read_file_snippet(file_path, line_num, context=2)
                    vuln = self._create_vulnerability(
                        scan_id=scan_id, file_path=relative_path, line_number=line_num,
                        severity="MEDIUM", category="AI Hallucinated API",
                        title=f"Potentially Hallucinated API: {description}",
                        description=f"Detected potentially hallucinated API call: {description} in {relative_path}:{line_num}",
                        code_snippet=code_snippet,
                        cwe_id="CWE-1104",
                        owasp_category=None,
                        fix_suggestion="Verify the API/method actually exists in the library documentation. AI models may generate non-existent APIs.",
                    )
                    vulnerabilities.append(vuln)
                    seen.add(key)

        return vulnerabilities

    def _check_ai_cors(
        self, content: str, lines: List[str], relative_path: str,
        scan_id: str, file_path: str,
    ) -> List[Vulnerability]:
        """Check for AI-generated over-permissive CORS."""
        vulnerabilities: List[Vulnerability] = []

        for pattern, description in AI_CORS_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                match = re.search(pattern, line)
                if match:
                    code_snippet = read_file_snippet(file_path, line_num, context=2)
                    vuln = self._create_vulnerability(
                        scan_id=scan_id, file_path=relative_path, line_number=line_num,
                        severity="MEDIUM", category="AI Insecure CORS",
                        title=description,
                        description=f"AI-generated code with overly permissive CORS policy in {relative_path}:{line_num}. "
                                    f"AI models frequently generate CORS wildcard (*) configurations.",
                        code_snippet=code_snippet,
                        cwe_id="CWE-346",
                        owasp_category="A05",
                        fix_suggestion="Replace wildcard (*) with specific allowed origins. Use environment variables for origin configuration.",
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_insecure_defaults(
        self, content: str, lines: List[str], relative_path: str,
        scan_id: str, file_path: str,
    ) -> List[Vulnerability]:
        """Check for AI-generated insecure defaults."""
        vulnerabilities: List[Vulnerability] = []
        seen_lines: set = set()

        for pattern, description in AI_INSECURE_DEFAULTS:
            for line_num, line in enumerate(lines, 1):
                if line_num in seen_lines:
                    continue
                if re.search(pattern, line):
                    code_snippet = read_file_snippet(file_path, line_num, context=2)
                    severity = "HIGH" if "password" in description.lower() or "secret" in description.lower() else "MEDIUM"
                    vuln = self._create_vulnerability(
                        scan_id=scan_id, file_path=relative_path, line_number=line_num,
                        severity=severity, category="AI Insecure Default",
                        title=description,
                        description=f"AI-generated code with insecure default configuration: {description} in {relative_path}:{line_num}",
                        code_snippet=code_snippet,
                        cwe_id="CWE-798" if "password" in description.lower() or "secret" in description.lower() else "CWE-1188",
                        owasp_category="A05",
                        fix_suggestion="Replace default/demo values with secure configuration. Use environment variables for secrets. Disable DEBUG in production.",
                    )
                    vulnerabilities.append(vuln)
                    seen_lines.add(line_num)

        return vulnerabilities

    def _check_placeholder_auth(
        self, content: str, lines: List[str], relative_path: str,
        scan_id: str, file_path: str,
    ) -> List[Vulnerability]:
        """Check for AI-generated placeholder authentication."""
        vulnerabilities: List[Vulnerability] = []

        for pattern, description in AI_PLACEHOLDER_AUTH:
            for line_num in range(len(lines)):
                # Multi-line matching
                context = "\n".join(lines[line_num:min(line_num + 3, len(lines))])
                if re.search(pattern, context):
                    if any(v.line_number == line_num + 1 for v in vulnerabilities):
                        continue
                    code_snippet = read_file_snippet(file_path, line_num + 1, context=3)
                    vuln = self._create_vulnerability(
                        scan_id=scan_id, file_path=relative_path, line_number=line_num + 1,
                        severity="CRITICAL", category="AI Placeholder Authentication",
                        title=description,
                        description=f"Detected placeholder/fake authentication in AI-generated code: {description} in {relative_path}:{line_num + 1}",
                        code_snippet=code_snippet,
                        cwe_id="CWE-306",
                        owasp_category="A07",
                        fix_suggestion="Replace placeholder authentication with real auth (OAuth2, JWT, session-based). Never ship placeholder auth to production.",
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_llm_api_keys(
        self, content: str, lines: List[str], relative_path: str,
        scan_id: str, file_path: str,
    ) -> List[Vulnerability]:
        """Check for hardcoded LLM API keys."""
        vulnerabilities: List[Vulnerability] = []

        for pattern, description in HARDCODED_LLM_KEY_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                match = re.search(pattern, line)
                if match:
                    # Mask the actual key in the snippet
                    masked_line = re.sub(r"['\"][a-zA-Z0-9_-]{20,}['\"]", '"***MASKED***"', line)
                    code_snippet = read_file_snippet(file_path, line_num, context=2)
                    if code_snippet:
                        code_snippet = re.sub(r"['\"][a-zA-Z0-9_-]{20,}['\"]", '"***MASKED***"', code_snippet)

                    vuln = self._create_vulnerability(
                        scan_id=scan_id, file_path=relative_path, line_number=line_num,
                        severity="CRITICAL", category="LLM API Key Exposure",
                        title=description,
                        description=f"{description} detected in {relative_path}:{line_num}. "
                                    f"AI-generated code often includes hardcoded API keys for LLM services.",
                        code_snippet=code_snippet,
                        cwe_id="CWE-798",
                        owasp_category="A07",
                        fix_suggestion="Move API keys to environment variables or a secrets manager. Rotate any exposed keys immediately.",
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_llm_input_validation(
        self, content: str, lines: List[str], relative_path: str,
        scan_id: str, file_path: str,
    ) -> List[Vulnerability]:
        """Check for missing input validation before LLM calls."""
        vulnerabilities: List[Vulnerability] = []

        for pattern, description in LLM_INPUT_VALIDATION_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    # Check if there's validation nearby
                    context_start = max(0, line_num - 10)
                    context = "\n".join(lines[context_start:line_num])
                    if not re.search(r"(validate|sanitize|check|filter|length|limit|clean)", context, re.IGNORECASE):
                        code_snippet = read_file_snippet(file_path, line_num, context=3)
                        vuln = self._create_vulnerability(
                            scan_id=scan_id, file_path=relative_path, line_number=line_num,
                            severity="HIGH", category="LLM Input Validation Missing",
                            title=description,
                            description=f"{description} in {relative_path}:{line_num}. "
                                        f"No input validation detected before LLM API call.",
                            code_snippet=code_snippet,
                            cwe_id="CWE-20",
                            owasp_category="A03",
                            fix_suggestion="Add input validation before LLM calls: check length, filter malicious content, rate limit requests.",
                        )
                        vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_llm_output_sanitization(
        self, content: str, lines: List[str], relative_path: str,
        scan_id: str, file_path: str,
    ) -> List[Vulnerability]:
        """Check for unsanitized LLM output usage."""
        vulnerabilities: List[Vulnerability] = []

        for pattern, description in LLM_OUTPUT_SANITIZATION_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    code_snippet = read_file_snippet(file_path, line_num, context=3)
                    vuln = self._create_vulnerability(
                        scan_id=scan_id, file_path=relative_path, line_number=line_num,
                        severity="CRITICAL", category="LLM Insecure Output Handling",
                        title=description,
                        description=f"{description} in {relative_path}:{line_num}. "
                                    f"LLM output is used in a dangerous context without sanitization.",
                        code_snippet=code_snippet,
                        cwe_id="CWE-94",
                        owasp_category="LLM02",
                        fix_suggestion="Never pass LLM output directly to eval(), exec(), SQL queries, or HTML rendering. Validate and sanitize all LLM outputs.",
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_rag_prompt_injection(
        self, content: str, lines: List[str], relative_path: str,
        scan_id: str, file_path: str,
    ) -> List[Vulnerability]:
        """Check for prompt injection in RAG applications."""
        vulnerabilities: List[Vulnerability] = []

        for pattern, description in RAG_PROMPT_INJECTION_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    code_snippet = read_file_snippet(file_path, line_num, context=3)
                    vuln = self._create_vulnerability(
                        scan_id=scan_id, file_path=relative_path, line_number=line_num,
                        severity="CRITICAL", category="LLM Prompt Injection",
                        title=description,
                        description=f"{description} in {relative_path}:{line_num}",
                        code_snippet=code_snippet,
                        cwe_id="CWE-94",
                        owasp_category="LLM01",
                        fix_suggestion="Implement prompt injection defenses: use delimiters between system and user content, validate retrieved documents, use prompt sealing techniques.",
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_system_prompt_boundaries(
        self, content: str, lines: List[str], relative_path: str,
        scan_id: str, file_path: str,
    ) -> List[Vulnerability]:
        """Check for missing system prompt boundaries."""
        vulnerabilities: List[Vulnerability] = []

        for pattern, description in SYSTEM_PROMPT_BOUNDARY_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    code_snippet = read_file_snippet(file_path, line_num, context=3)
                    vuln = self._create_vulnerability(
                        scan_id=scan_id, file_path=relative_path, line_number=line_num,
                        severity="MEDIUM", category="LLM System Prompt Boundary",
                        title=description,
                        description=f"{description} in {relative_path}:{line_num}",
                        code_snippet=code_snippet,
                        cwe_id="CWE-94",
                        owasp_category="LLM01",
                        fix_suggestion="Use clear delimiters between system prompt and user content. Add instruction integrity checks.",
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _check_owasp_llm(
        self, content: str, lines: List[str], relative_path: str,
        scan_id: str, file_path: str,
    ) -> List[Vulnerability]:
        """Check for OWASP LLM Top 10 patterns."""
        vulnerabilities: List[Vulnerability] = []
        seen_lines: set = set()

        for llm_id, patterns in OWASP_LLM_PATTERNS.items():
            for pattern, description in patterns:
                for line_num, line in enumerate(lines, 1):
                    if line_num in seen_lines:
                        continue
                    if re.search(pattern, line):
                        code_snippet = read_file_snippet(file_path, line_num, context=3)
                        severity = LLM_SEVERITY_MAP.get(llm_id, "MEDIUM")
                        cwe_id = OWASP_LLM_CWE_MAP.get(llm_id, "CWE-1104")
                        vuln = self._create_vulnerability(
                            scan_id=scan_id, file_path=relative_path, line_number=line_num,
                            severity=severity, category=f"OWASP {llm_id}",
                            title=description,
                            description=f"OWASP LLM Top 10 - {llm_id}: {description} in {relative_path}:{line_num}",
                            code_snippet=code_snippet,
                            cwe_id=cwe_id,
                            owasp_category=llm_id,
                            fix_suggestion=self._get_owasp_llm_fix(llm_id),
                        )
                        vulnerabilities.append(vuln)
                        seen_lines.add(line_num)

        return vulnerabilities

    def _check_mcp_security(
        self, content: str, lines: List[str], relative_path: str,
        scan_id: str, file_path: str,
    ) -> List[Vulnerability]:
        """Check for MCP (Model Context Protocol) security issues."""
        vulnerabilities: List[Vulnerability] = []

        for pattern, description, mcp_id in MCP_SECURITY_PATTERNS:
            for line_num, line in enumerate(lines, 1):
                if re.search(pattern, line):
                    code_snippet = read_file_snippet(file_path, line_num, context=3)
                    severity = LLM_SEVERITY_MAP.get(mcp_id, "MEDIUM")
                    vuln = self._create_vulnerability(
                        scan_id=scan_id, file_path=relative_path, line_number=line_num,
                        severity=severity, category=f"MCP Security: {mcp_id}",
                        title=description,
                        description=f"MCP Security - {mcp_id}: {description} in {relative_path}:{line_num}",
                        code_snippet=code_snippet,
                        cwe_id="CWE-749",
                        owasp_category="LLM07",
                        fix_suggestion=self._get_mcp_fix(mcp_id),
                    )
                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _analyze_python_ast(
        self,
        file_path: str,
        scan_id: str,
        source_path: str,
    ) -> List[Vulnerability]:
        """Analyze Python AST for LLM API security patterns."""
        vulnerabilities: List[Vulnerability] = []
        relative_path = os.path.relpath(file_path, source_path)

        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                source = f.read()
            tree = ast.parse(source)
        except (SyntaxError, Exception):
            return vulnerabilities

        for node in ast.walk(tree):
            # Check for openai.ChatCompletion.create without try/except
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node.func)
                if func_name and any(fn in func_name for fn in [
                    "openai", "ChatCompletion", "Completion",
                ]):
                    # Check if wrapped in try/except
                    parent = self._find_parent(tree, node)
                    if not isinstance(parent, ast.Try):
                        if node.lineno:
                            code_snippet = read_file_snippet(file_path, node.lineno, context=2)
                            vuln = self._create_vulnerability(
                                scan_id=scan_id, file_path=relative_path,
                                line_number=node.lineno,
                                column=getattr(node, "col_offset", 0) + 1,
                                severity="MEDIUM", category="LLM API Error Handling Missing",
                                title="LLM API call without error handling",
                                description=f"OpenAI API call at {relative_path}:{node.lineno} lacks try/except. "
                                            f"LLM APIs can fail with rate limits, timeouts, or content filter errors.",
                                code_snippet=code_snippet,
                                cwe_id="CWE-391",
                                owasp_category="LLM04",
                                fix_suggestion="Wrap LLM API calls in try/except blocks. Handle rate limits (429), timeouts, and content filter errors.",
                            )
                            vulnerabilities.append(vuln)

            # Check for hardcoded API keys in assignments
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name_lower = target.id.lower()
                        if any(kw in name_lower for kw in [
                            "openai_key", "openai_api_key", "anthropic_key",
                            "llm_api_key", "ai_key", "gpt_key", "claude_key",
                        ]):
                            if isinstance(node.value, (ast.Constant, ast.Str)):
                                if node.lineno:
                                    code_snippet = read_file_snippet(file_path, node.lineno, context=2)
                                    # Mask the key
                                    if code_snippet:
                                        code_snippet = re.sub(r"['\"][a-zA-Z0-9_-]+['\"]", '"***MASKED***"', code_snippet)

                                    vuln = self._create_vulnerability(
                                        scan_id=scan_id, file_path=relative_path,
                                        line_number=node.lineno,
                                        column=getattr(node, "col_offset", 0) + 1,
                                        severity="CRITICAL", category="LLM API Key Hardcoded",
                                        title=f"Hardcoded LLM API key: {target.id}",
                                        description=f"Variable '{target.id}' contains a hardcoded LLM API key at {relative_path}:{node.lineno}",
                                        code_snippet=code_snippet,
                                        cwe_id="CWE-798",
                                        owasp_category="LLM06",
                                        fix_suggestion="Use environment variables or a secrets manager for LLM API keys. Rotate exposed keys immediately.",
                                    )
                                    vulnerabilities.append(vuln)

        return vulnerabilities

    def _get_call_name(self, func: Any) -> str:
        """Get the name of a function call from AST node."""
        if isinstance(func, ast.Name):
            return func.id
        elif isinstance(func, ast.Attribute):
            parts = []
            node: Any = func
            while isinstance(node, ast.Attribute):
                parts.append(node.attr)
                node = node.value
            if isinstance(node, ast.Name):
                parts.append(node.id)
            return ".".join(reversed(parts))
        return ""

    def _find_parent(self, tree: ast.AST, target: ast.AST) -> Optional[ast.AST]:
        """Find the parent node of a target node in the AST."""
        for node in ast.walk(tree):
            for child in ast.iter_child_nodes(node):
                if child is target:
                    return node
        return None

    def _create_vulnerability(
        self,
        scan_id: str,
        file_path: str,
        line_number: int,
        severity: str,
        category: str,
        title: str,
        description: str,
        code_snippet: Optional[str] = None,
        cwe_id: Optional[str] = None,
        owasp_category: Optional[str] = None,
        fix_suggestion: Optional[str] = None,
        column: Optional[int] = None,
    ) -> Vulnerability:
        """Create a standardized vulnerability object."""
        cvss_map = {"CRITICAL": 9.0, "HIGH": 7.5, "MEDIUM": 5.0, "LOW": 2.0, "INFO": 0.0}

        return Vulnerability(
            scan_id=scan_id,
            file_path=file_path,
            line_number=line_number,
            column=column,
            severity=severity,
            category=category,
            cwe_id=cwe_id,
            cwe_name=CWE_MAPPING.get(cwe_id or "", category),
            title=title,
            description=description,
            code_snippet=code_snippet,
            fix_suggestion=fix_suggestion,
            tool_source=self.tool_name,
            cvss_score=cvss_map.get(severity, 5.0),
            owasp_category=owasp_category,
            confidence="HIGH" if severity in ("CRITICAL", "HIGH") else "MEDIUM",
            created_at=datetime.utcnow(),
        )

    def _get_owasp_llm_fix(self, llm_id: str) -> str:
        """Get fix suggestion for OWASP LLM Top 10 issue."""
        fixes = {
            "LLM01": "Implement prompt injection defenses: use delimiters, validate inputs, use prompt sealing, implement output filtering.",
            "LLM02": "Validate and sanitize all LLM outputs before use. Never pass LLM output to eval(), SQL, or HTML rendering directly.",
            "LLM03": "Validate all training/fine-tuning data sources. Implement data provenance tracking and sanitization pipelines.",
            "LLM04": "Implement rate limiting, max token limits, request timeouts, and circuit breakers for LLM API calls.",
            "LLM05": "Use only trusted model sources. Validate model hashes. Scan dependencies for known vulnerabilities.",
            "LLM06": "Filter sensitive information from LLM outputs. Implement output filtering. Do not expose system prompts.",
            "LLM07": "Validate all plugin/tool inputs. Implement least-privilege access. Use sandboxed execution environments.",
            "LLM08": "Implement human-in-the-loop for critical actions. Restrict LLM permissions. Use approval workflows.",
            "LLM09": "Do not rely solely on LLM outputs for security decisions. Implement human review. Validate LLM outputs independently.",
            "LLM10": "Implement model access controls. Use API authentication. Monitor for model extraction attempts.",
        }
        return fixes.get(llm_id, "Review and fix according to OWASP LLM Top 10 guidelines.")

    def _get_mcp_fix(self, mcp_id: str) -> str:
        """Get fix suggestion for MCP security issue."""
        fixes = {
            "MCP-Tool-Poisoning": "Validate tool descriptions at registration. Do not allow user input in tool schemas. Sanitize tool metadata.",
            "MCP-Malicious-Description": "Implement tool description review. Use allowlists for approved tools. Validate tool schemas.",
            "MCP-Privilege-Escalation": "Implement least-privilege for MCP tools. Validate permissions before tool execution. Log all tool invocations.",
            "MCP-Unrestricted-Tools": "Implement tool allowlisting. Restrict tool permissions. Validate tool access based on user context.",
            "MCP-Unvalidated-Input": "Validate all tool arguments before execution. Implement input sanitization. Use schema validation.",
            "MCP-Unauthenticated-Server": "Implement authentication for MCP server connections. Use TLS. Validate client identity.",
            "MCP-Trust-Boundary": "Sanitize tool outputs before passing to LLM context. Implement output filtering. Validate tool results.",
        }
        return fixes.get(mcp_id, "Review and fix MCP security configuration.")

    def _deduplicate(self, vulnerabilities: List[Vulnerability]) -> List[Vulnerability]:
        """Deduplicate vulnerabilities by file_path + line_number + category."""
        seen: Dict[str, Vulnerability] = {}
        for vuln in vulnerabilities:
            key = f"{vuln.file_path}:{vuln.line_number}:{vuln.category}"
            if key not in seen:
                seen[key] = vuln
            else:
                existing = seen[key]
                severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
                if severity_order.get(vuln.severity, 0) > severity_order.get(existing.severity, 0):
                    seen[key] = vuln
        return list(seen.values())

    def is_available(self) -> bool:
        """Always available - no external dependencies."""
        return True
