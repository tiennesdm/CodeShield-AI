"""
Advanced Taint Analysis Engine for CodeShield AI.

Intra-procedural taint tracking for Python source code using AST.
Detects data flow from sources (user input) to sinks (dangerous operations)
without passing through sanitizers.

Vulnerability Types Detected:
- SQL Injection: user input -> SQL sink without sanitization
- XSS: user input -> HTML/JS output without escaping
- Command Injection: user input -> os.system/subprocess without validation
- Path Traversal: user input -> file operations without validation
- SSRF: user input -> HTTP requests without allowlist

Data Flow Analysis:
- Track variable assignments and propagation
- Detect taint through function calls
- Handle taint through collections (lists, dicts)

Uses Python AST only (no external dependencies).
"""

import ast
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from models.vulnerability import Vulnerability
from utils.logger import get_logger

logger = get_logger(__name__)

# ============================================================================
# Source Definitions (User-Controllable Input)
# ============================================================================

SOURCE_PATTERNS: Dict[str, List[str]] = {
    "request_params": [
        r"request\.args\[",
        r"request\.form\[",
        r"request\.json",
        r"request\.data",
        r"request\.files",
        r"request\.values",
        r"request\.cookies",
        r"request\.headers\[",
        r"request\.get_json",
        r"request\.get_data",
        r"flask\.request\.",
        r"req\.query",
        r"req\.params",
        r"req\.body",
        r"req\.headers",
        r"req\.[a-z_]+",
    ],
    "django_request": [
        r"request\.GET\.",
        r"request\.POST\.",
        r"request\.FILES",
        r"request\.COOKIES",
        r"request\.META",
    ],
    "function_args": [
        r"sys\.argv",
        r"input\s*\(",
        r"raw_input\s*\(",
        r"os\.environ",
        r"os\.environ\.get",
    ],
    "file_reads": [
        r"open\s*\(",
    ],
    "network_input": [
        r"\.recv\s*\(",
        r"socket\.recv",
        r"\.read\s*\(",
    ],
    "user_input_sources": [
        r"request\.",
        r"params\[",
        r"args\[",
        r"kwargs",
    ],
}

# Flatten all source patterns
ALL_SOURCE_PATTERNS: List[str] = []
for patterns in SOURCE_PATTERNS.values():
    ALL_SOURCE_PATTERNS.extend(patterns)


# ============================================================================
# Sink Definitions (Dangerous Operations)
# ============================================================================

SINK_PATTERNS: Dict[str, Dict[str, Any]] = {
    "sql_injection": {
        "functions": [
            r"\.execute\s*\(",
            r"\.executemany\s*\(",
            r"\.raw\s*\(",
            r"cursor\.execute",
            r"Cursor\.execute",
            r"db\.execute",
            r"\.query\s*\(",
            r"\.run\s*\(",
            r"\.find\s*\(",
            r"\.find_one\s*\(",
            r"\.aggregate\s*\(",
        ],
        "severity": "HIGH",
        "cwe": "CWE-89",
        "category": "SQL Injection",
        "description": "User input flows into SQL query without proper parameterization",
    },
    "command_injection": {
        "functions": [
            r"os\.system\s*\(",
            r"os\.popen\s*\(",
            r"subprocess\.call\s*\(",
            r"subprocess\.run\s*\(",
            r"subprocess\.Popen\s*\(",
            r"subprocess\.check_output\s*\(",
            r"subprocess\.check_call\s*\(",
            r"commands\.getoutput\s*\(",
            r"commands\.getstatusoutput\s*\(",
            r"eval\s*\(",
            r"exec\s*\(",
            r"execfile\s*\(",
            r"compile\s*\(",
            r"__import__\s*\(",
        ],
        "severity": "CRITICAL",
        "cwe": "CWE-78",
        "category": "Command Injection",
        "description": "User input flows into command execution without validation",
    },
    "xss": {
        "functions": [
            r"render_template_string\s*\(",
            r"render_template\s*\(",
            r"\.render\s*\(",
            r"make_response\s*\(",
            r"HttpResponse\s*\(",
            r"\.write\s*\(",
            r"send_file\s*\(",
            r"render_to_response\s*\(",
            r"render_to_string\s*\(",
        ],
        "severity": "HIGH",
        "cwe": "CWE-79",
        "category": "XSS",
        "description": "User input flows into HTML/JS output without escaping",
    },
    "path_traversal": {
        "functions": [
            r"open\s*\(",
            r"file\s*\(",
            r"\.read\s*\(",
            r"\.write\s*\(",
            r"os\.open\s*\(",
            r"os\.read\s*\(",
            r"os\.write\s*\(",
            r"shutil\.copy\s*\(",
            r"shutil\.move\s*\(",
            r"shutil\.copyfile\s*\(",
            r"shutil\.copytree\s*\(",
            r"send_file\s*\(",
            r"send_from_directory\s*\(",
            r"\.save\s*\(",
        ],
        "severity": "HIGH",
        "cwe": "CWE-22",
        "category": "Path Traversal",
        "description": "User input flows into file path without validation",
    },
    "ssrf": {
        "functions": [
            r"urllib\.request\.urlopen\s*\(",
            r"urllib2\.urlopen\s*\(",
            r"requests\.get\s*\(",
            r"requests\.post\s*\(",
            r"requests\.put\s*\(",
            r"requests\.delete\s*\(",
            r"requests\.head\s*\(",
            r"requests\.patch\s*\(",
            r"requests\.request\s*\(",
            r"httpx\.get\s*\(",
            r"httpx\.post\s*\(",
            r"httpx\.request\s*\(",
            r"http\.client\.HTTPConnection\s*\(",
            r"http\.client\.HTTPSConnection\s*\(",
            r"\.get\s*\(",
            r"\.post\s*\(",
            r"urlopen\s*\(",
        ],
        "severity": "HIGH",
        "cwe": "CWE-918",
        "category": "SSRF",
        "description": "User input flows into HTTP request without allowlist validation",
    },
    "ldap_injection": {
        "functions": [
            r"\.search_s\s*\(",
            r"\.search_ext\s*\(",
            r"\.search_st\s*\(",
        ],
        "severity": "HIGH",
        "cwe": "CWE-90",
        "category": "LDAP Injection",
        "description": "User input flows into LDAP query without sanitization",
    },
    "xpath_injection": {
        "functions": [
            r"\.xpath\s*\(",
            r"\.findall\s*\(",
            r"\.find\s*\(",
            r"\.findtext\s*\(",
            r"\.iterfind\s*\(",
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-91",
        "category": "XPath Injection",
        "description": "User input flows into XPath query without sanitization",
    },
    "xml_injection": {
        "functions": [
            r"\.parse\s*\(",
            r"\.parseString\s*\(",
            r"\.fromstring\s*\(",
            r"ET\.parse\s*\(",
            r"ElementTree\.parse\s*\(",
            r"\.tostring\s*\(",
            r"\.xml\s*\(",
        ],
        "severity": "MEDIUM",
        "cwe": "CWE-91",
        "category": "XML Injection",
        "description": "User input flows into XML parsing without sanitization",
    },
    "code_injection": {
        "functions": [
            r"eval\s*\(",
            r"exec\s*\(",
            r"execfile\s*\(",
            r"compile\s*\(",
            r"__import__\s*\(",
            r"types\.FunctionType\s*\(",
            r"getattr\s*\(",
            r"setattr\s*\(",
            r"hasattr\s*\(",
        ],
        "severity": "CRITICAL",
        "cwe": "CWE-94",
        "category": "Code Injection",
        "description": "User input flows into code execution context",
    },
}

# ============================================================================
# Sanitizer Definitions
# ============================================================================

SANITIZER_PATTERNS: Dict[str, List[str]] = {
    "sql": [
        r"parameteriz",
        r"placeholder",
        r"\?",
        r"%s",
        r"bindparam",
        r"text\s*\(",
    ],
    "xss": [
        r"escape\s*\(",
        r"bleach\.",
        r"htmlspecialchars",
        r"sanitize",
        r"purif",
        r"clean\s*\(",
        r"Markup\s*\(",
        r"strip_tags",
    ],
    "command": [
        r"shlex\.quote",
        r"shlex\.split",
        r"escape\s*\(",
        r"validat",
        r"sanitize",
        r"re\.match",
        r"re\.search",
        r"re\.fullmatch",
        r"allowlist",
        r"whitelist",
        r"safepath",
    ],
    "path": [
        r"os\.path\.abspath",
        r"os\.path\.realpath",
        r"os\.path\.normpath",
        r"secure_filename",
        r"pathlib\.",
        r"allowlist",
        r"whitelist",
        r"is_safe_path",
    ],
    "ssrf": [
        r"allowlist",
        r"whitelist",
        r"urlparse",
        r"validators\.url",
        r"re\.match",
        r"is_safe_url",
        r"url_has_allowed_host",
    ],
    "general": [
        r"validat",
        r"sanitize",
        r"escape",
        r"clean",
        r"int\s*\(",
        r"float\s*\(",
        r"str\s*\(",
        r"bool\s*\(",
        r"len\s*\(",
    ],
}


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class TaintFlow:
    """Represents a taint flow from source to sink."""

    source_var: str
    sink_type: str
    sink_func: str
    file_path: str
    source_line: int
    sink_line: int
    severity: str
    cwe: str
    category: str
    description: str
    data_path: List[str] = field(default_factory=list)
    sanitized: bool = False
    sanitizer_used: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source_var": self.source_var,
            "sink_type": self.sink_type,
            "sink_func": self.sink_func,
            "file_path": self.file_path,
            "source_line": self.source_line,
            "sink_line": self.sink_line,
            "severity": self.severity,
            "cwe": self.cwe,
            "category": self.category,
            "description": self.description,
            "data_path": self.data_path,
            "sanitized": self.sanitized,
            "sanitizer_used": self.sanitizer_used,
        }


# ============================================================================
# AST-based Taint Analyzer
# ============================================================================

class TaintAnalyzer:
    """
    Intra-procedural taint analysis engine.

    Uses Python AST to track data flow from user-controllable sources
to dangerous sinks, detecting various injection vulnerabilities.
    """

    def __init__(self) -> None:
        self.taint_flows: List[TaintFlow] = []
        self._source_patterns = ALL_SOURCE_PATTERNS
        self._sink_patterns = SINK_PATTERNS
        self._sanitizer_patterns = SANITIZER_PATTERNS

    # Maps SINK_PATTERNS keys to sanitizer categories in SANITIZER_PATTERNS.
    _SANITIZER_CATEGORY_MAP: Dict[str, str] = {
        "sql_injection": "sql",
        "command_injection": "command",
        "code_injection": "command",
        "xss": "xss",
        "path_traversal": "path",
        "ssrf": "ssrf",
    }

    async def scan(self, source_path: str, scan_id: str) -> List[Vulnerability]:
        """Async alias for :meth:`analyze` (used by the orchestrator)."""
        return await self.analyze(source_path, scan_id)

    async def analyze(self, source_path: str, scan_id: str) -> List[Vulnerability]:
        """
        Run taint analysis on all Python files in source path.

        Args:
            source_path: Path to the source directory
            scan_id: Scan identifier

        Returns:
            List of Vulnerability objects
        """
        self.taint_flows = []
        path = Path(source_path)
        py_files = list(path.rglob("*.py"))

        logger.info(
            "[%s] Running taint analysis on %d Python files", scan_id, len(py_files)
        )

        for py_file in py_files:
            if py_file.name.startswith(".") or "__pycache__" in str(py_file):
                continue
            try:
                self._analyze_file(str(py_file), scan_id)
            except Exception as e:
                logger.debug("Taint analysis failed for %s: %s", py_file, e)

        logger.info(
            "[%s] Taint analysis found %d flows", scan_id, len(self.taint_flows)
        )

        return self._flows_to_vulnerabilities(scan_id)

    def _analyze_file(self, file_path: str, scan_id: str) -> None:
        """Analyze a single Python file for taint flows."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            tree = ast.parse(content)
        except SyntaxError:
            return
        except Exception:
            return

        # Build a mapping of line numbers to source code lines
        lines = content.split("\n")

        # Walk AST and look for functions/methods
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                self._analyze_function(node, file_path, content, lines)
            elif isinstance(node, ast.Module):
                # Also analyze module-level code
                self._analyze_function_body(node.body, file_path, content, lines, "<module>")

    def _analyze_function(
        self,
        func: ast.FunctionDef,
        file_path: str,
        content: str,
        lines: List[str],
    ) -> None:
        """Analyze a function body for taint flows."""
        func_name = func.name

        # Seed function parameters as potential taint sources (a standard
        # taint-analysis assumption: parameters may carry untrusted input).
        initial_tainted: Dict[str, int] = {}
        func_line = getattr(func, "lineno", 1)
        for arg_name in self._iter_param_names(func):
            if arg_name in ("self", "cls"):
                continue
            initial_tainted[arg_name] = func_line

        self._analyze_function_body(
            func.body, file_path, content, lines, func_name, initial_tainted
        )

    @staticmethod
    def _iter_param_names(func: ast.FunctionDef) -> List[str]:
        """Collect all parameter names of a function definition."""
        args = func.args
        names: List[str] = []
        for collection in (getattr(args, "posonlyargs", []), args.args, args.kwonlyargs):
            names.extend(a.arg for a in collection)
        if args.vararg:
            names.append(args.vararg.arg)
        if args.kwarg:
            names.append(args.kwarg.arg)
        return names

    def _analyze_function_body(
        self,
        body: List[ast.stmt],
        file_path: str,
        content: str,
        lines: List[str],
        func_name: str,
        initial_tainted: Optional[Dict[str, int]] = None,
    ) -> None:
        """Analyze function body statements for taint flows."""
        # Track tainted variables in this scope
        tainted_vars: Dict[str, int] = dict(initial_tainted or {})  # var_name -> source_line

        # Collect all statements recursively
        all_stmts = self._collect_statements(body)

        for stmt in all_stmts:
            # Identify taint sources (assignments from user input)
            sources = self._find_sources(stmt, content, lines)
            for var_name, line_no in sources:
                tainted_vars[var_name] = line_no

            # Track variable propagation (tainted_var used in new assignment)
            propagated = self._track_propagation(stmt, tainted_vars, content, lines)
            for var_name, source_line in propagated:
                if var_name not in tainted_vars:
                    tainted_vars[var_name] = source_line

            # Check for sinks using tainted variables
            for sink_type, sink_config in self._sink_patterns.items():
                sink_matches = self._find_sinks(
                    stmt, sink_type, sink_config, tainted_vars, content, lines
                )
                for flow in sink_matches:
                    flow.file_path = file_path
                    # Check if there are sanitizers between source and sink
                    sanitized, sanitizer = self._check_sanitizers(
                        stmt, sink_type, content
                    )
                    flow.sanitized = sanitized
                    flow.sanitizer_used = sanitizer
                    if not sanitized:
                        self.taint_flows.append(flow)

    def _collect_statements(self, body: List[ast.stmt]) -> List[ast.stmt]:
        """Recursively collect all statements from a body."""
        statements: List[ast.stmt] = []
        for stmt in body:
            statements.append(stmt)
            # Recurse into control flow
            if isinstance(stmt, (ast.If, ast.While, ast.For, ast.With, ast.Try, ast.AsyncFor)):
                if hasattr(stmt, "body"):
                    statements.extend(self._collect_statements(stmt.body))
                if hasattr(stmt, "orelse"):
                    statements.extend(self._collect_statements(stmt.orelse))
                if hasattr(stmt, "finalbody"):
                    statements.extend(self._collect_statements(stmt.finalbody))
                if hasattr(stmt, "handlers"):
                    for handler in stmt.handlers:
                        if hasattr(handler, "body"):
                            statements.extend(self._collect_statements(handler.body))
        return statements

    def _find_sources(
        self, stmt: ast.stmt, content: str, lines: List[str]
    ) -> List[Tuple[str, int]]:
        """Find taint sources in a statement (assignments from user input)."""
        sources: List[Tuple[str, int]] = []

        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                var_name = self._get_var_name(target)
                if var_name:
                    source_info = self._is_taint_source(stmt.value, content, lines)
                    if source_info:
                        sources.append((var_name, source_info[1]))

        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value:
                var_name = self._get_var_name(stmt.target)
                if var_name:
                    source_info = self._is_taint_source(stmt.value, content, lines)
                    if source_info:
                        sources.append((var_name, source_info[1]))

        elif isinstance(stmt, (ast.For, ast.AsyncFor)):
            # For loop variable could be tainted
            var_name = self._get_var_name(stmt.target)
            if var_name:
                source_info = self._is_taint_source(stmt.iter, content, lines)
                if source_info:
                    sources.append((var_name, source_info[1]))

        return sources

    def _is_taint_source(
        self, node: ast.expr, content: str, lines: List[str]
    ) -> Optional[Tuple[str, int]]:
        """Check if an AST node represents a taint source."""
        line_no = getattr(node, "lineno", 1)
        if line_no <= len(lines):
            line_content = lines[line_no - 1]
        else:
            line_content = ""

        # Check for known source patterns
        for source_type, patterns in SOURCE_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, line_content):
                    return (source_type, line_no)

        # Check for attribute access that looks like request data
        if isinstance(node, ast.Attribute):
            attr_chain = self._get_attribute_chain(node)
            if attr_chain and "request" in attr_chain.lower():
                return ("request_attribute", line_no)

        # Check for function calls that return user input
        if isinstance(node, ast.Call):
            func_name = self._get_call_name(node)
            if func_name and any(
                re.search(p, func_name) for p in ALL_SOURCE_PATTERNS
            ):
                return ("function_call", line_no)

        # Check for subscript on request-like objects
        if isinstance(node, ast.Subscript):
            base_name = self._get_subscript_base(node)
            if base_name and "request" in base_name.lower():
                return ("request_subscript", line_no)

        return None

    def _track_propagation(
        self,
        stmt: ast.stmt,
        tainted_vars: Dict[str, int],
        content: str,
        lines: List[str],
    ) -> List[Tuple[str, int]]:
        """Track how tainted variables propagate through assignments."""
        propagated: List[Tuple[str, int]] = []

        if isinstance(stmt, ast.Assign):
            for target in stmt.targets:
                var_name = self._get_var_name(target)
                if var_name and self._uses_tainted_var(stmt.value, tainted_vars):
                    # Find the source line
                    source_line = self._find_source_line(stmt.value, tainted_vars)
                    if source_line:
                        propagated.append((var_name, source_line))

        elif isinstance(stmt, ast.AnnAssign):
            if stmt.value:
                var_name = self._get_var_name(stmt.target)
                if var_name and self._uses_tainted_var(stmt.value, tainted_vars):
                    source_line = self._find_source_line(stmt.value, tainted_vars)
                    if source_line:
                        propagated.append((var_name, source_line))

        return propagated

    def _uses_tainted_var(
        self, node: ast.AST, tainted_vars: Dict[str, int]
    ) -> bool:
        """Check if a node uses any tainted variable."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name):
                if child.id in tainted_vars:
                    return True
            elif isinstance(child, ast.Attribute):
                # Check if base of attribute is tainted
                base = self._get_attribute_base_name(child)
                if base and base in tainted_vars:
                    return True
        return False

    def _find_source_line(
        self, node: ast.AST, tainted_vars: Dict[str, int]
    ) -> int:
        """Find the original source line for a tainted expression."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in tainted_vars:
                return tainted_vars[child.id]
            elif isinstance(child, ast.Attribute):
                base = self._get_attribute_base_name(child)
                if base and base in tainted_vars:
                    return tainted_vars[base]
        return 1

    def _find_sinks(
        self,
        stmt: ast.stmt,
        sink_type: str,
        sink_config: Dict[str, Any],
        tainted_vars: Dict[str, int],
        content: str,
        lines: List[str],
    ) -> List[TaintFlow]:
        """Find sink calls that use tainted variables."""
        flows: List[TaintFlow] = []
        sink_patterns = sink_config["functions"]

        # Walk the statement looking for sink function calls
        for node in ast.walk(stmt):
            if isinstance(node, ast.Call):
                call_name = self._get_call_name(node)
                if not call_name:
                    continue

                # Check if this call matches a sink pattern. Sink patterns
                # end with ``\s*\(`` but call_name has no parenthesis, so
                # match against ``call_name + "("``.
                call_probe = call_name + "("
                is_sink = False
                for pattern in sink_patterns:
                    if re.search(pattern, call_probe):
                        is_sink = True
                        break

                if not is_sink:
                    continue

                # Check if any argument uses a tainted variable
                sink_line = getattr(node, "lineno", 1)
                for arg in node.args:
                    if self._uses_tainted_var(arg, tainted_vars):
                        source_var = self._get_tainted_var_name(arg, tainted_vars)
                        source_line = tainted_vars.get(source_var, 1)

                        flow = TaintFlow(
                            source_var=source_var,
                            sink_type=sink_type,
                            sink_func=call_name,
                            file_path="",
                            source_line=source_line,
                            sink_line=sink_line,
                            severity=sink_config["severity"],
                            cwe=sink_config["cwe"],
                            category=sink_config["category"],
                            description=sink_config["description"],
                            data_path=[f"line {source_line} -> line {sink_line}"],
                        )
                        flows.append(flow)

                # Check keyword arguments too
                for keyword in node.keywords:
                    if self._uses_tainted_var(keyword.value, tainted_vars):
                        source_var = self._get_tainted_var_name(
                            keyword.value, tainted_vars
                        )
                        source_line = tainted_vars.get(source_var, 1)

                        flow = TaintFlow(
                            source_var=source_var,
                            sink_type=sink_type,
                            sink_func=f"{call_name}({keyword.arg}=...)",
                            file_path="",
                            source_line=source_line,
                            sink_line=sink_line,
                            severity=sink_config["severity"],
                            cwe=sink_config["cwe"],
                            category=sink_config["category"],
                            description=sink_config["description"],
                            data_path=[f"line {source_line} -> line {sink_line}"],
                        )
                        flows.append(flow)

        return flows

    def _check_sanitizers(
        self, stmt: ast.stmt, sink_type: str, content: str
    ) -> Tuple[bool, str]:
        """
        Check if sanitizers are applied between source and sink.

        Args:
            stmt: The AST statement containing the sink
            sink_type: Type of sink
            content: Full file content

        Returns:
            Tuple of (is_sanitized, sanitizer_name)
        """
        # Get the relevant statement text. When called without an AST node
        # (e.g. from unit tests), the caller passes the statement text directly
        # as ``content``.
        if stmt is None:
            stmt_text = content
        else:
            stmt_text = self._get_node_text(stmt, content) or content
        if not stmt_text:
            return False, ""

        # Map full sink-type names (SINK_PATTERNS keys) to sanitizer categories.
        category = self._SANITIZER_CATEGORY_MAP.get(sink_type, sink_type)

        # SQL needs special handling: a bare ``%s``/``?`` placeholder only
        # indicates parameterization when values are passed separately, NOT when
        # string formatting (``"..." % x``, ``.format()``, concatenation,
        # f-strings) is used to build the query.
        if category == "sql":
            has_placeholder = bool(
                re.search(r"%s|%d|\?|:\w+|%\(\w+\)s", stmt_text)
                or re.search(r"parameteriz|bindparam|text\s*\(", stmt_text, re.IGNORECASE)
            )
            uses_string_format = bool(
                re.search(r"['\"]\s*%\s+\w", stmt_text)  # "..." % var
                or re.search(r"\.format\s*\(", stmt_text)
                or "+" in stmt_text
                or 'f"' in stmt_text
                or "f'" in stmt_text
            )
            if has_placeholder and not uses_string_format:
                return True, "parameterized_query"
            # Fall through to general sanitizers (validate/int/etc.).
            for pattern in self._sanitizer_patterns.get("general", []):
                if re.search(pattern, stmt_text, re.IGNORECASE):
                    return True, pattern
            return False, ""

        # Check sink-specific sanitizers + general sanitizers.
        sink_sanitizers = self._sanitizer_patterns.get(category, [])
        general_sanitizers = self._sanitizer_patterns.get("general", [])
        for pattern in sink_sanitizers + general_sanitizers:
            if re.search(pattern, stmt_text, re.IGNORECASE):
                return True, pattern

        return False, ""

    def _get_node_text(self, node: ast.AST, content: str) -> str:
        """Extract the source text for an AST node."""
        try:
            if hasattr(node, "lineno") and hasattr(node, "end_lineno"):
                lines = content.split("\n")
                start = node.lineno - 1
                end = getattr(node, "end_lineno", node.lineno) - 1
                if start >= 0 and end < len(lines):
                    return "\n".join(lines[start:end + 1])
        except Exception:
            pass
        return ""

    def _get_var_name(self, node: ast.AST) -> str:
        """Get the variable name from an assignment target."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Tuple):
            # Tuple unpacking - get first name
            for elt in node.elts:
                if isinstance(elt, ast.Name):
                    return elt.id
        return ""

    def _get_call_name(self, node: ast.Call) -> str:
        """Get the full function name from a call node."""
        if isinstance(node.func, ast.Name):
            return node.func.id
        elif isinstance(node.func, ast.Attribute):
            parts = []
            n = node.func
            while isinstance(n, ast.Attribute):
                parts.append(n.attr)
                n = n.value
            if isinstance(n, ast.Name):
                parts.append(n.id)
            return ".".join(reversed(parts))
        return ""

    def _get_attribute_chain(self, node: ast.Attribute) -> str:
        """Get the full attribute chain (e.g., 'request.args.get')."""
        parts = []
        n = node
        while isinstance(n, ast.Attribute):
            parts.append(n.attr)
            n = n.value
        if isinstance(n, ast.Name):
            parts.append(n.id)
        return ".".join(reversed(parts))

    def _get_attribute_base_name(self, node: ast.Attribute) -> str:
        """Get the base name of an attribute chain."""
        n = node
        while isinstance(n, ast.Attribute):
            n = n.value
        if isinstance(n, ast.Name):
            return n.id
        return ""

    def _get_subscript_base(self, node: ast.Subscript) -> str:
        """Get the base name of a subscript expression."""
        n = node.value
        while isinstance(n, ast.Attribute):
            n = n.value
        if isinstance(n, ast.Name):
            return n.id
        return ""

    def _get_tainted_var_name(
        self, node: ast.AST, tainted_vars: Dict[str, int]
    ) -> str:
        """Get the name of the tainted variable used in a node."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in tainted_vars:
                return child.id
            elif isinstance(child, ast.Attribute):
                base = self._get_attribute_base_name(child)
                if base and base in tainted_vars:
                    return base
        return "unknown"

    def _flows_to_vulnerabilities(
        self, scan_id: str
    ) -> List[Vulnerability]:
        """Convert TaintFlows to Vulnerability objects."""
        vulns: List[Vulnerability] = []
        seen: Set[str] = set()

        for flow in self.taint_flows:
            # Deduplicate by file + sink_line + category
            key = f"{flow.file_path}:{flow.sink_line}:{flow.category}"
            if key in seen:
                continue
            seen.add(key)

            vuln = Vulnerability(
                scan_id=scan_id,
                file_path=flow.file_path,
                line_number=flow.sink_line,
                severity=flow.severity,
                category=f"Taint: {flow.category}",
                cwe_id=flow.cwe,
                cwe_name=flow.category,
                title=f"{flow.category}: {flow.source_var} -> {flow.sink_func}",
                description=(
                    f"{flow.description}\n\n"
                    f"Source variable: '{flow.source_var}' (line {flow.source_line})\n"
                    f"Sink function: '{flow.sink_func}' (line {flow.sink_line})\n"
                    f"Data path: {' -> '.join(flow.data_path)}"
                ),
                code_snippet=f"{flow.sink_func}",
                fix_suggestion=self._get_remediation(flow.sink_type),
                tool_source="taint_analyzer",
                confidence="HIGH",
            )
            vulns.append(vuln)

        return vulns

    def _get_remediation(self, sink_type: str) -> str:
        """Get remediation advice for a sink type."""
        remediations = {
            "sql_injection": (
                "Use parameterized queries or an ORM. "
                "Never concatenate user input into SQL strings. "
                "Example: cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
            ),
            "command_injection": (
                "Use subprocess with a list of arguments instead of shell=True. "
                "Validate and whitelist allowed commands. "
                "Example: subprocess.run(['ls', '-la', safe_path], shell=False)"
            ),
            "xss": (
                "Use template auto-escaping or explicitly escape output. "
                "Use a framework like Jinja2 with autoescape=True. "
                "Sanitize user input before rendering in HTML."
            ),
            "path_traversal": (
                "Use os.path.abspath() and validate paths against allowed directories. "
                "Use pathlib.Path with resolved paths. "
                "Never use user input directly in file paths."
            ),
            "ssrf": (
                "Validate URLs against an allowlist of allowed hosts/schemes. "
                "Block internal network addresses (127.0.0.1, 10.x.x.x, etc.). "
                "Use a dedicated SSRF-prevention library."
            ),
            "code_injection": (
                "Never pass user input to eval(), exec(), or compile(). "
                "Use ast.literal_eval() for safe evaluation of literals only. "
                "Implement a safe expression parser if dynamic evaluation is needed."
            ),
            "ldap_injection": (
                "Use parameterized LDAP queries. "
                "Escape special characters in LDAP filters. "
                "Validate user input against allowed patterns."
            ),
            "xpath_injection": (
                "Use parameterized XPath queries. "
                "Validate user input before including in XPath expressions."
            ),
            "xml_injection": (
                "Use defusedxml library for safe XML parsing. "
                "Disable external entity processing (XXE prevention). "
                "Validate XML input against a strict schema."
            ),
        }
        return remediations.get(
            sink_type,
            "Validate and sanitize all user input before using in security-sensitive operations.",
        )

    def get_analysis_summary(self) -> Dict[str, Any]:
        """Get a summary of the taint analysis results."""
        category_counts: Dict[str, int] = {}
        severity_counts: Dict[str, int] = {}

        for flow in self.taint_flows:
            category_counts[flow.category] = category_counts.get(flow.category, 0) + 1
            severity_counts[flow.severity] = severity_counts.get(flow.severity, 0) + 1

        return {
            "total_flows": len(self.taint_flows),
            "by_category": category_counts,
            "by_severity": severity_counts,
            "sanitized_flows": sum(1 for f in self.taint_flows if f.sanitized),
            "unsanitized_flows": sum(1 for f in self.taint_flows if not f.sanitized),
        }
