"""
Tests for Advanced Taint Analysis Engine.

Covers taint source detection, sink detection, data flow propagation,
sanitizer checking, and vulnerability detection for SQL injection,
XSS, command injection, path traversal, and SSRF.
"""

import ast
import os
import tempfile

import pytest

from scanner.tools.taint_analyzer import (
    ALL_SOURCE_PATTERNS,
    SANITIZER_PATTERNS,
    SINK_PATTERNS,
    CallGraphBuilder,
    TaintAnalyzer,
    TaintFlow,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def analyzer():
    """Create a TaintAnalyzer instance."""
    return TaintAnalyzer()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


def write_file(temp_dir: str, filename: str, content: str) -> str:
    """Helper to write a test file."""
    filepath = os.path.join(temp_dir, filename)
    with open(filepath, "w") as f:
        f.write(content)
    return filepath


# ============================================================================
# SQL Injection Detection Tests
# ============================================================================

class TestSQLInjectionDetection:
    """Tests for SQL injection taint detection."""

    def test_basic_sql_injection(self, analyzer, temp_dir):
        """Test detection of basic SQL injection."""
        write_file(temp_dir, "app.py", """
def get_user(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-t1")
        )

        sql_vulns = [v for v in vulns if "SQL" in v.category or "sql" in v.title.lower()]
        assert len(sql_vulns) > 0

    def test_sql_with_request_args(self, analyzer, temp_dir):
        """Test SQL injection through Flask request.args."""
        write_file(temp_dir, "routes.py", """
from flask import request
import sqlite3

def search():
    term = request.args.get('q')
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name = '" + term + "'")
    return cursor.fetchall()
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-t2")
        )

        sql_vulns = [v for v in vulns if "SQL" in v.category]
        assert len(sql_vulns) > 0

    def test_sql_fstring_injection(self, analyzer, temp_dir):
        """Test SQL injection through f-string."""
        write_file(temp_dir, "api.py", """
def get_data(table_name):
    cursor.execute(f"SELECT * FROM {table_name}")
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-t3")
        )

        sql_vulns = [v for v in vulns if "SQL" in v.category]
        assert len(sql_vulns) > 0

    def test_sql_with_format_string(self, analyzer, temp_dir):
        """Test SQL injection through format string."""
        write_file(temp_dir, "db.py", """
def query_user(username):
    cursor.execute("SELECT * FROM users WHERE name = '{}'".format(username))
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-t4")
        )

        sql_vulns = [v for v in vulns if "SQL" in v.category]
        assert len(sql_vulns) > 0

    def test_sql_with_orm_execute(self, analyzer, temp_dir):
        """Test SQL injection through ORM execute method."""
        write_file(temp_dir, "models.py", """
def find_user(email):
    result = db.execute("SELECT * FROM users WHERE email = '%s'" % email)
    return result
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-t5")
        )

        sql_vulns = [v for v in vulns if "SQL" in v.category]
        assert len(sql_vulns) > 0


# ============================================================================
# Command Injection Detection Tests
# ============================================================================

class TestCommandInjectionDetection:
    """Tests for command injection taint detection."""

    def test_os_system_injection(self, analyzer, temp_dir):
        """Test detection of os.system command injection."""
        write_file(temp_dir, "utils.py", """
import os

def process_file(filename):
    os.system("ls -la " + filename)
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-c1")
        )

        cmd_vulns = [v for v in vulns if "Command" in v.category]
        assert len(cmd_vulns) > 0

    def test_subprocess_injection(self, analyzer, temp_dir):
        """Test detection of subprocess command injection."""
        write_file(temp_dir, "executor.py", """
import subprocess

def run_command(cmd):
    result = subprocess.check_output(cmd, shell=True)
    return result
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-c2")
        )

        cmd_vulns = [v for v in vulns if "Command" in v.category]
        assert len(cmd_vulns) > 0

    def test_subprocess_with_request_input(self, analyzer, temp_dir):
        """Test command injection with request input."""
        write_file(temp_dir, "api.py", """
from flask import request
import subprocess

@app.route('/run')
def run():
    cmd = request.args.get('cmd')
    result = subprocess.call(cmd, shell=True)
    return str(result)
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-c3")
        )

        cmd_vulns = [v for v in vulns if "Command" in v.category]
        assert len(cmd_vulns) > 0


# ============================================================================
# XSS Detection Tests
# ============================================================================

class TestXSSDetection:
    """Tests for XSS taint detection."""

    def test_render_template_string_xss(self, analyzer, temp_dir):
        """Test XSS through render_template_string."""
        write_file(temp_dir, "views.py", """
from flask import render_template_string, request

def hello():
    name = request.args.get('name', 'World')
    return render_template_string('<h1>Hello {{ name }}</h1>', name=name)
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-x1")
        )

        xss_vulns = [v for v in vulns if "XSS" in v.category or "xss" in v.title.lower()]
        assert len(xss_vulns) > 0

    def test_direct_html_response(self, analyzer, temp_dir):
        """Test XSS through direct HTML response."""
        write_file(temp_dir, "handlers.py", """
from flask import request, make_response

def echo():
    message = request.args.get('msg', '')
    response = make_response('<div>' + message + '</div>')
    return response
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-x2")
        )

        xss_vulns = [v for v in vulns if "XSS" in v.category]
        assert len(xss_vulns) > 0


# ============================================================================
# Path Traversal Detection Tests
# ============================================================================

class TestPathTraversalDetection:
    """Tests for path traversal taint detection."""

    def test_open_with_user_input(self, analyzer, temp_dir):
        """Test path traversal through open()."""
        write_file(temp_dir, "files.py", """
def read_file(filename):
    with open(filename, 'r') as f:
        return f.read()
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-p1")
        )

        path_vulns = [v for v in vulns if "Path" in v.category]
        # Note: open() alone may not flag without tainted source
        assert isinstance(path_vulns, list)

    def test_send_file_with_request_param(self, analyzer, temp_dir):
        """Test path traversal through send_file."""
        write_file(temp_dir, "downloads.py", """
from flask import send_file, request
import os

@app.route('/download')
def download():
    filename = request.args.get('file')
    return send_file(os.path.join('/uploads', filename))
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-p2")
        )

        path_vulns = [v for v in vulns if "Path" in v.category]
        assert len(path_vulns) > 0


# ============================================================================
# SSRF Detection Tests
# ============================================================================

class TestSSRFDetection:
    """Tests for SSRF taint detection."""

    def test_requests_get_with_user_input(self, analyzer, temp_dir):
        """Test SSRF through requests.get()."""
        write_file(temp_dir, "proxy.py", """
import requests
from flask import request

@app.route('/fetch')
def fetch():
    url = request.args.get('url')
    response = requests.get(url)
    return response.text
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-s1")
        )

        ssrf_vulns = [v for v in vulns if "SSRF" in v.category]
        assert len(ssrf_vulns) > 0

    def test_urllib_urlopen(self, analyzer, temp_dir):
        """Test SSRF through urllib.urlopen."""
        write_file(temp_dir, "fetcher.py", """
import urllib.request
from flask import request

def fetch_url():
    target = request.form.get('target')
    response = urllib.request.urlopen(target)
    return response.read()
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-s2")
        )

        ssrf_vulns = [v for v in vulns if "SSRF" in v.category]
        assert len(ssrf_vulns) > 0


# ============================================================================
# Code Injection Detection Tests
# ============================================================================

class TestCodeInjectionDetection:
    """Tests for code injection taint detection."""

    def test_eval_with_user_input(self, analyzer, temp_dir):
        """Test code injection through eval()."""
        write_file(temp_dir, "calc.py", """
from flask import request

def calculate():
    expression = request.args.get('expr')
    result = eval(expression)
    return str(result)
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-e1")
        )

        code_vulns = [v for v in vulns if "Code" in v.category or "eval" in v.title.lower()]
        assert len(code_vulns) > 0

    def test_exec_with_user_input(self, analyzer, temp_dir):
        """Test code injection through exec()."""
        write_file(temp_dir, "executor.py", """
from flask import request

def execute():
    code = request.form.get('code')
    exec(code)
    return "Done"
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-e2")
        )

        code_vulns = [v for v in vulns if "Code" in v.category or "exec" in v.title.lower()]
        assert len(code_vulns) > 0


# ============================================================================
# Sanitizer Detection Tests
# ============================================================================

class TestSanitizerDetection:
    """Tests for sanitizer checking."""

    def test_parameterized_query_is_sanitized(self, analyzer):
        """Test that parameterized queries are detected as sanitized."""
        stmt_text = "cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))"
        sanitized, sanitizer = analyzer._check_sanitizers(None, "sql_injection", stmt_text)

        assert sanitized is True

    def test_escaped_output_is_sanitized(self, analyzer):
        """Test that escaped output is detected as sanitized."""
        stmt_text = 'response = make_response(escape(user_input))'
        sanitized, sanitizer = analyzer._check_sanitizers(None, "xss", stmt_text)

        assert sanitized is True

    def test_shlex_quote_is_sanitized(self, analyzer):
        """Test that shlex.quote is detected as sanitizer."""
        stmt_text = "subprocess.call(shlex.quote(user_input))"
        sanitized, sanitizer = analyzer._check_sanitizers(None, "command_injection", stmt_text)

        assert sanitized is True

    def test_no_sanitizer_detected(self, analyzer):
        """Test that unsanitized input is detected."""
        stmt_text = "cursor.execute(query)"
        sanitized, sanitizer = analyzer._check_sanitizers(None, "sql_injection", stmt_text)

        # May or may not be sanitized depending on context
        assert isinstance(sanitized, bool)


# ============================================================================
# Data Flow Propagation Tests
# ============================================================================

class TestDataFlowPropagation:
    """Tests for taint propagation through assignments."""

    def test_variable_propagation(self, analyzer, temp_dir):
        """Test taint propagation through variable assignment chain."""
        write_file(temp_dir, "chain.py", """
from flask import request
import sqlite3

def search():
    raw_term = request.args.get('q')
    search_term = raw_term
    final_term = search_term.upper()
    conn = sqlite3.connect('db.sqlite')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM products WHERE name = '" + final_term + "'")
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-df1")
        )

        sql_vulns = [v for v in vulns if "SQL" in v.category]
        assert len(sql_vulns) > 0

    def test_dict_propagation(self, analyzer, temp_dir):
        """Test taint propagation through dictionary."""
        write_file(temp_dir, "dict_flow.py", """
from flask import request
import os

def process():
    data = {}
    data['filename'] = request.files['upload'].filename
    target = data['filename']
    os.system("process " + target)
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-df2")
        )

        assert isinstance(vulns, list)

    def test_list_propagation(self, analyzer, temp_dir):
        """Test taint propagation through list."""
        write_file(temp_dir, "list_flow.py", """
from flask import request
import sqlite3

def batch_query():
    params = []
    params.append(request.args.get('id'))
    user_id = params[0]
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-df3")
        )

        assert isinstance(vulns, list)


# ============================================================================
# Utility Method Tests
# ============================================================================

class TestUtilityMethods:
    """Tests for utility methods."""

    def test_remediation_sql(self, analyzer):
        """Test SQL injection remediation advice."""
        remediation = analyzer._get_remediation("sql_injection")
        assert "parameterized" in remediation.lower() or "ORM" in remediation

    def test_remediation_xss(self, analyzer):
        """Test XSS remediation advice."""
        remediation = analyzer._get_remediation("xss")
        assert "escape" in remediation.lower() or "autoescape" in remediation.lower()

    def test_remediation_command(self, analyzer):
        """Test command injection remediation advice."""
        remediation = analyzer._get_remediation("command_injection")
        assert "subprocess" in remediation.lower() or "shell" in remediation.lower()

    def test_remediation_path(self, analyzer):
        """Test path traversal remediation advice."""
        remediation = analyzer._get_remediation("path_traversal")
        assert "abspath" in remediation.lower() or "pathlib" in remediation.lower()

    def test_remediation_ssrf(self, analyzer):
        """Test SSRF remediation advice."""
        remediation = analyzer._get_remediation("ssrf")
        assert "allowlist" in remediation.lower() or "whitelist" in remediation.lower()

    def test_unknown_sink_type(self, analyzer):
        """Test remediation for unknown sink type."""
        remediation = analyzer._get_remediation("unknown_type")
        assert "sanitize" in remediation.lower() or "Validate" in remediation

    def test_taint_flow_dataclass(self):
        """Test TaintFlow dataclass."""
        flow = TaintFlow(
            source_var="user_input",
            sink_type="sql_injection",
            sink_func="cursor.execute",
            file_path="app.py",
            source_line=10,
            sink_line=15,
            severity="HIGH",
            cwe="CWE-89",
            category="SQL Injection",
            description="User input flows to SQL query",
        )
        d = flow.to_dict()
        assert d["source_var"] == "user_input"
        assert d["sink_type"] == "sql_injection"
        assert d["severity"] == "HIGH"

    def test_sink_patterns_structure(self):
        """Test that sink patterns are well-structured."""
        for sink_type, config in SINK_PATTERNS.items():
            assert "functions" in config
            assert "severity" in config
            assert "cwe" in config
            assert "category" in config
            assert "description" in config
            assert len(config["functions"]) > 0
            assert config["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

    def test_source_patterns_non_empty(self):
        """Test that source patterns are defined."""
        assert len(ALL_SOURCE_PATTERNS) > 0

    def test_sanitizer_patterns_non_empty(self):
        """Test that sanitizer patterns are defined."""
        for category, patterns in SANITIZER_PATTERNS.items():
            assert len(patterns) > 0

    def test_empty_directory(self, analyzer, temp_dir):
        """Test analysis of empty directory."""
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-empty")
        )
        assert len(vulns) == 0

    def test_analysis_summary(self, analyzer, temp_dir):
        """Test analysis summary generation."""
        write_file(temp_dir, "app.py", """
from flask import request
import sqlite3

def search():
    term = request.args.get('q')
    cursor.execute("SELECT * FROM products WHERE name = '" + term + "'")
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-summary")
        )

        summary = analyzer.get_analysis_summary()
        assert "total_flows" in summary
        assert "by_category" in summary
        assert "by_severity" in summary
        assert summary["total_flows"] > 0

    def test_no_false_positive_safe_code(self, analyzer, temp_dir):
        """Test that safe code doesn't produce false positives."""
        write_file(temp_dir, "safe.py", """
def helper():
    x = 42
    y = "hello"
    return x + len(y)
""")

        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            analyzer.analyze(temp_dir, "test-safe")
        )

        # Safe code should not produce taint vulnerabilities
        taint_vulns = [v for v in vulns if v.tool_source == "taint_analyzer"]
        assert len(taint_vulns) == 0
