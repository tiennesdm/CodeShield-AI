"""
Constants for CodeShield AI.

Contains CWE mappings, OWASP Top 10, severity levels, and language/tool mappings.
"""

from typing import Dict, List, Set

# Severity levels with weights for risk scoring
SEVERITY_LEVELS = {
    "CRITICAL": {"weight": 25, "color": "#DC2626", "description": "Immediate action required"},
    "HIGH": {"weight": 10, "color": "#EA580C", "description": "Address as soon as possible"},
    "MEDIUM": {"weight": 4, "color": "#D97706", "description": "Address in next sprint"},
    "LOW": {"weight": 1, "color": "#65A30D", "description": "Address when convenient"},
    "INFO": {"weight": 0, "color": "#2563EB", "description": "Informational only"},
}

# OWASP Top 10 2021
OWASP_TOP10 = {
    "A01": {"name": "Broken Access Control", "description": "Restrictions on authenticated users are not properly enforced."},
    "A02": {"name": "Cryptographic Failures", "description": "Failures related to cryptography leading to sensitive data exposure."},
    "A03": {"name": "Injection", "description": "User-supplied data is not validated, filtered, or sanitized."},
    "A04": {"name": "Insecure Design", "description": "Missing or ineffective security controls in design."},
    "A05": {"name": "Security Misconfiguration", "description": "Improperly configured permissions, defaults, or security headers."},
    "A06": {"name": "Vulnerable and Outdated Components", "description": "Using components with known vulnerabilities."},
    "A07": {"name": "Identification and Authentication Failures", "description": "Authentication-related attacks to user identities."},
    "A08": {"name": "Software and Data Integrity Failures", "description": "Assumptions related to software updates and CI/CD pipelines."},
    "A09": {"name": "Security Logging and Monitoring Failures", "description": "Insufficient logging and monitoring of security events."},
    "A10": {"name": "Server-Side Request Forgery (SSRF)", "description": "Fetching a remote resource without validating the user-supplied URL."},
}

# CWE to OWASP mapping
CWE_TO_OWASP: Dict[str, str] = {
    # Injection
    "CWE-77": "A03",
    "CWE-78": "A03",
    "CWE-79": "A03",
    "CWE-80": "A03",
    "CWE-89": "A03",
    "CWE-90": "A03",
    "CWE-91": "A03",
    "CWE-93": "A03",
    "CWE-94": "A03",
    "CWE-95": "A03",
    "CWE-116": "A03",
    # Broken Access Control
    "CWE-22": "A01",
    "CWE-23": "A01",
    "CWE-285": "A01",
    "CWE-287": "A07",
    "CWE-306": "A07",
    "CWE-307": "A07",
    "CWE-798": "A07",
    "CWE-639": "A01",
    # Cryptographic Failures
    "CWE-311": "A02",
    "CWE-312": "A02",
    "CWE-319": "A02",
    "CWE-326": "A02",
    "CWE-327": "A02",
    "CWE-328": "A02",
    "CWE-330": "A02",
    "CWE-502": "A08",
    # Security Misconfiguration
    "CWE-209": "A05",
    "CWE-200": "A05",
    "CWE-548": "A05",
    "CWE-1004": "A05",
    # SSRF
    "CWE-918": "A10",
}

# Common CWE names
CWE_MAPPING: Dict[str, str] = {
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-site Scripting (XSS)",
    "CWE-89": "SQL Injection",
    "CWE-90": "LDAP Injection",
    "CWE-91": "XML Injection",
    "CWE-94": "Code Injection",
    "CWE-95": "Eval Injection",
    "CWE-116": "Improper Encoding",
    "CWE-209": "Information Exposure",
    "CWE-200": "Information Exposure",
    "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication",
    "CWE-311": "Missing Encryption",
    "CWE-312": "Cleartext Storage",
    "CWE-319": "Cleartext Transmission",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Broken Crypto",
    "CWE-330": "Insufficient Randomness",
    "CWE-502": "Deserialization",
    "CWE-548": "Directory Listing",
    "CWE-639": "Authorization Bypass",
    "CWE-798": "Hardcoded Credentials",
    "CWE-918": "Server-Side Request Forgery",
    "CWE-1004": "Sensitive Cookie Without HttpOnly",
    "CWE-352": "Cross-Site Request Forgery",
    "CWE-384": "Session Fixation",
    "CWE-434": "Unrestricted File Upload",
    "CWE-601": "Open Redirect",
    "CWE-732": "Incorrect Permission Assignment",
}

# Supported languages
SUPPORTED_LANGUAGES = {
    "python": {
        "extensions": {".py"},
        "name": "Python",
        "frameworks": ["Django", "Flask", "FastAPI", "Tornado", "Pyramid"],
    },
    "javascript": {
        "extensions": {".js", ".jsx", ".mjs"},
        "name": "JavaScript",
        "frameworks": ["React", "Vue", "Angular", "Express", "Node.js"],
    },
    "typescript": {
        "extensions": {".ts", ".tsx"},
        "name": "TypeScript",
        "frameworks": ["React", "Vue", "Angular", "NestJS"],
    },
    "java": {
        "extensions": {".java"},
        "name": "Java",
        "frameworks": ["Spring", "Spring Boot", "Jakarta EE", "Hibernate"],
    },
    "go": {
        "extensions": {".go"},
        "name": "Go",
        "frameworks": ["Gin", "Echo", "Fiber"],
    },
    "ruby": {
        "extensions": {".rb"},
        "name": "Ruby",
        "frameworks": ["Rails", "Sinatra"],
    },
    "php": {
        "extensions": {".php"},
        "name": "PHP",
        "frameworks": ["Laravel", "Symfony", "CodeIgniter"],
    },
    "csharp": {
        "extensions": {".cs"},
        "name": "C#",
        "frameworks": [".NET", "ASP.NET Core"],
    },
    "swift": {
        "extensions": {".swift"},
        "name": "Swift",
        "frameworks": ["Vapor", "Perfect"],
    },
    "kotlin": {
        "extensions": {".kt", ".kts"},
        "name": "Kotlin",
        "frameworks": ["Ktor", "Spring"],
    },
    "rust": {
        "extensions": {".rs"},
        "name": "Rust",
        "frameworks": ["Actix", "Rocket"],
    },
    "html": {
        "extensions": {".html", ".htm"},
        "name": "HTML",
        "frameworks": [],
    },
    "dockerfile": {
        "extensions": {"", ".dockerfile"},
        "name": "Dockerfile",
        "frameworks": [],
    },
    "terraform": {
        "extensions": {".tf", ".tfvars"},
        "name": "Terraform",
        "frameworks": [],
    },
    "sql": {
        "extensions": {".sql"},
        "name": "SQL",
        "frameworks": [],
    },
}

# Tool to language mapping
TOOL_LANGUAGE_MAP = {
    "semgrep": [
        "python",
        "javascript",
        "typescript",
        "java",
        "go",
        "ruby",
        "php",
        "csharp",
        "swift",
        "kotlin",
        "rust",
        "html",
    ],
    "eslint": ["javascript", "typescript"],
    "pylint": ["python"],
    "bandit": ["python"],
    "pmd": ["java"],
    "gitleaks": ["*"],  # All languages
    "dependency_check": ["*"],  # All languages
    "custom_ai": ["*"],  # All languages
}

# File patterns to detect frameworks
FRAMEWORK_PATTERNS = {
    "React": ["package.json", ".jsx", ".tsx", "react", "React"],
    "React Native": ["package.json", "react-native"],
    "Vue": ["package.json", "vue"],
    "Angular": ["angular.json", "package.json", "@angular"],
    "Node.js": ["package.json", "node_modules", "server.js"],
    "Express": ["package.json", "express"],
    "Django": ["manage.py", "settings.py", "wsgi.py", "django"],
    "Flask": ["app.py", "flask", "Flask"],
    "FastAPI": ["fastapi", "FastAPI"],
    "Spring Boot": ["pom.xml", "build.gradle", "spring-boot"],
    "Spring": ["pom.xml", "build.gradle", "Application.java"],
    "Rails": ["Gemfile", "config/routes.rb", "app/controllers"],
    "Laravel": ["composer.json", "artisan"],
    ".NET": [".csproj", ".sln"],
    "ASP.NET Core": ["Startup.cs", "Program.cs", ".csproj"],
}

# Severity mapping from tool-specific levels to standard levels
SEVERITY_MAP = {
    # Bandit
    "LOW": "LOW",
    "MEDIUM": "MEDIUM",
    "HIGH": "HIGH",
    # Semgrep
    "ERROR": "HIGH",
    "WARNING": "MEDIUM",
    "INFO": "INFO",
    # ESLint
    "1": "LOW",
    "2": "MEDIUM",
    # PMD
    "1": "LOW",
    "2": "MEDIUM",
    "3": "HIGH",
    "4": "CRITICAL",
    "5": "CRITICAL",
    # Gitleaks
    "CRITICAL": "CRITICAL",
    # Dependency Check
    "0.0": "INFO",
    "1.0": "LOW",
    "4.0": "MEDIUM",
    "7.0": "HIGH",
    # Generic
    "blocker": "CRITICAL",
    "critical": "CRITICAL",
    "major": "HIGH",
    "high": "HIGH",
    "minor": "MEDIUM",
    "medium": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
}

# Scan phases for progress tracking
SCAN_PHASES = [
    ("initialization", 5),
    ("language_detection", 15),
    ("tool_selection", 20),
    ("scanning", 80),
    ("parsing", 90),
    ("reporting", 100),
]
