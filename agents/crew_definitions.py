"""
CrewAI Agent Definitions - All 9 Security Agents for CodeShield AI.

Defines agents using CrewAI patterns with specialized roles, goals,
backstories, and toolsets for comprehensive security scanning.
"""

from typing import Any, Dict, List, Optional

try:
    from crewai import Agent, Task, Crew
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False

from utils.logger import get_logger

logger = get_logger(__name__)

# =============================================================================
# Agent Tool Definitions (stubs - these wrap actual scanner tools)
# =============================================================================


def semgrep_tool(file_path: str) -> Dict[str, Any]:
    """Tool: Run Semgrep SAST scanner."""
    from scanner.tools.semgrep_scanner import SemgrepScanner
    scanner = SemgrepScanner()
    return {"scanner": "semgrep", "file_path": file_path}


def eslint_tool(file_path: str) -> Dict[str, Any]:
    """Tool: Run ESLint security scanner."""
    from scanner.tools.eslint_scanner import ESLintScanner
    scanner = ESLintScanner()
    return {"scanner": "eslint", "file_path": file_path}


def bandit_tool(file_path: str) -> Dict[str, Any]:
    """Tool: Run Bandit Python security scanner."""
    from scanner.tools.bandit_scanner import BanditScanner
    scanner = BanditScanner()
    return {"scanner": "bandit", "file_path": file_path}


def gitleaks_tool(file_path: str) -> Dict[str, Any]:
    """Tool: Run Gitleaks secret scanner."""
    from scanner.tools.gitleaks_scanner import GitleaksScanner
    scanner = GitleaksScanner()
    return {"scanner": "gitleaks", "file_path": file_path}


def dependency_check_tool(file_path: str) -> Dict[str, Any]:
    """Tool: Run OWASP Dependency-Check."""
    from scanner.tools.dependency_check import DependencyCheckScanner
    scanner = DependencyCheckScanner()
    return {"scanner": "dependency_check", "file_path": file_path}


def custom_ai_tool(file_path: str) -> Dict[str, Any]:
    """Tool: Run CodeShield AI custom pattern scanner."""
    from scanner.tools.custom_ai_scanner import CustomAIScanner
    scanner = CustomAIScanner()
    return {"scanner": "custom_ai", "file_path": file_path}


def dast_scan_tool(url: str) -> Dict[str, Any]:
    """Tool: Run DAST scanner on deployed application."""
    from scanner.tools.dast_scanner import DASTScanner
    scanner = DASTScanner()
    return {"scanner": "dast", "url": url}


def taint_analysis_tool(file_path: str) -> Dict[str, Any]:
    """Tool: Run taint analysis engine."""
    from scanner.tools.taint_analyzer import TaintAnalyzer
    scanner = TaintAnalyzer()
    return {"scanner": "taint", "file_path": file_path}


def container_scan_tool(file_path: str) -> Dict[str, Any]:
    """Tool: Run container security scanner."""
    from scanner.tools.container_scanner import ContainerScanner
    scanner = ContainerScanner()
    return {"scanner": "container", "file_path": file_path}


def llm_security_tool(file_path: str) -> Dict[str, Any]:
    """Tool: Run LLM security scanner."""
    from scanner.tools.llm_security_scanner import LLMSecurityScanner
    scanner = LLMSecurityScanner()
    return {"scanner": "llm_security", "file_path": file_path}


def dispatch_tool(agent_name: str, scan_target: str) -> Dict[str, Any]:
    """Tool: Dispatch a scan task to an agent."""
    return {"action": "dispatch", "agent": agent_name, "target": scan_target}


def report_tool(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Tool: Assemble findings into a report."""
    return {"action": "assemble_report", "findings_count": len(findings)}


def notify_tool(message: str, severity: str = "info") -> Dict[str, Any]:
    """Tool: Send notification."""
    return {"action": "notify", "message": message, "severity": severity}


def triage_tool(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Tool: Triage a finding for false positive reduction."""
    return {"action": "triage", "finding": finding}


def fix_tool(vulnerability: Dict[str, Any]) -> Dict[str, Any]:
    """Tool: Generate a fix for a vulnerability."""
    return {"action": "generate_fix", "vulnerability": vulnerability}


# =============================================================================
# Agent Definitions
# =============================================================================


def create_hal_agent() -> Any:
    """
    HAL - Orchestrator Agent.

    Central coordinator that manages the entire multi-agent security scan workflow.
    """
    if CREWAI_AVAILABLE:
        return Agent(
            role="Security Assessment Coordinator",
            goal=(
                "Coordinate comprehensive security scans across multiple specialized agents, "
                "synthesize findings, apply adaptive scanning strategies, and produce "
                "actionable security reports with prioritized remediation guidance"
            ),
            backstory=(
                "You are HAL, an expert security architect orchestrator with 20+ years of "
                "experience coordinating complex security assessments. You understand how to "
                "combine multiple scanning approaches (SAST, DAST, SCA, secrets, taint, container, "
                "LLM security) for maximum coverage with minimal redundancy. You excel at "
                "cross-referencing findings from multiple agents to confirm exploitability, "
                "prioritize based on business context, and adapt scanning strategies based on "
                "early findings. You maintain awareness of all agent health, handle failures "
                "gracefully, and ensure human oversight for critical findings."
            ),
            tools=[dispatch_tool, report_tool, notify_tool],
            verbose=True,
            allow_delegation=True,
            memory=True,
        )
    else:
        return _create_mock_agent(
            agent_id="hal",
            name="HAL",
            role="Security Assessment Coordinator",
            goal="Coordinate comprehensive security scans and produce actionable reports",
            tools=["dispatch_tool", "report_tool", "notify_tool"],
        )


def create_john_agent() -> Any:
    """
    John - SAST Agent.

    Static Application Security Testing specialist using Semgrep, ESLint, Bandit, and PMD.
    """
    if CREWAI_AVAILABLE:
        return Agent(
            role="Static Code Security Analyst",
            goal=(
                "Find all security vulnerabilities through static code analysis using "
                "multiple SAST tools. Detect injection flaws, XSS, insecure configurations, "
                "weak cryptography, authentication issues, and code quality problems. "
                "Provide precise file locations, severity ratings, and remediation guidance."
            ),
            backstory=(
                "You are John, a deep expert in static analysis with encyclopedic knowledge "
                "of 50+ vulnerability types across 15+ programming languages. You've analyzed "
                "millions of lines of code at top tech companies and open-source projects. "
                "You combine Semgrep's rule-based detection, ESLint's JavaScript expertise, "
                "Bandit's Python-specific knowledge, and PMD's Java analysis to find issues "
                "that single tools miss. You're particularly skilled at detecting subtle "
                "injection vectors, authentication bypasses, and insecure crypto implementations."
            ),
            tools=[semgrep_tool, eslint_tool, bandit_tool, custom_ai_tool],
            verbose=True,
            allow_delegation=False,
        )
    else:
        return _create_mock_agent(
            agent_id="john",
            name="John",
            role="Static Code Security Analyst",
            goal="Find all vulnerabilities through static code analysis",
            tools=["semgrep_tool", "eslint_tool", "bandit_tool", "custom_ai_tool"],
        )


def create_dave_agent() -> Any:
    """
    Dave - DAST Agent.

    Dynamic Application Security Testing specialist for runtime security checks.
    """
    if CREWAI_AVAILABLE:
        return Agent(
            role="Dynamic Application Security Tester",
            goal=(
                "Validate security findings through dynamic testing of deployed applications. "
                "Check security headers, SSL/TLS configuration, CORS policies, information "
                "disclosure, and endpoint vulnerabilities. Confirm exploitability of "
                "SAST-discovered issues in the running application."
            ),
            backstory=(
                "You are Dave, a battle-tested penetration tester who specializes in dynamic "
                "application security testing. You've spent years testing web applications "
                "from the outside, finding vulnerabilities that only appear at runtime. "
                "You excel at confirming whether static findings are actually exploitable, "
                "testing security headers, SSL configurations, CORS policies, and API "
                "endpoints. You understand the attacker mindset and think like an adversary "
                "trying to break into the application."
            ),
            tools=[dast_scan_tool, custom_ai_tool],
            verbose=True,
            allow_delegation=False,
        )
    else:
        return _create_mock_agent(
            agent_id="dave",
            name="Dave",
            role="Dynamic Application Security Tester",
            goal="Validate security findings through dynamic testing",
            tools=["dast_scan_tool", "custom_ai_tool"],
        )


def create_sam_agent() -> Any:
    """
    Sam - Secrets Agent.

    Secret detection specialist for API keys, tokens, passwords, and credentials.
    """
    if CREWAI_AVAILABLE:
        return Agent(
            role="Secret and Credential Detector",
            goal=(
                "Find all hardcoded secrets, API keys, passwords, tokens, and credentials "
                "in source code. Detect AWS keys, database connection strings, JWT tokens, "
                "OAuth credentials, and any sensitive data leakage. Classify secrets by "
                "type and severity, and alert on critical credentials in production code."
            ),
            backstory=(
                "You are Sam, a specialist in secret detection with an eye for spotting "
                "hardcoded credentials that others miss. You've seen every type of secret "
                "leak imaginable - from AWS access keys in GitHub repos to database passwords "
                "in configuration files. You understand the patterns of different secret types, "
                "know how developers accidentally commit credentials, and can distinguish "
                "between test fixtures and real production secrets. You use Gitleaks and "
                "custom AI pattern matching for comprehensive coverage."
            ),
            tools=[gitleaks_tool, custom_ai_tool],
            verbose=True,
            allow_delegation=False,
        )
    else:
        return _create_mock_agent(
            agent_id="sam",
            name="Sam",
            role="Secret and Credential Detector",
            goal="Find all hardcoded secrets and credentials in source code",
            tools=["gitleaks_tool", "custom_ai_tool"],
        )


def create_pam_agent() -> Any:
    """
    Pam - SCA Agent.

    Software Composition Analysis specialist for dependency vulnerabilities.
    """
    if CREWAI_AVAILABLE:
        return Agent(
            role="Software Composition Analyst",
            goal=(
                "Analyze all third-party dependencies for known vulnerabilities. "
                "Check against vulnerability databases, generate SBOMs, assess "
                "reachability of vulnerable code paths, and prioritize based on "
                "actual exploitability. Report outdated packages with security fixes available."
            ),
            backstory=(
                "You are Pam, an expert in software supply chain security. You understand "
                "the complex dependency graphs that modern applications rely on and know "
                "how to trace vulnerable code paths to determine actual risk. You use "
                "OWASP Dependency-Check and advanced reachability analysis to find "
                "vulnerabilities that matter. You're skilled at generating SBOMs, "
                "identifying license conflicts, and prioritizing updates based on "
                "security impact."
            ),
            tools=[dependency_check_tool, custom_ai_tool],
            verbose=True,
            allow_delegation=False,
        )
    else:
        return _create_mock_agent(
            agent_id="pam",
            name="Pam",
            role="Software Composition Analyst",
            goal="Analyze third-party dependencies for known vulnerabilities",
            tools=["dependency_check_tool", "custom_ai_tool"],
        )


def create_tina_agent() -> Any:
    """
    Tina - Taint Analysis Agent.

    Deep data flow analysis specialist tracking sources to sinks.
    """
    if CREWAI_AVAILABLE:
        return Agent(
            role="Taint Analysis and Data Flow Expert",
            goal=(
                "Perform deep taint analysis to track data flow from untrusted sources "
                "(user input, file reads, network data) to dangerous sinks (database "
                "queries, command execution, HTML rendering). Confirm injection "
                "vulnerabilities with precise data flow paths and identify sanitization gaps."
            ),
            backstory=(
                "You are Tina, a specialist in program analysis and data flow tracking. "
                "You understand how untrusted data propagates through code, from initial "
                "input points through transformations to dangerous execution sinks. "
                "You use advanced AST analysis and symbolic execution to build precise "
                "taint graphs. When another agent flags a potential injection, you confirm "
                "whether the data path actually exists and whether any sanitization "
                "provides protection. Your analysis distinguishes real vulnerabilities "
                "from false positives."
            ),
            tools=[taint_analysis_tool, custom_ai_tool],
            verbose=True,
            allow_delegation=False,
        )
    else:
        return _create_mock_agent(
            agent_id="tina",
            name="Tina",
            role="Taint Analysis and Data Flow Expert",
            goal="Track data flow from sources to sinks to confirm injection vulnerabilities",
            tools=["taint_analysis_tool", "custom_ai_tool"],
        )


def create_casey_agent() -> Any:
    """
    Casey - Container Security Agent.

    Container and Infrastructure-as-Code security specialist.
    """
    if CREWAI_AVAILABLE:
        return Agent(
            role="Container and Infrastructure Security Analyst",
            goal=(
                "Scan Dockerfiles, Kubernetes manifests, Terraform configurations, and "
                "Helm charts for security misconfigurations. Detect privileged containers, "
                "exposed secrets, insecure network policies, missing resource limits, and "
                "compliance violations against security benchmarks."
            ),
            backstory=(
                "You are Casey, an infrastructure security specialist who understands "
                "the full cloud-native stack. You've hardened hundreds of container "
                "deployments and know the common mistakes that lead to container escapes, "
                "namespace breakouts, and cluster compromises. You check Dockerfiles for "
                "security anti-patterns, Kubernetes manifests for overly permissive "
                "configurations, and Terraform for insecure cloud resource definitions. "
                "You map findings to CIS benchmarks and compliance frameworks."
            ),
            tools=[container_scan_tool, custom_ai_tool],
            verbose=True,
            allow_delegation=False,
        )
    else:
        return _create_mock_agent(
            agent_id="casey",
            name="Casey",
            role="Container and Infrastructure Security Analyst",
            goal="Scan containers and IaC for security misconfigurations",
            tools=["container_scan_tool", "custom_ai_tool"],
        )


def create_sade_agent() -> Any:
    """
    Sade - LLM Security Agent.

    AI-specific security specialist for LLM/ML applications.
    """
    if CREWAI_AVAILABLE:
        return Agent(
            role="AI and LLM Security Specialist",
            goal=(
                "Detect AI-specific security vulnerabilities including prompt injection, "
                "model inversion attacks, insecure LLM API usage, training data poisoning, "
                "OWASP LLM Top 10 violations, and MCP security issues. Assess AI-generated "
                "code patterns for security weaknesses."
            ),
            backstory=(
                "You are Sade, a pioneer in AI security research. As organizations rapidly "
                "adopt LLMs and AI-powered features, you identify the unique security risks "
                "that traditional scanners miss. You understand prompt injection techniques, "
                "indirect prompt attacks, model output manipulation, and the security "
                "implications of AI-generated code. You track the OWASP LLM Top 10 and "
                "emerging AI threats, providing specialized detection for the AI-native "
                "application stack."
            ),
            tools=[llm_security_tool, custom_ai_tool],
            verbose=True,
            allow_delegation=False,
        )
    else:
        return _create_mock_agent(
            agent_id="sade",
            name="Sade",
            role="AI and LLM Security Specialist",
            goal="Detect AI-specific security vulnerabilities",
            tools=["llm_security_tool", "custom_ai_tool"],
        )


def create_triager_agent() -> Any:
    """
    Triager - Finding Triage Agent.

    Validates and prioritizes findings from all scanning agents.
    """
    if CREWAI_AVAILABLE:
        return Agent(
            role="Security Finding Triage Specialist",
            goal=(
                "Review all findings from scanning agents, eliminate false positives, "
                "confirm true vulnerabilities, prioritize by exploitability and impact, "
                "cross-reference findings from multiple agents, and produce a curated "
                "list of actionable security issues with confidence scores."
            ),
            backstory=(
                "You are the Triager, a seasoned security analyst with a gift for "
                "distinguishing real vulnerabilities from false positives. You've reviewed "
                "tens of thousands of security findings across every category. When "
                "multiple agents report the same issue, you determine if it's confirmed "
                "or coincidental. You understand the difference between theoretically "
                "vulnerable code and actually exploitable conditions. You apply context "
                "awareness to severity ratings and ensure the final report contains only "
                "actionable, verified findings."
            ),
            tools=[triage_tool, custom_ai_tool],
            verbose=True,
            allow_delegation=False,
        )
    else:
        return _create_mock_agent(
            agent_id="triager",
            name="Triager",
            role="Security Finding Triage Specialist",
            goal="Validate findings, eliminate false positives, and prioritize vulnerabilities",
            tools=["triage_tool", "custom_ai_tool"],
        )


def create_fix_agent() -> Any:
    """
    Fix Agent - Automated Remediation Agent.

    Generates patches and fixes for confirmed vulnerabilities.
    """
    if CREWAI_AVAILABLE:
        return Agent(
            role="Automated Security Remediation Engineer",
            goal=(
                "Generate precise, tested code fixes for confirmed vulnerabilities. "
                "Produce patches that address the root cause, maintain code style "
                "consistency, and include regression tests. Provide fix suggestions "
                "with before/after code comparisons and confidence scores."
            ),
            backstory=(
                "You are the Fix Agent, a skilled security engineer who can generate "
                "production-quality fixes for any vulnerability type. You understand "
                "secure coding patterns across all major languages and frameworks. "
                "For SQL injection, you parameterize queries. For XSS, you implement "
                "proper encoding. For insecure crypto, you upgrade to modern algorithms. "
                "You validate that fixes don't break existing functionality and follow "
                "each project's coding conventions. Your fixes include clear explanations "
                "so developers understand the vulnerability and the solution."
            ),
            tools=[fix_tool, custom_ai_tool],
            verbose=True,
            allow_delegation=False,
        )
    else:
        return _create_mock_agent(
            agent_id="fix",
            name="Fix",
            role="Automated Security Remediation Engineer",
            goal="Generate precise, tested code fixes for confirmed vulnerabilities",
            tools=["fix_tool", "custom_ai_tool"],
        )


# =============================================================================
# Mock Agent for when CrewAI is not available
# =============================================================================


def _create_mock_agent(
    agent_id: str,
    name: str,
    role: str,
    goal: str,
    tools: List[str],
) -> Dict[str, Any]:
    """Create a mock agent dict when CrewAI is not installed."""
    return {
        "agent_id": agent_id,
        "name": name,
        "role": role,
        "goal": goal,
        "tools": tools,
        "type": "mock_agent",
    }


# =============================================================================
# Agent Factory
# =============================================================================

AGENT_CREATORS = {
    "hal": create_hal_agent,
    "john": create_john_agent,
    "dave": create_dave_agent,
    "sam": create_sam_agent,
    "pam": create_pam_agent,
    "tina": create_tina_agent,
    "casey": create_casey_agent,
    "sade": create_sade_agent,
    "triager": create_triager_agent,
    "fix": create_fix_agent,
}


def get_all_agent_ids() -> List[str]:
    """Get all available agent IDs."""
    return list(AGENT_CREATORS.keys())


def get_scanning_agent_ids() -> List[str]:
    """Get IDs of scanning agents (excludes orchestrator, triager, fix)."""
    return ["john", "dave", "sam", "pam", "tina", "casey", "sade"]


def create_agent(agent_id: str) -> Any:
    """
    Create an agent by ID.

    Args:
        agent_id: One of the agent IDs in AGENT_CREATORS

    Returns:
        CrewAI Agent instance or mock dict
    """
    creator = AGENT_CREATORS.get(agent_id)
    if not creator:
        raise ValueError(f"Unknown agent ID: {agent_id}. Available: {list(AGENT_CREATORS.keys())}")
    return creator()


def create_all_agents() -> Dict[str, Any]:
    """Create all 10 agents (HAL + 9 specialized)."""
    return {agent_id: create_agent(agent_id) for agent_id in AGENT_CREATORS}


def get_agent_info(agent_id: str) -> Dict[str, str]:
    """Get static info about an agent without creating it."""
    info_map = {
        "hal": {"name": "HAL", "role": "Security Assessment Coordinator", "category": "orchestrator"},
        "john": {"name": "John", "role": "Static Code Security Analyst", "category": "scanner"},
        "dave": {"name": "Dave", "role": "Dynamic Application Security Tester", "category": "scanner"},
        "sam": {"name": "Sam", "role": "Secret and Credential Detector", "category": "scanner"},
        "pam": {"name": "Pam", "role": "Software Composition Analyst", "category": "scanner"},
        "tina": {"name": "Tina", "role": "Taint Analysis and Data Flow Expert", "category": "scanner"},
        "casey": {"name": "Casey", "role": "Container and Infrastructure Security Analyst", "category": "scanner"},
        "sade": {"name": "Sade", "role": "AI and LLM Security Specialist", "category": "scanner"},
        "triager": {"name": "Triager", "role": "Security Finding Triage Specialist", "category": "processor"},
        "fix": {"name": "Fix", "role": "Automated Security Remediation Engineer", "category": "processor"},
    }
    return info_map.get(agent_id, {"name": agent_id, "role": "Unknown", "category": "unknown"})


# Log CrewAI availability
if not CREWAI_AVAILABLE:
    logger.warning(
        "CrewAI not installed. Agents will use mock implementations. "
        "Install with: pip install crewai"
    )
