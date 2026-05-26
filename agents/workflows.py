"""
Workflow Definitions - CrewAI Task and Workflow Definitions.

Defines scan workflows using CrewAI Tasks:
- Full Scan Workflow: All 7 agents -> Triager -> Fix -> Report
- Quick Scan Workflow: SAST + Secrets only -> Triager -> Report
- Deep Scan Workflow: All 7 + Taint deep analysis -> Triager -> Fix -> Report
- Compliance Scan Workflow: SAST + SCA + Container -> Compliance Report
- LLM Security Workflow: LLM Security Agent only -> specialized report
"""

from typing import Any, Dict, List, Optional

try:
    from crewai import Task, Crew, Process
    CREWAI_AVAILABLE = True
except ImportError:
    CREWAI_AVAILABLE = False

from utils.logger import get_logger

logger = get_logger(__name__)


# =============================================================================
# Task Definitions
# =============================================================================


def create_sast_task(agent: Any, context: Dict[str, Any]) -> Any:
    """Create SAST scanning task for John."""
    scan_target = context.get("source_path", "/tmp/scan")
    scan_id = context.get("scan_id", "unknown")

    if CREWAI_AVAILABLE:
        return Task(
            description=(
                f"Perform comprehensive static analysis security scan on codebase at "
                f"{scan_target} (scan_id: {scan_id}). Use Semgrep, ESLint, Bandit, and "
                "custom AI pattern matching to find all security vulnerabilities including "
                "injection flaws, XSS, insecure crypto, authentication issues, path traversal, "
                "and insecure deserialization. For each finding, provide: file path, line number, "
                "severity (CRITICAL/HIGH/MEDIUM/LOW), CWE ID, vulnerability category, description, "
                "affected code snippet, and fix suggestion. Return findings as a structured list."
            ),
            expected_output=(
                "A structured list of all vulnerabilities found by SAST tools. Each vulnerability "
                "must include: file_path, line_number, severity, category, cwe_id, description, "
                "code_snippet, and fix_suggestion. If no vulnerabilities are found, return an empty list."
            ),
            agent=agent,
        )
    else:
        return _create_mock_task("sast_scan", agent, context)


def create_dast_task(agent: Any, context: Dict[str, Any]) -> Any:
    """Create DAST scanning task for Dave."""
    scan_target = context.get("source_path", "/tmp/scan")
    scan_id = context.get("scan_id", "unknown")
    base_url = context.get("base_url")

    if CREWAI_AVAILABLE:
        return Task(
            description=(
                f"Perform dynamic application security testing for scan {scan_id}. "
                f"Target path: {scan_target}. "
                + (f"Test deployed application at {base_url}. " if base_url else "")
                + "Check security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options), "
                "SSL/TLS configuration, CORS policies, information disclosure in error messages, "
                "and endpoint vulnerabilities. Cross-reference with any SAST findings to confirm "
                "exploitability. Report confirmed exploitable issues with severity ratings."
            ),
            expected_output=(
                "List of DAST findings with: vulnerability type, severity, URL/endpoint affected, "
                "evidence of exploitability, and remediation advice. Include a section on "
                "security header assessment."
            ),
            agent=agent,
        )
    else:
        return _create_mock_task("dast_scan", agent, context)


def create_secrets_task(agent: Any, context: Dict[str, Any]) -> Any:
    """Create secrets scanning task for Sam."""
    scan_target = context.get("source_path", "/tmp/scan")
    scan_id = context.get("scan_id", "unknown")

    if CREWAI_AVAILABLE:
        return Task(
            description=(
                f"Scan codebase at {scan_target} (scan_id: {scan_id}) for all hardcoded secrets, "
                "API keys, passwords, tokens, and credentials. Detect: AWS access keys, "
                "GitHub tokens, database connection strings, JWT secrets, OAuth credentials, "
                "private keys, API tokens, and any other sensitive data. Classify each secret "
                "by type, assess severity based on production exposure risk, and flag any "
                "AWS keys or database credentials as CRITICAL priority."
            ),
            expected_output=(
                "List of all detected secrets with: secret_type, file_path, line_number, "
                "severity, partial_value (masked), and remediation instruction. "
                "Flag any AWS/production credentials for immediate escalation."
            ),
            agent=agent,
        )
    else:
        return _create_mock_task("secrets_scan", agent, context)


def create_sca_task(agent: Any, context: Dict[str, Any]) -> Any:
    """Create SCA scanning task for Pam."""
    scan_target = context.get("source_path", "/tmp/scan")
    scan_id = context.get("scan_id", "unknown")

    if CREWAI_AVAILABLE:
        return Task(
            description=(
                f"Analyze all third-party dependencies at {scan_target} (scan_id: {scan_id}). "
                "Check package.json, requirements.txt, Cargo.toml, go.mod, pom.xml, and other "
                "dependency manifests against vulnerability databases. Generate an SBOM, "
                "assess reachability of vulnerable code paths, identify outdated packages with "
                "security fixes available, and flag high-risk transitive dependencies."
            ),
            expected_output=(
                "Dependency vulnerability report with: package name, current version, "
                "vulnerable version range, CVE ID, severity, fixed version, reachability "
                "score, and recommended upgrade path. Include SBOM summary."
            ),
            agent=agent,
        )
    else:
        return _create_mock_task("sca_scan", agent, context)


def create_taint_task(agent: Any, context: Dict[str, Any]) -> Any:
    """Create taint analysis task for Tina."""
    scan_target = context.get("source_path", "/tmp/scan")
    scan_id = context.get("scan_id", "unknown")
    focus_files = context.get("focus_files", [])

    if CREWAI_AVAILABLE:
        return Task(
            description=(
                f"Perform deep taint analysis on {scan_target} (scan_id: {scan_id}). "
                + (f"Focus on files: {focus_files}. " if focus_files else "")
                + "Track data flow from all untrusted sources (user input, file reads, "
                "network requests, environment variables) to dangerous sinks (SQL queries, "
                "command execution, HTML rendering, file operations). Build taint graphs, "
                "identify sanitization gaps, and confirm injection vulnerabilities with "
                "precise source-to-sink paths."
            ),
            expected_output=(
                "Taint analysis results with: source location, sink location, data flow path, "
                "sanitization checks (if any), confirmed vulnerability type, and confidence level. "
                "Include taint graph summary."
            ),
            agent=agent,
        )
    else:
        return _create_mock_task("taint_scan", agent, context)


def create_container_task(agent: Any, context: Dict[str, Any]) -> Any:
    """Create container security scanning task for Casey."""
    scan_target = context.get("source_path", "/tmp/scan")
    scan_id = context.get("scan_id", "unknown")

    if CREWAI_AVAILABLE:
        return Task(
            description=(
                f"Scan container and infrastructure configurations at {scan_target} "
                f"(scan_id: {scan_id}). Check Dockerfiles for: privileged containers, "
                "root user execution, exposed secrets, missing health checks, and base image "
                "vulnerabilities. Check Kubernetes manifests for: overly permissive RBAC, "
                "missing network policies, hostPath mounts, privileged security contexts. "
                "Check Terraform for: exposed storage, open security groups, unencrypted "
                "resources, and IAM policy violations. Map findings to CIS benchmarks."
            ),
            expected_output=(
                "Container/IaC security findings with: configuration file, issue type, "
                "severity, CIS benchmark mapping, current value, recommended fix, and "
                "compliance impact."
            ),
            agent=agent,
        )
    else:
        return _create_mock_task("container_scan", agent, context)


def create_llm_security_task(agent: Any, context: Dict[str, Any]) -> Any:
    """Create LLM security scanning task for Sade."""
    scan_target = context.get("source_path", "/tmp/scan")
    scan_id = context.get("scan_id", "unknown")

    if CREWAI_AVAILABLE:
        return Task(
            description=(
                f"Scan codebase at {scan_target} (scan_id: {scan_id}) for AI/LLM-specific "
                "security vulnerabilities. Detect: prompt injection vulnerabilities (direct "
                "and indirect), insecure LLM API usage (missing input validation, output "
                "sanitization), model inversion risks, training data poisoning vectors, "
                "OWASP LLM Top 10 violations (LLM01-LLM10), MCP security issues, insecure "
                "AI-generated code patterns, and excessive model permissions. Classify "
                "findings by OWASP LLM category."
            ),
            expected_output=(
                "LLM security findings with: vulnerability type, OWASP LLM category, "
                "file_path, line number, severity, description, affected code, "
                "and AI-specific remediation guidance."
            ),
            agent=agent,
        )
    else:
        return _create_mock_task("llm_security_scan", agent, context)


def create_triage_task(agent: Any, context: Dict[str, Any]) -> Any:
    """Create triage task for the Triager agent."""
    findings = context.get("all_findings", [])
    scan_id = context.get("scan_id", "unknown")

    if CREWAI_AVAILABLE:
        return Task(
            description=(
                f"Triage all findings from scan {scan_id}. Review {len(findings)} findings "
                "from multiple scanning agents. Cross-reference findings from different "
                "agents on the same file/line to boost confidence. Eliminate false positives "
                "using code context analysis. Confirm true vulnerabilities. Apply priority "
                "scoring: CRITICAL (exploitable, high impact), HIGH (confirmed vulnerability), "
                "MEDIUM (likely issue), LOW (informational). Flag any findings requiring "
                "human approval. Produce a curated, deduplicated list of actionable findings."
            ),
            expected_output=(
                "Triaged findings list with: original finding, confidence score (CONFIRMED/" 
                "LIKELY/FALSE_POSITIVE/INFO), adjusted severity, cross-references from "
                "other agents, and triage notes explaining the decision."
            ),
            agent=agent,
            context={"findings": findings},
        )
    else:
        return _create_mock_task("triage", agent, context)


def create_fix_task(agent: Any, context: Dict[str, Any]) -> Any:
    """Create fix generation task for the Fix agent."""
    confirmed_findings = context.get("confirmed_findings", [])
    scan_id = context.get("scan_id", "unknown")

    if CREWAI_AVAILABLE:
        return Task(
            description=(
                f"Generate fixes for {len(confirmed_findings)} confirmed vulnerabilities "
                f"from scan {scan_id}. For each vulnerability: analyze the root cause, "
                "produce a secure code fix that addresses the vulnerability without breaking "
                "functionality, maintain the existing code style, include a brief explanation "
                "of the vulnerability and the fix, and provide a confidence score. Prioritize "
                "CRITICAL and HIGH severity findings. Group related fixes by file."
            ),
            expected_output=(
                "Fix proposals with: vulnerability reference, fixed code snippet, "
                "diff (before/after), explanation, confidence score, and potential "
                "breaking change assessment."
            ),
            agent=agent,
            context={"confirmed_findings": confirmed_findings},
        )
    else:
        return _create_mock_task("fix", agent, context)


def create_report_task(agent: Any, context: Dict[str, Any]) -> Any:
    """Create report assembly task for HAL."""
    scan_id = context.get("scan_id", "unknown")
    findings = context.get("all_findings", [])
    fixes = context.get("fix_proposals", [])

    if CREWAI_AVAILABLE:
        return Task(
            description=(
                f"Assemble the final security report for scan {scan_id}. Compile all "
                f"findings ({len(findings)} total, {len(fixes)} with fixes), organize by "
                "severity and category, include executive summary with risk score, provide "
                "detailed findings with evidence and fix guidance, list prioritized "
                "remediation roadmap, and include appendix with scanning methodology. "
                "Format for both technical and executive audiences."
            ),
            expected_output=(
                "Complete security report with: executive summary, risk score, findings "
                "by severity (CRITICAL/HIGH/MEDIUM/LOW), detailed vulnerability descriptions, "
                "fix suggestions, prioritized remediation plan, and scan metadata."
            ),
            agent=agent,
            context={"findings": findings, "fixes": fixes},
        )
    else:
        return _create_mock_task("report", agent, context)


def create_compliance_report_task(agent: Any, context: Dict[str, Any]) -> Any:
    """Create compliance report task."""
    scan_id = context.get("scan_id", "unknown")
    framework = context.get("compliance_framework", "SOC2")

    if CREWAI_AVAILABLE:
        return Task(
            description=(
                f"Generate {framework} compliance report for scan {scan_id}. Map findings "
                f"to {framework} controls, assess compliance status per control (compliant/" 
                "non-compliant/partial), identify gaps, provide remediation recommendations, "
                "and produce audit-ready documentation."
            ),
            expected_output=(
                f"{framework} compliance report with: control mapping, compliance status, "
                "gaps identified, remediation plan, and executive summary."
            ),
            agent=agent,
        )
    else:
        return _create_mock_task("compliance_report", agent, context)


# =============================================================================
# Mock Task for fallback
# =============================================================================


def _create_mock_task(task_type: str, agent: Any, context: Dict[str, Any]) -> Dict[str, Any]:
    """Create a mock task dict when CrewAI is not installed."""
    return {
        "task_type": task_type,
        "agent": agent.get("agent_id", "unknown") if isinstance(agent, dict) else str(agent),
        "context": context,
        "status": "pending",
    }


# =============================================================================
# Workflow Definitions
# =============================================================================


class ScanWorkflow:
    """Base class for scan workflows."""

    def __init__(self, workflow_id: str, name: str, description: str) -> None:
        self.workflow_id = workflow_id
        self.name = name
        self.description = description

    def get_required_agents(self) -> List[str]:
        """Get list of agent IDs required for this workflow."""
        raise NotImplementedError

    def create_tasks(self, agents: Dict[str, Any], context: Dict[str, Any]) -> List[Any]:
        """Create all tasks for this workflow."""
        raise NotImplementedError

    def to_dict(self) -> Dict[str, Any]:
        return {
            "workflow_id": self.workflow_id,
            "name": self.name,
            "description": self.description,
            "required_agents": self.get_required_agents(),
        }


class FullScanWorkflow(ScanWorkflow):
    """
    Full Scan Workflow: All 7 scanning agents -> Triager -> Fix -> Report.

    Comprehensive security scan using all available agents for maximum coverage.
    """

    def __init__(self) -> None:
        super().__init__(
            workflow_id="full_scan",
            name="Full Security Scan",
            description=(
                "Comprehensive security scan using all 7 scanning agents (SAST, DAST, "
                "Secrets, SCA, Taint, Container, LLM Security). Results are triaged, "
                "fixes generated for confirmed findings, and a complete report assembled. "
                "Best for thorough security assessments."
            ),
        )

    def get_required_agents(self) -> List[str]:
        return ["john", "dave", "sam", "pam", "tina", "casey", "sade", "triager", "fix"]

    def create_tasks(self, agents: Dict[str, Any], context: Dict[str, Any]) -> List[Any]:
        tasks = []

        # Phase 1: Parallel scanning tasks
        if "john" in agents:
            tasks.append(create_sast_task(agents["john"], context))
        if "dave" in agents:
            tasks.append(create_dast_task(agents["dave"], context))
        if "sam" in agents:
            tasks.append(create_secrets_task(agents["sam"], context))
        if "pam" in agents:
            tasks.append(create_sca_task(agents["pam"], context))
        if "tina" in agents:
            tasks.append(create_taint_task(agents["tina"], context))
        if "casey" in agents:
            tasks.append(create_container_task(agents["casey"], context))
        if "sade" in agents:
            tasks.append(create_llm_security_task(agents["sade"], context))

        # Phase 2: Triage (depends on all scan results)
        if "triager" in agents:
            tasks.append(create_triage_task(agents["triager"], context))

        # Phase 3: Fix generation (depends on triaged results)
        if "fix" in agents:
            tasks.append(create_fix_task(agents["fix"], context))

        # Phase 4: Report assembly (depends on everything)
        if "hal" in agents:
            tasks.append(create_report_task(agents["hal"], context))

        return tasks


class QuickScanWorkflow(ScanWorkflow):
    """
    Quick Scan Workflow: SAST + Secrets only -> Triager -> Report.

    Fast scan for rapid feedback during development.
    """

    def __init__(self) -> None:
        super().__init__(
            workflow_id="quick_scan",
            name="Quick Security Scan",
            description=(
                "Fast security scan using only SAST and Secrets detection agents. "
                "Results are triaged and a concise report is generated. Ideal for "
                "CI/CD pipelines and rapid development feedback loops."
            ),
        )

    def get_required_agents(self) -> List[str]:
        return ["john", "sam", "triager"]

    def create_tasks(self, agents: Dict[str, Any], context: Dict[str, Any]) -> List[Any]:
        tasks = []

        if "john" in agents:
            tasks.append(create_sast_task(agents["john"], context))
        if "sam" in agents:
            tasks.append(create_secrets_task(agents["sam"], context))
        if "triager" in agents:
            tasks.append(create_triage_task(agents["triager"], context))
        if "hal" in agents:
            tasks.append(create_report_task(agents["hal"], context))

        return tasks


class DeepScanWorkflow(ScanWorkflow):
    """
    Deep Scan Workflow: All 7 + Taint deep analysis -> Triager -> Fix -> Report.

    Intensive scan with enhanced taint analysis for critical applications.
    """

    def __init__(self) -> None:
        super().__init__(
            workflow_id="deep_scan",
            name="Deep Security Scan",
            description=(
                "Intensive security scan with all 7 agents plus enhanced deep taint "
                "analysis. Taint analysis focuses on files flagged by other scanners for "
                "maximum precision. Full triage, fix generation, and comprehensive report. "
                "Best for critical applications and pre-release assessments."
            ),
        )

    def get_required_agents(self) -> List[str]:
        return ["john", "dave", "sam", "pam", "tina", "casey", "sade", "triager", "fix"]

    def create_tasks(self, agents: Dict[str, Any], context: Dict[str, Any]) -> List[Any]:
        # Deep scan runs all tasks like full scan, but with enhanced taint context
        deep_context = dict(context)
        deep_context["deep_taint"] = True

        tasks = []

        if "john" in agents:
            tasks.append(create_sast_task(agents["john"], deep_context))
        if "dave" in agents:
            tasks.append(create_dast_task(agents["dave"], deep_context))
        if "sam" in agents:
            tasks.append(create_secrets_task(agents["sam"], deep_context))
        if "pam" in agents:
            tasks.append(create_sca_task(agents["pam"], deep_context))
        if "tina" in agents:
            # Enhanced taint with focus files from other scans
            tasks.append(create_taint_task(agents["tina"], deep_context))
        if "casey" in agents:
            tasks.append(create_container_task(agents["casey"], deep_context))
        if "sade" in agents:
            tasks.append(create_llm_security_task(agents["sade"], deep_context))
        if "triager" in agents:
            tasks.append(create_triage_task(agents["triager"], deep_context))
        if "fix" in agents:
            tasks.append(create_fix_task(agents["fix"], deep_context))
        if "hal" in agents:
            tasks.append(create_report_task(agents["hal"], deep_context))

        return tasks


class ComplianceScanWorkflow(ScanWorkflow):
    """
    Compliance Scan Workflow: SAST + SCA + Container -> Compliance Report.

    Focused scan for compliance framework alignment.
    """

    def __init__(self) -> None:
        super().__init__(
            workflow_id="compliance_scan",
            name="Compliance Security Scan",
            description=(
                "Compliance-focused scan using SAST, SCA, and Container security agents. "
                "Produces an audit-ready compliance report mapped to frameworks like SOC2, "
                "ISO 27001, or PCI DSS. Best for compliance audits and regulatory requirements."
            ),
        )

    def get_required_agents(self) -> List[str]:
        return ["john", "pam", "casey"]

    def create_tasks(self, agents: Dict[str, Any], context: Dict[str, Any]) -> List[Any]:
        tasks = []

        if "john" in agents:
            tasks.append(create_sast_task(agents["john"], context))
        if "pam" in agents:
            tasks.append(create_sca_task(agents["pam"], context))
        if "casey" in agents:
            tasks.append(create_container_task(agents["casey"], context))
        if "hal" in agents:
            tasks.append(create_compliance_report_task(agents["hal"], context))

        return tasks


class LLMSecurityWorkflow(ScanWorkflow):
    """
    LLM Security Workflow: LLM Security Agent only -> specialized report.

    Specialized scan for AI/ML applications.
    """

    def __init__(self) -> None:
        super().__init__(
            workflow_id="llm_security_scan",
            name="LLM Security Scan",
            description=(
                "Specialized scan focusing exclusively on AI/LLM security vulnerabilities. "
                "Uses the LLM Security Agent to detect prompt injection, insecure LLM API usage, "
                "OWASP LLM Top 10 violations, and MCP security issues. Best for applications "
                "with AI/LLM components."
            ),
        )

    def get_required_agents(self) -> List[str]:
        return ["sade"]

    def create_tasks(self, agents: Dict[str, Any], context: Dict[str, Any]) -> List[Any]:
        tasks = []

        if "sade" in agents:
            tasks.append(create_llm_security_task(agents["sade"], context))
        if "hal" in agents:
            report_ctx = dict(context)
            report_ctx["report_type"] = "llm_security"
            tasks.append(create_report_task(agents["hal"], report_ctx))

        return tasks


# =============================================================================
# Workflow Registry
# =============================================================================

_WORKFLOW_REGISTRY: Dict[str, ScanWorkflow] = {}


def register_workflow(workflow: ScanWorkflow) -> None:
    """Register a workflow in the global registry."""
    _WORKFLOW_REGISTRY[workflow.workflow_id] = workflow


def get_workflow(workflow_id: str) -> Optional[ScanWorkflow]:
    """Get a workflow by ID."""
    return _WORKFLOW_REGISTRY.get(workflow_id)


def list_workflows() -> List[Dict[str, Any]]:
    """List all registered workflows."""
    return [w.to_dict() for w in _WORKFLOW_REGISTRY.values()]


def initialize_workflows() -> None:
    """Register all default workflows."""
    register_workflow(FullScanWorkflow())
    register_workflow(QuickScanWorkflow())
    register_workflow(DeepScanWorkflow())
    register_workflow(ComplianceScanWorkflow())
    register_workflow(LLMSecurityWorkflow())
    logger.info("Registered %d workflows", len(_WORKFLOW_REGISTRY))


# Initialize on import
initialize_workflows()
