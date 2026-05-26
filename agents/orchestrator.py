"""
HAL Orchestrator - Central Multi-Agent Orchestrator for CodeShield AI.

Coordinates 9 specialized security agents through 4-phase workflows:
1. Phase 1 (Parallel): Dispatch all 7 scanning agents simultaneously
2. Phase 2 (Sequential): Triager processes all findings
3. Phase 3 (Conditional): Fix Agent generates patches for confirmed findings
4. Phase 4 (Sequential): Report Assembler creates final report

Features:
- Adaptive scanning: Adjusts priorities based on early findings
- Findings chaining: Cross-references findings from multiple agents
- Human-in-the-loop: Pauses for approval on critical findings
- Progress tracking: Real-time progress updates
"""

import asyncio
import json
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Coroutine, Dict, List, Optional, Set

from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)


class OrchestratorPhase(str, Enum):
    """Phases of the orchestrator workflow."""

    INITIALIZING = "initializing"
    PHASE_1_SCANNING = "phase_1_scanning"
    PHASE_2_TRIAGE = "phase_2_triage"
    PHASE_3_FIX = "phase_3_fix"
    PHASE_4_REPORT = "phase_4_report"
    COMPLETED = "completed"
    FAILED = "failed"
    PAUSED_APPROVAL = "paused_for_approval"


class HumanApprovalStatus(str, Enum):
    """Status of human approval requests."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    TIMED_OUT = "timed_out"


@dataclass
class AgentScanResult:
    """Result from a single scanning agent."""

    agent_id: str
    agent_name: str
    status: str = "pending"  # pending, running, completed, failed
    findings: List[Dict[str, Any]] = field(default_factory=list)
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration_ms(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time) * 1000
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "agent_id": self.agent_id,
            "agent_name": self.agent_name,
            "status": self.status,
            "findings_count": len(self.findings),
            "duration_ms": round(self.duration_ms, 2),
            "error_message": self.error_message,
            "metadata": self.metadata,
        }


@dataclass
class CrossReferencedFinding:
    """A finding enhanced with cross-reference data from multiple agents."""

    finding_id: str
    primary_agent: str
    file_path: str
    line_number: int
    category: str
    severity: str
    confidence: str  # HIGH, MEDIUM, LOW, CONFIRMED, EXPLOITABLE
    correlated_agents: List[str] = field(default_factory=list)
    description: str = ""
    code_snippet: Optional[str] = None
    fix_suggestion: Optional[str] = None
    requires_human_approval: bool = False
    approval_status: Optional[HumanApprovalStatus] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "primary_agent": self.primary_agent,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "category": self.category,
            "severity": self.severity,
            "confidence": self.confidence,
            "correlated_agents": self.correlated_agents,
            "description": self.description,
            "code_snippet": self.code_snippet,
            "fix_suggestion": self.fix_suggestion,
            "requires_human_approval": self.requires_human_approval,
            "approval_status": (
                self.approval_status.value if self.approval_status else None
            ),
        }


@dataclass
class OrchestratorState:
    """Current state of an orchestrator scan."""

    scan_id: str
    phase: OrchestratorPhase = OrchestratorPhase.INITIALIZING
    workflow_id: str = "full_scan"
    progress: int = 0  # 0-100
    agent_results: Dict[str, AgentScanResult] = field(default_factory=dict)
    all_findings: List[Dict[str, Any]] = field(default_factory=list)
    cross_referenced_findings: List[CrossReferencedFinding] = field(default_factory=list)
    triaged_findings: List[Dict[str, Any]] = field(default_factory=list)
    fix_proposals: List[Dict[str, Any]] = field(default_factory=list)
    report: Optional[Dict[str, Any]] = None
    human_approval_requests: List[Dict[str, Any]] = field(default_factory=list)
    start_time: Optional[float] = None
    end_time: Optional[float] = None
    error_message: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def duration_ms(self) -> float:
        if self.start_time and self.end_time:
            return (self.end_time - self.start_time) * 1000
        if self.start_time:
            return (time.time() - self.start_time) * 1000
        return 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "phase": self.phase.value,
            "workflow_id": self.workflow_id,
            "progress": self.progress,
            "agent_results": {
                aid: ar.to_dict() for aid, ar in self.agent_results.items()
            },
            "total_raw_findings": len(self.all_findings),
            "cross_referenced_findings": len(self.cross_referenced_findings),
            "triaged_findings": len(self.triaged_findings),
            "fix_proposals": len(self.fix_proposals),
            "human_approval_requests": self.human_approval_requests,
            "duration_ms": round(self.duration_ms, 2),
            "error_message": self.error_message,
            "metadata": self.metadata,
        }


class HALOrchestrator:
    """
    HAL - Central Multi-Agent Orchestrator.

    Coordinates 9 specialized security agents through adaptive multi-phase workflows
    with cross-referencing, human-in-the-loop, and progress tracking.
    """

    # Phase progress weights
    PHASE_WEIGHTS = {
        OrchestratorPhase.INITIALIZING: 0,
        OrchestratorPhase.PHASE_1_SCANNING: 60,
        OrchestratorPhase.PHASE_2_TRIAGE: 75,
        OrchestratorPhase.PHASE_3_FIX: 85,
        OrchestratorPhase.PHASE_4_REPORT: 95,
        OrchestratorPhase.COMPLETED: 100,
        OrchestratorPhase.FAILED: 0,
        OrchestratorPhase.PAUSED_APPROVAL: 70,
    }

    # Agents that participate in scanning (Phase 1)
    SCANNING_AGENTS = ["john", "dave", "sam", "pam", "tina", "casey", "sade"]

    def __init__(self) -> None:
        self._active_states: Dict[str, OrchestratorState] = {}
        self._progress_callbacks: List[Callable[[str, int, str], Coroutine[Any, Any, None]]] = []
        self._approval_callbacks: List[
            Callable[[str, List[Dict[str, Any]]], Coroutine[Any, Any, None]]
        ] = []
        self._lock = asyncio.Lock()
        self._running = False

        # Import components
        try:
            from agents.bus import AgentCommunicationBus, AgentMessage, MessageType, Priority, get_message_bus
            from agents.registry import AgentRegistry, AgentCapabilities, AgentStatus, get_registry
            from agents.health import AgentHealthMonitor, get_health_monitor
            self._bus = get_message_bus()
            self._registry = get_registry()
            self._health_monitor = get_health_monitor()
            self._components_available = True
        except ImportError as e:
            logger.warning("Agent components not available: %s. Running in standalone mode.", e)
            self._bus = None
            self._registry = None
            self._health_monitor = None
            self._components_available = False

    async def start(self) -> None:
        """Start the orchestrator and its components."""
        self._running = True
        if self._bus:
            await self._bus.start()
        if self._registry:
            await self._registry.start()
        if self._health_monitor:
            await self._health_monitor.start()

        # Subscribe to findings messages
        if self._bus:
            await self._bus.subscribe_all(self._on_bus_message)

        logger.info("HAL Orchestrator started")

    async def stop(self) -> None:
        """Stop the orchestrator and its components."""
        self._running = False
        if self._bus:
            await self._bus.stop()
        if self._registry:
            await self._registry.stop()
        if self._health_monitor:
            await self._health_monitor.stop()
        logger.info("HAL Orchestrator stopped")

    async def _on_bus_message(self, message: Any) -> None:
        """Handle messages from the communication bus."""
        if message.message_type == MessageType.FINDING:
            scan_id = message.payload.get("scan_id")
            if scan_id and scan_id in self._active_states:
                state = self._active_states[scan_id]
                state.all_findings.append(message.payload.get("finding", {}))
        elif message.message_type == MessageType.ERROR:
            logger.error(
                "Agent %s error: %s", message.agent_id, message.payload.get("error")
            )

    async def run_workflow(
        self,
        scan_id: str,
        workflow_id: str,
        source_path: str,
        context: Optional[Dict[str, Any]] = None,
    ) -> OrchestratorState:
        """
        Execute a multi-agent scan workflow.

        Args:
            scan_id: Unique scan identifier
            workflow_id: Workflow type (full_scan, quick_scan, deep_scan, etc.)
            source_path: Path to source code
            context: Additional context (base_url, focus_files, etc.)

        Returns:
            Final orchestrator state
        """
        context = context or {}
        state = OrchestratorState(
            scan_id=scan_id,
            workflow_id=workflow_id,
            start_time=time.time(),
            metadata=context,
        )

        async with self._lock:
            self._active_states[scan_id] = state

        try:
            # Phase 1: Parallel scanning
            await self._phase_1_scanning(state, source_path, context)

            # Adaptive: Check if we need to adjust based on findings
            await self._adaptive_adjustment(state)

            # Cross-reference findings
            self._cross_reference_findings(state)

            # Phase 2: Triage
            await self._phase_2_triage(state, context)

            # Check for critical findings requiring human approval
            approval_required = self._check_human_approval(state)
            if approval_required:
                await self._pause_for_approval(state)

            # Phase 3: Fix generation (conditional)
            if workflow_id not in ("quick_scan",):
                await self._phase_3_fix(state, context)

            # Phase 4: Report assembly
            await self._phase_4_report(state, context)

            state.phase = OrchestratorPhase.COMPLETED
            state.end_time = time.time()
            state.progress = 100

            await self._update_progress(state)
            logger.info(
                "Workflow %s completed for scan %s in %.1fs",
                workflow_id,
                scan_id,
                state.duration_ms / 1000,
            )

        except Exception as e:
            logger.error("Workflow %s failed for scan %s: %s", workflow_id, scan_id, e, exc_info=True)
            state.phase = OrchestratorPhase.FAILED
            state.error_message = str(e)
            state.end_time = time.time()

        return state

    async def _phase_1_scanning(
        self, state: OrchestratorState, source_path: str, context: Dict[str, Any]
    ) -> None:
        """
        Phase 1: Dispatch all scanning agents in parallel.

        Agents run simultaneously and their results are collected.
        """
        state.phase = OrchestratorPhase.PHASE_1_SCANNING
        await self._update_progress(state)

        # Determine which agents to run based on workflow
        from agents.workflows import get_workflow
        workflow = get_workflow(state.workflow_id)
        if workflow:
            required_agents = workflow.get_required_agents()
            scanning_agents = [a for a in self.SCANNING_AGENTS if a in required_agents]
        else:
            scanning_agents = self.SCANNING_AGENTS

        # Create and dispatch tasks for each agent
        tasks = []
        for agent_id in scanning_agents:
            task = self._run_scanning_agent(state, agent_id, source_path, context)
            tasks.append(task)

        # Run all agents in parallel
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        # Collect all findings
        for agent_id, result in state.agent_results.items():
            state.all_findings.extend(result.findings)

        state.progress = self.PHASE_WEIGHTS[OrchestratorPhase.PHASE_1_SCANNING]
        await self._update_progress(state)

        logger.info(
            "Phase 1 complete for scan %s: %d total findings from %d agents",
            state.scan_id,
            len(state.all_findings),
            len(state.agent_results),
        )

    async def _run_scanning_agent(
        self,
        state: OrchestratorState,
        agent_id: str,
        source_path: str,
        context: Dict[str, Any],
    ) -> None:
        """Run a single scanning agent and record results."""
        from agents.crew_definitions import get_agent_info

        agent_info = get_agent_info(agent_id)
        agent_name = agent_info.get("name", agent_id)

        result = AgentScanResult(
            agent_id=agent_id,
            agent_name=agent_name,
            status="running",
            start_time=time.time(),
        )
        state.agent_results[agent_id] = result

        try:
            # Run the actual scanner
            findings = await self._execute_agent_scan(agent_id, source_path, context)

            result.findings = findings
            result.status = "completed"
            result.end_time = time.time()

            # Publish finding messages to bus
            if self._bus:
                from agents.bus import AgentMessage, MessageType, Priority
                for finding in findings:
                    msg = AgentMessage(
                        agent_id=agent_id,
                        message_type=MessageType.FINDING,
                        payload={"scan_id": state.scan_id, "finding": finding},
                        correlation_id=state.scan_id,
                        priority=self._finding_to_priority(finding),
                    )
                    await self._bus.publish(msg)

            logger.info(
                "Agent %s found %d findings in %.1fs",
                agent_id,
                len(findings),
                result.duration_ms / 1000,
            )

        except Exception as e:
            result.status = "failed"
            result.error_message = str(e)
            result.end_time = time.time()
            logger.error("Agent %s failed: %s", agent_id, e)

    async def _execute_agent_scan(
        self, agent_id: str, source_path: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Execute the actual scan for an agent."""
        scan_id = context.get("scan_id", "unknown")

        # Map agent IDs to scanner tools
        scanner_map = {
            "john": self._run_sast_scan,
            "dave": self._run_dast_scan,
            "sam": self._run_secrets_scan,
            "pam": self._run_sca_scan,
            "tina": self._run_taint_scan,
            "casey": self._run_container_scan,
            "sade": self._run_llm_security_scan,
        }

        scanner_func = scanner_map.get(agent_id)
        if scanner_func:
            return await scanner_func(source_path, scan_id, context)

        return []

    async def _run_sast_scan(
        self, source_path: str, scan_id: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Run SAST scanning (Semgrep, ESLint, Bandit)."""
        from scanner.engine import ScanEngine
        from models.vulnerability import ScanConfig

        try:
            engine = ScanEngine()
            config = ScanConfig(tools=["semgrep", "eslint", "bandit", "custom_ai"])
            result = await engine.run_scan(
                scan_id=f"{scan_id}_john",
                source_path=source_path,
                source_type="local",
                name="SAST Scan",
                config=config,
            )
            return [self._vuln_to_dict(v) for v in result.vulnerabilities]
        except Exception as e:
            logger.error("SAST scan failed: %s", e)
            return []

    async def _run_dast_scan(
        self, source_path: str, scan_id: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Run DAST scanning."""
        try:
            from scanner.tools.dast_scanner import DASTScanner
            scanner = DASTScanner()
            vulns = await scanner.scan(source_path, scan_id)
            return [self._vuln_to_dict(v) for v in vulns]
        except Exception as e:
            logger.error("DAST scan failed: %s", e)
            return []

    async def _run_secrets_scan(
        self, source_path: str, scan_id: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Run secrets scanning."""
        try:
            from scanner.tools.gitleaks_scanner import GitleaksScanner
            from scanner.tools.custom_ai_scanner import CustomAIScanner

            findings = []
            gitleaks = GitleaksScanner()
            custom_ai = CustomAIScanner()

            for scanner in [gitleaks, custom_ai]:
                try:
                    vulns = await scanner.scan(source_path, scan_id)
                    findings.extend([self._vuln_to_dict(v) for v in vulns])
                except Exception as e:
                    logger.error("Secrets scanner %s error: %s", scanner.__class__.__name__, e)

            return findings
        except Exception as e:
            logger.error("Secrets scan failed: %s", e)
            return []

    async def _run_sca_scan(
        self, source_path: str, scan_id: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Run SCA scanning."""
        try:
            from scanner.tools.dependency_check import DependencyCheckScanner
            scanner = DependencyCheckScanner()
            vulns = await scanner.scan(source_path, scan_id)
            return [self._vuln_to_dict(v) for v in vulns]
        except Exception as e:
            logger.error("SCA scan failed: %s", e)
            return []

    async def _run_taint_scan(
        self, source_path: str, scan_id: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Run taint analysis."""
        try:
            from scanner.tools.taint_analyzer import TaintAnalyzer
            scanner = TaintAnalyzer()
            vulns = await scanner.scan(source_path, scan_id)
            return [self._vuln_to_dict(v) for v in vulns]
        except Exception as e:
            logger.error("Taint scan failed: %s", e)
            return []

    async def _run_container_scan(
        self, source_path: str, scan_id: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Run container security scanning."""
        try:
            from scanner.tools.container_scanner import ContainerScanner
            scanner = ContainerScanner()
            vulns = await scanner.scan(source_path, scan_id)
            return [self._vuln_to_dict(v) for v in vulns]
        except Exception as e:
            logger.error("Container scan failed: %s", e)
            return []

    async def _run_llm_security_scan(
        self, source_path: str, scan_id: str, context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Run LLM security scanning."""
        try:
            from scanner.tools.llm_security_scanner import LLMSecurityScanner
            scanner = LLMSecurityScanner()
            vulns = await scanner.scan(source_path, scan_id)
            return [self._vuln_to_dict(v) for v in vulns]
        except Exception as e:
            logger.error("LLM security scan failed: %s", e)
            return []

    def _vuln_to_dict(self, vuln: Any) -> Dict[str, Any]:
        """Convert a vulnerability object to a dictionary."""
        if hasattr(vuln, "model_dump"):
            return vuln.model_dump()
        elif hasattr(vuln, "__dict__"):
            return dict(vuln.__dict__)
        return dict(vuln) if isinstance(vuln, dict) else {}

    def _finding_to_priority(self, finding: Dict[str, Any]) -> Any:
        """Convert finding severity to message priority."""
        from agents.bus import Priority
        severity = finding.get("severity", "MEDIUM")
        severity_map = {
            "CRITICAL": Priority.CRITICAL,
            "HIGH": Priority.HIGH,
            "MEDIUM": Priority.MEDIUM,
            "LOW": Priority.LOW,
            "INFO": Priority.INFO,
        }
        return severity_map.get(severity, Priority.MEDIUM)

    async def _adaptive_adjustment(self, state: OrchestratorState) -> None:
        """
        Adaptive scanning: adjust priorities based on early findings.

        Rules:
        - If Secrets Agent finds AWS keys -> prioritize DAST Agent for production check
        - If SAST finds SQL injection -> prioritize Taint Agent for data flow confirmation
        - If LLM Security Agent finds prompt injection -> escalate severity
        """
        findings = state.all_findings

        # Check for AWS keys
        aws_secret_found = any(
            f.get("category", "").lower() in ("aws key", "aws secret", "aws credential")
            or "aws" in f.get("description", "").lower()
            for f in findings
        )
        if aws_secret_found and "dave" in state.agent_results:
            logger.info("Adaptive: AWS keys found, prioritizing DAST agent")
            state.agent_results["dave"].metadata["priority_boost"] = True
            state.metadata["adaptive_action"] = "prioritized_dast_for_aws"

        # Check for SQL injection
        sql_injection_found = any(
            "sql injection" in f.get("category", "").lower()
            or "sql_injection" in f.get("category", "").lower()
            for f in findings
        )
        if sql_injection_found and "tina" in state.agent_results:
            logger.info("Adaptive: SQL injection found, prioritizing Taint agent")
            state.agent_results["tina"].metadata["priority_boost"] = True
            state.agent_results["tina"].metadata["focus_files"] = list(
                set(
                    f.get("file_path", "")
                    for f in findings
                    if "sql" in f.get("category", "").lower()
                )
            )
            state.metadata["adaptive_action"] = "prioritized_taint_for_sql"

        # Check for prompt injection
        prompt_injection_found = any(
            "prompt injection" in f.get("category", "").lower()
            for f in findings
        )
        if prompt_injection_found:
            logger.info("Adaptive: Prompt injection found, escalating severity")
            for f in findings:
                if "prompt injection" in f.get("category", "").lower():
                    f["severity"] = "CRITICAL"
                    f["metadata"] = f.get("metadata", {})
                    f["metadata"]["escalated"] = True
            state.metadata["adaptive_action"] = "escalated_prompt_injection"

    def _cross_reference_findings(self, state: OrchestratorState) -> None:
        """
        Cross-reference findings from multiple agents.

        Rules:
        - Same file + same line from 2+ agents = HIGH confidence
        - SAST + Taint both flag SQL injection = CONFIRMED
        - DAST validates SAST finding = EXPLOITABLE
        """
        findings = state.all_findings
        cross_referenced: Dict[str, CrossReferencedFinding] = {}

        for finding in findings:
            file_path = finding.get("file_path", "")
            line_number = finding.get("line_number", 0)
            category = finding.get("category", "").lower()
            agent_id = finding.get("tool_source", "unknown")
            finding_key = f"{file_path}:{line_number}:{category}"

            if finding_key in cross_referenced:
                # Already seen - cross-reference
                existing = cross_referenced[finding_key]
                if agent_id not in existing.correlated_agents:
                    existing.correlated_agents.append(agent_id)

                # Apply cross-reference rules
                agents_involved = existing.correlated_agents + [existing.primary_agent]

                # Same file+line from 2+ agents = HIGH confidence
                if len(agents_involved) >= 2:
                    existing.confidence = "HIGH"

                # SAST + Taint on SQL injection = CONFIRMED
                has_sast = any(a in ("semgrep", "bandit", "custom_ai", "john") for a in agents_involved)
                has_taint = any(a in ("taint_analyzer", "tina") for a in agents_involved)
                if has_sast and has_taint and "sql" in category:
                    existing.confidence = "CONFIRMED"

                # DAST validates SAST = EXPLOITABLE
                has_sast = any(a in ("semgrep", "bandit", "custom_ai", "john") for a in agents_involved)
                has_dast = any(a in ("dast_scanner", "dave") for a in agents_involved)
                if has_sast and has_dast:
                    existing.confidence = "EXPLOITABLE"
                    existing.severity = self._escalate_severity(existing.severity)

                # Update with more severe finding's data
                if self._severity_rank(finding.get("severity", "LOW")) > self._severity_rank(
                    existing.severity
                ):
                    existing.severity = finding.get("severity", existing.severity)
                    existing.description = finding.get("description", existing.description)
                    existing.fix_suggestion = finding.get(
                        "fix_suggestion", existing.fix_suggestion
                    )

            else:
                # New finding
                crf = CrossReferencedFinding(
                    finding_id=str(uuid.uuid4())[:8],
                    primary_agent=agent_id,
                    file_path=file_path,
                    line_number=line_number,
                    category=finding.get("category", ""),
                    severity=finding.get("severity", "MEDIUM"),
                    confidence="LOW" if agent_id else "MEDIUM",
                    description=finding.get("description", ""),
                    code_snippet=finding.get("code_snippet"),
                    fix_suggestion=finding.get("fix_suggestion"),
                )
                cross_referenced[finding_key] = crf

        state.cross_referenced_findings = list(cross_referenced.values())

        logger.info(
            "Cross-referenced %d raw findings into %d unique findings",
            len(findings),
            len(state.cross_referenced_findings),
        )

    async def _phase_2_triage(
        self, state: OrchestratorState, context: Dict[str, Any]
    ) -> None:
        """
        Phase 2: Triage all findings.

        Uses the AI triage engine to validate and prioritize findings.
        """
        state.phase = OrchestratorPhase.PHASE_2_TRIAGE
        state.progress = self.PHASE_WEIGHTS[OrchestratorPhase.PHASE_2_TRIAGE]
        await self._update_progress(state)

        if not state.cross_referenced_findings:
            logger.info("No findings to triage for scan %s", state.scan_id)
            return

        try:
            # Convert CrossReferencedFinding to dicts for triage
            findings_dicts = [crf.to_dict() for crf in state.cross_referenced_findings]

            # Try AI triage engine
            try:
                from ai_triage import AITriageEngine
                triage_engine = AITriageEngine()

                # Convert to Vulnerability objects for triage
                from models.vulnerability import Vulnerability
                vulns = []
                for f in state.all_findings:
                    try:
                        v = Vulnerability(
                            scan_id=state.scan_id,
                            file_path=f.get("file_path", ""),
                            line_number=f.get("line_number", 0),
                            severity=f.get("severity", "MEDIUM"),
                            category=f.get("category", "Unknown"),
                            title=f.get("title", f.get("category", "Finding")),
                            description=f.get("description", ""),
                            code_snippet=f.get("code_snippet"),
                            fix_suggestion=f.get("fix_suggestion"),
                            tool_source=f.get("tool_source", "multi_agent"),
                            cwe_id=f.get("cwe_id"),
                            confidence=f.get("confidence", "MEDIUM"),
                        )
                        vulns.append(v)
                    except Exception:
                        pass

                if vulns:
                    triaged = await triage_engine.triage_vulnerabilities(vulns, None)
                    state.triaged_findings = [self._vuln_to_dict(v) for v in triaged]
                else:
                    state.triaged_findings = findings_dicts

            except Exception as e:
                logger.warning("AI triage unavailable, using rule-based triage: %s", e)
                state.triaged_findings = findings_dicts

            logger.info(
                "Phase 2 complete: %d findings after triage",
                len(state.triaged_findings),
            )

        except Exception as e:
            logger.error("Triage phase failed: %s", e)
            state.triaged_findings = [crf.to_dict() for crf in state.cross_referenced_findings]

    async def _phase_3_fix(
        self, state: OrchestratorState, context: Dict[str, Any]
    ) -> None:
        """
        Phase 3: Generate fixes for confirmed findings.

        Only generates fixes for CONFIRMED and HIGH confidence findings.
        """
        state.phase = OrchestratorPhase.PHASE_3_FIX
        state.progress = self.PHASE_WEIGHTS[OrchestratorPhase.PHASE_3_FIX]
        await self._update_progress(state)

        confirmed_findings = [
            f for f in state.triaged_findings
            if f.get("confidence") in ("CONFIRMED", "EXPLOITABLE", "HIGH")
            or f.get("severity") in ("CRITICAL", "HIGH")
        ]

        if not confirmed_findings:
            logger.info("No confirmed findings for fix generation")
            return

        try:
            # Try auto-fix engine
            try:
                from auto_fix import AutoFixEngine
                fix_engine = AutoFixEngine()

                from models.vulnerability import Vulnerability
                for finding_dict in confirmed_findings[:20]:  # Limit to 20 fixes
                    try:
                        vuln = Vulnerability(
                            scan_id=state.scan_id,
                            file_path=finding_dict.get("file_path", ""),
                            line_number=finding_dict.get("line_number", 0),
                            severity=finding_dict.get("severity", "MEDIUM"),
                            category=finding_dict.get("category", "Unknown"),
                            title=finding_dict.get("category", "Finding"),
                            description=finding_dict.get("description", ""),
                            code_snippet=finding_dict.get("code_snippet"),
                            tool_source=finding_dict.get("primary_agent", "multi_agent"),
                        )
                        fix_result = await fix_engine.generate_fix(vuln, None)
                        if hasattr(fix_result, "to_dict"):
                            state.fix_proposals.append(fix_result.to_dict())
                        elif isinstance(fix_result, dict):
                            state.fix_proposals.append(fix_result)
                    except Exception as e:
                        logger.debug("Fix generation for single finding failed: %s", e)

            except Exception as e:
                logger.warning("Auto-fix engine unavailable: %s", e)

            logger.info(
                "Phase 3 complete: %d fix proposals generated",
                len(state.fix_proposals),
            )

        except Exception as e:
            logger.error("Fix phase failed: %s", e)

    async def _phase_4_report(
        self, state: OrchestratorState, context: Dict[str, Any]
    ) -> None:
        """
        Phase 4: Assemble final report.
        """
        state.phase = OrchestratorPhase.PHASE_4_REPORT
        state.progress = self.PHASE_WEIGHTS[OrchestratorPhase.PHASE_4_REPORT]
        await self._update_progress(state)

        # Calculate stats
        severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in state.triaged_findings:
            sev = f.get("severity", "INFO").upper()
            if sev in severity_counts:
                severity_counts[sev] += 1

        # Calculate risk score
        risk_score = min(
            severity_counts["CRITICAL"] * 25
            + severity_counts["HIGH"] * 10
            + severity_counts["MEDIUM"] * 4
            + severity_counts["LOW"] * 1,
            100,
        )

        state.report = {
            "scan_id": state.scan_id,
            "workflow": state.workflow_id,
            "executive_summary": {
                "total_findings": len(state.triaged_findings),
                "risk_score": risk_score,
                "severity_breakdown": severity_counts,
                "agents_participated": list(state.agent_results.keys()),
                "agents_succeeded": sum(
                    1 for r in state.agent_results.values() if r.status == "completed"
                ),
                "agents_failed": sum(
                    1 for r in state.agent_results.values() if r.status == "failed"
                ),
                "cross_referenced_findings": len(state.cross_referenced_findings),
                "fix_proposals": len(state.fix_proposals),
            },
            "findings": state.triaged_findings,
            "fix_proposals": state.fix_proposals,
            "agent_details": {
                aid: ar.to_dict() for aid, ar in state.agent_results.items()
            },
            "metadata": {
                "duration_ms": state.duration_ms,
                "adaptive_actions": state.metadata.get("adaptive_action"),
            },
        }

        logger.info(
            "Phase 4 complete: Report assembled with %d findings, risk score %d",
            len(state.triaged_findings),
            risk_score,
        )

    def _check_human_approval(self, state: OrchestratorState) -> bool:
        """
        Check if any critical findings require human approval.

        Returns True if approval is needed.
        """
        approval_thresholds = state.metadata.get("approval_thresholds", ["CRITICAL"])

        for finding in state.triaged_findings:
            severity = finding.get("severity", "").upper()
            confidence = finding.get("confidence", "")

            if severity in approval_thresholds or confidence == "EXPLOITABLE":
                finding["requires_human_approval"] = True
                state.human_approval_requests.append({
                    "finding_id": finding.get("finding_id", str(uuid.uuid4())[:8]),
                    "severity": severity,
                    "category": finding.get("category", ""),
                    "file_path": finding.get("file_path", ""),
                    "description": finding.get("description", ""),
                    "status": HumanApprovalStatus.PENDING.value,
                })

        return len(state.human_approval_requests) > 0

    async def _pause_for_approval(self, state: OrchestratorState) -> None:
        """Pause workflow for human approval."""
        state.phase = OrchestratorPhase.PAUSED_APPROVAL
        await self._update_progress(state)

        # Notify approval listeners
        for callback in self._approval_callbacks:
            try:
                await callback(state.scan_id, state.human_approval_requests)
            except Exception as e:
                logger.error("Approval callback error: %s", e)

        logger.info(
            "Scan %s paused for human approval: %d findings need review",
            state.scan_id,
            len(state.human_approval_requests),
        )

    async def approve_findings(
        self, scan_id: str, finding_ids: List[str], approved: bool = True
    ) -> bool:
        """
        Approve or reject findings pending human approval.

        Args:
            scan_id: The scan ID
            finding_ids: IDs of findings to approve/reject
            approved: True to approve, False to reject

        Returns:
            True if successful
        """
        state = self._active_states.get(scan_id)
        if not state:
            return False

        status = (
            HumanApprovalStatus.APPROVED
            if approved
            else HumanApprovalStatus.REJECTED
        )

        for req in state.human_approval_requests:
            if req["finding_id"] in finding_ids:
                req["status"] = status.value

        # If all approved or rejected, resume workflow
        pending = [
            r for r in state.human_approval_requests
            if r["status"] == HumanApprovalStatus.PENDING.value
        ]
        if not pending:
            logger.info("All approvals resolved for scan %s, resuming", scan_id)
            # Resume from current phase
            if state.phase == OrchestratorPhase.PAUSED_APPROVAL:
                state.phase = OrchestratorPhase.PHASE_3_FIX

        return True

    async def _update_progress(self, state: OrchestratorState) -> None:
        """Notify progress listeners of state change."""
        for callback in self._progress_callbacks:
            try:
                await callback(
                    state.scan_id, state.progress, state.phase.value
                )
            except Exception as e:
                logger.error("Progress callback error: %s", e)

    def add_progress_callback(
        self, callback: Callable[[str, int, str], Coroutine[Any, Any, None]]
    ) -> None:
        """Add a progress update callback."""
        self._progress_callbacks.append(callback)

    def add_approval_callback(
        self,
        callback: Callable[[str, List[Dict[str, Any]]], Coroutine[Any, Any, None]],
    ) -> None:
        """Add a human approval request callback."""
        self._approval_callbacks.append(callback)

    def get_state(self, scan_id: str) -> Optional[OrchestratorState]:
        """Get the current state of a scan."""
        return self._active_states.get(scan_id)

    def remove_state(self, scan_id: str) -> None:
        """Remove a scan state from active tracking."""
        self._active_states.pop(scan_id, None)

    @staticmethod
    def _severity_rank(severity: str) -> int:
        """Get numeric rank for severity comparison."""
        ranks = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
        return ranks.get(severity.upper(), 0)

    @staticmethod
    def _escalate_severity(severity: str) -> str:
        """Escalate severity by one level."""
        escalation = {
            "INFO": "LOW",
            "LOW": "MEDIUM",
            "MEDIUM": "HIGH",
            "HIGH": "CRITICAL",
            "CRITICAL": "CRITICAL",
        }
        return escalation.get(severity.upper(), severity)

    def get_all_active_scans(self) -> Dict[str, Dict[str, Any]]:
        """Get all currently active scans."""
        return {
            scan_id: state.to_dict()
            for scan_id, state in self._active_states.items()
        }


# Global orchestrator instance
_orchestrator: Optional[HALOrchestrator] = None


def get_orchestrator() -> HALOrchestrator:
    """Get or create the global orchestrator instance."""
    global _orchestrator
    if _orchestrator is None:
        _orchestrator = HALOrchestrator()
    return _orchestrator


async def reset_orchestrator() -> None:
    """Reset the global orchestrator instance (for testing)."""
    global _orchestrator
    if _orchestrator:
        await _orchestrator.stop()
    _orchestrator = None
