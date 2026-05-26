"""
Tests for the HAL Orchestrator.

Tests workflow execution, phase transitions, adaptive scanning,
cross-referencing, human-in-the-loop, and progress tracking.
"""

import asyncio
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import sys
sys.path.insert(0, "/mnt/agents/output/backend")

from agents.orchestrator import (
    AgentScanResult,
    CrossReferencedFinding,
    HALOrchestrator,
    HumanApprovalStatus,
    OrchestratorPhase,
    OrchestratorState,
    get_orchestrator,
    reset_orchestrator,
)


class TestAgentScanResult:
    """Test AgentScanResult dataclass."""

    def test_creation(self):
        """Test creating a scan result."""
        result = AgentScanResult(
            agent_id="john",
            agent_name="John",
            status="completed",
            findings=[{"severity": "HIGH"}],
        )
        assert result.agent_id == "john"
        assert result.status == "completed"
        assert len(result.findings) == 1

    def test_duration(self):
        """Test duration calculation."""
        import time
        result = AgentScanResult(
            agent_id="john",
            agent_name="John",
            start_time=time.time() - 1.0,
            end_time=time.time(),
        )
        assert result.duration_ms >= 900  # At least 900ms

    def test_to_dict(self):
        """Test serialization."""
        result = AgentScanResult(
            agent_id="john",
            agent_name="John",
            findings=[{"severity": "HIGH"}],
        )
        d = result.to_dict()
        assert d["agent_id"] == "john"
        assert d["findings_count"] == 1


class TestCrossReferencedFinding:
    """Test CrossReferencedFinding dataclass."""

    def test_creation(self):
        """Test creating a cross-referenced finding."""
        crf = CrossReferencedFinding(
            finding_id="f001",
            primary_agent="john",
            file_path="app.py",
            line_number=42,
            category="SQL Injection",
            severity="HIGH",
            confidence="CONFIRMED",
            correlated_agents=["tina"],
        )
        assert crf.finding_id == "f001"
        assert crf.confidence == "CONFIRMED"
        assert len(crf.correlated_agents) == 1

    def test_requires_approval(self):
        """Test approval flag."""
        crf = CrossReferencedFinding(
            finding_id="f002",
            primary_agent="john",
            file_path="app.py",
            line_number=42,
            category="SQL Injection",
            severity="CRITICAL",
            confidence="EXPLOITABLE",
            requires_human_approval=True,
            approval_status=HumanApprovalStatus.PENDING,
        )
        assert crf.requires_human_approval is True
        assert crf.approval_status == HumanApprovalStatus.PENDING


class TestOrchestratorState:
    """Test OrchestratorState dataclass."""

    def test_creation(self):
        """Test creating an orchestrator state."""
        state = OrchestratorState(scan_id="s001")
        assert state.scan_id == "s001"
        assert state.phase == OrchestratorPhase.INITIALIZING
        assert state.progress == 0

    def test_to_dict(self):
        """Test serialization."""
        state = OrchestratorState(
            scan_id="s001",
            phase=OrchestratorPhase.COMPLETED,
            progress=100,
        )
        d = state.to_dict()
        assert d["scan_id"] == "s001"
        assert d["phase"] == "completed"
        assert d["progress"] == 100


class TestHALOrchestrator:
    """Test HALOrchestrator."""

    @pytest.fixture
    async def orchestrator(self):
        orch = HALOrchestrator()
        await orch.start()
        yield orch
        await orch.stop()

    @pytest.mark.asyncio
    async def test_start_stop(self):
        """Test orchestrator lifecycle."""
        orch = HALOrchestrator()
        await orch.start()
        assert orch._running is True
        await orch.stop()
        assert orch._running is False

    @pytest.mark.asyncio
    async def test_severity_rank(self):
        """Test severity ranking."""
        assert HALOrchestrator._severity_rank("CRITICAL") == 4
        assert HALOrchestrator._severity_rank("HIGH") == 3
        assert HALOrchestrator._severity_rank("MEDIUM") == 2
        assert HALOrchestrator._severity_rank("LOW") == 1
        assert HALOrchestrator._severity_rank("INFO") == 0

    @pytest.mark.asyncio
    async def test_escalate_severity(self):
        """Test severity escalation."""
        assert HALOrchestrator._escalate_severity("INFO") == "LOW"
        assert HALOrchestrator._escalate_severity("LOW") == "MEDIUM"
        assert HALOrchestrator._escalate_severity("MEDIUM") == "HIGH"
        assert HALOrchestrator._escalate_severity("HIGH") == "CRITICAL"
        assert HALOrchestrator._escalate_severity("CRITICAL") == "CRITICAL"

    @pytest.mark.asyncio
    async def test_cross_reference_findings(self, orchestrator):
        """Test cross-referencing findings from multiple agents."""
        state = OrchestratorState(scan_id="s001")
        state.all_findings = [
            {
                "file_path": "app.py",
                "line_number": 42,
                "category": "SQL Injection",
                "severity": "HIGH",
                "tool_source": "john",
                "description": "SQLi found by SAST",
            },
            {
                "file_path": "app.py",
                "line_number": 42,
                "category": "SQL Injection",
                "severity": "HIGH",
                "tool_source": "tina",
                "description": "SQLi confirmed by taint",
            },
            {
                "file_path": "config.py",
                "line_number": 10,
                "category": "Secret Leak",
                "severity": "CRITICAL",
                "tool_source": "sam",
                "description": "AWS key found",
            },
        ]

        orchestrator._cross_reference_findings(state)

        assert len(state.cross_referenced_findings) == 2  # deduplicated

        # Check SQL injection is CONFIRMED (SAST + Taint)
        sql_findings = [
            f for f in state.cross_referenced_findings
            if "sql" in f.category.lower()
        ]
        assert len(sql_findings) == 1
        assert sql_findings[0].confidence in ("CONFIRMED", "HIGH")

    @pytest.mark.asyncio
    async def test_adaptive_aws_keys(self, orchestrator):
        """Test adaptive scanning triggers for AWS keys."""
        state = OrchestratorState(scan_id="s001")
        state.agent_results["dave"] = AgentScanResult(
            agent_id="dave", agent_name="Dave"
        )
        state.all_findings = [
            {
                "category": "AWS Key",
                "severity": "CRITICAL",
                "file_path": "config.py",
                "line_number": 1,
                "description": "AWS access key found",
            }
        ]

        await orchestrator._adaptive_adjustment(state)

        assert state.agent_results["dave"].metadata.get("priority_boost") is True
        assert "prioritized_dast_for_aws" in state.metadata.get("adaptive_action", "")

    @pytest.mark.asyncio
    async def test_adaptive_sql_injection(self, orchestrator):
        """Test adaptive scanning triggers for SQL injection."""
        state = OrchestratorState(scan_id="s001")
        state.agent_results["tina"] = AgentScanResult(
            agent_id="tina", agent_name="Tina"
        )
        state.all_findings = [
            {
                "category": "SQL Injection",
                "severity": "HIGH",
                "file_path": "app.py",
                "line_number": 42,
                "description": "SQLi found",
            }
        ]

        await orchestrator._adaptive_adjustment(state)

        assert state.agent_results["tina"].metadata.get("priority_boost") is True
        assert "prioritized_taint_for_sql" in state.metadata.get("adaptive_action", "")

    @pytest.mark.asyncio
    async def test_adaptive_prompt_injection(self, orchestrator):
        """Test adaptive scanning escalates prompt injection."""
        state = OrchestratorState(scan_id="s001")
        state.all_findings = [
            {
                "category": "Prompt Injection",
                "severity": "HIGH",
                "file_path": "ai_module.py",
                "line_number": 10,
            }
        ]

        await orchestrator._adaptive_adjustment(state)

        assert state.all_findings[0]["severity"] == "CRITICAL"
        assert state.all_findings[0]["metadata"]["escalated"] is True

    @pytest.mark.asyncio
    async def test_human_approval_check(self, orchestrator):
        """Test human approval detection."""
        state = OrchestratorState(scan_id="s001")
        state.triaged_findings = [
            {"severity": "CRITICAL", "category": "RCE", "finding_id": "f001"},
            {"severity": "HIGH", "category": "XSS", "finding_id": "f002"},
            {"severity": "MEDIUM", "category": "INFO", "finding_id": "f003"},
        ]
        state.metadata["approval_thresholds"] = ["CRITICAL"]

        approval_needed = orchestrator._check_human_approval(state)

        assert approval_needed is True
        assert len(state.human_approval_requests) == 1
        assert state.human_approval_requests[0]["finding_id"] == "f001"

    @pytest.mark.asyncio
    async def test_approve_findings(self, orchestrator):
        """Test approving findings."""
        state = OrchestratorState(scan_id="s001")
        state.triaged_findings = [
            {"severity": "CRITICAL", "finding_id": "f001"},
        ]
        state.human_approval_requests = [
            {
                "finding_id": "f001",
                "status": HumanApprovalStatus.PENDING.value,
            }
        ]
        state.phase = OrchestratorPhase.PAUSED_APPROVAL
        orchestrator._active_states["s001"] = state

        success = await orchestrator.approve_findings("s001", ["f001"], approved=True)

        assert success is True
        assert state.human_approval_requests[0]["status"] == HumanApprovalStatus.APPROVED.value

    @pytest.mark.asyncio
    async def test_get_state(self, orchestrator):
        """Test retrieving scan state."""
        state = OrchestratorState(scan_id="s001")
        orchestrator._active_states["s001"] = state

        retrieved = orchestrator.get_state("s001")
        assert retrieved is not None
        assert retrieved.scan_id == "s001"

    @pytest.mark.asyncio
    async def test_remove_state(self, orchestrator):
        """Test removing scan state."""
        state = OrchestratorState(scan_id="s001")
        orchestrator._active_states["s001"] = state

        orchestrator.remove_state("s001")
        assert orchestrator.get_state("s001") is None

    @pytest.mark.asyncio
    async def test_progress_callbacks(self, orchestrator):
        """Test progress tracking callbacks."""
        updates = []

        async def callback(scan_id, progress, phase):
            updates.append((scan_id, progress, phase))

        orchestrator.add_progress_callback(callback)

        state = OrchestratorState(scan_id="s001", progress=50)
        await orchestrator._update_progress(state)

        assert len(updates) == 1
        assert updates[0] == ("s001", 50, "initializing")

    @pytest.mark.asyncio
    async def test_approval_callbacks(self, orchestrator):
        """Test approval request callbacks."""
        requests_received = []

        async def callback(scan_id, requests):
            requests_received.append((scan_id, len(requests)))

        orchestrator.add_approval_callback(callback)

        state = OrchestratorState(scan_id="s001")
        state.human_approval_requests = [{"finding_id": "f001"}]
        orchestrator._active_states["s001"] = state

        await orchestrator._pause_for_approval(state)

        assert len(requests_received) == 1

    @pytest.mark.asyncio
    async def test_get_all_active_scans(self, orchestrator):
        """Test getting all active scans."""
        state1 = OrchestratorState(scan_id="s001")
        state2 = OrchestratorState(scan_id="s002")
        orchestrator._active_states["s001"] = state1
        orchestrator._active_states["s002"] = state2

        scans = orchestrator.get_all_active_scans()
        assert len(scans) == 2
        assert "s001" in scans
        assert "s002" in scans


class TestOrchestratorConstants:
    """Test orchestrator constants."""

    def test_phase_weights_sum(self):
        """Test that phase weights cover all phases."""
        weights = HALOrchestrator.PHASE_WEIGHTS
        assert OrchestratorPhase.INITIALIZING in weights
        assert OrchestratorPhase.PHASE_1_SCANNING in weights
        assert OrchestratorPhase.PHASE_2_TRIAGE in weights
        assert OrchestratorPhase.PHASE_3_FIX in weights
        assert OrchestratorPhase.PHASE_4_REPORT in weights
        assert OrchestratorPhase.COMPLETED in weights

    def test_scanning_agents(self):
        """Test scanning agents list."""
        agents = HALOrchestrator.SCANNING_AGENTS
        assert "john" in agents  # SAST
        assert "dave" in agents  # DAST
        assert "sam" in agents   # Secrets
        assert "pam" in agents   # SCA
        assert "tina" in agents  # Taint
        assert "casey" in agents  # Container
        assert "sade" in agents  # LLM Security
        assert "hal" not in agents  # Orchestrator shouldn't scan


class TestOrchestratorSingleton:
    """Test singleton behavior."""

    def test_singleton(self):
        """Test that get_orchestrator returns singleton."""
        orch1 = get_orchestrator()
        orch2 = get_orchestrator()
        assert orch1 is orch2

    @pytest.mark.asyncio
    async def test_reset(self):
        """Test resetting orchestrator."""
        orch = get_orchestrator()
        await orch.start()
        await reset_orchestrator()
        new_orch = get_orchestrator()
        assert new_orch is not orch
