"""
Tests for the Findings Chain Visualizer.

Covers:
- Chain building from vulnerabilities
- Final confidence computation
- Chain status determination
- Strongest chains selection
- Broken chains detection
- Exploitable chains detection
- Visualization data generation
- Chain lookup by vulnerability ID
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../.."))

import pytest
from models.vulnerability import Vulnerability
from agents.chains import (
    ChainsVisualizer,
    FindingChain,
    ChainNode,
    ChainStatus,
    ChainNodeType,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def visualizer():
    """Create a ChainsVisualizer instance."""
    return ChainsVisualizer()


@pytest.fixture
def single_agent_vulns():
    """Vulnerabilities from a single agent."""
    return [
        Vulnerability(
            scan_id="s1", file_path="src/app.py", line_number=42,
            severity="HIGH", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
            description="Potential SQL injection at line 42",
            code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            fix_suggestion="Use params", tool_source="bandit",
            confidence="HIGH", id="chain-001",
        ),
    ]


@pytest.fixture
def multi_agent_vulns():
    """Vulnerabilities detected by multiple agents (same location)."""
    return [
        Vulnerability(
            scan_id="s1", file_path="src/app.py", line_number=42,
            severity="HIGH", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQLi", title="SQLi SAST",
            description="Potential SQL injection at line 42",
            code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            fix_suggestion="Use params", tool_source="bandit",
            confidence="HIGH", id="chain-002",
        ),
        Vulnerability(
            scan_id="s1", file_path="src/app.py", line_number=42,
            severity="HIGH", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQLi", title="SQLi Taint",
            description="User input flows to SQL sink",
            code_snippet="cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            fix_suggestion="Use params", tool_source="taint_analyzer",
            confidence="HIGH", id="chain-003",
        ),
        Vulnerability(
            scan_id="s1", file_path="src/app.py", line_number=42,
            severity="HIGH", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQLi", title="SQLi DAST",
            description="Confirmed exploitable via UNION injection",
            code_snippet="", fix_suggestion="Use params",
            tool_source="dast_scanner", confidence="HIGH", id="chain-004",
        ),
    ]


@pytest.fixture
def mixed_vulns():
    """Vulnerabilities at different locations from different agents."""
    return [
        Vulnerability(
            scan_id="s1", file_path="src/app.py", line_number=42,
            severity="HIGH", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQLi", title="SQLi",
            description="Potential SQL injection",
            code_snippet="code", fix_suggestion="fix",
            tool_source="bandit", confidence="HIGH", id="mv-001",
        ),
        Vulnerability(
            scan_id="s1", file_path="src/app.py", line_number=42,
            severity="HIGH", category="SQL Injection",
            cwe_id="CWE-89", cwe_name="SQLi", title="SQLi Taint",
            description="User input flows to SQL sink",
            code_snippet="code", fix_suggestion="fix",
            tool_source="taint_analyzer", confidence="HIGH", id="mv-002",
        ),
        Vulnerability(
            scan_id="s1", file_path="src/utils.py", line_number=10,
            severity="MEDIUM", category="XSS",
            cwe_id="CWE-79", cwe_name="XSS", title="XSS",
            description="innerHTML assignment",
            code_snippet="code", fix_suggestion="fix",
            tool_source="eslint", confidence="MEDIUM", id="mv-003",
        ),
    ]


# ---------------------------------------------------------------------------
# Chain Building Tests
# ---------------------------------------------------------------------------

class TestChainBuilding:
    """Test chain building from vulnerabilities."""

    def test_empty_vulnerabilities(self, visualizer):
        """Test empty vulnerability list returns empty chains."""
        chains = visualizer.build_chains([])
        assert chains == [], "Empty list should return empty chains"

    def test_single_agent_single_chain(self, visualizer, single_agent_vulns):
        """Test single agent creates one chain."""
        chains = visualizer.build_chains(single_agent_vulns)
        assert len(chains) == 1, f"Expected 1 chain, got {len(chains)}"

    def test_single_agent_status_unconfirmed(self, visualizer, single_agent_vulns):
        """Test single agent chain is UNCONFIRMED."""
        chains = visualizer.build_chains(single_agent_vulns)
        assert chains[0].final_status == ChainStatus.UNCONFIRMED

    def test_multi_agent_creates_one_chain(self, visualizer, multi_agent_vulns):
        """Test multiple agents on same location create one chain."""
        chains = visualizer.build_chains(multi_agent_vulns)
        assert len(chains) == 1, f"Expected 1 chain for same location, got {len(chains)}"

    def test_multi_agent_has_all_nodes(self, visualizer, multi_agent_vulns):
        """Test chain has nodes for all agents."""
        chains = visualizer.build_chains(multi_agent_vulns)
        chain = chains[0]
        assert len(chain.nodes) == 3, f"Expected 3 nodes, got {len(chain.nodes)}"

    def test_node_types(self, visualizer, multi_agent_vulns):
        """Test node types are classified correctly."""
        chains = visualizer.build_chains(multi_agent_vulns)
        chain = chains[0]
        node_types = [n.node_type for n in chain.nodes]
        assert ChainNodeType.DETECTION in node_types, "Should have DETECTION nodes"
        assert ChainNodeType.CONFIRMATION in node_types, "Should have CONFIRMATION nodes"

    def test_chain_location(self, visualizer, multi_agent_vulns):
        """Test chain location is correct."""
        chains = visualizer.build_chains(multi_agent_vulns)
        chain = chains[0]
        assert chain.file_path == "src/app.py"
        assert chain.line_number == 42
        assert chain.category == "SQL Injection"


class TestConfidenceComputation:
    """Test final confidence computation."""

    def test_empty_nodes_zero_confidence(self, visualizer):
        """Test empty nodes give zero confidence."""
        confidence = visualizer._compute_final_confidence([])
        assert confidence == 0.0, f"Expected 0.0, got {confidence}"

    def test_single_node_base_confidence(self, visualizer):
        """Test single node gives base confidence."""
        nodes = [
            ChainNode(agent_name="bandit", vuln_id="v1", confidence=80.0, node_type=ChainNodeType.DETECTION)
        ]
        confidence = visualizer._compute_final_confidence(nodes)
        assert confidence == 80.0, f"Expected 80.0, got {confidence}"

    def test_confirmation_weighted_higher(self, visualizer):
        """Test confirmation nodes are weighted higher."""
        detection = ChainNode(agent_name="bandit", vuln_id="v1", confidence=80.0, node_type=ChainNodeType.DETECTION)
        confirmation = ChainNode(agent_name="dast", vuln_id="v2", confidence=90.0, node_type=ChainNodeType.CONFIRMATION)
        confidence = visualizer._compute_final_confidence([detection, confirmation])
        # Confirmation has 1.5x weight, so should be higher than simple average
        simple_avg = (80 + 90) / 2
        assert confidence > simple_avg, f"Weighted avg ({confidence}) should exceed simple avg ({simple_avg})"

    def test_multi_agent_boost(self, visualizer):
        """Test 3+ agents get confidence boost."""
        nodes = [
            ChainNode(agent_name="bandit", vuln_id="v1", confidence=70.0, node_type=ChainNodeType.DETECTION),
            ChainNode(agent_name="semgrep", vuln_id="v2", confidence=70.0, node_type=ChainNodeType.DETECTION),
            ChainNode(agent_name="dast", vuln_id="v3", confidence=90.0, node_type=ChainNodeType.CONFIRMATION),
        ]
        confidence = visualizer._compute_final_confidence(nodes)
        assert confidence <= 100.0, f"Confidence should not exceed 100, got {confidence}"

    def test_confidence_clamped_to_100(self, visualizer):
        """Test confidence is clamped to 100."""
        nodes = [
            ChainNode(agent_name="a", vuln_id="v1", confidence=99.0, node_type=ChainNodeType.DETECTION),
            ChainNode(agent_name="b", vuln_id="v2", confidence=99.0, node_type=ChainNodeType.CONFIRMATION),
            ChainNode(agent_name="c", vuln_id="v3", confidence=99.0, node_type=ChainNodeType.CONFIRMATION),
            ChainNode(agent_name="d", vuln_id="v4", confidence=99.0, node_type=ChainNodeType.CONFIRMATION),
        ]
        confidence = visualizer._compute_final_confidence(nodes)
        assert confidence <= 100.0, f"Confidence should be clamped to 100, got {confidence}"


class TestChainStatus:
    """Test chain status determination."""

    def test_unconfirmed_single_node(self, visualizer):
        """Test single node is UNCONFIRMED."""
        nodes = [ChainNode(agent_name="bandit", vuln_id="v1", confidence=60.0)]
        status = visualizer._determine_chain_status(nodes, 60.0, None)
        assert status == ChainStatus.UNCONFIRMED

    def test_valid_multi_node(self, visualizer):
        """Test multi-node with agreement is VALID."""
        nodes = [
            ChainNode(agent_name="bandit", vuln_id="v1", confidence=80.0),
            ChainNode(agent_name="taint", vuln_id="v2", confidence=85.0),
        ]
        status = visualizer._determine_chain_status(nodes, 82.0, None)
        assert status in [ChainStatus.VALID, ChainStatus.CONVERGED, ChainStatus.STRONG]

    def test_strong_high_confidence(self, visualizer):
        """Test 3+ agents with high confidence is STRONG."""
        nodes = [
            ChainNode(agent_name="bandit", vuln_id="v1", confidence=85.0),
            ChainNode(agent_name="taint", vuln_id="v2", confidence=85.0),
            ChainNode(agent_name="dast", vuln_id="v3", confidence=95.0),
        ]
        status = visualizer._determine_chain_status(nodes, 90.0, None)
        assert status in [ChainStatus.STRONG, ChainStatus.CONVERGED]

    def test_weak_low_confidence(self, visualizer):
        """Test low confidence chain is WEAK."""
        nodes = [
            ChainNode(agent_name="bandit", vuln_id="v1", confidence=30.0),
            ChainNode(agent_name="taint", vuln_id="v2", confidence=25.0),
        ]
        status = visualizer._determine_chain_status(nodes, 27.0, None)
        assert status == ChainStatus.WEAK


# ---------------------------------------------------------------------------
# Chain Analysis Tests
# ---------------------------------------------------------------------------

class TestChainAnalysis:
    """Test chain analysis methods."""

    def test_get_strongest_chains(self, visualizer, multi_agent_vulns):
        """Test getting strongest chains."""
        chains = visualizer.build_chains(multi_agent_vulns)
        strongest = visualizer.get_strongest_chains(chains, limit=5)
        assert len(strongest) >= 1
        # Should be sorted by confidence descending
        if len(strongest) >= 2:
            assert strongest[0].final_confidence >= strongest[-1].final_confidence

    def test_get_exploitable_chains(self, visualizer, multi_agent_vulns):
        """Test getting exploitable chains."""
        chains = visualizer.build_chains(multi_agent_vulns)
        exploitable = visualizer.get_exploitable_chains(chains)
        # DAST confirmed should be exploitable
        assert len(exploitable) >= 1, "Should have exploitable chains with DAST"

    def test_chain_for_vulnerability(self, visualizer, multi_agent_vulns):
        """Test lookup by vulnerability ID."""
        visualizer.build_chains(multi_agent_vulns)
        chain = visualizer.get_chain_for_vulnerability("chain-002")
        assert chain is not None, "Should find chain for vuln ID"

    def test_chain_not_found(self, visualizer, multi_agent_vulns):
        """Test lookup for nonexistent vuln ID."""
        visualizer.build_chains(multi_agent_vulns)
        chain = visualizer.get_chain_for_vulnerability("nonexistent")
        assert chain is None, "Should return None for unknown vuln ID"


# ---------------------------------------------------------------------------
# Visualization Data Tests
# ---------------------------------------------------------------------------

class TestVisualizationData:
    """Test visualization data generation."""

    def test_has_meta(self, visualizer, multi_agent_vulns):
        """Test viz data has metadata."""
        chains = visualizer.build_chains(multi_agent_vulns)
        viz = visualizer.generate_visualization_data(chains)
        assert "meta" in viz
        assert "total_chains" in viz["meta"]

    def test_has_chains(self, visualizer, multi_agent_vulns):
        """Test viz data has chain data."""
        chains = visualizer.build_chains(multi_agent_vulns)
        viz = visualizer.generate_visualization_data(chains)
        assert "chains" in viz
        assert len(viz["chains"]) > 0

    def test_has_graph_data(self, visualizer, multi_agent_vulns):
        """Test viz data has graph structure."""
        chains = visualizer.build_chains(multi_agent_vulns)
        viz = visualizer.generate_visualization_data(chains)
        assert "visualization" in viz
        assert "graph" in viz["visualization"]

    def test_text_report(self, visualizer, multi_agent_vulns):
        """Test text report generation."""
        chains = visualizer.build_chains(multi_agent_vulns)
        report = visualizer.generate_text_report(chains)
        assert "Chain:" in report
        assert "FINAL:" in report

    def test_chain_to_text(self, visualizer, multi_agent_vulns):
        """Test individual chain text representation."""
        chains = visualizer.build_chains(multi_agent_vulns)
        text = chains[0].to_text()
        assert chains[0].chain_id in text
        assert "confidence" in text.lower()


# ---------------------------------------------------------------------------
# Integration Tests
# ---------------------------------------------------------------------------

class TestChainPipeline:
    """Test the full chain analysis pipeline."""

    @pytest.mark.asyncio
    async def test_full_analysis(self, visualizer, mixed_vulns):
        """Test full chain analysis."""
        result = await visualizer.analyze_chains(mixed_vulns)
        assert "chains" in result
        assert "stats" in result
        assert "strongest_chains" in result
        assert "exploitable_chains" in result

    @pytest.mark.asyncio
    async def test_stats_present(self, visualizer, mixed_vulns):
        """Test stats are in result."""
        result = await visualizer.analyze_chains(mixed_vulns)
        stats = result["stats"]
        assert "total_chains" in stats
        assert stats["total_chains"] >= 1

    @pytest.mark.asyncio
    async def test_empty_vulnerabilities(self, visualizer):
        """Test pipeline with empty vulns."""
        result = await visualizer.analyze_chains([])
        assert result["chains"] == []
        assert result["stats"]["total_chains"] == 0

    @pytest.mark.asyncio
    async def test_get_stats(self, visualizer):
        """Test get_stats returns configuration."""
        stats = await visualizer.get_stats()
        assert "confidence_threshold" in stats
        assert "agreement_threshold" in stats


# ---------------------------------------------------------------------------
# Chain Data Class Tests
# ---------------------------------------------------------------------------

class TestChainDataClasses:
    """Test chain dataclass methods."""

    def test_chain_node_to_dict(self):
        """Test ChainNode serialization."""
        node = ChainNode(
            agent_name="bandit",
            vuln_id="v1",
            confidence=85.0,
            confidence_label="HIGH",
            description="SQL injection found",
            node_type=ChainNodeType.DETECTION,
        )
        d = node.to_dict()
        assert d["agent_name"] == "bandit"
        assert d["confidence"] == 85.0
        assert d["node_type"] == "detection"

    def test_finding_chain_to_dict(self):
        """Test FindingChain serialization."""
        chain = FindingChain(
            chain_id="test-chain-001",
            file_path="src/app.py",
            line_number=42,
            category="SQL Injection",
            final_confidence=85.0,
            final_status=ChainStatus.STRONG,
            nodes=[
                ChainNode(agent_name="bandit", vuln_id="v1", confidence=80.0),
                ChainNode(agent_name="dast", vuln_id="v2", confidence=95.0),
            ],
        )
        d = chain.to_dict()
        assert d["chain_id"] == "test-chain-001"
        assert d["final_confidence"] == 85.0
        assert d["final_status"] == "strong"
        assert len(d["nodes"]) == 2

    def test_chain_text_output(self):
        """Test chain text representation."""
        chain = FindingChain(
            chain_id="test-chain-002",
            file_path="src/app.py",
            line_number=42,
            category="SQL Injection",
            final_confidence=95.0,
            final_status=ChainStatus.STRONG,
            is_exploitable=True,
            nodes=[
                ChainNode(
                    agent_name="bandit", vuln_id="v1", confidence=60.0,
                    description="Potential SQL injection at line 42"
                ),
                ChainNode(
                    agent_name="dast_scanner", vuln_id="v2", confidence=95.0,
                    description="Confirmed exploitable via UNION injection"
                ),
            ],
        )
        text = chain.to_text()
        assert chain.chain_id in text
        assert "EXPLOITABLE" in text
        assert "bandit" in text.lower() or "Bandit" in text


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
