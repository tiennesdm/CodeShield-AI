"""
Findings Chain Visualizer for CodeShield AI.

Tracks how findings chain across multiple agents, building confidence
through cross-validation. Identifies the strongest chains (highest confidence)
and flags broken chains where agents disagree.

Example chain:
    SAST Agent: "Potential SQL injection at line 42" (confidence: 60%)
      -> Taint Agent: "User input flows to SQL sink" (confidence: 80%)
        -> DAST Agent: "Confirmed exploitable via UNION injection" (confidence: 95%)
          -> Triager: FINAL CONFIDENCE: 95%, EXPLOITABLE

Features:
- Build chain graph from agent findings
- Identify strongest chains (highest cumulative confidence)
- Flag broken chains (agents disagree)
- Chain visualization data generation
- CrewAI-compatible Agent interface
"""

import os
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from models.vulnerability import Vulnerability
from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

CHAIN_CONFIDENCE_THRESHOLD = float(os.environ.get("CS_CHAIN_CONF_THRESHOLD", "70.0"))
CHAIN_AGREEMENT_THRESHOLD = float(os.environ.get("CS_CHAIN_AGREE_THRESHOLD", "0.5"))

# Agent execution order (for chain visualization)
AGENT_EXECUTION_ORDER = [
    "sast_scanner",
    "semgrep",
    "bandit",
    "eslint",
    "pmd",
    "gitleaks",
    "custom_ai",
    "taint_analyzer",
    "sca_analyzer",
    "dast_scanner",
    "container_scanner",
    "llm_security_scanner",
    "triager",
]

# Agent display names
AGENT_DISPLAY_NAMES: Dict[str, str] = {
    "sast_scanner": "SAST Agent",
    "semgrep": "Semgrep",
    "bandit": "Bandit",
    "eslint": "ESLint",
    "pmd": "PMD",
    "gitleaks": "Gitleaks",
    "custom_ai": "AI Pattern Scanner",
    "taint_analyzer": "Taint Analyzer",
    "sca_analyzer": "SCA Analyzer",
    "dast_scanner": "DAST Agent",
    "container_scanner": "Container Scanner",
    "llm_security_scanner": "LLM Security Scanner",
    "triager": "Triager",
}

# Confidence numeric mapping
CONFIDENCE_VALUES = {
    "HIGH": 0.85,
    "MEDIUM": 0.50,
    "LOW": 0.20,
}


class ChainStatus(str, Enum):
    """Status of a findings chain."""

    VALID = "valid"  # All agents agree
    STRONG = "strong"  # High cumulative confidence
    BROKEN = "broken"  # Agents disagree
    WEAK = "weak"  # Low overall confidence
    UNCONFIRMED = "unconfirmed"  # Single agent finding
    CONVERGED = "converged"  # Multiple agents confirm


class ChainNodeType(str, Enum):
    """Type of chain node."""

    DETECTION = "detection"
    CONFIRMATION = "confirmation"
    TRIAGE = "triage"


@dataclass
class ChainNode:
    """A single node in a findings chain."""

    agent_name: str
    vuln_id: str
    confidence: float = 0.0
    confidence_label: str = "LOW"
    description: str = ""
    evidence: str = ""
    node_type: ChainNodeType = ChainNodeType.DETECTION
    timestamp: Optional[datetime] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "agent_name": self.agent_name,
            "display_name": AGENT_DISPLAY_NAMES.get(self.agent_name, self.agent_name),
            "vuln_id": self.vuln_id,
            "confidence": round(self.confidence, 2),
            "confidence_label": self.confidence_label,
            "description": self.description,
            "evidence": self.evidence,
            "node_type": self.node_type.value,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
        }


@dataclass
class FindingChain:
    """A complete chain of findings across agents."""

    chain_id: str
    file_path: str
    line_number: int
    category: str
    nodes: List[ChainNode] = field(default_factory=list)
    final_confidence: float = 0.0
    final_status: ChainStatus = ChainStatus.UNCONFIRMED
    is_exploitable: bool = False
    is_false_positive: bool = False
    chain_description: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "chain_id": self.chain_id,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "category": self.category,
            "nodes": [n.to_dict() for n in self.nodes],
            "node_count": len(self.nodes),
            "final_confidence": round(self.final_confidence, 2),
            "final_status": self.final_status.value,
            "is_exploitable": self.is_exploitable,
            "is_false_positive": self.is_false_positive,
            "chain_description": self.chain_description,
            "created_at": self.created_at.isoformat(),
        }

    def to_text(self) -> str:
        """Generate text representation of the chain."""
        lines = [
            f"Chain: {self.chain_id}",
            f"Location: {self.file_path}:{self.line_number} ({self.category})",
            f"Status: {self.final_status.value.upper()} | Confidence: {self.final_confidence:.1f}%",
            "",
        ]

        indent = 0
        for node in self.nodes:
            prefix = "  " * indent + ("-> " if indent > 0 else "")
            display_name = AGENT_DISPLAY_NAMES.get(node.agent_name, node.agent_name)
            lines.append(
                f"{prefix}{display_name}: \"{node.description[:60]}\" (confidence: {node.confidence:.0f}%)"
            )
            indent += 1

        lines.append(f"  {'  ' * (indent)}=> FINAL: {self.final_status.value.upper()}, {'EXPLOITABLE' if self.is_exploitable else 'NOT EXPLOITABLE'}")
        lines.append("")

        return "\n".join(lines)


class ChainsVisualizer:
    """
    Findings Chain Visualizer for CodeShield AI.

    Tracks how findings flow through multiple agents, building
    confidence chains that show cross-validation strength.

    Compatible with CrewAI agent interfaces.
    """

    def __init__(self) -> None:
        """Initialize the Chains Visualizer."""
        self._chains: Dict[str, FindingChain] = {}
        self._vuln_to_chain: Dict[str, str] = {}  # vuln_id -> chain_id
        logger.info("ChainsVisualizer initialized")

    # ========================================================================
    # Chain Building
    # ========================================================================

    def build_chains(
        self,
        vulnerabilities: List[Vulnerability],
        triage_results: Optional[List[Any]] = None,
    ) -> List[FindingChain]:
        """
        Build finding chains from vulnerabilities.

        Groups vulnerabilities by file_path + line_number + category,
        then creates chains showing which agents found each.

        Args:
            vulnerabilities: All vulnerabilities
            triage_results: Optional triage results

        Returns:
            List of finding chains
        """
        if not vulnerabilities:
            return []

        # Group by location + category
        groups: Dict[str, List[Vulnerability]] = defaultdict(list)
        for v in vulnerabilities:
            key = f"{v.file_path}:{v.line_number}:{v.category}"
            groups[key].append(v)

        chains: List[FindingChain] = []

        for key, group in groups.items():
            # Sort by agent execution order
            sorted_group = sorted(
                group,
                key=lambda v: (
                    AGENT_EXECUTION_ORDER.index(v.tool_source)
                    if v.tool_source in AGENT_EXECUTION_ORDER
                    else 99
                ),
            )

            # Create chain nodes
            nodes: List[ChainNode] = []
            for v in sorted_group:
                conf_value = CONFIDENCE_VALUES.get(v.confidence.upper(), 0.5)
                node = ChainNode(
                    agent_name=v.tool_source,
                    vuln_id=v.id,
                    confidence=conf_value * 100,
                    confidence_label=v.confidence,
                    description=v.description[:200],
                    evidence=v.code_snippet or "",
                    node_type=self._classify_node_type(v.tool_source),
                )
                nodes.append(node)

            # Determine final confidence
            final_confidence = self._compute_final_confidence(nodes)

            # Determine chain status
            chain_status = self._determine_chain_status(
                nodes, final_confidence, triage_results
            )

            # Check if exploitable
            is_exploitable = any(
                "confirmed" in n.description.lower() or n.agent_name == "dast_scanner"
                for n in nodes
            )

            # Build chain description
            descriptions = [n.description for n in nodes]
            chain_desc = " | ".join(d[:50] for d in descriptions)

            chain = FindingChain(
                chain_id=f"chain-{hash(key) & 0xFFFFFFFF:08x}",
                file_path=sorted_group[0].file_path,
                line_number=sorted_group[0].line_number,
                category=sorted_group[0].category,
                nodes=nodes,
                final_confidence=final_confidence,
                final_status=chain_status,
                is_exploitable=is_exploitable,
                chain_description=chain_desc,
            )

            chains.append(chain)

            # Map vuln IDs to chain
            for v in sorted_group:
                self._vuln_to_chain[v.id] = chain.chain_id

        self._chains = {c.chain_id: c for c in chains}

        logger.info(
            "Built %d chains from %d vulnerabilities",
            len(chains),
            len(vulnerabilities),
        )
        return chains

    @staticmethod
    def _classify_node_type(agent_name: str) -> ChainNodeType:
        """
        Classify the node type based on agent name.

        Args:
            agent_name: Agent name

        Returns:
            ChainNodeType
        """
        if agent_name in ("triager",):
            return ChainNodeType.TRIAGE
        elif agent_name in ("dast_scanner", "taint_analyzer"):
            return ChainNodeType.CONFIRMATION
        else:
            return ChainNodeType.DETECTION

    @staticmethod
    def _compute_final_confidence(nodes: List[ChainNode]) -> float:
        """
        Compute final confidence from chain nodes.

        Uses Bayesian-inspired combination where confirmation
        nodes (DAST, Taint) weigh more heavily.

        Args:
            nodes: Chain nodes

        Returns:
            Final confidence (0-100)
        """
        if not nodes:
            return 0.0

        # Weight confirmation nodes more heavily
        weights = {
            ChainNodeType.DETECTION: 1.0,
            ChainNodeType.CONFIRMATION: 1.5,
            ChainNodeType.TRIAGE: 1.2,
        }

        weighted_sum = sum(
            n.confidence * weights.get(n.node_type, 1.0) for n in nodes
        )
        total_weight = sum(weights.get(n.node_type, 1.0) for n in nodes)

        base_confidence = weighted_sum / total_weight if total_weight > 0 else 0

        # Boost for multi-agent agreement
        agent_count = len(set(n.agent_name for n in nodes))
        if agent_count >= 3:
            base_confidence = min(100.0, base_confidence * 1.15)
        elif agent_count == 2:
            base_confidence = min(100.0, base_confidence * 1.08)

        return min(100.0, base_confidence)

    def _determine_chain_status(
        self,
        nodes: List[ChainNode],
        final_confidence: float,
        triage_results: Optional[List[Any]] = None,
    ) -> ChainStatus:
        """
        Determine the chain status.

        Args:
            nodes: Chain nodes
            final_confidence: Final confidence score
            triage_results: Optional triage results

        Returns:
            ChainStatus
        """
        if len(nodes) == 1:
            return ChainStatus.UNCONFIRMED

        # Check for disagreements (broken chain)
        descriptions = [n.description.lower() for n in nodes]
        fp_indicators = sum(1 for d in descriptions if "false positive" in d)
        tp_indicators = sum(1 for d in descriptions if any(
            kw in d for kw in ["exploitable", "confirmed", "vulnerable", "injection"]
        ))

        if fp_indicators > 0 and tp_indicators > 0:
            return ChainStatus.BROKEN

        if final_confidence >= CHAIN_CONFIDENCE_THRESHOLD:
            if len(nodes) >= 2:
                return ChainStatus.STRONG if len(nodes) >= 3 else ChainStatus.CONVERGED
            return ChainStatus.VALID

        return ChainStatus.WEAK

    # ========================================================================
    # Chain Analysis
    # ========================================================================

    def get_strongest_chains(
        self,
        chains: Optional[List[FindingChain]] = None,
        limit: int = 10,
    ) -> List[FindingChain]:
        """
        Get the strongest chains (highest confidence).

        Args:
            chains: Optional list of chains (uses internal if None)
            limit: Maximum number to return

        Returns:
            Sorted list of strongest chains
        """
        target = chains or list(self._chains.values())
        sorted_chains = sorted(target, key=lambda c: -c.final_confidence)
        return sorted_chains[:limit]

    def get_broken_chains(
        self,
        chains: Optional[List[FindingChain]] = None,
    ) -> List[FindingChain]:
        """
        Get chains where agents disagree.

        Args:
            chains: Optional list of chains

        Returns:
            List of broken chains
        """
        target = chains or list(self._chains.values())
        return [c for c in target if c.final_status == ChainStatus.BROKEN]

    def get_exploitable_chains(
        self,
        chains: Optional[List[FindingChain]] = None,
    ) -> List[FindingChain]:
        """
        Get chains marked as exploitable.

        Args:
            chains: Optional list of chains

        Returns:
            List of exploitable chains
        """
        target = chains or list(self._chains.values())
        return [c for c in target if c.is_exploitable]

    def get_chain_for_vulnerability(self, vuln_id: str) -> Optional[FindingChain]:
        """
        Get the chain containing a specific vulnerability.

        Args:
            vuln_id: Vulnerability ID

        Returns:
            FindingChain or None
        """
        chain_id = self._vuln_to_chain.get(vuln_id)
        if chain_id:
            return self._chains.get(chain_id)
        return None

    # ========================================================================
    # Visualization Data
    # ========================================================================

    def generate_visualization_data(
        self,
        chains: Optional[List[FindingChain]] = None,
    ) -> Dict[str, Any]:
        """
        Generate data for chain visualization.

        Produces a structure suitable for D3.js or similar visualization.

        Args:
            chains: Optional list of chains

        Returns:
            Visualization data dict
        """
        target = chains or list(self._chains.values())

        # Build nodes and links for graph
        graph_nodes: Set[str] = set()
        graph_links: List[Dict[str, Any]] = []
        chain_visualizations: List[Dict[str, Any]] = []

        for chain in target:
            # Chain-level visualization
            viz_nodes = []
            for i, node in enumerate(chain.nodes):
                node_id = f"{chain.chain_id}-{i}"
                graph_nodes.add(node_id)
                viz_nodes.append(
                    {
                        "id": node_id,
                        "agent": node.agent_name,
                        "display_name": AGENT_DISPLAY_NAMES.get(
                            node.agent_name, node.agent_name
                        ),
                        "confidence": node.confidence,
                        "node_type": node.node_type.value,
                        "description": node.description[:100],
                        "level": i,
                    }
                )

                # Links between consecutive nodes
                if i > 0:
                    prev_id = f"{chain.chain_id}-{i - 1}"
                    graph_links.append(
                        {
                            "source": prev_id,
                            "target": node_id,
                            "chain_id": chain.chain_id,
                            "confidence": node.confidence,
                        }
                    )

            chain_visualizations.append(
                {
                    "chain_id": chain.chain_id,
                    "category": chain.category,
                    "location": f"{chain.file_path}:{chain.line_number}",
                    "final_confidence": chain.final_confidence,
                    "status": chain.final_status.value,
                    "is_exploitable": chain.is_exploitable,
                    "nodes": viz_nodes,
                }
            )

        # Summary statistics
        status_counts: Dict[str, int] = defaultdict(int)
        for chain in target:
            status_counts[chain.final_status.value] += 1

        return {
            "meta": {
                "total_chains": len(target),
                "status_distribution": dict(status_counts),
                "exploitable_count": sum(1 for c in target if c.is_exploitable),
                "broken_count": sum(1 for c in target if c.final_status == ChainStatus.BROKEN),
            },
            "chains": [c.to_dict() for c in target],
            "visualization": {
                "graph": {
                    "nodes": list(graph_nodes),
                    "links": graph_links,
                },
                "chain_trees": chain_visualizations,
            },
        }

    def generate_text_report(
        self,
        chains: Optional[List[FindingChain]] = None,
    ) -> str:
        """
        Generate a text report of all chains.

        Args:
            chains: Optional list of chains

        Returns:
            Text report string
        """
        target = chains or list(self._chains.values())

        lines = [
            "=" * 78,
            "  FINDINGS CHAIN VISUALIZATION REPORT",
            "=" * 78,
            f"  Total Chains: {len(target)}",
            f"  Exploitable:  {sum(1 for c in target if c.is_exploitable)}",
            f"  Broken:       {sum(1 for c in target if c.final_status == ChainStatus.BROKEN)}",
            "=" * 78,
            "",
        ]

        # Strongest chains first
        sorted_chains = sorted(target, key=lambda c: -c.final_confidence)

        for chain in sorted_chains:
            lines.append(chain.to_text())

        # Summary section
        lines.extend([
            "=" * 78,
            "  SUMMARY",
            "=" * 78,
        ])

        status_counts: Dict[str, int] = defaultdict(int)
        for c in target:
            status_counts[c.final_status.value] += 1

        for status, count in sorted(status_counts.items()):
            lines.append(f"  {status.upper()}: {count}")

        lines.append("=" * 78)

        return "\n".join(lines)

    # ========================================================================
    # Main API
    # ========================================================================

    async def analyze_chains(
        self,
        vulnerabilities: List[Vulnerability],
        triage_results: Optional[List[Any]] = None,
    ) -> Dict[str, Any]:
        """
        Run full chain analysis.

        Args:
            vulnerabilities: All vulnerabilities
            triage_results: Optional triage results

        Returns:
            Complete chain analysis result
        """
        start_time = datetime.now(timezone.utc)

        chains = self.build_chains(vulnerabilities, triage_results)
        viz_data = self.generate_visualization_data(chains)
        text_report = self.generate_text_report(chains)

        strongest = self.get_strongest_chains(chains, limit=10)
        broken = self.get_broken_chains(chains)
        exploitable = self.get_exploitable_chains(chains)

        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

        return {
            "chains": [c.to_dict() for c in chains],
            "strongest_chains": [c.to_dict() for c in strongest],
            "broken_chains": [c.to_dict() for c in broken],
            "exploitable_chains": [c.to_dict() for c in exploitable],
            "visualization_data": viz_data,
            "text_report": text_report,
            "stats": {
                "total_chains": len(chains),
                "strong_chains": sum(1 for c in chains if c.final_status == ChainStatus.STRONG),
                "broken_chains": len(broken),
                "exploitable_chains": len(exploitable),
                "unconfirmed_chains": sum(1 for c in chains if c.final_status == ChainStatus.UNCONFIRMED),
                "elapsed_seconds": round(elapsed, 2),
            },
        }

    async def get_stats(self) -> Dict[str, Any]:
        """Get chains visualizer statistics."""
        return {
            "confidence_threshold": CHAIN_CONFIDENCE_THRESHOLD,
            "agreement_threshold": CHAIN_AGREEMENT_THRESHOLD,
            "total_tracked_chains": len(self._chains),
            "agent_display_names": AGENT_DISPLAY_NAMES,
        }
