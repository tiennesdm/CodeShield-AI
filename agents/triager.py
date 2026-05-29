"""
Triager Agent - Intelligent Finding Quality Controller for CodeShield AI.

Post-processing agent that deduplicates findings, scores confidence,
runs AI triage, and adjusts severity based on context. Receives findings
from all scanning agents and produces the final triaged output.

Features:
- Hash-based deduplication (file + line + category)
- Semantic deduplication (fuzzy matching on descriptions)
- Cross-agent deduplication with confidence boost
- AI-powered triage with context analysis
- Reachability-adjusted and exploitation-adjusted severity
- CrewAI-compatible Agent interface
"""

import asyncio
import hashlib
import os
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from models.vulnerability import SeverityLevel, Vulnerability
from ai_triage import AITriageEngine, TriageVerdict
from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration (overridable via environment variables)
# ---------------------------------------------------------------------------

SEMANTIC_DEDUP_THRESHOLD = float(os.environ.get("CS_TRIAGE_SEMANTIC_THRESHOLD", "0.85"))
CONFIDENCE_MULTIPLIER_AGREEMENT = float(os.environ.get("CS_TRIAGE_CONF_MULTIPLIER", "1.20"))
CONFIDENCE_TAINT_BONUS = float(os.environ.get("CS_TRIAGE_TAINT_BONUS", "15.0"))
CONFIDENCE_DAST_BONUS = float(os.environ.get("CS_TRIAGE_DAST_BONUS", "10.0"))
CONFIDENCE_FP_PENALTY = float(os.environ.get("CS_TRIAGE_FP_PENALTY", "30.0"))
CONFIDENCE_TEST_PENALTY = float(os.environ.get("CS_TRIAGE_TEST_PENALTY", "20.0"))

# Severity ordering for adjustments
SEVERITY_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]

# Known Exploited Vulnerabilities catalog (simplified KEV check)
KEV_PATTERNS: Dict[str, List[str]] = {
    "SQL Injection": ["CVE-2023-", "CVE-2024-"],
    "XSS": ["CVE-2023-", "CVE-2024-"],
    "Remote Code Execution": ["CVE-2023-", "CVE-2024-"],
    "Command Injection": ["CVE-2023-", "CVE-2024-"],
}

# Context patterns that elevate severity
CRITICAL_CONTEXT_PATTERNS = [
    (r"admin|administrator|management", "admin panel"),
    (r"login|authentication|auth|session", "authentication"),
    (r"payment|billing|checkout|stripe", "payment processing"),
    (r"password_reset|forgot_password|reset", "password reset"),
    (r"api_key|secret|token|credential", "secret handling"),
    (r"sso|oauth|saml|oidc", "identity provider"),
]

# Known false positive patterns
FALSE_POSITIVE_PATTERNS = [
    r"test.*mock|mock.*test",
    r"example\.com|localhost|127\.0\.0\.1",
    r"TODO|FIXME|HACK|XXX.*security",
    r"placeholder.*password|password.*placeholder",
    r"changeme|change_me|YOUR_",
]

# Test file patterns
TEST_FILE_PATTERNS = [
    r"test_", r"_test\.", r"_tests\.", r"tests?/",
    r"spec_", r"_spec\.", r"__tests__", r"__mocks__",
    r"mock_", r"_mock\.", r"fixture", r"conftest",
    r"\.test\.", r"\.spec\.", r"jest", r"cypress",
    r"playwright", r"e2e",
]


class TriageStatus(str, Enum):
    """Final triage status for a finding."""

    CONFIRMED = "confirmed"
    LIKELY_TRUE = "likely_true_positive"
    LIKELY_FALSE = "likely_false_positive"
    UNCERTAIN = "uncertain"
    SUPPRESSED = "suppressed"


@dataclass
class TriagedFinding:
    """A finding after triage processing."""

    vulnerability: Vulnerability
    confidence_score: float = 0.0  # 0-100
    triage_status: TriageStatus = TriageStatus.UNCERTAIN
    original_severity: str = ""
    adjusted_severity: str = ""
    severity_adjustment_reason: str = ""
    duplicate_of: Optional[str] = None
    agent_sources: List[str] = field(default_factory=list)
    chain_ids: List[str] = field(default_factory=list)
    is_reachable: bool = False
    is_exploitable: bool = False
    is_false_positive: bool = False
    context_analysis: Dict[str, Any] = field(default_factory=dict)
    triage_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary representation."""
        return {
            "vulnerability": self.vulnerability.model_dump(),
            "confidence_score": round(self.confidence_score, 2),
            "triage_status": self.triage_status.value,
            "original_severity": self.original_severity,
            "adjusted_severity": self.adjusted_severity,
            "severity_adjustment_reason": self.severity_adjustment_reason,
            "duplicate_of": self.duplicate_of,
            "agent_sources": self.agent_sources,
            "chain_ids": self.chain_ids,
            "is_reachable": self.is_reachable,
            "is_exploitable": self.is_exploitable,
            "is_false_positive": self.is_false_positive,
            "context_analysis": self.context_analysis,
            "triage_metadata": self.triage_metadata,
        }


class TriagerAgent:
    """
    Triager Agent - Intelligent Finding Quality Controller.

    Processes findings from all scanning agents to:
    1. Deduplicate findings (hash-based, semantic, cross-agent)
    2. Score confidence (base + multi-agent agreement + context)
    3. Run AI triage on HIGH/CRITICAL findings
    4. Adjust severity based on reachability and exploitation context

    Compatible with CrewAI agent interfaces.
    """

    def __init__(self, ai_triage_engine: Optional[AITriageEngine] = None) -> None:
        """
        Initialize the Triager Agent.

        Args:
            ai_triage_engine: Optional AI triage engine instance.
        """
        self.ai_triage_engine = ai_triage_engine or AITriageEngine()
        self._semantic_cache: Dict[str, str] = {}
        logger.info("TriagerAgent initialized")

    # ========================================================================
    # A. Deduplication Engine
    # ========================================================================

    @staticmethod
    def _hash_finding(vuln: Vulnerability) -> str:
        """
        Generate a hash key for hash-based deduplication.

        Uses file_path + line_number + category as the dedup key.

        Args:
            vuln: Vulnerability to hash

        Returns:
            MD5 hash string
        """
        key = f"{vuln.file_path}:{vuln.line_number}:{vuln.category}"
        return hashlib.md5(key.encode()).hexdigest()

    @staticmethod
    def _normalized_description(description: str) -> str:
        """
        Normalize a description for semantic comparison.

        Lowercases, removes punctuation, and strips whitespace.

        Args:
            description: Raw description string

        Returns:
            Normalized string
        """
        desc = description.lower()
        desc = re.sub(r"[^a-z0-9\s]", "", desc)
        desc = re.sub(r"\s+", " ", desc).strip()
        return desc

    @staticmethod
    def _jaccard_similarity(str1: str, str2: str) -> float:
        """
        Compute Jaccard similarity between two strings (word-level).

        Args:
            str1: First string
            str2: Second string

        Returns:
            Jaccard similarity coefficient (0.0 - 1.0)
        """
        set1 = set(str1.split())
        set2 = set(str2.split())
        if not set1 or not set2:
            return 0.0
        intersection = set1 & set2
        union = set1 | set2
        return len(intersection) / len(union)

    @staticmethod
    def _levenshtein_distance(s1: str, s2: str) -> int:
        """
        Compute Levenshtein distance between two strings.

        Args:
            s1: First string
            s2: Second string

        Returns:
            Edit distance
        """
        if len(s1) < len(s2):
            return TriagerAgent._levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)

        previous_row = range(len(s2) + 1)
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row

        return previous_row[-1]

    def _semantic_similarity(self, desc1: str, desc2: str) -> float:
        """
        Compute semantic similarity between two descriptions.

        Uses a combination of Jaccard similarity and normalized Levenshtein distance.

        Args:
            desc1: First description
            desc2: Second description

        Returns:
            Similarity score (0.0 - 1.0)
        """
        norm1 = self._normalized_description(desc1)
        norm2 = self._normalized_description(desc2)

        if not norm1 or not norm2:
            return 0.0

        jaccard = self._jaccard_similarity(norm1, norm2)

        # Normalized Levenshtein similarity
        max_len = max(len(norm1), len(norm2))
        if max_len == 0:
            levenshtein_sim = 1.0
        else:
            distance = self._levenshtein_distance(norm1, norm2)
            levenshtein_sim = 1.0 - (distance / max_len)

        # Weighted combination
        return 0.6 * jaccard + 0.4 * levenshtein_sim

    def _deduplicate_hash_based(
        self, findings: List[Vulnerability]
    ) -> Tuple[Dict[str, List[Vulnerability]], List[Vulnerability]]:
        """
        Group findings by hash (file + line + category).

        Args:
            findings: Raw findings from all agents

        Returns:
            Tuple of (hash_groups, unique_findings)
        """
        hash_groups: Dict[str, List[Vulnerability]] = {}

        for finding in findings:
            h = self._hash_finding(finding)
            if h not in hash_groups:
                hash_groups[h] = []
            hash_groups[h].append(finding)

        # Take the best representative from each group
        unique_findings: List[Vulnerability] = []
        for h, group in hash_groups.items():
            best = self._select_best_finding(group)
            unique_findings.append(best)

        logger.info(
            "Hash-based dedup: %d findings -> %d unique (removed %d)",
            len(findings),
            len(unique_findings),
            len(findings) - len(unique_findings),
        )
        return hash_groups, unique_findings

    def _deduplicate_semantic(
        self, findings: List[Vulnerability]
    ) -> List[Vulnerability]:
        """
        Merge findings with semantically similar descriptions.

        Args:
            findings: Hash-deduplicated findings

        Returns:
            Semantically deduplicated findings
        """
        merged: List[Vulnerability] = []
        skip_indices: Set[int] = set()

        for i, finding in enumerate(findings):
            if i in skip_indices:
                continue

            # Find similar findings
            similar_group = [finding]
            for j in range(i + 1, len(findings)):
                if j in skip_indices:
                    continue

                similarity = self._semantic_similarity(
                    finding.description, findings[j].description
                )
                if similarity >= SEMANTIC_DEDUP_THRESHOLD:
                    similar_group.append(findings[j])
                    skip_indices.add(j)

            # Select the best from the similar group
            best = self._select_best_finding(similar_group)
            merged.append(best)

        logger.info(
            "Semantic dedup: %d -> %d findings (merged %d)",
            len(findings),
            len(merged),
            len(findings) - len(merged),
        )
        return merged

    def _deduplicate_cross_agent(
        self,
        hash_groups: Dict[str, List[Vulnerability]],
        findings: List[Vulnerability],
    ) -> Tuple[List[Vulnerability], Dict[str, List[str]]]:
        """
        Process cross-agent duplicates and boost confidence.

        For each finding that appeared from multiple agents, records
        all agent sources and boosts confidence.

        Args:
            hash_groups: Groups from hash-based dedup
            findings: Deduplicated findings

        Returns:
            Tuple of (processed_findings, source_map)
        """
        source_map: Dict[str, List[str]] = {}

        for finding in findings:
            h = self._hash_finding(finding)
            group = hash_groups.get(h, [finding])
            sources = list(set(g.tool_source for g in group))
            source_map[finding.id] = sources

        return findings, source_map

    @staticmethod
    def _select_best_finding(findings: List[Vulnerability]) -> Vulnerability:
        """
        Select the best (most detailed) finding from a group.

        Prioritizes findings with:
        1. Fix suggestion
        2. Code snippet
        3. Highest confidence
        4. Highest severity
        5. Most detailed description

        Args:
            findings: Group of similar findings

        Returns:
            Best finding
        """
        def score(f: Vulnerability) -> int:
            s = 0
            if f.fix_suggestion:
                s += 10
            if f.code_snippet:
                s += 8
            conf_score = {"HIGH": 4, "MEDIUM": 2, "LOW": 0}.get(f.confidence, 0)
            s += conf_score
            sev_score = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 2, "LOW": 1, "INFO": 0}.get(f.severity, 0)
            s += sev_score
            s += min(len(f.description) // 50, 5)  # Up to 5 points for detail
            return s

        return max(findings, key=score)

    # ========================================================================
    # B. Confidence Scoring
    # ========================================================================

    def _compute_base_confidence(self, vuln: Vulnerability) -> float:
        """
        Map confidence string to numeric score.

        Args:
            vuln: Vulnerability

        Returns:
            Base confidence (0-100)
        """
        mapping = {
            "HIGH": 80.0,
            "MEDIUM": 50.0,
            "LOW": 20.0,
        }
        return mapping.get(vuln.confidence.upper(), 50.0)

    def _apply_multi_agent_bonus(
        self, base_score: float, agent_sources: List[str]
    ) -> float:
        """
        Boost confidence when multiple agents agree.

        Args:
            base_score: Base confidence score
            agent_sources: List of agent names that found this

        Returns:
            Adjusted score
        """
        if len(agent_sources) > 1:
            boost = CONFIDENCE_MULTIPLIER_AGREEMENT - 1.0  # 0.20
            return base_score * (1 + boost * (len(agent_sources) - 1))
        return base_score

    def _apply_taint_bonus(self, base_score: float, vuln: Vulnerability) -> float:
        """
        Boost confidence if taint analysis confirms data flow.

        Args:
            base_score: Current confidence score
            vuln: Vulnerability

        Returns:
            Adjusted score
        """
        if vuln.tool_source == "taint_analyzer" or (
            vuln.code_snippet and any(
                pattern in vuln.code_snippet.lower()
                for pattern in ["request.", "input(", "sys.argv", "os.environ"]
            )
        ):
            return base_score + CONFIDENCE_TAINT_BONUS
        return base_score

    def _apply_dast_bonus(self, base_score: float, vuln: Vulnerability) -> float:
        """
        Boost confidence if DAST validated exploitability.

        Args:
            base_score: Current confidence score
            vuln: Vulnerability

        Returns:
            Adjusted score
        """
        if vuln.tool_source == "dast_scanner" or "confirmed" in vuln.description.lower():
            return base_score + CONFIDENCE_DAST_BONUS
        return base_score

    @staticmethod
    def _apply_fp_penalty(base_score: float, vuln: Vulnerability) -> float:
        """
        Reduce confidence for known false positive patterns.

        Args:
            base_score: Current confidence score
            vuln: Vulnerability

        Returns:
            Adjusted score
        """
        combined = f"{vuln.file_path} {vuln.description} {vuln.code_snippet or ''}"
        for pattern in FALSE_POSITIVE_PATTERNS:
            if re.search(pattern, combined, re.IGNORECASE):
                return base_score - CONFIDENCE_FP_PENALTY
        return base_score

    @staticmethod
    def _apply_test_file_penalty(base_score: float, vuln: Vulnerability) -> float:
        """
        Reduce confidence if finding is in a test file.

        Args:
            base_score: Current confidence score
            vuln: Vulnerability

        Returns:
            Adjusted score
        """
        path_lower = vuln.file_path.lower()
        for pattern in TEST_FILE_PATTERNS:
            if re.search(pattern, path_lower):
                return base_score - CONFIDENCE_TEST_PENALTY
        return base_score

    def _compute_confidence_score(
        self, vuln: Vulnerability, agent_sources: List[str]
    ) -> float:
        """
        Compute final confidence score (0-100).

        Pipeline:
        1. Base confidence from scanning tool
        2. +20% if multiple agents agree
        3. +15% if taint analysis confirms data flow
        4. +10% if DAST validates exploitability
        5. -30% if known false positive pattern
        6. -20% if in test file / mock data

        Args:
            vuln: Vulnerability
            agent_sources: List of agent names

        Returns:
            Final confidence score 0-100
        """
        score = self._compute_base_confidence(vuln)
        score = self._apply_multi_agent_bonus(score, agent_sources)
        score = self._apply_taint_bonus(score, vuln)
        score = self._apply_dast_bonus(score, vuln)
        score = self._apply_fp_penalty(score, vuln)
        score = self._apply_test_file_penalty(score, vuln)

        # Clamp to 0-100
        return max(0.0, min(100.0, score))

    # ========================================================================
    # C. AI Triage Integration
    # ========================================================================

    async def _run_ai_triage(
        self, finding: TriagedFinding, source_path: Optional[str] = None
    ) -> TriagedFinding:
        """
        Run AI triage on a finding (focused on HIGH/CRITICAL).

        Args:
            finding: Finding to triage
            source_path: Path to source code

        Returns:
            Updated finding with triage results
        """
        # Only run AI triage on HIGH and CRITICAL findings
        if finding.adjusted_severity not in ("HIGH", "CRITICAL"):
            return finding

        try:
            from utils.ws_manager import ws_manager
            import asyncio
            scan_id = finding.vulnerability.scan_id
            file_name = os.path.basename(finding.vulnerability.file_path)
            asyncio.create_task(
                ws_manager.broadcast_to_scan(
                    scan_id,
                    {
                        "type": "log",
                        "message": f"Triaging vulnerability in {file_name} at line {finding.vulnerability.line_number}...",
                        "level": "info"
                    }
                )
            )
        except Exception:
            pass

        try:
            triaged = await self.ai_triage_engine.triage_vulnerabilities(
                [finding.vulnerability],
                source_path=source_path,
                use_llm=True,
                emit_ws_logs=False,
            )
            if triaged and len(triaged) > 0:
                result = triaged[0]
                finding.vulnerability = result

                # Check for false positive markers
                if "LIKELY FALSE POSITIVE" in result.description:
                    finding.is_false_positive = True
                    finding.triage_status = TriageStatus.LIKELY_FALSE
                    finding.confidence_score *= 0.3  # Significant penalty

                # Extract context analysis
                finding.context_analysis = {
                    "has_validation": self.ai_triage_engine._has_validation(
                        result.code_snippet or ""
                    ),
                    "is_test_file": self.ai_triage_engine._is_test_file(
                        result.file_path
                    ),
                    "is_user_controlled": self.ai_triage_engine._is_user_controlled(
                        result.code_snippet or ""
                    ),
                }

            try:
                from utils.ws_manager import ws_manager
                import asyncio
                scan_id = finding.vulnerability.scan_id
                file_name = os.path.basename(finding.vulnerability.file_path)
                status_text = "LIKELY FALSE POSITIVE" if finding.is_false_positive else "CONFIRMED"
                asyncio.create_task(
                    ws_manager.broadcast_to_scan(
                        scan_id,
                        {
                            "type": "log",
                            "message": f"Completed triage for {file_name} - Status: {status_text}",
                            "level": "success" if not finding.is_false_positive else "warn"
                        }
                    )
                )
            except Exception:
                pass

        except Exception as e:
            logger.warning("AI triage failed for %s: %s", finding.vulnerability.id, e)
            finding.triage_metadata["triage_error"] = str(e)

        return finding

    # ========================================================================
    # D. Severity Adjustment
    # ========================================================================

    @staticmethod
    def _adjust_severity_reachable(
        severity: str, is_reachable: bool
    ) -> Tuple[str, str]:
        """
        Adjust severity upward if vulnerability is reachable.

        Args:
            severity: Current severity
            is_reachable: Whether the vuln is reachable

        Returns:
            Tuple of (adjusted_severity, reason)
        """
        if not is_reachable:
            return severity, ""

        try:
            idx = SEVERITY_ORDER.index(severity.upper())
        except ValueError:
            idx = 1  # Default to LOW

        new_idx = min(len(SEVERITY_ORDER) - 1, idx + 1)
        new_severity = SEVERITY_ORDER[new_idx]

        if new_severity != severity.upper():
            return new_severity, f"Reachable vulnerability (+1 level: {severity} -> {new_severity})"
        return severity, ""

    @staticmethod
    def _adjust_severity_exploitation(
        severity: str, vuln: Vulnerability
    ) -> Tuple[str, str]:
        """
        Set to CRITICAL if KEV (Known Exploited Vulnerability) confirmed.

        Args:
            severity: Current severity
            vuln: Vulnerability

        Returns:
            Tuple of (adjusted_severity, reason)
        """
        # Check for KEV patterns
        combined = f"{vuln.category} {vuln.description} {vuln.cwe_id or ''}"
        for category, patterns in KEV_PATTERNS.items():
            if category in combined:
                for pattern in patterns:
                    if pattern in combined:
                        return "CRITICAL", f"Known Exploited Vulnerability (KEV): {pattern}"

        # Check DAST-confirmed exploitable
        if vuln.tool_source == "dast_scanner" and "confirmed" in vuln.description.lower():
            return "CRITICAL", "DAST confirmed exploitation"

        return severity, ""

    @staticmethod
    def _adjust_severity_context(
        severity: str, vuln: Vulnerability
    ) -> Tuple[str, str]:
        """
        Adjust severity based on context (e.g., auth bypass in admin panel).

        Args:
            severity: Current severity
            vuln: Vulnerability

        Returns:
            Tuple of (adjusted_severity, reason)
        """
        combined = f"{vuln.file_path} {vuln.description} {vuln.code_snippet or ''}".lower()

        for pattern, context_name in CRITICAL_CONTEXT_PATTERNS:
            if re.search(pattern, combined):
                # Auth bypass in sensitive context = CRITICAL
                if vuln.category.lower() in [
                    "authentication bypass",
                    "authorization bypass",
                    "privilege escalation",
                    "session fixation",
                ]:
                    return "CRITICAL", f"Auth bypass in {context_name} context"

                # Injection in sensitive context = +1 level
                if vuln.category.lower() in [
                    "sql injection",
                    "command injection",
                    "code injection",
                    "xss",
                ]:
                    try:
                        idx = SEVERITY_ORDER.index(severity.upper())
                    except ValueError:
                        idx = 1
                    new_idx = min(len(SEVERITY_ORDER) - 1, idx + 1)
                    return SEVERITY_ORDER[new_idx], f"Injection in {context_name} context (+1 level)"

        return severity, ""

    def _adjust_severity(
        self, vuln: Vulnerability, is_reachable: bool = False
    ) -> Tuple[str, str]:
        """
        Run full severity adjustment pipeline.

        Order: exploitation > context > reachability

        Args:
            vuln: Vulnerability
            is_reachable: Whether it's reachable

        Returns:
            Tuple of (final_severity, reason)
        """
        reasons = []
        current = vuln.severity.upper()

        # 1. Exploitation adjustment (strongest)
        new_sev, reason = self._adjust_severity_exploitation(current, vuln)
        if reason:
            reasons.append(reason)
            current = new_sev

        # 2. Context adjustment
        new_sev, reason = self._adjust_severity_context(current, vuln)
        if reason:
            reasons.append(reason)
            current = new_sev

        # 3. Reachability adjustment
        new_sev, reason = self._adjust_severity_reachable(current, is_reachable)
        if reason:
            reasons.append(reason)
            current = new_sev

        return current, "; ".join(reasons) if reasons else "No adjustment"

    # ========================================================================
    # E. Main Pipeline
    # ========================================================================

    async def triage(
        self,
        findings: List[Vulnerability],
        source_path: Optional[str] = None,
        reachability_data: Optional[Dict[str, bool]] = None,
    ) -> List[TriagedFinding]:
        """
        Run the full triage pipeline on all findings.

        Pipeline:
        1. Hash-based deduplication
        2. Semantic deduplication
        3. Cross-agent processing
        4. Confidence scoring
        5. AI triage (HIGH/CRITICAL only)
        6. Severity adjustment

        Args:
            findings: Raw findings from all scanning agents
            source_path: Path to source code for context analysis
            reachability_data: Dict mapping vuln_id -> is_reachable

        Returns:
            List of triaged findings
        """
        if not findings:
            logger.info("No findings to triage")
            return []

        logger.info("TriagerAgent: Processing %d findings", len(findings))
        start_time = datetime.now(timezone.utc)

        # Step 1: Hash-based deduplication
        hash_groups, unique_findings = self._deduplicate_hash_based(findings)

        # Step 2: Semantic deduplication
        deduplicated = self._deduplicate_semantic(unique_findings)

        # Step 3: Cross-agent processing
        processed, source_map = self._deduplicate_cross_agent(
            hash_groups, deduplicated
        )

        # Step 4-6: Process each finding
        triaged_findings: List[TriagedFinding] = []

        for vuln in processed:
            sources = source_map.get(vuln.id, [vuln.tool_source])

            # Compute reachability
            is_reachable = reachability_data.get(vuln.id, False) if reachability_data else False

            # Severity adjustment
            adjusted_severity, sev_reason = self._adjust_severity(vuln, is_reachable)

            # Confidence scoring
            confidence = self._compute_confidence_score(vuln, sources)

            # Create triaged finding
            triaged = TriagedFinding(
                vulnerability=vuln,
                confidence_score=confidence,
                original_severity=vuln.severity,
                adjusted_severity=adjusted_severity,
                severity_adjustment_reason=sev_reason,
                agent_sources=sources,
                is_reachable=is_reachable,
                is_exploitable="confirmed" in vuln.description.lower(),
            )

            # Update vulnerability severity if adjusted
            if adjusted_severity != vuln.severity:
                triaged.vulnerability.severity = adjusted_severity

            triaged_findings.append(triaged)

        # Step 5: AI triage on HIGH/CRITICAL
        triaged_high_critical = [
            f for f in triaged_findings
            if f.adjusted_severity in ("HIGH", "CRITICAL")
            and not f.is_false_positive
        ]

        if triaged_high_critical:
            logger.info(
                "Running AI triage on %d HIGH/CRITICAL findings",
                len(triaged_high_critical),
            )
            tasks = [
                self._run_ai_triage(f, source_path)
                for f in triaged_high_critical
            ]
            await asyncio.gather(*tasks, return_exceptions=True)

        # Set final triage status
        for finding in triaged_findings:
            if finding.is_false_positive:
                finding.triage_status = TriageStatus.LIKELY_FALSE
            elif finding.confidence_score >= 80:
                finding.triage_status = TriageStatus.CONFIRMED
            elif finding.confidence_score >= 50:
                finding.triage_status = TriageStatus.LIKELY_TRUE
            else:
                finding.triage_status = TriageStatus.UNCERTAIN

        # Sort by adjusted severity and confidence
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        triaged_findings.sort(
            key=lambda f: (
                severity_order.get(f.adjusted_severity, 5),
                -f.confidence_score,
            )
        )

        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()
        logger.info(
            "TriagerAgent: Completed in %.2fs - %d findings triaged (%d confirmed, %d likely FP)",
            elapsed,
            len(triaged_findings),
            sum(1 for f in triaged_findings if f.triage_status == TriageStatus.CONFIRMED),
            sum(1 for f in triaged_findings if f.triage_status == TriageStatus.LIKELY_FALSE),
        )

        return triaged_findings

    async def get_stats(self) -> Dict[str, Any]:
        """Get triager agent statistics."""
        return {
            "semantic_dedup_threshold": SEMANTIC_DEDUP_THRESHOLD,
            "confidence_multiplier_agreement": CONFIDENCE_MULTIPLIER_AGREEMENT,
            "confidence_taint_bonus": CONFIDENCE_TAINT_BONUS,
            "confidence_dast_bonus": CONFIDENCE_DAST_BONUS,
            "ai_triage_available": self.ai_triage_engine._openai_client is not None,
        }
