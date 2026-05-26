"""
CodeShield AI - Policy Enforcement & Security Gates Engine.

Implements policy-as-code for security governance:
- YAML-based policy definitions
- Built-in policies for merge blocking, vulnerability limits, CWE blocking
- Custom policy DSL with rules, conditions, and actions
- Policy evaluation: pass/warn/fail with detailed reports
- CI/CD integration: exit codes + SARIF annotations
- Phased enforcement: WARN → ERROR mode transition
- Policy inheritance: org → team → repository
"""

import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

import yaml

from models.vulnerability import ScanResult, Vulnerability
from utils.logger import get_logger

logger = get_logger(__name__)


class PolicySeverity(str, Enum):
    """Severity levels for policy violations."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class PolicyAction(str, Enum):
    """Actions that can be taken when a policy is violated."""

    BLOCK = "block"  # Block merge/build
    WARN = "warn"  # Warning only
    NOTIFY = "notify"  # Send notification
    REQUIRE_REVIEW = "require_review"  # Require manual review
    AUTO_FIX = "auto_fix"  # Attempt automatic fix


class PolicyEnforcementMode(str, Enum):
    """Enforcement mode for policies."""

    WARN = "warn"  # Log violations but don't block
    ERROR = "error"  # Block on violations
    AUDIT = "audit"  # Log only, no notifications


class EvaluationStatus(str, Enum):
    """Overall policy evaluation status."""

    PASSED = "passed"
    WARNED = "warned"
    FAILED = "failed"


# Severity numeric ordering for comparisons
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class PolicyRuleCondition:
    """A single condition within a policy rule."""

    type: str  # e.g., "severity_count", "cwe_match", "secret_detection", "max_risk_score"
    severity: Optional[str] = None  # CRITICAL, HIGH, MEDIUM, LOW
    count: Optional[int] = None  # threshold count
    cwe_ids: List[str] = field(default_factory=list)
    categories: List[str] = field(default_factory=list)
    max_risk_score: Optional[int] = None
    min_risk_score: Optional[int] = None
    tools: List[str] = field(default_factory=list)
    confidence: Optional[str] = None  # HIGH, MEDIUM, LOW
    path_patterns: List[str] = field(default_factory=list)
    inverted: bool = False  # If True, condition passes when criteria are NOT met

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "severity": self.severity,
            "count": self.count,
            "cwe_ids": self.cwe_ids,
            "categories": self.categories,
            "max_risk_score": self.max_risk_score,
            "min_risk_score": self.min_risk_score,
            "tools": self.tools,
            "confidence": self.confidence,
            "path_patterns": self.path_patterns,
            "inverted": self.inverted,
        }


@dataclass
class PolicyRule:
    """A rule within a policy."""

    name: str
    description: str
    conditions: List[PolicyRuleCondition]
    action: PolicyAction = PolicyAction.BLOCK
    severity: PolicySeverity = PolicySeverity.HIGH
    message: str = ""
    enabled: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "description": self.description,
            "conditions": [c.to_dict() for c in self.conditions],
            "action": self.action.value,
            "severity": self.severity.value,
            "message": self.message,
            "enabled": self.enabled,
        }


@dataclass
class PolicyScope:
    """Scope of a policy (org, team, or repository)."""

    level: str  # "organization", "team", "repository"
    organization: Optional[str] = None
    team: Optional[str] = None
    repository: Optional[str] = None
    branch_patterns: List[str] = field(default_factory=lambda: ["*"])

    def matches(self, org: str, team: Optional[str], repo: str, branch: str) -> bool:
        """Check if this scope matches the given context."""
        if self.organization and self.organization != org:
            return False
        if self.team and self.team != team:
            return False
        if self.repository and self.repository != repo:
            return False
        if self.branch_patterns and self.branch_patterns != ["*"]:
            import fnmatch
            if not any(fnmatch.fnmatch(branch, p) for p in self.branch_patterns):
                return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "level": self.level,
            "organization": self.organization,
            "team": self.team,
            "repository": self.repository,
            "branch_patterns": self.branch_patterns,
        }


@dataclass
class SecurityPolicy:
    """A complete security policy definition."""

    id: str = field(default_factory=lambda: str(uuid4())[:8])
    name: str = ""
    description: str = ""
    version: str = "1.0"
    enabled: bool = True
    rules: List[PolicyRule] = field(default_factory=list)
    scope: PolicyScope = field(default_factory=lambda: PolicyScope(level="repository"))
    enforcement_mode: PolicyEnforcementMode = PolicyEnforcementMode.ERROR
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    created_by: str = "system"
    parent_policy_id: Optional[str] = None  # For inheritance
    phased_enforcement: bool = False  # If True, starts in WARN mode
    phase_transition_date: Optional[datetime] = None
    custom_metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "enabled": self.enabled,
            "rules": [r.to_dict() for r in self.rules],
            "scope": self.scope.to_dict(),
            "enforcement_mode": self.enforcement_mode.value,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "created_by": self.created_by,
            "parent_policy_id": self.parent_policy_id,
            "phased_enforcement": self.phased_enforcement,
            "phase_transition_date": (
                self.phase_transition_date.isoformat()
                if self.phase_transition_date
                else None
            ),
            "custom_metadata": self.custom_metadata,
        }


@dataclass
class PolicyViolation:
    """A single policy violation found during evaluation."""

    rule_name: str
    policy_id: str
    policy_name: str
    severity: str
    message: str
    action: str
    affected_files: List[str] = field(default_factory=list)
    vulnerability_count: int = 0
    matched_vulnerabilities: List[str] = field(default_factory=list)
    suggested_fix: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_name": self.rule_name,
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "severity": self.severity,
            "message": self.message,
            "action": self.action,
            "affected_files": self.affected_files,
            "vulnerability_count": self.vulnerability_count,
            "matched_vulnerabilities": self.matched_vulnerabilities,
            "suggested_fix": self.suggested_fix,
        }


@dataclass
class PolicyEvaluationReport:
    """Complete report from a policy evaluation."""

    scan_id: str
    overall_status: EvaluationStatus
    exit_code: int  # 0 = passed, 1 = warned, 2 = failed
    policies_evaluated: int = 0
    rules_evaluated: int = 0
    rules_passed: int = 0
    rules_warned: int = 0
    rules_failed: int = 0
    violations: List[PolicyViolation] = field(default_factory=list)
    passed_rules: List[str] = field(default_factory=list)
    summary: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evaluation_duration_ms: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "overall_status": self.overall_status.value,
            "exit_code": self.exit_code,
            "policies_evaluated": self.policies_evaluated,
            "rules_evaluated": self.rules_evaluated,
            "rules_passed": self.rules_passed,
            "rules_warned": self.rules_warned,
            "rules_failed": self.rules_failed,
            "violations": [v.to_dict() for v in self.violations],
            "passed_rules": self.passed_rules,
            "summary": self.summary,
            "timestamp": self.timestamp.isoformat(),
            "evaluation_duration_ms": self.evaluation_duration_ms,
        }


class PolicyEngine:
    """
    Policy enforcement engine for CodeShield AI.

    Evaluates security policies against scan results and produces
    pass/warn/fail determinations with detailed violation reports.
    """

    # SQL injection related CWEs
    SQL_INJECTION_CWES = ["CWE-89", "CWE-564", "CWE-943"]
    # XSS related CWEs
    XSS_CWES = ["CWE-79", "CWE-80", "CWE-87"]
    # Secret/Credential related CWEs
    SECRET_CWES = ["CWE-798", "CWE-259", "CWE-312", "CWE-522"]

    def __init__(self) -> None:
        """Initialize the policy engine with built-in policies."""
        self.policies: Dict[str, SecurityPolicy] = {}
        self._init_built_in_policies()

    def _init_built_in_policies(self) -> None:
        """Create the default built-in security policies."""
        built_ins = [
            self._create_block_critical_policy(),
            self._create_block_high_count_policy(),
            self._create_require_secret_review_policy(),
            self._create_require_scan_policy(),
            self._create_max_vulnerability_policy(),
            self._create_block_sql_injection_policy(),
        ]
        for policy in built_ins:
            self.policies[policy.id] = policy

    def _create_block_critical_policy(self) -> SecurityPolicy:
        """Block merge on any CRITICAL vulnerabilities."""
        return SecurityPolicy(
            id="builtin-block-critical",
            name="Block on Critical Vulnerabilities",
            description="Blocks merging/pipeline when any CRITICAL vulnerabilities are found",
            rules=[
                PolicyRule(
                    name="block_critical",
                    description="Block when CRITICAL vulnerabilities are detected",
                    conditions=[
                        PolicyRuleCondition(
                            type="severity_count",
                            severity="CRITICAL",
                            count=1,
                        )
                    ],
                    action=PolicyAction.BLOCK,
                    severity=PolicySeverity.CRITICAL,
                    message="CRITICAL vulnerabilities found. Immediate remediation required before merge.",
                )
            ],
            scope=PolicyScope(level="repository"),
            enforcement_mode=PolicyEnforcementMode.ERROR,
        )

    def _create_block_high_count_policy(self) -> SecurityPolicy:
        """Block merge when HIGH vulnerabilities exceed threshold."""
        return SecurityPolicy(
            id="builtin-block-high-count",
            name="Block on High Vulnerability Count",
            description="Blocks merging/pipeline when HIGH vulnerabilities exceed the threshold",
            rules=[
                PolicyRule(
                    name="block_high_count",
                    description="Block when more than 5 HIGH vulnerabilities are found",
                    conditions=[
                        PolicyRuleCondition(
                            type="severity_count",
                            severity="HIGH",
                            count=5,
                        )
                    ],
                    action=PolicyAction.BLOCK,
                    severity=PolicySeverity.HIGH,
                    message="More than 5 HIGH severity vulnerabilities found. Address before merge.",
                )
            ],
            scope=PolicyScope(level="repository"),
            enforcement_mode=PolicyEnforcementMode.ERROR,
        )

    def _create_require_secret_review_policy(self) -> SecurityPolicy:
        """Require review when secrets are detected."""
        return SecurityPolicy(
            id="builtin-require-secret-review",
            name="Require Review for Secrets",
            description="Requires manual review when secrets or credentials are detected",
            rules=[
                PolicyRule(
                    name="require_secret_review",
                    description="Flag for review when hardcoded secrets are found",
                    conditions=[
                        PolicyRuleCondition(
                            type="cwe_match",
                            cwe_ids=self.SECRET_CWES,
                        )
                    ],
                    action=PolicyAction.REQUIRE_REVIEW,
                    severity=PolicySeverity.HIGH,
                    message="Hardcoded secrets detected. Manual review required.",
                )
            ],
            scope=PolicyScope(level="repository"),
            enforcement_mode=PolicyEnforcementMode.WARN,
        )

    def _create_require_scan_policy(self) -> SecurityPolicy:
        """Require security scan before merge."""
        return SecurityPolicy(
            id="builtin-require-scan",
            name="Require Security Scan",
            description="Ensures a security scan has been performed before merging",
            rules=[
                PolicyRule(
                    name="require_scan",
                    description="Verify scan has been completed",
                    conditions=[
                        PolicyRuleCondition(
                            type="scan_completed",
                        )
                    ],
                    action=PolicyAction.BLOCK,
                    severity=PolicySeverity.HIGH,
                    message="No security scan found. Run a scan before merging.",
                )
            ],
            scope=PolicyScope(level="repository"),
            enforcement_mode=PolicyEnforcementMode.ERROR,
        )

    def _create_max_vulnerability_policy(self) -> SecurityPolicy:
        """Maximum vulnerability count per severity level."""
        return SecurityPolicy(
            id="builtin-max-vulnerabilities",
            name="Maximum Vulnerability Counts",
            description="Enforces maximum allowed vulnerabilities per severity level",
            rules=[
                PolicyRule(
                    name="max_critical",
                    description="Maximum 0 CRITICAL vulnerabilities allowed",
                    conditions=[
                        PolicyRuleCondition(
                            type="severity_count",
                            severity="CRITICAL",
                            count=0,
                        )
                    ],
                    action=PolicyAction.BLOCK,
                    severity=PolicySeverity.CRITICAL,
                    message="CRITICAL vulnerabilities must be 0 before merge.",
                ),
                PolicyRule(
                    name="max_high",
                    description="Maximum 3 HIGH vulnerabilities allowed",
                    conditions=[
                        PolicyRuleCondition(
                            type="severity_count",
                            severity="HIGH",
                            count=3,
                        )
                    ],
                    action=PolicyAction.BLOCK,
                    severity=PolicySeverity.HIGH,
                    message="HIGH vulnerabilities must not exceed 3.",
                ),
                PolicyRule(
                    name="max_medium",
                    description="Warn when more than 10 MEDIUM vulnerabilities",
                    conditions=[
                        PolicyRuleCondition(
                            type="severity_count",
                            severity="MEDIUM",
                            count=10,
                        )
                    ],
                    action=PolicyAction.WARN,
                    severity=PolicySeverity.MEDIUM,
                    message="More than 10 MEDIUM vulnerabilities. Consider addressing before merge.",
                ),
            ],
            scope=PolicyScope(level="repository"),
            enforcement_mode=PolicyEnforcementMode.ERROR,
        )

    def _create_block_sql_injection_policy(self) -> SecurityPolicy:
        """Block all SQL injection vulnerabilities."""
        return SecurityPolicy(
            id="builtin-block-sql-injection",
            name="Block SQL Injection",
            description="Blocks merging/pipeline when SQL injection vulnerabilities are detected",
            rules=[
                PolicyRule(
                    name="block_sql_injection",
                    description="Block when SQL injection (CWE-89) is detected",
                    conditions=[
                        PolicyRuleCondition(
                            type="cwe_match",
                            cwe_ids=self.SQL_INJECTION_CWES,
                        )
                    ],
                    action=PolicyAction.BLOCK,
                    severity=PolicySeverity.CRITICAL,
                    message="SQL injection vulnerability detected. This is a critical security issue.",
                )
            ],
            scope=PolicyScope(level="repository"),
            enforcement_mode=PolicyEnforcementMode.ERROR,
        )

    def create_policy(self, policy: SecurityPolicy) -> str:
        """
        Create a new custom policy.

        Args:
            policy: The security policy to create

        Returns:
            Policy ID
        """
        if not policy.id:
            policy.id = str(uuid4())[:8]
        policy.created_at = datetime.now(timezone.utc)
        policy.updated_at = datetime.now(timezone.utc)
        self.policies[policy.id] = policy
        logger.info("Created policy: %s (%s)", policy.name, policy.id)
        return policy.id

    def update_policy(self, policy_id: str, updates: Dict[str, Any]) -> Optional[SecurityPolicy]:
        """
        Update an existing policy.

        Args:
            policy_id: ID of the policy to update
            updates: Dictionary of fields to update

        Returns:
            Updated policy or None if not found
        """
        if policy_id not in self.policies:
            return None

        policy = self.policies[policy_id]
        if "name" in updates:
            policy.name = updates["name"]
        if "description" in updates:
            policy.description = updates["description"]
        if "enabled" in updates:
            policy.enabled = updates["enabled"]
        if "enforcement_mode" in updates:
            policy.enforcement_mode = PolicyEnforcementMode(updates["enforcement_mode"])
        if "rules" in updates:
            policy.rules = [PolicyRule(**r) for r in updates["rules"]]
        if "phased_enforcement" in updates:
            policy.phased_enforcement = updates["phased_enforcement"]
        if "phase_transition_date" in updates:
            policy.phase_transition_date = datetime.fromisoformat(
                updates["phase_transition_date"]
            )

        policy.updated_at = datetime.now(timezone.utc)
        logger.info("Updated policy: %s", policy_id)
        return policy

    def delete_policy(self, policy_id: str) -> bool:
        """
        Delete a policy.

        Args:
            policy_id: ID of the policy to delete

        Returns:
            True if deleted, False if not found
        """
        if policy_id not in self.policies:
            return False
        del self.policies[policy_id]
        logger.info("Deleted policy: %s", policy_id)
        return True

    def get_policy(self, policy_id: str) -> Optional[SecurityPolicy]:
        """Get a policy by ID."""
        return self.policies.get(policy_id)

    def list_policies(
        self,
        enabled_only: bool = False,
        scope_level: Optional[str] = None,
    ) -> List[SecurityPolicy]:
        """
        List all policies with optional filtering.

        Args:
            enabled_only: Only return enabled policies
            scope_level: Filter by scope level

        Returns:
            List of policies
        """
        policies = list(self.policies.values())
        if enabled_only:
            policies = [p for p in policies if p.enabled]
        if scope_level:
            policies = [p for p in policies if p.scope.level == scope_level]
        return policies

    def evaluate_scan(
        self,
        scan_result: ScanResult,
        context: Optional[Dict[str, str]] = None,
    ) -> PolicyEvaluationReport:
        """
        Evaluate all applicable policies against a scan result.

        Args:
            scan_result: The scan result to evaluate
            context: Optional evaluation context (org, team, repo, branch)

        Returns:
            PolicyEvaluationReport with full evaluation results
        """
        import time
        start_time = time.time()

        context = context or {}
        org = context.get("organization", "")
        team = context.get("team")
        repo = context.get("repository", "")
        branch = context.get("branch", "main")

        report = PolicyEvaluationReport(scan_id=scan_result.scan_id, overall_status=EvaluationStatus.PASSED, exit_code=0)
        violations: List[PolicyViolation] = []
        passed_rules_list: List[str] = []

        enabled_policies = [p for p in self.policies.values() if p.enabled]
        report.policies_evaluated = len(enabled_policies)

        for policy in enabled_policies:
            # Check scope match
            if not policy.scope.matches(org, team, repo, branch):
                continue

            # Determine effective enforcement mode
            effective_mode = policy.enforcement_mode
            if policy.phased_enforcement:
                effective_mode = self._get_phased_enforcement_mode(policy)

            for rule in policy.rules:
                if not rule.enabled:
                    continue

                report.rules_evaluated += 1
                condition_met, matched_vulns = self._evaluate_rule_conditions(
                    rule, scan_result
                )

                if condition_met:
                    # Violation found
                    affected_files = list(
                        set(v.file_path for v in matched_vulns)
                    )

                    violation = PolicyViolation(
                        rule_name=rule.name,
                        policy_id=policy.id,
                        policy_name=policy.name,
                        severity=rule.severity.value,
                        message=rule.message or f"Policy rule '{rule.name}' violated",
                        action=rule.action.value,
                        affected_files=affected_files,
                        vulnerability_count=len(matched_vulns),
                        matched_vulnerabilities=[v.id for v in matched_vulns],
                        suggested_fix=self._generate_suggested_fix(rule, matched_vulns),
                    )
                    violations.append(violation)

                    if effective_mode == PolicyEnforcementMode.ERROR:
                        report.rules_failed += 1
                    elif effective_mode == PolicyEnforcementMode.WARN:
                        report.rules_warned += 1
                else:
                    report.rules_passed += 1
                    passed_rules_list.append(f"{policy.name}/{rule.name}")

        report.violations = violations
        report.passed_rules = passed_rules_list
        report.evaluation_duration_ms = int((time.time() - start_time) * 1000)

        # Determine overall status
        if report.rules_failed > 0:
            report.overall_status = EvaluationStatus.FAILED
            report.exit_code = 2
        elif report.rules_warned > 0:
            report.overall_status = EvaluationStatus.WARNED
            report.exit_code = 1
        else:
            report.overall_status = EvaluationStatus.PASSED
            report.exit_code = 0

        # Build summary
        report.summary = {
            "total_vulnerabilities": len(scan_result.vulnerabilities),
            "severity_breakdown": {
                "critical": scan_result.stats.get("critical", 0),
                "high": scan_result.stats.get("high", 0),
                "medium": scan_result.stats.get("medium", 0),
                "low": scan_result.stats.get("low", 0),
            },
            "violations_by_severity": self._count_violations_by_severity(violations),
            "blocking_violations": sum(
                1 for v in violations if v.action == PolicyAction.BLOCK.value
            ),
            "review_required": sum(
                1 for v in violations if v.action == PolicyAction.REQUIRE_REVIEW.value
            ),
            "phased_policies": [
                p.id for p in enabled_policies if p.phased_enforcement
            ],
        }

        logger.info(
            "Policy evaluation for scan %s: status=%s, violations=%d, duration=%dms",
            scan_result.scan_id,
            report.overall_status.value,
            len(violations),
            report.evaluation_duration_ms,
        )

        return report

    def _evaluate_rule_conditions(
        self, rule: PolicyRule, scan_result: ScanResult
    ) -> Tuple[bool, List[Vulnerability]]:
        """
        Evaluate all conditions in a rule.

        Args:
            rule: Policy rule to evaluate
            scan_result: Scan result to check against

        Returns:
            Tuple of (all_conditions_met, matched_vulnerabilities)
        """
        all_matched: List[Vulnerability] = []

        for condition in rule.conditions:
            matched = self._evaluate_condition(condition, scan_result)

            if condition.inverted:
                matched = not matched

            if not matched:
                return False, []

        return True, all_matched if all_matched else scan_result.vulnerabilities

    def _evaluate_condition(
        self, condition: PolicyRuleCondition, scan_result: ScanResult
    ) -> bool:
        """Evaluate a single condition against a scan result."""
        vulns = scan_result.vulnerabilities

        if condition.type == "severity_count":
            severity = condition.severity or "HIGH"
            threshold = condition.count or 1
            count = sum(
                1 for v in vulns if v.severity.upper() == severity.upper()
            )
            return count >= threshold

        elif condition.type == "cwe_match":
            target_cwes = set(condition.cwe_ids)
            matched = [
                v for v in vulns if v.cwe_id and v.cwe_id.upper() in target_cwes
            ]
            return len(matched) > 0

        elif condition.type == "category_match":
            target_categories = set(c.lower() for c in condition.categories)
            matched = [
                v
                for v in vulns
                if v.category.lower() in target_categories
            ]
            return len(matched) > 0

        elif condition.type == "max_risk_score":
            max_score = condition.max_risk_score or 100
            return scan_result.risk_score <= max_score

        elif condition.type == "min_risk_score":
            min_score = condition.min_risk_score or 0
            return scan_result.risk_score >= min_score

        elif condition.type == "secret_detection":
            secret_keywords = ["secret", "password", "token", "api key", "credential"]
            matched = [
                v
                for v in vulns
                if any(kw in v.category.lower() for kw in secret_keywords)
            ]
            return len(matched) > 0

        elif condition.type == "scan_completed":
            return scan_result.status == "completed"

        elif condition.type == "tool_match":
            target_tools = set(t.lower() for t in condition.tools)
            matched = [
                v for v in vulns if v.tool_source.lower() in target_tools
            ]
            return len(matched) > 0

        elif condition.type == "path_pattern":
            patterns = condition.path_patterns
            matched = [
                v
                for v in vulns
                if any(re.search(p, v.file_path) for p in patterns)
            ]
            return len(matched) > 0

        return False

    def _get_phased_enforcement_mode(
        self, policy: SecurityPolicy
    ) -> PolicyEnforcementMode:
        """Determine effective enforcement mode for phased policies."""
        if not policy.phased_enforcement:
            return policy.enforcement_mode

        if policy.phase_transition_date:
            if datetime.now(timezone.utc) >= policy.phase_transition_date:
                return PolicyEnforcementMode.ERROR
        return PolicyEnforcementMode.WARN

    @staticmethod
    def _generate_suggested_fix(
        rule: PolicyRule, matched_vulns: List[Vulnerability]
    ) -> str:
        """Generate a suggested fix message for a violation."""
        fixes = []
        for v in matched_vulns[:3]:  # Top 3
            if v.fix_suggestion:
                fixes.append(f"- {v.file_path}:{v.line_number}: {v.fix_suggestion}")
        return "\n".join(fixes) if fixes else "Review matched vulnerabilities and apply appropriate fixes."

    @staticmethod
    def _count_violations_by_severity(
        violations: List[PolicyViolation],
    ) -> Dict[str, int]:
        """Count violations by severity."""
        counts: Dict[str, int] = {}
        for v in violations:
            counts[v.severity] = counts.get(v.severity, 0) + 1
        return counts

    def evaluate_policy_file(
        self,
        policy_file_path: str,
        scan_result: ScanResult,
        context: Optional[Dict[str, str]] = None,
    ) -> PolicyEvaluationReport:
        """
        Evaluate a policy defined in a YAML file.

        Args:
            policy_file_path: Path to the YAML policy file
            scan_result: Scan result to evaluate
            context: Optional evaluation context

        Returns:
            PolicyEvaluationReport
        """
        policy = self.load_policy_from_file(policy_file_path)
        if not policy:
            report = PolicyEvaluationReport(
                scan_id=scan_result.scan_id,
                overall_status=EvaluationStatus.PASSED,
                exit_code=0,
            )
            report.summary = {"error": "Failed to load policy file"}
            return report

        # Temporarily add to policies and evaluate
        self.policies[policy.id] = policy
        return self.evaluate_scan(scan_result, context)

    def load_policy_from_file(self, file_path: str) -> Optional[SecurityPolicy]:
        """
        Load a policy from a YAML file.

        Args:
            file_path: Path to YAML file

        Returns:
            SecurityPolicy or None if loading fails
        """
        try:
            with open(file_path, "r") as f:
                data = yaml.safe_load(f)
            return self._policy_from_dict(data)
        except Exception as e:
            logger.error("Failed to load policy from %s: %s", file_path, e)
            return None

    def _policy_from_dict(self, data: Dict[str, Any]) -> SecurityPolicy:
        """Convert a dictionary to a SecurityPolicy."""
        scope_data = data.get("scope", {"level": "repository"})
        scope = PolicyScope(
            level=scope_data.get("level", "repository"),
            organization=scope_data.get("organization"),
            team=scope_data.get("team"),
            repository=scope_data.get("repository"),
            branch_patterns=scope_data.get("branch_patterns", ["*"]),
        )

        rules = []
        for rule_data in data.get("rules", []):
            conditions = []
            for cond_data in rule_data.get("conditions", []):
                conditions.append(
                    PolicyRuleCondition(
                        type=cond_data.get("type", ""),
                        severity=cond_data.get("severity"),
                        count=cond_data.get("count"),
                        cwe_ids=cond_data.get("cwe_ids", []),
                        categories=cond_data.get("categories", []),
                        max_risk_score=cond_data.get("max_risk_score"),
                        min_risk_score=cond_data.get("min_risk_score"),
                        tools=cond_data.get("tools", []),
                        confidence=cond_data.get("confidence"),
                        path_patterns=cond_data.get("path_patterns", []),
                        inverted=cond_data.get("inverted", False),
                    )
                )

            rules.append(
                PolicyRule(
                    name=rule_data.get("name", ""),
                    description=rule_data.get("description", ""),
                    conditions=conditions,
                    action=PolicyAction(rule_data.get("action", "block")),
                    severity=PolicySeverity(rule_data.get("severity", "HIGH")),
                    message=rule_data.get("message", ""),
                    enabled=rule_data.get("enabled", True),
                )
            )

        return SecurityPolicy(
            id=data.get("id", str(uuid4())[:8]),
            name=data.get("name", ""),
            description=data.get("description", ""),
            version=data.get("version", "1.0"),
            enabled=data.get("enabled", True),
            rules=rules,
            scope=scope,
            enforcement_mode=PolicyEnforcementMode(
                data.get("enforcement_mode", "error")
            ),
            phased_enforcement=data.get("phased_enforcement", False),
            phase_transition_date=(
                datetime.fromisoformat(data["phase_transition_date"])
                if data.get("phase_transition_date")
                else None
            ),
            parent_policy_id=data.get("parent_policy_id"),
            custom_metadata=data.get("custom_metadata", {}),
        )

    def generate_policy_yaml_template(self) -> str:
        """Generate a sample policy YAML file."""
        template = {
            "name": "Custom Security Policy",
            "description": "Define custom security rules for your repository",
            "version": "1.0",
            "enabled": True,
            "scope": {
                "level": "repository",
                "organization": "my-org",
                "repository": "my-repo",
                "branch_patterns": ["main", "release/*"],
            },
            "enforcement_mode": "error",
            "phased_enforcement": False,
            "rules": [
                {
                    "name": "no_secrets_in_production_code",
                    "description": "Block hardcoded secrets in production files",
                    "conditions": [
                        {
                            "type": "cwe_match",
                            "cwe_ids": ["CWE-798", "CWE-259"],
                        },
                        {
                            "type": "path_pattern",
                            "path_patterns": ["^(?!.*test.*$).*"],
                        },
                    ],
                    "action": "block",
                    "severity": "CRITICAL",
                    "message": "Secrets found in production code",
                    "enabled": True,
                },
                {
                    "name": "max_risk_score",
                    "description": "Block if risk score exceeds threshold",
                    "conditions": [
                        {
                            "type": "min_risk_score",
                            "min_risk_score": 75,
                        }
                    ],
                    "action": "block",
                    "severity": "HIGH",
                    "message": "Risk score exceeds maximum threshold",
                    "enabled": True,
                },
            ],
        }
        return yaml.dump(template, default_flow_style=False, sort_keys=False)

    def to_sarif_annotations(self, report: PolicyEvaluationReport) -> List[Dict[str, Any]]:
        """
        Convert policy violations to SARIF annotation format.

        Args:
            report: Policy evaluation report

        Returns:
            List of SARIF annotation dictionaries
        """
        annotations = []
        for violation in report.violations:
            for file_path in violation.affected_files:
                annotations.append({
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path},
                    },
                    "message": {
                        "text": f"[{violation.severity}] {violation.message} (Policy: {violation.policy_name})",
                    },
                    "level": "error" if violation.action == "block" else "warning",
                })
        return annotations
