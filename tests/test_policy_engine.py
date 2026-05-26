"""
Tests for the Policy Enforcement Engine.

Covers policy creation, evaluation, built-in policies, and YAML loading.
"""

import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from models.vulnerability import ScanResult, ScanStats, Vulnerability
from policy_engine import (
    PolicyAction,
    PolicyEnforcementMode,
    PolicyEngine,
    PolicyEvaluationReport,
    PolicyRule,
    PolicyRuleCondition,
    PolicyScope,
    PolicySeverity,
    SecurityPolicy,
    EvaluationStatus,
)


# =============================================================================
# Fixtures
# =============================================================================

@pytest.fixture
def policy_engine():
    """Create a fresh policy engine."""
    return PolicyEngine()


@pytest.fixture
def sample_scan_no_vulns():
    """Create a sample scan with no vulnerabilities."""
    return ScanResult(
        scan_id="test-scan-001",
        name="Test Scan",
        source_type="zip",
        source_path="/tmp/test",
        status="completed",
        stats={"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        risk_score=0,
    )


@pytest.fixture
def sample_scan_with_vulns():
    """Create a sample scan with vulnerabilities."""
    vulns = [
        Vulnerability(
            scan_id="test-scan-002",
            file_path="src/app.py",
            line_number=42,
            severity="CRITICAL",
            category="SQL Injection",
            cwe_id="CWE-89",
            title="SQL Injection",
            description="SQL injection in user input",
            fix_suggestion="Use parameterized queries",
            tool_source="bandit",
            confidence="HIGH",
        ),
        Vulnerability(
            scan_id="test-scan-002",
            file_path="src/auth.py",
            line_number=15,
            severity="HIGH",
            category="Hardcoded Password",
            cwe_id="CWE-798",
            title="Hardcoded password",
            description="Password found in source code",
            fix_suggestion="Use environment variables",
            tool_source="custom_ai",
            confidence="HIGH",
        ),
        Vulnerability(
            scan_id="test-scan-002",
            file_path="src/utils.py",
            line_number=30,
            severity="MEDIUM",
            category="Weak Cryptography",
            cwe_id="CWE-328",
            title="Weak MD5 hash",
            description="Using MD5 for hashing",
            fix_suggestion="Use SHA-256",
            tool_source="bandit",
            confidence="HIGH",
        ),
        Vulnerability(
            scan_id="test-scan-002",
            file_path="src/main.py",
            line_number=100,
            severity="HIGH",
            category="SQL Injection",
            cwe_id="CWE-89",
            title="Another SQL Injection",
            description="Unparameterized query",
            fix_suggestion="Use parameterized queries",
            tool_source="semgrep",
            confidence="MEDIUM",
        ),
    ]

    return ScanResult(
        scan_id="test-scan-002",
        name="Vulnerable Scan",
        source_type="zip",
        source_path="/tmp/test",
        status="completed",
        stats={"total": 4, "critical": 1, "high": 2, "medium": 1, "low": 0, "info": 0},
        risk_score=45,
        vulnerabilities=vulns,
    )


@pytest.fixture
def sample_scan_high_risk():
    """Create a scan with many HIGH vulnerabilities."""
    vulns = [
        Vulnerability(
            scan_id="test-scan-003",
            file_path=f"src/app{i}.py",
            line_number=i,
            severity="HIGH",
            category="Hardcoded Secret",
            cwe_id="CWE-798",
            title=f"Secret {i}",
            description="Hardcoded API key",
            tool_source="gitleaks",
            confidence="HIGH",
        )
        for i in range(10)
    ]

    return ScanResult(
        scan_id="test-scan-003",
        name="High Risk Scan",
        source_type="zip",
        source_path="/tmp/test",
        status="completed",
        stats={"total": 10, "critical": 0, "high": 10, "medium": 0, "low": 0, "info": 0},
        risk_score=100,
        vulnerabilities=vulns,
    )


# =============================================================================
# Built-in Policy Tests
# =============================================================================

class TestBuiltInPolicies:
    """Tests for built-in security policies."""

    def test_block_critical_policy_exists(self, policy_engine):
        """Test that block critical policy exists."""
        policy = policy_engine.get_policy("builtin-block-critical")
        assert policy is not None
        assert policy.name == "Block on Critical Vulnerabilities"
        assert policy.enforcement_mode == PolicyEnforcementMode.ERROR

    def test_block_high_count_policy_exists(self, policy_engine):
        """Test that high count policy exists."""
        policy = policy_engine.get_policy("builtin-block-high-count")
        assert policy is not None
        assert "High Vulnerability Count" in policy.name

    def test_require_secret_review_exists(self, policy_engine):
        """Test that secret review policy exists."""
        policy = policy_engine.get_policy("builtin-require-secret-review")
        assert policy is not None

    def test_max_vulnerability_policy_exists(self, policy_engine):
        """Test that max vulnerability policy exists."""
        policy = policy_engine.get_policy("builtin-max-vulnerabilities")
        assert policy is not None

    def test_block_sql_injection_exists(self, policy_engine):
        """Test that SQL injection policy exists."""
        policy = policy_engine.get_policy("builtin-block-sql-injection")
        assert policy is not None

    def test_builtin_policies_have_rules(self, policy_engine):
        """Test that all built-in policies have at least one rule."""
        for policy in policy_engine.list_policies():
            if policy.id.startswith("builtin-"):
                assert len(policy.rules) > 0
                for rule in policy.rules:
                    assert rule.name
                    assert len(rule.conditions) > 0


# =============================================================================
# Policy Evaluation Tests
# =============================================================================

class TestPolicyEvaluation:
    """Tests for policy evaluation logic."""

    def test_evaluate_clean_scan(self, policy_engine, sample_scan_no_vulns):
        """Test evaluation of a scan with no vulnerabilities."""
        report = policy_engine.evaluate_scan(sample_scan_no_vulns)

        assert report.overall_status == EvaluationStatus.PASSED
        assert report.exit_code == 0
        assert len(report.violations) == 0

    def test_evaluate_scan_with_critical(self, policy_engine, sample_scan_with_vulns):
        """Test evaluation detects CRITICAL vulnerability."""
        report = policy_engine.evaluate_scan(sample_scan_with_vulns)

        assert report.overall_status == EvaluationStatus.FAILED
        assert report.exit_code == 2
        assert len(report.violations) > 0

        # Check that critical violation is present
        critical_violations = [
            v for v in report.violations if v.severity == "CRITICAL"
        ]
        assert len(critical_violations) > 0

    def test_evaluate_high_count_threshold(self, policy_engine, sample_scan_high_risk):
        """Test high count threshold policy triggers."""
        report = policy_engine.evaluate_scan(sample_scan_high_risk)

        # Should fail because there are 10 HIGH vulnerabilities (>5 threshold)
        assert report.overall_status == EvaluationStatus.FAILED
        assert report.exit_code == 2

        high_count_violations = [
            v for v in report.violations if "high_count" in v.rule_name
        ]
        assert len(high_count_violations) > 0

    def test_sql_injection_blocking(self, policy_engine, sample_scan_with_vulns):
        """Test SQL injection policy blocks."""
        report = policy_engine.evaluate_scan(sample_scan_with_vulns)

        sql_violations = [
            v for v in report.violations if "sql" in v.rule_name.lower()
        ]
        assert len(sql_violations) > 0

    def test_evaluation_summary(self, policy_engine, sample_scan_with_vulns):
        """Test evaluation summary is populated."""
        report = policy_engine.evaluate_scan(sample_scan_with_vulns)

        assert "total_vulnerabilities" in report.summary
        assert "severity_breakdown" in report.summary
        assert "blocking_violations" in report.summary

    def test_evaluation_with_context(self, policy_engine, sample_scan_with_vulns):
        """Test evaluation with context filtering."""
        context = {
            "organization": "test-org",
            "repository": "wrong-repo",
        }
        report = policy_engine.evaluate_scan(sample_scan_with_vulns, context)

        # Should pass because scope doesn't match
        assert report.overall_status == EvaluationStatus.PASSED


# =============================================================================
# Policy CRUD Tests
# =============================================================================

class TestPolicyCRUD:
    """Tests for policy create, read, update, delete."""

    def test_create_policy(self, policy_engine):
        """Test creating a custom policy."""
        policy = SecurityPolicy(
            name="Test Policy",
            description="A test policy",
            rules=[
                PolicyRule(
                    name="test_rule",
                    description="Test rule",
                    conditions=[
                        PolicyRuleCondition(
                            type="severity_count",
                            severity="HIGH",
                            count=3,
                        )
                    ],
                    action=PolicyAction.BLOCK,
                )
            ],
            scope=PolicyScope(level="repository"),
        )

        policy_id = policy_engine.create_policy(policy)
        assert policy_id

        retrieved = policy_engine.get_policy(policy_id)
        assert retrieved is not None
        assert retrieved.name == "Test Policy"

    def test_update_policy(self, policy_engine):
        """Test updating a policy."""
        policy = SecurityPolicy(
            name="Update Test",
            rules=[],
            scope=PolicyScope(level="repository"),
        )
        policy_id = policy_engine.create_policy(policy)

        updated = policy_engine.update_policy(
            policy_id, {"name": "Updated Name", "enabled": False}
        )
        assert updated is not None
        assert updated.name == "Updated Name"
        assert updated.enabled is False

    def test_delete_policy(self, policy_engine):
        """Test deleting a policy."""
        policy = SecurityPolicy(
            name="Delete Test",
            rules=[],
            scope=PolicyScope(level="repository"),
        )
        policy_id = policy_engine.create_policy(policy)
        assert policy_engine.get_policy(policy_id) is not None

        deleted = policy_engine.delete_policy(policy_id)
        assert deleted is True
        assert policy_engine.get_policy(policy_id) is None

    def test_cannot_delete_builtin(self, policy_engine):
        """Test that built-in policies cannot be deleted."""
        deleted = policy_engine.delete_policy("builtin-block-critical")
        assert deleted is False  # or should return True but we prevent it at API level
        # Built-in policies may or may not be deletable depending on implementation

    def test_list_policies(self, policy_engine):
        """Test listing policies."""
        policies = policy_engine.list_policies()
        assert len(policies) >= 6  # At least built-in policies

        enabled_only = policy_engine.list_policies(enabled_only=True)
        assert len(enabled_only) >= 6

    def test_list_policies_by_scope(self, policy_engine):
        """Test filtering policies by scope."""
        policies = policy_engine.list_policies(scope_level="repository")
        assert len(policies) >= 6


# =============================================================================
# Policy Scope Tests
# =============================================================================

class TestPolicyScope:
    """Tests for policy scope matching."""

    def test_scope_matches_all(self):
        """Test wildcard scope matching."""
        scope = PolicyScope(level="repository", branch_patterns=["*"])
        assert scope.matches("any-org", None, "any-repo", "main") is True

    def test_scope_matches_specific_repo(self):
        """Test specific repo matching."""
        scope = PolicyScope(
            level="repository", repository="my-repo", branch_patterns=["main"]
        )
        assert scope.matches("org", None, "my-repo", "main") is True
        assert scope.matches("org", None, "other-repo", "main") is False

    def test_scope_matches_branch_pattern(self):
        """Test branch pattern matching."""
        scope = PolicyScope(
            level="repository", branch_patterns=["main", "release/*"]
        )
        assert scope.matches("org", None, "repo", "main") is True
        assert scope.matches("org", None, "repo", "release/v1") is True
        assert scope.matches("org", None, "repo", "feature/x") is False


# =============================================================================
# YAML Policy Loading Tests
# =============================================================================

class TestPolicyYAML:
    """Tests for YAML policy file loading."""

    def test_load_policy_from_yaml(self, policy_engine):
        """Test loading a policy from YAML file."""
        yaml_content = """
name: Test YAML Policy
description: Loaded from YAML
version: "1.0"
enabled: true
scope:
  level: repository
  repository: test-repo
  branch_patterns:
    - main
enforcement_mode: error
rules:
  - name: test_yaml_rule
    description: Test rule from YAML
    conditions:
      - type: severity_count
        severity: CRITICAL
        count: 1
    action: block
    severity: CRITICAL
    message: YAML rule triggered
    enabled: true
"""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            f.write(yaml_content)
            f.flush()
            policy = policy_engine.load_policy_from_file(f.name)
            os.unlink(f.name)

        assert policy is not None
        assert policy.name == "Test YAML Policy"
        assert len(policy.rules) == 1
        assert policy.rules[0].name == "test_yaml_rule"

    def test_generate_policy_yaml_template(self, policy_engine):
        """Test YAML template generation."""
        template = policy_engine.generate_policy_yaml_template()

        assert "name:" in template
        assert "rules:" in template
        assert "conditions:" in template
        assert "scope:" in template

    def test_load_invalid_yaml(self, policy_engine):
        """Test loading invalid YAML."""
        with tempfile.NamedTemporaryFile(
            mode="w", suffix=".yml", delete=False
        ) as f:
            f.write("invalid: yaml: : content")
            f.flush()
            policy = policy_engine.load_policy_from_file(f.name)
            os.unlink(f.name)

        assert policy is None


# =============================================================================
# SARIF Annotations Tests
# =============================================================================

class TestSARIFAnnotations:
    """Tests for SARIF annotation generation."""

    def test_violations_to_sarif_annotations(self, policy_engine, sample_scan_with_vulns):
        """Test converting violations to SARIF annotations."""
        report = policy_engine.evaluate_scan(sample_scan_with_vulns)
        annotations = policy_engine.to_sarif_annotations(report)

        assert isinstance(annotations, list)
        if report.violations:
            assert len(annotations) > 0
            assert "physicalLocation" in annotations[0]
            assert "message" in annotations[0]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
