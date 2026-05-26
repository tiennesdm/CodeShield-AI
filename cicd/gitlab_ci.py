"""
GitLab CI Component Generator for CodeShield AI.

Generates .gitlab-ci.yml templates with:
- Native SARIF artifact reports for GitLab Security Dashboard
- MR widget integration for vulnerability display
- Pipeline status: pass/warn/fail based on severity thresholds
- Configurable job templates with stages
- Multi-language scanning support
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class GitLabCIConfig:
    """Configuration for GitLab CI template generation."""

    stage: str = "security"
    image: str = "python:3.11-slim"
    variables: Dict[str, str] = field(default_factory=lambda: {
        "CODESHIELD_API_URL": "https://api.codeshield.ai",
        "CODESHIELD_SEVERITY_THRESHOLD": "MEDIUM",
        "CODESHIELD_FAIL_ON": "HIGH",
        "CODESHIELD_OUTPUT_FORMAT": "sarif",
        "CODESHIELD_TIMEOUT": "600",
    })
    scan_type: str = "full"
    languages: List[str] = field(default_factory=lambda: ["python", "javascript"])
    severity_threshold: str = "MEDIUM"
    fail_on: str = "HIGH"
    allow_failure: bool = False
    artifacts_expiry: str = "30 days"
    rules: List[Dict[str, Any]] = field(default_factory=lambda: [
        {"if": '$CI_PIPELINE_SOURCE == "merge_request_event"'},
        {"if": '$CI_COMMIT_BRANCH == "main"'},
        {"if": '$CI_COMMIT_BRANCH == "develop"'},
    ])
    needs: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    cache: Dict[str, Any] = field(default_factory=dict)
    services: List[str] = field(default_factory=list)
    before_script: List[str] = field(default_factory=lambda: [
        "pip install codeshield-cli",
    ])

    def merged_variables(self) -> Dict[str, str]:
        """Get all variables with user overrides merged."""
        vars_dict = dict(self.variables)
        vars_dict["CODESHIELD_SCAN_TYPE"] = self.scan_type
        vars_dict["CODESHIELD_SEVERITY_THRESHOLD"] = self.severity_threshold
        vars_dict["CODESHIELD_FAIL_ON"] = self.fail_on
        vars_dict["CODESHIELD_LANGUAGES"] = ",".join(self.languages)
        return vars_dict


class GitLabCIGenerator:
    """
    Generator for GitLab CI/CD configuration.

    Produces .gitlab-ci.yml templates that integrate with:
    - GitLab Security Dashboard (via artifacts:reports:sarif)
    - MR Widget (vulnerability display in merge requests)
    - Pipeline status control (pass/warn/fail)
    - Multi-stage pipeline support
    """

    def __init__(self, api_base_url: str = "https://api.codeshield.ai") -> None:
        """Initialize the GitLab CI generator."""
        self.api_base_url = api_base_url.rstrip("/")

    def generate_ci_template(
        self,
        config: Optional[GitLabCIConfig] = None,
        include_sast_rules: bool = True,
        include_secret_detection: bool = True,
        include_dependency_scan: bool = True,
    ) -> str:
        """
        Generate a complete .gitlab-ci.yml template.

        Args:
            config: CI configuration
            include_sast_rules: Include SAST scanning job
            include_secret_detection: Include secret detection job
            include_dependency_scan: Include dependency scanning job

        Returns:
            GitLab CI YAML content
        """
        if config is None:
            config = GitLabCIConfig()

        sections: List[str] = []

        # Stages
        sections.append(self._generate_stages(config))

        # Variables
        sections.append(self._generate_variables(config))

        # Cache
        if config.cache:
            sections.append(self._generate_cache(config))

        # SAST job
        if include_sast_rules:
            sections.append(self._generate_sast_job(config))

        # Secret detection job
        if include_secret_detection:
            sections.append(self._generate_secret_detection_job(config))

        # Dependency scan job
        if include_dependency_scan:
            sections.append(self._generate_dependency_scan_job(config))

        # Merge reports job
        sections.append(self._generate_merge_reports_job(config))

        # Security gate job
        sections.append(self._generate_security_gate_job(config))

        return "\n".join(sections)

    def _generate_stages(self, config: GitLabCIConfig) -> str:
        """Generate stages section."""
        return """# ============================================
# CodeShield AI - GitLab CI Security Pipeline
# https://codeshield.ai
# ============================================

stages:
  - build
  - test
  - security
  - deploy
"""

    def _generate_variables(self, config: GitLabCIConfig) -> str:
        """Generate global variables section."""
        vars_dict = config.merged_variables()
        vars_yaml = "\n".join(f'    {k}: "{v}"' for k, v in vars_dict.items())

        return f"""variables:
{vars_yaml}
"""

    def _generate_cache(self, config: GitLabCIConfig) -> str:
        """Generate cache configuration."""
        if not config.cache:
            return ""

        import json
        cache_yaml = json.dumps(config.cache, indent=2)
        return f"""default:
  cache: {cache_yaml}
"""

    def _generate_sast_job(self, config: GitLabCIConfig) -> str:
        """Generate SAST scanning job."""
        rules_yaml = self._format_rules(config.rules)
        needs_yaml = self._format_needs(config.needs)
        tags_yaml = self._format_tags(config.tags)
        before_script_yaml = self._format_script(config.before_script)

        allow_failure = "true" if config.allow_failure else "false"

        return f"""
# --------------------------------------------
# SAST Scanning Job
# --------------------------------------------
codeshield-sast:
  stage: {config.stage}
  image: {config.image}
  variables:
    CODESHIELD_SCAN_TYPE: "sast"
    CODESHIELD_OUTPUT_FORMAT: "sarif"
  {needs_yaml}
  {tags_yaml}
  before_script:
{before_script_yaml}
  script:
    - |
      echo "=== CodeShield AI SAST Scan ==="
      echo "Languages: $CODESHIELD_LANGUAGES"
      echo "Threshold: $CODESHIELD_SEVERITY_THRESHOLD"

      # Prepare scan config
      cat > scan-config.json << 'CONFIG'
      {{
        "scan_type": "sast",
        "languages": $(echo "$CODESHIELD_LANGUAGES" | tr ',' '\\n' | jq -R . | jq -s .),
        "severity_threshold": "$CODESHIELD_SEVERITY_THRESHOLD",
        "output_format": "sarif",
        "timeout": $CODESHIELD_TIMEOUT
      }}
      CONFIG

      # Upload source and start scan
      ZIP_FILE="source-code.zip"
      zip -r "$ZIP_FILE" . -x '*.git/*' -x 'node_modules/*' -x 'vendor/*' -x '.venv/*'

      SCAN_RESPONSE=$(curl -s -X POST "$CODESHIELD_API_URL/api/scan/zip" \\
          -H "Authorization: Bearer $CODESHIELD_API_TOKEN" \\
          -F "file=@$ZIP_FILE" \\
          -F "config=@scan-config.json")

      SCAN_ID=$(echo "$SCAN_RESPONSE" | jq -r '.scan_id')
      echo "Scan started: $SCAN_ID"

      # Poll for completion
      for i in $(seq 1 $CODESHIELD_TIMEOUT); do
          STATUS=$(curl -s "$CODESHIELD_API_URL/api/scan/$SCAN_ID/status" \\
              -H "Authorization: Bearer $CODESHIELD_API_TOKEN" | jq -r '.status')
          echo "Status: $STATUS"
          [ "$STATUS" = "completed" ] && break
          [ "$STATUS" = "failed" ] && exit 1
          sleep 5
      done

      # Export SARIF
      curl -s "$CODESHIELD_API_URL/api/export/$SCAN_ID?format=sarif" \\
          -H "Authorization: Bearer $CODESHIELD_API_TOKEN" \\
          > codeshield-sast-results.sarif

      # Generate summary
      curl -s "$CODESHIELD_API_URL/api/scan/$SCAN_ID/results" \\
          -H "Authorization: Bearer $CODESHIELD_API_TOKEN" \\
          > codeshield-sast-summary.json

      echo "SAST scan complete. Results: codeshield-sast-results.sarif"
  artifacts:
    when: always
    expire_in: {config.artifacts_expiry}
    paths:
      - codeshield-sast-results.sarif
      - codeshield-sast-summary.json
    reports:
      sarif: codeshield-sast-results.sarif
  allow_failure: {allow_failure}
{rules_yaml}
"""

    def _generate_secret_detection_job(self, config: GitLabCIConfig) -> str:
        """Generate secret detection job."""
        rules_yaml = self._format_rules(config.rules)
        before_script_yaml = self._format_script(config.before_script)
        allow_failure = "true" if config.allow_failure else "false"

        return f"""
# --------------------------------------------
# Secret Detection Job
# --------------------------------------------
codeshield-secrets:
  stage: {config.stage}
  image: {config.image}
  variables:
    CODESHIELD_SCAN_TYPE: "secrets"
    CODESHIELD_OUTPUT_FORMAT: "sarif"
  before_script:
{before_script_yaml}
  script:
    - |
      echo "=== CodeShield AI Secret Detection ==="

      # Prepare scan config for secrets
      cat > secrets-config.json << 'CONFIG'
      {{
        "scan_type": "secrets",
        "languages": ["*"],
        "severity_threshold": "LOW",
        "output_format": "sarif",
        "timeout": $CODESHIELD_TIMEOUT
      }}
      CONFIG

      # Upload source and start scan
      ZIP_FILE="source-code.zip"
      zip -r "$ZIP_FILE" . -x '*.git/*' -x 'node_modules/*'

      SCAN_RESPONSE=$(curl -s -X POST "$CODESHIELD_API_URL/api/scan/zip" \\
          -H "Authorization: Bearer $CODESHIELD_API_TOKEN" \\
          -F "file=@$ZIP_FILE" \\
          -F "config=@secrets-config.json")

      SCAN_ID=$(echo "$SCAN_RESPONSE" | jq -r '.scan_id')
      echo "Scan started: $SCAN_ID"

      # Poll for completion
      for i in $(seq 1 $CODESHIELD_TIMEOUT); do
          STATUS=$(curl -s "$CODESHIELD_API_URL/api/scan/$SCAN_ID/status" \\
              -H "Authorization: Bearer $CODESHIELD_API_TOKEN" | jq -r '.status')
          echo "Status: $STATUS"
          [ "$STATUS" = "completed" ] && break
          [ "$STATUS" = "failed" ] && exit 1
          sleep 5
      done

      # Export SARIF
      curl -s "$CODESHIELD_API_URL/api/export/$SCAN_ID?format=sarif" \\
          -H "Authorization: Bearer $CODESHIELD_API_TOKEN" \\
          > codeshield-secrets-results.sarif

      echo "Secret detection complete. Results: codeshield-secrets-results.sarif"
  artifacts:
    when: always
    expire_in: {config.artifacts_expiry}
    paths:
      - codeshield-secrets-results.sarif
    reports:
      sarif: codeshield-secrets-results.sarif
  allow_failure: {allow_failure}
{rules_yaml}
"""

    def _generate_dependency_scan_job(self, config: GitLabCIConfig) -> str:
        """Generate dependency scanning job."""
        rules_yaml = self._format_rules(config.rules)
        before_script_yaml = self._format_script(config.before_script)
        allow_failure = "true" if config.allow_failure else "false"

        return f"""
# --------------------------------------------
# Dependency Vulnerability Scan Job
# --------------------------------------------
codeshield-dependency:
  stage: {config.stage}
  image: {config.image}
  variables:
    CODESHIELD_SCAN_TYPE: "dependencies"
    CODESHIELD_OUTPUT_FORMAT: "sarif"
  before_script:
{before_script_yaml}
  script:
    - |
      echo "=== CodeShield AI Dependency Scan ==="

      # Find dependency files
      DEP_FILES=""
      [ -f "requirements.txt" ] && DEP_FILES="$DEP_FILES requirements.txt"
      [ -f "package.json" ] && DEP_FILES="$DEP_FILES package.json"
      [ -f "pom.xml" ] && DEP_FILES="$DEP_FILES pom.xml"
      [ -f "build.gradle" ] && DEP_FILES="$DEP_FILES build.gradle"
      [ -f "go.mod" ] && DEP_FILES="$DEP_FILES go.mod"
      [ -f "Gemfile" ] && DEP_FILES="$DEP_FILES Gemfile"
      [ -f "composer.json" ] && DEP_FILES="$DEP_FILES composer.json"
      [ -f "Cargo.toml" ] && DEP_FILES="$DEP_FILES Cargo.toml"

      echo "Found dependency files: $DEP_FILES"

      # Upload source and start scan
      ZIP_FILE="source-code.zip"
      zip -r "$ZIP_FILE" . -x '*.git/*' -x 'node_modules/*' -x '.venv/*'

      SCAN_RESPONSE=$(curl -s -X POST "$CODESHIELD_API_URL/api/scan/zip" \\
          -H "Authorization: Bearer $CODESHIELD_API_TOKEN" \\
          -F "file=@$ZIP_FILE" \\
          -F "config={{\\"scan_type\\": \\"dependencies\\", \\"output_format\\": \\"sarif\\"}}")

      SCAN_ID=$(echo "$SCAN_RESPONSE" | jq -r '.scan_id')
      echo "Scan started: $SCAN_ID"

      # Poll for completion
      for i in $(seq 1 $CODESHIELD_TIMEOUT); do
          STATUS=$(curl -s "$CODESHIELD_API_URL/api/scan/$SCAN_ID/status" \\
              -H "Authorization: Bearer $CODESHIELD_API_TOKEN" | jq -r '.status')
          echo "Status: $STATUS"
          [ "$STATUS" = "completed" ] && break
          [ "$STATUS" = "failed" ] && exit 1
          sleep 5
      done

      # Export SARIF
      curl -s "$CODESHIELD_API_URL/api/export/$SCAN_ID?format=sarif" \\
          -H "Authorization: Bearer $CODESHIELD_API_TOKEN" \\
          > codeshield-dependency-results.sarif

      echo "Dependency scan complete. Results: codeshield-dependency-results.sarif"
  artifacts:
    when: always
    expire_in: {config.artifacts_expiry}
    paths:
      - codeshield-dependency-results.sarif
    reports:
      sarif: codeshield-dependency-results.sarif
  allow_failure: {allow_failure}
{rules_yaml}
"""

    def _generate_merge_reports_job(self, config: GitLabCIConfig) -> str:
        """Generate job to merge all SARIF reports."""
        rules_yaml = self._format_rules(config.rules)
        allow_failure = "true" if config.allow_failure else "false"

        return f"""
# --------------------------------------------
# Merge Reports Job
# --------------------------------------------
codeshield-merge-reports:
  stage: {config.stage}
  image: {config.image}
  needs:
    - job: codeshield-sast
      optional: true
    - job: codeshield-secrets
      optional: true
    - job: codeshield-dependency
      optional: true
  script:
    - |
      echo "=== Merging CodeShield Reports ==="

      # Merge SARIF files if multiple exist
      if [ -f "codeshield-sast-results.sarif" ] && [ -f "codeshield-secrets-results.sarif" ]; then
          echo "Merging SARIF reports..."
          # Use jq to merge runs arrays
          jq -s '{{
            "$schema": .[0]."$schema",
            version: .[0].version,
            runs: [.[].runs[]]
          }}' codeshield-sast-results.sarif codeshield-secrets-results.sarif \\
              > codeshield-merged-results.sarif 2>/dev/null || \\
              cp codeshield-sast-results.sarif codeshield-merged-results.sarif
      elif [ -f "codeshield-sast-results.sarif" ]; then
          cp codeshield-sast-results.sarif codeshield-merged-results.sarif
      elif [ -f "codeshield-secrets-results.sarif" ]; then
          cp codeshield-secrets-results.sarif codeshield-merged-results.sarif
      else
          echo '{{"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json", "version": "2.1.0", "runs": []}}' \\
              > codeshield-merged-results.sarif
      fi

      echo "Reports merged: codeshield-merged-results.sarif"
  artifacts:
    when: always
    expire_in: {config.artifacts_expiry}
    paths:
      - codeshield-merged-results.sarif
    reports:
      sarif: codeshield-merged-results.sarif
  allow_failure: {allow_failure}
{rules_yaml}
"""

    def _generate_security_gate_job(self, config: GitLabCIConfig) -> str:
        """Generate security quality gate job."""
        rules_yaml = self._format_rules(config.rules)

        # Determine allow_failure based on severity threshold
        gate_allow_failure = "false"

        return f"""
# --------------------------------------------
# Security Quality Gate
# Fails pipeline based on severity threshold
# --------------------------------------------
codeshield-security-gate:
  stage: {config.stage}
  image: {config.image}
  needs:
    - job: codeshield-merge-reports
  script:
    - |
      echo "=== CodeShield AI Security Gate ==="
      echo "Fail threshold: $CODESHIELD_FAIL_ON"

      # Parse SARIF for severity counts
      if [ -f "codeshield-merged-results.sarif" ]; then
          CRITICAL=$(jq '[.runs[].results[] | select(.level == "error")] | length' codeshield-merged-results.sarif 2>/dev/null || echo "0")
          HIGH=$(jq '[.runs[].results[] | select(.level == "error")] | length' codeshield-merged-results.sarif 2>/dev/null || echo "0")
          MEDIUM=$(jq '[.runs[].results[] | select(.level == "warning")] | length' codeshield-merged-results.sarif 2>/dev/null || echo "0")
          LOW=$(jq '[.runs[].results[] | select(.level == "note")] | length' codeshield-merged-results.sarif 2>/dev/null || echo "0")
      else
          CRITICAL=0
          HIGH=0
          MEDIUM=0
          LOW=0
      fi

      echo "Critical: $CRITICAL"
      echo "High: $HIGH"
      echo "Medium: $MEDIUM"
      echo "Low: $LOW"

      # Security gate logic
      EXIT_CODE=0
      case "$CODESHIELD_FAIL_ON" in
          "CRITICAL")
              [ "$CRITICAL" -gt 0 ] && EXIT_CODE=1
              ;;
          "HIGH")
              [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ] && EXIT_CODE=1
              ;;
          "MEDIUM")
              [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ] || [ "$MEDIUM" -gt 0 ] && EXIT_CODE=1
              ;;
          "LOW")
              [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ] || [ "$MEDIUM" -gt 0 ] || [ "$LOW" -gt 0 ] && EXIT_CODE=1
              ;;
      esac

      # Generate gate report for GitLab
      cat > codeshield-gate-report.json << EOF
      {{
        "version": "15.0.0",
        "vulnerabilities": [],
        "remediations": [],
        "scan": {{
          "scanner": {{ "id": "codeshield-ai", "name": "CodeShield AI" }},
          "analyzer": {{ "id": "codeshield-ai", "name": "CodeShield AI" }},
          "start_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
          "end_time": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
          "status": "$([ $EXIT_CODE -eq 0 ] && echo 'success' || echo 'failure')",
          "type": "sast"
        }}
      }}
      EOF

      if [ $EXIT_CODE -ne 0 ]; then
          echo "❌ Security gate FAILED: vulnerabilities found at or above '$CODESHIELD_FAIL_ON'"
      else
          echo "✅ Security gate PASSED"
      fi

      exit $EXIT_CODE
  allow_failure: {gate_allow_failure}
{rules_yaml}
"""

    @staticmethod
    def _format_rules(rules: List[Dict[str, Any]]) -> str:
        """Format GitLab CI rules as YAML."""
        if not rules:
            return ""
        rules_lines = ["  rules:"]
        for rule in rules:
            for key, value in rule.items():
                rules_lines.append(f"    - {key}: {value}")
        return "\n".join(rules_lines)

    @staticmethod
    def _format_needs(needs: List[str]) -> str:
        """Format GitLab CI needs as YAML."""
        if not needs:
            return ""
        needs_lines = ["  needs:"]
        for need in needs:
            needs_lines.append(f"    - {need}")
        return "\n".join(needs_lines)

    @staticmethod
    def _format_tags(tags: List[str]) -> str:
        """Format GitLab CI tags as YAML."""
        if not tags:
            return ""
        tags_lines = ["  tags:"]
        for tag in tags:
            tags_lines.append(f"    - {tag}")
        return "\n".join(tags_lines)

    @staticmethod
    def _format_script(lines: List[str]) -> str:
        """Format script lines with proper indentation."""
        return "\n".join(f"    - {line}" for line in lines)

    def generate_all(
        self,
        output_dir: str,
        config: Optional[GitLabCIConfig] = None,
    ) -> Dict[str, str]:
        """
        Generate all GitLab CI files.

        Args:
            output_dir: Directory to write files to
            config: CI configuration

        Returns:
            Dictionary of generated file paths
        """
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        files = {}

        # Main .gitlab-ci.yml
        ci_yml = self.generate_ci_template(config)
        (out_path / ".gitlab-ci.yml").write_text(ci_yml)
        files["gitlab_ci"] = str(out_path / ".gitlab-ci.yml")

        logger.info("Generated GitLab CI files in %s", output_dir)
        return files
