"""
GitHub Action Generator for CodeShield AI.

Generates action.yml, Dockerfile, and entrypoint script for the CodeShield AI
GitHub Action. Supports:
- Multi-language scanning with configurable inputs
- SARIF output for GitHub Code Scanning integration
- PR annotations with inline vulnerability comments
- Post-scan summary comments on pull requests
- Configurable severity thresholds with fail-on logic
"""

import os
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)

# Default severity order for threshold comparison
SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


@dataclass
class GitHubActionInput:
    """Input configuration for the GitHub Action."""

    scan_type: str = "full"  # full, sast, secrets, dependencies
    languages: List[str] = field(default_factory=lambda: ["python", "javascript", "java"])
    severity_threshold: str = "MEDIUM"  # INFO, LOW, MEDIUM, HIGH, CRITICAL
    output_format: str = "sarif"  # sarif, json, html, junit
    fail_on: str = "HIGH"  # NEVER, LOW, MEDIUM, HIGH, CRITICAL
    api_url: str = "https://api.codeshield.ai"
    api_token: str = ""
    config_path: str = ""  # Path to custom config file
    timeout: int = 600  # seconds
    pr_comments: bool = True
    sarif_upload: bool = True
    ignore_paths: List[str] = field(default_factory=list)

    def to_action_inputs(self) -> Dict[str, Any]:
        """Convert to GitHub Action inputs YAML format."""
        return {
            "scan_type": {
                "description": "Type of scan to run (full, sast, secrets, dependencies)",
                "required": False,
                "default": self.scan_type,
            },
            "languages": {
                "description": "Comma-separated list of languages to scan",
                "required": False,
                "default": ",".join(self.languages),
            },
            "severity_threshold": {
                "description": "Minimum severity to report (INFO, LOW, MEDIUM, HIGH, CRITICAL)",
                "required": False,
                "default": self.severity_threshold,
            },
            "output_format": {
                "description": "Output format for scan results (sarif, json, html, junit)",
                "required": False,
                "default": self.output_format,
            },
            "fail_on": {
                "description": "Minimum severity that causes the action to fail",
                "required": False,
                "default": self.fail_on,
            },
            "api_token": {
                "description": "CodeShield AI API token",
                "required": True,
            },
            "config_path": {
                "description": "Path to custom scan configuration file",
                "required": False,
                "default": self.config_path,
            },
            "timeout": {
                "description": "Scan timeout in seconds",
                "required": False,
                "default": str(self.timeout),
            },
            "pr_comments": {
                "description": "Enable PR comments with vulnerability summary",
                "required": False,
                "default": "true" if self.pr_comments else "false",
            },
            "sarif_upload": {
                "description": "Upload SARIF results to GitHub Code Scanning",
                "required": False,
                "default": "true" if self.sarif_upload else "false",
            },
            "ignore_paths": {
                "description": "Comma-separated paths to ignore during scanning",
                "required": False,
                "default": ",".join(self.ignore_paths) if self.ignore_paths else "",
            },
        }

    def to_action_outputs(self) -> Dict[str, Any]:
        """Convert to GitHub Action outputs YAML format."""
        return {
            "sarif_file": {
                "description": "Path to the generated SARIF report file",
            },
            "summary": {
                "description": "JSON summary of scan results",
            },
            "exit_code": {
                "description": "Exit code (0 = pass, 1 = fail)",
            },
            "critical_count": {
                "description": "Number of CRITICAL vulnerabilities found",
            },
            "high_count": {
                "description": "Number of HIGH vulnerabilities found",
            },
            "medium_count": {
                "description": "Number of MEDIUM vulnerabilities found",
            },
            "low_count": {
                "description": "Number of LOW vulnerabilities found",
            },
            "risk_score": {
                "description": "Overall risk score (0-100)",
            },
        }


class GitHubActionGenerator:
    """
    Generator for CodeShield AI GitHub Action artifacts.

    Produces:
    - action.yml: GitHub Action metadata
    - Dockerfile: Container definition
    - entrypoint.sh: Runtime script
    - README.md: Usage documentation
    """

    def __init__(self, api_base_url: str = "https://api.codeshield.ai") -> None:
        """Initialize the GitHub Action generator."""
        self.api_base_url = api_base_url.rstrip("/")
        self.default_inputs = GitHubActionInput()

    def generate_action_yml(self, inputs: Optional[GitHubActionInput] = None) -> str:
        """
        Generate action.yml content.

        Args:
            inputs: Custom action inputs configuration

        Returns:
            action.yml content as string
        """
        if inputs is None:
            inputs = self.default_inputs

        action_inputs = inputs.to_action_inputs()
        action_outputs = inputs.to_action_outputs()

        # Build inputs section
        inputs_yaml = "\n".join(
            f"    {name}:\n"
            f"      description: '{info['description']}'\n"
            f"      required: {str(info.get('required', False)).lower()}\n"
            f"      default: '{info.get('default', '')}'"
            for name, info in action_inputs.items()
        )

        # Build outputs section
        outputs_yaml = "\n".join(
            f"    {name}:\n"
            f"      description: '{info['description']}'"
            for name, info in action_outputs.items()
        )

        yml = f"""# CodeShield AI - GitHub Action
# Automatically scan code for vulnerabilities on every push and pull request
# https://codeshield.ai

name: 'CodeShield AI Security Scan'
description: 'Multi-language SAST, secret detection, and dependency vulnerability scanning'
author: 'CodeShield AI'
branding:
  icon: 'shield'
  color: 'purple'

inputs:
{inputs_yaml}

outputs:
{outputs_yaml}

runs:
  using: 'docker'
  image: 'Dockerfile'
  env:
    CODESHIELD_API_URL: '{self.api_base_url}'
  args:
    - ${{ inputs.scan_type }}
    - ${{ inputs.languages }}
    - ${{ inputs.severity_threshold }}
    - ${{ inputs.output_format }}
    - ${{ inputs.fail_on }}
    - ${{ inputs.api_token }}
    - ${{ inputs.config_path }}
    - ${{ inputs.timeout }}
    - ${{ inputs.pr_comments }}
    - ${{ inputs.sarif_upload }}
    - ${{ inputs.ignore_paths }}
"""
        return yml

    def generate_dockerfile(
        self,
        base_image: str = "python:3.11-slim",
        install_packages: Optional[List[str]] = None,
    ) -> str:
        """
        Generate Dockerfile for the GitHub Action.

        Args:
            base_image: Docker base image
            install_packages: Additional packages to install

        Returns:
            Dockerfile content as string
        """
        packages = install_packages or ["git", "curl", "jq", "node.js", "npm"]
        packages_str = " ".join(packages)

        dockerfile = f"""# CodeShield AI GitHub Action Dockerfile
FROM {base_image}

LABEL maintainer="CodeShield AI <support@codeshield.ai>"
LABEL description="CodeShield AI Security Scanner GitHub Action"

# Install dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \\
    {packages_str} \\
    && rm -rf /var/lib/apt/lists/*

# Install CodeShield AI CLI
RUN pip install --no-cache-dir codeshield-cli

# Copy entrypoint script
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Set working directory to the GitHub workspace
WORKDIR /github/workspace

ENTRYPOINT ["/entrypoint.sh"]
"""
        return dockerfile

    def generate_entrypoint_script(self) -> str:
        """
        Generate entrypoint.sh script for the GitHub Action.

        Returns:
            Shell script content as string
        """
        script = '''#!/bin/bash
set -euo pipefail

# CodeShield AI GitHub Action Entrypoint
# Arguments: scan_type languages severity_threshold output_format fail_on api_token config_path timeout pr_comments sarif_upload ignore_paths

SCAN_TYPE="$1"
LANGUAGES="$2"
SEVERITY_THRESHOLD="$3"
OUTPUT_FORMAT="$4"
FAIL_ON="$5"
API_TOKEN="$6"
CONFIG_PATH="$7"
TIMEOUT="$8"
PR_COMMENTS="$9"
SARIF_UPLOAD="${10}"
IGNORE_PATHS="${11}"

# Configuration
API_URL="${CODESHIELD_API_URL:-https://api.codeshield.ai}"
OUTPUT_DIR="codeshield-results"
SARIF_FILE="${OUTPUT_DIR}/codeshield-results.sarif"
JSON_FILE="${OUTPUT_DIR}/codeshield-results.json"
SUMMARY_FILE="${OUTPUT_DIR}/summary.json"

mkdir -p "$OUTPUT_DIR"

echo "::: CodeShield AI Security Scan :::"
echo "Scan Type: $SCAN_TYPE"
echo "Languages: $LANGUAGES"
echo "Severity Threshold: $SEVERITY_THRESHOLD"
echo "Output Format: $OUTPUT_FORMAT"
echo "Fail On: $FAIL_ON"
echo ""

# Build language array
LANG_ARRAY=$(echo "$LANGUAGES" | tr ',' '\\n' | jq -R . | jq -s .)

# Build ignore paths array
IGNORE_ARRAY="[]"
if [ -n "$IGNORE_PATHS" ]; then
    IGNORE_ARRAY=$(echo "$IGNORE_PATHS" | tr ',' '\\n' | jq -R . | jq -s .)
fi

# Build scan configuration
CONFIG_JSON=$(cat <<EOF
{
  "scan_type": "$SCAN_TYPE",
  "languages": $LANG_ARRAY,
  "severity_threshold": "$SEVERITY_THRESHOLD",
  "output_format": "$OUTPUT_FORMAT",
  "fail_on": "$FAIL_ON",
  "ignore_paths": $IGNORE_ARRAY,
  "timeout": $TIMEOUT
}
EOF
)

# Merge with custom config if provided
if [ -n "$CONFIG_PATH" ] && [ -f "$CONFIG_PATH" ]; then
    echo "Loading custom configuration from $CONFIG_PATH"
    CUSTOM_CONFIG=$(cat "$CONFIG_PATH")
    CONFIG_JSON=$(echo "$CONFIG_JSON" "$CUSTOM_CONFIG" | jq -s '.[0] * .[1]')
fi

# Run scan via API
echo "Starting security scan..."
SCAN_RESPONSE=$(curl -s -X POST "$API_URL/api/scan/zip" \\
    -H "Authorization: Bearer $API_TOKEN" \\
    -H "Content-Type: multipart/form-data" \\
    -F "config=$CONFIG_JSON" \\
    -F "file=@$GITHUB_WORKSPACE" \\
    --max-time "$TIMEOUT" || echo '{"error": "API request failed"}')

# Check for API errors
if echo "$SCAN_RESPONSE" | jq -e '.error' > /dev/null 2>&1; then
    echo "Error: $(echo "$SCAN_RESPONSE" | jq -r '.error')"
    echo "sarif_file=" >> "$GITHUB_OUTPUT"
    echo "summary={}\\" >> "$GITHUB_OUTPUT"
    echo "exit_code=1" >> "$GITHUB_OUTPUT"
    exit 1
fi

SCAN_ID=$(echo "$SCAN_RESPONSE" | jq -r '.scan_id')
echo "Scan started with ID: $SCAN_ID"

# Poll for scan completion
POLL_INTERVAL=5
ELAPSED=0
while [ $ELAPSED -lt $TIMEOUT ]; do
    STATUS_RESPONSE=$(curl -s "$API_URL/api/scan/$SCAN_ID/status" \\
        -H "Authorization: Bearer $API_TOKEN" \\
        --max-time 30 || echo '{"status": "unknown"}')

    STATUS=$(echo "$STATUS_RESPONSE" | jq -r '.status')
    PROGRESS=$(echo "$STATUS_RESPONSE" | jq -r '.progress // 0')

    echo "Scan status: $STATUS ($PROGRESS%)"

    if [ "$STATUS" = "completed" ]; then
        break
    elif [ "$STATUS" = "failed" ]; then
        echo "Scan failed: $(echo "$STATUS_RESPONSE" | jq -r '.error // "Unknown error"')"
        echo "sarif_file=" >> "$GITHUB_OUTPUT"
        echo "summary={}\\" >> "$GITHUB_OUTPUT"
        echo "exit_code=1" >> "$GITHUB_OUTPUT"
        exit 1
    fi

    sleep $POLL_INTERVAL
    ELAPSED=$((ELAPSED + POLL_INTERVAL))
done

if [ $ELAPSED -ge $TIMEOUT ]; then
    echo "Scan timed out after ${TIMEOUT}s"
    echo "sarif_file=" >> "$GITHUB_OUTPUT"
    echo "summary={}\\" >> "$GITHUB_OUTPUT"
    echo "exit_code=1" >> "$GITHUB_OUTPUT"
    exit 1
fi

# Export results in requested format
echo "Exporting scan results..."
if [ "$OUTPUT_FORMAT" = "sarif" ] || [ "$SARIF_UPLOAD" = "true" ]; then
    curl -s "$API_URL/api/export/$SCAN_ID?format=sarif" \\
        -H "Authorization: Bearer $API_TOKEN" \\
        --max-time 60 > "$SARIF_FILE"
    echo "SARIF report saved to $SARIF_FILE"
fi

if [ "$OUTPUT_FORMAT" = "json" ]; then
    curl -s "$API_URL/api/export/$SCAN_ID?format=json" \\
        -H "Authorization: Bearer $API_TOKEN" \\
        --max-time 60 > "$JSON_FILE"
fi

if [ "$OUTPUT_FORMAT" = "html" ]; then
    curl -s "$API_URL/api/export/$SCAN_ID?format=html" \\
        -H "Authorization: Bearer $API_TOKEN" \\
        --max-time 60 > "$OUTPUT_DIR/codeshield-results.html"
fi

# Fetch results summary
RESULTS=$(curl -s "$API_URL/api/scan/$SCAN_ID/results" \\
    -H "Authorization: Bearer $API_TOKEN" \\
    --max-time 60)

# Extract severity counts
CRITICAL=$(echo "$RESULTS" | jq '.stats.critical // 0')
HIGH=$(echo "$RESULTS" | jq '.stats.high // 0')
MEDIUM=$(echo "$RESULTS" | jq '.stats.medium // 0')
LOW=$(echo "$RESULTS" | jq '.stats.low // 0')
TOTAL=$(echo "$RESULTS" | jq '.stats.total // 0')
RISK_SCORE=$(echo "$RESULTS" | jq '.risk_score // 0')

# Create summary JSON
SUMMARY_JSON=$(cat <<EOF
{
  "scan_id": "$SCAN_ID",
  "total_vulnerabilities": $TOTAL,
  "critical": $CRITICAL,
  "high": $HIGH,
  "medium": $MEDIUM,
  "low": $LOW,
  "risk_score": $RISK_SCORE,
  "threshold": "$FAIL_ON"
}
EOF
)

echo "$SUMMARY_JSON" > "$SUMMARY_FILE"

# Set outputs
echo "sarif_file=$SARIF_FILE" >> "$GITHUB_OUTPUT"
echo "summary=$SUMMARY_JSON" >> "$GITHUB_OUTPUT"
echo "critical_count=$CRITICAL" >> "$GITHUB_OUTPUT"
echo "high_count=$HIGH" >> "$GITHUB_OUTPUT"
echo "medium_count=$MEDIUM" >> "$GITHUB_OUTPUT"
echo "low_count=$LOW" >> "$GITHUB_OUTPUT"
echo "risk_score=$RISK_SCORE" >> "$GITHUB_OUTPUT"

# Upload SARIF to GitHub Code Scanning
if [ "$SARIF_UPLOAD" = "true" ] && [ -f "$SARIF_FILE" ]; then
    echo "Uploading SARIF to GitHub Code Scanning..."
    # GitHub SARIF upload API
    gh api \\
        --method POST \\
        -H "Accept: application/vnd.github+json" \\
        "/repos/$GITHUB_REPOSITORY/code-scanning/analysis" \\
        -f "sarif=@$SARIF_FILE" \\
        -f "tool_name=CodeShield AI" \\
        -f "checkout_uri=file:///github/workspace" \\
        -f "ref=$GITHUB_REF" \\
        -f "commit_sha=$GITHUB_SHA" \\
        || echo "Warning: SARIF upload failed (this is normal if Advanced Security is not enabled)"
fi

# Post PR comment with summary
if [ "$PR_COMMENTS" = "true" ] && [ -n "${GITHUB_TOKEN:-}" ] && [ "${GITHUB_EVENT_NAME:-}" = "pull_request" ]; then
    echo "Posting scan summary as PR comment..."

    # Determine status icon
    if [ $CRITICAL -gt 0 ]; then
        STATUS_ICON="❌"
        STATUS_TEXT="FAILED"
    elif [ "$FAIL_ON" = "HIGH" ] && [ $HIGH -gt 0 ]; then
        STATUS_ICON="❌"
        STATUS_TEXT="FAILED"
    else
        STATUS_ICON="✅"
        STATUS_TEXT="PASSED"
    fi

    COMMENT_BODY=$(cat <<EOF
## $STATUS_ICON CodeShield AI Security Scan - $STATUS_TEXT

| Severity | Count |
|----------|-------|
| 🔴 Critical | $CRITICAL |
| 🟠 High | $HIGH |
| 🟡 Medium | $MEDIUM |
| 🟢 Low | $LOW |
| **Total** | **$TOTAL** |

**Risk Score:** $RISK_SCORE/100

<details>
<summary>View Details</summary>

- **Scan ID:** $SCAN_ID
- **Threshold:** $FAIL_ON
- [View Full Report]($API_URL/api/scan/$SCAN_ID/results)

</details>
EOF
)

    # Post comment via GitHub API
    PR_NUMBER=$(echo "$GITHUB_REF" | sed 's/refs\\/pull\\///' | sed 's/\\/merge//')
    curl -s -X POST \\
        "https://api.github.com/repos/$GITHUB_REPOSITORY/issues/$PR_NUMBER/comments" \\
        -H "Authorization: token $GITHUB_TOKEN" \\
        -H "Content-Type: application/json" \\
        -d "{\\"body\\": $(echo "$COMMENT_BODY" | jq -R -s .)}" \\
        > /dev/null
fi

# PR annotations (inline comments)
if [ "$PR_COMMENTS" = "true" ] && [ "$GITHUB_EVENT_NAME" = "pull_request" ] && [ $TOTAL -gt 0 ]; then
    echo "::group::Vulnerability Annotations"

    # Generate annotations from results
    echo "$RESULTS" | jq -r '.vulnerabilities[] | 
        "::\\(.severity | ascii_downcase) file=\\(.file_path),line=\\(.line_number)::\\(.title): \\(.description) [\\(.cwe_id // "N/A")]"' \\
        2>/dev/null || true

    echo "::endgroup::"
fi

# Determine exit code based on fail_on threshold
echo ""
echo "===== Scan Summary ====="
echo "Critical: $CRITICAL"
echo "High:     $HIGH"
echo "Medium:   $MEDIUM"
echo "Low:      $LOW"
echo "Total:    $TOTAL"
echo "Risk:     $RISK_SCORE/100"
echo "========================"

# Check if we should fail
EXIT_CODE=0
case "$FAIL_ON" in
    "CRITICAL")
        [ $CRITICAL -gt 0 ] && EXIT_CODE=1
        ;;
    "HIGH")
        [ $CRITICAL -gt 0 ] || [ $HIGH -gt 0 ] && EXIT_CODE=1
        ;;
    "MEDIUM")
        [ $CRITICAL -gt 0 ] || [ $HIGH -gt 0 ] || [ $MEDIUM -gt 0 ] && EXIT_CODE=1
        ;;
    "LOW")
        [ $TOTAL -gt 0 ] && EXIT_CODE=1
        ;;
    "NEVER")
        EXIT_CODE=0
        ;;
esac

echo "exit_code=$EXIT_CODE" >> "$GITHUB_OUTPUT"

if [ $EXIT_CODE -ne 0 ]; then
    echo "❌ Scan failed: vulnerabilities found at or above '$FAIL_ON' threshold"
fi

exit $EXIT_CODE
'''
        return script

    def generate_readme(self) -> str:
        """Generate README.md for the GitHub Action."""
        readme = """# CodeShield AI - GitHub Action

Multi-language SAST, secret detection, and dependency vulnerability scanning for your GitHub workflows.

## Features

- **Multi-language support**: Python, JavaScript/TypeScript, Java, Go, Ruby, PHP, C#, and more
- **SARIF output**: Native integration with GitHub Advanced Security Code Scanning
- **PR annotations**: Inline vulnerability comments on pull requests
- **Summary comments**: Automatic scan summary posted as PR comment
- **Configurable thresholds**: Set severity thresholds for pass/fail
- **Secret detection**: Find hardcoded secrets, API keys, tokens
- **Dependency scanning**: Detect known vulnerabilities in dependencies

## Usage

### Basic Usage

```yaml
name: CodeShield Security Scan
on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run CodeShield AI Scan
        uses: codeshield-ai/codeshield-action@v1
        with:
          api_token: ${{ secrets.CODESHIELD_API_TOKEN }}
          fail_on: HIGH
```

### Advanced Configuration

```yaml
      - name: Run CodeShield AI Scan
        uses: codeshield-ai/codeshield-action@v1
        with:
          scan_type: full
          languages: python,javascript,java
          severity_threshold: MEDIUM
          output_format: sarif
          fail_on: HIGH
          api_token: ${{ secrets.CODESHIELD_API_TOKEN }}
          pr_comments: 'true'
          sarif_upload: 'true'
          ignore_paths: tests/,migrations/
          timeout: 600
```

### Upload SARIF to GitHub Code Scanning

```yaml
      - name: Run CodeShield AI Scan
        uses: codeshield-ai/codeshield-action@v1
        id: codeshield
        with:
          api_token: ${{ secrets.CODESHIELD_API_TOKEN }}

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v2
        if: always()
        with:
          sarif_file: ${{ steps.codeshield.outputs.sarif_file }}
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `scan_type` | Type of scan (full, sast, secrets, dependencies) | No | `full` |
| `languages` | Comma-separated languages | No | `python,javascript,java` |
| `severity_threshold` | Min severity to report | No | `MEDIUM` |
| `output_format` | Output format (sarif, json, html, junit) | No | `sarif` |
| `fail_on` | Severity threshold for failure | No | `HIGH` |
| `api_token` | CodeShield AI API token | **Yes** | - |
| `config_path` | Path to custom config | No | `` |
| `timeout` | Scan timeout (seconds) | No | `600` |
| `pr_comments` | Enable PR comments | No | `true` |
| `sarif_upload` | Upload to Code Scanning | No | `true` |
| `ignore_paths` | Paths to ignore | No | `` |

## Outputs

| Output | Description |
|--------|-------------|
| `sarif_file` | Path to SARIF report |
| `summary` | JSON summary of results |
| `exit_code` | 0 = pass, 1 = fail |
| `critical_count` | Critical vulnerability count |
| `high_count` | High vulnerability count |
| `medium_count` | Medium vulnerability count |
| `low_count` | Low vulnerability count |
| `risk_score` | Overall risk score (0-100) |

## License

MIT
"""
        return readme

    def generate_all(
        self,
        output_dir: str,
        inputs: Optional[GitHubActionInput] = None,
    ) -> Dict[str, str]:
        """
        Generate all GitHub Action files.

        Args:
            output_dir: Directory to write files to
            inputs: Custom action inputs configuration

        Returns:
            Dictionary of generated file paths
        """
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        files = {}

        # action.yml
        action_yml = self.generate_action_yml(inputs)
        (out_path / "action.yml").write_text(action_yml)
        files["action_yml"] = str(out_path / "action.yml")

        # Dockerfile
        dockerfile = self.generate_dockerfile()
        (out_path / "Dockerfile").write_text(dockerfile)
        files["dockerfile"] = str(out_path / "Dockerfile")

        # entrypoint.sh
        entrypoint = self.generate_entrypoint_script()
        (out_path / "entrypoint.sh").write_text(entrypoint)
        os.chmod(out_path / "entrypoint.sh", 0o755)
        files["entrypoint"] = str(out_path / "entrypoint.sh")

        # README.md
        readme = self.generate_readme()
        (out_path / "README.md").write_text(readme)
        files["readme"] = str(out_path / "README.md")

        logger.info("Generated GitHub Action files in %s", output_dir)
        return files

    def generate_workflow_yaml(
        self,
        branches: List[str] = None,
        schedule_cron: Optional[str] = None,
    ) -> str:
        """
        Generate a sample GitHub workflow YAML that uses the action.

        Args:
            branches: Branches to trigger on
            schedule_cron: Optional cron schedule for scheduled scans

        Returns:
            Workflow YAML content
        """
        if branches is None:
            branches = ["main", "develop"]

        triggers = []
        triggers.append("  push:\n    branches: [" + ", ".join(branches) + "]")
        triggers.append("  pull_request:\n    branches: [" + ", ".join(branches) + "]")
        if schedule_cron:
            triggers.append(f"  schedule:\n    - cron: '{schedule_cron}'")
        triggers.append("  workflow_dispatch:")

        trigger_yaml = "\n".join(triggers)

        yaml = f"""name: CodeShield AI Security Scan

on:
{trigger_yaml}

permissions:
  contents: read
  security-events: write
  pull-requests: write
  actions: read

jobs:
  codeshield-scan:
    name: Security Scan
    runs-on: ubuntu-latest
    steps:
      - name: Checkout code
        uses: actions/checkout@v4
        with:
          fetch-depth: 0

      - name: Run CodeShield AI Scan
        uses: codeshield-ai/codeshield-action@v1
        id: codeshield
        with:
          scan_type: full
          languages: python,javascript
          severity_threshold: MEDIUM
          output_format: sarif
          fail_on: HIGH
          api_token: ${{ secrets.CODESHIELD_API_TOKEN }}
          pr_comments: 'true'
          sarif_upload: 'true'
          timeout: 600

      - name: Upload SARIF to GitHub Code Scanning
        uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: ${{ steps.codeshield.outputs.sarif_file }}
          category: codeshield-ai

      - name: Upload scan artifacts
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: codeshield-results
          path: codeshield-results/
          retention-days: 30

      - name: Summary
        if: always()
        run: |
          echo "## CodeShield AI Scan Results" >> $GITHUB_STEP_SUMMARY
          echo "Critical: ${{ steps.codeshield.outputs.critical_count }}" >> $GITHUB_STEP_SUMMARY
          echo "High: ${{ steps.codeshield.outputs.high_count }}" >> $GITHUB_STEP_SUMMARY
          echo "Medium: ${{ steps.codeshield.outputs.medium_count }}" >> $GITHUB_STEP_SUMMARY
          echo "Low: ${{ steps.codeshield.outputs.low_count }}" >> $GITHUB_STEP_SUMMARY
          echo "Risk Score: ${{ steps.codeshield.outputs.risk_score }}/100" >> $GITHUB_STEP_SUMMARY
"""
        return yaml
