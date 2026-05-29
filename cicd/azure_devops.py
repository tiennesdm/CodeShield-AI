"""
Azure DevOps Integration Generator for CodeShield AI.

Generates Azure Pipelines YAML templates with:
- SARIF upload to Azure DevOps Advanced Security
- Work item auto-creation for critical findings
- Build status integration
- Multi-stage pipeline support
- Branch policy integration
"""

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class AzureDevOpsConfig:
    """Configuration for Azure Pipelines template generation."""

    pool_name: str = "ubuntu-latest"
    vm_image: str = "ubuntu-latest"
    container_image: str = "python:3.11-slim"
    use_container: bool = False
    scan_type: str = "full"
    languages: List[str] = field(default_factory=lambda: ["python", "javascript"])
    severity_threshold: str = "MEDIUM"
    fail_on: str = "HIGH"
    output_format: str = "sarif"
    api_url: str = "https://api.codeshield.ai"
    timeout_minutes: int = 10
    api_token_variable: str = "CODESHIELD_API_TOKEN"
    trigger_branches: List[str] = field(default_factory=lambda: ["main", "develop"])
    pr_branches: List[str] = field(default_factory=lambda: ["main"])
    schedule_cron: Optional[str] = None
    stages: List[str] = field(default_factory=lambda: ["build", "test", "security"])
    create_work_items: bool = True
    work_item_area_path: str = ""
    work_item_iteration_path: str = ""
    work_item_assigned_to: str = ""
    publish_sarif_to_advance_security: bool = True
    artifact_name: str = "codeshield-results"
    # Branch policy settings
    require_scan_on_pr: bool = True
    minimum_severity_for_work_item: str = "HIGH"


class AzureDevOpsGenerator:
    """
    Generator for Azure DevOps Pipelines integration.

    Produces:
    - azure-pipelines.yml: Main pipeline definition
    - Pipeline templates for stages
    - Service connection configuration guide
    - Branch policy configuration
    """

    def __init__(self, api_base_url: str = "https://api.codeshield.ai") -> None:
        """Initialize the Azure DevOps generator."""
        self.api_base_url = api_base_url.rstrip("/")

    def generate_pipeline_yaml(
        self,
        config: Optional[AzureDevOpsConfig] = None,
    ) -> str:
        """
        Generate azure-pipelines.yml content.

        Args:
            config: Azure DevOps configuration

        Returns:
            Pipeline YAML content
        """
        if config is None:
            config = AzureDevOpsConfig()

        trigger_yaml = self._format_trigger(config)
        pr_yaml = self._format_pr(config)
        pool_yaml = self._format_pool(config)
        stages_yaml = self._format_stages(config)
        schedule_yaml = self._format_schedules(config)

        yaml_content = f"""# CodeShield AI - Azure DevOps Pipeline
# https://codeshield.ai
# Auto-generated Azure Pipelines YAML

# ============================================
# Trigger Configuration
# ============================================
{trigger_yaml}

{pr_yaml}

{schedule_yaml}
# ============================================
# Pipeline Variables
# ============================================
variables:
  - name: CODESHIELD_API_URL
    value: '{self.api_base_url}'
  - name: CODESHIELD_SCAN_TYPE
    value: '{config.scan_type}'
  - name: CODESHIELD_LANGUAGES
    value: '{",".join(config.languages)}'
  - name: CODESHIELD_SEVERITY_THRESHOLD
    value: '{config.severity_threshold}'
  - name: CODESHIELD_FAIL_ON
    value: '{config.fail_on}'
  - name: CODESHIELD_TIMEOUT
    value: '{config.timeout_minutes * 60}'
  - name: CODESHIELD_OUTPUT_FORMAT
    value: 'sarif'
  - group: codeshield-secrets  # API token stored here

# ============================================
# Pipeline Stages
# ============================================
{pool_yaml}

{stages_yaml}
"""
        return yaml_content

    def _format_trigger(self, config: AzureDevOpsConfig) -> str:
        """Format trigger section."""
        branches = "\n".join(f"    - {b}" for b in config.trigger_branches)
        return f"""trigger:
  branches:
    include:
{branches}"""

    def _format_pr(self, config: AzureDevOpsConfig) -> str:
        """Format PR trigger section."""
        branches = "\n".join(f"    - {b}" for b in config.pr_branches)
        return f"""pr:
  branches:
    include:
{branches}"""

    def _format_schedules(self, config: AzureDevOpsConfig) -> str:
        """Format scheduled runs section."""
        if not config.schedule_cron:
            return ""
        return f"""schedules:
  - cron: "{config.schedule_cron}"
    displayName: "Nightly Security Scan"
    branches:
      include:
        - {config.trigger_branches[0] if config.trigger_branches else 'main'}
    always: true

"""

    def _format_pool(self, config: AzureDevOpsConfig) -> str:
        """Format pool section."""
        if config.use_container:
            return f"""pool:
  name: {config.pool_name}
container: {config.container_image}"""
        return f"""pool:
  vmImage: '{config.vm_image}'"""

    def _format_stages(self, config: AzureDevOpsConfig) -> str:
        """Format all pipeline stages."""
        stages = []

        # Build stage
        if "build" in config.stages:
            stages.append(self._generate_build_stage(config))

        # Test stage
        if "test" in config.stages:
            stages.append(self._generate_test_stage(config))

        # Security scan stage
        if "security" in config.stages:
            stages.append(self._generate_security_stage(config))

        # Deploy stage (conditional)
        if "deploy" in config.stages:
            stages.append(self._generate_deploy_stage(config))

        return "\n".join(stages)

    def _generate_build_stage(self, config: AzureDevOpsConfig) -> str:
        """Generate build stage."""
        return """
stages:
- stage: Build
  displayName: 'Build'
  jobs:
  - job: BuildJob
    displayName: 'Build Application'
    steps:
    - task: UsePythonVersion@0
      inputs:
        versionSpec: '3.11'
      displayName: 'Use Python 3.11'

    - script: |
        echo "Building application..."
        # Add your build steps here
      displayName: 'Build'
"""

    def _generate_test_stage(self, config: AzureDevOpsConfig) -> str:
        """Generate test stage."""
        return """- stage: Test
  displayName: 'Test'
  dependsOn: Build
  jobs:
  - job: TestJob
    displayName: 'Run Tests'
    steps:
    - task: UsePythonVersion@0
      inputs:
        versionSpec: '3.11'
      displayName: 'Use Python 3.11'

    - script: |
        echo "Running tests..."
        # Add your test steps here
      displayName: 'Run Tests'
"""

    def _generate_security_stage(self, config: AzureDevOpsConfig) -> str:
        """Generate security scan stage."""
        work_item_section = ""
        if config.create_work_items:
            work_item_section = self._generate_work_item_task(config)

        publish_sarif_section = ""
        if config.publish_sarif_to_advance_security:
            publish_sarif_section = self._generate_sarif_publish_task()

        return f"""- stage: SecurityScan
  displayName: 'Security Scan'
  dependsOn: Test
  condition: succeededOrFailed()
  jobs:
  - job: CodeShieldScan
    displayName: 'CodeShield AI Security Scan'
    timeoutInMinutes: {config.timeout_minutes + 5}
    steps:
    - checkout: self
      fetchDepth: 0

    - task: UsePythonVersion@0
      inputs:
        versionSpec: '3.11'
      displayName: 'Use Python 3.11'

    - script: |
        echo "=== CodeShield AI Security Scan ==="
        echo "Languages: $(CODESHIELD_LANGUAGES)"
        echo "Threshold: $(CODESHIELD_SEVERITY_THRESHOLD)"
        echo "Fail On: $(CODESHIELD_FAIL_ON)"

        # Install CLI
        pip install codeshield-cli 2>/dev/null || true

        # Create source archive
        zip -r source-code.zip . \\
            -x '*.git/*' \\
            -x 'node_modules/*' \\
            -x '.venv/*' \\
            -x 'target/*' \\
            -x 'build/*' \\
            -x '*.pyc' \\
            -x '__pycache__/*' \\
            2>/dev/null || true

        # Prepare scan config
        cat > scan-config.json << 'CONFIG'
        {{
          "scan_type": "$(CODESHIELD_SCAN_TYPE)",
          "languages": $(echo "$(CODESHIELD_LANGUAGES)" | tr ',' '\\n' | jq -R . | jq -s .),
          "severity_threshold": "$(CODESHIELD_SEVERITY_THRESHOLD)",
          "output_format": "sarif",
          "timeout": $(CODESHIELD_TIMEOUT)
        }}
        CONFIG

        # Start scan
        SCAN_RESPONSE=$(curl -s -X POST "$(CODESHIELD_API_URL)/api/scan/zip" \\
            -H "Authorization: Bearer $(CODESHIELD_API_TOKEN)" \\
            -F "file=@source-code.zip" \\
            -F "config=@scan-config.json")

        SCAN_ID=$(echo "$SCAN_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin)['scan_id'])")
        echo "##vso[task.setvariable variable=SCAN_ID]$SCAN_ID"
        echo "Scan started: $SCAN_ID"
      displayName: 'Start Security Scan'
      env:
        CODESHIELD_API_TOKEN: $({config.api_token_variable})

    - script: |
        # Poll for scan completion
        SCAN_ID="$(SCAN_ID)"
        TIMEOUT=$(CODESHIELD_TIMEOUT)
        ELAPSED=0
        INTERVAL=5

        while [ $ELAPSED -lt $TIMEOUT ]; do
            STATUS=$(curl -s "$(CODESHIELD_API_URL)/api/scan/$SCAN_ID/status" \\
                -H "Authorization: Bearer $(CODESHIELD_API_TOKEN)" | \\
                python3 -c "import sys,json; print(json.load(sys.stdin)['status'])")

            echo "Status: $STATUS ($(date))"
            [ "$STATUS" = "completed" ] && break
            [ "$STATUS" = "failed" ] && exit 1

            sleep $INTERVAL
            ELAPSED=$((ELAPSED + INTERVAL))
        done

        if [ $ELAPSED -ge $TIMEOUT ]; then
            echo "##vso[task.logissue type=error]Scan timed out after ${{TIMEOUT}}s"
            exit 1
        fi

        echo "Scan completed successfully"
      displayName: 'Wait for Scan Completion'
      env:
        CODESHIELD_API_TOKEN: $({config.api_token_variable})

    - script: |
        # Export results in SARIF format
        SCAN_ID="$(SCAN_ID)"
        curl -s "$(CODESHIELD_API_URL)/api/export/$SCAN_ID?format=sarif" \\
            -H "Authorization: Bearer $(CODESHIELD_API_TOKEN)" \\
            > $(Build.ArtifactStagingDirectory)/codeshield-results.sarif

        # Export HTML report
        curl -s "$(CODESHIELD_API_URL)/api/export/$SCAN_ID?format=html" \\
            -H "Authorization: Bearer $(CODESHIELD_API_TOKEN)" \\
            > $(Build.ArtifactStagingDirectory)/codeshield-report.html

        # Export JSON results for summary
        curl -s "$(CODESHIELD_API_URL)/api/scan/$SCAN_ID/results" \\
            -H "Authorization: Bearer $(CODESHIELD_API_TOKEN)" \\
            > $(Build.ArtifactStagingDirectory)/codeshield-results.json

        echo "Results exported"
      displayName: 'Export Scan Results'
      env:
        CODESHIELD_API_TOKEN: $({config.api_token_variable})

    - task: PublishBuildArtifacts@1
      inputs:
        PathtoPublish: '$(Build.ArtifactStagingDirectory)'
        ArtifactName: '{config.artifact_name}'
        publishLocation: 'Container'
      displayName: 'Publish Scan Artifacts'
      condition: always()

{publish_sarif_section}

    - script: |
        # Parse results and generate summary
        RESULTS_FILE="$(Build.ArtifactStagingDirectory)/codeshield-results.json"

        if [ -f "$RESULTS_FILE" ]; then
            CRITICAL=$(python3 -c "import json; d=json.load(open('$RESULTS_FILE')); print(d.get('stats',{{}}).get('critical',0))")
            HIGH=$(python3 -c "import json; d=json.load(open('$RESULTS_FILE')); print(d.get('stats',{{}}).get('high',0))")
            MEDIUM=$(python3 -c "import json; d=json.load(open('$RESULTS_FILE')); print(d.get('stats',{{}}).get('medium',0))")
            LOW=$(python3 -c "import json; d=json.load(open('$RESULTS_FILE')); print(d.get('stats',{{}}).get('low',0))")
            RISK=$(python3 -c "import json; d=json.load(open('$RESULTS_FILE')); print(d.get('risk_score',0))")

            echo "##vso[task.logissue type=summary]\\n### CodeShield AI Security Scan Results\\n| Severity | Count |\\n|----------|-------|\\n| 🔴 Critical | $CRITICAL |\\n| 🟠 High | $HIGH |\\n| 🟡 Medium | $MEDIUM |\\n| 🟢 Low | $LOW |\\n\\n**Risk Score:** $RISK/100"

            echo "##vso[task.setvariable variable=CODESHIELD_CRITICAL]$CRITICAL"
            echo "##vso[task.setvariable variable=CODESHIELD_HIGH]$HIGH"
            echo "##vso[task.setvariable variable=CODESHIELD_MEDIUM]$MEDIUM"
            echo "##vso[task.setvariable variable=CODESHIELD_LOW]$LOW"
            echo "##vso[task.setvariable variable=CODESHIELD_RISK]$RISK"

            # Fail pipeline based on threshold
            EXIT_CODE=0
            case "$(CODESHIELD_FAIL_ON)" in
                "CRITICAL") [ "$CRITICAL" -gt 0 ] && EXIT_CODE=1 ;;
                "HIGH") [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ] && EXIT_CODE=1 ;;
                "MEDIUM") [ "$CRITICAL" -gt 0 ] || [ "$HIGH" -gt 0 ] || [ "$MEDIUM" -gt 0 ] && EXIT_CODE=1 ;;
            esac

            if [ $EXIT_CODE -ne 0 ]; then
                echo "##vso[task.logissue type=error]Security scan failed: vulnerabilities found at or above '$(CODESHIELD_FAIL_ON)' threshold"
                exit 1
            fi
        fi
      displayName: 'Generate Summary & Quality Gate'
      env:
        CODESHIELD_API_TOKEN: $({config.api_token_variable})

{work_item_section}
"""

    def _generate_sarif_publish_task(self) -> str:
        """Generate SARIF publish to Advanced Security task."""
        return """    - task: AdvancedSecurity-Publish@1
      inputs:
        SarifInputPath: '$(Build.ArtifactStagingDirectory)/codeshield-results.sarif'
        Category: 'codeshield-ai'
      displayName: 'Publish SARIF to Advanced Security'
      condition: always()
"""

    def _generate_work_item_task(self, config: AzureDevOpsConfig) -> str:
        """Generate work item creation task for critical findings."""
        area_path_line = "\n          areaPath: "" + config.work_item_area_path + """ if config.work_item_area_path else ""
        iteration_path_line = "\n          iterationPath: "" + config.work_item_iteration_path + """ if config.work_item_iteration_path else ""

        script_content = """          import json
          import os
          import sys
          import urllib.request
          import urllib.error

          org_url = os.environ.get("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI", "")
          project = os.environ.get("SYSTEM_TEAMPROJECT", "")
          pat = os.environ.get("SYSTEM_ACCESSTOKEN", "")
          build_id = os.environ.get("BUILD_BUILDID", "")
          build_url = f"{org_url}{project}/_build/results?buildId={build_id}"

          if not pat:
              print("No access token available. Skipping work item creation.")
              sys.exit(0)

          results_file = "$(Build.ArtifactStagingDirectory)/codeshield-results.json"
          try:
              with open(results_file) as f:
                  results = json.load(f)
          except Exception as e:
              print(f"Failed to read results: {e}")
              sys.exit(0)

          critical_vulns = [
              v for v in results.get("vulnerabilities", [])
              if v.get("severity", "").upper() == "CRITICAL"
          ]

          if not critical_vulns:
              print("No critical vulnerabilities found.")
              sys.exit(0)

          for vuln in critical_vulns[:10]:
              title = "[CRITICAL] " + vuln.get("title", "Security Vulnerability")
              description = (
                  "<b>Critical security vulnerability detected by CodeShield AI</b><br/>\n"
                  + "<br/>\n"
                  + "<b>Title:</b> " + vuln.get("title", "N/A") + "<br/>\n"
                  + "<b>Category:</b> " + vuln.get("category", "N/A") + "<br/>\n"
                  + "<b>CWE:</b> " + vuln.get("cwe_id", "N/A") + "<br/>\n"
                  + "<b>File:</b> " + vuln.get("file_path", "N/A") + "<br/>\n"
                  + "<b>Line:</b> " + str(vuln.get("line_number", "N/A")) + "<br/>\n"
                  + "<br/>\n"
                  + "<b>Description:</b><br/>\n"
                  + vuln.get("description", "No description available") + "<br/>\n"
                  + "<br/>\n"
                  + "<b>Fix Suggestion:</b><br/>\n"
                  + vuln.get("fix_suggestion", "Review and fix based on CWE guidelines.") + "<br/>\n"
                  + "<br/>\n"
                  + "<b>Scan Details:</b><br/>\n"
                  + '<a href="' + build_url + '">View Build</a>'
              )

              work_item = [
                  {"op": "add", "path": "/fields/System.Title", "value": title},
                  {"op": "add", "path": "/fields/System.Description", "value": description},
                  {"op": "add", "path": "/fields/Microsoft.VSTS.Common.Priority", "value": 1},
                  {"op": "add", "path": "/fields/Microsoft.VSTS.Common.Severity", "value": "1 - Critical"},
                  {"op": "add", "path": "/fields/System.Tags", "value": "security;codeshield;critical"},
              ]

              url = f"{org_url}{project}/_apis/wit/workitems/$Bug?api-version=7.0"
              req = urllib.request.Request(
                  url,
                  data=json.dumps(work_item).encode(),
                  headers={
                      "Content-Type": "application/json-patch+json",
                      "Authorization": f"Basic {pat}"
                  },
                  method="POST"
              )

              try:
                  with urllib.request.urlopen(req, timeout=30) as resp:
                      data = json.loads(resp.read())
                      print(f"Created work item: {data.get(\"id\")} - {title}")
              except urllib.error.HTTPError as e:
                  print(f"Failed to create work item: {e.code} {e.reason}")
              except Exception as e:
                  print(f"Error creating work item: {e}")
"""

        ending = area_path_line + iteration_path_line

        return "    - task: PythonScript@0\n"             "      displayName: 'Create Work Items for Critical Findings'\n"             "      condition: and(always(), gt(variables['CODESHIELD_CRITICAL'], 0))\n"             "      inputs:\n"             "        scriptSource: 'inline'\n"             "        script: |\n" + script_content + ending + "\n"             "      env:\n"             "        SYSTEM_ACCESSTOKEN: $(System.AccessToken)\n"

    def _generate_deploy_stage(self, config: AzureDevOpsConfig) -> str:
        """Generate deploy stage (gated by security scan)."""
        return """- stage: Deploy
  displayName: 'Deploy'
  dependsOn:
    - Build
    - Test
    - SecurityScan
  condition: |
    and(
      succeeded('Build'),
      succeeded('Test'),
      in(dependencies.SecurityScan.result, 'Succeeded', 'SucceededWithIssues')
    )
  jobs:
  - deployment: DeployApp
    displayName: 'Deploy Application'
    environment: 'production'
    strategy:
      runOnce:
        deploy:
          steps:
          - script: |
              echo "Deploying application..."
              # Add deployment steps here
            displayName: 'Deploy'
"""

    def generate_branch_policy_json(self, config: Optional[AzureDevOpsConfig] = None) -> str:
        """
        Generate branch policy configuration JSON.

        Args:
            config: Azure DevOps configuration

        Returns:
            Branch policy JSON content
        """
        policy = {
            "isBlocking": True,
            "isEnabled": True,
            "settings": {
                "displayName": "CodeShield AI Security Scan",
                "buildDefinitionId": 0,  # To be filled in
                "queueOnSourceUpdateOnly": True,
                "manualQueueOnly": False,
                "validDuration": 720,  # 12 hours
                "scope": [
                    {
                        "repositoryId": "",  # To be filled in
                        "refName": "refs/heads/main",
                        "matchKind": "Exact",
                    }
                ],
            },
        }
        return json.dumps(policy, indent=2)

    def generate_service_connection_guide(self) -> str:
        """
        Generate service connection setup guide.

        Returns:
            Markdown guide for setting up service connection
        """
        return """# Azure DevOps Service Connection Setup

## 1. Create Variable Group

1. Go to **Pipelines > Library** in your Azure DevOps project
2. Click **+ Variable group**
3. Name: `codeshield-secrets`
4. Add variable:
   - Name: `CODESHIELD_API_TOKEN`
   - Value: Your CodeShield AI API token
   - Click the lock icon to make it secret
5. Save

## 2. Grant Pipeline Permissions

1. In the variable group, go to **Pipeline permissions**
2. Select the pipelines that need access

## 3. Enable System Access Token

1. Go to your pipeline definition
2. Ensure the build service has permissions:
   - Project Settings > Pipelines > Settings
   - Enable "Limit job authorization scope" appropriately

## 4. Branch Policy (Optional)

1. Go to **Repos > Branches**
2. Click the **...** menu on `main` branch > **Branch policies**
3. Add **Build validation**
4. Select your CodeShield pipeline
5. Set "Trigger" to "Automatic"
6. Set "Policy requirement" to "Required"

## 5. Advanced Security (Optional)

To publish SARIF to Azure DevOps Advanced Security:
1. Enable **Azure DevOps Advanced Security** in your project
2. The `AdvancedSecurity-Publish@1` task will automatically upload SARIF
"""

    def generate_all(
        self,
        output_dir: str,
        config: Optional[AzureDevOpsConfig] = None,
    ) -> Dict[str, str]:
        """
        Generate all Azure DevOps files.

        Args:
            output_dir: Directory to write files to
            config: Azure DevOps configuration

        Returns:
            Dictionary of generated file paths
        """
        out_path = Path(output_dir)
        out_path.mkdir(parents=True, exist_ok=True)

        if config is None:
            config = AzureDevOpsConfig()

        files = {}

        # Main pipeline YAML
        pipeline_yaml = self.generate_pipeline_yaml(config)
        (out_path / "azure-pipelines.yml").write_text(pipeline_yaml)
        files["pipeline"] = str(out_path / "azure-pipelines.yml")

        # Branch policy
        branch_policy = self.generate_branch_policy_json(config)
        (out_path / "branch-policy.json").write_text(branch_policy)
        files["branch_policy"] = str(out_path / "branch-policy.json")

        # Service connection guide
        guide = self.generate_service_connection_guide()
        (out_path / "SETUP.md").write_text(guide)
        files["setup_guide"] = str(out_path / "SETUP.md")

        logger.info("Generated Azure DevOps files in %s", output_dir)
        return files
