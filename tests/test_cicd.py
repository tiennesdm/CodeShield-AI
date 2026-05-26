"""
Tests for the CI/CD Integration Package.

Covers GitHub Action, GitLab CI, Jenkins Plugin, and Azure DevOps generators.
"""

import os
import re
import tempfile
from pathlib import Path

import pytest

# Ensure backend is on path
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from cicd.github_action import GitHubActionGenerator, GitHubActionInput
from cicd.gitlab_ci import GitLabCIGenerator, GitLabCIConfig
from cicd.jenkins_plugin import JenkinsPluginGenerator, JenkinsConfig
from cicd.azure_devops import AzureDevOpsGenerator, AzureDevOpsConfig


# =============================================================================
# GitHub Action Tests
# =============================================================================

class TestGitHubActionGenerator:
    """Tests for the GitHub Action generator."""

    def test_generate_action_yml(self):
        """Test action.yml generation."""
        generator = GitHubActionGenerator(api_base_url="https://api.test.codeshield")
        inputs = GitHubActionInput(
            scan_type="full",
            languages=["python", "javascript"],
            severity_threshold="MEDIUM",
            output_format="sarif",
            fail_on="HIGH",
            pr_comments=True,
            sarif_upload=True,
        )

        yml = generator.generate_action_yml(inputs)

        assert "name: 'CodeShield AI Security Scan'" in yml
        assert "scan_type" in yml
        assert "api_token" in yml
        assert "sarif_file" in yml
        assert "https://api.test.codeshield" in yml
        assert "severity_threshold" in yml

    def test_generate_dockerfile(self):
        """Test Dockerfile generation."""
        generator = GitHubActionGenerator()
        dockerfile = generator.generate_dockerfile(
            base_image="python:3.11-slim",
            install_packages=["git", "curl"],
        )

        assert "FROM python:3.11-slim" in dockerfile
        assert "git curl" in dockerfile
        assert "entrypoint.sh" in dockerfile
        assert "/github/workspace" in dockerfile

    def test_generate_entrypoint_script(self):
        """Test entrypoint.sh generation."""
        generator = GitHubActionGenerator()
        script = generator.generate_entrypoint_script()

        assert "#!/bin/bash" in script
        assert "SARIF_FILE=" in script
        assert "STATUS=" in script
        assert "exit" in script
        assert "curl -s" in script

    def test_generate_workflow_yaml(self):
        """Test workflow YAML generation."""
        generator = GitHubActionGenerator()
        yaml = generator.generate_workflow_yaml(
            branches=["main", "develop"],
            schedule_cron="0 2 * * 1",
        )

        assert "name: CodeShield AI Security Scan" in yaml
        assert "push:" in yaml
        assert "pull_request:" in yaml
        assert "schedule:" in yaml
        assert "0 2 * * 1" in yaml
        assert "github/codeql-action/upload-sarif" in yaml

    def test_generate_all(self):
        """Test generating all GitHub Action files."""
        generator = GitHubActionGenerator()
        with tempfile.TemporaryDirectory() as tmpdir:
            files = generator.generate_all(tmpdir)

            assert "action_yml" in files
            assert "dockerfile" in files
            assert "entrypoint" in files
            assert "readme" in files
            assert os.path.exists(files["action_yml"])
            assert os.path.exists(files["dockerfile"])

    def test_default_inputs(self):
        """Test default input values."""
        inputs = GitHubActionInput()

        assert inputs.scan_type == "full"
        assert "python" in inputs.languages
        assert inputs.severity_threshold == "MEDIUM"
        assert inputs.fail_on == "HIGH"
        assert inputs.pr_comments is True
        assert inputs.sarif_upload is True

    def test_to_action_inputs(self):
        """Test conversion to action inputs format."""
        inputs = GitHubActionInput()
        action_inputs = inputs.to_action_inputs()

        assert "scan_type" in action_inputs
        assert "api_token" in action_inputs
        assert action_inputs["api_token"]["required"] is True
        assert action_inputs["scan_type"]["default"] == "full"


# =============================================================================
# GitLab CI Tests
# =============================================================================

class TestGitLabCIGenerator:
    """Tests for the GitLab CI generator."""

    def test_generate_ci_template(self):
        """Test .gitlab-ci.yml generation."""
        generator = GitLabCIGenerator()
        config = GitLabCIConfig(
            stage="security",
            scan_type="full",
            languages=["python", "javascript"],
            severity_threshold="MEDIUM",
            fail_on="HIGH",
        )

        yml = generator.generate_ci_template(config)

        assert "stages:" in yml
        assert "codeshield-sast:" in yml
        assert "codeshield-secrets:" in yml
        assert "codeshield-security-gate:" in yml
        assert "artifacts:" in yml
        assert "reports:" in yml
        assert "sarif:" in yml

    def test_ci_template_has_rules(self):
        """Test that generated CI has rules."""
        generator = GitLabCIGenerator()
        yml = generator.generate_ci_template()

        assert "rules:" in yml
        assert "merge_request_event" in yml

    def test_ci_config_merged_variables(self):
        """Test variable merging."""
        config = GitLabCIConfig(
            scan_type="sast",
            severity_threshold="HIGH",
            languages=["python"],
        )
        vars_dict = config.merged_variables()

        assert vars_dict["CODESHIELD_SCAN_TYPE"] == "sast"
        assert vars_dict["CODESHIELD_SEVERITY_THRESHOLD"] == "HIGH"
        assert vars_dict["CODESHIELD_LANGUAGES"] == "python"

    def test_sast_job_generation(self):
        """Test SAST job generation."""
        generator = GitLabCIGenerator()
        config = GitLabCIConfig()

        job = generator._generate_sast_job(config)

        assert "codeshield-sast:" in job
        assert "stage: security" in job
        assert "curl -s" in job
        assert "sarif:" in job

    def test_security_gate_job(self):
        """Test security gate job generation."""
        generator = GitLabCIGenerator()
        config = GitLabCIConfig()

        gate = generator._generate_security_gate_job(config)

        assert "codeshield-security-gate:" in gate
        assert "Security Quality Gate" in gate
        assert "EXIT_CODE" in gate

    def test_generate_all(self):
        """Test generating all GitLab CI files."""
        generator = GitLabCIGenerator()
        with tempfile.TemporaryDirectory() as tmpdir:
            files = generator.generate_all(tmpdir)

            assert "gitlab_ci" in files
            assert os.path.exists(files["gitlab_ci"])


# =============================================================================
# Jenkins Plugin Tests
# =============================================================================

class TestJenkinsPluginGenerator:
    """Tests for the Jenkins plugin generator."""

    def test_generate_declarative_pipeline(self):
        """Test Declarative Pipeline generation."""
        generator = JenkinsPluginGenerator()
        config = JenkinsConfig(
            stage_name="Security Scan",
            scan_type="full",
            fail_on="HIGH",
        )

        pipeline = generator.generate_declarative_pipeline(config)

        assert "pipeline {" in pipeline
        assert "stage('Security Scan')" in pipeline
        assert "codeshield-api-token" in pipeline
        assert "post {" in pipeline
        assert "publishHTML" in pipeline

    def test_generate_scripted_pipeline(self):
        """Test Scripted Pipeline generation."""
        generator = JenkinsPluginGenerator()
        config = JenkinsConfig()

        pipeline = generator.generate_scripted_pipeline(config)

        assert "node(" in pipeline
        assert "stage('Checkout')" in pipeline
        assert "curl -s" in pipeline

    def test_generate_shared_library_step(self):
        """Test Shared Library step generation."""
        generator = JenkinsPluginGenerator()
        config = JenkinsConfig()

        step = generator.generate_shared_library_step(config)

        assert "def call" in step
        assert "codeshieldScan" in step
        assert "withCredentials" in step
        assert "scanType:" in step

    def test_generate_stage_snippet(self):
        """Test minimal stage snippet."""
        generator = JenkinsPluginGenerator()
        config = JenkinsConfig()

        snippet = generator.generate_stage_snippet(config)

        assert "stage('Security Scan')" in snippet
        assert "withCredentials" in snippet
        assert "archiveArtifacts" in snippet

    def test_ansi_colors_in_pipeline(self):
        """Test that ANSI colors are used in pipeline output."""
        generator = JenkinsPluginGenerator()
        config = JenkinsConfig()

        pipeline = generator.generate_declarative_pipeline(config)

        assert "RED" in pipeline or "\\u001B[31m" in pipeline
        assert "GREEN" in pipeline or "\\u001B[32m" in pipeline

    def test_generate_all(self):
        """Test generating all Jenkins files."""
        generator = JenkinsPluginGenerator()
        with tempfile.TemporaryDirectory() as tmpdir:
            files = generator.generate_all(tmpdir)

            assert "declarative" in files
            assert "scripted" in files
            assert "shared_library" in files
            assert os.path.exists(files["declarative"])


# =============================================================================
# Azure DevOps Tests
# =============================================================================

class TestAzureDevOpsGenerator:
    """Tests for the Azure DevOps generator."""

    def test_generate_pipeline_yaml(self):
        """Test azure-pipelines.yml generation."""
        generator = AzureDevOpsGenerator()
        config = AzureDevOpsConfig(
            stages=["build", "test", "security"],
            trigger_branches=["main", "develop"],
        )

        yml = generator.generate_pipeline_yaml(config)

        assert "trigger:" in yml
        assert "stages:" in yml
        assert "SecurityScan" in yml
        assert "AdvancedSecurity-Publish" in yml
        assert "CODESHIELD_API_TOKEN" in yml

    def test_generate_branch_policy_json(self):
        """Test branch policy generation."""
        generator = AzureDevOpsGenerator()
        policy_json = generator.generate_branch_policy_json()

        assert "isBlocking" in policy_json
        assert "settings" in policy_json
        assert "CodeShield AI Security Scan" in policy_json

    def test_generate_service_connection_guide(self):
        """Test service connection guide."""
        generator = AzureDevOpsGenerator()
        guide = generator.generate_service_connection_guide()

        assert "Variable Group" in guide
        assert "CODESHIELD_API_TOKEN" in guide

    def test_pipeline_has_schedules(self):
        """Test that schedules are included."""
        generator = AzureDevOpsGenerator()
        config = AzureDevOpsConfig(
            schedule_cron="0 2 * * 1",
        )
        yml = generator.generate_pipeline_yaml(config)

        assert "schedules:" in yml

    def test_generate_all(self):
        """Test generating all Azure DevOps files."""
        generator = AzureDevOpsGenerator()
        with tempfile.TemporaryDirectory() as tmpdir:
            files = generator.generate_all(tmpdir)

            assert "pipeline" in files
            assert "branch_policy" in files
            assert "setup_guide" in files
            assert os.path.exists(files["pipeline"])


# =============================================================================
# CI/CD Integration Tests
# =============================================================================

class TestCICDTemplates:
    """Tests for the CI/CD template files."""

    def test_template_files_exist(self):
        """Verify template files exist."""
        template_dir = Path(__file__).parent.parent / "cicd" / "templates"
        assert template_dir.exists()

    def test_github_action_template(self):
        """Test GitHub Action template file."""
        template_path = Path(__file__).parent.parent / "cicd" / "templates" / "github-action.yml"
        if template_path.exists():
            content = template_path.read_text()
            assert "name:" in content
            assert "uses:" in content or "run:" in content

    def test_gitlab_ci_template(self):
        """Test GitLab CI template file."""
        template_path = Path(__file__).parent.parent / "cicd" / "templates" / "gitlab-ci.yml"
        if template_path.exists():
            content = template_path.read_text()
            assert "stages:" in content

    def test_jenkinsfile_template(self):
        """Test Jenkinsfile template."""
        template_path = Path(__file__).parent.parent / "cicd" / "templates" / "Jenkinsfile"
        if template_path.exists():
            content = template_path.read_text()
            assert "pipeline" in content

    def test_azure_pipelines_template(self):
        """Test Azure Pipelines template."""
        template_path = Path(__file__).parent.parent / "cicd" / "templates" / "azure-pipelines.yml"
        if template_path.exists():
            content = template_path.read_text()
            assert "trigger:" in content


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
