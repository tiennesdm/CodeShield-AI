"""
CodeShield AI - CI/CD Integration Package.

Provides generators for CI/CD pipeline integrations across multiple platforms:
- GitHub Actions
- GitLab CI/CD
- Jenkins
- Azure DevOps

Each module generates platform-specific configuration files with
security scanning, SARIF reporting, and policy enforcement.
"""

from cicd.azure_devops import AzureDevOpsGenerator
from cicd.github_action import GitHubActionGenerator
from cicd.gitlab_ci import GitLabCIGenerator
from cicd.jenkins_plugin import JenkinsPluginGenerator

__all__ = [
    "GitHubActionGenerator",
    "GitLabCIGenerator",
    "JenkinsPluginGenerator",
    "AzureDevOpsGenerator",
]
