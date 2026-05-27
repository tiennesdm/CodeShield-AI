"""
GitHub configuration for CodeShield AI PR automation.

Provides settings for GitHub API integration including PAT token
management, repo defaults, and branch naming conventions.
"""

import os
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class GitHubConfig:
    """Configuration for GitHub API integration."""

    # Personal Access Token for GitHub API authentication
    pat: str = field(default_factory=lambda: os.getenv("GITHUB_PAT", ""))

    # Default repository owner and name
    owner: str = field(default_factory=lambda: os.getenv("GITHUB_OWNER", ""))
    repo: str = field(default_factory=lambda: os.getenv("GITHUB_REPO", ""))

    # Default base branch for PRs
    default_branch: str = field(default="main")

    # Branch naming prefix for auto-generated test branches
    branch_prefix: str = field(default="auto-tests")

    # PR labels to apply
    pr_labels: List[str] = field(default_factory=lambda: ["auto-tests", "codeshield-ai"])

    # GitHub API base URL
    api_base_url: str = field(default="https://api.github.com")

    # Request timeout in seconds
    timeout: int = field(default=30)

    # Retry configuration
    max_retries: int = field(default=3)
    retry_backoff: float = field(default=1.5)

    # Commit author
    commit_author_name: str = field(default="CodeShield AI")
    commit_author_email: str = field(default="codeshield-ai@noreply.github.com")

    @property
    def is_configured(self) -> bool:
        """Check if the minimum required config is present."""
        return bool(self.pat and self.owner and self.repo)

    @property
    def repo_full_name(self) -> str:
        """Return the full repository name as owner/repo."""
        return f"{self.owner}/{self.repo}"

    @property
    def headers(self) -> dict:
        """Return the default Authorization headers for GitHub API requests."""
        return {
            "Authorization": f"token {self.pat}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
            "User-Agent": "CodeShield-AI-PR-Agent/1.0",
        }

    def get_repo_api_url(self, endpoint: str = "") -> str:
        """Build a GitHub API URL for this repository."""
        base = f"{self.api_base_url}/repos/{self.owner}/{self.repo}"
        if endpoint:
            return f"{base}/{endpoint}"
        return base


# Global config instance
github_config = GitHubConfig()


def get_github_config() -> GitHubConfig:
    """Get the global GitHub configuration."""
    return github_config


def configure_github(pat: str, owner: str, repo: str, **kwargs) -> GitHubConfig:
    """
    Configure GitHub settings programmatically.

    Args:
        pat: Personal Access Token
        owner: Repository owner/organization
        repo: Repository name
        **kwargs: Additional config options

    Returns:
        Updated GitHubConfig instance
    """
    global github_config
    github_config = GitHubConfig(pat=pat, owner=owner, repo=repo, **kwargs)
    return github_config
