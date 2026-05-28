"""
PR Agent for CodeShield AI - GitHub Pull Request Automation.

Creates branches, commits auto-generated test files, and raises pull requests
on GitHub repositories. Integrates with the test generation pipeline to
provide end-to-end test file creation and PR workflow.
"""

import asyncio
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from agents.base import BaseSecurityAgent
from agents.pr_description import (
    FunctionTestInfo,
    PRDescriptionGenerator,
    TestGenerationResult,
    TestModuleSummary,
)
from agents.results import AgentResult, ScanContext
from config.github import get_github_config
from integrations.github_client import GitHubAPIError, GitHubClient
from models.vulnerability import Vulnerability
from utils.logger import get_logger

logger = get_logger(__name__)


class PRAgent(BaseSecurityAgent):
    """
    Creates GitHub branches, commits test files, and raises PRs.

    Integrates with the test generation workflow to automatically
    create pull requests containing auto-generated test cases.

    Attributes:
        name: Agent identifier
        role: Human-readable description of the agent's role
        tools: List of tool names this agent can invoke
        priority: Execution priority (lower = earlier in pipeline)
    """

    name = "pr_agent"
    role = "GitHub Pull Request Automation"
    tools = ["github_api", "branch_manager", "pr_creator"]
    priority = 90  # Runs late in the pipeline (after test generation)

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the PR Agent.

        Args:
            config: Optional configuration dict with keys:
                - pat: GitHub Personal Access Token
                - owner: Repository owner
                - repo: Repository name
                - default_branch: Base branch for PRs (default: main)
                - branch_prefix: Prefix for auto-created branches (default: auto-tests)
                - pr_labels: Labels to apply to PRs
        """
        super().__init__(config)
        self.github_config = get_github_config()

        # Override with any per-instance config
        self.pat: str = self.config.get("pat", self.github_config.pat)
        self.owner: str = self.config.get("owner", self.github_config.owner)
        self.repo: str = self.config.get("repo", self.github_config.repo)
        self.default_branch: str = self.config.get(
            "default_branch", self.github_config.default_branch
        )
        self.branch_prefix: str = self.config.get(
            "branch_prefix", self.github_config.branch_prefix
        )
        self.pr_labels: List[str] = self.config.get(
            "pr_labels", self.github_config.pr_labels
        )

        self._client: Optional[GitHubClient] = None
        self._last_result: Optional[Dict[str, Any]] = None

    # ------------------------------------------------------------------
    # BaseSecurityAgent interface
    # ------------------------------------------------------------------

    async def scan(self, context: ScanContext) -> AgentResult:
        """
        Execute the PR creation workflow.

        This is the main entry point for the BaseSecurityAgent interface.
        It delegates to create_pr_for_tests with parameters from the context.

        Args:
            context: ScanContext with metadata including:
                - test_generation_result: TestGenerationResult
                - github_url: Target GitHub repository URL
                - auto_pr: Whether to auto-create PR

        Returns:
            AgentResult with PR creation status
        """
        start_time = time.time() * 1000
        errors: List[str] = []
        metadata: Dict[str, Any] = {"agent": self.name}

        try:
            test_result = context.metadata.get("test_generation_result")
            github_url = context.metadata.get("github_url", "")
            auto_pr = context.metadata.get("auto_pr", True)

            if not auto_pr:
                metadata["pr_created"] = False
                metadata["reason"] = "auto_pr is disabled"
                return self._build_result(
                    context=context,
                    findings=[],
                    start_time_ms=start_time,
                    errors=errors,
                    metadata=metadata,
                )

            if not test_result:
                errors.append("No test generation result provided")
                return self._build_result(
                    context=context,
                    findings=[],
                    start_time_ms=start_time,
                    errors=errors,
                    metadata=metadata,
                )

            if isinstance(test_result, dict):
                test_result = PRDescriptionGenerator.from_dict(test_result)

            pr_result = await self.create_pr_for_tests(
                test_result=test_result,
                github_url=github_url,
            )

            metadata.update(pr_result)

        except Exception as e:
            logger.error("PR Agent workflow failed: %s", e, exc_info=True)
            errors.append(str(e))

        return self._build_result(
            context=context,
            findings=[],
            start_time_ms=start_time,
            errors=errors,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Core PR workflow
    # ------------------------------------------------------------------

    async def create_pr_for_tests(
        self,
        test_result: TestGenerationResult,
        github_url: str = "",
        test_files_content: Optional[Dict[str, str]] = None,
    ) -> Dict[str, Any]:
        """
        Full PR workflow: check PAT, create branch, commit files, create PR.

        Args:
            test_result: The test generation result
            github_url: GitHub repository URL (e.g., https://github.com/owner/repo)
            test_files_content: Dict mapping file paths to their content for commits

        Returns:
            Dict with pr_url, branch_name, commit_count, and status info
        """
        workflow_start = time.time() * 1000
        result: Dict[str, Any] = {
            "pr_created": False,
            "pr_url": None,
            "pr_number": None,
            "branch_name": None,
            "commits": 0,
            "errors": [],
        }

        # Step 1: Check if GitHub PAT is configured
        if not self._check_pat_configured():
            result["errors"].append("GitHub PAT is not configured")
            logger.error("GitHub PAT not configured. Set GITHUB_PAT environment variable.")
            return result

        # Parse owner/repo from URL if provided, or use configured values
        if github_url:
            parsed = self._parse_github_url(github_url)
            if parsed:
                self.owner, self.repo = parsed
                logger.info("Using repo from URL: %s/%s", self.owner, self.repo)

        if not self.owner or not self.repo:
            result["errors"].append(
                "Repository owner and name must be configured or provided via github_url"
            )
            return result

        # Initialize GitHub client
        client = self._get_client()

        try:
            # Step 2: Test connection
            connected = await client.test_connection()
            if not connected:
                result["errors"].append(
                    f"Failed to connect to GitHub API for {self.owner}/{self.repo}. "
                    "Check PAT permissions."
                )
                return result

            # Step 3: Determine default branch
            try:
                self.default_branch = await client.get_default_branch()
            except GitHubAPIError as e:
                logger.warning("Could not get default branch, using '%s': %s", self.default_branch, e)

            # Step 4: Create new branch
            timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
            branch_name = f"{self.branch_prefix}/{timestamp}"

            try:
                branch_info = await client.create_branch(
                    branch_name=branch_name,
                    from_branch=self.default_branch,
                )
                result["branch_name"] = branch_name
                logger.info("Created branch: %s", branch_name)
            except GitHubAPIError as e:
                result["errors"].append(f"Failed to create branch: {e}")
                return result

            # Step 5: Commit test files
            commits = 0
            if test_files_content:
                for file_path, content in test_files_content.items():
                    try:
                        await self._commit_test_file(
                            client=client,
                            file_path=file_path,
                            content=content,
                            branch=branch_name,
                        )
                        commits += 1
                    except GitHubAPIError as e:
                        error_msg = f"Failed to commit {file_path}: {e}"
                        logger.error(error_msg)
                        result["errors"].append(error_msg)

                result["commits"] = commits
                logger.info("Committed %d test files to %s", commits, branch_name)

            # Step 6: Generate PR description
            pr_body = PRDescriptionGenerator.generate(test_result)
            pr_title = f"\U0001f916 Auto-generated test cases for {test_result.project_name or self.repo}"

            # Step 7: Create Pull Request
            try:
                pr_info = await client.create_pull_request(
                    title=pr_title,
                    body=pr_body,
                    head=branch_name,
                    base=self.default_branch,
                )
                pr_number = pr_info.get("number")
                pr_url = pr_info.get("html_url", "")
                result["pr_created"] = True
                result["pr_number"] = pr_number
                result["pr_url"] = pr_url
                logger.info("Created PR #%s: %s", pr_number, pr_url)

                # Step 8: Add labels
                if self.pr_labels and pr_number:
                    try:
                        await client.add_labels(pr_number, self.pr_labels)
                        logger.info("Added labels %s to PR #%s", self.pr_labels, pr_number)
                    except GitHubAPIError as e:
                        logger.warning("Failed to add labels to PR #%s: %s", pr_number, e)

            except GitHubAPIError as e:
                error_msg = f"Failed to create PR: {e}"
                result["errors"].append(error_msg)
                logger.error(error_msg)

        except Exception as e:
            error_msg = f"Unexpected error in PR workflow: {e}"
            result["errors"].append(error_msg)
            logger.error(error_msg, exc_info=True)

        finally:
            await client.close()

        elapsed = int((time.time() * 1000) - workflow_start)
        result["elapsed_ms"] = elapsed
        self._last_result = result

        return result

    async def commit_test_files(
        self,
        test_files_content: Dict[str, str],
        branch: Optional[str] = None,
        commit_message_prefix: str = "Add tests",
    ) -> Dict[str, Any]:
        """
        Commit multiple test files to an existing branch.

        Args:
            test_files_content: Dict mapping repo file paths to file content
            branch: Branch name (uses latest auto-created branch if None)
            commit_message_prefix: Prefix for commit messages

        Returns:
            Dict with commit_count, committed_files, and errors
        """
        result: Dict[str, Any] = {
            "commit_count": 0,
            "committed_files": [],
            "errors": [],
        }

        target_branch = branch or self._last_result.get("branch_name") if self._last_result else None
        if not target_branch:
            result["errors"].append("No branch specified and no auto-created branch available")
            return result

        if not self._check_pat_configured():
            result["errors"].append("GitHub PAT is not configured")
            return result

        client = self._get_client()

        try:
            for file_path, content in test_files_content.items():
                try:
                    module_name = file_path.split("/")[-1].replace("_test.py", "").replace("test_", "")
                    func_count = content.count("def test_")
                    message = f"{commit_message_prefix} for {module_name}: {func_count} tests"

                    await self._commit_test_file(
                        client=client,
                        file_path=file_path,
                        content=content,
                        branch=target_branch,
                        message=message,
                    )
                    result["commit_count"] += 1
                    result["committed_files"].append(file_path)
                    logger.info("Committed: %s", file_path)

                except GitHubAPIError as e:
                    error_msg = f"Failed to commit {file_path}: {e}"
                    result["errors"].append(error_msg)
                    logger.error(error_msg)

        finally:
            await client.close()

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_client(self) -> GitHubClient:
        """Get or create a GitHubClient instance."""
        if self._client is None:
            self._client = GitHubClient(
                pat=self.pat,
                owner=self.owner,
                repo=self.repo,
            )
        return self._client

    def _check_pat_configured(self) -> bool:
        """Check if the GitHub PAT is configured and non-empty."""
        return bool(self.pat and len(self.pat) > 0)

    def _parse_github_url(self, url: str) -> Optional[Tuple[str, str]]:
        """
        Extract owner and repo from a GitHub URL.

        Supports formats:
        - https://github.com/owner/repo
        - https://github.com/owner/repo.git
        - git@github.com:owner/repo.git
        - owner/repo

        Args:
            url: GitHub repository URL

        Returns:
            Tuple of (owner, repo) or None if parsing fails
        """
        if not url:
            return None

        # Handle SSH format: git@github.com:owner/repo.git
        if url.startswith("git@github.com:"):
            parts = url.replace("git@github.com:", "").replace(".git", "").split("/")
            if len(parts) >= 2:
                return parts[0], parts[1]

        # Handle HTTPS format: https://github.com/owner/repo
        if "github.com" in url:
            parts = url.replace("https://", "").replace("http://", "").rstrip("/").split("/")
            # parts = ["github.com", "owner", "repo", ...]
            if len(parts) >= 3:
                return parts[1], parts[2].replace(".git", "")

        # Handle short format: owner/repo
        if "/" in url and "github.com" not in url and not url.startswith("http"):
            parts = url.split("/")
            if len(parts) == 2:
                return parts[0], parts[1].replace(".git", "")

        logger.warning("Could not parse GitHub URL: %s", url)
        return None

    async def _commit_test_file(
        self,
        client: GitHubClient,
        file_path: str,
        content: str,
        branch: str,
        message: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Commit a single test file to a branch.

        Gets the current file content (if exists) to get the SHA for updates,
        then creates or updates the file.

        Args:
            client: GitHubClient instance
            file_path: Path in the repository
            content: File content (plain text)
            branch: Branch to commit to
            message: Optional commit message

        Returns:
            API response dict
        """
        # Get existing file content and SHA (if file exists)
        try:
            existing_content, sha = await client.get_file_content(file_path, branch=branch)
        except GitHubAPIError:
            existing_content, sha = "", None

        # Generate commit message if not provided
        if not message:
            module_name = file_path.split("/")[-1].replace("_test.py", "").replace("test_", "")
            func_count = content.count("def test_")
            message = f"Add tests for {module_name}: {func_count} tests"

        # Create or update the file
        return await client.create_or_update_file(
            path=file_path,
            content=content,
            message=message,
            branch=branch,
            sha=sha,
        )

    # ------------------------------------------------------------------
    # Status and utility
    # ------------------------------------------------------------------

    def get_last_result(self) -> Optional[Dict[str, Any]]:
        """Get the result of the last PR creation workflow."""
        return self._last_result

    def get_pr_summary(self) -> Dict[str, Any]:
        """Get a summary of the PR agent's current state."""
        return {
            "agent": self.name,
            "role": self.role,
            "pat_configured": self._check_pat_configured(),
            "owner": self.owner,
            "repo": self.repo,
            "default_branch": self.default_branch,
            "last_result": self._last_result,
        }

    # ------------------------------------------------------------------
    # Capabilities overrides
    # ------------------------------------------------------------------

    def _requires_network(self) -> bool:
        """PR Agent requires network access for GitHub API calls."""
        return True

    def _get_supported_languages(self) -> List[str]:
        """Supports all languages (test files are language-agnostic for PR creation)."""
        return ["*"]

    def _get_categories(self) -> List[str]:
        """Return the agent's capability categories."""
        return ["pr_automation", "github_integration", "test_deployment"]
