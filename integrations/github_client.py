"""
GitHub API Client for CodeShield AI PR Automation.

Provides a robust, retry-aware client for GitHub API operations including:
- Branch creation
- File content retrieval and updates
- Pull request creation and labeling
- Connection testing

All methods use Authorization: token {PAT} headers with automatic retries
and exponential backoff for resilience against transient failures.
"""

import asyncio
import base64
import json
import logging
from typing import Any, Dict, List, Optional, Tuple

import aiohttp

logger = logging.getLogger(__name__)


class GitHubAPIError(Exception):
    """Raised when the GitHub API returns an error response."""

    def __init__(self, message: str, status_code: int = None, response_body: str = None):
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class GitHubClient:
    """
    Async GitHub API client with automatic retries and error handling.

    Args:
        pat: Personal Access Token for authentication
        owner: Repository owner (user or organization)
        repo: Repository name
        timeout: Request timeout in seconds (default: 30)
        max_retries: Number of retries for transient failures (default: 3)
        retry_backoff: Exponential backoff multiplier (default: 1.5)
        api_base_url: GitHub API base URL (default: https://api.github.com)
    """

    def __init__(
        self,
        pat: str,
        owner: str,
        repo: str,
        timeout: int = 30,
        max_retries: int = 3,
        retry_backoff: float = 1.5,
        api_base_url: str = "https://api.github.com",
    ) -> None:
        self.pat = pat
        self.owner = owner
        self.repo = repo
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_backoff = retry_backoff
        self.api_base_url = api_base_url
        self._session: Optional[aiohttp.ClientSession] = None

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def headers(self) -> Dict[str, str]:
        """Return the default Authorization headers for GitHub API requests."""
        return {
            "Authorization": f"token {self.pat}",
            "Accept": "application/vnd.github.v3+json",
            "Content-Type": "application/json",
            "User-Agent": "CodeShield-AI-PR-Agent/1.0",
        }

    @property
    def repo_api_url(self) -> str:
        """Return the repository API base URL."""
        return f"{self.api_base_url}/repos/{self.owner}/{self.repo}"

    # ------------------------------------------------------------------
    # Session management
    # ------------------------------------------------------------------

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create an aiohttp ClientSession."""
        if self._session is None or self._session.closed:
            self._session = aiohttp.ClientSession(
                headers=self.headers,
                timeout=aiohttp.ClientTimeout(total=self.timeout),
            )
        return self._session

    async def close(self) -> None:
        """Close the underlying HTTP session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None

    # ------------------------------------------------------------------
    # Core request handler with retries
    # ------------------------------------------------------------------

    async def _request(
        self,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> Tuple[int, Any]:
        """
        Make an HTTP request with automatic retries and exponential backoff.

        Handles:
        - 404 Not Found (no retry, raise immediately)
        - 409 Conflict (retry with backoff)
        - 5xx Server errors (retry with backoff)
        - Network timeouts (retry with backoff)

        Args:
            method: HTTP method (GET, POST, PUT, etc.)
            url: Request URL
            **kwargs: Additional aiohttp request kwargs

        Returns:
            Tuple of (status_code, response_json)

        Raises:
            GitHubAPIError: On non-retryable errors or max retries exceeded
        """
        session = await self._get_session()
        last_error: Optional[Exception] = None

        for attempt in range(1, self.max_retries + 1):
            try:
                async with session.request(method, url, **kwargs) as response:
                    status = response.status
                    body_text = await response.text()

                    # Try to parse JSON; fall back to text
                    try:
                        body = json.loads(body_text) if body_text else {}
                    except json.JSONDecodeError:
                        body = {"raw": body_text}

                    # Success
                    if status in (200, 201, 204):
                        return status, body

                    # 404 Not Found - don't retry, raise immediately
                    if status == 404:
                        raise GitHubAPIError(
                            f"GitHub API 404: {body.get('message', 'Not Found')} for {url}",
                            status_code=404,
                            response_body=body_text,
                        )

                    # 409 Conflict - retry with backoff
                    if status == 409:
                        if attempt < self.max_retries:
                            wait = self.retry_backoff ** attempt
                            logger.warning(
                                "GitHub API 409 conflict on %s %s (attempt %d/%d), "
                                "retrying in %.1fs...",
                                method, url, attempt, self.max_retries, wait,
                            )
                            await asyncio.sleep(wait)
                            continue
                        raise GitHubAPIError(
                            f"GitHub API 409: Conflict after {self.max_retries} retries for {url}",
                            status_code=409,
                            response_body=body_text,
                        )

                    # 5xx Server errors - retry with backoff
                    if 500 <= status < 600:
                        if attempt < self.max_retries:
                            wait = self.retry_backoff ** attempt
                            logger.warning(
                                "GitHub API %d on %s %s (attempt %d/%d), "
                                "retrying in %.1fs...",
                                status, method, url, attempt, self.max_retries, wait,
                            )
                            await asyncio.sleep(wait)
                            continue
                        raise GitHubAPIError(
                            f"GitHub API {status}: Server error after {self.max_retries} retries for {url}",
                            status_code=status,
                            response_body=body_text,
                        )

                    # 4xx client errors (other than 404) - don't retry
                    if 400 <= status < 500:
                        raise GitHubAPIError(
                            f"GitHub API {status}: {body.get('message', 'Client error')} for {url}",
                            status_code=status,
                            response_body=body_text,
                        )

                    # Unexpected status
                    raise GitHubAPIError(
                        f"GitHub API unexpected status {status}: {body.get('message', '')} for {url}",
                        status_code=status,
                        response_body=body_text,
                    )

            except GitHubAPIError:
                raise
            except asyncio.TimeoutError:
                wait = self.retry_backoff ** attempt
                last_error = asyncio.TimeoutError(
                    f"Request timeout for {method} {url} (attempt {attempt}/{self.max_retries})"
                )
                if attempt < self.max_retries:
                    logger.warning(
                        "Timeout on %s %s (attempt %d/%d), retrying in %.1fs...",
                        method, url, attempt, self.max_retries, wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise GitHubAPIError(
                    f"Request timeout after {self.max_retries} retries for {method} {url}",
                    status_code=0,
                ) from last_error
            except aiohttp.ClientError as e:
                wait = self.retry_backoff ** attempt
                last_error = e
                if attempt < self.max_retries:
                    logger.warning(
                        "Network error on %s %s (attempt %d/%d): %s, retrying in %.1fs...",
                        method, url, attempt, self.max_retries, e, wait,
                    )
                    await asyncio.sleep(wait)
                    continue
                raise GitHubAPIError(
                    f"Network error after {self.max_retries} retries for {method} {url}: {e}",
                    status_code=0,
                ) from last_error

        # Should not reach here, but just in case
        raise GitHubAPIError(
            f"Max retries ({self.max_retries}) exceeded for {method} {url}",
            status_code=0,
        )

    # ------------------------------------------------------------------
    # Branch operations
    # ------------------------------------------------------------------

    async def get_default_branch(self) -> str:
        """
        Get the default branch name for the repository.

        Returns:
            The default branch name (e.g., 'main' or 'master')
        """
        url = self.repo_api_url
        status, body = await self._request("GET", url)
        default_branch = body.get("default_branch", "main")
        logger.info("Default branch for %s/%s: %s", self.owner, self.repo, default_branch)
        return default_branch

    async def get_branch_sha(self, branch_name: str) -> str:
        """
        Get the SHA of the latest commit on a branch.

        Args:
            branch_name: Name of the branch

        Returns:
            Commit SHA string

        Raises:
            GitHubAPIError: If the branch does not exist
        """
        url = f"{self.repo_api_url}/git/ref/heads/{branch_name}"
        status, body = await self._request("GET", url)
        sha = body["object"]["sha"]
        logger.debug("SHA for branch '%s': %s", branch_name, sha)
        return sha

    async def create_branch(self, branch_name: str, from_branch: str = "main") -> Dict[str, Any]:
        """
        Create a new branch from an existing branch.

        Args:
            branch_name: Name for the new branch
            from_branch: Branch to create from (default: main)

        Returns:
            API response dict with the new branch ref info
        """
        try:
            base_sha = await self.get_branch_sha(from_branch)
        except GitHubAPIError as e:
            if e.status_code == 404:
                # Try 'master' as fallback if 'main' doesn't exist
                if from_branch == "main":
                    logger.warning("Branch 'main' not found, trying 'master'")
                    base_sha = await self.get_branch_sha("master")
                else:
                    raise
            else:
                raise

        url = f"{self.repo_api_url}/git/refs"
        payload = {
            "ref": f"refs/heads/{branch_name}",
            "sha": base_sha,
        }

        status, body = await self._request("POST", url, json=payload)
        logger.info(
            "Created branch '%s' from '%s' (SHA: %s)",
            branch_name, from_branch, base_sha,
        )
        return body

    # ------------------------------------------------------------------
    # File operations
    # ------------------------------------------------------------------

    async def get_file_content(self, path: str, branch: str = "main") -> Tuple[str, Optional[str]]:
        """
        Get the content and SHA of a file from the repository.

        Args:
            path: File path within the repository
            branch: Branch to read from (default: main)

        Returns:
            Tuple of (decoded_content, sha). Content is decoded from base64.
            sha is None if the file doesn't exist.

        Raises:
            GitHubAPIError: On API errors (except 404, which returns ("", None))
        """
        url = f"{self.repo_api_url}/contents/{path}?ref={branch}"

        try:
            status, body = await self._request("GET", url)

            # Handle both single file and directory responses
            if isinstance(body, dict) and "content" in body:
                content_b64 = body["content"].replace("\n", "")
                decoded = base64.b64decode(content_b64).decode("utf-8")
                sha = body.get("sha")
                logger.debug("Retrieved file '%s' (SHA: %s, %d bytes)", path, sha, len(decoded))
                return decoded, sha
            elif isinstance(body, list):
                # It's a directory, not a file
                raise GitHubAPIError(
                    f"Path '{path}' is a directory, not a file",
                    status_code=422,
                )
            else:
                raise GitHubAPIError(
                    f"Unexpected response format for file '{path}'",
                    status_code=status,
                )

        except GitHubAPIError as e:
            if e.status_code == 404:
                logger.debug("File '%s' not found on branch '%s'", path, branch)
                return "", None
            raise

    async def create_or_update_file(
        self,
        path: str,
        content: str,
        message: str,
        branch: str,
        sha: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Create a new file or update an existing file in the repository.

        Args:
            path: File path within the repository
            content: File content (plain text, will be base64 encoded)
            message: Commit message
            branch: Branch to commit to
            sha: SHA of the existing file (required for updates, omit for creation)

        Returns:
            API response dict with commit info
        """
        url = f"{self.repo_api_url}/contents/{path}"
        content_b64 = base64.b64encode(content.encode("utf-8")).decode("utf-8")

        payload: Dict[str, Any] = {
            "message": message,
            "content": content_b64,
            "branch": branch,
        }

        if sha:
            payload["sha"] = sha

        status, body = await self._request("PUT", url, json=payload)

        action = "Updated" if sha else "Created"
        logger.info(
            "%s file '%s' on branch '%s' (%d bytes)",
            action, path, branch, len(content),
        )
        return body

    # ------------------------------------------------------------------
    # Pull Request operations
    # ------------------------------------------------------------------

    async def create_pull_request(
        self,
        title: str,
        body: str,
        head: str,
        base: str = "main",
    ) -> Dict[str, Any]:
        """
        Create a new pull request.

        Args:
            title: PR title
            body: PR description/body (supports Markdown)
            head: Branch containing the changes
            base: Branch to merge into (default: main)

        Returns:
            API response dict with PR info including 'number'
        """
        url = f"{self.repo_api_url}/pulls"
        payload = {
            "title": title,
            "body": body,
            "head": head,
            "base": base,
        }

        status, response_body = await self._request("POST", url, json=payload)
        pr_number = response_body.get("number", "?")
        pr_url = response_body.get("html_url", "")
        logger.info(
            "Created PR #%s: '%s' (%s)",
            pr_number, title, pr_url,
        )
        return response_body

    async def add_labels(self, pr_number: int, labels: List[str]) -> Dict[str, Any]:
        """
        Add labels to a pull request.

        Args:
            pr_number: Pull request number
            labels: List of label names to add

        Returns:
            API response dict with the updated labels list
        """
        url = f"{self.repo_api_url}/issues/{pr_number}/labels"
        payload = {"labels": labels}

        status, body = await self._request("POST", url, json=payload)
        logger.info("Added labels %s to PR #%d", labels, pr_number)
        return body

    # ------------------------------------------------------------------
    # Utility methods
    # ------------------------------------------------------------------

    async def test_connection(self) -> bool:
        """
        Test the GitHub API connection and authentication.

        Returns:
            True if the connection is successful and the token has repo access
        """
        try:
            url = self.repo_api_url
            status, body = await self._request("GET", url)

            # Check we have push access
            permissions = body.get("permissions", {})
            has_push = permissions.get("push", False)
            has_pull = permissions.get("pull", False)

            if has_pull:
                logger.info(
                    "GitHub connection OK for %s/%s (push=%s)",
                    self.owner, self.repo, has_push,
                )
                return True
            else:
                logger.warning(
                    "GitHub token lacks pull access for %s/%s",
                    self.owner, self.repo,
                )
                return False

        except GitHubAPIError as e:
            logger.error("GitHub connection test failed: %s", e)
            return False
        except Exception as e:
            logger.error("Unexpected error testing GitHub connection: %s", e)
            return False

    async def list_pull_requests(
        self,
        state: str = "open",
        head: Optional[str] = None,
        base: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        List pull requests for the repository.

        Args:
            state: Filter by state (open, closed, all)
            head: Filter by head branch
            base: Filter by base branch

        Returns:
            List of PR dicts
        """
        params: Dict[str, str] = {"state": state}
        if head:
            params["head"] = f"{self.owner}:{head}"
        if base:
            params["base"] = base

        query = "&".join(f"{k}={v}" for k, v in params.items())
        url = f"{self.repo_api_url}/pulls?{query}"

        status, body = await self._request("GET", url)
        if isinstance(body, list):
            return body
        return []

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit - ensures session cleanup."""
        await self.close()
