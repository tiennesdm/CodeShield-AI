"""
GitHub repository cloning and handling for CodeShield AI.

Clones GitHub repositories for scanning using GitPython or subprocess.
"""

import asyncio
import os
import re
import shutil
from pathlib import Path
from typing import Optional, Tuple
from urllib.parse import urlparse

from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)


class GitHubHandler:
    """
    Handles cloning and validation of Git repositories (GitHub, GitLab, Bitbucket).

    Supports HTTPS URLs and extracts repository metadata.
    """

    # Regex for validating Git URLs (GitHub, GitLab, Bitbucket)
    GIT_URL_PATTERN = re.compile(
        r"^https://(github\.com|gitlab\.com|bitbucket\.org)/[a-zA-Z0-9_.-]+/[a-zA-Z0-9_.-]+(/.*)?$"
    )

    def __init__(self) -> None:
        """Initialize the GitHub handler."""
        self.settings = get_settings()

    def validate_url(self, url: str) -> Tuple[bool, str]:
        """
        Validate a Git URL format.

        Args:
            url: The Git URL to validate

        Returns:
            Tuple of (is_valid, error_message)
        """
        if not url:
            return False, "URL is empty"

        valid_prefixes = ["https://github.com/", "https://gitlab.com/", "https://bitbucket.org/"]
        if not any(url.startswith(prefix) for prefix in valid_prefixes):
            return False, "URL must start with https://github.com/, https://gitlab.com/, or https://bitbucket.org/"

        # Use proper URL parsing to prevent URL injection attacks
        try:
            parsed = urlparse(url)
            if parsed.scheme != "https" or parsed.hostname not in ["github.com", "gitlab.com", "bitbucket.org"]:
                return False, "Invalid Git repository URL format"
            if not parsed.path or parsed.path.count("/") < 2:
                return False, "Invalid Git repository path"
        except Exception:
            return False, "Invalid URL format"

        if not self.GIT_URL_PATTERN.match(url):
            return False, "Invalid Git repository URL format"

        return True, ""

    def extract_repo_info(self, url: str) -> Tuple[str, str]:
        """
        Extract owner and repo name from Git URL.

        Args:
            url: Git repository URL

        Returns:
            Tuple of (owner, repo_name)
        """
        # Remove trailing slash and .git
        url = url.rstrip("/").replace(".git", "")
        parts = url.split("/")

        # URL format: https://domain.com/{owner}/{repo}
        if len(parts) >= 5:
            return parts[3], parts[4]

        return "unknown", "unknown"

    async def clone_repository(self, url: str, scan_id: str, branch: Optional[str] = None) -> str:
        """
        Clone a Git repository.

        Args:
            url: Git repository URL
            scan_id: Scan identifier for directory naming
            branch: Optional branch name to clone

        Returns:
            Path to the cloned repository

        Raises:
            ValueError: If URL is invalid
            RuntimeError: If cloning fails
        """
        # Validate URL
        is_valid, error = self.validate_url(url)
        if not is_valid:
            raise ValueError(f"Invalid Git URL: {error}")

        # Create clone directory
        owner, repo = self.extract_repo_info(url)
        # Sanitize repo name for use in path
        safe_repo = re.sub(r"[^a-zA-Z0-9_.-]", "_", repo)
        clone_dir = self.settings.temp_dir / f"github_{scan_id}_{safe_repo}"

        # Remove existing directory if present
        if clone_dir.exists():
            shutil.rmtree(clone_dir, ignore_errors=True)

        logger.info("Cloning %s/%s (branch: %s) to %s", owner, safe_repo, branch or "default", clone_dir)

        timeout = getattr(self.settings, "github_clone_timeout", 120)

        try:
            # Build git clone command parameters
            cmd = ["git", "clone", "--depth", "1"]
            if branch:
                cmd.extend(["--branch", branch])
            cmd.extend([url, str(clone_dir)])

            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(), timeout=timeout
            )

            if process.returncode != 0:
                error_msg = stderr.decode("utf-8", errors="ignore") if stderr else "Unknown error"
                raise RuntimeError(f"Git clone failed: {error_msg}")

            logger.info("Successfully cloned %s/%s", owner, safe_repo)
            return str(clone_dir)

        except asyncio.TimeoutError:
            # Kill the process if it timed out
            try:
                process.kill()
                await process.wait()
            except Exception:
                pass
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise RuntimeError(f"Git clone timed out after {timeout} seconds")
        except FileNotFoundError:
            raise RuntimeError("Git is not installed or not in PATH")
        except RuntimeError:
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise
        except Exception as e:
            shutil.rmtree(clone_dir, ignore_errors=True)
            raise RuntimeError(f"Failed to clone repository: {str(e)}")

    async def clone_with_gitpython(self, url: str, scan_id: str, branch: Optional[str] = None) -> str:
        """
        Clone a repository using GitPython (alternative method).

        Args:
            url: Git repository URL
            scan_id: Scan identifier
            branch: Optional branch name to clone

        Returns:
            Path to the cloned repository
        """
        try:
            import git

            owner, repo = self.extract_repo_info(url)
            safe_repo = re.sub(r"[^a-zA-Z0-9_.-]", "_", repo)
            clone_dir = self.settings.temp_dir / f"github_{scan_id}_{safe_repo}"

            if clone_dir.exists():
                shutil.rmtree(clone_dir, ignore_errors=True)

            logger.info("Cloning with GitPython: %s (branch: %s)", url, branch or "default")
            
            kwargs = {"depth": 1}
            if branch:
                kwargs["branch"] = branch
                
            git.Repo.clone_from(url, str(clone_dir), **kwargs)

            return str(clone_dir)

        except ImportError:
            logger.warning("GitPython not installed, falling back to subprocess")
            return await self.clone_repository(url, scan_id, branch)
        except Exception as e:
            raise RuntimeError(f"GitPython clone failed: {str(e)}")
