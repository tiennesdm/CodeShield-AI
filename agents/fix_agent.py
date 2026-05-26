"""
Fix Agent - Automated Security Remediation for CodeShield AI.

Post-processing agent that generates, validates, and applies security fixes
for triaged findings. Supports deterministic codemods, LLM-powered fixes,
and automated PR/MR creation via GitHub/GitLab APIs.

Features:
- Priority queue for fix ordering (CRITICAL first)
- Batch fixes for same-file groupings
- Dependency-aware fix ordering
- Fix validation (syntax + pattern verification)
- Unified diff generation
- Backup and rollback capability
- GitHub/GitLab PR/MR creation
- CrewAI-compatible Agent interface
"""

import asyncio
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from models.vulnerability import SeverityLevel, Vulnerability
from auto_fix import AutoFixEngine, AutoFixResult, FixStatus
from ai_triage import AITriageEngine
from utils.logger import get_logger

logger = get_logger(__name__)

# ---------------------------------------------------------------------------
# Configuration (overridable via environment variables)
# ---------------------------------------------------------------------------

FIX_BATCH_SIZE = int(os.environ.get("CS_FIX_BATCH_SIZE", "10"))
ENABLE_PR_CREATION = os.environ.get("CS_FIX_ENABLE_PR", "true").lower() == "true"
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN", "")
GITLAB_TOKEN = os.environ.get("GITLAB_TOKEN", "")
BACKUP_ENABLED = os.environ.get("CS_FIX_BACKUP", "true").lower() == "true"

# Dependency ordering: categories that must be fixed before others
FIX_DEPENDENCY_ORDER: Dict[str, int] = {
    "Input Validation": 0,
    "Data Validation": 0,
    "Missing Headers": 1,
    "CORS": 1,
    "Hardcoded Secret": 2,
    "Weak Crypto": 3,
    "SQL Injection": 4,
    "XSS": 4,
    "Code Injection": 4,
    "Command Injection": 4,
    "Path Traversal": 5,
    "Authentication Bypass": 6,
    "Authorization Bypass": 6,
}

# Category grouping for batching
CATEGORY_TO_PRIORITY: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}


class FixApplicationStatus(str, Enum):
    """Status of fix application to a file."""

    PENDING = "pending"
    APPLIED = "applied"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    VALIDATED = "validated"


class VCSProvider(str, Enum):
    """Version control system provider."""

    GITHUB = "github"
    GITLAB = "gitlab"


@dataclass
class FixQueueItem:
    """An item in the fix priority queue."""

    vuln: Vulnerability
    priority_score: float = 0.0
    dependency_order: int = 99
    file_path: str = ""
    estimated_fix_time: int = 30  # minutes
    fix_result: Optional[AutoFixResult] = None
    application_status: FixApplicationStatus = FixApplicationStatus.PENDING
    backup_path: Optional[str] = None
    error_message: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "vuln_id": self.vuln.id,
            "priority_score": round(self.priority_score, 2),
            "dependency_order": self.dependency_order,
            "file_path": self.file_path,
            "estimated_fix_time": self.estimated_fix_time,
            "fix_status": self.fix_result.status.value if self.fix_result else None,
            "application_status": self.application_status.value,
            "backup_path": self.backup_path,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat(),
        }


@dataclass
class FixBatch:
    """A batch of fixes for the same file."""

    file_path: str
    items: List[FixQueueItem] = field(default_factory=list)
    combined_diff: str = ""
    application_status: FixApplicationStatus = FixApplicationStatus.PENDING
    backup_path: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "file_path": self.file_path,
            "item_count": len(self.items),
            "items": [item.to_dict() for item in self.items],
            "combined_diff_length": len(self.combined_diff),
            "application_status": self.application_status.value,
            "backup_path": self.backup_path,
        }


@dataclass
class PullRequestResult:
    """Result of a PR/MR creation."""

    success: bool = False
    provider: str = ""
    pr_url: str = ""
    branch_name: str = ""
    commit_sha: str = ""
    fixes_count: int = 0
    error_message: Optional[str] = None
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "provider": self.provider,
            "pr_url": self.pr_url,
            "branch_name": self.branch_name,
            "commit_sha": self.commit_sha,
            "fixes_count": self.fixes_count,
            "error_message": self.error_message,
            "created_at": self.created_at.isoformat(),
        }


class FixAgent:
    """
    Fix Agent - Automated Security Remediation.

    Manages the full fix lifecycle:
    1. Priority queue for fix ordering
    2. Batch fixes for same-file groupings
    3. Dependency-aware ordering
    4. Fix generation (deterministic + LLM)
    5. Fix validation (syntax + pattern)
    6. Fix application with backup
    7. PR/MR creation via GitHub/GitLab APIs

    Compatible with CrewAI agent interfaces.
    """

    def __init__(
        self,
        auto_fix_engine: Optional[AutoFixEngine] = None,
        ai_triage_engine: Optional[AITriageEngine] = None,
    ) -> None:
        """
        Initialize the Fix Agent.

        Args:
            auto_fix_engine: AutoFixEngine instance
            ai_triage_engine: AITriageEngine instance
        """
        self.auto_fix_engine = auto_fix_engine or AutoFixEngine()
        self.ai_triage_engine = ai_triage_engine or AITriageEngine()
        self._queue: List[FixQueueItem] = []
        self._batches: Dict[str, FixBatch] = {}
        self._backups: Dict[str, str] = {}  # file_path -> backup_path
        self._applied_fixes: List[FixQueueItem] = []
        logger.info("FixAgent initialized")

    # ========================================================================
    # A. Fix Queue Management
    # ========================================================================

    def _compute_priority_score(self, vuln: Vulnerability) -> float:
        """
        Compute priority score for a fix item.

        Higher score = higher priority.
        Based on: severity weight + confidence bonus + category weight.

        Args:
            vuln: Vulnerability

        Returns:
            Priority score (float)
        """
        severity_scores = {
            "CRITICAL": 100.0,
            "HIGH": 75.0,
            "MEDIUM": 50.0,
            "LOW": 25.0,
            "INFO": 10.0,
        }
        base = severity_scores.get(vuln.severity.upper(), 25.0)

        # Confidence bonus
        confidence_bonus = {
            "HIGH": 15.0,
            "MEDIUM": 5.0,
            "LOW": -10.0,
        }.get(vuln.confidence.upper(), 0.0)

        # Exploitation bonus
        exploit_bonus = 20.0 if "confirmed" in vuln.description.lower() else 0.0

        return base + confidence_bonus + exploit_bonus

    def _get_dependency_order(self, vuln: Vulnerability) -> int:
        """
        Get dependency order for a vulnerability category.

        Lower numbers should be fixed first.

        Args:
            vuln: Vulnerability

        Returns:
            Dependency order integer
        """
        cat_lower = vuln.category.lower()
        for category, order in FIX_DEPENDENCY_ORDER.items():
            if category.lower() in cat_lower:
                return order
        return 99  # Default: last

    def build_fix_queue(
        self,
        vulnerabilities: List[Vulnerability],
        triage_results: Optional[List[Any]] = None,
    ) -> List[FixQueueItem]:
        """
        Build a prioritized fix queue from vulnerabilities.

        Args:
            vulnerabilities: List of vulnerabilities to fix
            triage_results: Optional triage results for priority adjustment

        Returns:
            Prioritized list of fix queue items
        """
        queue: List[FixQueueItem] = []

        for vuln in vulnerabilities:
            item = FixQueueItem(
                vuln=vuln,
                priority_score=self._compute_priority_score(vuln),
                dependency_order=self._get_dependency_order(vuln),
                file_path=vuln.file_path,
            )
            queue.append(item)

        # Sort: dependency_order ascending, then priority_score descending
        queue.sort(key=lambda x: (x.dependency_order, -x.priority_score))

        self._queue = queue
        logger.info("Fix queue built: %d items", len(queue))
        return queue

    def create_batches(self, queue: List[FixQueueItem]) -> Dict[str, FixBatch]:
        """
        Group fix items into batches by file path.

        Args:
            queue: Fix queue items

        Returns:
            Dict of file_path -> FixBatch
        """
        batches: Dict[str, FixBatch] = {}

        for item in queue:
            fp = item.file_path
            if fp not in batches:
                batches[fp] = FixBatch(file_path=fp)
            batches[fp].items.append(item)

        # Sort items within each batch by dependency order, then priority
        for batch in batches.values():
            batch.items.sort(key=lambda x: (x.dependency_order, -x.priority_score))

        self._batches = batches
        logger.info("Created %d fix batches", len(batches))
        return batches

    # ========================================================================
    # B. Fix Generation
    # ========================================================================

    async def generate_fixes(
        self,
        queue: List[FixQueueItem],
        source_path: Optional[str] = None,
    ) -> List[FixQueueItem]:
        """
        Generate fixes for all items in the queue.

        Args:
            queue: Fix queue items
            source_path: Path to source code

        Returns:
            Updated queue items with fix results
        """
        logger.info("Generating fixes for %d queue items", len(queue))

        tasks = []
        for item in queue:
            task = self.auto_fix_engine.generate_fix(
                item.vuln,
                source_path=source_path,
                use_llm=True,
            )
            tasks.append((item, task))

        # Run fixes concurrently with semaphore to limit parallelism
        semaphore = asyncio.Semaphore(5)

        async def _run_fix(
            item: FixQueueItem, task: Any
        ) -> FixQueueItem:
            async with semaphore:
                try:
                    result = await task
                    item.fix_result = result
                    if result.status in (FixStatus.SUCCESS, FixStatus.PARTIAL):
                        logger.debug(
                            "Fix generated for %s (%s)",
                            item.vuln.id,
                            result.fix_type,
                        )
                    else:
                        logger.debug(
                            "Fix generation %s for %s: %s",
                            result.status.value,
                            item.vuln.id,
                            result.error_message,
                        )
                except Exception as e:
                    logger.error("Fix generation failed for %s: %s", item.vuln.id, e)
                    item.fix_result = AutoFixResult(
                        vuln_id=item.vuln.id,
                        status=FixStatus.FAILED,
                        error_message=str(e),
                        fix_type="none",
                        description="Fix generation threw exception",
                    )
                return item

        results = await asyncio.gather(
            *[_run_fix(item, task) for item, task in tasks]
        )

        successful = sum(
            1
            for r in results
            if r.fix_result
            and r.fix_result.status in (FixStatus.SUCCESS, FixStatus.PARTIAL)
        )
        logger.info(
            "Fix generation complete: %d/%d successful",
            successful,
            len(results),
        )

        return list(results)

    # ========================================================================
    # C. Fix Application
    # ========================================================================

    async def apply_fix(
        self,
        item: FixQueueItem,
        source_path: str,
        create_backup: bool = True,
    ) -> Dict[str, Any]:
        """
        Apply a single fix to the source file.

        Args:
            item: Fix queue item with generated fix
            source_path: Source code directory
            create_backup: Whether to create backup

        Returns:
            Result dict with success status
        """
        if not item.fix_result or not item.fix_result.fixed_code:
            return {"success": False, "error": "No fix available"}

        file_path = os.path.join(source_path, item.vuln.file_path)

        if not os.path.exists(file_path):
            return {"success": False, "error": f"File not found: {file_path}"}

        try:
            # Create backup
            if create_backup and BACKUP_ENABLED:
                backup_path = await self._create_backup(file_path)
                item.backup_path = backup_path
                self._backups[file_path] = backup_path

            # Read original content
            with open(file_path, "r", encoding="utf-8") as f:
                original_content = f.read()

            # Get vulnerable code
            vulnerable_code = item.fix_result.original_code
            if not vulnerable_code:
                return {"success": False, "error": "No vulnerable code captured"}

            # Apply fix
            fixed_content = original_content.replace(
                vulnerable_code.strip(),
                item.fix_result.fixed_code.strip(),
                1,
            )

            if fixed_content == original_content:
                # Try with looser matching
                fixed_content = self._fuzzy_replace(
                    original_content,
                    vulnerable_code.strip(),
                    item.fix_result.fixed_code.strip(),
                )

            if fixed_content == original_content:
                return {
                    "success": False,
                    "error": "Could not locate vulnerable code in file",
                }

            # Validate syntax before writing
            if file_path.endswith(".py"):
                try:
                    import ast

                    ast.parse(fixed_content)
                except SyntaxError as e:
                    item.application_status = FixApplicationStatus.FAILED
                    return {
                        "success": False,
                        "error": f"Fix introduces syntax error: {e}",
                    }

            # Write fixed content
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(fixed_content)

            item.application_status = FixApplicationStatus.APPLIED
            self._applied_fixes.append(item)

            logger.info("Applied fix to %s for %s", file_path, item.vuln.id)
            return {
                "success": True,
                "file_path": file_path,
                "backup_path": item.backup_path,
                "diff": item.fix_result.diff,
            }

        except Exception as e:
            item.application_status = FixApplicationStatus.FAILED
            item.error_message = str(e)
            logger.error("Failed to apply fix to %s: %s", file_path, e)
            return {"success": False, "error": str(e)}

    async def apply_batch_fixes(
        self,
        batch: FixBatch,
        source_path: str,
        create_backup: bool = True,
    ) -> Dict[str, Any]:
        """
        Apply all fixes in a batch for a single file.

        Args:
            batch: Fix batch
            source_path: Source code directory
            create_backup: Whether to create backup

        Returns:
            Result dict with success status
        """
        file_path = os.path.join(source_path, batch.file_path)

        if not os.path.exists(file_path):
            return {"success": False, "error": f"File not found: {file_path}"}

        try:
            # Create single backup for the batch
            if create_backup and BACKUP_ENABLED:
                backup_path = await self._create_backup(file_path)
                batch.backup_path = backup_path
                self._backups[file_path] = backup_path

            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            original_content = content
            applied = 0
            failed = 0
            diffs = []

            for item in batch.items:
                if not item.fix_result or not item.fix_result.fixed_code:
                    continue

                vulnerable_code = item.fix_result.original_code
                if not vulnerable_code:
                    failed += 1
                    continue

                new_content = content.replace(
                    vulnerable_code.strip(),
                    item.fix_result.fixed_code.strip(),
                    1,
                )

                if new_content != content:
                    content = new_content
                    item.application_status = FixApplicationStatus.APPLIED
                    applied += 1
                    diffs.append(item.fix_result.diff or "")
                    self._applied_fixes.append(item)
                else:
                    # Try fuzzy replace
                    new_content = self._fuzzy_replace(
                        content,
                        vulnerable_code.strip(),
                        item.fix_result.fixed_code.strip(),
                    )
                    if new_content != content:
                        content = new_content
                        item.application_status = FixApplicationStatus.APPLIED
                        applied += 1
                        diffs.append(item.fix_result.diff or "")
                        self._applied_fixes.append(item)
                    else:
                        item.application_status = FixApplicationStatus.FAILED
                        failed += 1

            # Validate syntax
            if file_path.endswith(".py"):
                try:
                    import ast

                    ast.parse(content)
                except SyntaxError as e:
                    # Rollback
                    with open(file_path, "w", encoding="utf-8") as f:
                        f.write(original_content)
                    batch.application_status = FixApplicationStatus.FAILED
                    return {
                        "success": False,
                        "error": f"Batch fix introduces syntax error: {e}",
                        "applied": applied,
                        "rolled_back": True,
                    }

            # Write final content
            with open(file_path, "w", encoding="utf-8") as f:
                f.write(content)

            batch.combined_diff = "\n".join(diffs)
            batch.application_status = FixApplicationStatus.APPLIED

            logger.info(
                "Batch fix applied to %s: %d applied, %d failed",
                file_path,
                applied,
                failed,
            )

            return {
                "success": True,
                "file_path": file_path,
                "applied": applied,
                "failed": failed,
                "backup_path": batch.backup_path,
                "diff": batch.combined_diff,
            }

        except Exception as e:
            batch.application_status = FixApplicationStatus.FAILED
            logger.error("Batch fix failed for %s: %s", file_path, e)
            return {"success": False, "error": str(e)}

    @staticmethod
    def _fuzzy_replace(content: str, old: str, new: str) -> str:
        """
        Attempt a fuzzy replacement when exact match fails.

        Normalizes whitespace for matching.

        Args:
            content: File content
            old: Code to replace
            new: Replacement code

        Returns:
            Updated content
        """
        # Normalize whitespace for matching
        escaped = re.escape(old)
        normalized_old = escaped.replace(r"\ ", r"\s+")
        # Replace all whitespace sequences with \s+ pattern
        normalized_old = re.sub(r"(\\\s)+", r"\\s+", normalized_old)
        try:
            pattern = re.compile(normalized_old, re.MULTILINE)
            match = pattern.search(content)
            if match:
                return content[: match.start()] + new + content[match.end() :]
        except re.error:
            pass
        return content

    async def _create_backup(self, file_path: str) -> str:
        """
        Create a backup of a file before modification.

        Args:
            file_path: Path to file to backup

        Returns:
            Path to backup file
        """
        backup_dir = Path(tempfile.gettempdir()) / "codeshield_fix_backups"
        backup_dir.mkdir(parents=True, exist_ok=True)

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        hash_suffix = hashlib.md5(file_path.encode()).hexdigest()[:8]
        backup_name = f"{Path(file_path).name}.{timestamp}.{hash_suffix}.bak"
        backup_path = str(backup_dir / backup_name)

        shutil.copy2(file_path, backup_path)
        return backup_path

    async def rollback_file(self, file_path: str) -> Dict[str, Any]:
        """
        Rollback a file to its backup.

        Args:
            file_path: Path to file to rollback

        Returns:
            Result dict
        """
        backup = self._backups.get(file_path)
        if not backup or not os.path.exists(backup):
            return {"success": False, "error": "No backup found"}

        try:
            shutil.copy2(backup, file_path)
            logger.info("Rolled back %s from backup", file_path)
            return {"success": True, "file_path": file_path, "backup_path": backup}
        except Exception as e:
            logger.error("Rollback failed for %s: %s", file_path, e)
            return {"success": False, "error": str(e)}

    async def rollback_all(self) -> Dict[str, Any]:
        """
        Rollback all files that have backups.

        Returns:
            Result dict with rollback status per file
        """
        results = {}
        for file_path in list(self._backups.keys()):
            results[file_path] = await self.rollback_file(file_path)

        success_count = sum(1 for r in results.values() if r.get("success"))
        return {
            "total": len(results),
            "successful": success_count,
            "failed": len(results) - success_count,
            "details": results,
        }

    # ========================================================================
    # D. PR Creation
    # ========================================================================

    async def create_pull_request(
        self,
        source_path: str,
        items: List[FixQueueItem],
        provider: VCSProvider = VCSProvider.GITHUB,
        repo_url: Optional[str] = None,
        branch_name: Optional[str] = None,
        base_branch: str = "main",
        token: Optional[str] = None,
    ) -> PullRequestResult:
        """
        Create a pull request with all applied fixes.

        Args:
            source_path: Source code directory
            items: Applied fix items
            provider: VCS provider (github or gitlab)
            repo_url: Repository URL
            branch_name: Branch name for the fix
            base_branch: Base branch to merge into
            token: API token

        Returns:
            PullRequestResult
        """
        if not ENABLE_PR_CREATION:
            return PullRequestResult(
                success=False, error_message="PR creation is disabled"
            )

        if not repo_url:
            return PullRequestResult(
                success=False, error_message="Repository URL is required"
            )

        token = token or (GITHUB_TOKEN if provider == VCSProvider.GITHUB else GITLAB_TOKEN)
        if not token:
            return PullRequestResult(
                success=False, error_message=f"API token required for {provider.value}"
            )

        # Generate branch name
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        branch = branch_name or f"codeshield/security-fixes-{timestamp}"

        try:
            # Create git branch
            subprocess.run(
                ["git", "-C", source_path, "checkout", "-b", branch],
                capture_output=True,
                text=True,
                check=True,
            )

            # Stage changes
            subprocess.run(
                ["git", "-C", source_path, "add", "-A"],
                capture_output=True,
                text=True,
                check=True,
            )

            # Build commit message
            commit_msg = self._build_commit_message(items)

            # Commit
            result = subprocess.run(
                ["git", "-C", source_path, "commit", "-m", commit_msg],
                capture_output=True,
                text=True,
                check=True,
            )

            # Get commit SHA
            sha_result = subprocess.run(
                ["git", "-C", source_path, "rev-parse", "HEAD"],
                capture_output=True,
                text=True,
                check=True,
            )
            commit_sha = sha_result.stdout.strip()

            # Push branch
            try:
                subprocess.run(
                    ["git", "-C", source_path, "push", "origin", branch],
                    capture_output=True,
                    text=True,
                    check=True,
                )
            except subprocess.CalledProcessError:
                logger.warning("Could not push branch - remote may not be configured")

            # Create PR via API
            if provider == VCSProvider.GITHUB:
                pr_result = await self._create_github_pr(
                    repo_url, branch, base_branch, token, items
                )
            else:
                pr_result = await self._create_gitlab_mr(
                    repo_url, branch, base_branch, token, items
                )

            return pr_result

        except subprocess.CalledProcessError as e:
            logger.error("Git command failed: %s", e.stderr)
            return PullRequestResult(
                success=False,
                provider=provider.value,
                branch_name=branch,
                error_message=f"Git command failed: {e.stderr}",
            )
        except FileNotFoundError:
            return PullRequestResult(
                success=False,
                provider=provider.value,
                branch_name=branch,
                error_message="Git not found. Install git to use PR creation.",
            )
        except Exception as e:
            logger.error("PR creation failed: %s", e)
            return PullRequestResult(
                success=False,
                provider=provider.value,
                branch_name=branch,
                error_message=str(e),
            )

    def _build_commit_message(self, items: List[FixQueueItem]) -> str:
        """
        Build a commit message for the fix commit.

        Args:
            items: Applied fix items

        Returns:
            Commit message string
        """
        lines = [
            "fix(security): Address security vulnerabilities",
            "",
            "Auto-remediation by CodeShield AI:",
            "",
        ]

        # Group by category
        by_category: Dict[str, List[str]] = {}
        for item in items:
            cat = item.vuln.category
            if cat not in by_category:
                by_category[cat] = []
            by_category[cat].append(item.vuln.file_path)

        for cat, files in sorted(by_category.items()):
            unique_files = sorted(set(files))
            lines.append(f"- {cat}:")
            for f in unique_files:
                lines.append(f"  - {f}")

        lines.extend(["", "Generated automatically by CodeShield AI"])
        return "\n".join(lines)

    async def _create_github_pr(
        self,
        repo_url: str,
        branch: str,
        base_branch: str,
        token: str,
        items: List[FixQueueItem],
    ) -> PullRequestResult:
        """
        Create a GitHub pull request.

        Args:
            repo_url: Repository URL
            branch: Branch name
            base_branch: Base branch
            token: GitHub token
            items: Fix items

        Returns:
            PullRequestResult
        """
        import urllib.request
        import urllib.parse

        # Extract owner/repo from URL
        match = re.search(r"github\.com/([^/]+)/([^/]+?)(?:\.git)?$", repo_url)
        if not match:
            return PullRequestResult(
                success=False, provider="github", error_message="Invalid GitHub URL"
            )

        owner, repo = match.groups()
        title, body = self._build_pr_description(items)

        url = f"https://api.github.com/repos/{owner}/{repo}/pulls"
        data = json.dumps(
            {
                "title": title,
                "body": body,
                "head": branch,
                "base": base_branch,
            }
        ).encode()

        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "Authorization": f"token {token}",
                "Accept": "application/vnd.github.v3+json",
                "Content-Type": "application/json",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                pr_data = json.loads(resp.read().decode())
                return PullRequestResult(
                    success=True,
                    provider="github",
                    pr_url=pr_data.get("html_url", ""),
                    branch_name=branch,
                    fixes_count=len(items),
                )
        except Exception as e:
            logger.error("GitHub PR creation failed: %s", e)
            return PullRequestResult(
                success=False,
                provider="github",
                branch_name=branch,
                error_message=f"GitHub API error: {e}",
            )

    async def _create_gitlab_mr(
        self,
        repo_url: str,
        branch: str,
        base_branch: str,
        token: str,
        items: List[FixQueueItem],
    ) -> PullRequestResult:
        """
        Create a GitLab merge request.

        Args:
            repo_url: Repository URL
            branch: Branch name
            base_branch: Base branch
            token: GitLab token
            items: Fix items

        Returns:
            PullRequestResult
        """
        import urllib.request
        import urllib.parse

        # Extract project path from URL
        match = re.search(r"gitlab\.com/(.+?)(?:\.git)?$", repo_url)
        if not match:
            return PullRequestResult(
                success=False, provider="gitlab", error_message="Invalid GitLab URL"
            )

        project_path = match.group(1)
        project_id = urllib.parse.quote(project_path, safe="")
        title, body = self._build_pr_description(items)

        url = f"https://gitlab.com/api/v4/projects/{project_id}/merge_requests"
        data = json.dumps(
            {
                "source_branch": branch,
                "target_branch": base_branch,
                "title": title,
                "description": body,
            }
        ).encode()

        req = urllib.request.Request(
            url,
            data=data,
            headers={
                "PRIVATE-TOKEN": token,
                "Content-Type": "application/json",
            },
        )

        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                mr_data = json.loads(resp.read().decode())
                return PullRequestResult(
                    success=True,
                    provider="gitlab",
                    pr_url=mr_data.get("web_url", ""),
                    branch_name=branch,
                    fixes_count=len(items),
                )
        except Exception as e:
            logger.error("GitLab MR creation failed: %s", e)
            return PullRequestResult(
                success=False,
                provider="gitlab",
                branch_name=branch,
                error_message=f"GitLab API error: {e}",
            )

    def _build_pr_description(self, items: List[FixQueueItem]) -> Tuple[str, str]:
        """
        Build PR/MR title and description.

        Args:
            items: Fix items

        Returns:
            Tuple of (title, body)
        """
        critical_count = sum(
            1 for i in items if i.vuln.severity.upper() == "CRITICAL"
        )
        high_count = sum(1 for i in items if i.vuln.severity.upper() == "HIGH")

        title = f"fix(security): Address {len(items)} security vulnerabilities"
        if critical_count > 0:
            title += f" ({critical_count} CRITICAL)"

        body_lines = [
            "## Security Fixes",
            "",
            f"This PR addresses **{len(items)}** security vulnerabilities auto-detected by CodeShield AI.",
            "",
            "### Summary",
            f"- CRITICAL: {critical_count}",
            f"- HIGH: {high_count}",
            f"- Total: {len(items)}",
            "",
            "### Changes",
            "",
        ]

        # Group by file
        by_file: Dict[str, List[FixQueueItem]] = {}
        for item in items:
            fp = item.vuln.file_path
            if fp not in by_file:
                by_file[fp] = []
            by_file[fp].append(item)

        for file_path, file_items in sorted(by_file.items()):
            body_lines.append(f"#### `{file_path}`")
            body_lines.append("")
            for item in file_items:
                body_lines.append(
                    f"- **{item.vuln.category}** ({item.vuln.severity}): {item.fix_result.description if item.fix_result else 'N/A'}"
                )
            body_lines.append("")

        body_lines.extend([
            "### Risk Assessment",
            "",
            "These fixes are automatically generated and should be reviewed before merging.",
            "- [ ] Review each change for correctness",
            "- [ ] Run tests to verify no regressions",
            "- [ ] Verify fix does not change application behavior",
            "",
            "---",
            "*Generated by CodeShield AI*",
        ])

        return title, "\n".join(body_lines)

    # ========================================================================
    # Main Pipeline
    # ========================================================================

    async def run_fix_pipeline(
        self,
        vulnerabilities: List[Vulnerability],
        source_path: str,
        create_pr: bool = False,
        repo_url: Optional[str] = None,
        vcs_provider: VCSProvider = VCSProvider.GITHUB,
    ) -> Dict[str, Any]:
        """
        Run the full fix pipeline.

        1. Build fix queue
        2. Create batches
        3. Generate fixes
        4. Apply fixes
        5. Optionally create PR

        Args:
            vulnerabilities: Vulnerabilities to fix
            source_path: Source code directory
            create_pr: Whether to create a PR
            repo_url: Repository URL for PR
            vcs_provider: VCS provider

        Returns:
            Pipeline result dict
        """
        start_time = datetime.now(timezone.utc)

        # Step 1: Build queue
        queue = self.build_fix_queue(vulnerabilities)

        # Step 2: Create batches
        batches = self.create_batches(queue)

        # Step 3: Generate fixes
        queue = await self.generate_fixes(queue, source_path)

        # Filter to items with successful fixes
        fixable = [item for item in queue if item.fix_result and item.fix_result.fixed_code]

        # Step 4: Apply fixes by batch
        apply_results = []
        for batch in batches.values():
            batch_fixable = [item for item in batch.items if item.fix_result and item.fix_result.fixed_code]
            if not batch_fixable:
                continue

            # Update batch items to the generated ones
            batch.items = batch_fixable
            result = await self.apply_batch_fixes(batch, source_path)
            apply_results.append(result)

        applied_count = sum(r.get("applied", 0) for r in apply_results)
        failed_count = sum(r.get("failed", 0) for r in apply_results)

        # Step 5: Create PR if requested
        pr_result = None
        if create_pr and applied_count > 0:
            applied_items = [item for item in queue if item.application_status == FixApplicationStatus.APPLIED]
            pr_result = await self.create_pull_request(
                source_path=source_path,
                items=applied_items,
                provider=vcs_provider,
                repo_url=repo_url,
            )

        elapsed = (datetime.now(timezone.utc) - start_time).total_seconds()

        return {
            "total_vulnerabilities": len(vulnerabilities),
            "fixable_count": len(fixable),
            "applied": applied_count,
            "failed": failed_count,
            "batches_processed": len(batches),
            "elapsed_seconds": round(elapsed, 2),
            "pr": pr_result.to_dict() if pr_result else None,
            "backup_paths": self._backups,
        }

    async def get_stats(self) -> Dict[str, Any]:
        """Get fix agent statistics."""
        return {
            "fix_batch_size": FIX_BATCH_SIZE,
            "pr_creation_enabled": ENABLE_PR_CREATION,
            "backup_enabled": BACKUP_ENABLED,
            "fixes_applied": len(self._applied_fixes),
            "backups_created": len(self._backups),
            "queue_items": len(self._queue),
            "batches": len(self._batches),
        }
