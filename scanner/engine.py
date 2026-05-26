"""
Main scanning orchestrator for CodeShield AI.

Coordinates language detection, tool selection, execution, and result aggregation.
Runs scans asynchronously with progress tracking.
"""

import asyncio
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from models.vulnerability import ScanConfig, ScanResult, Vulnerability
from scanner.language_detector import LanguageDetector
from scanner.tool_runner import ToolRunner
from scanner.tools.bandit_scanner import BanditScanner
from scanner.tools.custom_ai_scanner import CustomAIScanner
from scanner.tools.dependency_check import DependencyCheckScanner
from scanner.tools.eslint_scanner import ESLintScanner
from scanner.tools.gitleaks_scanner import GitleaksScanner
from scanner.tools.pmd_scanner import PMDScanner
from scanner.tools.pylint_scanner import PylintScanner
from scanner.tools.semgrep_scanner import SemgrepScanner
from utils.config import get_settings
from utils.constants import TOOL_LANGUAGE_MAP
from utils.helpers import count_lines, find_files
from utils.logger import get_logger

logger = get_logger(__name__)


class ScanEngine:
    """
    Main scanning engine that orchestrates the entire scan process.

    Handles language detection, tool selection, parallel execution,
    and result aggregation.
    """

    def __init__(self) -> None:
        """Initialize the scan engine with all available scanners."""
        self.language_detector = LanguageDetector()
        self.tool_runner = ToolRunner()

        # Initialize all scanners
        self.scanners = {
            "semgrep": SemgrepScanner(),
            "eslint": ESLintScanner(),
            "pylint": PylintScanner(),
            "bandit": BanditScanner(),
            "pmd": PMDScanner(),
            "gitleaks": GitleaksScanner(),
            "dependency_check": DependencyCheckScanner(),
            "custom_ai": CustomAIScanner(),
        }

        logger.info("Scan engine initialized with %d scanners", len(self.scanners))

    async def run_scan(
        self,
        scan_id: str,
        source_path: str,
        source_type: str,
        name: str,
        config: Optional[ScanConfig] = None,
        db=None,
    ) -> ScanResult:
        """
        Run a complete scan on the given source code.

        Args:
            scan_id: Unique scan identifier
            source_path: Path to the source code directory
            source_type: "zip" or "github"
            name: Human-readable scan name
            config: Optional scan configuration
            db: Optional database instance for progress updates

        Returns:
            Complete ScanResult with all findings
        """
        config = config or ScanConfig()
        settings = get_settings()

        result = ScanResult(
            scan_id=scan_id,
            name=name or f"Scan {scan_id}",
            source_type=source_type,
            source_path=source_path,
            status="running",
            progress=0,
            start_time=datetime.now(timezone.utc),
        )

        # Save initial state
        if db:
            await db.save_scan(result)

        try:
            # Phase 1: File discovery
            logger.info("[%s] Starting file discovery in %s", scan_id, source_path)
            await self._update_progress(db, result, 5, "running")

            all_files = find_files(
                source_path,
                max_size_mb=config.max_file_size_mb or settings.max_file_size_mb,
            )
            result.total_files = len(all_files)

            if result.total_files == 0:
                result.status = "completed"
                result.progress = 100
                result.end_time = datetime.now(timezone.utc)
                if result.start_time:
                    result.scan_duration = int(
                        (result.end_time - result.start_time).total_seconds()
                    )
                if db:
                    await db.save_scan(result)
                return result

            # Phase 2: Language detection
            logger.info("[%s] Detecting languages...", scan_id)
            await self._update_progress(db, result, 15, "running")

            languages = self.language_detector.detect_languages(source_path, all_files)
            result.languages = languages
            logger.info("[%s] Detected languages: %s", scan_id, languages)

            # Phase 3: Tool selection
            await self._update_progress(db, result, 20, "running")
            tools_to_run = self._select_tools(languages, config)
            result.tools_used = tools_to_run
            logger.info("[%s] Selected tools: %s", scan_id, tools_to_run)

            # Phase 4: Run scanners in parallel
            logger.info("[%s] Running %d scanners...", scan_id, len(tools_to_run))
            await self._update_progress(db, result, 30, "running")

            all_vulnerabilities: List[Vulnerability] = []
            tool_results = await self._run_scanners(
                scan_id, source_path, tools_to_run, config
            )

            for tool_name, vulns in tool_results.items():
                all_vulnerabilities.extend(vulns)
                logger.info(
                    "[%s] Tool %s found %d issues", scan_id, tool_name, len(vulns)
                )

            await self._update_progress(db, result, 85, "running")

            # Phase 5: Post-process results
            all_vulnerabilities = self._deduplicate_vulnerabilities(all_vulnerabilities)
            all_vulnerabilities = self._apply_severity_filter(
                all_vulnerabilities, config
            )
            all_vulnerabilities = self._sort_vulnerabilities(all_vulnerabilities)

            # Assign scan_id to all vulnerabilities
            for vuln in all_vulnerabilities:
                vuln.scan_id = scan_id

            result.vulnerabilities = all_vulnerabilities
            result.compute_stats()
            result.compute_risk_score()
            result.total_lines = self._count_total_lines(all_files)

            # Phase 6: Finalize
            result.status = "completed"
            result.progress = 100
            result.end_time = datetime.now(timezone.utc)
            if result.start_time:
                result.scan_duration = int(
                    (result.end_time - result.start_time).total_seconds()
                )

            logger.info(
                "[%s] Scan completed: %d vulnerabilities found, risk score: %d",
                scan_id,
                len(all_vulnerabilities),
                result.risk_score,
            )

            if db:
                await db.save_scan(result)

            return result

        except Exception as e:
            logger.error("[%s] Scan failed: %s", scan_id, str(e), exc_info=True)
            result.status = "failed"
            result.error_message = str(e)
            result.end_time = datetime.now(timezone.utc)
            if result.start_time:
                result.scan_duration = int(
                    (result.end_time - result.start_time).total_seconds()
                )
            if db:
                await db.save_scan(result)
            return result

    async def _update_progress(
        self,
        db: Any,
        result: ScanResult,
        progress: int,
        status: str,
    ) -> None:
        """Update scan progress in database."""
        result.progress = progress
        result.status = status
        if db:
            await db.save_scan(result)

    def _select_tools(
        self, languages: List[str], config: ScanConfig
    ) -> List[str]:
        """
        Select appropriate scanners based on detected languages.

        Args:
            languages: List of detected language names
            config: Scan configuration

        Returns:
            List of tool names to run
        """
        # If user specified tools, use those
        if config.tools:
            return [t for t in config.tools if t in self.scanners]

        # Auto-select based on languages
        selected = set()
        for tool_name, tool_langs in TOOL_LANGUAGE_MAP.items():
            if tool_name not in self.scanners:
                continue
            if "*" in tool_langs:
                selected.add(tool_name)
                continue
            for lang in languages:
                if lang.lower() in tool_langs:
                    selected.add(tool_name)
                    break

        # Always include custom AI scanner
        selected.add("custom_ai")

        return sorted(list(selected))

    async def _run_scanners(
        self,
        scan_id: str,
        source_path: str,
        tools: List[str],
        config: ScanConfig,
    ) -> Dict[str, List[Vulnerability]]:
        """
        Run all selected scanners in parallel.

        Args:
            scan_id: Scan identifier
            source_path: Path to source code
            tools: List of tool names
            config: Scan configuration

        Returns:
            Dictionary mapping tool name to list of vulnerabilities
        """
        tasks = []
        tool_names = []

        for tool_name in tools:
            scanner = self.scanners.get(tool_name)
            if scanner is None:
                logger.warning("[%s] Scanner '%s' is not available, skipping", scan_id, tool_name)
                continue

            task = self._run_single_scanner(
                scan_id, source_path, tool_name, scanner, config
            )
            tasks.append(task)
            tool_names.append(tool_name)

        if not tasks:
            return {}

        results = await asyncio.gather(*tasks, return_exceptions=True)

        tool_results: Dict[str, List[Vulnerability]] = {}
        for tool_name, result in zip(tool_names, results):
            if isinstance(result, Exception):
                logger.error(
                    "[%s] Scanner %s failed: %s", scan_id, tool_name, result
                )
                tool_results[tool_name] = []
            else:
                tool_results[tool_name] = result

        return tool_results

    async def _run_single_scanner(
        self,
        scan_id: str,
        source_path: str,
        tool_name: str,
        scanner: Any,
        config: ScanConfig,
    ) -> List[Vulnerability]:
        """
        Run a single scanner with error handling.

        Args:
            scan_id: Scan identifier
            source_path: Path to source code
            tool_name: Name of the tool
            scanner: Scanner instance
            config: Scan configuration

        Returns:
            List of vulnerabilities found
        """
        try:
            timeout = config.timeout_seconds or get_settings().default_scan_timeout
            vulns = await asyncio.wait_for(
                scanner.scan(source_path, scan_id),
                timeout=timeout,
            )
            return vulns
        except asyncio.TimeoutError:
            logger.warning("[%s] Scanner %s timed out", scan_id, tool_name)
            return []
        except Exception as e:
            logger.error("[%s] Scanner %s error: %s", scan_id, tool_name, e)
            return []

    def _deduplicate_vulnerabilities(
        self, vulnerabilities: List[Vulnerability]
    ) -> List[Vulnerability]:
        """
        Remove duplicate vulnerabilities found by multiple tools.

        Deduplication is based on file_path + line_number + category.

        Args:
            vulnerabilities: List of vulnerabilities

        Returns:
            Deduplicated list
        """
        seen: Dict[str, Vulnerability] = {}

        for vuln in vulnerabilities:
            key = f"{vuln.file_path}:{vuln.line_number}:{vuln.category}"
            if key not in seen:
                seen[key] = vuln
            else:
                # Keep the one with higher severity
                existing = seen[key]
                severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
                if severity_order.get(vuln.severity, 0) > severity_order.get(
                    existing.severity, 0
                ):
                    seen[key] = vuln

        return list(seen.values())

    def _apply_severity_filter(
        self, vulnerabilities: List[Vulnerability], config: ScanConfig
    ) -> List[Vulnerability]:
        """
        Filter vulnerabilities by severity levels.

        Args:
            vulnerabilities: List of vulnerabilities
            config: Scan configuration

        Returns:
            Filtered list
        """
        if not config.severity_filters:
            if not config.include_info:
                return [v for v in vulnerabilities if v.severity != "INFO"]
            return vulnerabilities

        allowed = set(s.upper() for s in config.severity_filters)
        return [v for v in vulnerabilities if v.severity.upper() in allowed]

    def _sort_vulnerabilities(
        self, vulnerabilities: List[Vulnerability]
    ) -> List[Vulnerability]:
        """
        Sort vulnerabilities by severity (highest first).

        Args:
            vulnerabilities: List of vulnerabilities

        Returns:
            Sorted list
        """
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        return sorted(
            vulnerabilities,
            key=lambda v: (
                severity_order.get(v.severity, 99),
                v.file_path,
                v.line_number,
            ),
        )

    def _count_total_lines(self, files: List[str]) -> int:
        """Count total lines across all files."""
        total = 0
        for file_path in files:
            total += count_lines(file_path)
        return total
