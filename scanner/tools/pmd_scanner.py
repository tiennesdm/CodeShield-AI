"""
PMD scanner integration for CodeShield AI.

Static analysis for Java code including security and best practice rules.
"""

import asyncio
import json
import os
from typing import List

from models.vulnerability import Vulnerability
from scanner.parsers.pmd_parser import PMDParser
from scanner.tool_runner import ToolRunner
from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)


class PMDScanner:
    """
    PMD scanner for Java security and code quality analysis.

    Detects common Java security issues including:
    - SQL injection
    - XSS vulnerabilities
    - Hardcoded credentials
    - Insecure crypto
    - Input validation issues
    """

    def __init__(self) -> None:
        """Initialize the PMD scanner."""
        self.tool_runner = ToolRunner()
        self.parser = PMDParser()
        self.tool_name = "pmd"

    async def scan(self, source_path: str, scan_id: str) -> List[Vulnerability]:
        """
        Run PMD scan on Java files.

        Args:
            source_path: Path to the source code directory
            scan_id: Scan identifier

        Returns:
            List of vulnerabilities found
        """
        if not self.tool_runner.check_tool_installed("pmd"):
            logger.warning(
                "PMD is not installed. Download from: https://pmd.github.io/"
            )
            return []

        # Check if there are Java files
        java_files = self._find_java_files(source_path)
        if not java_files:
            logger.info("No Java files found, skipping PMD")
            return []

        logger.info("Running PMD on %d Java files", len(java_files))

        # Build command with JSON output
        settings = get_settings()
        output_file = str(settings.temp_dir / f"pmd_{scan_id}.json")

        command = [
            "pmd",
            "check",
            "-d", source_path,
            "-R", "rulesets/java/quickstart.xml,rulesets/java/security.xml",
            "-f", "json",
            "-r", output_file,
        ]

        # Run PMD
        success, raw_output, _ = await self.tool_runner.run_tool(
            tool_name="pmd",
            command=command,
            timeout=300,
        )

        vulnerabilities: List[Vulnerability] = []

        # Read output file using async thread
        if os.path.exists(output_file):
            try:
                data = await asyncio.to_thread(self._read_json_file, output_file)
                if data:
                    vulnerabilities = self.parser.parse(data, scan_id, source_path)
            except Exception as e:
                logger.error("Failed to parse PMD output: %s", e)
            finally:
                try:
                    await asyncio.to_thread(os.remove, output_file)
                except OSError:
                    pass

        logger.info("PMD found %d issues", len(vulnerabilities))
        return vulnerabilities

    def _find_java_files(self, source_path: str) -> List[str]:
        """Find Java files in the source directory."""
        files = []
        for dirpath, _, filenames in os.walk(source_path):
            for filename in filenames:
                if filename.endswith(".java"):
                    files.append(os.path.join(dirpath, filename))
        return files

    def _read_json_file(self, path: str):
        """Read and parse a JSON file. Runs in thread."""
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def is_available(self) -> bool:
        """Check if PMD is installed."""
        return self.tool_runner.check_tool_installed("pmd")
