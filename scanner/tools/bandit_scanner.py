"""
Bandit security scanner integration for CodeShield AI.

Python-specific security vulnerability scanner.
"""

import asyncio
import json
import os
from typing import List

from models.vulnerability import Vulnerability
from scanner.parsers.bandit_parser import BanditParser
from scanner.tool_runner import ToolRunner
from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)


class BanditScanner:
    """
    Bandit scanner for Python security vulnerabilities.

    Finds common security issues in Python code including:
    - Hardcoded passwords/tokens
    - SQL injection
    - Command injection
    - Insecure crypto
    - XML vulnerabilities
    - YAML loading issues
    """

    def __init__(self) -> None:
        """Initialize the Bandit scanner."""
        self.tool_runner = ToolRunner()
        self.parser = BanditParser()
        self.tool_name = "bandit"

    async def scan(self, source_path: str, scan_id: str) -> List[Vulnerability]:
        """
        Run Bandit scan on Python files.

        Args:
            source_path: Path to the source code directory
            scan_id: Scan identifier

        Returns:
            List of vulnerabilities found
        """
        if not self.tool_runner.check_tool_installed("bandit"):
            logger.warning(
                "Bandit is not installed. Install with: pip install bandit"
            )
            return []

        # Check if there are Python files
        py_files = self._find_python_files(source_path)
        if not py_files:
            logger.info("No Python files found, skipping Bandit")
            return []

        logger.info("Running Bandit on %d Python files", len(py_files))

        # Build command with JSON output - use temp_dir for output
        settings = get_settings()
        output_file = str(settings.temp_dir / f"bandit_{scan_id}.json")

        command = [
            "bandit",
            "-r",  # recursive
            "-f", "json",  # JSON output
            "-o", output_file,  # output file
            "-ll",  # report medium and high
            source_path,
        ]

        # Run Bandit
        success, raw_output, _ = await self.tool_runner.run_tool(
            tool_name="bandit",
            command=command,
            timeout=300,
        )

        vulnerabilities: List[Vulnerability] = []

        # Read output file using asyncio.to_thread for blocking I/O
        if os.path.exists(output_file):
            try:
                data = await asyncio.to_thread(self._read_json_file, output_file)
                if data:
                    vulnerabilities = self.parser.parse(data, scan_id, source_path)
            except Exception as e:
                logger.error("Failed to parse Bandit output: %s", e)
            finally:
                try:
                    await asyncio.to_thread(os.remove, output_file)
                except OSError:
                    pass

        logger.info("Bandit found %d vulnerabilities", len(vulnerabilities))
        return vulnerabilities

    def _find_python_files(self, source_path: str) -> List[str]:
        """Find Python files in the source directory."""
        files = []
        for dirpath, _, filenames in os.walk(source_path):
            for filename in filenames:
                if filename.endswith(".py"):
                    files.append(os.path.join(dirpath, filename))
        return files

    def _read_json_file(self, path: str):
        """Read and parse a JSON file. Runs in thread."""
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def is_available(self) -> bool:
        """Check if Bandit is installed."""
        return self.tool_runner.check_tool_installed("bandit")
