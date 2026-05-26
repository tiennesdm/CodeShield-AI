"""
Semgrep SAST scanner integration for CodeShield AI.

Multi-language static analysis using Semgrep with OWASP and security rules.
"""

import asyncio
import json
import os
from typing import Any, Dict, List, Optional

from models.vulnerability import Vulnerability
from scanner.parsers.semgrep_parser import SemgrepParser
from scanner.tool_runner import ToolRunner
from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)


class SemgrepScanner:
    """
    Semgrep SAST scanner for multiple programming languages.

    Supports Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, and more.
    Uses the Semgrep CLI with security-focused rule sets.
    """

    def __init__(self) -> None:
        """Initialize the Semgrep scanner."""
        self.tool_runner = ToolRunner()
        self.parser = SemgrepParser()
        self.tool_name = "semgrep"

    async def scan(self, source_path: str, scan_id: str) -> List[Vulnerability]:
        """
        Run Semgrep scan on the source code.

        Args:
            source_path: Path to the source code directory
            scan_id: Scan identifier

        Returns:
            List of vulnerabilities found
        """
        if not self.tool_runner.check_tool_installed("semgrep"):
            logger.warning("Semgrep is not installed. Install with: pip install semgrep")
            return []

        # Build command with JSON output and security rules
        settings = get_settings()
        output_file = str(settings.temp_dir / f"semgrep_{scan_id}.json")

        command = [
            "semgrep",
            "--config=auto",
            "--json",
            "--output", output_file,
            "--quiet",
            source_path,
        ]

        # Run Semgrep
        success, raw_output, _ = await self.tool_runner.run_tool(
            tool_name="semgrep",
            command=command,
            timeout=300,
        )

        vulnerabilities: List[Vulnerability] = []

        # Try to read the output file first (using async thread)
        if os.path.exists(output_file):
            try:
                data = await asyncio.to_thread(self._read_json_file, output_file)
                if data:
                    vulnerabilities = self.parser.parse(data, scan_id, source_path)
            except Exception as e:
                logger.error("Failed to parse Semgrep output file: %s", e)
            finally:
                try:
                    await asyncio.to_thread(os.remove, output_file)
                except OSError:
                    pass
        elif success and raw_output:
            # Try parsing stdout
            try:
                data = json.loads(raw_output)
                vulnerabilities = self.parser.parse(data, scan_id, source_path)
            except json.JSONDecodeError:
                logger.warning("Semgrep output is not valid JSON")

        logger.info("Semgrep found %d vulnerabilities", len(vulnerabilities))
        return vulnerabilities

    def _read_json_file(self, path: str):
        """Read and parse a JSON file. Runs in thread."""
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def is_available(self) -> bool:
        """Check if Semgrep is installed."""
        return self.tool_runner.check_tool_installed("semgrep")
