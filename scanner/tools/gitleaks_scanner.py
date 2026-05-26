"""
Gitleaks scanner integration for CodeShield AI.

Detects hardcoded secrets, API keys, passwords, and tokens in source code.
"""

import asyncio
import json
import os
from typing import List

from models.vulnerability import Vulnerability
from scanner.parsers.gitleaks_parser import GitleaksParser
from scanner.tool_runner import ToolRunner
from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)


class GitleaksScanner:
    """
    Gitleaks scanner for secret detection.

    Finds hardcoded secrets including:
    - API keys and tokens
    - Passwords and passphrases
    - Private keys
    - Database connection strings
    - OAuth credentials
    """

    def __init__(self) -> None:
        """Initialize the Gitleaks scanner."""
        self.tool_runner = ToolRunner()
        self.parser = GitleaksParser()
        self.tool_name = "gitleaks"

    async def scan(self, source_path: str, scan_id: str) -> List[Vulnerability]:
        """
        Run Gitleaks scan on the source code.

        Args:
            source_path: Path to the source code directory
            scan_id: Scan identifier

        Returns:
            List of vulnerabilities (secrets) found
        """
        if not self.tool_runner.check_tool_installed("gitleaks"):
            logger.warning(
                "Gitleaks is not installed. Install from: https://github.com/gitleaks/gitleaks"
            )
            return []

        logger.info("Running Gitleaks on %s", source_path)

        # Build command with JSON output
        settings = get_settings()
        output_file = str(settings.temp_dir / f"gitleaks_{scan_id}.json")

        command = [
            "gitleaks",
            "detect",
            "-s", source_path,
            "-r", output_file,
            "-v",
        ]

        # Run Gitleaks
        success, raw_output, _ = await self.tool_runner.run_tool(
            tool_name="gitleaks",
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
                logger.error("Failed to parse Gitleaks output: %s", e)
            finally:
                try:
                    await asyncio.to_thread(os.remove, output_file)
                except OSError:
                    pass

        logger.info("Gitleaks found %d secrets", len(vulnerabilities))
        return vulnerabilities

    def _read_json_file(self, path: str):
        """Read and parse a JSON file. Runs in thread."""
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def is_available(self) -> bool:
        """Check if Gitleaks is installed."""
        return self.tool_runner.check_tool_installed("gitleaks")
