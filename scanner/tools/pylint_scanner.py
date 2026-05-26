"""
Pylint scanner integration for CodeShield AI.

Python code quality and basic security analysis.
"""

import asyncio
import json
import os
from typing import List

from models.vulnerability import Vulnerability
from scanner.parsers.pylint_parser import PylintParser
from scanner.tool_runner import ToolRunner
from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)


class PylintScanner:
    """
    Pylint scanner for Python code quality analysis.

    Detects code quality issues that may lead to security problems:
    - Dangerous default arguments
    - Bare except clauses
    - Eval/exec usage
    - Global variable usage
    """

    def __init__(self) -> None:
        """Initialize the Pylint scanner."""
        self.tool_runner = ToolRunner()
        self.parser = PylintParser()
        self.tool_name = "pylint"

    async def scan(self, source_path: str, scan_id: str) -> List[Vulnerability]:
        """
        Run Pylint scan on Python files.

        Args:
            source_path: Path to the source code directory
            scan_id: Scan identifier

        Returns:
            List of code quality issues found
        """
        if not self.tool_runner.check_tool_installed("pylint"):
            logger.warning(
                "Pylint is not installed. Install with: pip install pylint"
            )
            return []

        # Check if there are Python files
        py_files = self._find_python_files(source_path)
        if not py_files:
            logger.info("No Python files found, skipping Pylint")
            return []

        logger.info("Running Pylint on %d Python files", len(py_files))

        # Build command with JSON output
        settings = get_settings()
        output_file = str(settings.temp_dir / f"pylint_{scan_id}.json")

        command = [
            "pylint",
            "--output-format=json",
            f"--output={output_file}",
            "--disable=all",
            "--enable=W,E,R",
            source_path,
        ]

        # Run Pylint
        success, raw_output, _ = await self.tool_runner.run_tool(
            tool_name="pylint",
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
                logger.error("Failed to parse Pylint output: %s", e)
            finally:
                try:
                    await asyncio.to_thread(os.remove, output_file)
                except OSError:
                    pass

        logger.info("Pylint found %d issues", len(vulnerabilities))
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
        """Check if Pylint is installed."""
        return self.tool_runner.check_tool_installed("pylint")
