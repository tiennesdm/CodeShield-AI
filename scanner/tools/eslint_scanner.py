"""
ESLint scanner integration for CodeShield AI.

JavaScript/TypeScript/React/React Native linting and security analysis.
"""

import asyncio
import json
import os
from typing import List

from models.vulnerability import Vulnerability
from scanner.parsers.eslint_parser import ESLintParser
from scanner.tool_runner import ToolRunner
from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)


class ESLintScanner:
    """
    ESLint scanner for JavaScript and TypeScript code.

    Detects security issues, code quality problems, and React-specific issues.
    """

    def __init__(self) -> None:
        """Initialize the ESLint scanner."""
        self.tool_runner = ToolRunner()
        self.parser = ESLintParser()
        self.tool_name = "eslint"

    async def scan(self, source_path: str, scan_id: str) -> List[Vulnerability]:
        """
        Run ESLint scan on JavaScript/TypeScript files.

        Args:
            source_path: Path to the source code directory
            scan_id: Scan identifier

        Returns:
            List of vulnerabilities found
        """
        if not self.tool_runner.check_tool_installed("eslint"):
            logger.warning(
                "ESLint is not installed. Install with: npm install -g eslint"
            )
            return []

        # Find JS/TS files
        js_files = self._find_js_files(source_path)
        if not js_files:
            logger.info("No JavaScript/TypeScript files found, skipping ESLint")
            return []

        logger.info("Running ESLint on %d JS/TS files", len(js_files))

        # Build command - use JSON format
        settings = get_settings()
        output_file = str(settings.temp_dir / f"eslint_{scan_id}.json")

        command = [
            "eslint",
            "--format", "json",
            "--output-file", output_file,
            "--no-eslintrc",
            "--rule", "no-eval: error",
            "--rule", "no-implied-eval: error",
            "--rule", "no-new-func: error",
            source_path,
        ]

        # Run ESLint
        success, _, _ = await self.tool_runner.run_tool(
            tool_name="eslint",
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
                logger.error("Failed to parse ESLint output: %s", e)
            finally:
                try:
                    await asyncio.to_thread(os.remove, output_file)
                except OSError:
                    pass

        logger.info("ESLint found %d issues", len(vulnerabilities))
        return vulnerabilities

    def _find_js_files(self, source_path: str) -> List[str]:
        """Find JavaScript and TypeScript files."""
        js_extensions = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
        files = []
        for dirpath, _, filenames in os.walk(source_path):
            for filename in filenames:
                if any(filename.endswith(ext) for ext in js_extensions):
                    files.append(os.path.join(dirpath, filename))
        return files

    def _read_json_file(self, path: str):
        """Read and parse a JSON file. Runs in thread."""
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def is_available(self) -> bool:
        """Check if ESLint is installed."""
        return self.tool_runner.check_tool_installed("eslint")
