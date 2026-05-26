"""
OWASP Dependency-Check scanner integration for CodeShield AI.

Scans project dependencies for known vulnerabilities.
"""

import asyncio
import json
import os
import shutil
from typing import List

from models.vulnerability import Vulnerability
from scanner.parsers.dependency_parser import DependencyParser
from scanner.tool_runner import ToolRunner
from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)


class DependencyCheckScanner:
    """
    OWASP Dependency-Check scanner for vulnerable dependencies.

    Scans for known vulnerabilities in:
    - Python (requirements.txt, Pipfile)
    - JavaScript/Node.js (package.json, package-lock.json)
    - Java (pom.xml, build.gradle)
    - Ruby (Gemfile)
    - PHP (composer.json)
    """

    def __init__(self) -> None:
        """Initialize the Dependency-Check scanner."""
        self.tool_runner = ToolRunner()
        self.parser = DependencyParser()
        self.tool_name = "dependency-check"

    async def scan(self, source_path: str, scan_id: str) -> List[Vulnerability]:
        """
        Run OWASP Dependency-Check scan.

        Args:
            source_path: Path to the source code directory
            scan_id: Scan identifier

        Returns:
            List of vulnerable dependencies found
        """
        tool_name = "dependency-check.sh"
        if not self.tool_runner.check_tool_installed(tool_name):
            # Try alternative names
            for alt in ["dependency-check", "dependency-check.bat"]:
                if self.tool_runner.check_tool_installed(alt):
                    tool_name = alt
                    break
            else:
                logger.warning(
                    "OWASP Dependency-Check is not installed. "
                    "Download from: https://owasp.org/www-project-dependency-check/"
                )
                return []

        logger.info("Running OWASP Dependency-Check on %s", source_path)

        # Build command with JSON output - use temp_dir
        settings = get_settings()
        output_dir = str(settings.temp_dir / f"depcheck_{scan_id}")
        await asyncio.to_thread(os.makedirs, output_dir, exist_ok=True)

        report_file = os.path.join(output_dir, "dependency-check-report.json")

        command = [
            tool_name,
            "--project", f"CodeShield-{scan_id}",
            "--scan", source_path,
            "--format", "JSON",
            "--out", output_dir,
            "--enableExperimental",
        ]

        # Run Dependency-Check
        success, raw_output, _ = await self.tool_runner.run_tool(
            tool_name="dependency-check",
            command=command,
            timeout=600,  # Can take longer due to NVD updates
        )

        vulnerabilities: List[Vulnerability] = []

        # Read report file using async thread
        if os.path.exists(report_file):
            try:
                data = await asyncio.to_thread(self._read_json_file, report_file)
                if data:
                    vulnerabilities = self.parser.parse(data, scan_id, source_path)
            except Exception as e:
                logger.error("Failed to parse Dependency-Check output: %s", e)
            finally:
                # Cleanup
                try:
                    await asyncio.to_thread(shutil.rmtree, output_dir, ignore_errors=True)
                except OSError:
                    pass

        logger.info("Dependency-Check found %d vulnerable dependencies", len(vulnerabilities))
        return vulnerabilities

    def _has_dependency_files(self, source_path: str) -> bool:
        """Check if the project has dependency management files."""
        dep_files = [
            "requirements.txt",
            "Pipfile",
            "Pipfile.lock",
            "package.json",
            "package-lock.json",
            "yarn.lock",
            "pom.xml",
            "build.gradle",
            "Gemfile",
            "Gemfile.lock",
            "composer.json",
            "composer.lock",
            "go.mod",
            "go.sum",
            "Cargo.toml",
            "Cargo.lock",
        ]

        for dirpath, _, filenames in os.walk(source_path):
            for dep_file in dep_files:
                if dep_file in filenames:
                    return True
            # Only check root and first level
            depth = dirpath.count(os.sep) - source_path.count(os.sep)
            if depth > 2:
                break

        return False

    def _read_json_file(self, path: str):
        """Read and parse a JSON file. Runs in thread."""
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)

    def is_available(self) -> bool:
        """Check if Dependency-Check is installed."""
        for tool in ["dependency-check.sh", "dependency-check", "dependency-check.bat"]:
            if self.tool_runner.check_tool_installed(tool):
                return True
        return False
