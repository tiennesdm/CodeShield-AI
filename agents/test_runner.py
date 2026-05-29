"""
TestRunner Agent - Executes generated tests and captures coverage reports.

Runs pytest/jest/junit with coverage, parses output, and returns
structured results for the feedback loop.
"""

import asyncio
import json
import os
import subprocess
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import get_logger
from agents.base import BaseSecurityAgent
from agents.results import AgentResult, ScanContext

logger = get_logger(__name__)


@dataclass
class TestExecutionResult:
    test_file: str
    total_tests: int
    passed: int
    failed: int
    skipped: int
    errors: int
    duration_ms: int
    coverage_percent: float
    failed_tests: List[Dict[str, Any]] = field(default_factory=list)
    error_output: str = ""
    stdout: str = ""


@dataclass
class CoverageReport:
    overall_percent: float
    file_coverage: Dict[str, float]  # file_path -> coverage %
    uncovered_lines: Dict[str, List[int]]  # file_path -> [line numbers]
    uncovered_functions: Dict[str, List[str]]  # file_path -> [function names]
    threshold_met: bool = False
    threshold_target: float = 80.0


class TestRunnerAgent(BaseSecurityAgent):
    """Agent that executes tests and measures coverage."""

    name: str = "test_runner"
    role: str = "Test Execution & Coverage Reporter"
    tools: List[str] = []
    priority: int = 30

    def __init__(self, config=None):
        super().__init__(config)
        self.results: List[TestExecutionResult] = []
        self.coverage: Optional[CoverageReport] = None

    async def scan(self, context: ScanContext) -> AgentResult:
        """Execute all test files in the target directory."""
        start = time.time() * 1000
        test_dir = context.source_path
        language = (context.languages or ["python"])[0]

        self.results = await self._run_tests(test_dir, language)
        self.coverage = await self._measure_coverage(test_dir, language)

        metadata = {
            "executions": [self._serialize_exec(r) for r in self.results],
            "coverage": self._serialize_coverage(self.coverage),
            "all_passed": all(r.failed == 0 and r.errors == 0 for r in self.results),
            "overall_coverage": self.coverage.overall_percent if self.coverage else 0.0,
            "threshold_met": self.coverage.threshold_met if self.coverage else False,
        }

        elapsed = int((time.time() * 1000) - start)
        status = "success" if metadata["all_passed"] else "partial"

        return AgentResult(
            agent_name=self.name,
            agent_role=self.role,
            scan_id=context.scan_id,
            findings=[],
            summary=None,
            execution_time_ms=elapsed,
            status=status,
            errors=[r.error_output for r in self.results if r.error_output][:10],
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Python / pytest
    # ------------------------------------------------------------------

    async def _run_tests(self, test_dir: str, language: str) -> List[TestExecutionResult]:
        if language == "python":
            return await self._run_pytest(test_dir)
        elif language in ("javascript", "typescript"):
            return await self._run_jest(test_dir)
        elif language == "java":
            return await self._run_junit(test_dir)
        elif language == "go":
            return await self._run_go_test(test_dir)
        return []

    async def _run_pytest(self, test_dir: str) -> List[TestExecutionResult]:
        results = []
        test_files = list(Path(test_dir).rglob("test_*.py"))
        test_files += list(Path(test_dir).rglob("*_test.py"))

        for tf in test_files:
            cmd = [
                "python", "-m", "pytest",
                str(tf),
                "-v",
                "--tb=short",
                "--json-report",
                "--json-report-file=/tmp/pytest_report.json",
            ]
            try:
                proc = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        cwd=test_dir,
                    ),
                    timeout=60,
                )
                stdout, stderr = await proc.communicate()
                stdout_str = stdout.decode("utf-8", errors="replace")
                stderr_str = stderr.decode("utf-8", errors="replace")

                result = self._parse_pytest_output(stdout_str, stderr_str, str(tf))
                results.append(result)
            except asyncio.TimeoutError:
                results.append(TestExecutionResult(
                    test_file=str(tf), total_tests=0, passed=0, failed=0,
                    skipped=0, errors=1, duration_ms=60000, coverage_percent=0.0,
                    error_output="Test execution timed out after 60s",
                ))
            except Exception as e:
                results.append(TestExecutionResult(
                    test_file=str(tf), total_tests=0, passed=0, failed=0,
                    skipped=0, errors=1, duration_ms=0, coverage_percent=0.0,
                    error_output=str(e),
                ))
        return results

    def _parse_pytest_output(self, stdout: str, stderr: str, test_file: str) -> TestExecutionResult:
        passed, failed, skipped, errors = 0, 0, 0, 0
        failed_tests = []

        for line in stdout.split("\n"):
            if line.startswith("PASSED"):
                passed += 1
            elif line.startswith("FAILED"):
                failed += 1
                failed_tests.append({"name": line.replace("FAILED", "").strip(), "reason": "Assertion failed"})
            elif line.startswith("SKIPPED"):
                skipped += 1
            elif line.startswith("ERROR"):
                errors += 1

        if "passed" in stdout and "failed" in stdout:
            import re
            m = re.search(r'(\d+) passed', stdout)
            if m:
                passed = int(m.group(1))
            m = re.search(r'(\d+) failed', stdout)
            if m:
                failed = int(m.group(1))
            m = re.search(r'(\d+) skipped', stdout)
            if m:
                skipped = int(m.group(1))
            m = re.search(r'(\d+) error', stdout)
            if m:
                errors = int(m.group(1))

        total = passed + failed + skipped + errors
        coverage = self._extract_coverage_from_output(stdout + stderr)

        return TestExecutionResult(
            test_file=test_file,
            total_tests=total,
            passed=passed,
            failed=failed,
            skipped=skipped,
            errors=errors,
            duration_ms=0,
            coverage_percent=coverage,
            failed_tests=failed_tests,
            error_output=stderr[:2000] if errors > 0 else "",
            stdout=stdout[:2000],
        )

    def _extract_coverage_from_output(self, output: str) -> float:
        import re
        patterns = [
            r'TOTAL\s+\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+(\d+)%',
            r'coverage:.*?(\d+)%',
            r'Coverage:.*?(\d+)%',
        ]
        for p in patterns:
            m = re.search(p, output, re.IGNORECASE)
            if m:
                return float(m.group(1))
        return 0.0

    # ------------------------------------------------------------------
    # JavaScript / Jest
    # ------------------------------------------------------------------

    async def _run_jest(self, test_dir: str) -> List[TestExecutionResult]:
        results = []
        test_files = list(Path(test_dir).rglob("*.test.js"))
        test_files += list(Path(test_dir).rglob("*.test.ts"))

        for tf in test_files:
            cmd = ["npx", "jest", str(tf), "--verbose", "--coverage", "--json"]
            try:
                proc = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(
                        *cmd,
                        stdout=asyncio.subprocess.PIPE,
                        stderr=asyncio.subprocess.PIPE,
                        cwd=test_dir,
                    ),
                    timeout=60,
                )
                stdout, _ = await proc.communicate()
                stdout_str = stdout.decode("utf-8", errors="replace")

                try:
                    jest_result = json.loads(stdout_str)
                    num_total = jest_result.get("numTotalTests", 0)
                    num_passed = jest_result.get("numPassedTests", 0)
                    num_failed = jest_result.get("numFailedTests", 0)
                    num_pending = jest_result.get("numPendingTests", 0)
                    cov = jest_result.get("coverageMap", {})
                    cov_pct = self._calc_jest_coverage(cov)

                    results.append(TestExecutionResult(
                        test_file=str(tf),
                        total_tests=num_total,
                        passed=num_passed,
                        failed=num_failed,
                        skipped=num_pending,
                        errors=0,
                        duration_ms=0,
                        coverage_percent=cov_pct,
                    ))
                except json.JSONDecodeError:
                    results.append(TestExecutionResult(
                        test_file=str(tf), total_tests=0, passed=0, failed=0,
                        skipped=0, errors=1, duration_ms=0, coverage_percent=0.0,
                        error_output="Failed to parse jest output",
                    ))
            except asyncio.TimeoutError:
                results.append(TestExecutionResult(
                    test_file=str(tf), total_tests=0, passed=0, failed=0,
                    skipped=0, errors=1, duration_ms=60000, coverage_percent=0.0,
                    error_output="Jest timed out",
                ))
        return results

    def _calc_jest_coverage(self, coverage_map: dict) -> float:
        if not coverage_map:
            return 0.0
        total_stmts = 0
        covered_stmts = 0
        for file_cov in coverage_map.values():
            stmts = file_cov.get("statementMap", {})
            cov_data = file_cov.get("s", {})
            for stmt_id in stmts:
                total_stmts += 1
                if cov_data.get(stmt_id, 0) > 0:
                    covered_stmts += 1
        if total_stmts == 0:
            return 0.0
        return round((covered_stmts / total_stmts) * 100, 2)

    # ------------------------------------------------------------------
    # Java / JUnit  (stubs)
    # ------------------------------------------------------------------

    async def _run_junit(self, test_dir: str) -> List[TestExecutionResult]:
        # Stub: would run `mvn test` or `gradle test`
        return []

    # ------------------------------------------------------------------
    # Go  (stubs)
    # ------------------------------------------------------------------

    async def _run_go_test(self, test_dir: str) -> List[TestExecutionResult]:
        # Stub: would run `go test -v -cover`
        return []

    # ------------------------------------------------------------------
    # Coverage measurement
    # ------------------------------------------------------------------

    async def _measure_coverage(self, test_dir: str, language: str) -> Optional[CoverageReport]:
        if language == "python":
            return await self._measure_python_coverage(test_dir)
        return CoverageReport(
            overall_percent=0.0,
            file_coverage={},
            uncovered_lines={},
            uncovered_functions={},
        )

    async def _measure_python_coverage(self, test_dir: str) -> CoverageReport:
        # Run coverage and generate JSON report
        cov_json_path = "/tmp/coverage.json"
        cmd = [
            "python", "-m", "coverage", "run",
            "--source", test_dir,
            "-m", "pytest", test_dir, "-q",
        ]
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=120)

            # Generate JSON report
            report_cmd = ["python", "-m", "coverage", "json", "-o", cov_json_path]
            proc2 = await asyncio.create_subprocess_exec(*report_cmd)
            await asyncio.wait_for(proc2.communicate(), timeout=30)

            if os.path.exists(cov_json_path):
                with open(cov_json_path, "r") as f:
                    cov_data = json.load(f)
                return self._parse_coverage_json(cov_data)
        except Exception as e:
            logger.warning("Coverage measurement failed: %s", e)

        return CoverageReport(
            overall_percent=0.0, file_coverage={}, uncovered_lines={}, uncovered_functions={},
        )

    def _parse_coverage_json(self, cov_data: dict) -> CoverageReport:
        totals = cov_data.get("totals", {})
        percent = totals.get("percent_covered", 0.0)

        file_coverage = {}
        uncovered_lines = {}
        uncovered_functions = {}

        files = cov_data.get("files", {})
        for fpath, fdata in files.items():
            summary = fdata.get("summary", {})
            pct = summary.get("percent_covered", 0.0)
            file_coverage[fpath] = pct

            # Extract uncovered lines
            missing_lines = fdata.get("missing_lines", [])
            if missing_lines:
                uncovered_lines[fpath] = missing_lines

            # Extract uncovered functions
            missing_funcs = []
            for func_name, func_data in fdata.get("functions", {}).items():
                if func_data.get("percent_covered", 100.0) < 100.0:
                    missing_funcs.append(func_name)
            if missing_funcs:
                uncovered_functions[fpath] = missing_funcs

        threshold = self.config.get("coverage_threshold", 80.0)
        return CoverageReport(
            overall_percent=round(percent, 2),
            file_coverage=file_coverage,
            uncovered_lines=uncovered_lines,
            uncovered_functions=uncovered_functions,
            threshold_met=percent >= threshold,
            threshold_target=threshold,
        )

    # ------------------------------------------------------------------
    # Serializers
    # ------------------------------------------------------------------

    def _serialize_exec(self, r: TestExecutionResult) -> dict:
        return {
            "test_file": r.test_file,
            "total": r.total_tests,
            "passed": r.passed,
            "failed": r.failed,
            "skipped": r.skipped,
            "errors": r.errors,
            "coverage_percent": r.coverage_percent,
            "failed_tests": r.failed_tests,
        }

    def _serialize_coverage(self, c: Optional[CoverageReport]) -> dict:
        if not c:
            return {}
        return {
            "overall_percent": c.overall_percent,
            "threshold_target": c.threshold_target,
            "threshold_met": c.threshold_met,
            "files_with_low_coverage": {
                k: v for k, v in c.file_coverage.items() if v < c.threshold_target
            },
            "num_uncovered_lines": {k: len(v) for k, v in c.uncovered_lines.items()},
            "num_uncovered_functions": {k: len(v) for k, v in c.uncovered_functions.items()},
        }

    def get_coverage_report(self) -> Optional[CoverageReport]:
        return self.coverage

    def get_failed_tests(self) -> List[Dict[str, Any]]:
        failed = []
        for r in self.results:
            for ft in r.failed_tests:
                failed.append({"file": r.test_file, "test": ft["name"], "reason": ft["reason"]})
        return failed
