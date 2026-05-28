"""
FeedbackLoop Orchestrator - Runs the self-improving test generation cycle.

Cycle: Generate -> Run -> Analyze -> Improve -> (repeat until threshold)

Usage:
    loop = TestFeedbackLoop(config)
    result = await loop.run(source_dir, test_dir, language="python")
    # result contains final test files and coverage report
"""

import asyncio
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class FeedbackLoopResult:
    iterations: int
    initial_coverage: float
    final_coverage: float
    coverage_delta: float
    total_tests_generated: int
    total_tests_passed: int
    weak_tests_found: int
    improved_tests_added: int
    test_files_written: List[str] = field(default_factory=list)
    final_coverage_report: Optional[Dict] = None
    threshold_met: bool = False
    stopped_reason: str = ""  # "threshold_met", "max_iterations", "no_improvement", "error"


class TestFeedbackLoop:
    """
    Self-improving test generation loop.

    Iteratively generates, runs, and improves tests until coverage
    threshold is reached or max iterations exceeded.
    """

    def __init__(self, config: Optional[Dict] = None):
        self.config = config or {}
        self.coverage_threshold = self.config.get("coverage_threshold", 80.0)
        self.max_iterations = self.config.get("max_iterations", 5)
        self.min_improvement = self.config.get("min_improvement_per_iteration", 2.0)
        self.enable_mutation = self.config.get("enable_mutation_testing", True)
        self.coverage_history: List[float] = []
        self.iteration_results: List[Dict] = []

    async def run(
        self,
        source_dir: str,
        test_dir: str,
        language: str = "python",
        module_name: str = "target_module",
    ) -> FeedbackLoopResult:
        """
        Run the self-improving test generation feedback loop.

        Returns FeedbackLoopResult with final statistics.
        """
        logger.info(
            "Starting self-improving test loop: source=%s, test_dir=%s, "
            "language=%s, threshold=%.1f%%, max_iterations=%d",
            source_dir, test_dir, language, self.coverage_threshold, self.max_iterations,
        )

        start_time = time.time()
        total_tests = 0
        total_passed = 0
        weak_tests = 0
        improved_added = 0
        test_files_written = []

        # ---- ITERATION 0: Initial test generation ----
        logger.info("=== Iteration 0: Initial test generation ===")
        from agents.test_parser import TestParserAgent
        from agents.test_generator import TestGeneratorAgent
        from test_writer import TestWriter

        parser = TestParserAgent(self.config)
        generator = TestGeneratorAgent(self.config)
        writer = TestWriter(self.config)

        # Parse source code
        from agents.results import ScanContext
        ctx = ScanContext(
            scan_id=f"feedback_loop_{int(time.time())}",
            source_path=source_dir,
            languages=[language],
        )

        parsed = await parser.scan(ctx)
        generated = await generator.scan(ctx)

        # Write initial tests
        written = writer.write_tests(generated, test_dir, language)
        test_files_written.extend(written)
        logger.info("Iteration 0: Wrote %d initial test files", len(written))

        # ---- ITERATION LOOP: Run -> Analyze -> Improve ----
        for iteration in range(1, self.max_iterations + 1):
            logger.info("=== Iteration %d/%d ===", iteration, self.max_iterations)

            # Step 1: Run tests + measure coverage
            from agents.test_runner import TestRunnerAgent
            runner = TestRunnerAgent(self.config)
            run_result = await runner.scan(ctx)

            coverage = runner.get_coverage_report()
            current_cov = coverage.overall_percent if coverage else 0.0
            self.coverage_history.append(current_cov)

            total_tests += sum(r.get("total", 0) for r in run_result.metadata.get("executions", []))
            total_passed += sum(r.get("passed", 0) for r in run_result.metadata.get("executions", []))

            logger.info(
                "Iteration %d: Coverage = %.1f%%, Tests: %d passed / %d total",
                iteration, current_cov, total_passed, total_tests,
            )

            # Check threshold
            if coverage and coverage.threshold_met:
                logger.info("Coverage threshold (%.1f%%) MET! Stopping.", self.coverage_threshold)
                return self._build_result(
                    iterations=iteration,
                    initial=self.coverage_history[0] if self.coverage_history else 0.0,
                    final=current_cov,
                    total_tests=total_tests,
                    total_passed=total_passed,
                    weak=weak_tests,
                    improved=improved_added,
                    files=test_files_written,
                    coverage=coverage,
                    reason="threshold_met",
                )

            # Check no-improvement
            if len(self.coverage_history) >= 2:
                delta = current_cov - self.coverage_history[-2]
                if delta < self.min_improvement:
                    logger.info(
                        "Coverage improvement (%.1f%%) below minimum (%.1f%%). Stopping.",
                        delta, self.min_improvement,
                    )
                    return self._build_result(
                        iterations=iteration,
                        initial=self.coverage_history[0] if self.coverage_history else 0.0,
                        final=current_cov,
                        total_tests=total_tests,
                        total_passed=total_passed,
                        weak=weak_tests,
                        improved=improved_added,
                        files=test_files_written,
                        coverage=coverage,
                        reason="no_improvement",
                    )

            # Step 2: Analyze coverage gaps
            from agents.coverage_analyzer import CoverageAnalyzerAgent
            analyzer = CoverageAnalyzerAgent()

            gaps = analyzer.analyze_gaps(
                uncovered_lines=coverage.uncovered_lines if coverage else {},
                uncovered_functions=coverage.uncovered_functions if coverage else {},
                source_dir=source_dir,
                language=language,
            )
            logger.info("Iteration %d: Found %d coverage gaps", iteration, len(gaps))

            # Step 3: Mutation testing (find weak tests)
            mutation_results = []
            if self.enable_mutation and language == "python":
                from agents.mutation_tester import MutationTesterAgent
                mutator = MutationTesterAgent()

                # Find source files with tests
                source_files = list(Path(source_dir).rglob("*.py"))
                test_files = list(Path(test_dir).rglob("test_*.py"))

                for sf in source_files[:5]:  # Limit to top 5 for speed
                    for tf in test_files[:3]:
                        m_results = mutator.run_mutation_testing(
                            str(sf), str(tf), language
                        )
                        mutation_results.extend(m_results)

                weak_tests += len(mutation_results)
                logger.info("Iteration %d: Mutation testing found %d weak spots", iteration, len(mutation_results))

            # Step 4: Improve tests
            failed_tests = runner.get_failed_tests()
            from agents.test_improver import TestImproverAgent
            improver = TestImproverAgent(self.config)

            improved = await improver.improve(ctx, gaps, failed_tests, mutation_results, iteration)
            improved_added += len(improved)
            logger.info("Iteration %d: Generated %d improved tests", iteration, len(improved))

            # Write improved tests
            if improved:
                improved_code = improver.to_test_suite_code(module_name)
                if improved_code:
                    improved_file = os.path.join(
                        test_dir, f"test_{module_name}_improved_iter{iteration}.py"
                    )
                    with open(improved_file, "w", encoding="utf-8") as f:
                        f.write(improved_code)
                    test_files_written.append(improved_file)
                    logger.info("Wrote improved tests to %s", improved_file)

        # Max iterations reached
        final_cov = self.coverage_history[-1] if self.coverage_history else 0.0
        return self._build_result(
            iterations=self.max_iterations,
            initial=self.coverage_history[0] if self.coverage_history else 0.0,
            final=final_cov,
            total_tests=total_tests,
            total_passed=total_passed,
            weak=weak_tests,
            improved=improved_added,
            files=test_files_written,
            coverage=coverage if self.coverage_history else None,
            reason="max_iterations",
        )

    def _build_result(
        self,
        iterations: int,
        initial: float,
        final: float,
        total_tests: int,
        total_passed: int,
        weak: int,
        improved: int,
        files: List[str],
        coverage,
        reason: str,
    ) -> FeedbackLoopResult:
        return FeedbackLoopResult(
            iterations=iterations,
            initial_coverage=initial,
            final_coverage=final,
            coverage_delta=final - initial,
            total_tests_generated=total_tests,
            total_tests_passed=total_passed,
            weak_tests_found=weak,
            improved_tests_added=improved,
            test_files_written=files,
            final_coverage_report=self._serialize_coverage(coverage) if coverage else None,
            threshold_met=(final >= self.coverage_threshold),
            stopped_reason=reason,
        )

    def _serialize_coverage(self, coverage):
        if not coverage:
            return None
        return {
            "overall_percent": coverage.overall_percent,
            "threshold_target": coverage.threshold_target,
            "threshold_met": coverage.threshold_met,
            "files_with_low_coverage": {
                k: v for k, v in coverage.file_coverage.items()
                if v < coverage.threshold_target
            },
        }

    def get_progress_report(self) -> Dict[str, Any]:
        """Get current loop progress."""
        return {
            "current_iteration": len(self.coverage_history),
            "max_iterations": self.max_iterations,
            "coverage_history": self.coverage_history,
            "coverage_threshold": self.coverage_threshold,
            "latest_coverage": self.coverage_history[-1] if self.coverage_history else 0.0,
            "threshold_met": (
                self.coverage_history[-1] >= self.coverage_threshold
                if self.coverage_history else False
            ),
        }
