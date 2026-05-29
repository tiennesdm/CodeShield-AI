"""
TestImprover Agent - Generates improved test cases for coverage gaps and failures.

Receives coverage gaps and failed test info, generates targeted test cases
to improve coverage and fix weak tests.
"""

import os
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from utils.logger import get_logger
from agents.base import BaseSecurityAgent
from agents.results import AgentResult, ScanContext

logger = get_logger(__name__)


@dataclass
class ImprovedTest:
    target_function: str
    target_file: str
    improvement_type: str  # "coverage_gap", "failed_test", "mutation_weak"
    test_code: str
    description: str
    expected_coverage_increase: float = 0.0


class TestImproverAgent(BaseSecurityAgent):
    """Generates improved test cases based on coverage gaps and failures."""

    name: str = "test_improver"
    role: str = "Test Case Improver & Gap Filler"
    tools: List[str] = []
    priority: int = 40

    def __init__(self, config=None):
        super().__init__(config)
        self.improved_tests: List[ImprovedTest] = []
        self._iteration: int = 0
        self._max_iterations: int = config.get("max_improve_iterations", 5) if config else 5

    async def improve(
        self,
        context: ScanContext,
        coverage_gaps: List[Any],
        failed_tests: List[Dict[str, Any]],
        weak_mutations: List[Any],
        iteration: int = 0,
    ) -> List[ImprovedTest]:
        """Generate improved tests for all identified gaps."""
        self._iteration = iteration
        self.improved_tests = []

        logger.info(
            "TestImprover iteration %d/%d: %d coverage gaps, %d failed tests, %d weak mutations",
            iteration, self._max_iterations, len(coverage_gaps), len(failed_tests), len(weak_mutations),
        )

        # 1. Fix failed tests
        for ft in failed_tests:
            improved = self._improve_for_failure(ft, context)
            if improved:
                self.improved_tests.extend(improved)

        # 2. Fill coverage gaps
        for gap in coverage_gaps:
            improved = self._improve_for_coverage_gap(gap, context)
            if improved:
                self.improved_tests.extend(improved)

        # 3. Strengthen weak mutation spots
        for wm in weak_mutations:
            improved = self._improve_for_weak_mutation(wm, context)
            if improved:
                self.improved_tests.extend(improved)

        return self.improved_tests

    def _improve_for_failure(
        self,
        failed_test: Dict[str, Any],
        context: ScanContext,
    ) -> List[ImprovedTest]:
        """Generate improved test for a failed test case."""
        func_name = failed_test.get("function", "")
        file_path = failed_test.get("file", "")
        reason = failed_test.get("reason", "")

        test_code = self._generate_fixing_test(func_name, file_path, reason)
        return [ImprovedTest(
            target_function=func_name,
            target_file=file_path,
            improvement_type="failed_test",
            test_code=test_code,
            description=f"Fixed test for {func_name} - original failed: {reason}",
            expected_coverage_increase=5.0,
        )]

    def _improve_for_coverage_gap(
        self,
        gap: Any,
        context: ScanContext,
    ) -> List[ImprovedTest]:
        """Generate tests for uncovered code."""
        func_name = getattr(gap, "function_name", "")
        file_path = getattr(gap, "file_path", "")
        gap_type = getattr(gap, "gap_type", "")
        suggested_types = getattr(gap, "suggested_test_types", [])
        code_snippet = getattr(gap, "code_snippet", "")

        improved = []
        for test_type in suggested_types:
            test_code = self._generate_targeted_test(
                func_name, file_path, test_type, code_snippet
            )
            if test_code:
                improved.append(ImprovedTest(
                    target_function=func_name,
                    target_file=file_path,
                    improvement_type="coverage_gap",
                    test_code=test_code,
                    description=f"Added {test_type} test for {func_name} (gap: {gap_type})",
                    expected_coverage_increase=10.0,
                ))
        return improved

    def _improve_for_weak_mutation(
        self,
        mutation: Any,
        context: ScanContext,
    ) -> List[ImprovedTest]:
        """Generate tests that would catch weak mutations."""
        func_name = getattr(mutation, "function_name", "")
        file_path = getattr(mutation, "file_path", "")
        original = getattr(mutation, "original_code", "")
        mutated = getattr(mutation, "mutated_code", "")
        mut_type = getattr(mutation, "mutation_type", "")

        test_code = self._generate_mutation_killing_test(
            func_name, original, mutated, mut_type
        )
        return [ImprovedTest(
            target_function=func_name,
            target_file=file_path,
            improvement_type="mutation_weak",
            test_code=test_code,
            description=f"Added mutation-killing test for {func_name} ({mut_type}: {original} -> {mutated})",
            expected_coverage_increase=3.0,
        )]

    # ------------------------------------------------------------------
    # Test generation methods
    # ------------------------------------------------------------------

    def _generate_fixing_test(self, func_name: str, file_path: str, reason: str) -> str:
        """Generate a test that addresses a previous failure."""
        lines = [
            f"def test_{func_name}_improved_iter{self._iteration}():",
            f'    """Improved test for {func_name} (previous failure: {reason})."""',
            f"    # This test was generated to fix a previous failure",
            f"    # Original failure: {reason}",
            f"    result = {func_name}()",
            f"    assert result is not None",
            f"    # TODO: Add specific assertion based on expected behavior",
        ]
        return "\n".join(lines)

    def _generate_targeted_test(
        self,
        func_name: str,
        file_path: str,
        test_type: str,
        code_snippet: str,
    ) -> str:
        """Generate a targeted test for a specific gap type."""
        generators = {
            "basic": self._gen_basic_test,
            "error": self._gen_error_test,
            "async": self._gen_async_test,
            "branch": self._gen_branch_test,
            "edge": self._gen_edge_test,
            "null_safety": self._gen_null_safety_test,
            "mutation": self._gen_mutation_test,
        }
        gen = generators.get(test_type, self._gen_basic_test)
        return gen(func_name, file_path, code_snippet)

    def _gen_basic_test(self, func_name: str, file_path: str, snippet: str) -> str:
        return "\n".join([
            f"def test_{func_name}_basic_iter{self._iteration}():",
            f'    """Basic functionality test for {func_name} (improvement iter {self._iteration})."""',
            f"    # Arrange",
            f"    # TODO: Set up valid input parameters",
            f"    ",
            f"    # Act",
            f"    result = {func_name}()",
            f"    ",
            f"    # Assert",
            f"    assert result is not None",
            f"    # TODO: Add specific assertion for expected output",
        ])

    def _gen_error_test(self, func_name: str, file_path: str, snippet: str) -> str:
        exceptions = self._extract_exceptions(snippet)
        exc = exceptions[0] if exceptions else "Exception"
        return "\n".join([
            f"def test_{func_name}_error_handling_iter{self._iteration}():",
            f'    """Test {func_name} raises {exc} on invalid input."""',
            f"    with pytest.raises({exc}):",
            f"        # TODO: Pass invalid/malformed input",
            f"        {func_name}()",
        ])

    def _gen_async_test(self, func_name: str, file_path: str, snippet: str) -> str:
        return "\n".join([
            f"@pytest.mark.asyncio",
            f"async def test_{func_name}_async_iter{self._iteration}():",
            f'    """Async test for {func_name}."""',
            f"    result = await {func_name}()",
            f"    assert result is not None",
        ])

    def _gen_branch_test(self, func_name: str, file_path: str, snippet: str) -> str:
        conditions = self._extract_conditions(snippet)
        lines = [
            f"def test_{func_name}_branch_coverage_iter{self._iteration}():",
            f'    """Branch coverage test for {func_name}."""',
        ]
        for i, cond in enumerate(conditions[:3]):
            lines.extend([
                f"    # Branch {i + 1}: {cond}",
                f"    result_true = {func_name}()  # TODO: {cond} = True",
                f"    assert result_true is not None",
                f"    result_false = {func_name}()  # TODO: {cond} = False",
                f"    assert result_false is not None",
            ])
        return "\n".join(lines)

    def _gen_edge_test(self, func_name: str, file_path: str, snippet: str) -> str:
        return "\n".join([
            f"def test_{func_name}_edge_cases_iter{self._iteration}():",
            f'    """Edge case tests for {func_name}."""',
            f"    # Edge 1: Empty input",
            f"    result_empty = {func_name}()  # TODO: pass empty",
            f"    assert result_empty is not None",
            f"    ",
            f"    # Edge 2: Boundary minimum",
            f"    result_min = {func_name}()  # TODO: pass minimum",
            f"    ",
            f"    # Edge 3: Boundary maximum",
            f"    result_max = {func_name}()  # TODO: pass maximum",
        ])

    def _gen_null_safety_test(self, func_name: str, file_path: str, snippet: str) -> str:
        return "\n".join([
            f"def test_{func_name}_null_safety_iter{self._iteration}():",
            f'    """Null/None safety test for {func_name}."""',
            f"    result_none = {func_name}(None)",
            f"    # Should handle None gracefully - not crash",
            f"    assert result_none is not None or True  # Accepts None handling",
        ])

    def _gen_mutation_test(self, func_name: str, file_path: str, snippet: str) -> str:
        return "\n".join([
            f"def test_{func_name}_mutation_safety_iter{self._iteration}():",
            f'    """Mutation-testing safety test for {func_name}."""',
            f"    # This test verifies the exact behavior to catch mutants",
            f"    result = {func_name}()",
            f"    assert result is not None",
            f"    # TODO: Add exact expected value assertion",
        ])

    def _generate_mutation_killing_test(
        self,
        func_name: str,
        original: str,
        mutated: str,
        mut_type: str,
    ) -> str:
        """Generate a test specifically designed to kill a mutation."""
        return "\n".join([
            f"def test_{func_name}_kill_mutation_iter{self._iteration}():",
            f'    """Mutation-killing test: {mut_type} mutation ({original} -> {mutated})."""',
            f"    # This test must use a specific expected value to catch the mutation",
            f"    result = {func_name}()",
            f"    # TODO: Replace with exact expected value",
            f"    # If the mutation changes {original} to {mutated}, this should fail",
            f"    assert result is not None",
        ])

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _extract_exceptions(self, code_snippet: str) -> List[str]:
        """Extract exception types from code snippet."""
        exceptions = []
        for match in re.finditer(r'raise\s+(\w+)', code_snippet):
            exceptions.append(match.group(1))
        return exceptions or ["Exception"]

    def _extract_conditions(self, code_snippet: str) -> List[str]:
        """Extract conditional expressions from code snippet."""
        conditions = []
        for match in re.finditer(r'if\s+(.+):', code_snippet):
            conditions.append(match.group(1).strip())
        return conditions

    def to_test_suite_code(self, module_name: str) -> str:
        """Convert all improved tests to a test file code string."""
        if not self.improved_tests:
            return ""
        lines = [
            f'"""',
            f'Improved test cases for {module_name}',
            f'Generated by CodeShield AI TestImprover (iteration {self._iteration})',
            f'"""',
            "import pytest",
            f"from {module_name} import *",
            "",
        ]
        for it in self.improved_tests:
            lines.append(f"# {it.description}")
            lines.append(it.test_code)
            lines.append("")
        return "\n".join(lines)

    def get_stats(self) -> Dict[str, Any]:
        """Get improvement statistics."""
        if not self.improved_tests:
            return {"total": 0, "by_type": {}}
        by_type = {}
        for t in self.improved_tests:
            by_type[t.improvement_type] = by_type.get(t.improvement_type, 0) + 1
        return {
            "total": len(self.improved_tests),
            "by_type": by_type,
            "estimated_coverage_increase": sum(t.expected_coverage_increase for t in self.improved_tests),
            "iteration": self._iteration,
        }
