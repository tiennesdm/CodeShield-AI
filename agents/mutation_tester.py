"""
MutationTester Agent - Identifies weak tests via mutation testing.

Makes small semantic changes to source code and checks if tests catch them.
Tests that don't fail after a mutation are weak and need improvement.
"""

import ast
import copy
import os
import re
import tempfile
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class MutationResult:
    file_path: str
    function_name: str
    line_number: int
    original_code: str
    mutated_code: str
    mutation_type: str  # "arithmetic", "comparison", "boolean", "constant"
    tests_killed: int = 0  # How many test runs failed after mutation
    tests_survived: int = 0  # How many passed = WEAK
    survived: bool = False  # True if mutation survived = WEAK TESTS


class MutationTesterAgent:
    """Performs mutation testing to find weak tests."""

    name: str = "mutation_tester"
    role: str = "Weak Test Detector via Mutation Testing"

    # Mutation operators per language
    MUTATIONS = {
        "python": {
            "arithmetic": {
                " + ": " - ",
                " - ": " + ",
                " * ": " // ",
                " // ": " * ",
            },
            "comparison": {
                " == ": " != ",
                " != ": " == ",
                " > ": " < ",
                " < ": " > ",
                " >= ": " <= ",
                " <= ": " >= ",
            },
            "boolean": {
                " and ": " or ",
                " or ": " and ",
                "True": "False",
                "False": "True",
            },
            "constant": {
                "return 1": "return 0",
                "return 0": "return 1",
                "return True": "return False",
                "return False": "return True",
                "return None": "return 'mutated'",
            },
        },
    }

    def run_mutation_testing(
        self,
        source_file: str,
        test_file: str,
        language: str = "python",
    ) -> List[MutationResult]:
        """Run mutation testing on source file, return weak spots."""
        results = []

        with open(source_file, "r", encoding="utf-8") as f:
            original_code = f.read()

        mutations = self.MUTATIONS.get(language, self.MUTATIONS["python"])

        for mut_type, operators in mutations.items():
            for original, replacement in operators.items():
                # Find all occurrences
                lines = original_code.split("\n")
                for i, line in enumerate(lines, 1):
                    if original in line and self._is_safe_mutation(line, original):
                        # Apply mutation
                        mutated_line = line.replace(original, replacement, 1)
                        mutated_code = original_code.replace(line, mutated_line, 1)

                        # Run tests with mutation
                        killed = self._run_tests_with_mutation(
                            source_file, test_file, mutated_code, language
                        )

                        func_name = self._get_function_at_line(source_file, i)
                        result = MutationResult(
                            file_path=source_file,
                            function_name=func_name,
                            line_number=i,
                            original_code=line.strip(),
                            mutated_code=mutated_line.strip(),
                            mutation_type=mut_type,
                            tests_killed=killed,
                            survived=(killed == 0),
                        )
                        if result.survived:
                            results.append(result)

        return results

    def _is_safe_mutation(self, line: str, original: str) -> bool:
        """Check if mutation is safe to apply (not in string/comment)."""
        stripped = line.strip()
        # Skip comments
        if stripped.startswith("#"):
            return False
        # Skip string literals (basic check)
        if original in stripped and (stripped.count('"') % 2 == 0 or stripped.count("'") % 2 == 0):
            return True
        return False

    def _run_tests_with_mutation(
        self,
        source_file: str,
        test_file: str,
        mutated_code: str,
        language: str,
    ) -> int:
        """Run tests with mutated code. Return 1 if tests fail (mutation killed), 0 if pass (survived)."""
        # Write mutated code to temp file
        tmp_path = source_file + ".mutant"
        try:
            with open(tmp_path, "w", encoding="utf-8") as f:
                f.write(mutated_code)

            # Backup original
            with open(source_file, "r", encoding="utf-8") as f:
                backup = f.read()

            # Swap in mutant
            with open(source_file, "w", encoding="utf-8") as f:
                f.write(mutated_code)

            # Run tests
            import subprocess
            if language == "python":
                result = subprocess.run(
                    ["python", "-m", "pytest", test_file, "-x", "-q"],
                    capture_output=True,
                    timeout=60,
                )
            else:
                result = subprocess.CompletedProcess(args=[], returncode=-1)

            # Restore original
            with open(source_file, "w", encoding="utf-8") as f:
                f.write(backup)

            # Remove temp
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

            return 1 if result.returncode != 0 else 0

        except Exception as e:
            logger.debug("Mutation test failed: %s", e)
            # Restore
            try:
                with open(source_file, "r", encoding="utf-8") as f:
                    backup
                with open(source_file, "w", encoding="utf-8") as f:
                    f.write(backup)
            except Exception:
                pass
            return 0

    def _get_function_at_line(self, source_file: str, line_number: int) -> str:
        """Get function name at given line number."""
        try:
            with open(source_file, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read())
            for node in ast.iter_child_nodes(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    if hasattr(node, "lineno") and node.lineno <= line_number:
                        if hasattr(node, "end_lineno") and (node.end_lineno or node.lineno + 100) >= line_number:
                            return node.name
                elif isinstance(node, ast.ClassDef):
                    for child in ast.iter_child_nodes(node):
                        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            if hasattr(child, "lineno") and child.lineno <= line_number:
                                if hasattr(child, "end_lineno") and (child.end_lineno or child.lineno + 100) >= line_number:
                                    return f"{node.name}.{child.name}"
        except Exception:
            pass
        return "unknown"

    def get_weak_tests_report(self, results: List[MutationResult]) -> Dict[str, Any]:
        """Generate report of weak tests that survived mutations."""
        if not results:
            return {"status": "strong", "message": "All mutations were killed - tests are strong!"}

        by_function = {}
        for r in results:
            key = f"{r.file_path}::{r.function_name}"
            if key not in by_function:
                by_function[key] = []
            by_function[key].append(r)

        return {
            "status": "weak_tests_found",
            "total_mutations": len(results),
            "survived_mutations": len([r for r in results if r.survived]),
            "affected_functions": list(by_function.keys()),
            "details": [
                {
                    "function": r.function_name,
                    "line": r.line_number,
                    "mutation": f"{r.original_code} -> {r.mutated_code}",
                    "type": r.mutation_type,
                }
                for r in results[:20]  # Limit report
            ],
        }
