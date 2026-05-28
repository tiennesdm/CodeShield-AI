"""
CoverageAnalyzer Agent - Identifies coverage gaps and generates improvement targets.

Parses coverage reports, identifies uncovered code, and creates targeted
improvement tasks for the TestImprover agent.
"""

import ast
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class CoverageGap:
    file_path: str
    function_name: str
    line_start: int
    line_end: int
    gap_type: str  # "uncovered_lines", "uncovered_branch", "missing_exception"
    severity: str  # "critical", "high", "medium", "low"
    description: str
    current_coverage: float = 0.0
    suggested_test_types: List[str] = field(default_factory=list)
    code_snippet: str = ""


@dataclass
class ImprovementTarget:
    file_path: str
    function_name: str
    line_start: int
    line_end: int
    priority: int  # 1 = highest
    gap_type: str
    description: str
    suggested_test_types: List[str] = field(default_factory=list)
    code_snippet: str = ""


class CoverageAnalyzerAgent:
    """Analyzes coverage reports and identifies improvement targets."""

    name: str = "coverage_analyzer"
    role: str = "Coverage Gap Identifier"

    def analyze_gaps(
        self,
        uncovered_lines: Dict[str, List[int]],
        uncovered_functions: Dict[str, List[str]],
        source_dir: str,
        language: str = "python",
    ) -> List[ImprovementTarget]:
        """Analyze coverage gaps and return prioritized improvement targets."""
        targets = []

        # 1. Analyze uncovered lines → map to functions
        for file_path, lines in uncovered_lines.items():
            full_path = os.path.join(source_dir, file_path)
            if not os.path.exists(full_path):
                continue

            # Find which functions contain uncovered lines
            function_ranges = self._get_function_ranges(full_path, language)
            for func_name, (start, end) in function_ranges.items():
                uncovered_in_func = [l for l in lines if start <= l <= end]
                if uncovered_in_func:
                    coverage_pct = 100 - (len(uncovered_in_func) / max(end - start, 1) * 100)
                    snippet = self._get_code_snippet(full_path, start, end)
                    targets.append(ImprovementTarget(
                        file_path=file_path,
                        function_name=func_name,
                        line_start=start,
                        line_end=end,
                        priority=self._calc_priority(coverage_pct, func_name),
                        gap_type="uncovered_lines",
                        description=f"{len(uncovered_in_func)} lines uncovered in {func_name} (coverage: {coverage_pct:.1f}%)",
                        suggested_test_types=self._suggest_test_types(full_path, func_name, language),
                        code_snippet=snippet,
                    ))

        # 2. Analyze uncovered functions
        for file_path, funcs in uncovered_functions.items():
            full_path = os.path.join(source_dir, file_path)
            for func_name in funcs:
                # Skip if already covered by line analysis
                if any(t.file_path == file_path and t.function_name == func_name for t in targets):
                    continue
                function_ranges = self._get_function_ranges(full_path, language)
                if func_name in function_ranges:
                    start, end = function_ranges[func_name]
                    snippet = self._get_code_snippet(full_path, start, end)
                    targets.append(ImprovementTarget(
                        file_path=file_path,
                        function_name=func_name,
                        line_start=start,
                        line_end=end,
                        priority=1,  # Not covered at all = highest priority
                        gap_type="uncovered_function",
                        description=f"Function {func_name} has 0% coverage",
                        suggested_test_types=self._suggest_test_types(full_path, func_name, language),
                        code_snippet=snippet,
                    ))

        # Sort by priority
        targets.sort(key=lambda t: t.priority)
        return targets

    def _get_function_ranges(self, file_path: str, language: str) -> Dict[str, tuple]:
        """Get line ranges for all functions in a file."""
        ranges = {}
        if language == "python":
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    tree = ast.parse(f.read())
                for node in ast.iter_child_nodes(tree):
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        ranges[node.name] = (node.lineno, node.end_lineno or node.lineno + 10)
                    elif isinstance(node, ast.ClassDef):
                        for child in ast.iter_child_nodes(node):
                            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                                ranges[f"{node.name}.{child.name}"] = (child.lineno, child.end_lineno or child.lineno + 10)
            except Exception:
                pass
        return ranges

    def _get_code_snippet(self, file_path: str, start: int, end: int) -> str:
        """Extract code snippet from file."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            snippet_lines = lines[start - 1:end]
            return "\n".join(snippet_lines)
        except Exception:
            return ""

    def _calc_priority(self, coverage_pct: float, func_name: str) -> int:
        """Calculate improvement priority (1 = highest)."""
        if coverage_pct == 0:
            return 1
        elif coverage_pct < 25:
            return 2
        elif coverage_pct < 50:
            return 3
        elif coverage_pct < 75:
            return 4
        else:
            return 5

    def _suggest_test_types(self, file_path: str, func_name: str, language: str) -> List[str]:
        """Suggest what types of tests to add based on code analysis."""
        suggestions = ["basic"]
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Check for exception handling
            if "raise" in content or "try:" in content:
                suggestions.append("error")

            # Check for async
            if "async " in content:
                suggestions.append("async")

            # Check for conditionals (branch coverage)
            if content.count("if ") > 2:
                suggestions.append("branch")

            # Check for loops (edge cases)
            if "for " in content or "while " in content:
                suggestions.append("edge")

            # Check for None/empty handling
            if "is None" in content or "if not " in content:
                suggestions.append("null_safety")

            # Check for mutation risks
            if ".append(" in content or ".pop(" in content or ".sort(" in content:
                suggestions.append("mutation")

        except Exception:
            pass

        return list(set(suggestions))

    def generate_improvement_prompt(self, target: ImprovementTarget) -> str:
        """Generate a prompt for the AI test improver."""
        return f"""Generate test cases for the following function:

Function: {target.function_name}
File: {target.file_path}
Gap Type: {target.gap_type}
Priority: {target.priority}

Code:
```python
{target.code_snippet}
```

The current tests are NOT covering this function properly.
Please generate test cases that cover:
{chr(10).join(f"- {s}" for s in target.suggested_test_types)}

Generate pytest-style tests with proper fixtures and assertions.
"""
