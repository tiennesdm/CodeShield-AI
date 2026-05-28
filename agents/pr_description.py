"""
PR Description Generator for CodeShield AI Test Generation.

Generates beautiful, detailed Markdown pull request descriptions
summarizing auto-generated test cases with statistics, function
breakdowns, and test category coverage.
"""

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class FunctionTestInfo:
    """Information about tests generated for a single function."""

    function_name: str
    test_count: int = 0
    test_types: List[str] = field(default_factory=list)
    source_file: str = ""
    line_count: int = 0


@dataclass
class TestModuleSummary:
    """Summary of tests generated for a single module/file."""

    module_name: str
    source_file: str
    functions: List[FunctionTestInfo] = field(default_factory=list)
    total_tests: int = 0
    language: str = "python"

    @property
    def function_count(self) -> int:
        return len(self.functions)


@dataclass
class TestGenerationResult:
    """Complete result of a test generation run."""

    project_name: str = ""
    language: str = "python"
    modules: List[TestModuleSummary] = field(default_factory=list)
    total_functions: int = 0
    total_tests: int = 0
    test_files: List[str] = field(default_factory=list)
    generated_at: str = ""
    elapsed_time_ms: int = 0

    def __post_init__(self):
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()

    @property
    def coverage_estimate(self) -> int:
        """Estimate coverage percentage based on function-to-test ratio."""
        if self.total_functions == 0:
            return 0
        # Each function ideally has 4-5 test types; estimate coverage
        ratio = self.total_tests / max(self.total_functions * 4, 1)
        return min(int(ratio * 100), 95)

    @property
    def module_count(self) -> int:
        return len(self.modules)

    def get_all_test_types(self) -> List[str]:
        """Get all unique test types across all functions."""
        types: set = set()
        for module in self.modules:
            for func in module.functions:
                types.update(func.test_types)
        return sorted(types)

    def get_test_type_counts(self) -> Dict[str, int]:
        """Count how many functions have each test type."""
        counts: Dict[str, int] = {}
        for module in self.modules:
            for func in module.functions:
                for t in func.test_types:
                    counts[t] = counts.get(t, 0) + 1
        return counts


class PRDescriptionGenerator:
    """
    Generates formatted Markdown PR descriptions for auto-generated test cases.
    """

    # Emoji map for test types
    TEST_TYPE_ICONS: Dict[str, str] = {
        "basic": "\u2705",
        "edge": "\U0001f9ea",
        "error": "\u26a0\ufe0f",
        "exception": "\u26a0\ufe0f",
        "validation": "\U0001f510",
        "async": "\u26a1",
        "mock": "\U0001f916",
        "mocking": "\U0001f916",
        "integration": "\U0001f6e1",
        "performance": "\U0001f3c3",
        "security": "\U0001f512",
        "parameterized": "\U0001f504",
    }

    # Human-readable test type labels
    TEST_TYPE_LABELS: Dict[str, str] = {
        "basic": "Basic functionality",
        "edge": "Edge case handling",
        "error": "Error/exception handling",
        "exception": "Error/exception handling",
        "validation": "Input validation",
        "async": "Async behavior",
        "mock": "Mocking",
        "mocking": "Mocking",
        "integration": "Integration",
        "performance": "Performance",
        "security": "Security",
        "parameterized": "Parameterized",
    }

    # Test category checklist (always shown)
    DEFAULT_TEST_CATEGORIES: List[Dict[str, str]] = [
        {"type": "basic", "label": "Basic functionality tests", "applicable": "always"},
        {"type": "edge", "label": "Edge case handling", "applicable": "always"},
        {"type": "error", "label": "Error/exception tests", "applicable": "always"},
        {"type": "validation", "label": "Input validation tests", "applicable": "always"},
        {"type": "mock", "label": "Mock/patch tests", "applicable": "always"},
        {"type": "async", "label": "Async behavior tests", "applicable": "async"},
        {"type": "security", "label": "Security-focused tests", "applicable": "security"},
    ]

    @classmethod
    def generate(
        cls,
        result: TestGenerationResult,
        pr_agent_version: str = "1.0.0",
    ) -> str:
        """
        Generate a complete Markdown PR description.

        Args:
            result: The test generation result to describe
            pr_agent_version: Version of the PR agent

        Returns:
            Formatted Markdown string for the PR body
        """
        logger.info(
            "Generating PR description for project '%s' (%d modules, %d tests)",
            result.project_name, result.module_count, result.total_tests,
        )

        lines: List[str] = []

        # Header
        lines.append("## \U0001f916 Auto-Generated Test Cases by CodeShield AI\n")

        # Summary section
        lines.append("### Summary")
        lines.append(f"- **Project**: {result.project_name or 'Unknown'}")
        lines.append(f"- **Language**: {result.language.title()}")
        lines.append(f"- **Modules**: {result.module_count}")
        lines.append(f"- **Functions Found**: {result.total_functions}")
        lines.append(f"- **Test Cases Generated**: {result.total_tests}")
        lines.append(f"- **Coverage Estimate**: ~{result.coverage_estimate}%")
        lines.append(f"- **Generated At**: {result.generated_at}")
        if result.elapsed_time_ms > 0:
            elapsed_sec = result.elapsed_time_ms / 1000
            lines.append(f"- **Generation Time**: {elapsed_sec:.1f}s")
        lines.append("")

        # Test files section
        if result.test_files:
            lines.append("### Generated Test Files")
            for tf in result.test_files:
                lines.append(f"- `{tf}`")
            lines.append("")

        # Functions tested table
        lines.append("### Functions Tested\n")
        lines.append("| Module | Function | Tests | Types |")
        lines.append("|--------|----------|-------|-------|")

        for module in result.modules:
            for func in module.functions:
                type_tags = cls._format_test_types(func.test_types)
                module_display = module.module_name[:20]
                func_display = func.function_name[:30]
                lines.append(
                    f"| `{module_display}` | `{func_display}()` | "
                    f"{func.test_count} | {type_tags} |"
                )
        lines.append("")

        # Test type breakdown
        type_counts = result.get_test_type_counts()
        if type_counts:
            lines.append("### Test Type Breakdown\n")
            lines.append("| Test Type | Count | Icon |")
            lines.append("|-----------|-------|------|")
            for t, count in sorted(type_counts.items(), key=lambda x: -x[1]):
                icon = cls.TEST_TYPE_ICONS.get(t, "\U0001f9e9")
                label = cls.TEST_TYPE_LABELS.get(t, t.title())
                lines.append(f"| {label} | {count} | {icon} |")
            lines.append("")

        # Test categories checklist
        lines.append("### Test Categories\n")
        has_async = any(
            t in cls._get_all_types(result)
            for t in ("async", "await", "coroutine")
        )
        has_security = "security" in cls._get_all_types(result)

        for cat in cls.DEFAULT_TEST_CATEGORIES:
            applicable = cat["applicable"]
            if applicable == "always":
                lines.append(f"- \u2705 {cat['label']}")
            elif applicable == "async" and has_async:
                lines.append(f"- \u26a1 {cat['label']} (async code detected)")
            elif applicable == "security" and has_security:
                lines.append(f"- \U0001f512 {cat['label']} (security-relevant)")
            else:
                # Show as not applicable with strikethrough
                pass  # Skip non-applicable categories for cleaner output
        lines.append("")

        # Per-module details
        for module in result.modules:
            lines.append(f"#### Module: `{module.module_name}`")
            lines.append(f"- **Source**: `{module.source_file}`")
            lines.append(f"- **Functions**: {module.function_count}")
            lines.append(f"- **Tests**: {module.total_tests}")
            lines.append("")

            for func in module.functions:
                type_list = ", ".join(
                    f"`{t}`" for t in func.test_types
                ) if func.test_types else "`basic`"
                lines.append(
                    f"  - \U0001f539 `{func.function_name}()` "
                    f"- {func.test_count} tests ({type_list})"
                )
            lines.append("")

        # Footer
        lines.append("---\n")
        lines.append("### Generated By")
        lines.append(
            f"**CodeShield AI Test Generator Agent Swarm** \U0001f6e1\ufe0f  "
            f"(v{pr_agent_version})"
        )
        lines.append("")
        lines.append(
            "These tests were automatically generated using AI-powered analysis "
            "of your source code. Please review and adjust as needed before merging."
        )
        lines.append("")
        lines.append("---")

        return "\n".join(lines)

    @classmethod
    def generate_compact(
        cls,
        result: TestGenerationResult,
        pr_agent_version: str = "1.0.0",
    ) -> str:
        """
        Generate a compact PR description for smaller PRs.

        Args:
            result: The test generation result to describe
            pr_agent_version: Version of the PR agent

        Returns:
            Compact Markdown string
        """
        lines: List[str] = []

        lines.append("## \U0001f916 Auto-Generated Tests: "
                     f"{result.project_name or 'Project'}\n")
        lines.append(f"- **Language**: {result.language.title()}")
        lines.append(f"- **Functions**: {result.total_functions}")
        lines.append(f"- **Tests**: {result.total_tests}")
        lines.append(f"- **Coverage Estimate**: ~{result.coverage_estimate}%")
        lines.append("")

        if result.test_files:
            lines.append("**Files:** " + ", ".join(f"`{f}`" for f in result.test_files))
            lines.append("")

        lines.append("### Tested Functions\n")
        for module in result.modules:
            for func in module.functions:
                types = ", ".join(f"`{t}`" for t in func.test_types[:3])
                if len(func.test_types) > 3:
                    types += ", ..."
                lines.append(
                    f"- `{func.function_name}()` ({func.test_count} tests: {types})"
                )
        lines.append("")

        lines.append("---")
        lines.append(
            f"\U0001f6e1\ufe0f Generated by CodeShield AI v{pr_agent_version}"
        )

        return "\n".join(lines)

    @classmethod
    def _format_test_types(cls, types: List[str]) -> str:
        """Format test types as compact tags."""
        if not types:
            return "`basic`"
        tags = []
        for t in types[:4]:
            icon = cls.TEST_TYPE_ICONS.get(t, "")
            tags.append(f"{icon} `{t}`" if icon else f"`{t}`")
        if len(types) > 4:
            tags.append(f"+{len(types) - 4} more")
        return " ".join(tags)

    @classmethod
    def _get_all_types(cls, result: TestGenerationResult) -> List[str]:
        """Get flat list of all test type strings."""
        types: List[str] = []
        for m in result.modules:
            for f in m.functions:
                types.extend(f.test_types)
        return types

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TestGenerationResult:
        """
        Build a TestGenerationResult from a dictionary.

        Useful for deserializing from API responses or job storage.
        """
        modules = []
        for mod_data in data.get("modules", []):
            functions = []
            for func_data in mod_data.get("functions", []):
                functions.append(FunctionTestInfo(
                    function_name=func_data.get("function_name", "unknown"),
                    test_count=func_data.get("test_count", 0),
                    test_types=func_data.get("test_types", []),
                    source_file=func_data.get("source_file", ""),
                    line_count=func_data.get("line_count", 0),
                ))
            modules.append(TestModuleSummary(
                module_name=mod_data.get("module_name", "unknown"),
                source_file=mod_data.get("source_file", ""),
                functions=functions,
                total_tests=mod_data.get("total_tests", 0),
                language=mod_data.get("language", "python"),
            ))

        return TestGenerationResult(
            project_name=data.get("project_name", ""),
            language=data.get("language", "python"),
            modules=modules,
            total_functions=data.get("total_functions", 0),
            total_tests=data.get("total_tests", 0),
            test_files=data.get("test_files", []),
            generated_at=data.get("generated_at", ""),
            elapsed_time_ms=data.get("elapsed_time_ms", 0),
        )
