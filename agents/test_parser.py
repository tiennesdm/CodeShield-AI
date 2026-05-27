"""
TestParser Agent — Deep code parser for automatic test generation.

Parses source code using AST and regex-based extraction to identify all
testable units (functions, classes, methods) across Python, JavaScript,
TypeScript, Java, Go, and Ruby codebases.

Produces a structured output containing every function signature with its
arguments, return types, decorators, docstrings, complexity metrics, and
exception types — enabling downstream test generation agents to produce
comprehensive test suites.
"""

import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from agents.base import BaseSecurityAgent
from agents.results import AgentResult, ScanContext, ToolExecutionSummary
from models.test_models import ParsedFunction, ParserResult
from parsers.code_parser import (
    get_parser_for_file,
    get_parser_for_language,
    list_supported_languages,
)
from scanner.language_detector import LanguageDetector
from utils.logger import get_logger

logger = get_logger(__name__)


class TestParserAgent(BaseSecurityAgent):
    """
    Parses source code to extract all functions, classes, and methods for test generation.

    Supports Python (AST-based), JavaScript/TypeScript, Java, Go, and Ruby
    (regex-based parsing). The agent produces a ParserResult containing
    every testable unit with full signature metadata, cyclomatic complexity,
    and exception information.

    Attributes:
        name: Agent identifier ('test_parser')
        role: Human-readable role description
        tools: No external tools required (pure AST/regex)
        priority: Runs early in pipeline (priority 10)
    """

    name = "test_parser"
    role = "Code Parser & Test Target Extractor"
    tools: List[str] = []
    priority = 10  # Run early — provides data for test generation agents

    # File extensions we can parse
    SUPPORTED_EXTENSIONS: Set[str] = {
        ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs",
        ".java", ".go", ".rb",
    }

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """
        Initialize the TestParserAgent.

        Args:
            config: Optional configuration dict. Supports:
                - include_private: bool — include private functions (default False)
                - max_file_size_kb: int — skip files larger than this (default 500)
                - max_files: int — maximum files to parse (default 1000)
                - languages: List[str] — filter to specific languages
                - skip_tests: bool — skip test files (default True)
                - skip_patterns: List[str] — glob patterns to skip
        """
        super().__init__(config)
        self.include_private = self.config.get("include_private", False)
        self.max_file_size = self.config.get("max_file_size_kb", 500) * 1024
        self.max_files = self.config.get("max_files", 1000)
        self.filter_languages: Optional[Set[str]] = None
        if self.config.get("languages"):
            self.filter_languages = {
                lang.lower() for lang in self.config["languages"]
            }
        self.skip_tests = self.config.get("skip_tests", True)
        self.skip_patterns: List[str] = self.config.get("skip_patterns", [
            "node_modules", "vendor", ".git", "__pycache__",
            "*.min.js", "*.bundle.js", "dist", "build",
        ])
        self.language_detector = LanguageDetector()

    async def scan(self, context: ScanContext) -> AgentResult:
        """
        Scan source code and extract all testable units.

        Walks the source tree, detects languages, parses each file with
        the appropriate parser, and returns a structured result.

        Args:
            context: ScanContext with source_path and scan_id

        Returns:
            AgentResult with parsed functions/classes in metadata['parser_result']
        """
        start_time_ms = time.time() * 1000
        errors: List[str] = []
        tool_summaries: List[ToolExecutionSummary] = []

        source_path = context.source_path
        if not os.path.isdir(source_path):
            # Single file mode
            if os.path.isfile(source_path):
                result = await self._parse_single_file(source_path, context)
                elapsed = int((time.time() * 1000) - start_time_ms)
                return AgentResult(
                    agent_name=self.name,
                    agent_role=self.role,
                    scan_id=context.scan_id,
                    findings=[],  # No vulnerabilities — this is a parser
                    summary=self._build_summary(result),
                    execution_time_ms=elapsed,
                    status="success" if not result.errors else "partial",
                    errors=result.errors,
                    metadata={
                        "parser_result": result.model_dump(),
                        "files_parsed": result.files_parsed,
                        "files_failed": result.files_failed,
                        "total_functions": len(result.all_functions()),
                        "total_classes": len(result.all_classes()),
                        "languages": list(self._detected_languages),
                    },
                )
            else:
                errors.append(f"Source path not found: {source_path}")
                elapsed = int((time.time() * 1000) - start_time_ms)
                return AgentResult(
                    agent_name=self.name,
                    agent_role=self.role,
                    scan_id=context.scan_id,
                    errors=errors,
                    execution_time_ms=elapsed,
                    status="failed",
                    metadata={},
                )

        # Directory mode: discover and parse all source files
        result = await self._parse_directory(source_path, context)
        elapsed = int((time.time() * 1000) - start_time_ms)
        status = "success"
        if result.errors:
            status = "partial" if result.files_parsed > 0 else "failed"

        return AgentResult(
            agent_name=self.name,
            agent_role=self.role,
            scan_id=context.scan_id,
            findings=[],
            summary=self._build_summary(result),
            execution_time_ms=elapsed,
            status=status,
            errors=result.errors,
            metadata={
                "parser_result": result.model_dump(),
                "files_parsed": result.files_parsed,
                "files_failed": result.files_failed,
                "total_functions": len(result.all_functions()),
                "total_classes": len(result.all_classes()),
                "total_modules": len(result.modules),
                "languages": list(self._detected_languages),
            },
        )

    async def _parse_single_file(
        self, file_path: str, context: ScanContext
    ) -> ParserResult:
        """Parse a single source file."""
        result = ParserResult()
        self._detected_languages: Set[str] = set()

        try:
            parser = get_parser_for_file(file_path)
            if parser is None:
                ext = os.path.splitext(file_path)[1]
                result.errors.append(f"No parser for file extension: {ext}")
                result.files_failed = 1
                return result

            module = parser.parse_file(file_path)
            if not self.include_private:
                module.functions = [
                    f for f in module.functions if not f.is_private
                ]
                for cls in module.classes:
                    cls.methods = [
                        m for m in cls.methods if not m.is_private
                    ]

            result.modules.append(module)
            result.files_parsed = 1
            self._detected_languages.add(parser.language)

        except Exception as e:
            logger.error("[%s] Failed to parse %s: %s", context.scan_id, file_path, e)
            result.errors.append(f"Failed to parse {file_path}: {e}")
            result.files_failed = 1

        return result

    async def _parse_directory(
        self, source_path: str, context: ScanContext
    ) -> ParserResult:
        """Parse all source files in a directory tree."""
        result = ParserResult()
        self._detected_languages: Set[str] = set()
        files_parsed = 0
        files_failed = 0

        # Discover files
        all_files = self._discover_files(source_path)

        # Detect languages
        detected_langs = self.language_detector.detect_languages(source_path, all_files)
        logger.info(
            "[%s] Detected languages: %s", context.scan_id, detected_langs
        )

        # Filter by languages if configured
        if self.filter_languages:
            all_files = [
                f for f in all_files
                if self._get_file_language(f) in self.filter_languages
            ]

        # Sort to process in deterministic order
        all_files.sort()

        for file_path in all_files[:self.max_files]:
            # Skip files that are too large
            try:
                file_size = os.path.getsize(file_path)
                if file_size > self.max_file_size:
                    logger.debug("Skipping large file: %s (%d KB)", file_path, file_size // 1024)
                    continue
            except OSError:
                continue

            # Get parser for file
            parser = get_parser_for_file(file_path)
            if parser is None:
                continue

            try:
                module = parser.parse_file(file_path)

                # Filter private functions if not including them
                if not self.include_private:
                    module.functions = [
                        f for f in module.functions if not f.is_private
                    ]
                    for cls in module.classes:
                        cls.methods = [
                            m for m in cls.methods if not m.is_private
                        ]

                result.modules.append(module)
                files_parsed += 1
                self._detected_languages.add(parser.language)

                logger.debug(
                    "[%s] Parsed %s: %d functions, %d classes",
                    context.scan_id,
                    file_path,
                    len(module.functions),
                    len(module.classes),
                )

            except Exception as e:
                error_msg = f"Failed to parse {file_path}: {e}"
                logger.error("[%s] %s", context.scan_id, error_msg)
                result.errors.append(error_msg)
                files_failed += 1

        result.files_parsed = files_parsed
        result.files_failed = files_failed

        logger.info(
            "[%s] Parsing complete: %d files parsed, %d files failed, "
            "%d total functions, %d total classes",
            context.scan_id,
            files_parsed,
            files_failed,
            len(result.all_functions()),
            len(result.all_classes()),
        )

        return result

    def _discover_files(self, source_path: str) -> List[str]:
        """
        Discover all parseable source files under source_path.

        Skips test files, directories matching skip_patterns, and
        files without supported extensions.
        """
        discovered: List[str] = []

        for dirpath, dirnames, filenames in os.walk(source_path):
            # Filter out skipped directories
            dirnames[:] = [
                d for d in dirnames
                if not any(
                    pattern in d or d.startswith(".")
                    for pattern in self.skip_patterns
                )
            ]

            for filename in filenames:
                # Skip hidden files and patterns
                if filename.startswith("."):
                    continue

                # Check extension
                ext = os.path.splitext(filename)[1].lower()
                if ext not in self.SUPPORTED_EXTENSIONS:
                    continue

                # Skip test files if configured
                if self.skip_tests:
                    base = filename.lower()
                    # Common test file patterns
                    if any(
                        base.endswith(suffix)
                        for suffix in (
                            "_test.py", "_test.js", "_test.ts",
                            ".test.js", ".test.ts", ".spec.js", ".spec.ts",
                            "_spec.rb", "_test.rb", "_test.go",
                            "test_*.py",  # Python convention
                        )
                    ):
                        continue
                    if base.startswith("test_") and ext == ".py":
                        continue

                # Skip minified/bundled files
                if any(pattern.replace("*.", "").replace("*", "") in filename
                       for pattern in self.skip_patterns if "*." in pattern):
                    continue

                full_path = os.path.join(dirpath, filename)
                discovered.append(full_path)

        return discovered

    def _get_file_language(self, file_path: str) -> Optional[str]:
        """Get the language name for a file based on its extension."""
        ext = os.path.splitext(file_path)[1].lower()
        ext_to_lang = {
            ".py": "python",
            ".js": "javascript",
            ".jsx": "javascript",
            ".ts": "javascript",
            ".tsx": "javascript",
            ".mjs": "javascript",
            ".cjs": "javascript",
            ".java": "java",
            ".go": "go",
            ".rb": "ruby",
        }
        return ext_to_lang.get(ext)

    def _build_summary(self, result: ParserResult) -> Any:
        """Build a ScanSummary from parser results."""
        from agents.results import ScanSummary

        summary = ScanSummary()
        # For parser, we don't have severity findings
        # but we populate tool summaries
        summary.total_findings = len(result.all_functions())
        return summary

    # ------------------------------------------------------------------
    # Agent capability methods
    # ------------------------------------------------------------------

    def _get_supported_languages(self) -> List[str]:
        """Return languages supported by this agent."""
        return list_supported_languages()

    def _get_categories(self) -> List[str]:
        """Return categories this agent covers."""
        return ["code-parsing", "test-generation", "ast-analysis"]

    def _can_run_standalone(self) -> bool:
        """This agent can run standalone."""
        return True

    def _requires_network(self) -> bool:
        """No network required."""
        return False

    def _requires_external_tools(self) -> bool:
        """No external tools required — pure Python parsing."""
        return False

    # ------------------------------------------------------------------
    # Utility methods for consumers
    # ------------------------------------------------------------------

    def get_test_targets(self, result: ParserResult) -> List[Dict[str, Any]]:
        """
        Get a flat list of all test targets from a parser result.

        Returns a list of dictionaries suitable for passing to a
        test generation LLM prompt.
        """
        targets = []
        for func in result.all_functions():
            targets.append(func.to_test_target_dict())
        return targets

    def get_test_targets_by_class(
        self, result: ParserResult
    ) -> Dict[str, List[Dict[str, Any]]]:
        """
        Group test targets by class name.

        Returns a dictionary mapping class qualified names to lists
        of method test target dicts.
        """
        grouped: Dict[str, List[Dict[str, Any]]] = {}
        for module in result.modules:
            for cls in module.classes:
                targets = [m.to_test_target_dict() for m in cls.get_testable_methods()]
                if targets:
                    grouped[cls.qualified_name] = targets
        return grouped

    def get_high_complexity_functions(
        self, result: ParserResult, threshold: int = 10
    ) -> List[ParsedFunction]:
        """
        Return functions with cyclomatic complexity above threshold.

        These are candidates for more thorough testing.
        """
        return [
            f for f in result.all_functions()
            if f.complexity >= threshold
        ]

    def get_async_functions(self, result: ParserResult) -> List[ParsedFunction]:
        """Return all async functions for async-specific test generation."""
        return [f for f in result.all_functions() if f.is_async]

    def get_functions_with_exceptions(
        self, result: ParserResult
    ) -> List[ParsedFunction]:
        """Return all functions that raise exceptions."""
        return [f for f in result.all_functions() if f.raises]
