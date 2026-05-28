"""
Deep code parsers for multiple programming languages.

Extracts functions, classes, methods, and their signatures from source code
using AST (Python) or regex-based parsing (other languages).
Includes cyclomatic complexity calculation.
"""

import ast
import os
import re
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from models.test_models import (
    ParsedArg,
    ParsedClass,
    ParsedFunction,
    ParsedModule,
)
from utils.logger import get_logger

logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Cyclomatic Complexity Calculator
# ---------------------------------------------------------------------------

class ComplexityCalculator(ast.NodeVisitor):
    """
    Calculate cyclomatic complexity for Python code.

    Base complexity: 1
    +1 for each: if, elif, for, while, except, with, assert,
                 boolean operator (and, or), list/dict/set comprehension
    """

    def __init__(self) -> None:
        self.complexity = 1

    def visit_If(self, node: ast.If) -> None:
        self.complexity += 1
        # elif branches
        for child in node.orelse:
            if isinstance(child, ast.If):
                self.complexity += 1
        self.generic_visit(node)

    def visit_For(self, node: ast.For) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_While(self, node: ast.While) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_ExceptHandler(self, node: ast.ExceptHandler) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_With(self, node: ast.With) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_Assert(self, node: ast.Assert) -> None:
        self.complexity += 1
        self.generic_visit(node)

    def visit_BoolOp(self, node: ast.BoolOp) -> None:
        # Each boolean operator (and, or) adds 1
        self.complexity += len(node.values) - 1
        self.generic_visit(node)

    def visit_ListComp(self, node: ast.ListComp) -> None:
        self.complexity += len(node.generators)
        self.generic_visit(node)

    def visit_SetComp(self, node: ast.SetComp) -> None:
        self.complexity += len(node.generators)
        self.generic_visit(node)

    def visit_DictComp(self, node: ast.DictComp) -> None:
        self.complexity += len(node.generators)
        self.generic_visit(node)

    def visit_GeneratorExp(self, node: ast.GeneratorExp) -> None:
        self.complexity += len(node.generators)
        self.generic_visit(node)

    @classmethod
    def calculate(cls, node: ast.AST) -> int:
        """Calculate complexity for an AST node."""
        calc = cls()
        calc.visit(node)
        return calc.complexity


def calculate_complexity_regex(code: str, language: str) -> int:
    """
    Calculate approximate cyclomatic complexity for non-Python languages.

    Uses regex-based counting of control-flow constructs.
    """
    complexity = 1
    code_lower = code.lower()

    if language in ("javascript", "typescript"):
        # if statements (including else if)
        complexity += len(re.findall(r'\bif\s*\(', code_lower))
        complexity += len(re.findall(r'\belse\s+if\s*\(', code_lower))
        # loops
        complexity += len(re.findall(r'\bfor\s*\(', code_lower))
        complexity += len(re.findall(r'\bwhile\s*\(', code_lower))
        complexity += len(re.findall(r'\bdo\s*\{', code_lower))
        # switch cases
        complexity += len(re.findall(r'\bcase\s+', code_lower))
        # catch
        complexity += len(re.findall(r'\bcatch\s*\(', code_lower))
        # ternary
        complexity += len(re.findall(r'\?\s*[^:]*\s*:', code_lower))
        # && and ||
        complexity += len(re.findall(r'&&|\|\|', code))

    elif language == "java":
        complexity += len(re.findall(r'\bif\s*\(', code_lower))
        complexity += len(re.findall(r'\belse\s+if\s*\(', code_lower))
        complexity += len(re.findall(r'\bfor\s*\(', code_lower))
        complexity += len(re.findall(r'\bwhile\s*\(', code_lower))
        complexity += len(re.findall(r'\bdo\s*\{', code_lower))
        complexity += len(re.findall(r'\bcase\s+', code_lower))
        complexity += len(re.findall(r'\bcatch\s*\(', code_lower))
        complexity += len(re.findall(r'\?\s*[^:]*\s*:', code_lower))
        complexity += len(re.findall(r'&&|\|\|', code))

    elif language == "go":
        complexity += len(re.findall(r'\bif\s+', code_lower))
        complexity += len(re.findall(r'\bfor\s+', code_lower))
        complexity += len(re.findall(r'\bswitch\s+', code_lower))
        complexity += len(re.findall(r'\bcase\s+', code_lower))
        complexity += len(re.findall(r'&&|\|\|', code))

    elif language == "ruby":
        complexity += len(re.findall(r'\bif\b', code_lower))
        complexity += len(re.findall(r'\belsif\b', code_lower))
        complexity += len(re.findall(r'\bunless\b', code_lower))
        complexity += len(re.findall(r'\bfor\b', code_lower))
        complexity += len(re.findall(r'\bwhile\b', code_lower))
        complexity += len(re.findall(r'\buntil\b', code_lower))
        complexity += len(re.findall(r'\brescue\b', code_lower))
        complexity += len(re.findall(r'\band\b|\bor\b', code_lower))
        complexity += len(re.findall(r'\bwhen\b', code_lower))

    return max(1, complexity)


# ---------------------------------------------------------------------------
# Base Parser
# ---------------------------------------------------------------------------

class BaseCodeParser(ABC):
    """Abstract base class for all language-specific code parsers."""

    language: str = ""
    extensions: List[str] = []

    @abstractmethod
    def parse_file(self, file_path: str) -> ParsedModule:
        """Parse a source file and return a ParsedModule."""

    @abstractmethod
    def parse_string(self, code: str, file_path: str = "") -> ParsedModule:
        """Parse source code from a string and return a ParsedModule."""

    def _read_file(self, file_path: str) -> str:
        """Read file contents with encoding fallback."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                return f.read()
        except UnicodeDecodeError:
            with open(file_path, "r", encoding="latin-1") as f:
                return f.read()
        except Exception as e:
            logger.error("Failed to read %s: %s", file_path, e)
            raise

    def _is_private_name(self, name: str) -> bool:
        """Check if a name indicates a private/internal member."""
        return name.startswith("_") or name.startswith("__")


# ---------------------------------------------------------------------------
# Python Parser (AST-based)
# ---------------------------------------------------------------------------

class PythonCodeParser(BaseCodeParser):
    """
    Deep parser for Python source code using the ast module.

    Extracts all functions, classes, methods, async functions, decorators,
    type annotations, docstrings, imports, and cyclomatic complexity.
    """

    language = "python"
    extensions = [".py"]

    def parse_file(self, file_path: str) -> ParsedModule:
        """Parse a Python source file."""
        code = self._read_file(file_path)
        return self.parse_string(code, file_path)

    def parse_string(self, code: str, file_path: str = "") -> ParsedModule:
        """Parse Python code from a string."""
        try:
            tree = ast.parse(code)
        except SyntaxError as e:
            logger.error("Syntax error in %s: %s", file_path, e)
            return ParsedModule(
                file_path=file_path,
                language=self.language,
                total_lines=code.count("\n") + 1,
            )

        total_lines = code.count("\n") + 1
        module = ParsedModule(
            file_path=file_path,
            language=self.language,
            total_lines=total_lines,
        )

        # Extract module docstring
        module.module_docstring = ast.get_docstring(tree)

        # Extract imports
        module.imports = self._extract_imports(tree)

        # Build qualified name prefix from file path
        module_path = self._get_module_path(file_path)

        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func = self._parse_function(
                    node, module_path, file_path, is_method=False
                )
                module.functions.append(func)
            elif isinstance(node, ast.ClassDef):
                cls = self._parse_class(node, module_path, file_path)
                module.classes.append(cls)

        return module

    def _get_module_path(self, file_path: str) -> str:
        """Convert file path to dotted module path."""
        if not file_path:
            return ""
        path = Path(file_path)
        parts = list(path.parts)
        if parts[-1].endswith(".py"):
            parts[-1] = parts[-1][:-3]  # Remove .py
        return ".".join(parts)

    def _extract_imports(self, tree: ast.AST) -> List[str]:
        """Extract all import statements from the AST."""
        imports = []
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    imports.append(alias.name)
            elif isinstance(node, ast.ImportFrom):
                module = node.module or ""
                for alias in node.names:
                    imports.append(f"{module}.{alias.name}" if module else alias.name)
        return imports

    def _extract_decorators(self, node: ast.FunctionDef) -> List[str]:
        """Extract decorator names from a function/class node."""
        decorators = []
        for dec in node.decorator_list:
            decorators.append(self._expr_to_string(dec))
        return decorators

    def _expr_to_string(self, node: ast.expr) -> str:
        """Convert an AST expression to its string representation."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._expr_to_string(node.value)}.{node.attr}"
        elif isinstance(node, ast.Call):
            func_str = self._expr_to_string(node.func)
            return f"{func_str}()"
        elif isinstance(node, ast.Constant):
            return repr(node.value)
        return ""

    def _extract_raises(self, node: ast.AST) -> List[str]:
        """Extract all exception types raised in a function body."""
        raises = []
        for child in ast.walk(node):
            if isinstance(child, ast.Raise):
                if child.exc:
                    exc_name = self._get_raise_name(child.exc)
                    if exc_name and exc_name not in raises:
                        raises.append(exc_name)
        return raises

    def _get_raise_name(self, node: ast.expr) -> str:
        """Get the exception name from a Raise node."""
        if isinstance(node, ast.Call):
            return self._expr_to_string(node.func)
        elif isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._expr_to_string(node.value)}.{node.attr}"
        return ""

    def _get_arg_annotation(self, annotation: Optional[ast.expr]) -> Optional[str]:
        """Convert an annotation AST node to string."""
        if annotation is None:
            return None
        return ast.unparse(annotation)

    def _get_default_value(self, default: Optional[ast.expr]) -> Optional[str]:
        """Convert a default value AST node to string."""
        if default is None:
            return None
        return ast.unparse(default)

    def _parse_function_args(self, args: ast.arguments) -> List[ParsedArg]:
        """Parse function arguments into ParsedArg objects."""
        parsed_args: List[ParsedArg] = []

        # Positional-only args
        for i, arg in enumerate(args.posonlyargs):
            default_idx = i - (len(args.posonlyargs) - len(args.posonlydefaults))
            default = None
            if default_idx >= 0 and args.posonlydefaults:
                d_idx = default_idx - (len(args.posonlyargs) - len(args.posonlydefaults))
                if 0 <= d_idx < len(args.posonlydefaults):
                    default = self._get_default_value(args.posonlydefaults[d_idx])
            parsed_args.append(
                ParsedArg(
                    name=arg.arg,
                    type_annotation=self._get_arg_annotation(arg.annotation),
                    default_value=default,
                    is_posonly=True,
                )
            )

        # Regular args
        num_defaults = len(args.defaults)
        num_args = len(args.args)
        for i, arg in enumerate(args.args):
            default = None
            default_offset = num_args - num_defaults
            if i >= default_offset and num_defaults > 0:
                d_idx = i - default_offset
                if 0 <= d_idx < num_defaults:
                    default = self._get_default_value(args.defaults[d_idx])
            parsed_args.append(
                ParsedArg(
                    name=arg.arg,
                    type_annotation=self._get_arg_annotation(arg.annotation),
                    default_value=default,
                )
            )

        # *args
        if args.vararg:
            parsed_args.append(
                ParsedArg(
                    name=args.vararg.arg,
                    type_annotation=self._get_arg_annotation(args.vararg.annotation),
                    is_vararg=True,
                )
            )

        # Keyword-only args
        num_kw_defaults = len(args.kw_defaults)
        num_kwonly = len(args.kwonlyargs)
        for i, arg in enumerate(args.kwonlyargs):
            default = self._get_default_value(args.kw_defaults[i]) if i < num_kw_defaults else None
            parsed_args.append(
                ParsedArg(
                    name=arg.arg,
                    type_annotation=self._get_arg_annotation(arg.annotation),
                    default_value=default,
                    is_kwonly=True,
                )
            )

        # **kwargs
        if args.kwarg:
            parsed_args.append(
                ParsedArg(
                    name=args.kwarg.arg,
                    type_annotation=self._get_arg_annotation(args.kwarg.annotation),
                    is_kwarg=True,
                )
            )

        return parsed_args

    def _parse_function(
        self,
        node: Union[ast.FunctionDef, ast.AsyncFunctionDef],
        module_path: str,
        file_path: str,
        is_method: bool = False,
        class_name: str = "",
        class_decorators: Optional[List[str]] = None,
    ) -> ParsedFunction:
        """Parse a single function definition."""
        decorators = self._extract_decorators(node)
        is_async = isinstance(node, ast.AsyncFunctionDef)

        # Build qualified name
        if is_method and class_name:
            qualified_name = f"{module_path}.{class_name}.{node.name}"
        else:
            qualified_name = f"{module_path}.{node.name}"

        # Detect method type from decorators
        is_classmethod = "classmethod" in decorators
        is_staticmethod = "staticmethod" in decorators
        is_property_getter = "property" in decorators
        is_property_setter = any(
            d.startswith(node.name) and ".setter" in d for d in decorators
        )
        is_constructor = node.name == "__init__"

        # Extract return type
        return_type = self._get_arg_annotation(node.returns)

        # Extract raises
        raises = self._extract_raises(node)

        # Calculate complexity
        complexity = ComplexityCalculator.calculate(node)

        # Get line range
        line_start = node.lineno
        line_end = node.end_lineno or node.lineno

        func = ParsedFunction(
            name=node.name,
            qualified_name=qualified_name,
            file_path=file_path,
            line_start=line_start,
            line_end=line_end,
            args=self._parse_function_args(node.args),
            return_type=return_type,
            decorators=decorators,
            docstring=ast.get_docstring(node),
            is_async=is_async,
            is_method=is_method,
            is_classmethod=is_classmethod,
            is_staticmethod=is_staticmethod,
            is_private=self._is_private_name(node.name),
            is_property_getter=is_property_getter,
            is_property_setter=is_property_setter,
            is_constructor=is_constructor,
            raises=raises,
            complexity=complexity,
        )
        return func

    def _parse_class(
        self, node: ast.ClassDef, module_path: str, file_path: str
    ) -> ParsedClass:
        """Parse a class definition and its methods."""
        decorators = self._extract_decorators(node)

        # Extract base classes
        bases = []
        for base in node.bases:
            bases.append(self._expr_to_string(base))

        qualified_name = f"{module_path}.{node.name}"

        # Check if dataclass
        is_dataclass = any(
            d in ("dataclass", "dataclasses.dataclass") for d in decorators
        )

        cls = ParsedClass(
            name=node.name,
            qualified_name=qualified_name,
            file_path=file_path,
            line_start=node.lineno,
            line_end=node.end_lineno or node.lineno,
            bases=bases,
            docstring=ast.get_docstring(node),
            decorators=decorators,
            is_dataclass=is_dataclass,
            module_path=module_path,
        )

        # Parse methods
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                method = self._parse_function(
                    child,
                    module_path,
                    file_path,
                    is_method=True,
                    class_name=node.name,
                )
                cls.methods.append(method)

        return cls


# ---------------------------------------------------------------------------
# JavaScript / TypeScript Parser (regex-based)
# ---------------------------------------------------------------------------

class JavaScriptCodeParser(BaseCodeParser):
    """
    Parser for JavaScript and TypeScript source code.

    Uses regex-based extraction for:
    - Functions: function name(args) {}
    - Arrow functions: const name = (args) => {}
    - Class methods: class Name { method() {} }
    - Async variants
    - Exports
    """

    language = "javascript"
    extensions = [".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"]

    # JavaScript reserved keywords that shouldn't be parsed as method names
    JS_RESERVED_KEYWORDS = {
        "if", "else", "for", "while", "do", "switch", "case", "default",
        "try", "catch", "finally", "with", "return", "break", "continue",
        "throw", "new", "delete", "typeof", "instanceof", "void", "yield",
        "await", "in", "of", "debugger",
    }

    # Patterns for function detection
    FUNCTION_PATTERNS = [
        # async function name(args)
        (r'(?:export\s+(?:default\s+)?)?(?:async\s+)?function\s+(\w+)\s*\(([^)]*)\)\s*(?::\s*([\w<>|[\].\s]+))?\s*\{',
         True, False),
        # async function (anonymous) - assigned
        (r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?function\s*\(([^)]*)\)\s*(?::\s*([\w<>|[\].\s]+))?\s*\{',
         False, False),
        # const name = async (args) =>
        (r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\(([^)]*)\)\s*(?::\s*([\w<>|[\].\s]+))?\s*=>\s*\{?',
         False, False),
        # method shorthand: method(args) { (inside class/object)
        (r'(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*(?::\s*([\w<>|[\].\s]+))?\s*\{',
         False, True),
    ]

    # Arrow function assigned to const/let/var
    ARROW_PATTERN = re.compile(
        r'(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?(?:\(([^)]*)\)|(\w+))\s*=>',
        re.MULTILINE,
    )

    # Class pattern
    CLASS_PATTERN = re.compile(
        r'(?:export\s+(?:default\s+)?)?class\s+(\w+)\s*(?:extends\s+(\w+))?\s*\{',
        re.MULTILINE,
    )

    # Method inside class
    METHOD_PATTERN = re.compile(
        r'(?:async\s+)?(\w+|\[\s*Symbol\.\w+\s*\])\s*\(([^)]*)\)\s*(?::\s*([\w<>|[\].\s]+))?\s*\{',
        re.MULTILINE,
    )

    # Import patterns
    IMPORT_PATTERN = re.compile(
        r"import\s+(?:(\{[^}]*\}|\*\s+as\s+\w+|\w+)\s+from\s+)?['\"]([^'\"]+)['\"]"
    )

    def parse_file(self, file_path: str) -> ParsedModule:
        """Parse a JS/TS source file."""
        code = self._read_file(file_path)
        return self.parse_string(code, file_path)

    def parse_string(self, code: str, file_path: str = "") -> ParsedModule:
        """Parse JS/TS code from a string."""
        language = "typescript" if any(
            file_path.endswith(ext) for ext in (".ts", ".tsx")
        ) else "javascript"

        total_lines = code.count("\n") + 1
        module = ParsedModule(
            file_path=file_path,
            language=language,
            total_lines=total_lines,
        )

        # Extract imports
        module.imports = self._extract_imports(code)

        # Parse classes
        module.classes = self._parse_classes(code, file_path)

        # Parse top-level functions
        module.functions = self._parse_top_level_functions(code, file_path)

        return module

    def _extract_imports(self, code: str) -> List[str]:
        """Extract import statements from JS/TS code."""
        imports = []
        for match in self.IMPORT_PATTERN.finditer(code):
            imports.append(match.group(2))
        return imports

    def _parse_top_level_functions(self, code: str, file_path: str) -> List[ParsedFunction]:
        """Parse top-level function declarations."""
        functions = []

        # Named function declarations
        func_pattern = re.compile(
            r'(?:export\s+(?:default\s+)?)?(async\s+)?function\s+(\w+)\s*\(([^)]*)\)\s*(?::\s*([\w<>|[\].\s]+))?\s*\{',
            re.MULTILINE,
        )
        for match in func_pattern.finditer(code):
            is_async = bool(match.group(1))
            name = match.group(2)
            args_str = match.group(3) or ""
            return_type = (match.group(4) or "").strip() or None
            line_start = code[:match.start()].count("\n") + 1

            # Extract body to find line_end
            body_start = match.end() - 1
            body_end = self._find_matching_brace(code, body_start)
            if body_end is None:
                body_end = body_start

            body = code[body_start:body_end + 1]
            complexity = calculate_complexity_regex(body, self.language)

            # Extract raises (throw statements)
            raises = re.findall(r'throw\s+new\s+(\w+)', body)

            functions.append(
                ParsedFunction(
                    name=name,
                    qualified_name=name,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=code[:body_end + 1].count("\n") + 1,
                    args=self._parse_js_args(args_str),
                    return_type=return_type,
                    is_async=is_async,
                    is_private=self._is_private_name(name),
                    raises=raises,
                    complexity=complexity,
                )
            )

        # Arrow functions and function expressions assigned to variables
        arrow_pattern = re.compile(
            r'(?:export\s+)?(?:const|let|var)\s+(\w+)\s*=\s*(async\s+)?(?:function\s*\(([^)]*)\)\s*(?::\s*([\w<>|[\].\s]+))?\s*\{|\(([^)]*)\)\s*(?::\s*([\w<>|[\].\s]+))?\s*=>\s*\{?)',
            re.MULTILINE,
        )
        for match in arrow_pattern.finditer(code):
            name = match.group(1)
            is_async = bool(match.group(2))
            args_str = match.group(3) or match.group(5) or ""
            return_type = (match.group(4) or match.group(6) or "").strip() or None
            line_start = code[:match.start()].count("\n") + 1

            # Extract body
            body_start = match.end() - 1
            if code[body_start] == "{":
                body_end = self._find_matching_brace(code, body_start)
                body = code[body_start:body_end + 1] if body_end else ""
            else:
                # Single expression arrow: find until semicolon or newline
                end_idx = code.find(";", match.end())
                if end_idx == -1:
                    end_idx = len(code)
                body = code[match.end():end_idx]

            complexity = calculate_complexity_regex(body, self.language)
            raises = re.findall(r'throw\s+new\s+(\w+)', body)

            line_end = code[:match.end() + len(body)].count("\n") + 1

            functions.append(
                ParsedFunction(
                    name=name,
                    qualified_name=name,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    args=self._parse_js_args(args_str),
                    return_type=return_type,
                    is_async=is_async,
                    is_private=self._is_private_name(name),
                    raises=raises,
                    complexity=complexity,
                )
            )

        return functions

    def _parse_classes(self, code: str, file_path: str) -> List[ParsedClass]:
        """Parse class definitions."""
        classes = []

        for match in self.CLASS_PATTERN.finditer(code):
            name = match.group(1)
            base_class = match.group(2)
            line_start = code[:match.start()].count("\n") + 1

            # Find class body
            body_start = code.find("{", match.end() - 1)
            body_end = self._find_matching_brace(code, body_start)
            if body_end is None:
                body_end = body_start

            class_body = code[body_start:body_end + 1]
            line_end = code[:body_end + 1].count("\n") + 1

            # Parse methods
            methods = self._parse_class_methods(class_body, name, file_path, line_start)

            # Extract docstring from JSDoc comment
            docstring = self._extract_jsdoc(code, match.start())

            classes.append(
                ParsedClass(
                    name=name,
                    qualified_name=name,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    methods=methods,
                    bases=[base_class] if base_class else [],
                    docstring=docstring,
                )
            )

        return classes

    def _parse_class_methods(
        self, class_body: str, class_name: str, file_path: str, class_line_offset: int
    ) -> List[ParsedFunction]:
        """Parse methods within a class body."""
        methods = []

        # Match methods: name(args) { ... }
        method_pattern = re.compile(
            r'(?:async\s+)?(static\s+)?(get\s+|set\s+)?(\w+|\[\s*Symbol\.\w+\s*\])\s*\(([^)]*)\)\s*(?::\s*([\w<>|[\].\s]+))?\s*\{',
            re.MULTILINE,
        )

        for match in method_pattern.finditer(class_body):
            is_static = bool(match.group(1))
            accessor = match.group(2) or ""
            name = match.group(3)
            args_str = match.group(4) or ""
            return_type = (match.group(5) or "").strip() or None

            # Skip JavaScript reserved keywords (e.g., `if (cond) {` inside methods)
            if name in self.JS_RESERVED_KEYWORDS:
                continue

            is_getter = accessor.strip() == "get" if accessor else False
            is_setter = accessor.strip() == "set" if accessor else False
            is_async = class_body[match.start():match.start() + 6] == "async "

            # Find method body
            body_start = class_body.find("{", match.end() - 1)
            body_end = self._find_matching_brace(class_body, body_start)
            if body_end is None:
                body_end = body_start

            body = class_body[body_start:body_end + 1]
            complexity = calculate_complexity_regex(body, self.language)
            raises = re.findall(r'throw\s+new\s+(\w+)', body)

            method_line_start = class_line_offset + class_body[:match.start()].count("\n")
            method_line_end = class_line_offset + class_body[:body_end + 1].count("\n")

            methods.append(
                ParsedFunction(
                    name=name,
                    qualified_name=f"{class_name}.{name}",
                    file_path=file_path,
                    line_start=method_line_start,
                    line_end=method_line_end,
                    args=self._parse_js_args(args_str),
                    return_type=return_type,
                    is_async=is_async,
                    is_method=True,
                    is_staticmethod=is_static,
                    is_private=self._is_private_name(name),
                    is_property_getter=is_getter,
                    is_property_setter=is_setter,
                    raises=raises,
                    complexity=complexity,
                )
            )

        return methods

    def _parse_js_args(self, args_str: str) -> List[ParsedArg]:
        """Parse JavaScript/TypeScript argument string into ParsedArg list."""
        args = []
        if not args_str.strip():
            return args

        # Simple split by comma, handling basic type annotations
        parts = self._split_args(args_str)
        for part in parts:
            part = part.strip()
            if not part:
                continue

            # Check for default value
            default = None
            if "=" in part:
                idx = part.index("=")
                default = part[idx + 1:].strip()
                part = part[:idx].strip()

            # Check for type annotation
            type_annotation = None
            if ":" in part:
                idx = part.index(":")
                type_annotation = part[idx + 1:].strip()
                part = part[:idx].strip()

            # Destructuring: { a, b } or [ a, b ]
            if part.startswith("{") or part.startswith("["):
                name = part
            else:
                name = part.lstrip("...").strip()

            is_vararg = "..." in part

            args.append(
                ParsedArg(
                    name=name,
                    type_annotation=type_annotation,
                    default_value=default,
                    is_vararg=is_vararg,
                )
            )

        return args

    def _split_args(self, args_str: str) -> List[str]:
        """Split argument string by commas, respecting nested brackets."""
        parts = []
        current = ""
        depth = 0
        for char in args_str:
            if char in "([{":
                depth += 1
                current += char
            elif char in ")]}]":
                depth -= 1
                current += char
            elif char == "," and depth == 0:
                parts.append(current)
                current = ""
            else:
                current += char
        if current.strip():
            parts.append(current)
        return parts

    def _find_matching_brace(self, code: str, open_pos: int) -> Optional[int]:
        """Find the position of the matching closing brace."""
        if open_pos >= len(code) or code[open_pos] != "{":
            return None
        depth = 1
        in_string = False
        string_char = None
        i = open_pos + 1
        while i < len(code) and depth > 0:
            char = code[i]
            if not in_string:
                if char in ('"', "'", "`"):
                    in_string = True
                    string_char = char
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
            else:
                if char == string_char and code[i - 1] != "\\":
                    in_string = False
                    string_char = None
            i += 1
        return i - 1 if depth == 0 else None

    def _extract_jsdoc(self, code: str, pos: int) -> Optional[str]:
        """Extract JSDoc comment before a position."""
        before = code[:pos]
        match = re.search(r'/\*\*(.*?)\*/', before, re.DOTALL)
        if match:
            doc = match.group(1)
            # Remove leading * from each line
            lines = [line.lstrip(" \t*") for line in doc.split("\n")]
            return "\n".join(lines).strip()
        return None


# ---------------------------------------------------------------------------
# Java Parser (regex-based)
# ---------------------------------------------------------------------------

class JavaCodeParser(BaseCodeParser):
    """
    Parser for Java source code using regex-based extraction.

    Extracts classes, methods, constructors, annotations, and imports.
    """

    language = "java"
    extensions = [".java"]

    # Java reserved keywords — not valid method names
    JAVA_RESERVED_KEYWORDS = {
        "if", "else", "for", "while", "do", "switch", "case", "default",
        "try", "catch", "finally", "synchronized", "return", "break",
        "continue", "throw", "new", "assert",
    }

    # Method pattern: visibility [static/final] ReturnType name(args) [throws ...] {
    METHOD_PATTERN = re.compile(
        r'((?:@[\w.]+\s*)*)\s*(public|private|protected)?\s*(static\s+)?(final\s+)?(synchronized\s+)?(\s*[\w.<>\[\],\s]+?)\s+(\w+)\s*\(([^)]*)\)\s*(?:throws\s+([\w.\s,]+))?\s*\{',
        re.MULTILINE,
    )

    # Class pattern
    CLASS_PATTERN = re.compile(
        r'((?:@[\w.]+\s*)*)\s*(public\s+)?(final\s+)?(abstract\s+)?class\s+(\w+)\s*(?:extends\s+(\w+))?\s*(?:implements\s+([\w.\s,]+))?\s*\{',
        re.MULTILINE,
    )

    # Import pattern
    IMPORT_PATTERN = re.compile(
        r'import\s+(static\s+)?([\w.*]+);'
    )

    # Package pattern
    PACKAGE_PATTERN = re.compile(
        r'package\s+([\w.]+);'
    )

    # Constructor pattern (must not have return type)
    CONSTRUCTOR_PATTERN = re.compile(
        r'((?:@[\w.]+\s*)*)\s*(public|private|protected)?\s*(\w+)\s*\(([^)]*)\)\s*(?:throws\s+([\w.\s,]+))?\s*\{',
        re.MULTILINE,
    )

    def parse_file(self, file_path: str) -> ParsedModule:
        """Parse a Java source file."""
        code = self._read_file(file_path)
        return self.parse_string(code, file_path)

    def parse_string(self, code: str, file_path: str = "") -> ParsedModule:
        """Parse Java code from a string."""
        total_lines = code.count("\n") + 1
        module = ParsedModule(
            file_path=file_path,
            language=self.language,
            total_lines=total_lines,
        )

        # Extract imports
        module.imports = self._extract_imports(code)

        # Extract package
        package_match = self.PACKAGE_PATTERN.search(code)
        package = package_match.group(1) if package_match else ""

        # Parse classes
        module.classes = self._parse_classes(code, file_path, package)

        # Parse top-level methods (outside classes, e.g., in interfaces)
        # Java doesn't really have top-level functions

        return module

    def _extract_imports(self, code: str) -> List[str]:
        """Extract import statements."""
        imports = []
        for match in self.IMPORT_PATTERN.finditer(code):
            imports.append(match.group(2))
        return imports

    def _parse_classes(self, code: str, file_path: str, package: str) -> List[ParsedClass]:
        """Parse class definitions."""
        classes = []

        for match in self.CLASS_PATTERN.finditer(code):
            annotations_str = match.group(1) or ""
            name = match.group(5)
            extends = match.group(6)
            implements = match.group(7)

            line_start = code[:match.start()].count("\n") + 1

            # Find class body
            body_start = code.find("{", match.end() - 1)
            body_end = self._find_matching_brace(code, body_start)
            if body_end is None:
                body_end = body_start

            class_body = code[body_start:body_end + 1]
            line_end = code[:body_end + 1].count("\n") + 1

            # Parse methods
            methods = self._parse_java_methods(
                class_body, name, file_path, line_start, package
            )

            # Build bases list
            bases = []
            if extends:
                bases.append(extends)
            if implements:
                for impl in implements.split(","):
                    impl = impl.strip()
                    if impl:
                        bases.append(impl)

            # Extract annotations
            annotations = re.findall(r'@([\w.]+)', annotations_str)

            classes.append(
                ParsedClass(
                    name=name,
                    qualified_name=f"{package}.{name}" if package else name,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    methods=methods,
                    bases=bases,
                    docstring=None,  # Java uses Javadoc
                    decorators=annotations,
                )
            )

        return classes

    def _parse_java_methods(
        self, class_body: str, class_name: str, file_path: str,
        class_line_offset: int, package: str
    ) -> List[ParsedFunction]:
        """Parse methods within a class body."""
        methods = []
        consumed_ranges: List[Tuple[int, int]] = []  # Track consumed body ranges

        def _is_inside_consumed(pos: int) -> bool:
            """Check if position is inside an already-consumed method body."""
            for start, end in consumed_ranges:
                if start <= pos <= end:
                    return True
            return False

        # Regular methods
        for match in self.METHOD_PATTERN.finditer(class_body):
            annotations_str = match.group(1) or ""
            visibility = match.group(2) or ""
            is_static = bool(match.group(3))
            return_type = match.group(6).strip()
            method_name = match.group(7)
            args_str = match.group(8) or ""
            throws_str = match.group(9) or ""

            # Skip reserved keywords (e.g., `if`, `for`, `while` inside method bodies)
            if method_name in self.JAVA_RESERVED_KEYWORDS:
                continue

            # Skip if this looks like a constructor
            if method_name == class_name:
                continue

            # Find method body
            body_start = class_body.find("{", match.end() - 1)
            body_end = self._find_matching_brace(class_body, body_start)
            if body_end is None:
                body_end = body_start

            # Skip if this match is inside an already-parsed method body
            if _is_inside_consumed(match.start()):
                continue

            # Record this method's body range
            consumed_ranges.append((body_start, body_end))

            body = class_body[body_start:body_end + 1]
            complexity = calculate_complexity_regex(body, self.language)

            # Extract throws
            raises = [t.strip() for t in throws_str.split(",") if t.strip()]
            # Also extract throw statements
            raises.extend(re.findall(r'throw\s+new\s+([\w.]+)', body))
            raises = list(dict.fromkeys(raises))  # deduplicate

            annotations = re.findall(r'@([\w.]+)', annotations_str)

            method_line_start = class_line_offset + class_body[:match.start()].count("\n")
            method_line_end = class_line_offset + class_body[:body_end + 1].count("\n")

            methods.append(
                ParsedFunction(
                    name=method_name,
                    qualified_name=f"{package}.{class_name}.{method_name}" if package else f"{class_name}.{method_name}",
                    file_path=file_path,
                    line_start=method_line_start,
                    line_end=method_line_end,
                    args=self._parse_java_args(args_str),
                    return_type=return_type,
                    decorators=annotations,
                    is_method=True,
                    is_staticmethod=is_static,
                    is_private=visibility == "private",
                    raises=raises,
                    complexity=complexity,
                )
            )

        # Constructors
        constructor_pattern = re.compile(
            r'(public|private|protected)?\s*' + re.escape(class_name) + r'\s*\(([^)]*)\)\s*(?:throws\s+([\w.\s,]+))?\s*\{',
            re.MULTILINE,
        )
        for match in constructor_pattern.finditer(class_body):
            visibility = match.group(1) or ""
            args_str = match.group(2) or ""
            throws_str = match.group(3) or ""

            body_start = class_body.find("{", match.end() - 1)
            body_end = self._find_matching_brace(class_body, body_start)
            if body_end is None:
                body_end = body_start

            # Skip if this constructor is inside an already-parsed method body
            if _is_inside_consumed(match.start()):
                continue
            consumed_ranges.append((body_start, body_end))

            body = class_body[body_start:body_end + 1]
            complexity = calculate_complexity_regex(body, self.language)
            raises = [t.strip() for t in throws_str.split(",") if t.strip()]

            method_line_start = class_line_offset + class_body[:match.start()].count("\n")
            method_line_end = class_line_offset + class_body[:body_end + 1].count("\n")

            methods.append(
                ParsedFunction(
                    name=class_name,
                    qualified_name=f"{package}.{class_name}.{class_name}" if package else f"{class_name}.{class_name}",
                    file_path=file_path,
                    line_start=method_line_start,
                    line_end=method_line_end,
                    args=self._parse_java_args(args_str),
                    is_method=True,
                    is_constructor=True,
                    is_private=visibility == "private",
                    raises=raises,
                    complexity=complexity,
                )
            )

        return methods

    def _parse_java_args(self, args_str: str) -> List[ParsedArg]:
        """Parse Java argument string into ParsedArg list."""
        args = []
        if not args_str.strip():
            return args

        # Handle generics by tracking angle bracket depth
        parts = self._split_java_args(args_str)
        for part in parts:
            part = part.strip()
            if not part:
                continue

            # Parse: annotations? modifiers? Type name [= default]
            # e.g., @NotNull final String name = "default"

            # Remove annotations
            part = re.sub(r'@[\w.]+(?:\([^)]*\))?\s*', '', part).strip()
            # Remove final modifier
            part = re.sub(r'^final\s+', '', part).strip()

            # Split on last space (type vs name)
            # Handle array notation []
            words = part.split()
            if len(words) >= 2:
                # Find varargs
                is_vararg = False
                type_annotation = " ".join(words[:-1])
                name = words[-1]
                if type_annotation.endswith("..."):
                    is_vararg = True
                    type_annotation = type_annotation[:-3].strip()
                args.append(
                    ParsedArg(
                        name=name,
                        type_annotation=type_annotation or None,
                        is_vararg=is_vararg,
                    )
                )
            elif len(words) == 1:
                args.append(ParsedArg(name=words[0]))

        return args

    def _split_java_args(self, args_str: str) -> List[str]:
        """Split Java argument string respecting generics."""
        parts = []
        current = ""
        depth = 0  # for < >
        paren_depth = 0  # for ( )
        for char in args_str:
            if char == "<":
                depth += 1
                current += char
            elif char == ">":
                depth -= 1
                current += char
            elif char == "(":
                paren_depth += 1
                current += char
            elif char == ")":
                paren_depth -= 1
                current += char
            elif char == "," and depth == 0 and paren_depth == 0:
                parts.append(current)
                current = ""
            else:
                current += char
        if current.strip():
            parts.append(current)
        return parts

    def _find_matching_brace(self, code: str, open_pos: int) -> Optional[int]:
        """Find matching closing brace."""
        if open_pos >= len(code) or code[open_pos] != "{":
            return None
        depth = 1
        in_string = False
        string_char = None
        i = open_pos + 1
        while i < len(code) and depth > 0:
            char = code[i]
            if not in_string:
                if char in ('"', "'"):
                    in_string = True
                    string_char = char
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
            else:
                if char == string_char and code[i - 1] != "\\":
                    in_string = False
                    string_char = None
            i += 1
        return i - 1 if depth == 0 else None


# ---------------------------------------------------------------------------
# Go Parser (regex-based)
# ---------------------------------------------------------------------------

class GoCodeParser(BaseCodeParser):
    """
    Parser for Go source code using regex-based extraction.

    Extracts functions, methods, structs, and imports.
    """

    language = "go"
    extensions = [".go"]

    # Function pattern: func Name(args) [ReturnType] {
    FUNCTION_PATTERN = re.compile(
        r'func\s+(\w+)\s*\(([^)]*)\)\s*([\w.\[\]<>\s,*]*)\s*\{',
        re.MULTILINE,
    )

    # Method pattern: func (r *Receiver) Name(args) [ReturnType] {
    # Return type may be parenthesized for multiple returns: (float64, error)
    METHOD_PATTERN = re.compile(
        r'func\s*\(([^)]*)\)\s+(\w+)\s*\(([^)]*)\)\s*([\w.\[\]<>\s,()*]*)\s*\{',
        re.MULTILINE,
    )

    # Struct pattern
    STRUCT_PATTERN = re.compile(
        r'type\s+(\w+)\s+struct\s*\{',
        re.MULTILINE,
    )

    # Import pattern
    IMPORT_PATTERN = re.compile(
        r'import\s+\(\s*([^)]+)\)|import\s+["\']([^"\']+)["\']',
        re.MULTILINE,
    )

    def parse_file(self, file_path: str) -> ParsedModule:
        """Parse a Go source file."""
        code = self._read_file(file_path)
        return self.parse_string(code, file_path)

    def parse_string(self, code: str, file_path: str = "") -> ParsedModule:
        """Parse Go code from a string."""
        total_lines = code.count("\n") + 1
        module = ParsedModule(
            file_path=file_path,
            language=self.language,
            total_lines=total_lines,
        )

        # Extract imports
        module.imports = self._extract_imports(code)

        # Parse structs and their methods
        module.classes = self._parse_structs(code, file_path)

        # Parse package-level functions
        module.functions = self._parse_functions(code, file_path)

        return module

    def _extract_imports(self, code: str) -> List[str]:
        """Extract import statements."""
        imports = []
        for match in self.IMPORT_PATTERN.finditer(code):
            if match.group(1):
                # Multi-line import block
                for line in match.group(1).split("\n"):
                    line = line.strip().strip('"')
                    if line:
                        imports.append(line)
            elif match.group(2):
                imports.append(match.group(2))
        return imports

    def _parse_functions(self, code: str, file_path: str) -> List[ParsedFunction]:
        """Parse package-level functions."""
        functions = []

        for match in self.FUNCTION_PATTERN.finditer(code):
            name = match.group(1)
            args_str = match.group(2) or ""
            return_type = (match.group(3) or "").strip() or None

            line_start = code[:match.start()].count("\n") + 1

            # Find body
            body_start = code.find("{", match.end() - 1)
            body_end = self._find_matching_brace(code, body_start)
            if body_end is None:
                body_end = body_start

            body = code[body_start:body_end + 1]
            complexity = calculate_complexity_regex(body, self.language)

            line_end = code[:body_end + 1].count("\n") + 1

            functions.append(
                ParsedFunction(
                    name=name,
                    qualified_name=name,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    args=self._parse_go_args(args_str),
                    return_type=return_type,
                    is_private=name[0].islower(),
                    complexity=complexity,
                )
            )

        return functions

    def _parse_structs(self, code: str, file_path: str) -> List[ParsedClass]:
        """Parse struct definitions and collect their methods."""
        structs = []
        struct_names = set()

        # Find all struct definitions
        for match in self.STRUCT_PATTERN.finditer(code):
            name = match.group(1)
            struct_names.add(name)

            line_start = code[:match.start()].count("\n") + 1

            # Find struct body
            body_start = code.find("{", match.end() - 1)
            body_end = self._find_matching_brace(code, body_start)
            if body_end is None:
                body_end = body_start

            line_end = code[:body_end + 1].count("\n") + 1

            structs.append(
                ParsedClass(
                    name=name,
                    qualified_name=name,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    methods=[],  # Will be populated below
                    bases=[],
                )
            )

        # Parse methods and associate with structs
        for match in self.METHOD_PATTERN.finditer(code):
            receiver = match.group(1)
            method_name = match.group(2)
            args_str = match.group(3) or ""
            return_type = (match.group(4) or "").strip() or None

            line_start = code[:match.start()].count("\n") + 1

            # Extract receiver type
            receiver_type = self._extract_receiver_type(receiver)

            # Find body
            body_start = code.find("{", match.end() - 1)
            body_end = self._find_matching_brace(code, body_start)
            if body_end is None:
                body_end = body_start

            body = code[body_start:body_end + 1]
            complexity = calculate_complexity_regex(body, self.language)

            line_end = code[:body_end + 1].count("\n") + 1

            # Find which struct this method belongs to
            for struct in structs:
                if struct.name == receiver_type:
                    struct.methods.append(
                        ParsedFunction(
                            name=method_name,
                            qualified_name=f"{receiver_type}.{method_name}",
                            file_path=file_path,
                            line_start=line_start,
                            line_end=line_end,
                            args=self._parse_go_args(args_str),
                            return_type=return_type,
                            is_method=True,
                            is_private=method_name[0].islower(),
                            complexity=complexity,
                        )
                    )
                    break

        return structs

    def _extract_receiver_type(self, receiver: str) -> str:
        """Extract the type name from a receiver declaration."""
        # e.g., "r *Receiver" or "r Receiver" -> "Receiver"
        receiver = receiver.strip()
        parts = receiver.split()
        if len(parts) >= 2:
            return parts[-1].lstrip("*")
        return receiver

    def _parse_go_args(self, args_str: str) -> List[ParsedArg]:
        """Parse Go argument string into ParsedArg list."""
        args = []
        if not args_str.strip():
            return args

        # Go supports: func(a, b int, c string) - grouped types
        parts = self._split_go_args(args_str)
        pending_names = []

        for part in parts:
            part = part.strip()
            if not part:
                continue

            # Check if this part contains both name and type
            if " " in part:
                words = part.rsplit(" ", 1)
                names = words[0].split(",")
                type_annotation = words[1].strip()
                # First resolve any pending names with this type
                if pending_names:
                    for n in pending_names + names:
                        n = n.strip()
                        if n:
                            args.append(
                                ParsedArg(
                                    name=n,
                                    type_annotation=type_annotation,
                                )
                            )
                    pending_names = []
                else:
                    for n in names:
                        n = n.strip()
                        if n:
                            args.append(
                                ParsedArg(
                                    name=n,
                                    type_annotation=type_annotation,
                                )
                            )
            else:
                # This might be a type for previous names
                if pending_names:
                    for n in pending_names:
                        args.append(
                            ParsedArg(
                                name=n.strip(),
                                type_annotation=part,
                            )
                        )
                    pending_names = []
                else:
                    pending_names.append(part)

        # Handle any remaining pending names (add without type)
        for n in pending_names:
            n = n.strip()
            if n:
                args.append(ParsedArg(name=n))

        return args

    def _split_go_args(self, args_str: str) -> List[str]:
        """Split Go argument string by commas, respecting function types."""
        parts = []
        current = ""
        depth = 0
        for char in args_str:
            if char == "(":
                depth += 1
                current += char
            elif char == ")":
                depth -= 1
                current += char
            elif char == "," and depth == 0:
                parts.append(current)
                current = ""
            else:
                current += char
        if current.strip():
            parts.append(current)
        return parts

    def _find_matching_brace(self, code: str, open_pos: int) -> Optional[int]:
        """Find matching closing brace."""
        if open_pos >= len(code) or code[open_pos] != "{":
            return None
        depth = 1
        in_string = False
        string_char = None
        i = open_pos + 1
        while i < len(code) and depth > 0:
            char = code[i]
            if not in_string:
                if char == '"':
                    in_string = True
                    string_char = char
                elif char == "`":
                    in_string = True
                    string_char = char
                elif char == "{":
                    depth += 1
                elif char == "}":
                    depth -= 1
            else:
                if char == string_char:
                    if string_char == '`':
                        in_string = False
                    elif code[i - 1] != "\\":
                        in_string = False
            i += 1
        return i - 1 if depth == 0 else None


# ---------------------------------------------------------------------------
# Ruby Parser (regex-based)
# ---------------------------------------------------------------------------

class RubyCodeParser(BaseCodeParser):
    """
    Parser for Ruby source code using regex-based extraction.

    Extracts classes, modules, methods, and attr declarations.
    """

    language = "ruby"
    extensions = [".rb"]

    # Method pattern: def name(args)
    METHOD_PATTERN = re.compile(
        r'def\s+(self\.)?(\w+[?!]?)\s*(?:\(([^)]*)\))?',
        re.MULTILINE,
    )

    # Class pattern: class Name < Parent
    CLASS_PATTERN = re.compile(
        r'class\s+(\w+)(?:\s*<\s*(\w+))?',
        re.MULTILINE,
    )

    # Module pattern: module Name
    MODULE_PATTERN = re.compile(
        r'module\s+(\w+)',
        re.MULTILINE,
    )

    # Require pattern
    REQUIRE_PATTERN = re.compile(
        r'require\s+["\']([^"\']+)["\']'
    )

    # Include/extend pattern
    MIXIN_PATTERN = re.compile(
        r'(include|extend|prepend)\s+([\w:]+)'
    )

    # Attr patterns — strictly single-line
    ATTR_PATTERN = re.compile(
        r'attr_(accessor|reader|writer)(?:\s+|:)(.+?)$',
        re.MULTILINE,
    )

    def parse_file(self, file_path: str) -> ParsedModule:
        """Parse a Ruby source file."""
        code = self._read_file(file_path)
        return self.parse_string(code, file_path)

    def parse_string(self, code: str, file_path: str = "") -> ParsedModule:
        """Parse Ruby code from a string."""
        total_lines = code.count("\n") + 1
        module = ParsedModule(
            file_path=file_path,
            language=self.language,
            total_lines=total_lines,
        )

        # Extract imports (require statements)
        module.imports = self._extract_imports(code)

        # Parse classes
        module.classes = self._parse_classes(code, file_path)

        # Parse module-level methods (outside classes)
        module.functions = self._parse_module_functions(code, file_path)

        return module

    def _extract_imports(self, code: str) -> List[str]:
        """Extract require and mixin statements."""
        imports = []
        for match in self.REQUIRE_PATTERN.finditer(code):
            imports.append(match.group(1))
        for match in self.MIXIN_PATTERN.finditer(code):
            imports.append(f"{match.group(1)} {match.group(2)}")
        return imports

    def _parse_classes(self, code: str, file_path: str) -> List[ParsedClass]:
        """Parse class definitions."""
        classes = []

        for match in self.CLASS_PATTERN.finditer(code):
            name = match.group(1)
            parent = match.group(2)
            line_start = code[:match.start()].count("\n") + 1

            # Find class body - use indentation-based extraction
            class_start_line = code[:match.end()].count("\n") + 1
            class_body, body_end_pos = self._extract_ruby_block(
                code, match.end(), class_start_line
            )
            line_end = code[:body_end_pos].count("\n") + 1

            # Parse methods within class
            methods = self._parse_ruby_methods(
                class_body, name, file_path, line_start
            )

            # Extract attr_accessors as pseudo-methods
            for attr_match in self.ATTR_PATTERN.finditer(class_body):
                attr_type = attr_match.group(1)
                attr_names = attr_match.group(2).split(",")
                for attr_name in attr_names:
                    attr_name = attr_name.strip().lstrip(":")
                    if attr_name:
                        is_getter = attr_type in ("accessor", "reader")
                        is_setter = attr_type in ("accessor", "writer")
                        if is_getter:
                            methods.append(
                                ParsedFunction(
                                    name=attr_name,
                                    qualified_name=f"{name}##{attr_name}",
                                    file_path=file_path,
                                    line_start=line_start,
                                    line_end=line_start,
                                    args=[],
                                    is_method=True,
                                    is_property_getter=True,
                                    return_type=None,
                                    complexity=1,
                                )
                            )
                        if is_setter:
                            methods.append(
                                ParsedFunction(
                                    name=f"{attr_name}=",
                                    qualified_name=f"{name}##{attr_name}=",
                                    file_path=file_path,
                                    line_start=line_start,
                                    line_end=line_start,
                                    args=[ParsedArg(name="value")],
                                    is_method=True,
                                    is_property_setter=True,
                                    return_type=None,
                                    complexity=1,
                                )
                            )

            classes.append(
                ParsedClass(
                    name=name,
                    qualified_name=name,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    methods=methods,
                    bases=[parent] if parent else [],
                )
            )

        return classes

    def _parse_module_functions(self, code: str, file_path: str) -> List[ParsedFunction]:
        """Parse top-level/module-level functions."""
        functions = []

        # Find def statements that are not inside a class/module block
        for match in self.METHOD_PATTERN.finditer(code):
            # Check if this def is inside a class
            if self._is_inside_class_or_module(code, match.start()):
                continue

            is_self_method = bool(match.group(1))
            name = match.group(2)
            args_str = match.group(3) or ""
            line_start = code[:match.start()].count("\n") + 1

            # Find method body
            body_start = match.end()
            body, body_end_pos = self._extract_ruby_block(code, body_start, line_start)
            line_end = code[:body_end_pos].count("\n") + 1

            complexity = calculate_complexity_regex(body, self.language)

            functions.append(
                ParsedFunction(
                    name=name,
                    qualified_name=name,
                    file_path=file_path,
                    line_start=line_start,
                    line_end=line_end,
                    args=self._parse_ruby_args(args_str),
                    is_private=name.startswith("_"),
                    complexity=complexity,
                )
            )

        return functions

    def _parse_ruby_methods(
        self, class_body: str, class_name: str, file_path: str, class_line_offset: int
    ) -> List[ParsedFunction]:
        """Parse methods within a class body."""
        methods = []

        for match in self.METHOD_PATTERN.finditer(class_body):
            is_self_method = bool(match.group(1))
            name = match.group(2)
            args_str = match.group(3) or ""

            method_line_start = class_line_offset + class_body[:match.start()].count("\n")

            # Find method body
            body_start = match.end()
            body, body_end_pos = self._extract_ruby_block(
                class_body, body_start, method_line_start
            )
            method_line_end = class_line_offset + class_body[:body_end_pos].count("\n")

            complexity = calculate_complexity_regex(body, self.language)

            # Check for initialize (constructor)
            is_constructor = name == "initialize"

            methods.append(
                ParsedFunction(
                    name=name,
                    qualified_name=f"{class_name}#{name}",
                    file_path=file_path,
                    line_start=method_line_start,
                    line_end=method_line_end,
                    args=self._parse_ruby_args(args_str),
                    is_method=True,
                    is_staticmethod=is_self_method,
                    is_private=name.startswith("_"),
                    is_constructor=is_constructor,
                    complexity=complexity,
                )
            )

        return methods

    def _parse_ruby_args(self, args_str: str) -> List[ParsedArg]:
        """Parse Ruby argument string into ParsedArg list."""
        args = []
        if not args_str.strip():
            return args

        parts = [p.strip() for p in args_str.split(",")]
        for part in parts:
            if not part:
                continue

            # Check for default value
            default = None
            if "=" in part:
                idx = part.index("=")
                default = part[idx + 1:].strip()
                part = part[:idx].strip()

            # Check for keyword arg (:name)
            is_kwarg = False
            if part.startswith(":"):
                is_kwarg = True
                part = part[1:]

            # Check for splat (*args, **kwargs, &block)
            is_vararg = False
            if part.startswith("*") or part.startswith("**") or part.startswith("&"):
                is_vararg = True

            # Remove leading symbols
            name = part.lstrip("*&: ").strip()

            args.append(
                ParsedArg(
                    name=name,
                    default_value=default,
                    is_vararg=is_vararg,
                    is_kwarg=is_kwarg,
                )
            )

        return args

    # Ruby block-opening keywords (each requires a matching `end`)
    RUBY_BLOCK_OPENERS = {
        'class', 'module', 'def', 'if', 'unless', 'while', 'until',
        'for', 'begin', 'case', 'do',
    }

    def _extract_ruby_block(
        self, code: str, start_pos: int, start_line: int
    ) -> Tuple[str, int]:
        """
        Extract a Ruby block using `end` keyword counting.

        Ruby blocks start after a keyword (def, class, etc.) and end
        at the matching `end` keyword. We count nested block openers
        to find the correct closing `end`.
        """
        remaining = code[start_pos:]
        lines = remaining.split("\n")
        if not lines:
            return "", start_pos

        block_lines = []
        depth = 1  # We've already seen the opening line (def/class/etc.)
        end_pos = start_pos

        for i, line in enumerate(lines[1:], 1):  # Skip opening line
            stripped = line.strip()
            if not stripped or stripped.startswith('#'):
                block_lines.append(line)
                end_pos = start_pos + len("\n".join(lines[:i + 1]))
                continue

            # Check for keywords at start of line (not inside strings)
            # Simple heuristic: check first word
            first_word = stripped.split(None, 1)[0] if stripped else ""

            # Count block openers (but not `elsif` or `else` - they're part of if)
            if first_word in self.RUBY_BLOCK_OPENERS and not stripped.startswith('end'):
                # Don't count `do` when used as a method (e.g., `values.do`)
                if first_word == 'do' and len(stripped) > 2 and not stripped[2].isspace():
                    pass  # Method call, not block opener
                else:
                    depth += 1

            # Check for closing `end`
            if first_word == 'end' and depth > 0:
                depth -= 1
                if depth == 0:
                    # Block ends here — don't include this line
                    end_pos = start_pos + len("\n".join(lines[:i + 1]))
                    break

            block_lines.append(line)
            end_pos = start_pos + len("\n".join(lines[:i + 1]))

        return "\n".join(block_lines), end_pos

    def _is_inside_class_or_module(self, code: str, pos: int) -> bool:
        """
        Check if a position is inside a class or module block.

        Uses full Ruby block counting (class, module, def, if, etc.)
        to accurately determine nesting.
        """
        before = code[:pos]
        depth = 0  # Overall block depth
        class_depth = 0  # Depth of class/module nesting
        for match in re.finditer(r'^(\s*)(\w+)', before, re.MULTILINE):
            word = match.group(2)
            if word in self.RUBY_BLOCK_OPENERS:
                depth += 1
            elif word == 'end':
                depth = max(0, depth - 1)
            # Track class/module specifically
            if word == 'class' or word == 'module':
                class_depth = depth
        # We're inside a class/module if class_depth > 0 and the overall
        # block depth is at least class_depth
        return class_depth > 0 and depth >= class_depth


# ---------------------------------------------------------------------------
# Parser Registry
# ---------------------------------------------------------------------------

# Registry of all available parsers
_PARSER_REGISTRY: Dict[str, BaseCodeParser] = {}


def _register_parsers() -> None:
    """Register all built-in parsers."""
    parsers = [
        PythonCodeParser(),
        JavaScriptCodeParser(),
        JavaCodeParser(),
        GoCodeParser(),
        RubyCodeParser(),
    ]
    for parser in parsers:
        _PARSER_REGISTRY[parser.language] = parser


# Initialize registry
_register_parsers()


def get_parser_for_language(language: str) -> Optional[BaseCodeParser]:
    """
    Get the appropriate parser for a language.

    Args:
        language: Language name (e.g., 'python', 'javascript', 'java', 'go', 'ruby')

    Returns:
        A BaseCodeParser subclass instance, or None if not supported.
    """
    lang_lower = language.lower()

    # Direct match
    if lang_lower in _PARSER_REGISTRY:
        return _PARSER_REGISTRY[lang_lower]

    # Aliases
    aliases = {
        "py": "python",
        "js": "javascript",
        "jsx": "javascript",
        "ts": "javascript",
        "tsx": "javascript",
        "golang": "go",
        "rb": "ruby",
    }
    if lang_lower in aliases:
        return _PARSER_REGISTRY.get(aliases[lang_lower])

    return None


def get_parser_for_file(file_path: str) -> Optional[BaseCodeParser]:
    """
    Get the appropriate parser for a file based on its extension.

    Args:
        file_path: Path to the source file

    Returns:
        A BaseCodeParser subclass instance, or None if not supported.
    """
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

    lang = ext_to_lang.get(ext)
    if lang:
        return get_parser_for_language(lang)
    return None


def list_supported_languages() -> List[str]:
    """Return list of all supported language names."""
    return sorted(_PARSER_REGISTRY.keys())



