"""
TestGeneratorAgent - Intelligent Test Case Generator for CodeShield AI.

Generates comprehensive test cases for parsed functions and classes across
Python, JavaScript, Java, Go, and Ruby using AST-based code analysis.
"""

import ast
import os
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from utils.logger import get_logger
from agents.base import BaseSecurityAgent
from agents.results import AgentResult, ScanContext

logger = get_logger(__name__)


class TestFramework(str, Enum):
    PYTEST = "pytest"
    JEST = "jest"
    JUNIT5 = "junit5"
    GO_TEST = "go_test"


@dataclass
class FunctionParam:
    name: str
    type_hint: Optional[str] = None
    has_default: bool = False
    default_value: Optional[str] = None
    is_optional: bool = False


@dataclass
class ParsedFunction:
    name: str
    params: List[FunctionParam] = field(default_factory=list)
    return_type: Optional[str] = None
    is_async: bool = False
    is_method: bool = False
    is_static: bool = False
    is_classmethod: bool = False
    is_property: bool = False
    is_generator: bool = False
    raises_exceptions: List[str] = field(default_factory=list)
    calls_external: bool = False
    complexity_score: int = 0
    docstring: Optional[str] = None
    source_file: Optional[str] = None
    language: str = "python"


@dataclass
class ParsedClass:
    name: str
    methods: List[ParsedFunction] = field(default_factory=list)
    init_params: List[FunctionParam] = field(default_factory=list)
    base_classes: List[str] = field(default_factory=list)
    is_dataclass: bool = False
    docstring: Optional[str] = None
    source_file: Optional[str] = None
    language: str = "python"


@dataclass
class GeneratedTest:
    name: str
    description: str
    test_code: str
    test_type: str
    language: str
    framework: str
    fixtures_needed: List[str] = field(default_factory=list)
    imports_needed: List[str] = field(default_factory=list)


@dataclass
class TestSuite:
    target_name: str
    language: str
    framework: str
    tests: List[GeneratedTest] = field(default_factory=list)
    fixtures: Dict[str, str] = field(default_factory=dict)
    imports: List[str] = field(default_factory=list)
    setup_code: Optional[str] = None

    def to_full_code(self) -> str:
        lines = []
        for imp in self.imports:
            lines.append(imp)
        lines.append("")
        if self.fixtures:
            for name, code in self.fixtures.items():
                lines.append(code)
                lines.append("")
        if self.setup_code:
            lines.append(self.setup_code)
            lines.append("")
        for test in self.tests:
            lines.append(test.test_code)
            lines.append("")
        return "\n".join(lines)


class TestGeneratorAgent(BaseSecurityAgent):
    name: str = "test_generator"
    role: str = "Intelligent Test Case Generator"
    tools: List[str] = []
    priority: int = 45

    def __init__(self, config=None):
        super().__init__(config)
        self._test_suites: List[TestSuite] = []

    async def scan(self, context):
        start = time.time() * 1000
        languages = context.languages or ["python"]
        all_suites = []
        errors = []
        for language in languages:
            try:
                suites = self._generate_tests_for_language(
                    context.source_path, language, context
                )
                all_suites.extend(suites)
            except Exception as e:
                errors.append(str(e))
                logger.error("Test generation failed for %s: %s", language, e)
        self._test_suites = all_suites
        metadata = self._build_metadata(all_suites)
        elapsed = int((time.time() * 1000) - start)
        status = "success" if not errors else "partial"
        return AgentResult(
            agent_name=self.name,
            agent_role=self.role,
            scan_id=context.scan_id,
            findings=[],
            summary=None,
            execution_time_ms=elapsed,
            status=status,
            errors=errors,
            metadata=metadata,
        )

    # ------------------------------------------------------------------
    # Language dispatch
    # ------------------------------------------------------------------

    def _generate_tests_for_language(self, source_path, language, context):
        generators = {
            "python": self._parse_and_generate_python,
            "javascript": self._parse_and_generate_js,
            "typescript": self._parse_and_generate_js,
            "java": self._parse_and_generate_java,
            "go": self._parse_and_generate_go,
            "ruby": self._parse_and_generate_ruby,
        }
        gen = generators.get(language)
        if gen:
            return gen(source_path, context, language)
        logger.warning("No test generator for language: %s", language)
        return []

    def _build_metadata(self, suites):
        meta = {
            "total_suites": len(suites),
            "total_tests": sum(len(s.tests) for s in suites),
            "by_language": {},
            "suites": [],
        }
        for suite in suites:
            lang = suite.language
            if lang not in meta["by_language"]:
                meta["by_language"][lang] = {"suites": 0, "tests": 0}
            meta["by_language"][lang]["suites"] += 1
            meta["by_language"][lang]["tests"] += len(suite.tests)
            meta["suites"].append({
                "target": suite.target_name,
                "language": suite.language,
                "framework": suite.framework,
                "test_count": len(suite.tests),
            })
        return meta

    # ==================================================================
    # PYTHON PARSING & GENERATION
    # ==================================================================

    def _parse_and_generate_python(self, source_path, context, _lang):
        suites = []
        skip_patterns = {"test_", "_test", "__init__", "conftest", "setup", "migrations"}
        for root, _, files in os.walk(source_path):
            for filename in files:
                if not filename.endswith(".py"):
                    continue
                if any(filename.startswith(p) or filename.endswith(p) for p in skip_patterns):
                    continue
                fp = os.path.join(root, filename)
                try:
                    suites.extend(self._parse_python_file(fp, filename))
                except Exception as e:
                    logger.debug("Skip %s: %s", fp, e)
        return suites

    def _parse_python_file(self, fp, filename):
        with open(fp, "r", encoding="utf-8") as f:
            source = f.read()
        tree = ast.parse(source)
        module_name = filename[:-3]
        suites = []
        for node in ast.iter_child_nodes(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                if not node.name.startswith("_"):
                    func = self._parse_py_func(node, module_name)
                    suite = self._gen_py_func_tests(func, module_name)
                    if suite.tests:
                        suites.append(suite)
            elif isinstance(node, ast.ClassDef):
                cls = self._parse_py_class(node, module_name)
                if cls.methods or cls.init_params:
                    suite = self._gen_py_class_tests(cls, module_name)
                    if suite.tests:
                        suites.append(suite)
        return suites

    def _parse_py_func(self, node, module_name):
        is_async = isinstance(node, ast.AsyncFunctionDef)
        params = self._extract_py_args(node.args)
        return_type = None
        if node.returns:
            try:
                return_type = ast.unparse(node.returns)
            except Exception:
                pass
        raises = []
        for child in ast.walk(node):
            if isinstance(child, ast.Raise):
                exc_name = "Exception"
                if child.exc and isinstance(child.exc, ast.Call):
                    fn = child.exc.func
                    if isinstance(fn, ast.Name):
                        exc_name = fn.id
                    elif isinstance(fn, ast.Attribute):
                        exc_name = fn.attr
                raises.append(exc_name)
        calls_external = False
        for child in ast.walk(node):
            if isinstance(child, ast.Call) and isinstance(child.func, ast.Attribute):
                if child.func.attr in ("get", "post", "put", "delete", "patch",
                                        "request", "query", "execute",
                                        "fetchone", "fetchall", "commit"):
                    calls_external = True
        docstring = ast.get_docstring(node)
        return ParsedFunction(
            name=node.name, params=params, return_type=return_type,
            is_async=is_async, raises_exceptions=list(set(raises)),
            calls_external=calls_external, docstring=docstring,
            source_file=module_name, language="python",
        )

    def _extract_py_args(self, args_node):
        params = []
        arg_names = [a.arg for a in args_node.args]
        kw_names = [a.arg for a in args_node.kwonlyargs]
        pos_defaults_start = len(arg_names) - len(args_node.defaults)
        for i, name in enumerate(arg_names):
            if name in ("self", "cls"):
                continue
            th = None
            if args_node.args[i].annotation:
                try:
                    th = ast.unparse(args_node.args[i].annotation)
                except Exception:
                    pass
            has_def = i >= pos_defaults_start
            def_val = None
            if has_def:
                try:
                    def_val = ast.unparse(args_node.defaults[i - pos_defaults_start])
                except Exception:
                    def_val = "..."
            params.append(FunctionParam(
                name=name, type_hint=th, has_default=has_def,
                default_value=def_val,
                is_optional=has_def or (th and "Optional" in th),
            ))
        for i, kw in enumerate(args_node.kwonlyargs):
            th = None
            if kw.annotation:
                try:
                    th = ast.unparse(kw.annotation)
                except Exception:
                    pass
            has_def = i < len(args_node.kw_defaults) and args_node.kw_defaults[i] is not None
            def_val = None
            if has_def:
                try:
                    def_val = ast.unparse(args_node.kw_defaults[i])
                except Exception:
                    pass
            params.append(FunctionParam(
                name=kw.arg, type_hint=th, has_default=has_def,
                default_value=def_val, is_optional=has_def,
            ))
        return params

    def _parse_py_class(self, node, module_name):
        methods = []
        init_params = []
        is_dataclass = any(
            (isinstance(d, ast.Name) and d.id == "dataclass")
            for d in node.decorator_list
        )
        for child in ast.iter_child_nodes(node):
            if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                func = self._parse_py_func(child, module_name)
                func.is_method = True
                if child.name == "__init__":
                    init_params = [p for p in func.params]
                elif child.name == "__new__":
                    pass
                elif child.name.startswith("_"):
                    pass
                else:
                    for dec in child.decorator_list:
                        dn = dec.id if isinstance(dec, ast.Name) else ""
                        if dn == "staticmethod":
                            func.is_static = True
                        elif dn == "classmethod":
                            func.is_classmethod = True
                        elif dn == "property":
                            func.is_property = True
                    methods.append(func)
        bases = []
        for base in node.bases:
            try:
                bases.append(ast.unparse(base))
            except Exception:
                pass
        docstring = ast.get_docstring(node)
        return ParsedClass(
            name=node.name, methods=methods, init_params=init_params,
            base_classes=bases, is_dataclass=is_dataclass,
            docstring=docstring, source_file=module_name, language="python",
        )

    # ------------------------------------------------------------------
    # Python Test Generation
    # ------------------------------------------------------------------

    def _gen_py_func_tests(self, func, module_name):
        tests = []
        arg_str = self._build_arg_string(func.params)

        # Test 1: Basic functionality
        tests.append(GeneratedTest(
            name=f"test_{func.name}_basic",
            description=f"Test {func.name} with basic valid input",
            test_code=self._py_test_basic(func, arg_str),
            test_type="basic",
            language="python",
            framework="pytest",
        ))

        # Test 2: Edge cases
        tests.append(GeneratedTest(
            name=f"test_{func.name}_edge_cases",
            description=f"Test {func.name} with edge cases (None, empty, zero)",
            test_code=self._py_test_edge(func),
            test_type="edge",
            language="python",
            framework="pytest",
        ))

        # Test 3: Error handling
        if func.raises_exceptions:
            tests.append(GeneratedTest(
                name=f"test_{func.name}_raises_error",
                description=f"Test {func.name} raises appropriate exceptions",
                test_code=self._py_test_error(func),
                test_type="error",
                language="python",
                framework="pytest",
            ))

        # Test 4: Async test
        if func.is_async:
            tests.append(GeneratedTest(
                name=f"test_{func.name}_async",
                description=f"Test async {func.name}",
                test_code=self._py_test_async(func, arg_str),
                test_type="async",
                language="python",
                framework="pytest",
            ))

        imports = ["import pytest", f"from {module_name} import {func.name}"]
        return TestSuite(
            target_name=func.name, language="python",
            framework="pytest", tests=tests, imports=imports,
        )

    def _gen_py_class_tests(self, cls, module_name):
        tests = []
        fixture_name = f"{cls.name.lower()}_fixture"
        init_args = self._build_arg_string(cls.init_params)

        # Fixture code
        fixture_code = "\n".join([
            "@pytest.fixture",
            f"def {fixture_name}():",
            f"    return {cls.name}({init_args})" if init_args else f"    return {cls.name}()",
        ])

        # Test 1: Init
        tests.append(GeneratedTest(
            name=f"test_{cls.name}_init",
            description=f"Test {cls.name} initialization",
            test_code="\n".join([
                f"def test_{cls.name}_init():",
                f"    obj = {cls.name}({init_args})" if init_args else f"    obj = {cls.name}()",
                "    assert obj is not None",
            ]),
            test_type="basic",
            language="python",
            framework="pytest",
        ))

        # Method tests
        for method in cls.methods:
            method_args = self._build_arg_string(method.params)
            if method.is_static:
                call_str = f"{cls.name}.{method.name}({method_args})"
            elif method.is_classmethod:
                call_str = f"{cls.name}.{method.name}({method_args})"
            else:
                call_str = f"{fixture_name}.{method.name}({method_args})"

            test_code = "\n".join([
                f"def test_{cls.name}_{method.name}({fixture_name}):",
                f"    result = {call_str}",
                "    assert result is not None",
            ])
            tests.append(GeneratedTest(
                name=f"test_{cls.name}_{method.name}",
                description=f"Test {cls.name}.{method.name}",
                test_code=test_code,
                test_type="basic",
                language="python",
                framework="pytest",
            ))

        imports = ["import pytest", f"from {module_name} import {cls.name}"]
        return TestSuite(
            target_name=cls.name, language="python",
            framework="pytest", tests=tests, imports=imports,
            fixtures={fixture_name: fixture_code},
        )

    def _build_arg_string(self, params):
        parts = []
        for p in params:
            if p.has_default and p.default_value:
                parts.append(f"{p.name}={p.default_value}")
            elif p.type_hint and "str" in p.type_hint:
                parts.append(f'{p.name}="test_value"')
            elif p.type_hint and "int" in p.type_hint:
                parts.append(f"{p.name}=42")
            elif p.type_hint and "bool" in p.type_hint:
                parts.append(f"{p.name}=True")
            elif p.type_hint and "float" in p.type_hint:
                parts.append(f"{p.name}=3.14")
            elif p.type_hint and "list" in p.type_hint.lower():
                parts.append(f"{p.name}=[]")
            elif p.type_hint and "dict" in p.type_hint.lower():
                parts.append(f"{p.name}={{}}")
            else:
                parts.append(f"{p.name}=None")
        return ", ".join(parts)

    def _py_test_basic(self, func, arg_str):
        lines = [f"def test_{func.name}_basic():"]
        if func.is_async:
            lines.append(f"    result = asyncio.run({func.name}({arg_str}))")
        else:
            lines.append(f"    result = {func.name}({arg_str})")
        lines.append("    assert result is not None")
        if func.return_type and func.return_type != "None":
            lines.append(f"    # assert isinstance(result, {func.return_type})")
        return "\n".join(lines)

    def _py_test_edge(self, func):
        lines = [f"def test_{func.name}_edge_cases():"]
        lines.append("    # Edge case 1: None inputs")
        none_args = ", ".join(f"{p.name}=None" for p in func.params if p.name not in ("self", "cls"))
        if none_args:
            lines.append(f"    # result = {func.name}({none_args})")
        lines.append("    # Edge case 2: Empty inputs")
        lines.append("    # result = {func.name}()")
        lines.append("    # Edge case 3: Boundary values")
        lines.append("    # Test with minimum and maximum expected values")
        return "\n".join(lines)

    def _py_test_error(self, func):
        exc = func.raises_exceptions[0] if func.raises_exceptions else "Exception"
        lines = [f"def test_{func.name}_raises_error():"]
        lines.append(f"    with pytest.raises({exc}):")
        bad_args = ", ".join(f"{p.name}=None" for p in func.params if p.name not in ("self", "cls"))
        if bad_args:
            lines.append(f"        {func.name}({bad_args})")
        else:
            lines.append(f"        {func.name}()")
        return "\n".join(lines)

    def _py_test_async(self, func, arg_str):
        lines = [f"@pytest.mark.asyncio"]
        lines.append(f"async def test_{func.name}_async():")
        lines.append(f"    result = await {func.name}({arg_str})")
        lines.append("    assert result is not None")
        return "\n".join(lines)

    # ==================================================================
    # JAVASCRIPT / TYPESCRIPT
    # ==================================================================

    def _parse_and_generate_js(self, source_path, context, lang):
        suites = []
        for root, _, files in os.walk(source_path):
            for f in files:
                if f.endswith((".js", ".ts", ".jsx", ".tsx")) and not f.endswith((".test.js", ".test.ts")):
                    fp = os.path.join(root, f)
                    try:
                        suites.extend(self._parse_js_file(fp, f, lang))
                    except Exception as e:
                        logger.debug("Skip JS %s: %s", fp, e)
        return suites

    def _parse_js_file(self, fp, filename, lang):
        with open(fp, "r", encoding="utf-8") as f:
            source = f.read()
        suites = []
        # Function declarations
        for match in re.finditer(r"function\s+(\w+)\s*\(([^)]*)\)", source):
            name, args_str = match.groups()
            params = [FunctionParam(name=a.strip()) for a in args_str.split(",") if a.strip()]
            func = ParsedFunction(name=name, params=params, language=lang)
            suite = self._gen_js_tests(func, filename)
            if suite.tests:
                suites.append(suite)
        # Arrow functions: const name = (...) =>
        for match in re.finditer(r"(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>", source):
            name, args_str = match.groups()
            params = [FunctionParam(name=a.strip()) for a in args_str.split(",") if a.strip()]
            func = ParsedFunction(name=name, params=params, language=lang)
            suite = self._gen_js_tests(func, filename)
            if suite.tests:
                suites.append(suite)
        # Classes
        for cmatch in re.finditer(r"class\s+(\w+)(?:\s+extends\s+(\w+))?\s*\{", source):
            cname, base = cmatch.groups()
            cls_start = cmatch.start()
            cls_region = source[cls_start:cls_start + 5000]
            methods = []
            for mmatch in re.finditer(r"(?:async\s+)?(\w+)\s*\(([^)]*)\)\s*\{", cls_region):
                mname, margs = mmatch.groups()
                if mname in ("constructor", "class"):
                    continue
                params = [FunctionParam(name=a.strip()) for a in margs.split(",") if a.strip()]
                methods.append(ParsedFunction(name=mname, params=params, is_method=True, language=lang))
            cls = ParsedClass(name=cname, methods=methods, base_classes=[base] if base else [], language=lang)
            suite = self._gen_js_class_tests(cls, filename)
            if suite.tests:
                suites.append(suite)
        return suites

    def _gen_js_tests(self, func, filename):
        module = filename.rsplit(".", 1)[0]
        tests = []
        arg_str = ", ".join(f'"test_{p.name}"' for p in func.params)
        tests.append(GeneratedTest(
            name=f"test_{func.name}_basic",
            description=f"Basic test for {func.name}",
            test_code="\n".join([
                f"describe('{func.name}', () => {{",
                f"    test('basic functionality', () => {{",
                f"        const result = {func.name}({arg_str});",
                f"        expect(result).toBeDefined();",
                f"    }});",
                f"    test('handles invalid input', () => {{",
                f"        expect(() => {func.name}(null)).toThrow();",
                f"    }});",
                f"}});",
            ]),
            test_type="basic",
            language="javascript",
            framework="jest",
        ))
        imports = [f"const {{ {func.name} }} = require('./{module}');"]
        return TestSuite(target_name=func.name, language="javascript", framework="jest", tests=tests, imports=imports)

    def _gen_js_class_tests(self, cls, filename):
        tests = []
        tests.append(GeneratedTest(
            name=f"test_{cls.name}_init",
            description=f"Test {cls.name} init",
            test_code="\n".join([
                f"describe('{cls.name}', () => {{",
                f"    test('initialization', () => {{",
                f"        const instance = new {cls.name}();",
                f"        expect(instance).toBeDefined();",
                f"    }});",
                f"}});",
            ]),
            test_type="basic",
            language="javascript",
            framework="jest",
        ))
        for m in cls.methods:
            arg_str = ", ".join(f'"test_{p.name}"' for p in m.params)
            tests.append(GeneratedTest(
                name=f"test_{cls.name}_{m.name}",
                description=f"Test {cls.name}.{m.name}",
                test_code="\n".join([
                    f"    test('{m.name} works correctly', () => {{",
                    f"        const instance = new {cls.name}();",
                    f"        const result = instance.{m.name}({arg_str});",
                    f"        expect(result).toBeDefined();",
                    f"    }});",
                ]),
                test_type="basic",
                language="javascript",
                framework="jest",
            ))
        imports = []
        return TestSuite(target_name=cls.name, language="javascript", framework="jest", tests=tests, imports=imports)

    # ==================================================================
    # JAVA
    # ==================================================================

    def _parse_and_generate_java(self, source_path, context, _lang):
        suites = []
        for root, _, files in os.walk(source_path):
            for f in files:
                if f.endswith(".java") and not f.endswith("Test.java"):
                    fp = os.path.join(root, f)
                    try:
                        suites.extend(self._parse_java_file(fp, f))
                    except Exception as e:
                        logger.debug("Skip Java %s: %s", fp, e)
        return suites

    def _parse_java_file(self, fp, filename):
        with open(fp, "r", encoding="utf-8") as f:
            source = f.read()
        suites = []
        pkg_match = re.search(r"package\s+([\w.]+);", source)
        package = pkg_match.group(1) if pkg_match else ""
        for cmatch in re.finditer(r"(public\s+)?class\s+(\w+)", source):
            cname = cmatch.group(2)
            cls_start = cmatch.start()
            cls_region = source[cls_start:cls_start + 8000]
            methods = []
            for mmatch in re.finditer(r"(public|private|protected)?\s*(static\s+)?(\w+(?:<[^>]+>)?)\s+(\w+)\s*\(([^)]*)\)", cls_region):
                vis, is_static, ret_type, mname, margs = mmatch.groups()
                if mname == cname:  # constructor
                    continue
                if ret_type in ("if", "for", "while", "return", "class"):
                    continue
                params = [FunctionParam(name=a.strip().split()[-1]) for a in margs.split(",") if a.strip()]
                is_s = is_static is not None and is_static.strip() != ""
                methods.append(ParsedFunction(name=mname, params=params, return_type=ret_type, is_static=is_s, is_method=True, language="java"))
            cls = ParsedClass(name=cname, methods=methods, language="java")
            suite = self._gen_java_tests(cls, package)
            if suite.tests:
                suites.append(suite)
        return suites

    def _gen_java_tests(self, cls, package):
        tests = []
        tests.append(GeneratedTest(
            name=f"test{cls.name}Init",
            description=f"Test {cls.name} init",
            test_code="\n".join([
                f"@Test",
                f"void test{cls.name}Init() {{",
                f"    {cls.name} instance = new {cls.name}();",
                f"    assertNotNull(instance);",
                f"}}",
            ]),
            test_type="basic",
            language="java",
            framework="junit5",
        ))
        for m in cls.methods:
            tests.append(GeneratedTest(
                name=f"test{cls.name}_{m.name}",
                description=f"Test {cls.name}.{m.name}",
                test_code="\n".join([
                    f"@Test",
                    f"void test{m.name.capitalize()}() {{",
                    f"    {cls.name} instance = new {cls.name}();",
                    f"    var result = instance.{m.name}();",
                    f"    assertNotNull(result);",
                    f"}}",
                ]),
                test_type="basic",
                language="java",
                framework="junit5",
            ))
        imports = [
            f"package {package};",
            "import org.junit.jupiter.api.Test;",
            "import static org.junit.jupiter.api.Assertions.*;",
        ]
        return TestSuite(target_name=cls.name, language="java", framework="junit5", tests=tests, imports=imports)

    # ==================================================================
    # GO
    # ==================================================================

    def _parse_and_generate_go(self, source_path, context, _lang):
        suites = []
        for root, _, files in os.walk(source_path):
            for f in files:
                if f.endswith(".go") and not f.endswith("_test.go"):
                    fp = os.path.join(root, f)
                    try:
                        suites.extend(self._parse_go_file(fp, f))
                    except Exception as e:
                        logger.debug("Skip Go %s: %s", fp, e)
        return suites

    def _parse_go_file(self, fp, filename):
        with open(fp, "r", encoding="utf-8") as f:
            source = f.read()
        suites = []
        pkg_match = re.search(r"package\s+(\w+)", source)
        package = pkg_match.group(1) if pkg_match else "main"
        for match in re.finditer(r"func\s+(?:\(([^)]+)\)\s+)?(\w+)\s*\(([^)]*)\)", source):
            receiver, name, args_str = match.groups()
            params = [FunctionParam(name=a.strip().split()[-1]) if " " in a.strip() else FunctionParam(name=a.strip()) for a in args_str.split(",") if a.strip()]
            func = ParsedFunction(name=name, params=params, language="go")
            suite = self._gen_go_tests(func, package)
            if suite.tests:
                suites.append(suite)
        return suites

    def _gen_go_tests(self, func, package):
        arg_vals = []
        for p in func.params:
            if "string" in p.type_hint.lower():
                arg_vals.append('"test"')
            elif "int" in p.type_hint.lower():
                arg_vals.append("42")
            elif "bool" in p.type_hint.lower():
                arg_vals.append("true")
            else:
                arg_vals.append("nil")
        arg_str = ", ".join(arg_vals) if arg_vals else ""
        tests = []
        tests.append(GeneratedTest(
            name=f"Test{func.name.capitalize()}",
            description=f"Test {func.name}",
            test_code="\n".join([
                f"func Test{func.name.capitalize()}(t *testing.T) {{",
                f"    result, err := {func.name}({arg_str})",
                f"    assert.NoError(t, err)",
                f"    assert.NotNil(t, result)",
                f"}}",
            ]),
            test_type="basic",
            language="go",
            framework="go_test",
        ))
        imports = [
            f"package {package}",
            'import "testing"',
            'import "github.com/stretchr/testify/assert"',
        ]
        return TestSuite(target_name=func.name, language="go", framework="go_test", tests=tests, imports=imports)

    # ==================================================================
    # RUBY
    # ==================================================================

    def _parse_and_generate_ruby(self, source_path, context, _lang):
        suites = []
        for root, _, files in os.walk(source_path):
            for f in files:
                if f.endswith(".rb") and not f.endswith("_spec.rb") and not f.endswith("_test.rb"):
                    fp = os.path.join(root, f)
                    try:
                        suites.extend(self._parse_ruby_file(fp, f))
                    except Exception as e:
                        logger.debug("Skip Ruby %s: %s", fp, e)
        return suites

    def _parse_ruby_file(self, fp, filename):
        with open(fp, "r", encoding="utf-8") as f:
            source = f.read()
        suites = []
        for cmatch in re.finditer(r"class\s+(\w+)", source):
            cname = cmatch.group(1)
            cls_start = cmatch.start()
            cls_region = source[cls_start:cls_start + 5000]
            methods = []
            for mmatch in re.finditer(r"def\s+(\w+)[^\n]*\n", cls_region):
                mname = mmatch.group(1)
                if mname in ("initialize",):
                    continue
                methods.append(ParsedFunction(name=mname, is_method=True, language="ruby"))
            cls = ParsedClass(name=cname, methods=methods, language="ruby")
            suite = self._gen_ruby_tests(cls)
            if suite.tests:
                suites.append(suite)
        return suites

    def _gen_ruby_tests(self, cls):
        tests = []
        tests.append(GeneratedTest(
            name=f"test_{cls.name.downcase}_init",
            description=f"Test {cls.name} init",
            test_code="\n".join([
                f"RSpec.describe {cls.name} do",
                f"  it 'initializes correctly' do",
                f"    instance = {cls.name}.new",
                f"    expect(instance).not_to be_nil",
                f"  end",
            ]),
            test_type="basic",
            language="ruby",
            framework="rspec",
        ))
        for m in cls.methods:
            tests.append(GeneratedTest(
                name=f"test_{cls.name}_{m.name}",
                description=f"Test {cls.name}#{m.name}",
                test_code="\n".join([
                    f"  it 'responds to {m.name}' do",
                    f"    instance = {cls.name}.new",
                    f"    expect(instance).to respond_to(:{m.name})",
                    f"  end",
                ]),
                test_type="basic",
                language="ruby",
                framework="rspec",
            ))
        imports = ["require 'rspec'"]
        return TestSuite(target_name=cls.name, language="ruby", framework="rspec", tests=tests, imports=imports)
