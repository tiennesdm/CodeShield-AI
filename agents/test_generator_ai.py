"""
AI-Enhanced Test Generator for CodeShield AI.

Uses OpenAI API to generate complex test scenarios, realistic test data,
hidden edge cases, integration tests, and property-based tests.

Falls back to local heuristic-based generation when OpenAI is unavailable.
"""

import json
import os
import re
from typing import Any, Dict, List, Optional

from utils.logger import get_logger

from agents.base import BaseSecurityAgent
from agents.results import AgentResult, ScanContext
from agents.test_generator import (
    DEFAULT_VALUES,
    FunctionParam,
    GeneratedTest,
    ParsedFunction,
    TestSuite,
)

logger = get_logger(__name__)


class AIEnhancedTestGenerator:
    """
    AI-enhanced test generation using OpenAI LLM.

    Generates sophisticated test scenarios that go beyond template-based
    generation, including:
    - Realistic business logic test data
    - Hidden edge cases humans often miss
    - Integration test scenarios
    - Property-based test hypotheses (Hypothesis-style)
    - Stateful/test sequence generation
    """

    def __init__(self, openai_api_key: Optional[str] = None) -> None:
        """
        Initialize the AI-enhanced test generator.

        Args:
            openai_api_key: Optional OpenAI API key. Falls back to env var.
        """
        self.openai_api_key = openai_api_key or os.environ.get("OPENAI_API_KEY", "")
        self._openai_client: Optional[Any] = None

        if self.openai_api_key:
            try:
                import openai

                self._openai_client = openai.AsyncOpenAI(api_key=self.openai_api_key)
                logger.info("OpenAI client initialized for AI-enhanced test generation")
            except ImportError:
                logger.warning("openai package not installed, using local heuristics")
            except Exception as e:
                logger.warning("Failed to initialize OpenAI client: %s", e)
        else:
            logger.info("No OpenAI API key configured, using local heuristics only")

    async def generate_ai_tests(
        self,
        func: ParsedFunction,
        module_name: str,
        context: Optional[str] = None,
    ) -> List[GeneratedTest]:
        """
        Generate AI-enhanced tests for a function.

        Args:
            func: Parsed function metadata
            module_name: Name of the containing module
            context: Optional surrounding code context

        Returns:
            List of generated test cases
        """
        if not self._openai_client:
            logger.info("LLM unavailable, falling back to heuristic test generation")
            return self._fallback_heuristic_tests(func, module_name)

        try:
            llm_tests = await self._llm_test_generation(func, module_name, context)
            if llm_tests:
                return llm_tests
        except Exception as e:
            logger.debug("LLM test generation failed, using fallback: %s", e)

        return self._fallback_heuristic_tests(func, module_name)

    async def generate_property_based_tests(
        self,
        func: ParsedFunction,
        module_name: str,
    ) -> List[GeneratedTest]:
        """
        Generate property-based tests (Hypothesis-style) for a function.

        Uses LLM to identify properties that should hold for all inputs,
        then generates Hypothesis strategies.

        Args:
            func: Parsed function metadata
            module_name: Name of the containing module

        Returns:
            List of property-based test cases
        """
        if not self._openai_client:
            return self._fallback_property_tests(func, module_name)

        try:
            prompt = self._build_property_test_prompt(func, module_name)
            response = await self._openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an expert in property-based testing using Python's Hypothesis "
                            "library. Generate property-based tests that define invariants and "
                            "properties that should hold for all valid inputs. "
                            "Respond with ONLY a JSON object containing 'tests' array. "
                            'Each test has: name, description, property_code (Hypothesis @given decorator + test function).'
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=1500,
            )

            content = self._extract_json_content(response.choices[0].message.content)
            if not content:
                return self._fallback_property_tests(func, module_name)

            data = json.loads(content)
            tests: List[GeneratedTest] = []

            for test_data in data.get("tests", []):
                test = GeneratedTest(
                    name=test_data.get("name", "property_test"),
                    description=test_data.get("description", "Property-based test"),
                    test_code=test_data.get("property_code", "# No code generated"),
                    test_type="property_based",
                    language="python",
                    framework="pytest",
                    imports_needed=["hypothesis", "hypothesis.strategies as st"],
                )
                tests.append(test)

            return tests if tests else self._fallback_property_tests(func, module_name)

        except Exception as e:
            logger.debug("Property-based test LLM generation failed: %s", e)
            return self._fallback_property_tests(func, module_name)

    async def generate_integration_tests(
        self,
        func: ParsedFunction,
        module_name: str,
        context: Optional[str] = None,
    ) -> List[GeneratedTest]:
        """
        Generate integration test scenarios for functions with external dependencies.

        Args:
            func: Parsed function metadata
            module_name: Name of the containing module
            context: Optional surrounding code context

        Returns:
            List of integration test cases
        """
        if not func.calls_external:
            return []

        if not self._openai_client:
            return self._fallback_integration_tests(func, module_name)

        try:
            prompt = self._build_integration_test_prompt(func, module_name, context)
            response = await self._openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an expert in integration testing. Generate integration tests "
                            "that verify a function works correctly with its external dependencies "
                            "(databases, APIs, file systems, message queues). "
                            "Use mocks for external dependencies and test the interaction patterns. "
                            "Respond with ONLY a JSON object containing 'tests' array. "
                            'Each test has: name, description, test_code (pytest test function).'
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=2000,
            )

            content = self._extract_json_content(response.choices[0].message.content)
            if not content:
                return self._fallback_integration_tests(func, module_name)

            data = json.loads(content)
            tests: List[GeneratedTest] = []

            for test_data in data.get("tests", []):
                test = GeneratedTest(
                    name=test_data.get("name", "integration_test"),
                    description=test_data.get("description", "Integration test"),
                    test_code=test_data.get("test_code", "# No code generated"),
                    test_type="integration",
                    language="python",
                    framework="pytest",
                    imports_needed=["unittest.mock"],
                )
                tests.append(test)

            return tests if tests else self._fallback_integration_tests(func, module_name)

        except Exception as e:
            logger.debug("Integration test LLM generation failed: %s", e)
            return self._fallback_integration_tests(func, module_name)

    async def _llm_test_generation(
        self,
        func: ParsedFunction,
        module_name: str,
        context: Optional[str] = None,
    ) -> Optional[List[GeneratedTest]]:
        """
        Use OpenAI LLM to generate sophisticated test cases.

        Args:
            func: Parsed function metadata
            module_name: Name of the containing module
            context: Optional surrounding code context

        Returns:
            List of generated tests or None if LLM unavailable
        """
        if not self._openai_client:
            return None

        prompt = self._build_test_generation_prompt(func, module_name, context)

        try:
            response = await self._openai_client.chat.completions.create(
                model="gpt-4",
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are an expert test automation engineer specializing in comprehensive "
                            "test coverage. Generate high-quality test cases that cover: "
                            "1) Basic flow/happy path, 2) Error handling, 3) Edge cases, "
                            "4) Null safety, 5) Type validation. "
                            "Respond with ONLY a JSON object containing 'tests' array. "
                            'Each test has: name, description, test_type (one of: basic, edge_case, '
                            'invalid_input, exception, boundary, async, mock), test_code (pytest function).'
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.2,
                max_tokens=2000,
            )

            content = self._extract_json_content(response.choices[0].message.content)
            if not content:
                return None

            data = json.loads(content)
            tests: List[GeneratedTest] = []

            for test_data in data.get("tests", []):
                test = GeneratedTest(
                    name=test_data.get("name", f"test_{func.name}"),
                    description=test_data.get("description", "AI-generated test"),
                    test_code=test_data.get("test_code", "# No code generated"),
                    test_type=test_data.get("test_type", "basic"),
                    language="python",
                    framework="pytest",
                )
                tests.append(test)

            return tests if tests else None

        except Exception as e:
            logger.debug("LLM test generation call failed: %s", e)
            return None

    def _build_test_generation_prompt(
        self,
        func: ParsedFunction,
        module_name: str,
        context: Optional[str] = None,
    ) -> str:
        """Build the LLM prompt for test generation."""
        params_desc = "\n".join(
            f"  - {p.name}: {p.type_hint or 'unknown'}"
            f"{' (optional, default=' + str(p.default_value) + ')' if p.has_default else ''}"
            f"{' (optional)' if p.is_optional else ''}"
            for p in func.params
        )

        doc = func.docstring or "No docstring available"

        code_ctx = ""
        if context:
            code_ctx = f"\n**Code Context**:\n```python\n{context[:2000]}\n```\n"

        return f"""Generate 5 comprehensive test cases for this function:

**Function**: `{func.name}`
**Module**: `{module_name}`
**Return Type**: {func.return_type or "unknown"}
**Async**: {func.is_async}
**Raises**: {func.raises_exceptions or "None detected"}
**Calls External**: {func.calls_external}

**Parameters**:
{params_desc}

**Docstring**:
{doc}{code_ctx}

Generate tests covering:
1. **Basic flow**: Valid input produces expected output
2. **Error handling**: Invalid inputs raise appropriate exceptions
3. **Edge cases**: Empty inputs, boundary values, extreme values
4. **Null safety**: None/null inputs handled gracefully
5. **Type validation**: Wrong types rejected appropriately

For async functions, use `@pytest.mark.asyncio` and `await`.
Use `pytest.raises` for exception testing.
Import the function: `from {module_name} import {func.name}`.

Respond with ONLY JSON:
{{"tests": [{{"name": "...", "description": "...", "test_type": "...", "test_code": "..."}}]}}"""

    def _build_property_test_prompt(
        self,
        func: ParsedFunction,
        module_name: str,
    ) -> str:
        """Build the LLM prompt for property-based test generation."""
        params_desc = "\n".join(
            f"  - {p.name}: {p.type_hint or 'unknown'}"
            for p in func.params
        )

        return f"""Generate property-based tests (Hypothesis-style) for this function:

**Function**: `{func.name}`
**Module**: `{module_name}`
**Return Type**: {func.return_type or "unknown"}

**Parameters**:
{params_desc}

**Docstring**:
{func.docstring or "No docstring available"}

Generate Hypothesis `@given` tests that verify:
1. Idempotency: calling twice gives same result
2. Invariants: output constraints that always hold
3. Round-trip properties: encode/decode pairs
4. Monotonicity: increasing input -> increasing output
5. No exceptions on valid inputs

Use `from hypothesis import given, strategies as st, settings`.
Import the function: `from {module_name} import {func.name}`.

Respond with ONLY JSON:
{{"tests": [{{"name": "...", "description": "...", "property_code": "..."}}]}}"""

    def _build_integration_test_prompt(
        self,
        func: ParsedFunction,
        module_name: str,
        context: Optional[str] = None,
    ) -> str:
        """Build the LLM prompt for integration test generation."""
        params_desc = "\n".join(
            f"  - {p.name}: {p.type_hint or 'unknown'}"
            for p in func.params
        )

        code_ctx = ""
        if context:
            code_ctx = f"\n**Code Context**:\n```python\n{context[:2000]}\n```\n"

        return f"""Generate integration tests for this function with external dependencies:

**Function**: `{func.name}`
**Module**: `{module_name}`
**Calls External**: Yes (APIs, databases, file system, etc.)

**Parameters**:
{params_desc}

**Docstring**:
{func.docstring or "No docstring available"}{code_ctx}

Generate integration tests that:
1. Mock external API calls and verify correct request formatting
2. Mock database interactions and verify query patterns
3. Test error handling when external services fail (timeouts, 500s)
4. Test retry logic if present
5. Verify response processing from external calls

Use `from unittest.mock import patch, MagicMock, AsyncMock`.
Use `from {module_name} import {func.name}`.

Respond with ONLY JSON:
{{"tests": [{{"name": "...", "description": "...", "test_code": "..."}}]}}"""

    @staticmethod
    def _extract_json_content(content: Optional[str]) -> Optional[str]:
        """Extract JSON from LLM response, handling markdown code blocks."""
        if not content:
            return None

        content = content.strip()
        if content.startswith("```json"):
            content = content[7:]
        if content.startswith("```"):
            content = content[3:]
        if content.endswith("```"):
            content = content[:-3]
        return content.strip()

    # ------------------------------------------------------------------
    # Fallback heuristic generators (when LLM unavailable)
    # ------------------------------------------------------------------

    def _fallback_heuristic_tests(
        self,
        func: ParsedFunction,
        module_name: str,
    ) -> List[GeneratedTest]:
        """
        Generate heuristic-based tests when LLM is unavailable.

        Identifies hidden edge cases using heuristics and code patterns.
        """
        tests: List[GeneratedTest] = []
        call_prefix = "await " if func.is_async else ""
        await_prefix = "async " if func.is_async else ""

        # Hidden edge case: mutability test
        if func.params and any(
            "list" in (p.type_hint or "").lower()
            or "dict" in (p.type_hint or "").lower()
            for p in func.params
        ):
            code = f"""{await_prefix}def test_{func.name}_mutability_safety():
    \"\"\"Test {func.name} does not mutate input unexpectedly.\"\"\"
    original = [1, 2, 3]  # Adjust to match expected input type
    original_copy = original.copy()
    result = {call_prefix}{func.name}({self._build_valid_args(func.params).replace("[1, 2, 3]", "original")})
    assert original == original_copy, 'Function mutated the input!'"""

            tests.append(
                GeneratedTest(
                    name=f"test_{func.name}_mutability_safety",
                    description=f"Test {func.name} does not mutate input",
                    test_code=code,
                    test_type="edge_case",
                    language="python",
                    framework="pytest",
                )
            )

        # Hidden edge case: idempotency test
        if not func.calls_external and not func.is_async:
            code = f"""def test_{func.name}_idempotency():
    \"\"\"Test {func.name} returns same result on repeated calls with same input.\"\"\"
    args = ({self._build_valid_args(func.params)})
    result1 = {func.name}(*args if isinstance(args, tuple) else (args,))
    result2 = {func.name}(*args if isinstance(args, tuple) else (args,))
    assert result1 == result2, "Function is not idempotent!"""

            tests.append(
                GeneratedTest(
                    name=f"test_{func.name}_idempotency",
                    description=f"Test {func.name} idempotency",
                    test_code=code,
                    test_type="edge_case",
                    language="python",
                    framework="pytest",
                )
            )

        # Hidden edge case: unicode/internationalization
        for param in func.params:
            if "str" in (param.type_hint or "").lower():
                code = f"""{await_prefix}def test_{func.name}_unicode_{param.name}():
    \"\"\"Test {func.name} handles unicode {param.name} correctly.\"\"\"
    result = {call_prefix}{func.name}({self._build_args_with_override(func.params, param.name, '"Hello \\u4e16\\u754c \\U0001f600 \\u00e9\\u00e0\\u00fc"')})
    assert result is not None"""

                tests.append(
                    GeneratedTest(
                        name=f"test_{func.name}_unicode_{param.name}",
                        description=f"Test {func.name} handles unicode {param.name}",
                        test_code=code,
                        test_type="edge_case",
                        language="python",
                        framework="pytest",
                    )
                )
                break  # One unicode test is enough

        # Hidden edge case: very large input
        for param in func.params:
            type_hint = (param.type_hint or "").lower()
            if "str" in type_hint:
                code = f"""{await_prefix}def test_{func.name}_large_{param.name}():
    \"\"\"Test {func.name} handles very large {param.name}.\"\"\"
    large_value = "x" * 100000
    result = {call_prefix}{func.name}({self._build_args_with_override(func.params, param.name, "large_value")})
    assert result is not None"""
                tests.append(
                    GeneratedTest(
                        name=f"test_{func.name}_large_{param.name}",
                        description=f"Test {func.name} handles large {param.name}",
                        test_code=code,
                        test_type="edge_case",
                        language="python",
                        framework="pytest",
                    )
                )
                break

        # Hidden edge case: concurrent execution
        if not func.is_async and not func.calls_external:
            code = f"""def test_{func.name}_thread_safety():
    \"\"\"Test {func.name} thread safety with concurrent calls.\"\"\"
    import concurrent.futures
    import threading

    results = []
    def worker():
        result = {func.name}({self._build_valid_args(func.params)})
        results.append(result)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(worker) for _ in range(100)]
        concurrent.futures.wait(futures)

    assert len(results) == 100
    # All results should be consistent (if function is pure)
    # assert len(set(results)) == 1  # Uncomment for pure functions"""

            tests.append(
                GeneratedTest(
                    name=f"test_{func.name}_thread_safety",
                    description=f"Test {func.name} thread safety",
                    test_code=code,
                    test_type="edge_case",
                    language="python",
                    framework="pytest",
                )
            )

        return tests

    def _fallback_property_tests(
        self,
        func: ParsedFunction,
        module_name: str,
    ) -> List[GeneratedTest]:
        """Generate fallback property-based tests using Hypothesis."""
        tests: List[GeneratedTest] = []

        # Build Hypothesis strategies based on parameter types
        strategies: List[str] = []
        for param in func.params:
            type_hint = (param.type_hint or "").lower()
            if "str" in type_hint:
                strategies.append(f"{param.name}=st.text(min_size=0, max_size=1000)")
            elif "int" in type_hint:
                strategies.append(f"{param.name}=st.integers(min_value=-1000000, max_value=1000000)")
            elif "float" in type_hint:
                strategies.append(f"{param.name}=st.floats(allow_nan=False, allow_infinity=False)")
            elif "bool" in type_hint:
                strategies.append(f"{param.name}=st.booleans()")
            elif "list" in type_hint:
                strategies.append(f"{param.name}=st.lists(st.integers(), max_size=100)")
            else:
                strategies.append(f"{param.name}=st.text()")

        strategies_str = ", ".join(strategies)
        args_str = ", ".join(p.name for p in func.params)
        call_prefix = "await " if func.is_async else ""
        await_prefix = "async " if func.is_async else ""

        # No-exception property
        code = f"""from hypothesis import given, strategies as st, settings, HealthCheck

@given({strategies_str})
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
{await_prefix}def test_{func.name}_no_exception({args_str}):
    \"\"\"Property: {func.name} never raises on valid inputs.\"\"\"
    try:
        result = {call_prefix}{func.name}({args_str})
        # If we get here, no exception was raised (property holds)
    except Exception as e:
        pytest.fail(f"Unexpected exception on valid input: {{e}}")
"""

        tests.append(
            GeneratedTest(
                name=f"test_{func.name}_no_exception",
                description=f"Property: {func.name} never raises on valid inputs",
                test_code=code,
                test_type="property_based",
                language="python",
                framework="pytest",
                imports_needed=["hypothesis", "hypothesis.strategies as st"],
            )
        )

        # Determinism property (for pure functions without external calls)
        if not func.calls_external:
            code = f"""from hypothesis import given, strategies as st, settings

@given({strategies_str})
@settings(max_examples=50)
{await_prefix}def test_{func.name}_deterministic({args_str}):
    \"\"\"Property: {func.name} returns the same result for the same input.\"\"\"
    result1 = {call_prefix}{func.name}({args_str})
    result2 = {call_prefix}{func.name}({args_str})
    assert result1 == result2, "Function is not deterministic!"
"""

            tests.append(
                GeneratedTest(
                    name=f"test_{func.name}_deterministic",
                    description=f"Property: {func.name} is deterministic",
                    test_code=code,
                    test_type="property_based",
                    language="python",
                    framework="pytest",
                    imports_needed=["hypothesis", "hypothesis.strategies as st"],
                )
            )

        return tests

    def _fallback_integration_tests(
        self,
        func: ParsedFunction,
        module_name: str,
    ) -> List[GeneratedTest]:
        """Generate fallback integration tests."""
        tests: List[GeneratedTest] = []
        call_prefix = "await " if func.is_async else ""
        await_prefix = "async " if func.is_async else ""

        # API failure simulation
        code = f"""{await_prefix}def test_{func.name}_api_timeout():
    \"\"\"Test {func.name} handles API timeout gracefully.\"\"\"
    with patch("requests.get") as mock_get:
        from requests.exceptions import Timeout
        mock_get.side_effect = Timeout("Connection timed out")
        with pytest.raises(Timeout):
            {call_prefix}{func.name}({self._build_valid_args(func.params)})
"""

        tests.append(
            GeneratedTest(
                name=f"test_{func.name}_api_timeout",
                description=f"Test {func.name} handles API timeout",
                test_code=code,
                test_type="integration",
                language="python",
                framework="pytest",
            )
        )

        # HTTP error simulation
        code = f"""{await_prefix}def test_{func.name}_http_error_500():
    \"\"\"Test {func.name} handles HTTP 500 error gracefully.\"\"\"
    mock_response = MagicMock()
    mock_response.status_code = 500
    mock_response.raise_for_status.side_effect = Exception("Internal Server Error")

    with patch("requests.get", return_value=mock_response):
        with pytest.raises(Exception):
            {call_prefix}{func.name}({self._build_valid_args(func.params)})
"""

        tests.append(
            GeneratedTest(
                name=f"test_{func.name}_http_error_500",
                description=f"Test {func.name} handles HTTP 500",
                test_code=code,
                test_type="integration",
                language="python",
                framework="pytest",
            )
        )

        # Database connection failure
        code = f"""{await_prefix}def test_{func.name}_db_connection_failure():
    \"\"\"Test {func.name} handles database connection failure.\"\"\"
    with patch("sqlite3.connect") as mock_connect:
        mock_connect.side_effect = Exception("Connection refused")
        with pytest.raises(Exception):
            {call_prefix}{func.name}({self._build_valid_args(func.params)})
"""

        tests.append(
            GeneratedTest(
                name=f"test_{func.name}_db_connection_failure",
                description=f"Test {func.name} handles DB connection failure",
                test_code=code,
                test_type="integration",
                language="python",
                framework="pytest",
            )
        )

        return tests

    def _build_valid_args(self, params: List[FunctionParam]) -> str:
        """Build a string of valid argument values for function parameters."""
        args: List[str] = []
        for param in params:
            if param.default_value is not None:
                args.append(param.default_value)
            elif param.has_default:
                args.append("None")
            else:
                type_hint = (param.type_hint or "").lower()
                if "str" in type_hint:
                    args.append(f'"test_{param.name}"')
                elif "int" in type_hint:
                    args.append("42")
                elif "float" in type_hint:
                    args.append("3.14")
                elif "bool" in type_hint:
                    args.append("True")
                elif "list" in type_hint:
                    args.append("[1, 2, 3]")
                elif "dict" in type_hint:
                    args.append(f"{{'{param.name}': 'value'}}")
                elif "optional" in type_hint:
                    args.append("None")
                else:
                    args.append(f'"test_{param.name}"')
        return ", ".join(args)

    def _build_args_with_override(
        self, params: List[FunctionParam], override_name: str, override_value: str
    ) -> str:
        """Build argument string with one parameter overridden."""
        args: List[str] = []
        for param in params:
            if param.name == override_name:
                args.append(str(override_value))
            else:
                type_hint = (param.type_hint or "").lower()
                if "str" in type_hint:
                    args.append(f'"test_{param.name}"')
                elif "int" in type_hint:
                    args.append("42")
                elif "float" in type_hint:
                    args.append("3.14")
                elif "bool" in type_hint:
                    args.append("True")
                elif "list" in type_hint:
                    args.append("[1, 2, 3]")
                elif "dict" in type_hint:
                    args.append(f"{{'{param.name}': 'value'}}")
                else:
                    args.append(f'"test_{param.name}"')
        return ", ".join(args)


class AITestGeneratorAgent(BaseSecurityAgent):
    """
    AI-Enhanced Test Generator Agent that combines LLM intelligence
    with template-based generation for maximum coverage.

    This agent wraps the base TestGeneratorAgent and enhances its output
    with AI-generated tests for complex scenarios.

    Priority: 44 (runs just before standard test generator)
    """

    name: str = "test_generator_ai"
    role: str = "AI-Enhanced Test Case Generator"
    tools: List[str] = []
    priority: int = 44

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        """Initialize the AI test generator agent."""
        super().__init__(config)
        api_key = (config or {}).get("openai_api_key")
        self._ai_generator = AIEnhancedTestGenerator(openai_api_key=api_key)
        self._base_generator: Optional[Any] = None

    async def scan(self, context: ScanContext) -> AgentResult:
        """
        Generate AI-enhanced tests for parsed functions/classes.

        Args:
            context: ScanContext with source_path, languages, etc.

        Returns:
            AgentResult with generated test suites as metadata.
        """
        import time

        start = time.time() * 1000
        logger.info(
            "[%s] AI TestGeneratorAgent starting",
            context.scan_id,
        )

        # First, run the base generator
        from agents.test_generator import TestGeneratorAgent

        base_gen = TestGeneratorAgent(self.config)
        base_result = await base_gen.scan(context)

        # Enhance with AI-generated tests if OpenAI is available
        ai_test_count = 0
        try:
            ai_tests = await self._generate_ai_enhancements(context, base_gen)
            ai_test_count = len(ai_tests)
        except Exception as e:
            logger.debug("AI enhancement failed: %s", e)
            ai_tests = []

        elapsed = int((time.time() * 1000) - start)

        # Merge metadata
        metadata = dict(base_result.metadata or {})
        metadata["ai_enhanced"] = self._ai_generator._openai_client is not None
        metadata["ai_generated_tests"] = ai_test_count

        logger.info(
            "[%s] AI TestGeneratorAgent complete: %d base tests + %d AI tests in %d ms",
            context.scan_id,
            metadata.get("total_tests", 0),
            ai_test_count,
            elapsed,
        )

        return AgentResult(
            agent_name=self.name,
            agent_role=self.role,
            scan_id=context.scan_id,
            findings=[],
            summary=base_result.summary,
            execution_time_ms=elapsed,
            status=base_result.status,
            errors=base_result.errors,
            metadata=metadata,
        )

    async def _generate_ai_enhancements(
        self,
        context: ScanContext,
        base_gen: Any,
    ) -> List[GeneratedTest]:
        """Generate AI-enhanced tests to supplement base tests."""
        ai_tests: List[GeneratedTest] = []

        # Get parsed functions from the base generator's test suites
        for suite in base_gen.get_test_suites():
            if suite.language != "python":
                continue

            # We need to re-parse to get function metadata
            # For now, generate property-based and integration tests generically
            try:
                prop_tests = await self._ai_generator.generate_property_based_tests(
                    ParsedFunction(name=suite.target_name),
                    suite.target_name,
                )
                ai_tests.extend(prop_tests)
            except Exception as e:
                logger.debug("Property test generation failed: %s", e)

        return ai_tests

    def _get_supported_languages(self) -> List[str]:
        return ["python", "javascript", "typescript", "java", "go"]

    def _get_categories(self) -> List[str]:
        return ["AI Test Generation", "Property-Based Testing", "Integration Testing"]
