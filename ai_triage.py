"""
AI False Positive Reduction Engine for CodeShield AI.

Hybrid SAST+LLM architecture that takes rule-based findings and validates
them using LLM-powered context analysis. Falls back to local heuristics
when the OpenAI API is unavailable.

Features:
- Context-aware triage with surrounding code analysis
- Confidence scoring adjustment based on code context patterns
- Organizational learning from user feedback
- OpenAI API integration with configurable key
- Local rule-based heuristics fallback
"""

import ast
import json
import os
import re
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from models.vulnerability import Vulnerability
from utils.helpers import read_file_snippet
from utils.logger import get_logger

logger = get_logger(__name__)

# Path to store user feedback for organizational learning
FEEDBACK_FILE = Path("./data/triage_feedback.json")

# Known false positive patterns (regex-based)
KNOWN_FP_PATTERNS: List[Tuple[str, str]] = [
    # Test files patterns
    (r"test.*mock", "Mock data in test file"),
    (r"mock.*data", "Mock data pattern"),
    (r"example.*com", "Example domain (example.com)"),
    (r"localhost:\d+", "Localhost reference"),
    (r"127\.0\.0\.1", "Loopback address"),
    (r"0\.0\.0\.0", "Default bind address"),
    (r"password\s*=\s*['\"]\\*+['\"]", "Masked password placeholder"),
    (r"api_key\s*=\s*['\"]<.*>['\"]", "Placeholder API key"),
    (r"TODO|FIXME|HACK|XXX", "Development comment marker"),
    (r"YOUR_|INSERT_|REPLACE_|ENTER_", "Template placeholder"),
    (r"changeme|change_me|placeholder", "Placeholder value"),
    (r"sample_|_sample|dummy_|_dummy", "Sample/dummy data"),
    (r"test_|_test|testing", "Test data"),
    (r"fake_|_fake|stub_|_stub", "Fake/stub data"),
]

# File path patterns that indicate test/mock files
TEST_FILE_PATTERNS = [
    r"test_", r"_test\.", r"_tests\.", r"tests?/",
    r"spec_", r"_spec\.", r"__tests__", r"__mocks__",
    r"mock_", r"_mock\.", r"fixture", r"conftest",
    r"\.test\.", r"\.spec\.", r"jest", r"cypress",
    r"playwright", r"selenium", r"e2e", r"integration",
]

# Patterns indicating validation/sanitization exists nearby
VALIDATION_PATTERNS = [
    r"validate", r"sanitize", r"escape", r"clean",
    r"strip", r"htmlspecialchars", r"bleach", r"purify",
    r"parametrize", r"placeholder", r"\?.*%s",
    r"re\.match", r"re\.search", r"re\.fullmatch",
    r"try\s*:", r"except\s+", r"finally\s*:",
    r"json\.loads", r"ast\.literal_eval",
    r" bleach", r"defusedxml", r"lxml",
    r"hashlib\.(sha256|sha512)", r"bcrypt",
    r"werkzeug\.(secure_filename|safe_join)",
]

# User-controlled input sources
USER_INPUT_SOURCES = [
    r"request\.(args|form|json|data|files|values)",
    r"req\.(query|params|body|headers)",
    r"\$_(GET|POST|REQUEST|COOKIE|FILES)",
    r"params\[", r"args\[", r"kwargs",
    r"input\(", r"raw_input\(",
    r"sys\.argv", r"os\.environ",
    r"flask\.request", r"django\.http",
    # Common user-controlled variable names
    r"\buser_id\b", r"\buser_input\b", r"\buser_data\b",
    r"\buser_supplied\b", r"\buntrusted\b", r"\brequest_data\b",
]

# OWASP LLM Top 10 categories mapping
LLM01_PATTERNS = [
    r"(?i)(prompt\s*injection|jailbreak|ignore.*previous|bypass.*safety)",
]

LLM02_PATTERNS = [
    r"(?i)(llm\.output|model\.response|completion\..*exec|output.*render)",
]

LLM06_PATTERNS = [
    r"(?i)(openai\.api_key|anthropic\.api_key|api_key\s*=\s*['\"]sk-)",
]


class TriageVerdict(str, Enum):
    """Verdict from AI triage analysis."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    UNCERTAIN = "uncertain"


class AITriageEngine:
    """
    AI-powered false positive reduction engine.

    Uses a hybrid approach: rule-based findings are validated using
    context-aware analysis powered by LLM (when available) or local
    heuristics (fallback). Organizational learning improves accuracy
    over time via user feedback.
    """

    def __init__(self, openai_api_key: Optional[str] = None) -> None:
        """
        Initialize the AI triage engine.

        Args:
            openai_api_key: Optional OpenAI API key. If not provided,
                reads from OPENAI_API_KEY environment variable.
        """
        self.openai_api_key = openai_api_key or os.environ.get("OPENAI_API_KEY", "")
        self._feedback_data: Optional[Dict[str, Any]] = None
        self._openai_client: Optional[Any] = None

        if self.openai_api_key:
            try:
                import openai

                self._openai_client = openai.AsyncOpenAI(api_key=self.openai_api_key)
                logger.info("OpenAI client initialized for AI triage")
            except ImportError:
                logger.warning("openai package not installed, using local heuristics")
            except Exception as e:
                logger.warning("Failed to initialize OpenAI client: %s", e)
        else:
            logger.info("No OpenAI API key configured, using local heuristics only")

    def _load_feedback(self) -> Dict[str, Any]:
        """Load organizational learning feedback data."""
        if self._feedback_data is not None:
            return self._feedback_data

        if FEEDBACK_FILE.exists():
            try:
                with open(FEEDBACK_FILE, "r", encoding="utf-8") as f:
                    self._feedback_data = json.load(f)
            except (json.JSONDecodeError, Exception) as e:
                logger.warning("Failed to load feedback data: %s", e)
                self._feedback_data = {"confirmations": [], "false_positives": []}
        else:
            self._feedback_data = {"confirmations": [], "false_positives": []}

        return self._feedback_data

    def _save_feedback(self) -> None:
        """Save organizational learning feedback data."""
        if self._feedback_data is None:
            return

        FEEDBACK_FILE.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(FEEDBACK_FILE, "w", encoding="utf-8") as f:
                json.dump(self._feedback_data, f, indent=2, default=str)
        except Exception as e:
            logger.warning("Failed to save feedback data: %s", e)

    def record_feedback(
        self,
        vuln_id: str,
        verdict: str,
        user_comment: Optional[str] = None,
    ) -> Dict[str, Any]:
        """
        Record user feedback for organizational learning.

        Args:
            vuln_id: Vulnerability ID
            verdict: 'confirmed_tp' or 'confirmed_fp'
            user_comment: Optional user comment

        Returns:
            Updated feedback data
        """
        feedback = self._load_feedback()

        entry = {
            "vuln_id": vuln_id,
            "verdict": verdict,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "comment": user_comment,
        }

        if verdict == "confirmed_fp":
            feedback["false_positives"].append(entry)
            # Also add the pattern to known FP patterns for future
            feedback.setdefault("fp_vuln_ids", []).append(vuln_id)
        else:
            feedback["confirmations"].append(entry)
            feedback.setdefault("tp_vuln_ids", []).append(vuln_id)

        self._feedback_data = feedback
        self._save_feedback()

        logger.info("Recorded %s feedback for vulnerability %s", verdict, vuln_id)
        return entry

    async def triage_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability],
        source_path: Optional[str] = None,
        use_llm: bool = True,
        emit_ws_logs: bool = True,
    ) -> List[Vulnerability]:
        """
        Run AI triage on a list of vulnerabilities.

        Analyzes each vulnerability in context and adjusts confidence
        scores or flags likely false positives.

        Args:
            vulnerabilities: List of vulnerabilities to triage
            source_path: Path to the scanned source code
            use_llm: Whether to use LLM for complex triage (if available)
            emit_ws_logs: Whether to emit real-time logs to the websocket

        Returns:
            Updated vulnerability list with adjusted confidence and FP flags
        """
        if not vulnerabilities:
            return vulnerabilities

        logger.info("Starting AI triage on %d vulnerabilities", len(vulnerabilities))

        # Load feedback for organizational learning
        feedback = self._load_feedback()
        fp_vuln_ids = set(feedback.get("fp_vuln_ids", []))
        tp_vuln_ids = set(feedback.get("tp_vuln_ids", []))

        triaged: List[Vulnerability] = []

        for vuln in vulnerabilities:
            # Check organizational learning first
            if vuln.id in fp_vuln_ids:
                vuln.confidence = "LOW"
                vuln.description = f"[LIKELY FALSE POSITIVE - previously flagged] {vuln.description}"
                triaged.append(vuln)
                continue

            if vuln.id in tp_vuln_ids:
                vuln.confidence = "HIGH"
                triaged.append(vuln)
                continue

            # Emit websocket log before triaging this file/vulnerability
            if emit_ws_logs and vuln.scan_id:
                try:
                    from utils.ws_manager import ws_manager
                    import asyncio
                    file_name = os.path.basename(vuln.file_path)
                    asyncio.create_task(
                        ws_manager.broadcast_to_scan(
                            vuln.scan_id,
                            {
                                "type": "log",
                                "message": f"Triaging vulnerability in {file_name} at line {vuln.line_number}...",
                                "level": "info"
                            }
                        )
                    )
                except Exception:
                    pass

            # Run context-aware analysis
            try:
                result = await self._analyze_vulnerability(vuln, source_path, use_llm)
                verdict = result["verdict"]
                confidence_adjustment = result["confidence_adjustment"]

                if verdict == TriageVerdict.FALSE_POSITIVE:
                    vuln.confidence = "LOW"
                    vuln.description = f"[LIKELY FALSE POSITIVE] {vuln.description}"
                elif verdict == TriageVerdict.TRUE_POSITIVE:
                    vuln.confidence = self._adjust_confidence(vuln.confidence, confidence_adjustment)
                else:
                    # Uncertain - keep original but add note
                    pass

            except Exception as e:
                logger.debug("Triage analysis failed for %s: %s", vuln.id, e)

            # Emit websocket log after triaging this file/vulnerability
            if emit_ws_logs and vuln.scan_id:
                try:
                    from utils.ws_manager import ws_manager
                    import asyncio
                    file_name = os.path.basename(vuln.file_path)
                    status_text = "LIKELY FALSE POSITIVE" if "LIKELY FALSE POSITIVE" in vuln.description else "CONFIRMED"
                    asyncio.create_task(
                        ws_manager.broadcast_to_scan(
                            vuln.scan_id,
                            {
                                "type": "log",
                                "message": f"Completed triage for {file_name} - Status: {status_text}",
                                "level": "success" if status_text == "CONFIRMED" else "warn"
                            }
                        )
                    )
                except Exception:
                    pass

            triaged.append(vuln)

        fp_count = sum(1 for v in triaged if "LIKELY FALSE POSITIVE" in v.description)
        logger.info("AI triage complete: %d/%d flagged as likely false positives", fp_count, len(triaged))

        return triaged

    async def _analyze_vulnerability(
        self,
        vuln: Vulnerability,
        source_path: Optional[str],
        use_llm: bool,
    ) -> Dict[str, Any]:
        """
        Analyze a single vulnerability with context-aware checks.

        Args:
            vuln: Vulnerability to analyze
            source_path: Path to source code
            use_llm: Whether to attempt LLM analysis

        Returns:
            Dict with 'verdict' and 'confidence_adjustment'
        """
        code_context = self._get_code_context(vuln, source_path)

        # 1. Check if this is a test/mock file
        if self._is_test_file(vuln.file_path):
            return {"verdict": TriageVerdict.FALSE_POSITIVE, "confidence_adjustment": -2}

        # 2. Check for known FP patterns in code
        if self._has_known_fp_pattern(code_context):
            return {"verdict": TriageVerdict.FALSE_POSITIVE, "confidence_adjustment": -2}

        # 3. Check for existing validation/sanitization
        has_validation = self._has_validation(code_context)

        # 4. Check if variable is actually user-controlled
        is_user_controlled = self._is_user_controlled(code_context)

        # 5. Check for specific vulnerability type patterns
        vuln_checks = self._check_vulnerability_specific(vuln, code_context)

        # Combine heuristics
        fp_score = 0
        tp_score = 0

        if has_validation:
            fp_score += 1
        if not is_user_controlled and vuln.category in ("SQL Injection", "XSS", "Code Injection"):
            fp_score += 2
        if vuln_checks.get("is_mock_data", False):
            fp_score += 3
        if vuln_checks.get("is_example_code", False):
            fp_score += 2
        if vuln_checks.get("has_safe_alternative", False):
            fp_score += 1
        if vuln_checks.get("is_sanitized", False):
            fp_score += 2

        # TP indicators
        if is_user_controlled:
            tp_score += 2
        if vuln_checks.get("direct_usage", False):
            tp_score += 2
        if vuln_checks.get("no_mitigation", False):
            tp_score += 1

        # Use LLM for borderline cases or complex analysis
        if use_llm and fp_score < 2 and tp_score < 2:
            try:
                llm_result = await self._llm_triage(vuln, code_context)
                if llm_result:
                    return llm_result
            except Exception as e:
                logger.debug("LLM triage failed, using heuristics: %s", e)

        # Final verdict based on scores
        if fp_score >= 2:
            return {"verdict": TriageVerdict.FALSE_POSITIVE, "confidence_adjustment": -fp_score}
        if tp_score >= 2:
            return {"verdict": TriageVerdict.TRUE_POSITIVE, "confidence_adjustment": tp_score}

        return {"verdict": TriageVerdict.UNCERTAIN, "confidence_adjustment": 0}

    def _get_code_context(
        self,
        vuln: Vulnerability,
        source_path: Optional[str],
        context_lines: int = 10,
    ) -> str:
        """
        Get surrounding code context for a vulnerability.

        Args:
            vuln: Vulnerability with file_path and line_number
            source_path: Base source directory
            context_lines: Lines of context to include

        Returns:
            Code context string
        """
        if not source_path:
            return vuln.code_snippet or ""

        full_path = os.path.join(source_path, vuln.file_path)
        if not os.path.exists(full_path):
            return vuln.code_snippet or ""

        snippet = read_file_snippet(full_path, vuln.line_number, context=context_lines)
        return snippet or vuln.code_snippet or ""

    def _is_test_file(self, file_path: str) -> bool:
        """Check if file path indicates a test or mock file."""
        path_lower = file_path.lower()
        return any(re.search(pattern, path_lower) for pattern in TEST_FILE_PATTERNS)

    def _has_known_fp_pattern(self, code_context: str) -> bool:
        """Check if code contains known false positive patterns."""
        if not code_context:
            return False

        context_lower = code_context.lower()
        for pattern, _ in KNOWN_FP_PATTERNS:
            if re.search(pattern, context_lower):
                return True
        return False

    def _has_validation(self, code_context: str) -> bool:
        """Check if code has validation or sanitization patterns."""
        if not code_context:
            return False

        for pattern in VALIDATION_PATTERNS:
            if re.search(pattern, code_context, re.IGNORECASE):
                return True
        return False

    def _is_user_controlled(self, code_context: str) -> bool:
        """Check if the variable in question is user-controlled."""
        if not code_context:
            return False

        for pattern in USER_INPUT_SOURCES:
            if re.search(pattern, code_context):
                return True
        return False

    def _check_vulnerability_specific(
        self,
        vuln: Vulnerability,
        code_context: str,
    ) -> Dict[str, bool]:
        """
        Run vulnerability-type-specific checks.

        Args:
            vuln: Vulnerability to check
            code_context: Surrounding code context

        Returns:
            Dict of check results
        """
        result: Dict[str, bool] = {
            "is_mock_data": False,
            "is_example_code": False,
            "has_safe_alternative": False,
            "is_sanitized": False,
            "direct_usage": False,
            "no_mitigation": False,
        }

        if not code_context:
            return result

        ctx_lower = code_context.lower()
        cat_lower = vuln.category.lower()

        # SQL Injection specific
        if "sql" in cat_lower:
            # Check for parameterized queries
            if re.search(r"(execute\s*\(\s*['\"].*\?|parameteriz|prepar|bind_param)", code_context, re.IGNORECASE):
                result["is_sanitized"] = True
            # Check for ORM usage
            if re.search(r"(sqlalchemy|django\.orm|peewee| Tortoise|Prisma)", code_context, re.IGNORECASE):
                result["has_safe_alternative"] = True
            # Check for f-string in SQL
            if re.search(r"f['\"].*\{.*\}.*['\"]", code_context):
                result["direct_usage"] = True

        # XSS specific
        elif "xss" in cat_lower or "cross-site" in cat_lower:
            # Check for escaping
            if re.search(r"(escape|htmlspecialchars|bleach|sanitize|DOMPurify)", code_context, re.IGNORECASE):
                result["is_sanitized"] = True
            # Check for safe framework usage
            if re.search(r"(React\.createElement|vue|angular.*sanitize|auto.*escape)", code_context, re.IGNORECASE):
                result["has_safe_alternative"] = True

        # Hardcoded secrets specific
        elif "secret" in cat_lower or "credential" in cat_lower or "password" in cat_lower:
            # Check for placeholder patterns
            if re.search(r"(your_|placeholder|changeme|example|sample|dummy|test_)", ctx_lower):
                result["is_mock_data"] = True
            # Check for env var usage in nearby code
            if re.search(r"(os\.environ|getenv|env\[|dotenv|config\[)", code_context):
                result["has_safe_alternative"] = True

        # Eval/exec specific
        elif "eval" in cat_lower or "exec" in cat_lower or "code injection" in cat_lower:
            # Check for safe alternatives already present
            if re.search(r"(ast\.literal_eval|json\.loads)", code_context):
                result["has_safe_alternative"] = True
            # Check if argument is hardcoded string (safer)
            if re.search(r"eval\s*\(\s*['\"]", code_context):
                result["is_sanitized"] = True

        # Path traversal specific
        elif "path" in cat_lower or "traversal" in cat_lower:
            # Check for path validation
            if re.search(r"(abspath|realpath|normpath|secure_filename|safe_join|allowlist|whitelist)", code_context, re.IGNORECASE):
                result["is_sanitized"] = True

        # Weak crypto specific
        elif "crypto" in cat_lower or "hash" in cat_lower or "md5" in cat_lower:
            # Check for strong alternatives nearby
            if re.search(r"(bcrypt|argon2|sha256|sha512|scrypt|pbkdf2)", code_context, re.IGNORECASE):
                result["has_safe_alternative"] = True
            # Check if this is for non-security purposes
            if re.search(r"(checksum|etag|cache_key|hash.*not.*secur|non.*cryptographic)", ctx_lower):
                result["is_example_code"] = True

        # CORS specific
        elif "cors" in cat_lower:
            # Check if wildcard is actually in development
            if re.search(r"(DEBUG\s*=\s*True|development|dev|localhost)", code_context, re.IGNORECASE):
                result["is_example_code"] = True

        # Check for mock/test data patterns
        if re.search(r"(mock\(|MagicMock|patch\(|@patch|unittest|pytest|test_)", code_context):
            result["is_mock_data"] = True

        # Check for no mitigation
        if not result["is_sanitized"] and not result["has_safe_alternative"]:
            result["no_mitigation"] = True

        return result

    def _adjust_confidence(self, current: str, adjustment: int) -> str:
        """Adjust confidence level by given amount."""
        levels = ["LOW", "MEDIUM", "HIGH"]
        try:
            idx = levels.index(current.upper())
        except ValueError:
            idx = 1  # Default to MEDIUM

        new_idx = max(0, min(len(levels) - 1, idx + adjustment))
        return levels[new_idx]

    async def _llm_complete(
        self, prompt: str, system: str, max_tokens: int = 200
    ) -> Optional[str]:
        """
        Get an LLM completion, preferring the governed LLM layer (any provider,
        with PII redaction + audit) and falling back to the legacy OpenAI
        client. Returns None if no LLM backend is available.
        """
        try:
            from governance.assist import governed_complete
            from governance.policy import DataSensitivity

            governed = await governed_complete(
                prompt,
                system=system,
                sensitivity=DataSensitivity.CONFIDENTIAL,
                actor="ai_triage",
                max_tokens=max_tokens,
            )
            if governed is not None:
                return governed.content
        except Exception as e:  # pragma: no cover - defensive
            logger.debug("Governed triage path unavailable: %s", e)

        if self._openai_client:
            try:
                response = await self._openai_client.chat.completions.create(
                    model="gpt-4",
                    messages=[
                        {"role": "system", "content": system},
                        {"role": "user", "content": prompt},
                    ],
                    temperature=0.1,
                    max_tokens=max_tokens,
                )
                return response.choices[0].message.content
            except Exception as e:
                logger.debug("Legacy OpenAI triage failed: %s", e)
        return None

    async def _llm_triage(
        self,
        vuln: Vulnerability,
        code_context: str,
    ) -> Optional[Dict[str, Any]]:
        """
        Use OpenAI LLM for complex triage analysis.

        Args:
            vuln: Vulnerability to analyze
            code_context: Surrounding code

        Returns:
            Triage result dict or None if LLM unavailable
        """
        prompt = self._build_triage_prompt(vuln, code_context)
        system = (
            "You are a security code review expert. Analyze the given "
            "vulnerability finding and determine if it is a true positive "
            "or false positive. Respond with ONLY a JSON object: "
            '{"verdict": "true_positive|false_positive|uncertain", "reason": "..."}'
        )

        try:
            content = await self._llm_complete(prompt, system, max_tokens=200)
            if not content:
                return None

            # Extract JSON from response
            content = content.strip()
            if content.startswith("```json"):
                content = content[7:]
            if content.startswith("```"):
                content = content[3:]
            if content.endswith("```"):
                content = content[:-3]
            content = content.strip()

            result = json.loads(content)
            verdict_str = result.get("verdict", "uncertain")

            verdict_map = {
                "false_positive": TriageVerdict.FALSE_POSITIVE,
                "true_positive": TriageVerdict.TRUE_POSITIVE,
            }
            verdict = verdict_map.get(verdict_str, TriageVerdict.UNCERTAIN)

            return {"verdict": verdict, "confidence_adjustment": 0}

        except Exception as e:
            logger.debug("LLM triage call failed: %s", e)
            return None

    def _build_triage_prompt(
        self,
        vuln: Vulnerability,
        code_context: str,
    ) -> str:
        """Build the LLM triage prompt."""
        return f"""Analyze this security vulnerability finding:

**Category**: {vuln.category}
**CWE**: {vuln.cwe_id or "Unknown"}
**Severity**: {vuln.severity}
**File**: {vuln.file_path}:{vuln.line_number}
**Description**: {vuln.description}

**Code Context**:
```
{code_context}
```

Consider:
1. Is this actually in production code (not test/example/mock)?
2. Is the variable user-controlled?
3. Is there existing validation or sanitization?
4. Is this a known false positive pattern?

Respond with ONLY JSON: {{"verdict": "true_positive|false_positive|uncertain", "reason": "brief explanation"}}"""

    async def get_triage_stats(self) -> Dict[str, Any]:
        """Get statistics about triage operations."""
        feedback = self._load_feedback()
        return {
            "total_confirmations": len(feedback.get("confirmations", [])),
            "total_false_positives_flagged": len(feedback.get("false_positives", [])),
            "llm_available": self._openai_client is not None,
            "feedback_file": str(FEEDBACK_FILE),
        }
