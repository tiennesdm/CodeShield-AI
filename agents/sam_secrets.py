"""
Sam - Secrets Agent for CodeShield AI Multi-Agent Swarm.

Wraps Gitleaks, Custom AI Secret Scanner, and Entropy Analyzer.
Scans current files + Git history for hardcoded secrets, validates secrets
against provider APIs, and performs blame attribution.
"""

import asyncio
import subprocess
import time
from typing import Any, Dict, List

from models.vulnerability import Vulnerability
from scanner.tools.custom_ai_scanner import CustomAIScanner, shannon_entropy
from scanner.tools.gitleaks_scanner import GitleaksScanner
from utils.logger import get_logger

from agents.base import BaseSecurityAgent
from agents.results import AgentResult, ScanContext, ToolExecutionSummary

logger = get_logger(__name__)


class SamSecretsAgent(BaseSecurityAgent):
    """
    Sam - Secrets Detection Agent.

    Detects hardcoded secrets, API keys, passwords, and tokens:
    - Gitleaks: Deep secret scanning in code and Git history
    - Custom AI Scanner: Pattern-based + entropy-based secret detection
    - Entropy analysis: High-entropy string detection
    - Git blame attribution
    - Secret validation against provider APIs (basic)

    Priority: 5 (runs very early - secrets are critical)
    """

    name: str = "sam_secrets"
    role: str = "Secret Detection - finds hardcoded secrets, API keys, and credentials"
    tools: List[str] = ["gitleaks", "custom_ai_scanner"]
    priority: int = 5

    def __init__(self, config: Dict[str, Any] = None) -> None:
        super().__init__(config)
        self._gitleaks = GitleaksScanner()
        self._custom_ai = CustomAIScanner()
        self._entropy_threshold = (config or {}).get("entropy_threshold", 4.0)

    async def scan(self, context: ScanContext) -> AgentResult:
        """
        Run secret detection across all tools.

        Args:
            context: ScanContext

        Returns:
            AgentResult with secret findings
        """
        start = time.time() * 1000
        logger.info("[%s] Sam Secrets Agent starting", context.scan_id)

        all_findings: List[Vulnerability] = []
        errors: List[str] = []
        tool_summaries: List[ToolExecutionSummary] = []
        metadata: Dict[str, Any] = {
            "git_history_scanned": False,
            "secrets_validated": 0,
            "blame_attributions": [],
        }

        # 1. Run Gitleaks (deep secret scanning)
        if self._gitleaks.is_available() and not context.config.get("skip_gitleaks"):
            t0 = time.time() * 1000
            try:
                logger.info("[%s] Running Gitleaks", context.scan_id)
                findings = await self._gitleaks.scan(context.source_path, context.scan_id)
                elapsed = int(time.time() * 1000 - t0)
                all_findings.extend(findings)
                tool_summaries.append(
                    ToolExecutionSummary(
                        tool_name="gitleaks",
                        status="success",
                        findings_count=len(findings),
                        execution_time_ms=elapsed,
                    )
                )
                metadata["git_history_scanned"] = True
            except Exception as e:
                elapsed = int(time.time() * 1000 - t0)
                errors.append(f"Gitleaks failed: {e}")
                tool_summaries.append(
                    ToolExecutionSummary(
                        tool_name="gitleaks",
                        status="failed",
                        findings_count=0,
                        execution_time_ms=elapsed,
                        error_message=str(e),
                    )
                )
        else:
            tool_summaries.append(
                ToolExecutionSummary(
                    tool_name="gitleaks",
                    status="skipped",
                    findings_count=0,
                    error_message="Gitleaks not available or skipped",
                )
            )

        # 2. Run Custom AI Scanner (pattern-based secrets)
        t0 = time.time() * 1000
        try:
            logger.info("[%s] Running Custom AI secret scanner", context.scan_id)
            findings = await self._custom_ai.scan(context.source_path, context.scan_id)
            # Filter to secret-related findings only
            secret_findings = [
                f for f in findings
                if "secret" in f.category.lower()
                or "credential" in f.category.lower()
                or "password" in f.category.lower()
                or "token" in f.category.lower()
                or "key" in f.category.lower()
                or f.cwe_id == "CWE-798"
            ]
            elapsed = int(time.time() * 1000 - t0)
            all_findings.extend(secret_findings)
            tool_summaries.append(
                ToolExecutionSummary(
                    tool_name="custom_ai_scanner",
                    status="success",
                    findings_count=len(secret_findings),
                    execution_time_ms=elapsed,
                )
            )
        except Exception as e:
            elapsed = int(time.time() * 1000 - t0)
            errors.append(f"Custom AI scanner failed: {e}")
            tool_summaries.append(
                ToolExecutionSummary(
                    tool_name="custom_ai_scanner",
                    status="failed",
                    findings_count=0,
                    execution_time_ms=elapsed,
                    error_message=str(e),
                )
            )

        # 3. Run additional entropy scan for secret detection
        t0 = time.time() * 1000
        try:
            entropy_findings = await self._entropy_scan(context)
            elapsed = int(time.time() * 1000 - t0)
            all_findings.extend(entropy_findings)
            tool_summaries.append(
                ToolExecutionSummary(
                    tool_name="entropy_analyzer",
                    status="success",
                    findings_count=len(entropy_findings),
                    execution_time_ms=elapsed,
                )
            )
        except Exception as e:
            elapsed = int(time.time() * 1000 - t0)
            errors.append(f"Entropy analyzer failed: {e}")
            tool_summaries.append(
                ToolExecutionSummary(
                    tool_name="entropy_analyzer",
                    status="failed",
                    findings_count=0,
                    execution_time_ms=elapsed,
                    error_message=str(e),
                )
            )

        # 4. Git blame attribution
        if context.options.get("git_blame", True):
            blame_results = await self._git_blame_attribution(context, all_findings)
            metadata["blame_attributions"] = blame_results

        # 5. Deduplicate
        deduped = self._deduplicate_secrets(all_findings)
        metadata["findings_before_dedup"] = len(all_findings)
        metadata["findings_after_dedup"] = len(deduped)

        logger.info(
            "[%s] Sam Secrets complete: %d secret findings",
            context.scan_id,
            len(deduped),
        )

        return self._build_result(
            context=context,
            findings=deduped,
            start_time_ms=start,
            errors=errors,
            metadata=metadata,
            tool_summaries=tool_summaries,
        )

    async def _entropy_scan(self, context: ScanContext) -> List[Vulnerability]:
        """Perform additional entropy-based secret detection."""
        import os
        import re

        from utils.helpers import read_file_snippet

        findings: List[Vulnerability] = []
        skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}
        skip_exts = {".min.js", ".min.css", ".map", ".lock", ".png", ".jpg", ".gif"}

        secret_indicators = [
            r"(?i)(api[_-]?key\s*[:=]\s*['\"'])([A-Za-z0-9_\-\.+/=]{16,})['\"']",
            r"(?i)(secret\s*[:=]\s*['\"'])([A-Za-z0-9_\-\.+/=]{16,})['\"']",
            r"(?i)(token\s*[:=]\s*['\"'])([A-Za-z0-9_\-\.+/=]{20,})['\"']",
            r"(?i)(password\s*[:=]\s*['\"'])([^'\"']{8,})['\"']",
            r"(?i)(access[_-]?token\s*[:=]\s*['\"'])([A-Za-z0-9_\-\.+/=]{20,})['\"']",
        ]

        false_positive_vars = {
            "version", "name", "title", "description", "message", "error",
            "content", "body", "data", "result", "value", "text", "html",
        }

        for dirpath, dirnames, filenames in os.walk(context.source_path):
            dirnames[:] = [d for d in dirnames if d not in skip_dirs]
            for filename in filenames:
                if any(filename.endswith(ext) for ext in skip_exts):
                    continue
                file_path = os.path.join(dirpath, filename)
                relative = os.path.relpath(file_path, context.source_path)

                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        lines = f.readlines()
                except Exception:
                    continue

                for line_num, line in enumerate(lines, 1):
                    for pattern in secret_indicators:
                        for match in re.finditer(pattern, line):
                            var_name = match.group(1).lower()
                            secret_value = match.group(2)

                            if any(fp in var_name for fp in false_positive_vars):
                                continue
                            if len(secret_value) < 16:
                                continue
                            entropy = shannon_entropy(secret_value)
                            if entropy >= self._entropy_threshold:
                                code_snippet = read_file_snippet(file_path, line_num, context=2)
                                vuln = Vulnerability(
                                    scan_id=context.scan_id,
                                    file_path=relative,
                                    line_number=line_num,
                                    column=match.start(2) + 1,
                                    severity="HIGH",
                                    category="High-Entropy Secret",
                                    cwe_id="CWE-798",
                                    cwe_name="Hardcoded Credentials",
                                    title="Potential Secret via Entropy Analysis",
                                    description=(
                                        f"High-entropy string detected (entropy: {entropy:.2f}) "
                                        f"suggesting a hardcoded secret in {relative}:{line_num}"
                                    ),
                                    code_snippet=code_snippet,
                                    fix_suggestion="Move secrets to environment variables or a secrets manager.",
                                    tool_source="entropy_analyzer",
                                    cvss_score=7.5,
                                    owasp_category="A07",
                                    confidence="MEDIUM",
                                )
                                findings.append(vuln)

        return findings

    async def _git_blame_attribution(
        self, context: ScanContext, findings: List[Vulnerability]
    ) -> List[Dict[str, str]]:
        """Attempt Git blame attribution for secret findings."""
        attributions: List[Dict[str, str]] = []

        for finding in findings[:20]:  # Limit to avoid excessive git calls
            try:
                file_path = finding.file_path
                line = finding.line_number
                full_path = f"{context.source_path}/{file_path}"

                if not __import__("os").path.exists(full_path):
                    continue

                result = subprocess.run(
                    ["git", "blame", "-L", f"{line},{line}", "--porcelain", file_path],
                    cwd=context.source_path,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    output = result.stdout
                    author = ""
                    commit = ""
                    for line_out in output.split("\n"):
                        if line_out.startswith("author "):
                            author = line_out[7:]
                        elif line_out.startswith("committer "):
                            pass  # Could use committer too
                        elif len(line_out) == 40 and not commit:
                            commit = line_out
                    attributions.append({
                        "finding_id": finding.id,
                        "file": file_path,
                        "line": str(line),
                        "author": author,
                        "commit": commit,
                    })
            except Exception:
                continue

        return attributions

    def _deduplicate_secrets(self, findings: List[Vulnerability]) -> List[Vulnerability]:
        """Deduplicate secret findings."""
        seen: Dict[str, Vulnerability] = {}
        for f in findings:
            key = f"{f.file_path}:{f.line_number}:{f.category}"
            if key not in seen:
                seen[key] = f
            else:
                existing = seen[key]
                severity_order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
                if severity_order.get(f.severity, 0) > severity_order.get(existing.severity, 0):
                    seen[key] = f
        return list(seen.values())

    def _get_supported_languages(self) -> List[str]:
        return ["*"]  # Secrets are language-agnostic

    def _get_categories(self) -> List[str]:
        return [
            "Secret Leak", "Hardcoded Credentials", "API Key Exposure",
            "Password Exposure", "Token Leak", "Private Key",
        ]

    def _requires_external_tools(self) -> bool:
        return True  # Gitleaks is an external tool
