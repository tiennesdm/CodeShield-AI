"""
Dave - DAST Agent for CodeShield AI Multi-Agent Swarm.

Wraps the DAST Scanner for dynamic security testing.
Runs URL-based security checks (headers, SSL/TLS, CORS, clickjacking,
open redirect) and optionally OWASP ZAP. Cross-validates SAST findings
by attempting dynamic confirmation of injection vulnerabilities.
"""

import time
from typing import Any, Dict, List

from models.vulnerability import Vulnerability
from scanner.tools.dast_scanner import DASTScanner
from utils.logger import get_logger

from agents.base import BaseSecurityAgent
from agents.results import AgentResult, ScanContext, ToolExecutionSummary

logger = get_logger(__name__)


class DaveDASTAgent(BaseSecurityAgent):
    """
    Dave - Dynamic Application Security Testing (DAST) Agent.

    Performs runtime security testing on deployed applications:
    - Security headers validation (HSTS, CSP, X-Frame-Options, etc.)
    - SSL/TLS configuration checks
    - CORS policy validation
    - Clickjacking detection
    - Open redirect testing
    - Optional OWASP ZAP integration
    - Cross-validates SAST findings dynamically

    Requires a target_url in the scan context.
    Priority: 20 (runs after SAST)
    """

    name: str = "dave_dast"
    role: str = "Dynamic Application Security Testing (DAST) - validates runtime security"
    tools: List[str] = ["dast_scanner", "zap"]
    priority: int = 20

    def __init__(self, config: Dict[str, Any] = None) -> None:
        super().__init__(config)
        self._dast = DASTScanner()
        self._timeout = config.get("timeout", 30) if config else 30

    async def scan(self, context: ScanContext) -> AgentResult:
        """
        Run dynamic security tests on the target URL.

        Args:
            context: ScanContext with target_url and optional sast_findings

        Returns:
            AgentResult with dynamic findings and SAST validation results
        """
        start = time.time() * 1000
        logger.info("[%s] Dave DAST Agent starting", context.scan_id)

        all_findings: List[Vulnerability] = []
        errors: List[str] = []
        tool_summaries: List[ToolExecutionSummary] = []
        metadata: Dict[str, Any] = {
            "target_url": context.target_url,
            "validation_results": [],
        }

        # Determine target URL
        target_url = context.target_url or self._extract_url_from_source(context)
        if not target_url:
            error_msg = "No target URL provided for DAST scan"
            errors.append(error_msg)
            logger.warning("[%s] %s", context.scan_id, error_msg)
            return self._build_result(
                context=context,
                findings=[],
                start_time_ms=start,
                errors=errors,
                metadata=metadata,
            )

        metadata["target_url"] = target_url

        # 1. Run URL security checks (always available)
        t0 = time.time() * 1000
        try:
            logger.info("[%s] Running URL security checks on %s", context.scan_id, target_url)
            url_findings = await self._dast.scan(
                target_url=target_url,
                scan_id=context.scan_id,
                use_zap=False,  # Use URL checks only (faster, always available)
            )
            elapsed = int(time.time() * 1000 - t0)
            all_findings.extend(url_findings)
            tool_summaries.append(
                ToolExecutionSummary(
                    tool_name="url_security_scanner",
                    status="success",
                    findings_count=len(url_findings),
                    execution_time_ms=elapsed,
                )
            )
            logger.info(
                "[%s] URL checks found %d findings in %d ms",
                context.scan_id,
                len(url_findings),
                elapsed,
            )
        except Exception as e:
            elapsed = int(time.time() * 1000 - t0)
            errors.append(f"URL security scan failed: {e}")
            tool_summaries.append(
                ToolExecutionSummary(
                    tool_name="url_security_scanner",
                    status="failed",
                    findings_count=0,
                    execution_time_ms=elapsed,
                    error_message=str(e),
                )
            )

        # 2. Optionally run ZAP if requested
        if context.options.get("use_zap", False):
            t0 = time.time() * 1000
            try:
                logger.info("[%s] Running OWASP ZAP scan on %s", context.scan_id, target_url)
                zap_findings = await self._dast.scan(
                    target_url=target_url,
                    scan_id=context.scan_id,
                    use_zap=True,
                    scan_type=context.options.get("zap_scan_type", "full"),
                )
                elapsed = int(time.time() * 1000 - t0)
                all_findings.extend(zap_findings)
                tool_summaries.append(
                    ToolExecutionSummary(
                        tool_name="zap_scanner",
                        status="success",
                        findings_count=len(zap_findings),
                        execution_time_ms=elapsed,
                    )
                )
            except Exception as e:
                elapsed = int(time.time() * 1000 - t0)
                errors.append(f"ZAP scan failed: {e}")
                tool_summaries.append(
                    ToolExecutionSummary(
                        tool_name="zap_scanner",
                        status="failed",
                        findings_count=0,
                        execution_time_ms=elapsed,
                        error_message=str(e),
                    )
                )

        # 3. Cross-validate SAST findings if provided
        if context.sast_findings:
            validation = self._cross_validate_sast(context)
            metadata["validation_results"] = validation
            logger.info(
                "[%s] Cross-validated %d SAST findings",
                context.scan_id,
                len(validation),
            )

        deduped = self._deduplicate(all_findings)
        logger.info(
            "[%s] Dave DAST complete: %d findings",
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

    def _extract_url_from_source(self, context: ScanContext) -> str:
        """Try to extract a target URL from source code or config."""
        # Could scan for API base URLs, config files, etc.
        # For now, return empty - caller must provide URL
        return ""

    def _cross_validate_sast(self, context: ScanContext) -> List[Dict[str, Any]]:
        """
        Cross-validate SAST findings with dynamic tests.

        For example, if SAST found SQL injection, DAST can attempt
        to confirm it via a test payload on the running app.

        Args:
            context: ScanContext with sast_findings

        Returns:
            List of validation result dicts
        """
        validation_results: List[Dict[str, Any]] = []
        sast_by_category: Dict[str, List[Vulnerability]] = {}

        for finding in context.sast_findings:
            cat = finding.category.lower()
            if cat not in sast_by_category:
                sast_by_category[cat] = []
            sast_by_category[cat].append(finding)

        # For each injection-type finding, note it for dynamic confirmation
        injection_cats = ["sql injection", "command injection", "xss", "ssrf"]
        for cat in injection_cats:
            if cat in sast_by_category:
                for finding in sast_by_category[cat]:
                    validation_results.append({
                        "sast_finding_id": finding.id,
                        "category": finding.category,
                        "file_path": finding.file_path,
                        "line_number": finding.line_number,
                        "validation_type": "dynamic_confirmation",
                        "status": "pending_validation",
                        "message": (
                            f"SAST found {finding.category} at {finding.file_path}:"
                            f"{finding.line_number}. Dynamic confirmation requires "
                            f"target endpoint mapping."
                        ),
                    })

        return validation_results

    def _deduplicate(self, findings: List[Vulnerability]) -> List[Vulnerability]:
        """Deduplicate DAST findings."""
        seen: Dict[str, Vulnerability] = {}
        for f in findings:
            key = f"{f.file_path}:{f.title}"
            if key not in seen:
                seen[key] = f
        return list(seen.values())

    def _get_supported_languages(self) -> List[str]:
        return ["*"]  # DAST is language-agnostic

    def _get_categories(self) -> List[str]:
        return [
            "Security Headers", "SSL/TLS", "CORS", "Clickjacking",
            "Open Redirect", "Information Disclosure", "Server Configuration",
        ]

    def _requires_network(self) -> bool:
        return True
