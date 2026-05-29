"""
Intelligent Vulnerability Prioritization Engine for CodeShield AI.

Provides context-aware vulnerability scoring based on:
- Code context: exposed endpoints, user input reachability, auth requirements
- Threat intelligence: CISA KEV, EPSS scores, exploit availability
- Business impact: production indicators, PII/financial data handling, regulatory exposure

Outputs a final priority score (0-100) mapped to priority bands P0-P4.
"""

import asyncio
import json
import os
import re
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from models.vulnerability import Vulnerability
from utils.logger import get_logger

logger = get_logger(__name__)

# Threat intel cache
THREAT_CACHE_FILE = Path("./data/threat_intel_cache.json")
THREAT_CACHE_TTL_HOURS = 24

# Regex patterns for detecting exposed endpoints
ROUTE_PATTERNS: Dict[str, List[str]] = {
    "python": [
        r"@app\.(route|get|post|put|delete|patch)\s*\(",
        r"@router\.(get|post|put|delete|patch)\s*\(",
        r"@api_view\s*\(",
        r"path\s*\(\s*r?['\"]",
        r"url\s*\(\s*r?['\"]",
        r"@blueprint\.(route|get|post)",
        r"add_url_rule\s*\(",
        r"@application\.(route|get|post)",
        r"@resource\s*\(",
    ],
    "javascript": [
        r"\.(get|post|put|delete|patch)\s*\(\s*['\"]",
        r"app\.(use|all)\s*\(\s*['\"]",
        r"router\.(get|post|put|delete|patch)\s*\(",
        r"@Controller\s*\(",
        r"@Get\s*\(|@Post\s*\(|@Put\s*\(|@Delete\s*\(",
    ],
    "java": [
        r"@RequestMapping\s*\(",
        r"@GetMapping\s*\(",
        r"@PostMapping\s*\(",
        r"@PutMapping\s*\(",
        r"@DeleteMapping\s*\(",
        r"@Path\s*\(",
    ],
    "go": [
        r"HandleFunc\s*\(",
        r"\.(Get|Post|Put|Delete|Patch)\s*\(",
    ],
    "ruby": [
        r"(get|post|put|delete|patch)\s+['\"]",
    ],
    "php": [
        r"Route::(get|post|put|delete|patch)",
        r"@Route\s*\(",
    ],
}

# Auth decorator/middleware patterns
AUTH_PATTERNS = [
    r"@login_required",
    r"@require_auth",
    r"@authenticated",
    r"@jwt_required",
    r"@oauth_required",
    r"@permission_required",
    r"@roles_required",
    r"@require_login",
    r"auth_middleware",
    r"authenticate",
    r"verify_token",
    r"check_permission",
    r"@preauthorize",
    r"@secured",
    r"@auth_required",
    r"passport\.authenticate",
    r"firebase\.auth",
    r"@Protect",
    r"@UseGuards",
]

# Production indicators
PRODUCTION_INDICATORS = [
    r"production|prod", r"staging|stage", r"deploy",
    r"live|real", r"master|main", r"release",
]

# Data sensitivity patterns
PII_PATTERNS = [
    r"ssn|social.?security",
    r"credit.?card|cvv|ccv",
    r"email|phone|address",
    r"dob|birth.?date",
    r"passport|driver.?license",
    r"health|medical|hipaa",
    r"bank.?account|routing",
    r"tax.?id|ein",
]

FINANCIAL_PATTERNS = [
    r"payment|stripe|paypal",
    r"balance|transaction|transfer",
    r"billing|invoice|charge",
    r"currency|wallet|fund",
    r"pci.?dss|pci_dss",
]

# Regulatory indicators
REGULATORY_PATTERNS: Dict[str, List[str]] = {
    "GDPR": [
        r"gdpr|eu.*data|data.*subject",
        r"consent|right.*erasure|portability",
        r"dpo|data.*protection",
    ],
    "PCI DSS": [
        r"pci.*dss|pci_dss|payment.*card",
        r"cardholder.*data|chd",
    ],
    "HIPAA": [
        r"hipaa|phi|protected.*health",
        r"health.*insurance|medical.*record",
    ],
    "SOC2": [
        r"soc.*2|soc2",
        r"trust.*service|security.*control",
    ],
    "CCPA": [
        r"ccpa|california.*consumer",
        r"ca.*privacy|consumer.*right",
    ],
}

# CVE to CWE mapping for threat intel
CVE_CWE_MAP: Dict[str, str] = {
    "CVE-2023-32629": "CWE-89",  # SQL Injection
    "CVE-2023-36884": "CWE-79",  # XSS
    "CVE-2023-38408": "CWE-798",  # Hardcoded credentials
    "CVE-2023-29357": "CWE-287",  # Auth bypass
}

# Simulated CISA KEV data (in production, fetch from CISA API)
CISA_KEV_ENTRIES: Set[str] = {
    "CVE-2023-32629", "CVE-2023-36884", "CVE-2023-38408",
    "CVE-2023-29357", "CVE-2023-21716", "CVE-2023-23397",
    "CVE-2023-34362", "CVE-2023-22515", "CVE-2023-20198",
    "CVE-2023-36874", "CVE-2023-3824", "CVE-2023-44487",
    "CVE-2023-4863", "CVE-2023-41993", "CVE-2023-36745",
    "CVE-2023-3519", "CVE-2023-27997", "CVE-2023-27350",
    "CVE-2023-21839", "CVE-2023-20873",
}


class PriorityBand(str, Enum):
    """Priority band for vulnerabilities."""

    P0 = "P0"  # Critical: Act immediately
    P1 = "P1"  # High: Fix within 24 hours
    P2 = "P2"  # Medium: Fix within 1 week
    P3 = "P3"  # Low: Fix within 1 month
    P4 = "P4"  # Info: Best practice


class PrioritizedVulnerability:
    """Vulnerability with priority scoring."""

    def __init__(
        self,
        vulnerability: Vulnerability,
        priority_score: float,
        priority_band: PriorityBand,
        context_factors: Dict[str, Any],
        threat_intel: Dict[str, Any],
        business_impact: Dict[str, Any],
    ) -> None:
        self.vulnerability = vulnerability
        self.priority_score = priority_score
        self.priority_band = priority_band
        self.context_factors = context_factors
        self.threat_intel = threat_intel
        self.business_impact = business_impact

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "vulnerability": self.vulnerability.model_dump(),
            "priority_score": round(self.priority_score, 1),
            "priority_band": self.priority_band.value,
            "context_factors": self.context_factors,
            "threat_intel": self.threat_intel,
            "business_impact": self.business_impact,
        }


class ThreatIntelProvider:
    """Provider for threat intelligence data."""

    def __init__(self) -> None:
        """Initialize threat intel provider."""
        self._cache: Optional[Dict[str, Any]] = None

    def _load_cache(self) -> Dict[str, Any]:
        """Load threat intel cache."""
        if self._cache is not None:
            return self._cache

        if THREAT_CACHE_FILE.exists():
            try:
                with open(THREAT_CACHE_FILE, "r", encoding="utf-8") as f:
                    self._cache = json.load(f)
                    # Check TTL
                    cached_time = self._cache.get("cached_at", "")
                    if cached_time:
                        cached_dt = datetime.fromisoformat(cached_time)
                        hours_ago = (datetime.now(timezone.utc) - cached_dt).total_seconds() / 3600
                        if hours_ago > THREAT_CACHE_TTL_HOURS:
                            self._cache = None
            except (Exception) as e:
                logger.warning("Failed to load threat cache: %s", e)
                self._cache = None

        if self._cache is None:
            self._cache = {
                "cached_at": datetime.now(timezone.utc).isoformat(),
                "kev": list(CISA_KEV_ENTRIES),
                "epss": {},
            }

        return self._cache

    async def check_cisa_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the CISA KEV catalog."""
        cache = self._load_cache()
        kev_set = set(cache.get("kev", []))
        return cve_id.upper() in kev_set

    async def get_epss_score(self, cve_id: str) -> float:
        """
        Get EPSS (Exploit Prediction Scoring System) score for a CVE.

        Returns a score between 0.0 and 1.0 representing probability
        of exploitation in the wild.
        """
        cache = self._load_cache()
        epss_data = cache.get("epss", {})

        if cve_id.upper() in epss_data:
            return float(epss_data[cve_id.upper()])

        # In production, fetch from EPSS API: https://api.first.org/epss/v1/epss
        # For now, estimate based on severity
        severity_map = {
            "CRITICAL": 0.8,
            "HIGH": 0.5,
            "MEDIUM": 0.2,
            "LOW": 0.05,
            "INFO": 0.01,
        }

        # Derive from CWE if we have a mapping
        cwe = CVE_CWE_MAP.get(cve_id.upper(), "")
        if cwe:
            base_score = severity_map.get("HIGH", 0.3)
        else:
            base_score = severity_map.get("MEDIUM", 0.2)

        # Cache the result
        epss_data[cve_id.upper()] = base_score
        self._save_cache()

        return base_score

    async def check_exploit_availability(self, cve_id: str) -> Dict[str, Any]:
        """
        Check if public exploits are available for a CVE.

        In production, queries ExploitDB, GitHub, VulnCheck, etc.
        """
        is_in_kev = await self.check_cisa_kev(cve_id)

        # Simulate exploit availability lookup
        exploit_available = is_in_kev or cve_id.upper() in {
            "CVE-2023-38408", "CVE-2023-32629",
        }

        return {
            "cve_id": cve_id,
            "exploit_available": exploit_available,
            "exploit_db_entry": exploit_available,
            "github_poc_available": exploit_available,
            "in_cisa_kev": is_in_kev,
            "source": "simulated",
        }

    def _save_cache(self) -> None:
        """Save threat intel cache."""
        if self._cache is None:
            return
        THREAT_CACHE_FILE.parent.mkdir(parents=True, exist_ok=True)
        try:
            with open(THREAT_CACHE_FILE, "w", encoding="utf-8") as f:
                json.dump(self._cache, f, indent=2)
        except Exception as e:
            logger.warning("Failed to save threat cache: %s", e)


class ContextAnalyzer:
    """Analyzes code context for vulnerability prioritization."""

    def analyze_endpoint_exposure(
        self,
        file_content: str,
        file_path: str,
        language: str = "python",
    ) -> bool:
        """
        Check if code is in a publicly exposed endpoint.

        Args:
            file_content: File content
            file_path: File path
            language: Programming language

        Returns:
            True if code is in an exposed endpoint
        """
        patterns = ROUTE_PATTERNS.get(language, ROUTE_PATTERNS.get("python", []))
        content = file_content or ""

        for pattern in patterns:
            if re.search(pattern, content):
                return True

        return False

    def analyze_auth_requirement(
        self,
        file_content: str,
        vuln_line: int,
    ) -> bool:
        """
        Check if authentication is required for the vulnerable code.

        Args:
            file_content: File content
            vuln_line: Line number of vulnerability

        Returns:
            True if authentication appears to be required
        """
        if not file_content:
            return False

        lines = file_content.splitlines()
        # Check context around vulnerability
        start = max(0, vuln_line - 20)
        end = min(len(lines), vuln_line + 5)
        context = "\n".join(lines[start:end])

        for pattern in AUTH_PATTERNS:
            if re.search(pattern, context, re.IGNORECASE):
                return True

        return False

    def analyze_user_input_reachability(
        self,
        file_content: str,
        vuln_line: int,
    ) -> bool:
        """
        Check if user input reaches the vulnerable line.

        Args:
            file_content: File content
            vuln_line: Line number of vulnerability

        Returns:
            True if user input reaches the vulnerability
        """
        if not file_content:
            return False

        lines = file_content.splitlines()
        start = max(0, vuln_line - 30)
        end = min(len(lines), vuln_line + 5)
        context = "\n".join(lines[start:end])

        user_input_patterns = [
            r"request\.(args|form|json|data|files|values)",
            r"req\.(query|params|body|headers)",
            r"\$_(GET|POST|REQUEST)",
            r"params\[", r"args\[",
            r"input\(", r"raw_input\(",
            r"sys\.argv",
            r"\buser_input\b", r"\buser_data\b", r"\buserinput\b",
            r"\buser_supplied\b", r"\buntrusted\b",
        ]

        for pattern in user_input_patterns:
            if re.search(pattern, context):
                return True

        return False

    def analyze_code_context(
        self,
        vuln: Vulnerability,
        source_path: Optional[str],
    ) -> Dict[str, Any]:
        """
        Analyze full code context for a vulnerability.

        Args:
            vuln: Vulnerability
            source_path: Source code path

        Returns:
            Context analysis results
        """
        result: Dict[str, Any] = {
            "is_exposed_endpoint": False,
            "requires_auth": False,
            "user_input_reachable": False,
            "is_in_dependency": False,
        }

        content: Optional[str] = None
        file_path = vuln.file_path
        if source_path:
            file_path = os.path.join(source_path, vuln.file_path)
            if os.path.exists(file_path):
                try:
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        content = f.read()
                except Exception:
                    content = None

        # Fall back to the finding's own code snippet when the file is not on disk
        if not content:
            content = vuln.code_snippet or ""
        if not content:
            return result

        # Detect language from extension
        language = self._detect_language(vuln.file_path)

        # Check if exposed endpoint
        result["is_exposed_endpoint"] = self.analyze_endpoint_exposure(
            content, file_path, language
        )

        # Check auth requirement
        result["requires_auth"] = self.analyze_auth_requirement(
            content, vuln.line_number
        )

        # Check user input reachability
        result["user_input_reachable"] = self.analyze_user_input_reachability(
            content, vuln.line_number
        )

        # Check if in dependency
        result["is_in_dependency"] = any(
            marker in vuln.file_path.lower()
            for marker in ["node_modules", "site-packages", "vendor", "dist-packages"]
        )

        return result

    def _detect_language(self, file_path: str) -> str:
        """Detect programming language from file extension."""
        ext_map = {
            ".py": "python", ".js": "javascript", ".ts": "javascript",
            ".java": "java", ".go": "go", ".rb": "ruby",
            ".php": "php", ".cs": "csharp", ".swift": "swift",
            ".kt": "java", ".rs": "rust",
        }
        ext = Path(file_path).suffix.lower()
        return ext_map.get(ext, "python")


class BusinessImpactAnalyzer:
    """Analyzes business impact of vulnerabilities."""

    def analyze_production_indicator(
        self,
        file_path: str,
        file_content: Optional[str] = None,
    ) -> float:
        """
        Check if code is production code.

        Returns:
            Score 0.0-1.0 indicating likelihood of being production code
        """
        path_lower = file_path.lower()

        # Check for production indicators in path
        for pattern in PRODUCTION_INDICATORS:
            if re.search(pattern, path_lower):
                return 0.8

        # Check for dev/test indicators
        dev_indicators = ["test", "spec", "mock", "dev", "debug", "example", "demo"]
        if any(ind in path_lower for ind in dev_indicators):
            return 0.3

        # Check content
        if file_content:
            content_lower = file_content.lower()
            if "debug = true" in content_lower or "debug=true" in content_lower:
                return 0.4
            if "production" in content_lower or "prod" in content_lower:
                return 0.9

        return 0.6  # Default: likely production

    def analyze_data_sensitivity(
        self,
        file_content: str,
    ) -> Dict[str, Any]:
        """
        Analyze data sensitivity of the code.

        Args:
            file_content: File content

        Returns:
            Dict with sensitivity analysis
        """
        if not file_content:
            return {"handles_pii": False, "handles_financial": False, "sensitivity_score": 0.0}

        content_lower = file_content.lower()

        pii_found = []
        for pattern in PII_PATTERNS:
            if re.search(pattern, content_lower):
                pii_found.append(pattern)

        financial_found = []
        for pattern in FINANCIAL_PATTERNS:
            if re.search(pattern, content_lower):
                financial_found.append(pattern)

        sensitivity_score = 0.0
        if pii_found:
            sensitivity_score += 0.4
        if financial_found:
            sensitivity_score += 0.5

        return {
            "handles_pii": bool(pii_found),
            "pii_types": [p for p in PII_PATTERNS if re.search(p, content_lower)],
            "handles_financial": bool(financial_found),
            "financial_types": [p for p in FINANCIAL_PATTERNS if re.search(p, content_lower)],
            "sensitivity_score": min(sensitivity_score, 1.0),
        }

    def analyze_regulatory_exposure(
        self,
        file_content: str,
        file_path: str,
    ) -> Dict[str, Any]:
        """
        Analyze regulatory exposure.

        Args:
            file_content: File content
            file_path: File path

        Returns:
            Dict with regulatory analysis
        """
        if not file_content:
            return {"regulations": [], "regulatory_score": 0.0}

        content_lower = file_content.lower()
        regulations_found = []

        for regulation, patterns in REGULATORY_PATTERNS.items():
            for pattern in patterns:
                if re.search(pattern, content_lower):
                    regulations_found.append(regulation)
                    break

        # Also check file path
        path_lower = file_path.lower()
        if "payment" in path_lower or "billing" in path_lower:
            if "PCI DSS" not in regulations_found:
                regulations_found.append("PCI DSS")

        if "health" in path_lower or "medical" in path_lower:
            if "HIPAA" not in regulations_found:
                regulations_found.append("HIPAA")

        regulatory_score = min(len(regulations_found) * 0.25, 1.0)

        return {
            "regulations": regulations_found,
            "regulatory_score": regulatory_score,
        }

    def analyze_business_impact(
        self,
        vuln: Vulnerability,
        source_path: Optional[str],
    ) -> Dict[str, Any]:
        """
        Full business impact analysis.

        Args:
            vuln: Vulnerability
            source_path: Source code path

        Returns:
            Business impact analysis
        """
        file_path = os.path.join(source_path, vuln.file_path) if source_path else vuln.file_path

        file_content = ""
        if source_path and os.path.exists(file_path):
            try:
                with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                    file_content = f.read()
            except Exception:
                pass

        production_score = self.analyze_production_indicator(file_path, file_content)
        data_sensitivity = self.analyze_data_sensitivity(file_content)
        regulatory = self.analyze_regulatory_exposure(file_content, file_path)

        return {
            "production_score": production_score,
            "data_sensitivity": data_sensitivity,
            "regulatory_exposure": regulatory,
            "overall_business_score": (
                production_score * 0.4
                + data_sensitivity["sensitivity_score"] * 0.4
                + regulatory["regulatory_score"] * 0.2
            ),
        }


class PrioritizationEngine:
    """
    Intelligent vulnerability prioritization engine.

    Combines context analysis, threat intelligence, and business impact
    to produce a final priority score (0-100) mapped to priority bands.
    """

    def __init__(self) -> None:
        """Initialize the prioritization engine."""
        self.context_analyzer = ContextAnalyzer()
        self.threat_intel = ThreatIntelProvider()
        self.business_analyzer = BusinessImpactAnalyzer()

    async def prioritize_vulnerabilities(
        self,
        vulnerabilities: List[Vulnerability],
        source_path: Optional[str] = None,
    ) -> List[PrioritizedVulnerability]:
        """
        Prioritize a list of vulnerabilities.

        Args:
            vulnerabilities: List of vulnerabilities to prioritize
            source_path: Path to scanned source code

        Returns:
            List of prioritized vulnerabilities
        """
        if not vulnerabilities:
            return []

        logger.info("Prioritizing %d vulnerabilities", len(vulnerabilities))

        prioritized: List[PrioritizedVulnerability] = []

        for vuln in vulnerabilities:
            try:
                p_vuln = await self._prioritize_single(vuln, source_path)
                prioritized.append(p_vuln)
            except Exception as e:
                logger.debug("Failed to prioritize %s: %s", vuln.id, e)
                # Add with default priority
                prioritized.append(
                    PrioritizedVulnerability(
                        vulnerability=vuln,
                        priority_score=self._severity_to_base_score(vuln.severity),
                        priority_band=self._score_to_band(
                            self._severity_to_base_score(vuln.severity)
                        ),
                        context_factors={},
                        threat_intel={},
                        business_impact={},
                    )
                )

        # Sort by priority score descending
        prioritized.sort(key=lambda x: x.priority_score, reverse=True)

        return prioritized

    async def _prioritize_single(
        self,
        vuln: Vulnerability,
        source_path: Optional[str],
    ) -> PrioritizedVulnerability:
        """Prioritize a single vulnerability."""
        # 1. Base score from severity
        base_score = self._severity_to_base_score(vuln.severity)

        # 2. Context analysis
        context_factors = self.context_analyzer.analyze_code_context(vuln, source_path)
        context_score = self._compute_context_score(context_factors)

        # 3. Threat intelligence
        threat_intel = await self._get_threat_intel(vuln)
        threat_score = self._compute_threat_score(threat_intel)

        # 4. Business impact
        business_impact = self.business_analyzer.analyze_business_impact(vuln, source_path)
        business_score = business_impact.get("overall_business_score", 0.5)

        # 5. Final weighted score (0-100)
        final_score = (
            base_score * 10 * 0.30      # base_score is 0-10 -> 0-100
            + context_score * 100 * 0.25
            + threat_score * 100 * 0.25
            + business_score * 100 * 0.20
        )

        final_score = min(100.0, max(0.0, final_score))

        priority_band = self._score_to_band(final_score)

        return PrioritizedVulnerability(
            vulnerability=vuln,
            priority_score=final_score,
            priority_band=priority_band,
            context_factors=context_factors,
            threat_intel=threat_intel,
            business_impact=business_impact,
        )

    def _severity_to_base_score(self, severity: str) -> float:
        """Convert severity to base score (0-10)."""
        scores = {
            "CRITICAL": 10.0,
            "HIGH": 7.5,
            "MEDIUM": 5.0,
            "LOW": 2.5,
            "INFO": 1.0,
        }
        return scores.get(severity.upper(), 5.0)

    def _compute_context_score(self, factors: Dict[str, Any]) -> float:
        """
        Compute context score from 0-1.

        Higher = more dangerous context (exposed endpoint, no auth, user input reachable)
        """
        score = 0.0

        if factors.get("is_exposed_endpoint"):
            score += 0.4
        if factors.get("user_input_reachable"):
            score += 0.3
        if not factors.get("requires_auth"):
            score += 0.2  # No auth = more dangerous
        if factors.get("is_in_dependency"):
            score -= 0.3  # Dependency issues are less directly controllable

        return min(1.0, max(0.0, score))

    def _compute_threat_score(self, threat_intel: Dict[str, Any]) -> float:
        """Compute threat score from 0-1."""
        score = 0.0

        if threat_intel.get("in_cisa_kev", False):
            score += 0.5
        if threat_intel.get("exploit_available", False):
            score += 0.3

        epss = threat_intel.get("epss_score", 0.0)
        score += epss * 0.2

        return min(1.0, score)

    async def _get_threat_intel(
        self,
        vuln: Vulnerability,
    ) -> Dict[str, Any]:
        """Get threat intelligence for a vulnerability."""
        result: Dict[str, Any] = {
            "in_cisa_kev": False,
            "exploit_available": False,
            "epss_score": 0.0,
            "cve_checked": False,
        }

        # Check if we have a CVE ID
        cve_id = None
        if vuln.cwe_id and vuln.cwe_id.startswith("CVE-"):
            cve_id = vuln.cwe_id

        if cve_id:
            result["cve_checked"] = True
            result["in_cisa_kev"] = await self.threat_intel.check_cisa_kev(cve_id)
            result["epss_score"] = await self.threat_intel.get_epss_score(cve_id)
            exploit_info = await self.threat_intel.check_exploit_availability(cve_id)
            result["exploit_available"] = exploit_info.get("exploit_available", False)
        else:
            # Estimate EPSS-like score from severity
            severity_scores = {"CRITICAL": 0.7, "HIGH": 0.4, "MEDIUM": 0.15, "LOW": 0.03, "INFO": 0.0}
            result["epss_score"] = severity_scores.get(vuln.severity.upper(), 0.1)

        return result

    def _score_to_band(self, score: float) -> PriorityBand:
        """Convert numeric score to priority band."""
        if score >= 80:
            return PriorityBand.P0
        elif score >= 60:
            return PriorityBand.P1
        elif score >= 40:
            return PriorityBand.P2
        elif score >= 20:
            return PriorityBand.P3
        else:
            return PriorityBand.P4

    def get_priority_guidelines(self) -> Dict[str, Any]:
        """Get priority band guidelines."""
        return {
            "P0": {
                "name": "Critical",
                "score_range": "80-100",
                "sla": "Act immediately",
                "description": "Actively exploited, exposed endpoint, critical severity",
            },
            "P1": {
                "name": "High",
                "score_range": "60-79",
                "sla": "Fix within 24 hours",
                "description": "High severity with exposure or exploit available",
            },
            "P2": {
                "name": "Medium",
                "score_range": "40-59",
                "sla": "Fix within 1 week",
                "description": "Medium severity with some risk factors",
            },
            "P3": {
                "name": "Low",
                "score_range": "20-39",
                "sla": "Fix within 1 month",
                "description": "Low severity or well-mitigated issues",
            },
            "P4": {
                "name": "Info",
                "score_range": "0-19",
                "sla": "Best practice",
                "description": "Informational findings, defense in depth",
            },
        }
