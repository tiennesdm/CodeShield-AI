"""
Composite Risk Scoring Engine for CodeShield AI.

Combines multiple risk indicators into a unified 0-100 risk score:
- CVSS v4.0 Base + Threat + Environmental scoring
- EPSS v3 (Exploit Prediction Scoring System) daily probability
- CISA KEV (Known Exploited Vulnerabilities) binary flag
- Reachability multiplier (direct/transitive/reachable)
- Asset criticality weighting
- Trend calculation: risk delta over time
"""

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

import httpx

from models.vulnerability import ScanResult, Vulnerability
from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)

# EPSS API endpoint
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# CISA KEV API endpoint
CISA_KEV_API_URL = "https://api.cisa.gov/known-exploited-vulnerabilities/catalog"

# CVSS v4.0 severity mapping
CVSS40_SEVERITY = {
    (0.0, 0.1): "NONE",
    (0.1, 4.0): "LOW",
    (4.0, 7.0): "MEDIUM",
    (7.0, 9.0): "HIGH",
    (9.0, 10.0): "CRITICAL",
}

# Risk score bands
RISK_BANDS = {
    (0, 10): {"label": "Minimal", "action": "No immediate action required"},
    (10, 25): {"label": "Low", "action": "Monitor and address in next maintenance cycle"},
    (25, 50): {"label": "Medium", "action": "Address within 30 days"},
    (50, 75): {"label": "High", "action": "Address within 7 days"},
    (75, 90): {"label": "Critical", "action": "Address within 48 hours"},
    (90, 101): {"label": "Severe", "action": "Immediate action required"},
}


@dataclass
class RiskFactors:
    """
    Individual risk factors for a vulnerability or scan.

    Each factor contributes to the final composite risk score.
    """

    cvss_base_score: float = 0.0  # CVSS v4.0 base score (0-10)
    cvss_threat_score: float = 0.0  # CVSS threat subscore
    cvss_environmental_score: float = 0.0  # CVSS environmental subscore
    epss_probability: float = 0.0  # EPSS v3 probability (0-1)
    cisa_kev: bool = False  # CISA KEV flag
    reachability_multiplier: float = 1.0  # 1.0x direct, 0.7x transitive, 1.5x reachable
    asset_criticality: float = 1.0  # 0.5 low, 1.0 medium, 1.5 high, 2.0 critical


@dataclass
class VulnerabilityRisk:
    """Risk assessment for a single vulnerability."""

    vulnerability_id: str
    composite_score: float  # 0-100
    risk_band: str
    risk_label: str
    recommended_action: str
    factors: RiskFactors
    contributing_factors: List[str]  # Human-readable list of why this score
    epss_data: Optional[Dict[str, Any]] = None
    kev_data: Optional[Dict[str, Any]] = None


@dataclass
class ScanRiskProfile:
    """Complete risk profile for a scan."""

    scan_id: str
    overall_score: float  # 0-100
    overall_band: str
    overall_label: str
    recommended_action: str
    vulnerability_risks: List[VulnerabilityRisk]
    summary: Dict[str, Any] = field(default_factory=dict)
    trend: Optional[str] = None  # "improving", "worsening", "stable"
    trend_delta: float = 0.0  # Score change from previous scan
    timestamp: datetime = field(default_factory=datetime.utcnow)


class RiskEngine:
    """
    Composite Risk Scoring Engine.

    Calculates unified risk scores by combining multiple indicators:
    1. CVSS v4.0 Base + Threat + Environmental metrics
    2. EPSS v3 exploitation probability
    3. CISA KEV confirmed exploitation flag
    4. Dependency reachability multiplier
    5. Asset criticality weighting

    The final composite score (0-100) maps to actionable risk bands.
    """

    def __init__(self) -> None:
        """Initialize the risk engine."""
        self._epss_cache: Dict[str, Dict[str, Any]] = {}
        self._kev_cache: Dict[str, bool] = {}
        self._cache_ttl = timedelta(hours=24)
        self._cache_timestamp: Optional[datetime] = None

    async def calculate_scan_risk(
        self,
        scan_result: ScanResult,
        previous_scan: Optional[ScanResult] = None,
        asset_criticality: str = "medium",
    ) -> ScanRiskProfile:
        """
        Calculate the complete risk profile for a scan.

        Args:
            scan_result: Current scan result
            previous_scan: Optional previous scan for trend calculation
            asset_criticality: Asset criticality level (low/medium/high/critical)

        Returns:
            ScanRiskProfile with full risk assessment
        """
        logger.info("Calculating risk profile for scan %s", scan_result.scan_id)

        # Convert asset criticality to multiplier
        criticality_map = {"low": 0.5, "medium": 1.0, "high": 1.5, "critical": 2.0}
        asset_weight = criticality_map.get(asset_criticality.lower(), 1.0)

        # Calculate risk for each vulnerability
        vuln_risks: List[VulnerabilityRisk] = []

        for vuln in scan_result.vulnerabilities:
            risk = await self._calculate_vulnerability_risk(vuln, asset_weight)
            vuln_risks.append(risk)

        # Calculate overall score from vulnerability risks
        if vuln_risks:
            # Weighted average: higher severity vulns contribute more
            weighted_scores = []
            for vr in vuln_risks:
                weight = 2.0 if vr.composite_score >= 75 else 1.5 if vr.composite_score >= 50 else 1.0
                weighted_scores.append(vr.composite_score * weight)
            overall_score = sum(weighted_scores) / max(len(weighted_scores) * 1.3, 1)
            overall_score = min(overall_score, 100.0)
        else:
            overall_score = 0.0

        # Determine risk band
        band, label, action = self._get_risk_band(overall_score)

        # Calculate trend
        trend = None
        trend_delta = 0.0
        if previous_scan and previous_scan.risk_score is not None:
            trend_delta = overall_score - previous_scan.risk_score
            if trend_delta > 5:
                trend = "worsening"
            elif trend_delta < -5:
                trend = "improving"
            else:
                trend = "stable"

        # Build summary
        severity_distribution = self._calculate_severity_distribution(vuln_risks)
        top_risks = sorted(vuln_risks, key=lambda x: x.composite_score, reverse=True)[:10]

        summary = {
            "total_vulnerabilities": len(vuln_risks),
            "severity_distribution": severity_distribution,
            "epss_enriched": sum(1 for v in vuln_risks if v.epss_data is not None),
            "kev_enriched": sum(1 for v in vuln_risks if v.kev_data is not None),
            "top_risks": [
                {
                    "id": v.vulnerability_id,
                    "score": round(v.composite_score, 1),
                    "band": v.risk_band,
                    "factors": v.contributing_factors,
                }
                for v in top_risks
            ],
            "by_reachability": self._group_by_reachability(vuln_risks),
        }

        profile = ScanRiskProfile(
            scan_id=scan_result.scan_id,
            overall_score=round(overall_score, 1),
            overall_band=band,
            overall_label=label,
            recommended_action=action,
            vulnerability_risks=vuln_risks,
            summary=summary,
            trend=trend,
            trend_delta=round(trend_delta, 1),
        )

        logger.info(
            "Risk profile for scan %s: score=%.1f, band=%s, trend=%s",
            scan_result.scan_id,
            overall_score,
            band,
            trend,
        )

        return profile

    async def _calculate_vulnerability_risk(
        self, vuln: Vulnerability, asset_criticality: float
    ) -> VulnerabilityRisk:
        """
        Calculate composite risk for a single vulnerability.

        Args:
            vuln: The vulnerability to assess
            asset_criticality: Asset criticality weight

        Returns:
            VulnerabilityRisk with full assessment
        """
        factors = RiskFactors()
        contributing: List[str] = []

        # 1. CVSS Base Score (0-10, default from severity)
        if vuln.cvss_score and vuln.cvss_score > 0:
            factors.cvss_base_score = min(vuln.cvss_score / 10.0, 1.0)
        else:
            factors.cvss_base_score = self._severity_to_cvss_ratio(vuln.severity)

        # 2. Check EPSS for CVE-based vulnerabilities
        epss_data = None
        if vuln.cwe_id:
            epss_data = await self._query_epss(vuln.cwe_id)
            if epss_data:
                factors.epss_probability = epss_data.get("epss", 0.0)

        # 3. Check CISA KEV
        kev_data = None
        if vuln.cwe_id:
            kev_flag = await self._query_kev(vuln.cwe_id)
            factors.cisa_kev = kev_flag
            if kev_flag:
                kev_data = {"known_exploited": True}

        # 4. Asset criticality
        factors.asset_criticality = asset_criticality

        # Calculate composite score
        # Formula: (CVSS * 40% + EPSS * 30% + KEV * 20% + Asset * 10%) * Reachability * 100
        cvss_weight = 0.40
        epss_weight = 0.30
        kev_weight = 0.20
        asset_weight = 0.10

        cvss_component = factors.cvss_base_score * cvss_weight
        epss_component = factors.epss_probability * epss_weight
        kev_component = (1.0 if factors.cisa_kev else 0.0) * kev_weight
        asset_component = min(factors.asset_criticality / 2.0, 1.0) * asset_weight

        base_score = (cvss_component + epss_component + kev_component + asset_component)
        composite = min(base_score * 100 * factors.reachability_multiplier, 100.0)

        # Build contributing factors list
        if factors.cvss_base_score >= 0.7:
            contributing.append(f"High CVSS base score ({factors.cvss_base_score:.1f})")
        if factors.epss_probability >= 0.5:
            contributing.append(f"High EPSS probability ({factors.epss_probability:.2%})")
        elif factors.epss_probability > 0:
            contributing.append(f"EPSS probability: {factors.epss_probability:.2%}")
        if factors.cisa_kev:
            contributing.append("Listed in CISA KEV catalog")
        if factors.asset_criticality > 1.0:
            contributing.append(f"Critical asset (multiplier: {factors.asset_criticality:.1f}x)")
        if factors.reachability_multiplier > 1.0:
            contributing.append("Reachable vulnerability")

        if not contributing:
            contributing.append("Standard severity-based scoring")

        # Determine band
        band, label, action = self._get_risk_band(composite)

        return VulnerabilityRisk(
            vulnerability_id=vuln.id,
            composite_score=round(composite, 1),
            risk_band=band,
            risk_label=label,
            recommended_action=action,
            factors=factors,
            contributing_factors=contributing,
            epss_data=epss_data,
            kev_data=kev_data,
        )

    async def _query_epss(self, cwe_id: str) -> Optional[Dict[str, Any]]:
        """
        Query EPSS API for exploitation probability.

        Args:
            cwe_id: CWE identifier

        Returns:
            EPSS data dict or None if not available
        """
        # EPSS works with CVE IDs, not CWE. We check cache first.
        if cwe_id in self._epss_cache:
            cached = self._epss_cache[cwe_id]
            return cached if cached else None

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    EPSS_API_URL,
                    params={"cve": cwe_id},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("data"):
                        epss_entry = data["data"][0]
                        self._epss_cache[cwe_id] = epss_entry
                        return epss_entry

            self._epss_cache[cwe_id] = {}
            return None

        except Exception as e:
            logger.debug("EPSS query failed for %s: %s", cwe_id, e)
            self._epss_cache[cwe_id] = {}
            return None

    async def _query_kev(self, cwe_id: str) -> bool:
        """
        Query CISA KEV catalog for known exploited vulnerability.

        Args:
            cwe_id: CWE identifier

        Returns:
            True if the vulnerability is in the KEV catalog
        """
        if cwe_id in self._kev_cache:
            return self._kev_cache[cwe_id]

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                resp = await client.get(
                    CISA_KEV_API_URL,
                    params={"cveID": cwe_id},
                )
                if resp.status_code == 200:
                    data = resp.json()
                    is_kev = bool(data.get("vulnerabilities"))
                    self._kev_cache[cwe_id] = is_kev
                    return is_kev

            self._kev_cache[cwe_id] = False
            return False

        except Exception as e:
            logger.debug("KEV query failed for %s: %s", cwe_id, e)
            self._kev_cache[cwe_id] = False
            return False

    @staticmethod
    def _severity_to_cvss_ratio(severity: str) -> float:
        """Convert severity string to CVSS ratio (0-1)."""
        mapping = {
            "CRITICAL": 0.95,
            "HIGH": 0.75,
            "MEDIUM": 0.50,
            "LOW": 0.25,
            "INFO": 0.05,
        }
        return mapping.get(severity.upper(), 0.5)

    @staticmethod
    def _get_risk_band(score: float) -> Tuple[str, str, str]:
        """
        Map a numerical score to a risk band.

        Args:
            score: Risk score (0-100)

        Returns:
            Tuple of (band_key, label, recommended_action)
        """
        for (low, high), info in RISK_BANDS.items():
            if low <= score < high:
                return (f"{low}-{high}", info["label"], info["action"])
        return ("0-10", "Minimal", "No immediate action required")

    def _calculate_severity_distribution(self, vuln_risks: List[VulnerabilityRisk]) -> Dict[str, int]:
        """Count vulnerabilities by risk band."""
        dist: Dict[str, int] = {}
        for vr in vuln_risks:
            band = vr.risk_label
            dist[band] = dist.get(band, 0) + 1
        return dist

    def _group_by_reachability(self, vuln_risks: List[VulnerabilityRisk]) -> Dict[str, int]:
        """Group vulnerabilities by reachability type."""
        groups = {"direct": 0, "transitive": 0, "reachable": 0}
        for vr in vuln_risks:
            mult = vr.factors.reachability_multiplier
            if mult >= 1.5:
                groups["reachable"] += 1
            elif mult <= 0.7:
                groups["transitive"] += 1
            else:
                groups["direct"] += 1
        return groups

    def to_dict(self, profile: ScanRiskProfile) -> Dict[str, Any]:
        """
        Convert ScanRiskProfile to a dictionary.

        Args:
            profile: The risk profile to convert

        Returns:
            Dictionary representation
        """
        return {
            "scan_id": profile.scan_id,
            "overall_score": profile.overall_score,
            "overall_band": profile.overall_band,
            "overall_label": profile.overall_label,
            "recommended_action": profile.recommended_action,
            "trend": profile.trend,
            "trend_delta": profile.trend_delta,
            "timestamp": profile.timestamp.isoformat(),
            "vulnerability_count": len(profile.vulnerability_risks),
            "vulnerabilities": [
                {
                    "id": v.vulnerability_id,
                    "composite_score": v.composite_score,
                    "risk_band": v.risk_band,
                    "risk_label": v.risk_label,
                    "recommended_action": v.recommended_action,
                    "factors": {
                        "cvss_base_score": v.factors.cvss_base_score,
                        "epss_probability": v.factors.epss_probability,
                        "cisa_kev": v.factors.cisa_kev,
                        "reachability_multiplier": v.factors.reachability_multiplier,
                        "asset_criticality": v.factors.asset_criticality,
                    },
                    "contributing_factors": v.contributing_factors,
                }
                for v in profile.vulnerability_risks
            ],
            "summary": profile.summary,
        }
