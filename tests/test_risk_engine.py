"""
Tests for CodeShield AI Risk Scoring Engine.

Tests the composite risk scoring with CVSS, EPSS, CISA KEV, and asset criticality.
"""

import asyncio
import os
import sys
from datetime import datetime

# Ensure backend is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from models.vulnerability import ScanResult, Vulnerability

from risk_engine import (
    RiskEngine,
    RiskFactors,
    RISK_BANDS,
    ScanRiskProfile,
    VulnerabilityRisk,
)


def create_test_scan(severity_counts=None):
    """Create a test ScanResult."""
    severity_counts = severity_counts or {"critical": 2, "high": 3, "medium": 4, "low": 2, "info": 1}
    vulns = []

    for sev, count in severity_counts.items():
        for i in range(count):
            vulns.append(
                Vulnerability(
                    scan_id="test-scan",
                    file_path=f"src/file_{sev}_{i}.py",
                    line_number=i + 1,
                    severity=sev.upper(),
                    category="Test Vulnerability",
                    cwe_id="CWE-89",
                    title=f"Test {sev} vulnerability {i}",
                    description=f"Test {sev} description",
                    tool_source="bandit" if i % 2 == 0 else "custom_ai",
                    cvss_score={"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.0, "info": 0.0}[sev],
                    owasp_category="A03",
                    confidence="HIGH",
                )
            )

    stats = {
        "total": sum(severity_counts.values()),
        **{k: v for k, v in severity_counts.items()},
    }

    return ScanResult(
        scan_id="test-scan",
        name="Test Scan",
        source_type="zip",
        source_path="/tmp/test",
        status="completed",
        vulnerabilities=vulns,
        stats=stats,
        risk_score=42,
    )


class TestRiskFactors:
    """Tests for RiskFactors dataclass."""

    def test_default_values(self):
        """Test RiskFactors default values."""
        factors = RiskFactors()
        assert factors.cvss_base_score == 0.0
        assert factors.epss_probability == 0.0
        assert factors.cisa_kev is False
        assert factors.reachability_multiplier == 1.0
        assert factors.asset_criticality == 1.0

    def test_custom_values(self):
        """Test RiskFactors with custom values."""
        factors = RiskFactors(
            cvss_base_score=0.75,
            epss_probability=0.5,
            cisa_kev=True,
            reachability_multiplier=1.5,
            asset_criticality=2.0,
        )
        assert factors.cvss_base_score == 0.75
        assert factors.epss_probability == 0.5
        assert factors.cisa_kev is True
        assert factors.reachability_multiplier == 1.5
        assert factors.asset_criticality == 2.0


class TestRiskBands:
    """Tests for risk band definitions."""

    def test_risk_bands_structure(self):
        """Test that risk bands are properly defined."""
        assert len(RISK_BANDS) > 0
        for (low, high), info in RISK_BANDS.items():
            assert "label" in info
            assert "action" in info
            assert low < high


class TestRiskEngine:
    """Tests for the RiskEngine class."""

    def test_engine_initialization(self):
        """Test RiskEngine initialization."""
        engine = RiskEngine()
        assert engine is not None

    def test_severity_to_cvss_ratio(self):
        """Test severity to CVSS ratio conversion."""
        assert RiskEngine._severity_to_cvss_ratio("CRITICAL") > 0.9
        assert RiskEngine._severity_to_cvss_ratio("HIGH") > 0.7
        assert RiskEngine._severity_to_cvss_ratio("MEDIUM") > 0.4
        assert RiskEngine._severity_to_cvss_ratio("LOW") > 0.1
        assert RiskEngine._severity_to_cvss_ratio("INFO") < 0.1

    def test_get_risk_band(self):
        """Test risk band determination."""
        band, label, action = RiskEngine._get_risk_band(5)
        assert label == "Minimal"

        band, label, action = RiskEngine._get_risk_band(50)
        assert label == "High"

        band, label, action = RiskEngine._get_risk_band(85)
        assert label in ("Critical", "Severe")

    @pytest.mark.asyncio
    async def test_calculate_scan_risk(self):
        """Test scan risk calculation."""
        engine = RiskEngine()
        scan = create_test_scan()

        profile = await engine.calculate_scan_risk(scan)

        assert isinstance(profile, ScanRiskProfile)
        assert profile.scan_id == "test-scan"
        assert 0 <= profile.overall_score <= 100
        assert profile.overall_band is not None
        assert profile.overall_label is not None
        assert len(profile.vulnerability_risks) > 0

    @pytest.mark.asyncio
    async def test_calculate_scan_risk_with_trend(self):
        """Test scan risk calculation with previous scan."""
        engine = RiskEngine()
        current = create_test_scan({"critical": 3, "high": 2, "medium": 1, "low": 0, "info": 0})
        previous = create_test_scan({"critical": 1, "high": 1, "medium": 1, "low": 0, "info": 0})
        previous.risk_score = 20

        profile = await engine.calculate_scan_risk(current, previous_scan=previous)

        assert profile.trend is not None
        assert profile.trend_delta > 0

    @pytest.mark.asyncio
    async def test_empty_scan(self):
        """Test risk calculation for scan with no vulnerabilities."""
        engine = RiskEngine()
        scan = create_test_scan({"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0})

        profile = await engine.calculate_scan_risk(scan)

        assert profile.overall_score == 0.0
        assert profile.overall_label in ("Minimal", "No Risk")

    def test_to_dict(self):
        """Test conversion to dictionary."""
        engine = RiskEngine()
        scan = create_test_scan()

        profile = asyncio.run(engine.calculate_scan_risk(scan))
        data = engine.to_dict(profile)

        assert isinstance(data, dict)
        assert "scan_id" in data
        assert "overall_score" in data
        assert "overall_band" in data
        assert "overall_label" in data
        assert "recommended_action" in data
        assert "vulnerability_count" in data
        assert "vulnerabilities" in data

    @pytest.mark.asyncio
    async def test_asset_criticality(self):
        """Test asset criticality weighting."""
        engine = RiskEngine()
        scan = create_test_scan({"critical": 1, "high": 0, "medium": 0, "low": 0, "info": 0})

        profile_low = await engine.calculate_scan_risk(scan, asset_criticality="low")
        profile_high = await engine.calculate_scan_risk(scan, asset_criticality="critical")

        assert profile_high.overall_score >= profile_low.overall_score

    @pytest.mark.asyncio
    async def test_vulnerability_risk_structure(self):
        """Test individual vulnerability risk structure."""
        engine = RiskEngine()
        scan = create_test_scan()

        profile = await engine.calculate_scan_risk(scan)

        for vr in profile.vulnerability_risks:
            assert 0 <= vr.composite_score <= 100
            assert vr.risk_band is not None
            assert vr.risk_label is not None
            assert vr.recommended_action is not None
            assert vr.factors is not None
            assert len(vr.contributing_factors) > 0


class TestRiskEngineCaching:
    """Tests for EPSS/KEV caching behavior."""

    def test_cache_initially_empty(self):
        """Test that caches start empty."""
        engine = RiskEngine()
        assert len(engine._epss_cache) == 0
        assert len(engine._kev_cache) == 0
