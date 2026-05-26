"""
Tests for compliance.frameworks module.
"""

import pytest

from compliance.frameworks import (
    ComplianceFrameworkRegistry, ControlStatus,
    get_framework_registry,
)


class TestComplianceFrameworkRegistry:
    def setup_method(self):
        self.registry = ComplianceFrameworkRegistry()

    def test_all_frameworks_registered(self):
        frameworks = self.registry.list_frameworks()
        assert len(frameworks) == 7
        ids = {f.id for f in frameworks}
        assert "soc2_type2" in ids
        assert "iso27001_2022" in ids
        assert "gdpr" in ids
        assert "pci_dss_4" in ids
        assert "eu_cra" in ids
        assert "nist_ssdf" in ids
        assert "owasp_asvs" in ids

    def test_get_soc2(self):
        fw = self.registry.get_framework("soc2_type2")
        assert fw is not None
        assert fw.name == "SOC 2 Type II"
        assert len(fw.controls) == 2
        # Check CC7.1 control
        cc71 = self.registry.get_control("soc2_type2", "soc2-cc7.1")
        assert cc71 is not None
        assert cc71.control_reference == "CC7.1"

    def test_get_iso27001(self):
        fw = self.registry.get_framework("iso27001_2022")
        assert fw is not None
        assert fw.name == "ISO/IEC 27001:2022"
        assert len(fw.controls) == 3
        a88 = self.registry.get_control("iso27001_2022", "iso-a.8.8")
        assert a88 is not None
        assert "Management of Technical Vulnerabilities" in a88.name

    def test_get_gdpr(self):
        fw = self.registry.get_framework("gdpr")
        assert fw is not None
        assert "GDPR" in fw.name
        assert len(fw.controls) == 1

    def test_get_pci_dss(self):
        fw = self.registry.get_framework("pci_dss_4")
        assert fw is not None
        assert "PCI DSS 4.0" in fw.name
        assert len(fw.controls) == 3

    def test_get_eu_cra(self):
        fw = self.registry.get_framework("eu_cra")
        assert fw is not None
        assert "EU Cyber Resilience Act" in fw.name
        assert len(fw.controls) == 3

    def test_get_nist_ssdf(self):
        fw = self.registry.get_framework("nist_ssdf")
        assert fw is not None
        assert "NIST SSDF" in fw.name
        assert len(fw.controls) == 2

    def test_get_owasp_asvs(self):
        fw = self.registry.get_framework("owasp_asvs")
        assert fw is not None
        assert "OWASP ASVS" in fw.name
        assert len(fw.controls) >= 5

    def test_get_unknown_framework(self):
        fw = self.registry.get_framework("nonexistent")
        assert fw is None

    def test_framework_to_dict(self):
        fw = self.registry.get_framework("soc2_type2")
        data = fw.to_dict()
        assert "id" in data
        assert "name" in data
        assert "controls" in data
        assert "compliance_percentage" in data

    def test_list_framework_ids(self):
        ids = self.registry.list_framework_ids()
        assert len(ids) == 7

    def test_region_filtering(self):
        eu_frameworks = self.registry.get_frameworks_for_region("eu")
        ids = {f.id for f in eu_frameworks}
        assert "gdpr" in ids
        assert "eu_cra" in ids

    def test_industry_filtering(self):
        payment_frameworks = self.registry.get_frameworks_for_industry("payments")
        ids = {f.id for f in payment_frameworks}
        assert "pci_dss_4" in ids

    def test_singleton(self):
        r1 = get_framework_registry()
        r2 = get_framework_registry()
        assert r1 is r2
