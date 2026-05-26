"""
Enterprise Compliance Framework Definitions

Defines security compliance frameworks with their controls, requirements,
and mappings to CodeShield AI scanning capabilities.

Supported frameworks:
- SOC 2 Type II (CC7.1, CC7.2)
- ISO 27001:2022 (A.8.8, A.8.9, A.8.15)
- GDPR Article 32(1)(d)
- PCI DSS 4.0 (Req 6.3.2, 6.4.1, 11.3.1.2)
- EU Cyber Resilience Act
- NIST SSDF (PO.4.1, PO.4.2)
- OWASP ASVS (Level 1/2/3)
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class ControlStatus(str, Enum):
    """Status of a compliance control."""
    COMPLIANT = "compliant"
    PARTIAL = "partial"
    NON_COMPLIANT = "non_compliant"
    NOT_APPLICABLE = "not_applicable"
    UNKNOWN = "unknown"


class ComplianceControl(BaseModel):
    """A single control within a compliance framework."""
    id: str
    framework_id: str
    name: str
    description: str
    control_reference: str
    category: str
    requirements: List[str] = Field(default_factory=list)
    scanner_capabilities: List[str] = Field(default_factory=list)
    required_evidence: List[str] = Field(default_factory=list)
    asvs_levels: List[int] = Field(default_factory=list)
    status: str = ControlStatus.UNKNOWN.value
    last_evaluated: Optional[datetime] = None
    evidence_count: int = 0
    notes: Optional[str] = None
    auto_verifiable: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class ComplianceFramework(BaseModel):
    """A compliance framework containing multiple controls."""
    id: str
    name: str
    version: str
    description: str
    category: str
    controls: List[ComplianceControl] = Field(default_factory=list)
    document_url: Optional[str] = None
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    compliance_percentage: float = 0.0
    total_controls: int = 0
    compliant_controls: int = 0
    region_scope: List[str] = Field(default_factory=list)
    applicable_industries: List[str] = Field(default_factory=list)

    def compute_compliance(self) -> None:
        """Recalculate compliance percentage from control statuses."""
        applicable = [c for c in self.controls
                      if c.status != ControlStatus.NOT_APPLICABLE.value]
        if not applicable:
            self.compliance_percentage = 0.0
            self.compliant_controls = 0
            self.total_controls = len(self.controls)
            return
        compliant = [c for c in applicable
                     if c.status == ControlStatus.COMPLIANT.value]
        self.compliant_controls = len(compliant)
        self.total_controls = len(applicable)
        self.compliance_percentage = (len(compliant) / len(applicable)) * 100

    def to_dict(self) -> Dict[str, Any]:
        self.compute_compliance()
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "category": self.category,
            "compliance_percentage": round(self.compliance_percentage, 1),
            "total_controls": self.total_controls,
            "compliant_controls": self.compliant_controls,
            "document_url": self.document_url,
            "region_scope": self.region_scope,
            "applicable_industries": self.applicable_industries,
            "last_updated": self.last_updated.isoformat(),
            "controls": [c.to_dict() for c in self.controls],
        }


class ComplianceFrameworkRegistry:
    """Registry of all supported compliance frameworks."""

    def __init__(self) -> None:
        self._frameworks: Dict[str, ComplianceFramework] = {}
        self._register_all_frameworks()

    def _register_all_frameworks(self) -> None:
        for framework in [
            self._build_soc2_type2(),
            self._build_iso27001_2022(),
            self._build_gdpr(),
            self._build_pci_dss_4(),
            self._build_eu_cra(),
            self._build_nist_ssdf(),
            self._build_owasp_asvs(),
        ]:
            self._frameworks[framework.id] = framework

    # -- SOC 2 Type II --
    def _build_soc2_type2(self) -> ComplianceFramework:
        controls = [
            ComplianceControl(
                id="soc2-cc7.1", framework_id="soc2_type2",
                name="Detection of Security Events",
                description="To detect security events, entity identifies and assesses "
                            "changes that could affect the system's ability to meet its objectives.",
                control_reference="CC7.1", category="System Operations",
                requirements=["Deploy detection policies and tools",
                              "Monitor systems for anomalies",
                              "Evaluate security events"],
                scanner_capabilities=["Static code analysis for security vulnerabilities",
                                      "Automated detection of insecure code patterns",
                                      "Secret detection in source code"],
                required_evidence=["Scan reports showing vulnerability detection",
                                   "Scan frequency documentation",
                                   "Tool configuration records"],
            ),
            ComplianceControl(
                id="soc2-cc7.2", framework_id="soc2_type2",
                name="Incident Response and Remediation",
                description="Security incidents are identified, analyzed, and remediated "
                            "in a timely manner.",
                control_reference="CC7.2", category="System Operations",
                requirements=["Identify security incidents",
                              "Analyze root cause of incidents",
                              "Remediate vulnerabilities promptly",
                              "Document incident response"],
                scanner_capabilities=["Vulnerability prioritization",
                                      "SLA tracking for remediation",
                                      "Remediation status monitoring",
                                      "Audit trail of vulnerability lifecycle"],
                required_evidence=["Vulnerability remediation records",
                                   "SLA compliance reports",
                                   "Mean time to remediate (MTTR) metrics"],
            ),
        ]
        return ComplianceFramework(
            id="soc2_type2",
            name="SOC 2 Type II",
            version="2017",
            description="Service Organization Control 2 Type II - Trust Services Criteria "
                        "for security, availability, processing integrity, confidentiality, and privacy.",
            category="security",
            controls=controls,
            document_url="https://www.aicpa.org/cpe-learning/courses/audit-data-analytics.html",
            region_scope=["global", "us"],
            applicable_industries=["saas", "technology", "finance", "healthcare"],
        )

    # -- ISO 27001:2022 --
    def _build_iso27001_2022(self) -> ComplianceFramework:
        controls = [
            ComplianceControl(
                id="iso-a.8.8", framework_id="iso27001_2022",
                name="Management of Technical Vulnerabilities",
                description="Information about technical vulnerabilities of information systems "
                            "being used shall be obtained in a timely fashion, the organization's "
                            "exposure to such vulnerabilities shall be evaluated and appropriate "
                            "measures taken to address the associated risk.",
                control_reference="A.8.8", category="Technological Controls",
                requirements=["Obtain vulnerability information timely",
                              "Evaluate exposure to vulnerabilities",
                              "Take appropriate measures to address risk"],
                scanner_capabilities=["Automated vulnerability scanning",
                                      "CVE database integration",
                                      "Vulnerability severity assessment",
                                      "Dependency vulnerability detection"],
                required_evidence=["Scan schedules and results",
                                   "Vulnerability assessment reports",
                                   "Remediation action records",
                                   "CVE reference documentation"],
            ),
            ComplianceControl(
                id="iso-a.8.9", framework_id="iso27001_2022",
                name="Configuration Management",
                description="Configurations of hardware, software, services and networks "
                            "shall be established, documented, implemented and monitored.",
                control_reference="A.8.9", category="Technological Controls",
                requirements=["Establish configurations",
                              "Document configurations",
                              "Implement configuration baselines",
                              "Monitor for configuration drift"],
                scanner_capabilities=["Detection of insecure configurations in code",
                                      "Security policy enforcement",
                                      "Baseline configuration validation"],
                required_evidence=["Configuration baselines",
                                   "Scan reports showing configuration compliance",
                                   "Policy violation records"],
            ),
            ComplianceControl(
                id="iso-a.8.15", framework_id="iso27001_2022",
                name="Logging",
                description="Logs that record activities, exceptions, faults and other relevant "
                            "events shall be produced, stored, protected and analyzed.",
                control_reference="A.8.15", category="Technological Controls",
                requirements=["Produce activity logs",
                              "Store logs securely",
                              "Protect log integrity",
                              "Analyze logs for security events"],
                scanner_capabilities=["Audit trail generation",
                                      "Tamper-resistant logging with hash chains",
                                      "Security event logging"],
                required_evidence=["Audit log records",
                                   "Log integrity verification",
                                   "Log analysis reports"],
            ),
        ]
        return ComplianceFramework(
            id="iso27001_2022",
            name="ISO/IEC 27001:2022",
            version="2022",
            description="International standard for information security management systems (ISMS).",
            category="security",
            controls=controls,
            document_url="https://www.iso.org/standard/27001",
            region_scope=["global"],
            applicable_industries=["all"],
        )

    # -- GDPR Article 32(1)(d) --
    def _build_gdpr(self) -> ComplianceFramework:
        controls = [
            ComplianceControl(
                id="gdpr-32.1.d", framework_id="gdpr",
                name="Regular Security Testing",
                description="A process for regularly testing, assessing and evaluating the "
                            "effectiveness of technical and organisational measures for ensuring "
                            "the security of the processing.",
                control_reference="Article 32(1)(d)", category="Data Protection",
                requirements=["Regular security testing process",
                              "Assessment of security measures",
                              "Evaluation of measure effectiveness",
                              "Documented test results"],
                scanner_capabilities=["Automated security testing of code",
                                      "Regular scheduled scanning",
                                      "Security posture assessment",
                                      "Compliance reporting with evidence"],
                required_evidence=["Security test schedules",
                                   "Vulnerability scan results",
                                   "Remediation evidence",
                                   "Security assessment reports"],
                region_scope=["eu", "global"],
            ),
        ]
        return ComplianceFramework(
            id="gdpr",
            name="GDPR Article 32",
            version="2016",
            description="General Data Protection Regulation - Security of processing requirements.",
            category="privacy",
            controls=controls,
            document_url="https://gdpr.eu/article-32-security-of-processing/",
            region_scope=["eu", "global"],
            applicable_industries=["all"],
        )

    # -- PCI DSS 4.0 --
    def _build_pci_dss_4(self) -> ComplianceFramework:
        controls = [
            ComplianceControl(
                id="pci-6.3.2", framework_id="pci_dss_4",
                name="Software Security Patches",
                description="Software security patches are installed within a timely manner "
                            "to protect system components from known vulnerabilities.",
                control_reference="Req 6.3.2", category="Secure Development",
                requirements=["Identify security patches",
                              "Install patches within defined timeframe",
                              "Document patch management process"],
                scanner_capabilities=["Dependency vulnerability scanning (SCA)",
                                      "CVE-based vulnerability detection",
                                      "Outdated dependency identification"],
                required_evidence=["Dependency scan reports",
                                   "CVE lists and severity ratings",
                                   "Patch timeline documentation"],
            ),
            ComplianceControl(
                id="pci-6.4.1", framework_id="pci_dss_4",
                name="Authorized Software Changes",
                description="Changes to all system components in the production environment "
                            "are made according to established procedures.",
                control_reference="Req 6.4.1", category="Secure Development",
                requirements=["Establish change control procedures",
                              "Authorize changes before implementation",
                              "Document all changes"],
                scanner_capabilities=["Pre-commit security scanning",
                                      "Policy enforcement on code changes",
                                      "Audit trail of security reviews"],
                required_evidence=["Change control records",
                                   "Pre-deployment scan results",
                                   "Security review documentation"],
            ),
            ComplianceControl(
                id="pci-11.3.1.2", framework_id="pci_dss_4",
                name="Authenticated Scanning",
                description="Vulnerability scans are performed with authentication "
                            "to achieve comprehensive coverage.",
                control_reference="Req 11.3.1.2", category="Vulnerability Management",
                requirements=["Perform authenticated vulnerability scans",
                              "Scan coverage of all system components",
                              "Re-scan after remediation"],
                scanner_capabilities=["Deep source code analysis (authenticated to codebase)",
                                      "Comprehensive file and function coverage",
                                      "Re-scan after fix verification"],
                required_evidence=["Authenticated scan reports",
                                   "Scan coverage metrics",
                                   "Re-scan verification results"],
            ),
        ]
        return ComplianceFramework(
            id="pci_dss_4",
            name="PCI DSS 4.0",
            version="4.0",
            description="Payment Card Industry Data Security Standard - Requirements for "
                        "entities that store, process, or transmit cardholder data.",
            category="industry",
            controls=controls,
            document_url="https://www.pcisecuritystandards.org/document_library",
            region_scope=["global"],
            applicable_industries=["payments", "finance", "ecommerce", "retail"],
        )

    # -- EU Cyber Resilience Act --
    def _build_eu_cra(self) -> ComplianceFramework:
        controls = [
            ComplianceControl(
                id="cra-sbom", framework_id="eu_cra",
                name="SBOM Generation",
                description="Products with digital elements must have a Software Bill of Materials "
                            "documenting software components and dependencies.",
                control_reference="CRA-Article 13", category="Product Security",
                requirements=["Generate and maintain SBOM",
                              "Document all software components",
                              "Track dependency versions"],
                scanner_capabilities=["Dependency analysis and SBOM generation",
                                      "Software composition analysis",
                                      "License and vulnerability correlation"],
                required_evidence=["SBOM documents",
                                   "Dependency inventory",
                                   "Component tracking records"],
                region_scope=["eu"],
            ),
            ComplianceControl(
                id="cra-disclosure", framework_id="eu_cra",
                name="Vulnerability Disclosure",
                description="Manufacturers must report actively exploited vulnerabilities "
                            "and severe incidents having impact on security.",
                control_reference="CRA-Article 14", category="Product Security",
                requirements=["Vulnerability disclosure process",
                              "Timely reporting of vulnerabilities",
                              "Coordinated vulnerability response"],
                scanner_capabilities=["Vulnerability detection and reporting",
                                      "Severity classification",
                                      "Automated vulnerability notifications"],
                required_evidence=["Vulnerability disclosure reports",
                                   "Detection and classification records",
                                   "Response timeline documentation"],
                region_scope=["eu"],
            ),
            ComplianceControl(
                id="cra-updates", framework_id="eu_cra",
                name="Security Updates",
                description="Manufacturers must provide security updates to address "
                            "vulnerabilities in products with digital elements.",
                control_reference="CRA-Article 15", category="Product Security",
                requirements=["Provide security updates",
                              "Address known vulnerabilities",
                              "Update notification process"],
                scanner_capabilities=["Vulnerability tracking across releases",
                                      "SLA monitoring for security fixes",
                                      "Fix verification scanning"],
                required_evidence=["Security update release records",
                                   "Vulnerability remediation timelines",
                                   "Update delivery confirmation"],
                region_scope=["eu"],
            ),
        ]
        return ComplianceFramework(
            id="eu_cra",
            name="EU Cyber Resilience Act",
            version="2024",
            description="European Union regulation on cybersecurity requirements for products "
                        "with digital elements.",
            category="regulatory",
            controls=controls,
            document_url="https://digital-strategy.ec.europa.eu/en/policies/cyber-resilience-act",
            region_scope=["eu"],
            applicable_industries=["technology", "manufacturing", "software", "iot"],
        )

    # -- NIST SSDF --
    def _build_nist_ssdf(self) -> ComplianceFramework:
        controls = [
            ComplianceControl(
                id="ssdf-po.4.1", framework_id="nist_ssdf",
                name="Software Security Reviews",
                description="The organization reviews software to confirm that the software "
                            "meets the security requirements.",
                control_reference="PO.4.1", category="Organize",
                requirements=["Define security review criteria",
                              "Conduct security reviews",
                              "Document review findings",
                              "Address identified issues"],
                scanner_capabilities=["Automated security code review (SAST)",
                                      "Security requirement validation",
                                      "Review finding documentation"],
                required_evidence=["Security review reports",
                                   "SAST scan results",
                                   "Issue tracking and remediation records"],
            ),
            ComplianceControl(
                id="ssdf-po.4.2", framework_id="nist_ssdf",
                name="Vulnerability Identification",
                description="The organization identifies and evaluates vulnerabilities "
                            "in the software and its dependencies.",
                control_reference="PO.4.2", category="Organize",
                requirements=["Identify software vulnerabilities",
                              "Evaluate vulnerability severity",
                              "Track vulnerabilities to resolution",
                              "Assess vulnerability impact"],
                scanner_capabilities=["Static application security testing",
                                      "Software composition analysis (SCA)",
                                      "Vulnerability severity scoring (CVSS)",
                                      "Vulnerability lifecycle tracking"],
                required_evidence=["Vulnerability scan reports",
                                   "CVSS scoring records",
                                   "Vulnerability tracking logs",
                                   "Resolution confirmation scans"],
            ),
        ]
        return ComplianceFramework(
            id="nist_ssdf",
            name="NIST SSDF",
            version="1.1",
            description="NIST Secure Software Development Framework - Recommendations for "
                        "mitigating the risk of software vulnerabilities.",
            category="security",
            controls=controls,
            document_url="https://csrc.nist.gov/projects/ssdf",
            region_scope=["global", "us"],
            applicable_industries=["all"],
        )

    # -- OWASP ASVS --
    def _build_owasp_asvs(self) -> ComplianceFramework:
        controls = [
            ComplianceControl(
                id="asvs-1.1.1", framework_id="owasp_asvs",
                name="Secure Development Lifecycle",
                description="Verify the use of a secure software development lifecycle "
                            "that addresses security at all stages.",
                control_reference="V1.1.1", category="Architecture",
                requirements=["Establish SDL process",
                              "Integrate security at all stages",
                              "Document security activities"],
                scanner_capabilities=["Automated SAST integration into CI/CD",
                                      "Security gate enforcement",
                                      "Scan result documentation"],
                required_evidence=["SDL documentation",
                                   "CI/CD security integration records",
                                   "Security scan reports"],
                asvs_levels=[1, 2, 3],
            ),
            ComplianceControl(
                id="asvs-1.1.2", framework_id="owasp_asvs",
                name="Security Requirements",
                description="Verify that security requirements are defined and "
                            "documented for the application.",
                control_reference="V1.1.2", category="Architecture",
                requirements=["Define security requirements",
                              "Document security requirements",
                              "Validate requirements implementation"],
                scanner_capabilities=["Security requirement verification through scanning",
                                      "Policy-based requirement checking"],
                required_evidence=["Security requirements document",
                                   "Requirement validation scan results"],
                asvs_levels=[2, 3],
            ),
            ComplianceControl(
                id="asvs-5.1.1", framework_id="owasp_asvs",
                name="Input Validation",
                description="Verify that the application has defenses against HTTP parameter "
                            "pollution attacks, and that the application checks for input "
                            "validation on the server side.",
                control_reference="V5.1.1", category="Validation",
                requirements=["Validate all inputs",
                              "Server-side validation",
                              "Defense against injection attacks"],
                scanner_capabilities=["Injection vulnerability detection (SQL, XSS, command)",
                                      "Input validation pattern analysis",
                                      "Server-side code analysis"],
                required_evidence=["Injection scan results",
                                   "Input validation code review findings"],
                asvs_levels=[1, 2, 3],
            ),
            ComplianceControl(
                id="asvs-5.3.1", framework_id="owasp_asvs",
                name="Output Encoding",
                description="Verify that output encoding is relevant for the interpreter "
                            "and context required.",
                control_reference="V5.3.1", category="Validation",
                requirements=["Context-appropriate output encoding",
                              "XSS prevention measures"],
                scanner_capabilities=["XSS vulnerability detection",
                                      "Output encoding pattern analysis"],
                required_evidence=["XSS scan results",
                                   "Encoding implementation review"],
                asvs_levels=[1, 2, 3],
            ),
            ComplianceControl(
                id="asvs-6.1.1", framework_id="owasp_asvs",
                name="Cryptographic Protection",
                description="Verify that all cryptographic modules fail securely."
                            "Use strong, industry-standard algorithms.",
                control_reference="V6.1.1", category="Cryptography",
                requirements=["Use strong cryptographic algorithms",
                              "Implement crypto correctly",
                              "Avoid deprecated algorithms"],
                scanner_capabilities=["Weak cryptography detection",
                                      "Deprecated algorithm identification",
                                      "Secure implementation validation"],
                required_evidence=["Cryptographic scan results",
                                   "Algorithm usage reports"],
                asvs_levels=[1, 2, 3],
            ),
            ComplianceControl(
                id="asvs-10.1.1", framework_id="owasp_asvs",
                name="Secure Communications",
                description="Verify that the application uses TLS 1.2 or higher "
                            "for all network communications.",
                control_reference="V10.1.1", category="Communication",
                requirements=["Use TLS 1.2+",
                              "Proper certificate validation",
                              "No insecure protocol fallback"],
                scanner_capabilities=["Insecure protocol detection",
                                      "TLS configuration analysis in code"],
                required_evidence=["Protocol scan results"],
                asvs_levels=[1, 2, 3],
            ),
            ComplianceControl(
                id="asvs-14.1.1", framework_id="owasp_asvs",
                name="Build and Deploy Security",
                description="Verify that the application build and deployment processes "
                            "are performed in a secure and repeatable way.",
                control_reference="V14.1.1", category="Configuration",
                requirements=["Secure build process",
                              "Dependency verification",
                              "Deployment security"],
                scanner_capabilities=["Dependency vulnerability scanning",
                                      "Build configuration analysis"],
                required_evidence=["Build scan results",
                                   "Dependency audit reports"],
                asvs_levels=[2, 3],
            ),
        ]
        return ComplianceFramework(
            id="owasp_asvs",
            name="OWASP ASVS",
            version="4.0.3",
            description="OWASP Application Security Verification Standard - Framework for "
                        "defining security requirements for web applications.",
            category="security",
            controls=controls,
            document_url="https://owasp.org/www-project-application-security-verification-standard/",
            region_scope=["global"],
            applicable_industries=["technology", "software", "web"],
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def get_framework(self, framework_id: str) -> Optional[ComplianceFramework]:
        """Get a framework by ID."""
        return self._frameworks.get(framework_id)

    def list_frameworks(self) -> List[ComplianceFramework]:
        """List all registered frameworks."""
        return list(self._frameworks.values())

    def list_framework_ids(self) -> List[str]:
        """List all framework IDs."""
        return list(self._frameworks.keys())

    def get_control(self, framework_id: str, control_id: str) -> Optional[ComplianceControl]:
        """Get a specific control from a framework."""
        fw = self._frameworks.get(framework_id)
        if not fw:
            return None
        for ctrl in fw.controls:
            if ctrl.id == control_id:
                return ctrl
        return None

    def get_frameworks_for_region(self, region: str) -> List[ComplianceFramework]:
        """Get frameworks applicable to a region."""
        return [f for f in self._frameworks.values()
                if "global" in f.region_scope or region in f.region_scope]

    def get_frameworks_for_industry(self, industry: str) -> List[ComplianceFramework]:
        """Get frameworks applicable to an industry."""
        return [f for f in self._frameworks.values()
                if "all" in f.applicable_industries or industry in f.applicable_industries]

    def to_dict(self) -> Dict[str, Any]:
        """Export all frameworks as a dictionary."""
        return {
            "frameworks": [f.to_dict() for f in self._frameworks.values()],
            "total": len(self._frameworks),
        }


# Singleton instance
_framework_registry: Optional[ComplianceFrameworkRegistry] = None


def get_framework_registry() -> ComplianceFrameworkRegistry:
    """Get or create the global compliance framework registry."""
    global _framework_registry
    if _framework_registry is None:
        _framework_registry = ComplianceFrameworkRegistry()
    return _framework_registry
