"""
Tests for CodeShield AI OSV Scanner.

Tests OSV.dev API integration, dependency parsing, and vulnerability enrichment.
"""

import json
import os
import sys
import tempfile

# Ensure backend is importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import pytest

from scanner.tools.osv_scanner import (
    OSVScanner,
    DependencyInfo,
    OSVVulnerability,
)


class TestDependencyInfo:
    """Tests for DependencyInfo dataclass."""

    def test_create(self):
        """Test creating a DependencyInfo."""
        dep = DependencyInfo(
            name="django",
            version="3.2.0",
            ecosystem="PyPI",
            file_source="requirements.txt",
        )
        assert dep.name == "django"
        assert dep.version == "3.2.0"
        assert dep.ecosystem == "PyPI"
        assert dep.is_transitive is False

    def test_transitive(self):
        """Test creating a transitive dependency."""
        dep = DependencyInfo(
            name="requests",
            version="2.28.0",
            ecosystem="PyPI",
            file_source="requirements.txt",
            is_transitive=True,
            parent_package="django",
        )
        assert dep.is_transitive is True
        assert dep.parent_package == "django"


class TestOSVVulnerability:
    """Tests for OSVVulnerability dataclass."""

    def test_create(self):
        """Test creating an OSVVulnerability."""
        vuln = OSVVulnerability(
            osv_id="PYSEC-2023-1",
            summary="Test vulnerability",
            details="Test details",
            severity="HIGH",
            cve_ids=["CVE-2023-12345"],
            cvss_score=7.5,
        )
        assert vuln.osv_id == "PYSEC-2023-1"
        assert vuln.severity == "HIGH"
        assert vuln.cvss_score == 7.5
        assert len(vuln.cve_ids) == 1


class TestOSVScannerParsing:
    """Tests for dependency file parsing."""

    @pytest.fixture
    def scanner(self):
        return OSVScanner()

    def test_parse_requirements_txt(self, scanner, tmp_path):
        """Test parsing requirements.txt."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("""
django==3.2.0
requests>=2.28.0
numpy>=1.21.0
# This is a comment
pytest~=7.0.0
flask>=2.0.0,<3.0.0
""")
        deps = scanner._parse_requirements_txt(str(req_file))
        assert len(deps) >= 4
        names = {d.name for d in deps}
        assert "django" in names
        assert "requests" in names
        assert "numpy" in names
        assert "pytest" in names

    def test_parse_requirements_txt_no_version(self, scanner, tmp_path):
        """Test parsing requirements.txt without versions."""
        req_file = tmp_path / "requirements.txt"
        req_file.write_text("django\nrequests\n")
        deps = scanner._parse_requirements_txt(str(req_file))
        assert len(deps) == 2
        assert deps[0].name == "django"
        assert deps[1].name == "requests"

    def test_parse_go_mod(self, scanner, tmp_path):
        """Test parsing go.mod."""
        go_mod = tmp_path / "go.mod"
        go_mod.write_text("""
module example.com/app

go 1.20

require (
    github.com/gin-gonic/gin v1.9.0
    github.com/stretchr/testify v1.8.0
)
""")
        deps = scanner._parse_go_mod(str(go_mod))
        assert len(deps) >= 2

    def test_parse_cargo_lock(self, scanner, tmp_path):
        """Test parsing Cargo.lock."""
        cargo_lock = tmp_path / "Cargo.lock"
        cargo_lock.write_text("""
[[package]]
name = "serde"
version = "1.0.160"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "tokio"
version = "1.28.0"
source = "registry+https://github.com/rust-lang/crates.io-index"
""")
        deps = scanner._parse_cargo_lock(str(cargo_lock))
        assert len(deps) == 2
        assert deps[0].name == "serde"
        assert deps[1].name == "tokio"

    def test_parse_pipfile_lock(self, scanner, tmp_path):
        """Test parsing Pipfile.lock."""
        pipfile = tmp_path / "Pipfile.lock"
        pipfile.write_text(json.dumps({
            "default": {
                "django": {"version": "==3.2.0"},
                "requests": {"version": ">=2.28.0"}
            },
            "develop": {
                "pytest": {"version": "==7.0.0"}
            }
        }))
        deps = scanner._parse_pipfile_lock(str(pipfile))
        assert len(deps) >= 2

    def test_parse_poetry_lock(self, scanner, tmp_path):
        """Test parsing poetry.lock."""
        poetry_lock = tmp_path / "poetry.lock"
        poetry_lock.write_text("""
[[package]]
name = "django"
version = "3.2.0"

[[package]]
name = "requests"
version = "2.28.0"
""")
        deps = scanner._parse_poetry_lock(str(poetry_lock))
        assert len(deps) >= 2

    def test_parse_composer_lock(self, scanner, tmp_path):
        """Test parsing composer.lock."""
        composer_lock = tmp_path / "composer.lock"
        composer_lock.write_text(json.dumps({
            "packages": [
                {"name": "laravel/framework", "version": "v9.0.0"},
                {"name": "symfony/console", "version": "v6.0.0"}
            ]
        }))
        deps = scanner._parse_composer_lock(str(composer_lock))
        assert len(deps) == 2

    def test_find_dependency_files(self, scanner, tmp_path):
        """Test finding dependency files."""
        # Create various dependency files
        (tmp_path / "requirements.txt").write_text("django==3.2.0")
        (tmp_path / "package-lock.json").write_text('{"packages": {}}')
        (tmp_path / "go.mod").write_text("module test")
        (tmp_path / "pom.xml").write_text("<project><dependencies/></project>")
        (tmp_path / "build.gradle").write_text("dependencies {}")

        found = scanner._find_dependency_files(str(tmp_path))
        filenames = {os.path.basename(f) for f in found}

        assert "requirements.txt" in filenames
        assert "package-lock.json" in filenames
        assert "go.mod" in filenames
        assert "pom.xml" in filenames
        assert "build.gradle" in filenames

    def test_is_available(self, scanner):
        """Test that OSV scanner reports as available."""
        assert scanner.is_available() is True


class TestOSVScannerVulnerabilityParsing:
    """Tests for OSV vulnerability data parsing."""

    @pytest.fixture
    def scanner(self):
        return OSVScanner()

    def test_parse_osv_vulnerability(self, scanner):
        """Test parsing OSV vulnerability data."""
        data = {
            "id": "PYSEC-2023-1",
            "summary": "SQL Injection in Django",
            "details": "Detailed description here",
            "severity": [{"type": "CVSS_V3", "score": "7.5"}],
            "aliases": ["CVE-2023-12345"],
            "affected": [{"ranges": [{"events": [{"fixed": "4.0.0"}]}]}],
            "published": "2023-01-01T00:00:00Z",
            "modified": "2023-01-15T00:00:00Z",
            "references": [{"type": "FIX", "url": "https://example.com/fix"}],
        }

        vuln = scanner._parse_osv_vulnerability(data)
        assert vuln.osv_id == "PYSEC-2023-1"
        assert vuln.severity == "HIGH"
        assert len(vuln.fixed_versions) == 1
        assert vuln.fixed_versions[0] == "4.0.0"

    def test_cvss_to_severity(self, scanner):
        """Test CVSS score to severity conversion."""
        assert scanner._cvss_to_severity(9.5) == "CRITICAL"
        assert scanner._cvss_to_severity(7.5) == "HIGH"
        assert scanner._cvss_to_severity(5.5) == "MEDIUM"
        assert scanner._cvss_to_severity(2.0) == "LOW"
        assert scanner._cvss_to_severity(0.0) == "INFO"

    def test_convert_to_vulnerability(self, scanner):
        """Test converting OSV vulnerability to Vulnerability model."""
        osv_vuln = OSVVulnerability(
            osv_id="PYSEC-2023-1",
            summary="SQL Injection",
            details="Test details",
            severity="HIGH",
            cve_ids=["CVE-2023-12345"],
            cvss_score=7.5,
            fixed_versions=["4.0.0"],
        )
        dep = DependencyInfo(
            name="django",
            version="3.2.0",
            ecosystem="PyPI",
            file_source="requirements.txt",
        )

        vuln = scanner._convert_to_vulnerability(osv_vuln, dep, "test-scan", "/tmp")
        assert vuln is not None
        assert vuln.category == "Vulnerable Dependency"
        assert vuln.tool_source == "osv_scanner"
        assert vuln.cwe_id == "CWE-1104"
        assert vuln.owasp_category == "A06"
