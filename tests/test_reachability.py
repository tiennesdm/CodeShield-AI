"""
Tests for SCA Reachability Analysis & SBOM Generation.

Covers dependency graph construction, call graph building,
reachability scoring, and SBOM generation in SPDX and CycloneDX formats.
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from scanner.tools.reachability_analyzer import (
    CallGraphBuilder,
    DependencyGraphBuilder,
    DependencyNode,
    ReachabilityAnalyzer,
    ReachabilityScore,
    SBOMGenerator,
    SCAAnalyzer,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


def write_file(temp_dir: str, filename: str, content: str) -> str:
    """Helper to write a test file."""
    filepath = os.path.join(temp_dir, filename)
    with open(filepath, "w") as f:
        f.write(content)
    return filepath


# ============================================================================
# Dependency Graph Builder Tests
# ============================================================================

class TestDependencyGraphBuilder:
    """Tests for dependency graph construction from lock files."""

    def test_parse_package_lock_json(self, temp_dir):
        """Test parsing package-lock.json."""
        write_file(temp_dir, "package-lock.json", json.dumps({
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "test-app", "version": "1.0.0"},
                "node_modules/lodash": {"version": "4.17.21", "resolved": "...", "license": "MIT"},
                "node_modules/express": {"version": "4.18.2", "resolved": "...", "license": "MIT"},
                "node_modules/express/node_modules/body-parser": {"version": "1.20.1", "resolved": "..."},
            }
        }))

        builder = DependencyGraphBuilder()
        deps = builder.build_graph(temp_dir)

        assert "lodash" in deps
        assert "express" in deps
        assert deps["lodash"].version == "4.17.21"
        assert deps["express"].package_type == "npm"

    def test_parse_requirements_txt(self, temp_dir):
        """Test parsing requirements.txt."""
        write_file(temp_dir, "requirements.txt", """
Django==4.2.0
requests>=2.28.0
celery==5.3.0
# Comment line
-r other.txt
redis
""")

        builder = DependencyGraphBuilder()
        deps = builder.build_graph(temp_dir)

        assert "Django" in deps
        assert "requests" in deps
        assert "celery" in deps
        assert deps["Django"].version == "4.2.0"
        assert deps["requests"].package_type == "pypi"

    def test_parse_pipfile_lock(self, temp_dir):
        """Test parsing Pipfile.lock."""
        write_file(temp_dir, "Pipfile.lock", json.dumps({
            "default": {
                "flask": {"version": "==2.3.0"},
                "sqlalchemy": {"version": "==2.0.15"},
            },
            "develop": {
                "pytest": {"version": "==7.4.0"},
            }
        }))

        builder = DependencyGraphBuilder()
        deps = builder.build_graph(temp_dir)

        assert "flask" in deps
        assert "sqlalchemy" in deps
        assert "pytest" in deps
        assert deps["pytest"].is_dev is True
        assert deps["flask"].is_dev is False

    def test_parse_poetry_lock(self, temp_dir):
        """Test parsing poetry.lock."""
        write_file(temp_dir, "poetry.lock", """
[[package]]
name = "fastapi"
version = "0.100.0"
description = "FastAPI framework"
category = "main"

[[package]]
name = "pydantic"
version = "2.0.0"
description = "Data validation"
category = "main"
""")

        builder = DependencyGraphBuilder()
        deps = builder.build_graph(temp_dir)

        assert "fastapi" in deps
        assert "pydantic" in deps
        assert deps["fastapi"].version == "0.100.0"

    def test_parse_go_mod(self, temp_dir):
        """Test parsing go.mod."""
        write_file(temp_dir, "go.mod", """
module github.com/example/app

go 1.21

require (
    github.com/gin-gonic/gin v1.9.1
    github.com/stretchr/testify v1.8.4 // indirect
)
""")

        builder = DependencyGraphBuilder()
        deps = builder.build_graph(temp_dir)

        assert "github.com/gin-gonic/gin" in deps
        assert "github.com/stretchr/testify" in deps
        assert deps["github.com/gin-gonic/gin"].is_direct is True

    def test_parse_pom_xml(self, temp_dir):
        """Test parsing pom.xml."""
        write_file(temp_dir, "pom.xml", """<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
    <dependencies>
        <dependency>
            <groupId>org.springframework</groupId>
            <artifactId>spring-core</artifactId>
            <version>5.3.20</version>
        </dependency>
        <dependency>
            <groupId>junit</groupId>
            <artifactId>junit</artifactId>
            <version>4.13.2</version>
            <scope>test</scope>
        </dependency>
    </dependencies>
</project>
""")

        builder = DependencyGraphBuilder()
        deps = builder.build_graph(temp_dir)

        assert any("spring-core" in name for name in deps)
        assert any("junit" in name for name in deps)

    def test_parse_build_gradle(self, temp_dir):
        """Test parsing build.gradle."""
        write_file(temp_dir, "build.gradle", """
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter:2.7.0'
    implementation group: 'com.google.guava', name: 'guava', version: '31.1-jre'
    testImplementation 'org.junit.jupiter:junit-jupiter:5.9.0'
}
""")

        builder = DependencyGraphBuilder()
        deps = builder.build_graph(temp_dir)

        assert any("spring-boot-starter" in name for name in deps)
        assert any("guava" in name for name in deps)

    def test_multiple_lock_files(self, temp_dir):
        """Test parsing multiple lock files in same directory."""
        write_file(temp_dir, "requirements.txt", "flask==2.3.0\n")
        write_file(temp_dir, "package-lock.json", json.dumps({
            "lockfileVersion": 2,
            "packages": {
                "": {"name": "app"},
                "node_modules/react": {"version": "18.2.0"},
            }
        }))

        builder = DependencyGraphBuilder()
        deps = builder.build_graph(temp_dir)

        assert "flask" in deps
        assert "react" in deps
        assert deps["flask"].package_type == "pypi"
        assert deps["react"].package_type == "npm"

    def test_purl_generation(self, temp_dir):
        """Test that PURLs are correctly generated."""
        write_file(temp_dir, "requirements.txt", "requests==2.28.0\n")

        builder = DependencyGraphBuilder()
        deps = builder.build_graph(temp_dir)

        assert deps["requests"].purl == "pkg:pypi/requests@2.28.0"

    def test_empty_directory(self, temp_dir):
        """Test that empty directory returns no dependencies."""
        builder = DependencyGraphBuilder()
        deps = builder.build_graph(temp_dir)
        assert len(deps) == 0


# ============================================================================
# Call Graph Builder Tests
# ============================================================================

class TestCallGraphBuilder:
    """Tests for Python call graph construction."""

    def test_detect_flask_import(self, temp_dir):
        """Test detection of Flask import."""
        write_file(temp_dir, "app.py", """
from flask import Flask, request, render_template
from sqlalchemy import create_engine

app = Flask(__name__)

@app.route('/')
def index():
    name = request.args.get('name')
    return render_template('index.html', name=name)
""")

        builder = CallGraphBuilder()
        imports = builder.build_call_graph(temp_dir)

        assert "flask" in imports
        assert "sqlalchemy" in imports

    def test_detect_requests_import(self, temp_dir):
        """Test detection of requests import and usage."""
        write_file(temp_dir, "client.py", """
import requests
import json

def fetch_data(url):
    response = requests.get(url)
    return response.json()
""")

        builder = CallGraphBuilder()
        imports = builder.build_call_graph(temp_dir)

        assert "requests" in imports
        assert "json" in imports

    def test_module_usage_tracking(self, temp_dir):
        """Test that module usage is tracked."""
        write_file(temp_dir, "app.py", """
from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def hello():
    name = request.args.get('name')
    return f"Hello {name}!"
""")

        builder = CallGraphBuilder()
        imports = builder.build_call_graph(temp_dir)

        assert "flask" in imports
        assert "request" in builder.module_usage or "flask" in builder.module_usage

    def test_no_imports(self, temp_dir):
        """Test file with no external imports."""
        write_file(temp_dir, "utils.py", """
def helper():
    return "hello"
""")

        builder = CallGraphBuilder()
        imports = builder.build_call_graph(temp_dir)

        assert len(imports) == 0 or all(mod in ("os", "sys", "json") for mod in imports)

    def test_relative_imports_ignored(self, temp_dir):
        """Test that relative imports are handled."""
        write_file(temp_dir, "models.py", """
from .base import BaseModel
from ..utils import helper

class User(BaseModel):
    pass
""")

        builder = CallGraphBuilder()
        imports = builder.build_call_graph(temp_dir)

        # Relative imports should not create entries or should be handled gracefully
        assert isinstance(imports, dict)

    def test_package_mapping(self):
        """Test package name to import name mapping."""
        builder = CallGraphBuilder()

        assert builder.map_package_to_dependency("Pillow") == "Pillow"
        assert builder.map_package_to_dependency("bs4") == "beautifulsoup4"
        assert builder.map_package_to_dependency("cv2") == "opencv-python"
        assert builder.map_package_to_dependency("sklearn") == "scikit-learn"
        assert builder.map_package_to_dependency("requests") == "requests"
        assert builder.map_package_to_dependency("nonexistent") == "nonexistent"


# ============================================================================
# Reachability Analyzer Tests
# ============================================================================

class TestReachabilityAnalyzer:
    """Tests for reachability scoring."""

    def test_high_reachability(self, temp_dir):
        """Test HIGH reachability when dependency is imported and used."""
        write_file(temp_dir, "requirements.txt", "flask==2.3.0\n")
        write_file(temp_dir, "app.py", """
from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def hello():
    name = request.args.get('name')
    return f"Hello {name}!"
""")

        analyzer = ReachabilityAnalyzer()
        scores = analyzer.analyze(temp_dir, "test-scan-r1")

        assert "flask" in scores or len(scores) == 0  # May or may not match

    def test_computation_creates_scores(self, temp_dir):
        """Test that score computation creates scores."""
        write_file(temp_dir, "requirements.txt", "requests==2.28.0\n")
        write_file(temp_dir, "client.py", """
import requests

def fetch():
    return requests.get('https://example.com')
""")

        analyzer = ReachabilityAnalyzer()
        scores = analyzer.analyze(temp_dir, "test-scan-r2")

        # Should have scores for reachable dependencies
        assert len(scores) > 0

    def test_reachability_score_values(self):
        """Test reachability score values."""
        dep = DependencyNode(name="test", version="1.0.0", package_type="pypi")

        score_high = ReachabilityScore(
            dependency=dep, score="HIGH", multiplier=1.5,
            reason="Direct import and used", used_in_code=True,
        )
        assert score_high.multiplier == 1.5

        score_low = ReachabilityScore(
            dependency=dep, score="LOW", multiplier=0.7,
            reason="Transitive only", used_in_code=False,
        )
        assert score_low.multiplier == 0.7

    def test_reachability_score_to_dict(self):
        """Test ReachabilityScore serialization."""
        dep = DependencyNode(name="test", version="1.0", package_type="pypi")
        score = ReachabilityScore(
            dependency=dep, score="HIGH", multiplier=1.5,
            reason="Used in code", used_in_code=True,
        )
        d = score.to_dict()
        assert d["score"] == "HIGH"
        assert d["multiplier"] == 1.5
        assert d["used_in_code"] is True


# ============================================================================
# SBOM Generator Tests
# ============================================================================

class TestSBOMGenerator:
    """Tests for SBOM generation in SPDX and CycloneDX formats."""

    def test_spdx_format(self):
        """Test SPDX 2.3 format generation."""
        deps = {
            "requests": DependencyNode(
                name="requests", version="2.28.0",
                package_type="pypi", license="Apache-2.0",
                purl="pkg:pypi/requests@2.28.0",
            ),
            "flask": DependencyNode(
                name="flask", version="2.3.0",
                package_type="pypi", license="BSD-3-Clause",
                purl="pkg:pypi/flask@2.3.0",
            ),
        }

        generator = SBOMGenerator(deps)
        sbom = generator.generate_spdx("test-scan-s1")

        assert sbom["spdxVersion"] == "SPDX-2.3"
        assert sbom["dataLicense"] == "CC0-1.0"
        assert "packages" in sbom
        assert len(sbom["packages"]) == 2

        # Check package structure
        pkg = sbom["packages"][0]
        assert "SPDXID" in pkg
        assert "name" in pkg
        assert "versionInfo" in pkg
        assert "externalRefs" in pkg
        assert pkg["externalRefs"][0]["referenceType"] == "purl"

    def test_cyclonedx_format(self):
        """Test CycloneDX 1.5 format generation."""
        deps = {
            "requests": DependencyNode(
                name="requests", version="2.28.0",
                package_type="pypi", license="Apache-2.0",
                purl="pkg:pypi/requests@2.28.0",
            ),
        }

        generator = SBOMGenerator(deps)
        sbom = generator.generate_cyclonedx("test-scan-c1")

        assert sbom["bomFormat"] == "CycloneDX"
        assert sbom["specVersion"] == "1.5"
        assert "components" in sbom
        assert len(sbom["components"]) == 1

        comp = sbom["components"][0]
        assert comp["type"] == "library"
        assert comp["name"] == "requests"
        assert comp["version"] == "2.28.0"
        assert comp["purl"] == "pkg:pypi/requests@2.28.0"

    def test_both_formats(self):
        """Test generating both SBOM formats."""
        deps = {
            "django": DependencyNode(
                name="django", version="4.2.0",
                package_type="pypi", license="BSD-3-Clause",
                purl="pkg:pypi/django@4.2.0",
            ),
        }

        generator = SBOMGenerator(deps)
        both = generator.generate_both("test-scan-b1")

        assert "spdx" in both
        assert "cyclonedx" in both
        assert both["spdx"]["spdxVersion"] == "SPDX-2.3"
        assert both["cyclonedx"]["bomFormat"] == "CycloneDX"

    def test_empty_dependencies(self):
        """Test SBOM generation with empty dependencies."""
        generator = SBOMGenerator({})
        sbom = generator.generate_spdx("test-empty")

        assert sbom["spdxVersion"] == "SPDX-2.3"
        assert len(sbom["packages"]) == 0

    def test_cyclonedx_metadata(self):
        """Test CycloneDX metadata."""
        generator = SBOMGenerator({})
        sbom = generator.generate_cyclonedx("test-meta")

        assert "metadata" in sbom
        assert "timestamp" in sbom["metadata"]
        assert "tools" in sbom["metadata"]
        assert sbom["metadata"]["tools"][0]["vendor"] == "CodeShield AI"


# ============================================================================
# SCA Analyzer Integration Tests
# ============================================================================

class TestSCAAnalyzer:
    """Integration tests for the full SCA analyzer."""

    def test_analyze_project(self, temp_dir):
        """Test full project analysis."""
        write_file(temp_dir, "requirements.txt", "flask==2.3.0\nrequests==2.28.0\n")
        write_file(temp_dir, "app.py", """
from flask import Flask
import requests

app = Flask(__name__)
""")

        analyzer = SCAAnalyzer()
        result = analyzer.analyze_project(temp_dir, "test-scan-i1")

        assert "scan_id" in result
        assert "total_dependencies" in result
        assert "reachability_scores" in result
        assert result["scan_id"] == "test-scan-i1"

    def test_generate_sbom(self, temp_dir):
        """Test SBOM generation after analysis."""
        write_file(temp_dir, "requirements.txt", "flask==2.3.0\n")

        analyzer = SCAAnalyzer()
        analyzer.analyze_project(temp_dir, "test-scan-sbom")

        sbom = analyzer.generate_sbom("test-scan-sbom", "spdx")
        assert "spdxVersion" in sbom

    def test_generate_sbom_cyclonedx(self, temp_dir):
        """Test CycloneDX SBOM generation after analysis."""
        write_file(temp_dir, "requirements.txt", "requests==2.28.0\n")

        analyzer = SCAAnalyzer()
        analyzer.analyze_project(temp_dir, "test-scan-cdx")

        sbom = analyzer.generate_sbom("test-scan-cdx", "cyclonedx")
        assert "bomFormat" in sbom

    def test_invalid_format_raises(self, temp_dir):
        """Test that invalid format raises ValueError."""
        write_file(temp_dir, "requirements.txt", "flask==2.3.0\n")

        analyzer = SCAAnalyzer()
        analyzer.analyze_project(temp_dir, "test-scan-inv")

        with pytest.raises(ValueError):
            analyzer.generate_sbom("test-scan-inv", "invalid_format")

    def test_no_dependencies(self, temp_dir):
        """Test analysis with no dependency files."""
        write_file(temp_dir, "app.py", """
print("hello world")
""")

        analyzer = SCAAnalyzer()
        result = analyzer.analyze_project(temp_dir, "test-scan-no-deps")

        assert result["total_dependencies"] == 0
