"""
SCA Reachability Analysis & SBOM Generation for CodeShield AI.

Builds dependency graphs from various lock files, constructs call graphs
from Python source code, performs reachability scoring, and generates
SBOMs in SPDX 2.3 and CycloneDX 1.5 formats.

Supported lock files:
- package-lock.json (npm)
- requirements.txt (pip)
- Pipfile.lock (pipenv)
- poetry.lock (poetry)
- go.mod (Go modules)
- pom.xml (Maven)
- build.gradle (Gradle)

Reachability scoring:
- Direct import + used in code = HIGH (1.5x multiplier)
- Direct import + not used = MEDIUM (1.0x multiplier)
- Transitive dependency only = LOW (0.7x multiplier)
- Not reachable = INFORMATIONAL (0.3x multiplier)
"""

import ast
import hashlib
import json
import os
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

from utils.logger import get_logger

logger = get_logger(__name__)

# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class DependencyNode:
    """A single node in the dependency graph."""

    name: str
    version: str
    package_type: str  # npm, pypi, golang, maven, gradle
    is_direct: bool = True
    is_dev: bool = False
    license: str = "UNKNOWN"
    purl: str = ""
    checksum: str = ""
    children: List[str] = field(default_factory=list)  # names of transitive deps
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "package_type": self.package_type,
            "is_direct": self.is_direct,
            "is_dev": self.is_dev,
            "license": self.license,
            "purl": self.purl,
            "checksum": self.checksum,
            "children": self.children,
            "vulnerabilities": self.vulnerabilities,
        }


@dataclass
class ReachabilityScore:
    """Reachability score for a dependency."""

    dependency: DependencyNode
    score: str  # HIGH, MEDIUM, LOW, INFORMATIONAL
    multiplier: float
    reason: str
    imported_modules: List[str] = field(default_factory=list)
    used_in_code: bool = False
    file_references: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dependency": self.dependency.to_dict(),
            "score": self.score,
            "multiplier": self.multiplier,
            "reason": self.reason,
            "imported_modules": self.imported_modules,
            "used_in_code": self.used_in_code,
            "file_references": self.file_references,
        }


# ============================================================================
# Dependency Graph Builder
# ============================================================================

class DependencyGraphBuilder:
    """Builds dependency graphs from various lock files."""

    def __init__(self) -> None:
        self.dependencies: Dict[str, DependencyNode] = {}

    def build_graph(self, source_path: str) -> Dict[str, DependencyNode]:
        """
        Build dependency graph from all supported lock files in source path.

        Args:
            source_path: Path to the source directory

        Returns:
            Dictionary mapping package name to DependencyNode
        """
        self.dependencies = {}
        path = Path(source_path)

        # package-lock.json (npm)
        npm_lock = path / "package-lock.json"
        if npm_lock.exists():
            self._parse_package_lock(str(npm_lock))

        # requirements.txt (pip)
        req_file = path / "requirements.txt"
        if req_file.exists():
            self._parse_requirements_txt(str(req_file))

        # Pipfile.lock (pipenv)
        pipfile_lock = path / "Pipfile.lock"
        if pipfile_lock.exists():
            self._parse_pipfile_lock(str(pipfile_lock))

        # poetry.lock
        poetry_lock = path / "poetry.lock"
        if poetry_lock.exists():
            self._parse_poetry_lock(str(poetry_lock))

        # go.mod
        go_mod = path / "go.mod"
        if go_mod.exists():
            self._parse_go_mod(str(go_mod))

        # pom.xml (Maven)
        pom_file = path / "pom.xml"
        if pom_file.exists():
            self._parse_pom_xml(str(pom_file))

        # build.gradle
        gradle_file = path / "build.gradle"
        if gradle_file.exists():
            self._parse_build_gradle(str(gradle_file))

        return self.dependencies

    def _parse_package_lock(self, file_path: str) -> None:
        """Parse package-lock.json for npm dependencies."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lock = json.load(f)

            packages = lock.get("packages", {})
            # New format (lockfileVersion 2+)
            if packages:
                for pkg_path, pkg_info in packages.items():
                    if pkg_path == "" or not pkg_info:
                        continue
                    name = pkg_info.get("name") or pkg_path.split("node_modules/")[-1]
                    version = pkg_info.get("version", "0.0.0")
                    is_dev = pkg_info.get("dev", False)
                    deps = list(pkg_info.get("dependencies", {}).keys())
                    license_info = self._extract_npm_license(pkg_info)

                    self.dependencies[name] = DependencyNode(
                        name=name,
                        version=version,
                        package_type="npm",
                        is_direct=not pkg_path.startswith("node_modules/"),
                        is_dev=is_dev,
                        license=license_info,
                        purl=f"pkg:npm/{name}@{version}",
                        children=deps,
                    )
            else:
                # Old format (lockfileVersion 1)
                deps = lock.get("dependencies", {})
                for name, info in deps.items():
                    self._add_npm_dep_old_format(name, info, is_direct=True)

        except Exception as e:
            logger.error("Failed to parse package-lock.json: %s", e)

    def _add_npm_dep_old_format(
        self, name: str, info: Dict[str, Any], is_direct: bool
    ) -> None:
        """Recursively add npm deps from old lockfile format."""
        version = info.get("version", "0.0.0")
        is_dev = info.get("dev", False)
        children = list(info.get("requires", {}).keys())
        license_info = self._extract_npm_license(info)

        if name not in self.dependencies:
            self.dependencies[name] = DependencyNode(
                name=name,
                version=version,
                package_type="npm",
                is_direct=is_direct,
                is_dev=is_dev,
                license=license_info,
                purl=f"pkg:npm/{name}@{version}",
                children=children,
            )

        # Recurse transitive dependencies
        for child_name, child_info in info.get("dependencies", {}).items():
            self._add_npm_dep_old_format(child_name, child_info, is_direct=False)

    def _extract_npm_license(self, pkg_info: Dict[str, Any]) -> str:
        """Extract license info from npm package info."""
        license_data = pkg_info.get("license")
        if isinstance(license_data, str):
            return license_data
        if isinstance(license_data, dict):
            return license_data.get("type", "UNKNOWN")
        if isinstance(license_data, list) and license_data:
            if isinstance(license_data[0], dict):
                return license_data[0].get("type", "UNKNOWN")
            return str(license_data[0])
        return "UNKNOWN"

    def _parse_requirements_txt(self, file_path: str) -> None:
        """Parse requirements.txt for Python dependencies."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue

                    # Parse package==version format
                    match = re.match(r"^([a-zA-Z0-9_\-\.]+)\s*==?\s*([^\s;]+)", line)
                    if match:
                        name = match.group(1)
                        version = match.group(2)
                        self.dependencies[name] = DependencyNode(
                            name=name,
                            version=version,
                            package_type="pypi",
                            is_direct=True,
                            purl=f"pkg:pypi/{name}@{version}",
                        )
                    elif re.match(r"^([a-zA-Z0-9_\-\.]+)\s*$", line):
                        # Package without version
                        name = line.split()[0]
                        self.dependencies[name] = DependencyNode(
                            name=name,
                            version="unknown",
                            package_type="pypi",
                            is_direct=True,
                            purl=f"pkg:pypi/{name}",
                        )
        except Exception as e:
            logger.error("Failed to parse requirements.txt: %s", e)

    def _parse_pipfile_lock(self, file_path: str) -> None:
        """Parse Pipfile.lock for Python dependencies."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                lock = json.load(f)

            default = lock.get("default", {})
            develop = lock.get("develop", {})

            for name, info in default.items():
                version = info.get("version", "")
                if version.startswith("=="):
                    version = version[2:]
                self.dependencies[name] = DependencyNode(
                    name=name,
                    version=version or "unknown",
                    package_type="pypi",
                    is_direct=True,
                    purl=f"pkg:pypi/{name}@{version}",
                )

            for name, info in develop.items():
                version = info.get("version", "")
                if version.startswith("=="):
                    version = version[2:]
                self.dependencies[name] = DependencyNode(
                    name=name,
                    version=version or "unknown",
                    package_type="pypi",
                    is_direct=True,
                    is_dev=True,
                    purl=f"pkg:pypi/{name}@{version}",
                )

        except Exception as e:
            logger.error("Failed to parse Pipfile.lock: %s", e)

    def _parse_poetry_lock(self, file_path: str) -> None:
        """Parse poetry.lock for Python dependencies."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # poetry.lock uses TOML-like format with [[package]] sections
            # Parse manually since tomllib may not be available
            package_pattern = r'\[\[package\]\]\s*\n((?:(?!\[\[).)*)'
            packages = re.findall(package_pattern, content, re.DOTALL)

            for pkg_section in packages:
                name_match = re.search(r'name\s*=\s*"([^"]+)"', pkg_section)
                version_match = re.search(r'version\s*=\s*"([^"]+)"', pkg_section)
                category_match = re.search(r'category\s*=\s*"([^"]+)"', pkg_section)

                name = name_match.group(1) if name_match else "unknown"
                version = version_match.group(1) if version_match else "unknown"
                category = category_match.group(1) if category_match else "main"

                # Parse dependencies
                deps = re.findall(
                    r'\[package\.dependencies\.([^\]]+)\]', content
                )

                self.dependencies[name] = DependencyNode(
                    name=name,
                    version=version,
                    package_type="pypi",
                    is_direct=(category == "main"),
                    is_dev=(category == "dev"),
                    purl=f"pkg:pypi/{name}@{version}",
                    children=deps,
                )

        except Exception as e:
            logger.error("Failed to parse poetry.lock: %s", e)

    def _parse_go_mod(self, file_path: str) -> None:
        """Parse go.mod for Go module dependencies."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Parse require blocks
            require_pattern = r'require\s*\((.*?)\)'
            require_blocks = re.findall(require_pattern, content, re.DOTALL)

            for block in require_blocks:
                for line in block.strip().split("\n"):
                    line = line.strip()
                    if not line or line.startswith("//"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        name = parts[0]
                        version = parts[1]
                        is_indirect = "// indirect" in line
                        self.dependencies[name] = DependencyNode(
                            name=name,
                            version=version,
                            package_type="golang",
                            is_direct=not is_indirect,
                            purl=f"pkg:golang/{name}@{version}",
                        )

            # Parse single-line requires
            single_pattern = r'require\s+(\S+)\s+(\S+)'
            for match in re.finditer(single_pattern, content):
                name = match.group(1)
                version = match.group(2)
                if name not in self.dependencies:
                    self.dependencies[name] = DependencyNode(
                        name=name,
                        version=version,
                        package_type="golang",
                        is_direct=True,
                        purl=f"pkg:golang/{name}@{version}",
                    )

        except Exception as e:
            logger.error("Failed to parse go.mod: %s", e)

    def _parse_pom_xml(self, file_path: str) -> None:
        """Parse pom.xml for Maven dependencies."""
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            ns = {"m": "http://maven.apache.org/POM/4.0.0"}

            # Try with namespace first
            deps = root.findall(".//m:dependency", ns)
            if not deps:
                deps = root.findall(".//dependency")

            for dep in deps:
                group_id = dep.findtext("m:groupId", "", ns) or dep.findtext("groupId", "")
                artifact_id = dep.findtext("m:artifactId", "", ns) or dep.findtext("artifactId", "")
                version = dep.findtext("m:version", "", ns) or dep.findtext("version", "")
                scope = dep.findtext("m:scope", "", ns) or dep.findtext("scope", "")

                name = f"{group_id}:{artifact_id}" if group_id else artifact_id
                is_dev = scope in ("test", "provided")

                self.dependencies[name] = DependencyNode(
                    name=name,
                    version=version or "unknown",
                    package_type="maven",
                    is_direct=True,
                    is_dev=is_dev,
                    purl=f"pkg:maven/{group_id}/{artifact_id}@{version}" if group_id else f"pkg:maven/{artifact_id}@{version}",
                )

        except Exception as e:
            logger.error("Failed to parse pom.xml: %s", e)

    def _parse_build_gradle(self, file_path: str) -> None:
        """Parse build.gradle for Gradle dependencies."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Parse implementation, compile, api, testImplementation, etc.
            dep_patterns = [
                r'(?:implementation|compile|api|testImplementation|testCompile|runtimeOnly)\s+["\']([^"\']+):([^"\']+):([^"\']+)["\']',
                r'(?:implementation|compile|api|testImplementation)\s+group:\s*["\']([^"\']+)["\']\s*,\s*name:\s*["\']([^"\']+)["\']\s*,\s*version:\s*["\']([^"\']+)["\']',
            ]

            for pattern in dep_patterns:
                for match in re.finditer(pattern, content):
                    group = match.group(1)
                    name = match.group(2)
                    version = match.group(3)
                    full_name = f"{group}:{name}"
                    is_test = "test" in match.group(0).lower()

                    self.dependencies[full_name] = DependencyNode(
                        name=full_name,
                        version=version,
                        package_type="gradle",
                        is_direct=True,
                        is_dev=is_test,
                        purl=f"pkg:maven/{group}/{name}@{version}",
                    )

        except Exception as e:
            logger.error("Failed to parse build.gradle: %s", e)


# ============================================================================
# Call Graph Builder (Python MVP)
# ============================================================================

class CallGraphBuilder:
    """Builds call graphs from Python source code for reachability analysis."""

    def __init__(self) -> None:
        self.imported_modules: Dict[str, List[str]] = {}  # module -> [files]
        self.module_usage: Dict[str, List[str]] = {}  # module -> [usage contexts]
        self.package_to_import: Dict[str, str] = {}  # top-level pkg -> import name

    def build_call_graph(self, source_path: str) -> Dict[str, List[str]]:
        """
        Build a call graph of imported modules from Python source.

        Args:
            source_path: Path to the source directory

        Returns:
            Dictionary mapping module names to list of files importing them
        """
        self.imported_modules = {}
        self.module_usage = {}
        self.package_to_import = {}

        path = Path(source_path)
        py_files = list(path.rglob("*.py"))

        for py_file in py_files:
            if py_file.name.startswith(".") or "__pycache__" in str(py_file):
                continue
            try:
                self._analyze_python_file(str(py_file))
            except Exception as e:
                logger.debug("Failed to analyze %s: %s", py_file, e)

        return self.imported_modules

    def _analyze_python_file(self, file_path: str) -> None:
        """Analyze a Python file for imports and usage."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            tree = ast.parse(content)
        except SyntaxError:
            return
        except Exception:
            return

        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    top_level = alias.name.split(".")[0]
                    self._record_import(top_level, file_path)
                    # Check if module is actually used
                    if alias.asname:
                        self._check_usage(content, alias.asname, file_path, top_level)
                    else:
                        self._check_usage(content, top_level, file_path, top_level)

            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    top_level = node.module.split(".")[0]
                    self._record_import(top_level, file_path)
                    for alias in node.names:
                        imported_name = alias.asname or alias.name
                        self._check_usage(
                            content, imported_name, file_path, top_level
                        )

    def _record_import(self, module: str, file_path: str) -> None:
        """Record an import of a module."""
        if module not in self.imported_modules:
            self.imported_modules[module] = []
        if file_path not in self.imported_modules[module]:
            self.imported_modules[module].append(file_path)

    def _check_usage(
        self, content: str, name: str, file_path: str, module: str
    ) -> None:
        """Check if an imported name is actually used in the code."""
        # Simple check: look for name usage beyond import
        usage_pattern = re.compile(rf'\b{name}\b')
        matches = usage_pattern.findall(content)
        # If more than just the import statement
        if len(matches) > 1:
            if module not in self.module_usage:
                self.module_usage[module] = []
            self.module_usage[module].append(file_path)

    def map_package_to_dependency(self, package_name: str) -> Optional[str]:
        """
        Map a Python package import name to a dependency name.

        Handles common name differences (e.g., 'PIL' -> 'Pillow',
        'bs4' -> 'beautifulsoup4', 'cv2' -> 'opencv-python').
        """
        # Direct match
        if package_name.lower() in (name.lower() for name in self.imported_modules):
            return package_name

        # Common package name mappings
        PACKAGE_MAPPINGS = {
            "PIL": "Pillow",
            "bs4": "beautifulsoup4",
            "cv2": "opencv-python",
            "sklearn": "scikit-learn",
            "yaml": "PyYAML",
            "jwt": "PyJWT",
            "Crypto": "pycryptodome",
            "cryptography": "cryptography",
            "requests": "requests",
            "flask": "Flask",
            "django": "Django",
            "fastapi": "fastapi",
            "sqlalchemy": "SQLAlchemy",
            "pandas": "pandas",
            "numpy": "numpy",
            "matplotlib": "matplotlib",
            "tensorflow": "tensorflow",
            "torch": "torch",
            "pytest": "pytest",
            "urllib3": "urllib3",
            "dateutil": "python-dateutil",
            "dotenv": "python-dotenv",
            "magic": "python-magic",
            "ldap": "python-ldap",
            "OpenSSL": "pyOpenSSL",
            "github": "PyGithub",
            "gitlab": "python-gitlab",
            "toml": "toml",
            "boto3": "boto3",
            "botocore": "botocore",
            "s3fs": "s3fs",
            "redis": "redis",
            "pymongo": "pymongo",
            "psycopg2": "psycopg2-binary",
            "MySQLdb": "mysqlclient",
            "selenium": "selenium",
            "PIL": "Pillow",
            "google": "google-cloud",
            "huggingface_hub": "huggingface-hub",
            "transformers": "transformers",
            "accelerate": "accelerate",
            "datasets": "datasets",
            "peft": "peft",
            "bitsandbytes": "bitsandbytes",
            "trl": "trl",
            "unsloth": "unsloth",
        }

        return PACKAGE_MAPPINGS.get(package_name, package_name)


# ============================================================================
# Reachability Analyzer
# ============================================================================

class ReachabilityAnalyzer:
    """
    SCA Reachability Analysis engine.

    Combines dependency graph and call graph to determine which
    vulnerable dependencies are actually reachable in code.
    """

    def __init__(self) -> None:
        self.dep_builder = DependencyGraphBuilder()
        self.call_builder = CallGraphBuilder()
        self.dependency_graph: Dict[str, DependencyNode] = {}
        self.call_graph: Dict[str, List[str]] = {}
        self.reachability_scores: Dict[str, ReachabilityScore] = {}

    def analyze(
        self, source_path: str, scan_id: str
    ) -> Dict[str, ReachabilityScore]:
        """
        Perform full reachability analysis.

        Args:
            source_path: Path to the source directory
            scan_id: Scan identifier

        Returns:
            Dictionary mapping dependency name to ReachabilityScore
        """
        # Phase 1: Build dependency graph
        logger.info("[%s] Building dependency graph...", scan_id)
        self.dependency_graph = self.dep_builder.build_graph(source_path)

        if not self.dependency_graph:
            logger.info("[%s] No dependency files found", scan_id)
            return {}

        logger.info(
            "[%s] Found %d dependencies", scan_id, len(self.dependency_graph)
        )

        # Phase 2: Build call graph (Python only for MVP)
        logger.info("[%s] Building call graph...", scan_id)
        self.call_graph = self.call_builder.build_call_graph(source_path)

        logger.info(
            "[%s] Found %d imported modules", scan_id, len(self.call_graph)
        )

        # Phase 3: Compute reachability scores
        logger.info("[%s] Computing reachability scores...", scan_id)
        self.reachability_scores = self._compute_scores()

        return self.reachability_scores

    def _compute_scores(self) -> Dict[str, ReachabilityScore]:
        """Compute reachability scores for all dependencies."""
        scores: Dict[str, ReachabilityScore] = {}

        for dep_name, dep_node in self.dependency_graph.items():
            # Map dependency name to import name
            import_name = self.call_builder.map_package_to_dependency(dep_name)

            # Check direct imports
            is_imported = False
            imported_by: List[str] = []
            for mod_name, files in self.call_graph.items():
                if mod_name.lower() == dep_name.lower() or \
                   (import_name and mod_name.lower() == import_name.lower()):
                    is_imported = True
                    imported_by = files
                    break

            # Check if used in code
            is_used = False
            usage_files: List[str] = []
            if import_name and import_name in self.call_builder.module_usage:
                is_used = True
                usage_files = self.call_builder.module_usage[import_name]

            # Calculate reachability score
            if is_imported and is_used:
                score = "HIGH"
                multiplier = 1.5
                reason = (
                    f"Dependency '{dep_name}' is directly imported "
                    f"and actively used in {len(usage_files)} file(s)"
                )
            elif is_imported:
                score = "MEDIUM"
                multiplier = 1.0
                reason = (
                    f"Dependency '{dep_name}' is directly imported "
                    f"but not actively used"
                )
            elif not dep_node.is_direct:
                score = "LOW"
                multiplier = 0.7
                reason = (
                    f"Dependency '{dep_name}' is a transitive dependency only"
                )
            else:
                score = "INFORMATIONAL"
                multiplier = 0.3
                reason = (
                    f"Dependency '{dep_name}' is not reachable from source code"
                )

            # Only add score for direct or reachable dependencies
            if dep_node.is_direct or is_imported:
                scores[dep_name] = ReachabilityScore(
                    dependency=dep_node,
                    score=score,
                    multiplier=multiplier,
                    reason=reason,
                    imported_modules=[import_name] if import_name else [],
                    used_in_code=is_used,
                    file_references=usage_files or imported_by,
                )

        return scores

    def get_reachable_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Get list of dependencies with HIGH/MEDIUM reachability that have vulnerabilities."""
        results: List[Dict[str, Any]] = []
        for name, score in self.reachability_scores.items():
            if score.score in ("HIGH", "MEDIUM") and score.dependency.vulnerabilities:
                results.append({
                    "dependency": name,
                    "version": score.dependency.version,
                    "reachability": score.score,
                    "multiplier": score.multiplier,
                    "vulnerabilities": score.dependency.vulnerabilities,
                })
        return results


# ============================================================================
# SBOM Generator
# ============================================================================

class SBOMGenerator:
    """Generate SBOMs in SPDX 2.3 and CycloneDX 1.5 formats."""

    def __init__(self, dependency_graph: Dict[str, DependencyNode]) -> None:
        self.dependency_graph = dependency_graph

    def generate_spdx(self, scan_id: str, document_name: str = "") -> Dict[str, Any]:
        """
        Generate SPDX 2.3 JSON format SBOM.

        Args:
            scan_id: The scan identifier
            document_name: Name of the document

        Returns:
            SPDX 2.3 JSON dictionary
        """
        now = datetime.now(timezone.utc)
        doc_name = document_name or f"codeshield-sbom-{scan_id}"

        packages = []
        relationships = []

        # Root package
        root_pkg_id = "SPDXRef-RootPackage"

        for dep_name, dep in self.dependency_graph.items():
            pkg_id = f"SPDXRef-Package-{self._sanitize_spdx_id(dep_name)}"

            pkg = {
                "SPDXID": pkg_id,
                "name": dep.name,
                "versionInfo": dep.version,
                "downloadLocation": "NOASSERTION",
                "filesAnalyzed": False,
                "primaryPackagePurpose": "LIBRARY",
                "licenseConcluded": dep.license,
                "licenseDeclared": dep.license,
                "copyrightText": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceType": "purl",
                        "referenceLocator": dep.purl,
                    }
                ],
            }

            if dep.checksum:
                pkg["checksums"] = [
                    {
                        "algorithm": "SHA256",
                        "checksumValue": dep.checksum,
                    }
                ]

            packages.append(pkg)

            # Relationship to root
            relationships.append({
                "spdxElementId": root_pkg_id,
                "relatedSpdxElement": pkg_id,
                "relationshipType": "DEPENDS_ON",
            })

            # Transitive dependencies
            for child_name in dep.children:
                child_id = f"SPDXRef-Package-{self._sanitize_spdx_id(child_name)}"
                relationships.append({
                    "spdxElementId": pkg_id,
                    "relatedSpdxElement": child_id,
                    "relationshipType": "DEPENDS_ON",
                })

        sbom = {
            "spdxVersion": "SPDX-2.3",
            "dataLicense": "CC0-1.0",
            "SPDXID": "SPDXRef-DOCUMENT",
            "name": doc_name,
            "documentNamespace": f"https://codeshield.ai/sbom/{scan_id}",
            "creationInfo": {
                "created": now.isoformat(),
                "creators": [
                    "Tool: CodeShield AI-1.0.0",
                    "Organization: CodeShield AI",
                ],
            },
            "packages": packages,
            "relationships": relationships,
        }

        return sbom

    def generate_cyclonedx(
        self, scan_id: str
    ) -> Dict[str, Any]:
        """
        Generate CycloneDX 1.5 JSON format SBOM.

        Args:
            scan_id: The scan identifier

        Returns:
            CycloneDX 1.5 JSON dictionary
        """
        now = datetime.now(timezone.utc)

        components = []
        for dep_name, dep in self.dependency_graph.items():
            component = {
                "type": "library",
                "name": dep.name,
                "version": dep.version,
                "purl": dep.purl,
                "licenses": [
                    {"expression": dep.license} if dep.license != "UNKNOWN" else {}
                ],
                "properties": [
                    {
                        "name": "codeshield:package_type",
                        "value": dep.package_type,
                    },
                    {
                        "name": "codeshield:is_direct",
                        "value": str(dep.is_direct),
                    },
                    {
                        "name": "codeshield:is_dev",
                        "value": str(dep.is_dev),
                    },
                ],
            }

            if dep.checksum:
                component["hashes"] = [
                    {
                        "alg": "SHA-256",
                        "content": dep.checksum,
                    }
                ]

            # Add vulnerability references if available
            if dep.vulnerabilities:
                component["vulnerabilities"] = dep.vulnerabilities

            components.append(component)

        sbom = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.5",
            "serialNumber": f"urn:uuid:{self._generate_uuid()}",
            "version": 1,
            "metadata": {
                "timestamp": now.isoformat(),
                "tools": [
                    {
                        "vendor": "CodeShield AI",
                        "name": "codeshield-sbom-generator",
                        "version": "1.0.0",
                    }
                ],
            },
            "components": components,
        }

        return sbom

    def generate_both(
        self, scan_id: str
    ) -> Dict[str, Dict[str, Any]]:
        """Generate both SPDX and CycloneDX SBOMs."""
        return {
            "spdx": self.generate_spdx(scan_id),
            "cyclonedx": self.generate_cyclonedx(scan_id),
        }

    @staticmethod
    def _sanitize_spdx_id(name: str) -> str:
        """Sanitize a package name for use in SPDX ID."""
        return re.sub(r"[^a-zA-Z0-9._-]", "-", name)

    @staticmethod
    def _generate_uuid() -> str:
        """Generate a UUID string."""
        import uuid
        return str(uuid.uuid4())


# ============================================================================
# Main API
# ============================================================================

class SCAAnalyzer:
    """
    Main SCA analysis orchestrator.

    Combines dependency graph construction, reachability analysis,
    and SBOM generation into a unified API.
    """

    def __init__(self) -> None:
        self.reachability = ReachabilityAnalyzer()
        self.sbom_generator: Optional[SBOMGenerator] = None

    def analyze_project(
        self, source_path: str, scan_id: str
    ) -> Dict[str, Any]:
        """
        Run full SCA analysis on a project.

        Args:
            source_path: Path to the source directory
            scan_id: The scan identifier

        Returns:
            Complete analysis results with reachability and SBOM
        """
        # Run reachability analysis
        scores = self.reachability.analyze(source_path, scan_id)

        # Build SBOM from dependency graph
        self.sbom_generator = SBOMGenerator(
            self.reachability.dependency_graph
        )

        # Compute summary stats
        reachable_vulns = self.reachability.get_reachable_vulnerabilities()

        score_distribution = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
        for score in scores.values():
            score_distribution[score.score] = score_distribution.get(score.score, 0) + 1

        return {
            "scan_id": scan_id,
            "total_dependencies": len(self.reachability.dependency_graph),
            "direct_dependencies": sum(
                1 for d in self.reachability.dependency_graph.values() if d.is_direct
            ),
            "transitive_dependencies": sum(
                1 for d in self.reachability.dependency_graph.values() if not d.is_direct
            ),
            "reachable_dependencies": len(scores),
            "score_distribution": score_distribution,
            "reachable_vulnerabilities": reachable_vulns,
            "reachability_scores": {
                name: score.to_dict() for name, score in scores.items()
            },
        }

    def generate_sbom(
        self, scan_id: str, format: str = "spdx"
    ) -> Dict[str, Any]:
        """
        Generate SBOM in specified format.

        Args:
            scan_id: The scan identifier
            format: 'spdx', 'cyclonedx', or 'both'

        Returns:
            SBOM dictionary
        """
        if self.sbom_generator is None:
            raise RuntimeError("Run analyze_project() first")

        if format == "spdx":
            return self.sbom_generator.generate_spdx(scan_id)
        elif format == "cyclonedx":
            return self.sbom_generator.generate_cyclonedx(scan_id)
        elif format == "both":
            return self.sbom_generator.generate_both(scan_id)
        else:
            raise ValueError(f"Unsupported SBOM format: {format}")
