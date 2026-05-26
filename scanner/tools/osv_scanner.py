"""
OSV.dev Scanner for CodeShield AI.

Integrates with the OSV.dev API for vulnerability database queries.
Supports multiple dependency file formats and provides transitive
dependency scanning via deps.dev API.

Features:
- OSV.dev API integration for real-time vulnerability lookup
- Support for package-lock.json, requirements.txt, pom.xml, build.gradle, go.mod, Cargo.lock
- Transitive dependency scanning via deps.dev API
- CVSS v4.0 scoring for each CVE
- CISA KEV (Known Exploited Vulnerabilities) flagging
- EPSS (Exploit Prediction Scoring System) integration
"""

import asyncio
import json
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import httpx

from models.vulnerability import Vulnerability
from utils.constants import CWE_MAPPING
from utils.helpers import read_file_snippet
from utils.logger import get_logger

logger = get_logger(__name__)

# OSV.dev API
OSV_QUERY_URL = "https://api.osv.dev/v1/query"
OSV_BATCH_QUERY_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns"

# deps.dev API for transitive dependencies
DEPSDEV_API_URL = "https://api.deps.dev/v3"

# EPSS API
EPSS_API_URL = "https://api.first.org/data/v1/epss"

# CISA KEV API
CISA_KEV_API_URL = "https://api.cisa.gov/known-exploited-vulnerabilities/catalog"

# Supported lockfile patterns
LOCKFILE_PATTERNS = {
    "package-lock.json": "npm",
    "yarn.lock": "npm",
    "pnpm-lock.yaml": "npm",
    "requirements.txt": "pypi",
    "Pipfile.lock": "pypi",
    "poetry.lock": "pypi",
    "pom.xml": "maven",
    "build.gradle": "gradle",
    "go.mod": "go",
    "go.sum": "go",
    "Cargo.lock": "cargo",
    "Cargo.toml": "cargo",
    "composer.lock": "packagist",
    " Gemfile.lock": "rubygems",
    "packages.lock.json": "nuget",
}


@dataclass
class DependencyInfo:
    """Represents a parsed dependency."""

    name: str
    version: str
    ecosystem: str
    file_source: str
    is_transitive: bool = False
    parent_package: Optional[str] = None


@dataclass
class OSVVulnerability:
    """Represents a vulnerability from OSV.dev."""

    osv_id: str
    summary: str
    details: str
    severity: str
    cve_ids: List[str] = field(default_factory=list)
    cvss_score: Optional[float] = None
    cvss_v4_score: Optional[float] = None
    fixed_versions: List[str] = field(default_factory=list)
    references: List[Dict[str, str]] = field(default_factory=list)
    published: Optional[str] = None
    modified: Optional[str] = None
    cisa_kev: bool = False
    epss_score: Optional[float] = None


class OSVScanner:
    """
    OSV.dev vulnerability scanner.

    Scans dependency lockfiles for known vulnerabilities using the
    OSV.dev open-source vulnerability database.
    """

    def __init__(self) -> None:
        """Initialize the OSV scanner."""
        self.tool_name = "osv_scanner"
        self._epss_cache: Dict[str, Optional[float]] = {}
        self._kev_cache: Dict[str, bool] = {}
        self._client: Optional[httpx.AsyncClient] = None

    async def _get_client(self) -> httpx.AsyncClient:
        """Get or create HTTP client with timeout."""
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(timeout=30.0, limits=httpx.Limits(max_connections=20))
        return self._client

    async def scan(self, source_path: str, scan_id: str) -> List[Vulnerability]:
        """
        Scan a directory for dependency files and query OSV.dev.

        Args:
            source_path: Path to the source code directory
            scan_id: Scan identifier

        Returns:
            List of vulnerabilities found
        """
        logger.info("Running OSV scanner on %s", source_path)
        vulnerabilities: List[Vulnerability] = []

        # Find all dependency files
        dep_files = self._find_dependency_files(source_path)
        if not dep_files:
            logger.info("No dependency files found in %s", source_path)
            return vulnerabilities

        logger.info("Found %d dependency files: %s", len(dep_files), dep_files)

        # Parse dependencies from each file
        all_deps: List[DependencyInfo] = []
        for dep_file in dep_files:
            try:
                deps = self._parse_dependency_file(dep_file, source_path)
                all_deps.extend(deps)
                logger.info("Parsed %d dependencies from %s", len(deps), dep_file)
            except Exception as e:
                logger.warning("Failed to parse %s: %s", dep_file, e)

        if not all_deps:
            return vulnerabilities

        # Query OSV.dev for vulnerabilities (batch queries for efficiency)
        osv_results = await self._query_osv_batch(all_deps)

        # Query transitive dependencies via deps.dev
        transitive_results = await self._query_transitive_deps(all_deps)

        # Combine results
        all_results = {**osv_results, **transitive_results}

        # Enrich with EPSS and KEV data
        await self._enrich_vulnerabilities(all_results)

        # Convert to Vulnerability objects
        for dep_info, osv_vulns in all_results.items():
            for osv_vuln in osv_vulns:
                vuln = self._convert_to_vulnerability(osv_vuln, dep_info, scan_id, source_path)
                if vuln:
                    vulnerabilities.append(vuln)

        logger.info("OSV scanner found %d vulnerabilities in %d dependencies", len(vulnerabilities), len(all_deps))
        return vulnerabilities

    def _find_dependency_files(self, source_path: str) -> List[str]:
        """Find all supported dependency files in the source directory."""
        found: List[str] = []
        for root, _, files in os.walk(source_path):
            # Skip node_modules and virtual environments
            dirs = root.split(os.sep)
            if any(skip in dirs for skip in ["node_modules", ".venv", "venv", "__pycache__", ".git"]):
                continue

            for filename in files:
                if filename in LOCKFILE_PATTERNS:
                    found.append(os.path.join(root, filename))
        return found

    def _parse_dependency_file(self, file_path: str, source_path: str) -> List[DependencyInfo]:
        """
        Parse dependencies from a lockfile.

        Args:
            file_path: Path to the dependency file
            source_path: Base source directory

        Returns:
            List of DependencyInfo objects
        """
        filename = os.path.basename(file_path)
        ecosystem = LOCKFILE_PATTERNS.get(filename, "")
        deps: List[DependencyInfo] = []

        if filename == "package-lock.json":
            deps = self._parse_package_lock(file_path)
        elif filename in ("requirements.txt",):
            deps = self._parse_requirements_txt(file_path)
        elif filename == "pom.xml":
            deps = self._parse_pom_xml(file_path)
        elif filename == "build.gradle":
            deps = self._parse_build_gradle(file_path)
        elif filename == "go.mod":
            deps = self._parse_go_mod(file_path)
        elif filename == "Cargo.lock":
            deps = self._parse_cargo_lock(file_path)
        elif filename == "Pipfile.lock":
            deps = self._parse_pipfile_lock(file_path)
        elif filename == "poetry.lock":
            deps = self._parse_poetry_lock(file_path)
        elif filename == "composer.lock":
            deps = self._parse_composer_lock(file_path)
        else:
            logger.debug("Parser not yet implemented for %s", filename)

        return deps

    def _parse_package_lock(self, file_path: str) -> List[DependencyInfo]:
        """Parse package-lock.json for npm dependencies."""
        deps: List[DependencyInfo] = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            packages = data.get("packages", {})
            for pkg_path, pkg_info in packages.items():
                if pkg_path == "":  # Root package
                    continue
                name = pkg_info.get("name") or pkg_path.split("node_modules/")[-1]
                version = pkg_info.get("version", "")
                if name and version:
                    is_transitive = pkg_path.count("node_modules") > 1
                    deps.append(DependencyInfo(
                        name=name,
                        version=version,
                        ecosystem="npm",
                        file_source=file_path,
                        is_transitive=is_transitive,
                    ))
        except Exception as e:
            logger.warning("Error parsing package-lock.json: %s", e)
        return deps

    def _parse_requirements_txt(self, file_path: str) -> List[DependencyInfo]:
        """Parse requirements.txt for Python dependencies."""
        deps: List[DependencyInfo] = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#") or line.startswith("-"):
                        continue
                    # Parse package==version, package>=version, etc.
                    match = re.match(r'^([a-zA-Z0-9_.\-]+)\s*[=<>!~]+\s*([a-zA-Z0-9._+\-]+)', line)
                    if match:
                        deps.append(DependencyInfo(
                            name=match.group(1),
                            version=match.group(2),
                            ecosystem="PyPI",
                            file_source=file_path,
                        ))
                    else:
                        # Just package name without version
                        match = re.match(r'^([a-zA-Z0-9_.\-]+)', line)
                        if match:
                            deps.append(DependencyInfo(
                                name=match.group(1),
                                version="",
                                ecosystem="PyPI",
                                file_source=file_path,
                            ))
        except Exception as e:
            logger.warning("Error parsing requirements.txt: %s", e)
        return deps

    def _parse_pom_xml(self, file_path: str) -> List[DependencyInfo]:
        """Parse pom.xml for Maven dependencies."""
        deps: List[DependencyInfo] = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Extract dependencies with regex (lightweight, no XML lib needed)
            dep_pattern = r'<dependency>\s*<groupId>([^<]+)</groupId>\s*<artifactId>([^<]+)</artifactId>\s*(?:<version>([^<]+)</version>)?\s*</dependency>'
            for match in re.finditer(dep_pattern, content, re.DOTALL):
                group_id = match.group(1).strip()
                artifact_id = match.group(2).strip()
                version = match.group(3).strip() if match.group(3) else ""
                name = f"{group_id}:{artifact_id}"
                deps.append(DependencyInfo(
                    name=name,
                    version=version,
                    ecosystem="Maven",
                    file_source=file_path,
                ))
        except Exception as e:
            logger.warning("Error parsing pom.xml: %s", e)
        return deps

    def _parse_build_gradle(self, file_path: str) -> List[DependencyInfo]:
        """Parse build.gradle for Gradle dependencies."""
        deps: List[DependencyInfo] = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Match implementation/compile dependencies
            patterns = [
                r"(?:implementation|compile|api|testImplementation)\s+['\"]([^'\"]+:[^'\"]+:[^'\"]+)['\"]",
                r"group:\s*['\"]([^'\"]+)['\"]\s*,\s*name:\s*['\"]([^'\"]+)['\"](?:\s*,\s*version:\s*['\"]([^'\"]+)['\"])?",
            ]

            for pattern in patterns:
                for match in re.finditer(pattern, content):
                    if match.lastindex == 3 and match.group(3):
                        name = f"{match.group(1)}:{match.group(2)}"
                        version = match.group(3)
                    elif match.lastindex == 1:
                        parts = match.group(1).split(":")
                        name = f"{parts[0]}:{parts[1]}"
                        version = parts[2] if len(parts) > 2 else ""
                    else:
                        continue

                    deps.append(DependencyInfo(
                        name=name,
                        version=version,
                        ecosystem="Maven",  # Gradle uses Maven coordinates
                        file_source=file_path,
                    ))
        except Exception as e:
            logger.warning("Error parsing build.gradle: %s", e)
        return deps

    def _parse_go_mod(self, file_path: str) -> List[DependencyInfo]:
        """Parse go.mod for Go dependencies."""
        deps: List[DependencyInfo] = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                in_require = False
                for line in f:
                    line = line.strip()
                    if line.startswith("require ("):
                        in_require = True
                        continue
                    if in_require and line == ")":
                        in_require = False
                        continue

                    match = re.match(r'^([^\s/]+(?:/[^\s]+)*)\s+v?([^\s]+)', line)
                    if match and not line.startswith("go ") and not line.startswith("module "):
                        deps.append(DependencyInfo(
                            name=match.group(1),
                            version=match.group(2),
                            ecosystem="Go",
                            file_source=file_path,
                        ))
        except Exception as e:
            logger.warning("Error parsing go.mod: %s", e)
        return deps

    def _parse_cargo_lock(self, file_path: str) -> List[DependencyInfo]:
        """Parse Cargo.lock for Rust dependencies."""
        deps: List[DependencyInfo] = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Parse TOML-style package entries
            package_pattern = r'\[\[package\]\](.*?)(?=\[\[|$)'
            for match in re.finditer(package_pattern, content, re.DOTALL):
                block = match.group(1)
                name_match = re.search(r'name\s*=\s*"([^"]+)"', block)
                version_match = re.search(r'version\s*=\s*"([^"]+)"', block)
                if name_match:
                    deps.append(DependencyInfo(
                        name=name_match.group(1),
                        version=version_match.group(1) if version_match else "",
                        ecosystem="crates.io",
                        file_source=file_path,
                    ))
        except Exception as e:
            logger.warning("Error parsing Cargo.lock: %s", e)
        return deps

    def _parse_pipfile_lock(self, file_path: str) -> List[DependencyInfo]:
        """Parse Pipfile.lock for Python dependencies."""
        deps: List[DependencyInfo] = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for section in ["default", "develop"]:
                packages = data.get(section, {})
                for name, info in packages.items():
                    version = info.get("version", "").lstrip("=") if isinstance(info, dict) else str(info)
                    deps.append(DependencyInfo(
                        name=name,
                        version=version,
                        ecosystem="PyPI",
                        file_source=file_path,
                    ))
        except Exception as e:
            logger.warning("Error parsing Pipfile.lock: %s", e)
        return deps

    def _parse_poetry_lock(self, file_path: str) -> List[DependencyInfo]:
        """Parse poetry.lock for Python dependencies."""
        deps: List[DependencyInfo] = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            package_pattern = r'\[\[package\]\](.*?)(?=\[\[|$)'
            for match in re.finditer(package_pattern, content, re.DOTALL):
                block = match.group(1)
                name_match = re.search(r'^name\s*=\s*"([^"]+)"', block, re.MULTILINE)
                version_match = re.search(r'^version\s*=\s*"([^"]+)"', block, re.MULTILINE)
                if name_match:
                    deps.append(DependencyInfo(
                        name=name_match.group(1),
                        version=version_match.group(1) if version_match else "",
                        ecosystem="PyPI",
                        file_source=file_path,
                    ))
        except Exception as e:
            logger.warning("Error parsing poetry.lock: %s", e)
        return deps

    def _parse_composer_lock(self, file_path: str) -> List[DependencyInfo]:
        """Parse composer.lock for PHP dependencies."""
        deps: List[DependencyInfo] = []
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            for pkg in data.get("packages", []):
                deps.append(DependencyInfo(
                    name=pkg.get("name", ""),
                    version=pkg.get("version", ""),
                    ecosystem="Packagist",
                    file_source=file_path,
                ))
        except Exception as e:
            logger.warning("Error parsing composer.lock: %s", e)
        return deps

    async def _query_osv_batch(
        self, dependencies: List[DependencyInfo]
    ) -> Dict[DependencyInfo, List[OSVVulnerability]]:
        """
        Query OSV.dev for vulnerabilities in batches.

        Args:
            dependencies: List of dependencies to query

        Returns:
            Dictionary mapping DependencyInfo to list of OSVVulnerabilities
        """
        results: Dict[DependencyInfo, List[OSVVulnerability]] = {}
        client = await self._get_client()

        # Process in batches of 100
        batch_size = 100
        for i in range(0, len(dependencies), batch_size):
            batch = dependencies[i : i + batch_size]
            queries = []

            for dep in batch:
                if dep.version:
                    queries.append({
                        "package": {"name": dep.name, "ecosystem": dep.ecosystem},
                        "version": dep.version,
                    })

            if not queries:
                continue

            try:
                resp = await client.post(
                    OSV_BATCH_QUERY_URL,
                    json={"queries": queries},
                )
                resp.raise_for_status()
                data = resp.json()

                for j, result in enumerate(data.get("results", [])):
                    if j < len(batch):
                        dep = batch[j]
                        vulns: List[OSVVulnerability] = []
                        for vuln_data in result.get("vulns", []):
                            osv_vuln = self._parse_osv_vulnerability(vuln_data)
                            vulns.append(osv_vuln)
                        if vulns:
                            results[dep] = vulns

                # Rate limiting
                await asyncio.sleep(0.1)

            except Exception as e:
                logger.warning("OSV batch query failed: %s", e)
                continue

        return results

    def _parse_osv_vulnerability(self, data: Dict[str, Any]) -> OSVVulnerability:
        """Parse OSV vulnerability data into OSVVulnerability object."""
        severity_score = 5.0
        severity_type = ""
        cvss_v4 = None

        # Extract severity
        for sev in data.get("severity", []):
            if sev.get("type") == "CVSS_V4":
                severity_score = float(sev.get("score", 5.0))
                severity_type = "CVSS_V4"
                cvss_v4 = severity_score
            elif sev.get("type") == "CVSS_V3" and severity_type != "CVSS_V4":
                severity_score = float(sev.get("score", 5.0))
                severity_type = "CVSS_V3"

        # Extract CVE IDs
        cve_ids = []
        for alias in data.get("aliases", []):
            if alias.startswith("CVE-"):
                cve_ids.append(alias)

        # Extract fixed versions
        fixed_versions: List[str] = []
        for affected in data.get("affected", []):
            for rng in affected.get("ranges", []):
                for event in rng.get("events", []):
                    if "fixed" in event:
                        fixed_versions.append(event["fixed"])

        severity_label = self._cvss_to_severity(severity_score)

        return OSVVulnerability(
            osv_id=data.get("id", ""),
            summary=data.get("summary", ""),
            details=data.get("details", ""),
            severity=severity_label,
            cve_ids=cve_ids,
            cvss_score=severity_score,
            cvss_v4_score=cvss_v4,
            fixed_versions=fixed_versions,
            references=data.get("references", []),
            published=data.get("published"),
            modified=data.get("modified"),
        )

    async def _query_transitive_deps(
        self, dependencies: List[DependencyInfo]
    ) -> Dict[DependencyInfo, List[OSVVulnerability]]:
        """
        Query deps.dev for transitive dependency vulnerabilities.

        Args:
            dependencies: List of direct dependencies

        Returns:
            Dictionary of transitive DependencyInfo to vulnerabilities
        """
        results: Dict[DependencyInfo, List[OSVVulnerability]] = {}

        # Only query deps.dev for supported ecosystems
        supported_ecosystems = {"npm": "npm", "PyPI": "pypi", "maven": "maven", "Maven": "maven"}

        for dep in dependencies[:20]:  # Limit to avoid excessive API calls
            ecosystem = supported_ecosystems.get(dep.ecosystem, "")
            if not ecosystem or not dep.version:
                continue

            try:
                client = await self._get_client()
                url = f"{DEPSDEV_API_URL}/systems/{ecosystem}/packages/{dep.name}/versions/{dep.version}:dependencies"
                resp = await client.get(url)

                if resp.status_code != 200:
                    continue

                deps_data = resp.json()
                for node in deps_data.get("nodes", []):
                    if node.get("relation") in ("TRANSITIVE", "INDIRECT"):
                        transitive_dep = DependencyInfo(
                            name=node.get("packageKey", {}).get("name", ""),
                            version=node.get("version", ""),
                            ecosystem=dep.ecosystem,
                            file_source=dep.file_source,
                            is_transitive=True,
                            parent_package=dep.name,
                        )

                        # Query OSV for this transitive dep
                        if transitive_dep.name and transitive_dep.version:
                            await asyncio.sleep(0.05)  # Rate limit
                            osv_results = await self._query_osv_batch([transitive_dep])
                            results.update(osv_results)

                await asyncio.sleep(0.2)

            except Exception as e:
                logger.debug("deps.dev query failed for %s: %s", dep.name, e)
                continue

        return results

    async def _enrich_vulnerabilities(
        self, results: Dict[DependencyInfo, List[OSVVulnerability]]
    ) -> None:
        """Enrich vulnerabilities with EPSS and KEV data."""
        # Collect all CVE IDs
        all_cves: Set[str] = set()
        for vulns in results.values():
            for v in vulns:
                all_cves.update(v.cve_ids)

        if not all_cves:
            return

        # Query EPSS in batch
        await self._query_epss_batch(all_cves)

        # Query KEV
        await self._query_kev_batch(all_cves)

        # Apply enrichment
        for vulns in results.values():
            for v in vulns:
                for cve in v.cve_ids:
                    if cve in self._epss_cache:
                        v.epss_score = self._epss_cache[cve]
                    if cve in self._kev_cache:
                        v.cisa_kev = self._kev_cache[cve]

    async def _query_epss_batch(self, cve_ids: Set[str]) -> None:
        """Query EPSS scores for multiple CVEs."""
        uncached = [cve for cve in cve_ids if cve not in self._epss_cache]
        if not uncached:
            return

        try:
            client = await self._get_client()
            cve_list = ",".join(uncached[:100])  # EPSS API limit
            resp = await client.get(
                EPSS_API_URL,
                params={"cve": cve_list},
                timeout=15,
            )

            if resp.status_code == 200:
                data = resp.json()
                for entry in data.get("data", []):
                    cve = entry.get("cve", "")
                    epss = float(entry.get("epss", 0))
                    self._epss_cache[cve] = epss

            # Mark missing CVEs as queried (None means no data)
            for cve in uncached:
                if cve not in self._epss_cache:
                    self._epss_cache[cve] = None

        except Exception as e:
            logger.debug("EPSS batch query failed: %s", e)
            for cve in uncached:
                self._epss_cache[cve] = None

    async def _query_kev_batch(self, cve_ids: Set[str]) -> None:
        """Query CISA KEV catalog for multiple CVEs."""
        uncached = [cve for cve in cve_ids if cve not in self._kev_cache]
        if not uncached:
            return

        try:
            client = await self._get_client()
            for cve in uncached[:50]:  # Limit to avoid rate limiting
                try:
                    resp = await client.get(
                        CISA_KEV_API_URL,
                        params={"cveID": cve},
                        timeout=10,
                    )
                    if resp.status_code == 200:
                        data = resp.json()
                        self._kev_cache[cve] = bool(data.get("vulnerabilities"))
                    else:
                        self._kev_cache[cve] = False
                    await asyncio.sleep(0.1)
                except Exception:
                    self._kev_cache[cve] = False

        except Exception as e:
            logger.debug("KEV batch query failed: %s", e)
            for cve in uncached:
                if cve not in self._kev_cache:
                    self._kev_cache[cve] = False

    def _convert_to_vulnerability(
        self,
        osv_vuln: OSVVulnerability,
        dep_info: DependencyInfo,
        scan_id: str,
        source_path: str,
    ) -> Optional[Vulnerability]:
        """
        Convert an OSVVulnerability to a CodeShield Vulnerability.

        Args:
            osv_vuln: OSV vulnerability data
            dep_info: Dependency information
            scan_id: Scan ID
            source_path: Base source path

        Returns:
            Vulnerability object or None
        """
        if not osv_vuln.osv_id:
            return None

        # Build description
        description = f"{osv_vuln.summary}"
        if osv_vuln.details:
            description += f"\n\n{osv_vuln.details[:500]}"
        if dep_info.is_transitive:
            description += f"\n(Transitive dependency via {dep_info.parent_package})"

        # Build fix suggestion
        fix = ""
        if osv_vuln.fixed_versions:
            fix = f"Upgrade to version: {', '.join(osv_vuln.fixed_versions[:3])}"
        else:
            fix = "Check OSV advisory for available fixes."

        # Build Cwe_id from OSV ID
        cwe_id = None
        if osv_vuln.cve_ids:
            cwe_id = osv_vuln.cve_ids[0]
        else:
            cwe_id = osv_vuln.osv_id

        # Determine severity
        severity = osv_vuln.severity
        cvss = osv_vuln.cvss_score or 5.0

        # Adjust severity based on KEV and EPSS
        if osv_vuln.cisa_kev:
            severity = "CRITICAL"
        elif osv_vuln.epss_score and osv_vuln.epss_score > 0.5:
            severity = "HIGH" if severity != "CRITICAL" else severity

        # Map to CWE for SCA vulnerabilities
        cwe_name = "Using Components with Known Vulnerabilities"
        cwe_code = "CWE-1104"

        return Vulnerability(
            scan_id=scan_id,
            file_path=dep_info.file_source,
            line_number=0,
            severity=severity,
            category="Vulnerable Dependency",
            cwe_id=cwe_code,
            cwe_name=cwe_name,
            title=f"{osv_vuln.summary} ({dep_info.name}@{dep_info.version})",
            description=description,
            code_snippet=f"Package: {dep_info.name}\nVersion: {dep_info.version}\nEcosystem: {dep_info.ecosystem}",
            fix_suggestion=fix,
            tool_source=self.tool_name,
            cvss_score=cvss,
            owasp_category="A06",
            confidence="HIGH",
            created_at=datetime.utcnow(),
        )

    @staticmethod
    def _cvss_to_severity(cvss_score: float) -> str:
        """Convert CVSS score to severity string."""
        if cvss_score >= 9.0:
            return "CRITICAL"
        elif cvss_score >= 7.0:
            return "HIGH"
        elif cvss_score >= 4.0:
            return "MEDIUM"
        elif cvss_score > 0.0:
            return "LOW"
        return "INFO"

    async def close(self) -> None:
        """Close the HTTP client."""
        if self._client and not self._client.is_closed:
            await self._client.aclose()

    def is_available(self) -> bool:
        """Check if the OSV scanner is available (always available - uses API)."""
        return True
