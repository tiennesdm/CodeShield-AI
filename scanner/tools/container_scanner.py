"""
Container & IaC Security Scanner for CodeShield AI.

Scans Dockerfiles, Kubernetes manifests, Terraform files, and Helm charts
for security misconfigurations and compliance violations.

Also integrates with Trivy CLI for deep image vulnerability scanning and
supports Checkov-style YAML-based policy checks.

Features:
- Dockerfile security scanning
- Kubernetes manifest security scanning
- Terraform security scanning
- Helm chart security scanning
- Trivy CLI integration for image scanning
- Checkov-style policy checks
"""

import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from models.vulnerability import Vulnerability
from utils.logger import get_logger

logger = get_logger(__name__)

# ============================================================================
# Policy Definitions (Checkov-style)
# ============================================================================

CHECKOV_POLICIES = {
    "dockerfile": [
        {
            "id": "CKV_DOCKER_1",
            "name": "Ensure FROM image uses specific tag",
            "description": "Using 'latest' tag in FROM instruction can lead to unpredictable builds",
            "severity": "MEDIUM",
            "cwe": "CWE-1104",
        },
        {
            "id": "CKV_DOCKER_2",
            "name": "Ensure HEALTHCHECK instruction is present",
            "description": "HEALTHCHECK instruction is missing - container health cannot be monitored",
            "severity": "LOW",
            "cwe": "CWE-693",
        },
        {
            "id": "CKV_DOCKER_3",
            "name": "Ensure USER instruction is present",
            "description": "Container runs as root - USER instruction is missing",
            "severity": "HIGH",
            "cwe": "CWE-250",
        },
        {
            "id": "CKV_DOCKER_4",
            "name": "Ensure COPY instead of ADD",
            "description": "ADD instruction should be replaced with COPY for better transparency",
            "severity": "LOW",
            "cwe": "CWE-829",
        },
        {
            "id": "CKV_DOCKER_5",
            "name": "No secrets in ENV/ARG instructions",
            "description": "Potential secret exposed in ENV or ARG instruction",
            "severity": "CRITICAL",
            "cwe": "CWE-798",
        },
        {
            "id": "CKV_DOCKER_6",
            "name": "Ensure multi-stage build",
            "description": "Consider using multi-stage builds to reduce image size and attack surface",
            "severity": "MEDIUM",
            "cwe": "CWE-1008",
        },
        {
            "id": "CKV_DOCKER_7",
            "name": "Ensure exposed ports are documented",
            "description": "EXPOSE instruction should document all exposed ports",
            "severity": "INFO",
            "cwe": "CWE-200",
        },
        {
            "id": "CKV_DOCKER_8",
            "name": "Do not use sudo in Dockerfile",
            "description": "Using sudo in Dockerfile can lead to privilege escalation",
            "severity": "HIGH",
            "cwe": "CWE-250",
        },
    ],
    "kubernetes": [
        {
            "id": "CKV_K8S_1",
            "name": "Containers must not run as privileged",
            "description": "Privileged container can access host resources",
            "severity": "CRITICAL",
            "cwe": "CWE-250",
        },
        {
            "id": "CKV_K8S_2",
            "name": "Containers must not use hostNetwork",
            "description": "Using hostNetwork bypasses network isolation",
            "severity": "HIGH",
            "cwe": "CWE-284",
        },
        {
            "id": "CKV_K8S_3",
            "name": "Containers must not use hostPID",
            "description": "Using hostPID allows access to host process namespace",
            "severity": "HIGH",
            "cwe": "CWE-284",
        },
        {
            "id": "CKV_K8S_4",
            "name": "Containers must not use hostIPC",
            "description": "Using hostIPC allows access to host IPC namespace",
            "severity": "HIGH",
            "cwe": "CWE-284",
        },
        {
            "id": "CKV_K8S_5",
            "name": "Missing securityContext runAsNonRoot",
            "description": "Container should run as non-root user",
            "severity": "HIGH",
            "cwe": "CWE-250",
        },
        {
            "id": "CKV_K8S_6",
            "name": "Missing resource limits",
            "description": "Container is missing CPU/memory resource limits",
            "severity": "MEDIUM",
            "cwe": "CWE-770",
        },
        {
            "id": "CKV_K8S_7",
            "name": "Missing readOnlyRootFilesystem",
            "description": "Container root filesystem should be read-only",
            "severity": "MEDIUM",
            "cwe": "CWE-276",
        },
        {
            "id": "CKV_K8S_8",
            "name": "Secrets should not be in env vars",
            "description": "Sensitive data should use Kubernetes Secrets, not environment variables",
            "severity": "HIGH",
            "cwe": "CWE-798",
        },
        {
            "id": "CKV_K8S_9",
            "name": "ServiceAccount should not have excessive permissions",
            "description": "ServiceAccount should follow principle of least privilege",
            "severity": "MEDIUM",
            "cwe": "CWE-250",
        },
        {
            "id": "CKV_K8S_10",
            "name": "NetworkPolicy should be defined",
            "description": "Missing NetworkPolicy for pod network isolation",
            "severity": "MEDIUM",
            "cwe": "CWE-284",
        },
    ],
    "terraform": [
        {
            "id": "CKV_TF_1",
            "name": "S3 bucket should not be publicly accessible",
            "description": "S3 bucket ACL allows public access",
            "severity": "CRITICAL",
            "cwe": "CWE-284",
        },
        {
            "id": "CKV_TF_2",
            "name": "Security group should not allow 0.0.0.0/0",
            "description": "Security group is open to the entire internet",
            "severity": "HIGH",
            "cwe": "CWE-284",
        },
        {
            "id": "CKV_TF_3",
            "name": "Storage should be encrypted",
            "description": "Storage resource is missing encryption configuration",
            "severity": "HIGH",
            "cwe": "CWE-311",
        },
        {
            "id": "CKV_TF_4",
            "name": "No hardcoded credentials",
            "description": "Potential hardcoded credentials detected in Terraform file",
            "severity": "CRITICAL",
            "cwe": "CWE-798",
        },
    ],
    "helm": [
        {
            "id": "CKV_HELM_1",
            "name": "Security context should be defined",
            "description": "values.yaml should define security context defaults",
            "severity": "HIGH",
            "cwe": "CWE-250",
        },
        {
            "id": "CKV_HELM_2",
            "name": "Image tag should be pinned",
            "description": "Image tag should not use 'latest' or be empty",
            "severity": "MEDIUM",
            "cwe": "CWE-1104",
        },
        {
            "id": "CKV_HELM_3",
            "name": "Resource limits should be defined",
            "description": "values.yaml should define resource limits",
            "severity": "MEDIUM",
            "cwe": "CWE-770",
        },
    ],
}

# Secret detection patterns for ENV/ARG instructions
SECRET_PATTERNS = [
    (r"(?i)(?:password|passwd|pwd)\s*=\s*[^\s\"']+", "Password in environment variable"),
    (r"(?i)(?:secret|api_key|apikey|api-key)\s*=\s*[^\s\"']+", "API key in environment variable"),
    (r"(?i)(?:token|auth_token|access_token)\s*=\s*[^\s\"']+", "Token in environment variable"),
    (r"(?i)(?:aws_access_key_id|aws_secret_access_key)\s*=\s*[^\s\"']+", "AWS credentials in environment variable"),
    (r"(?i)(?:private_key|ssh_key)\s*=\s*[^\s\"']+", "Private key in environment variable"),
    (r"(?i)bearer\s+[a-zA-Z0-9_\-\.]+", "Bearer token"),
    (r"AKIA[0-9A-Z]{16}", "AWS Access Key ID"),
]


# ============================================================================
# Data Classes
# ============================================================================

@dataclass
class ContainerFinding:
    """A single container/IaC security finding."""

    policy_id: str
    rule_name: str
    description: str
    severity: str
    cwe: str
    file_path: str
    line_number: int
    resource: str
    remediation: str


@dataclass
class TrivyResult:
    """Result from Trivy image scan."""

    target: str
    vulnerabilities: List[Dict[str, Any]] = field(default_factory=list)
    misconfigurations: List[Dict[str, Any]] = field(default_factory=list)


# ============================================================================
# Container Scanner
# ============================================================================

class ContainerScanner:
    """
    Comprehensive container and IaC security scanner.

    Scans Dockerfiles, Kubernetes manifests, Terraform files, and Helm charts
    for security misconfigurations. Also integrates with Trivy for deep image
    vulnerability scanning.
    """

    def __init__(self) -> None:
        """Initialize the container scanner."""
        self.policies = CHECKOV_POLICIES
        self.findings: List[ContainerFinding] = []
        self._trivy_available: Optional[bool] = None

    @property
    def trivy_available(self) -> bool:
        """Check if Trivy CLI is available."""
        if self._trivy_available is None:
            self._trivy_available = shutil.which("trivy") is not None
        return self._trivy_available

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def scan(
        self,
        source_path: str,
        scan_id: str,
        scan_images: bool = False,
    ) -> List[Vulnerability]:
        """
        Scan a directory for container/IaC security issues.

        Args:
            source_path: Path to the source directory
            scan_id: The scan identifier
            scan_images: Whether to also scan container images with Trivy

        Returns:
            List of Vulnerability objects
        """
        self.findings = []
        path = Path(source_path)

        if not path.exists():
            logger.warning("Source path does not exist: %s", source_path)
            return []

        # Scan Dockerfiles
        dockerfiles = list(path.rglob("Dockerfile*"))
        for df in dockerfiles:
            if df.is_file() and not any(part.startswith(".") for part in df.parts):
                self._scan_dockerfile(str(df), scan_id)

        # Scan Kubernetes manifests
        k8s_files = list(path.rglob("*.yaml")) + list(path.rglob("*.yml"))
        for kf in k8s_files:
            if kf.is_file() and not any(part.startswith(".") for part in kf.parts):
                self._scan_kubernetes(str(kf), scan_id)

        # Scan Terraform files
        tf_files = list(path.rglob("*.tf"))
        for tf in tf_files:
            if tf.is_file():
                self._scan_terraform(str(tf), scan_id)

        # Scan Helm charts
        helm_values = list(path.rglob("values.yaml"))
        for hv in helm_values:
            if hv.is_file():
                self._scan_helm_chart(str(hv), scan_id)

        # Trivy deep scan (if available and requested)
        if scan_images and self.trivy_available:
            self._run_trivy_filesystem_scan(source_path, scan_id)

        return self._findings_to_vulnerabilities(scan_id)

    async def scan_docker_image(
        self,
        image_name: str,
        scan_id: str,
    ) -> List[Vulnerability]:
        """
        Scan a Docker image with Trivy.

        Args:
            image_name: Name of the Docker image to scan
            scan_id: The scan identifier

        Returns:
            List of Vulnerability objects
        """
        if not self.trivy_available:
            logger.warning("Trivy not available for image scanning")
            return []

        self.findings = []
        trivy_results = self._run_trivy_image_scan(image_name)
        self._findings.extend(
            self._trivy_results_to_findings(trivy_results, scan_id)
        )
        return self._findings_to_vulnerabilities(scan_id)

    async def scan_containerfile(
        self,
        content: str,
        scan_id: str,
        filename: str = "Dockerfile",
    ) -> List[Vulnerability]:
        """
        Scan Dockerfile content directly (for CI/CD integration).

        Args:
            content: Dockerfile content as string
            scan_id: The scan identifier
            filename: Original filename

        Returns:
            List of Vulnerability objects
        """
        self.findings = []
        self._scan_dockerfile_content(content, filename, scan_id)
        return self._findings_to_vulnerabilities(scan_id)

    # ------------------------------------------------------------------
    # Dockerfile Scanning
    # ------------------------------------------------------------------

    def _scan_dockerfile(self, file_path: str, scan_id: str) -> None:
        """Scan a Dockerfile for security issues."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            self._scan_dockerfile_content(content, file_path, scan_id)
        except Exception as e:
            logger.error("Failed to scan Dockerfile %s: %s", file_path, e)

    def _scan_dockerfile_content(
        self, content: str, file_path: str, scan_id: str
    ) -> None:
        """Scan Dockerfile content line by line."""
        lines = content.split("\n")
        has_user = False
        has_healthcheck = False
        from_count = 0
        has_multi_stage = False

        for line_no, line in enumerate(lines, 1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue

            # Parse instruction (handle continuation lines)
            instruction = self._parse_dockerfile_instruction(stripped)

            if instruction:
                cmd, args = instruction

                # CKV_DOCKER_1: FROM latest tag
                if cmd == "FROM":
                    from_count += 1
                    self._check_from_instruction(args, file_path, line_no)

                # CKV_DOCKER_3: USER instruction
                elif cmd == "USER":
                    has_user = True

                # CKV_DOCKER_2: HEALTHCHECK
                elif cmd == "HEALTHCHECK":
                    has_healthcheck = True

                # CKV_DOCKER_4: ADD vs COPY
                elif cmd == "ADD":
                    self._add_finding(
                        "CKV_DOCKER_4",
                        file_path, line_no,
                        f"ADD {args}",
                        "Replace ADD with COPY unless extracting tar or using URL",
                    )

                # CKV_DOCKER_5: Secrets in ENV/ARG
                elif cmd in ("ENV", "ARG"):
                    self._check_env_secrets(args, file_path, line_no)

                # CKV_DOCKER_8: sudo usage
                elif cmd in ("RUN",):
                    if "sudo" in args.lower():
                        self._add_finding(
                            "CKV_DOCKER_8",
                            file_path, line_no,
                            f"RUN {args}",
                            "Remove sudo usage. Use USER instruction instead.",
                        )

        # Check for missing USER instruction
        if not has_user:
            self._add_finding(
                "CKV_DOCKER_3",
                file_path, 1,
                "Dockerfile",
                "Add 'USER <non-root>' instruction to run container as non-root",
            )

        # Check for missing HEALTHCHECK
        if not has_healthcheck:
            self._add_finding(
                "CKV_DOCKER_2",
                file_path, 1,
                "Dockerfile",
                "Add 'HEALTHCHECK' instruction to monitor container health",
            )

        # CKV_DOCKER_6: Multi-stage build check
        if from_count <= 1:
            self._add_finding(
                "CKV_DOCKER_6",
                file_path, 1,
                "Dockerfile",
                "Consider using multi-stage builds to reduce image size",
            )

    def _parse_dockerfile_instruction(
        self, line: str
    ) -> Optional[Tuple[str, str]]:
        """Parse a Dockerfile instruction into command and arguments."""
        # Match instruction at start of line (case insensitive)
        match = re.match(r"^([A-Za-z]+)\s+(.+)$", line)
        if match:
            return match.group(1).upper(), match.group(2).strip()
        return None

    def _check_from_instruction(
        self, args: str, file_path: str, line_no: int
    ) -> None:
        """Check FROM instruction for 'latest' tag."""
        # Parse image reference
        parts = args.split()
        image_ref = parts[0] if parts else args

        if ":" not in image_ref or image_ref.endswith(":latest"):
            self._add_finding(
                "CKV_DOCKER_1",
                file_path, line_no,
                f"FROM {args}",
                f"Use a specific version tag instead of 'latest' for '{image_ref}'",
            )

    def _check_env_secrets(
        self, args: str, file_path: str, line_no: int
    ) -> None:
        """Check ENV/ARG instructions for exposed secrets."""
        for pattern, description in SECRET_PATTERNS:
            if re.search(pattern, args):
                self._add_finding(
                    "CKV_DOCKER_5",
                    file_path, line_no,
                    f"ENV/ARG {args[:50]}...",
                    f"{description}. Use Docker secrets or mount at runtime.",
                )
                break

    # ------------------------------------------------------------------
    # Kubernetes Scanning
    # ------------------------------------------------------------------

    def _scan_kubernetes(self, file_path: str, scan_id: str) -> None:
        """Scan a Kubernetes YAML manifest for security issues."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()

            # Parse all documents in the YAML file
            docs = self._split_yaml_documents(content)

            for doc_idx, doc in enumerate(docs):
                if not doc.strip():
                    continue
                self._scan_k8s_document(doc, file_path, doc_idx, scan_id)

        except Exception as e:
            logger.error("Failed to scan K8s manifest %s: %s", file_path, e)

    def _split_yaml_documents(self, content: str) -> List[str]:
        """Split YAML content into separate documents."""
        return [doc for doc in content.split("---") if doc.strip()]

    def _scan_k8s_document(
        self, doc: str, file_path: str, doc_idx: int, scan_id: str
    ) -> None:
        """Scan a single Kubernetes document."""
        try:
            import yaml
            manifest = yaml.safe_load(doc)
        except Exception:
            # If yaml module not available or parsing fails, use regex
            self._scan_k8s_document_regex(doc, file_path, scan_id)
            return

        if not manifest or not isinstance(manifest, dict):
            return

        kind = manifest.get("kind", "")
        metadata = manifest.get("metadata", {}) or {}
        name = metadata.get("name", f"doc-{doc_idx}")

        # Scan Pod / Deployment / StatefulSet / DaemonSet
        if kind in ("Pod", "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job", "CronJob"):
            self._scan_k8s_workload(manifest, kind, name, file_path, scan_id)

        # Scan ServiceAccount
        elif kind == "ServiceAccount":
            self._scan_k8s_serviceaccount(manifest, name, file_path, scan_id)

        # Scan Role / ClusterRole
        elif kind in ("Role", "ClusterRole"):
            self._scan_k8s_role(manifest, kind, name, file_path, scan_id)

        # Scan NetworkPolicy
        elif kind == "NetworkPolicy":
            pass  # NetworkPolicy presence is good

    def _scan_k8s_workload(
        self,
        manifest: Dict[str, Any],
        kind: str,
        name: str,
        file_path: str,
        scan_id: str,
    ) -> None:
        """Scan a Kubernetes workload resource."""
        spec = manifest.get("spec", {}) or {}

        # Handle different workload structures
        if "template" in spec:
            pod_spec = spec.get("template", {}).get("spec", {}) or {}
        elif kind == "Pod":
            pod_spec = spec
        else:
            pod_spec = {}

        containers = []
        if "containers" in pod_spec:
            containers.extend(pod_spec.get("containers", []))
        if "initContainers" in pod_spec:
            containers.extend(pod_spec.get("initContainers", []))

        for container in containers:
            if not isinstance(container, dict):
                continue
            container_name = container.get("name", "unknown")
            resource = f"{kind}/{name}/{container_name}"

            # Security context
            security_context = container.get("securityContext", {}) or {}
            pod_security_context = pod_spec.get("securityContext", {}) or {}

            # CKV_K8S_1: Privileged
            if security_context.get("privileged", False):
                self._add_finding(
                    "CKV_K8S_1", file_path, 1, resource,
                    "Remove 'privileged: true' from securityContext",
                )

            # CKV_K8S_2: hostNetwork
            if pod_spec.get("hostNetwork", False):
                self._add_finding(
                    "CKV_K8S_2", file_path, 1, resource,
                    "Remove 'hostNetwork: true' from pod spec",
                )

            # CKV_K8S_3: hostPID
            if pod_spec.get("hostPID", False):
                self._add_finding(
                    "CKV_K8S_3", file_path, 1, resource,
                    "Remove 'hostPID: true' from pod spec",
                )

            # CKV_K8S_4: hostIPC
            if pod_spec.get("hostIPC", False):
                self._add_finding(
                    "CKV_K8S_4", file_path, 1, resource,
                    "Remove 'hostIPC: true' from pod spec",
                )

            # CKV_K8S_5: runAsNonRoot
            sc_run_as = security_context.get("runAsNonRoot")
            psc_run_as = pod_security_context.get("runAsNonRoot")
            if sc_run_as is None and psc_run_as is None:
                self._add_finding(
                    "CKV_K8S_5", file_path, 1, resource,
                    "Add 'runAsNonRoot: true' to securityContext",
                )

            # CKV_K8S_6: Resource limits
            resources = container.get("resources", {}) or {}
            limits = resources.get("limits", {}) or {}
            if not limits.get("memory") or not limits.get("cpu"):
                self._add_finding(
                    "CKV_K8S_6", file_path, 1, resource,
                    "Add memory and CPU resource limits",
                )

            # CKV_K8S_7: readOnlyRootFilesystem
            if not security_context.get("readOnlyRootFilesystem", False):
                self._add_finding(
                    "CKV_K8S_7", file_path, 1, resource,
                    "Add 'readOnlyRootFilesystem: true' to securityContext",
                )

            # CKV_K8S_8: Secrets in env
            env = container.get("env", []) or []
            for env_var in env:
                if not isinstance(env_var, dict):
                    continue
                env_name = env_var.get("name", "")
                env_value = env_var.get("value", "")
                for pattern, _ in SECRET_PATTERNS:
                    if re.search(pattern, f"{env_name}={env_value}"):
                        self._add_finding(
                            "CKV_K8S_8", file_path, 1,
                            f"{resource}/env/{env_name}",
                            "Use Kubernetes Secrets with secretKeyRef instead of hardcoded env vars",
                        )
                        break

        # CKV_K8S_10: Check if NetworkPolicy exists in namespace
        # This is a file-level check - we'll note it as best-practice
        if kind in ("Pod", "Deployment") and not self._has_network_policy_reference(file_path):
            self._add_finding(
                "CKV_K8S_10", file_path, 1, f"{kind}/{name}",
                "Consider adding a NetworkPolicy for pod network isolation",
            )

    def _scan_k8s_serviceaccount(
        self,
        manifest: Dict[str, Any],
        name: str,
        file_path: str,
        scan_id: str,
    ) -> None:
        """Scan a ServiceAccount for excessive permissions."""
        # Check automountServiceAccountToken
        if manifest.get("automountServiceAccountToken", True):
            self._add_finding(
                "CKV_K8S_9", file_path, 1, f"ServiceAccount/{name}",
                "Set 'automountServiceAccountToken: false' unless pods need API access",
            )

    def _scan_k8s_role(
        self,
        manifest: Dict[str, Any],
        kind: str,
        name: str,
        file_path: str,
        scan_id: str,
    ) -> None:
        """Scan a Role/ClusterRole for wildcard permissions."""
        rules = manifest.get("rules", []) or []
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            api_groups = rule.get("apiGroups", [])
            resources = rule.get("resources", [])
            verbs = rule.get("verbs", [])

            if "*" in api_groups and "*" in resources and "*" in verbs:
                self._add_finding(
                    "CKV_K8S_9", file_path, 1, f"{kind}/{name}",
                    "Avoid wildcard ('*') permissions in rules - use least privilege",
                )

    def _has_network_policy_reference(self, file_path: str) -> bool:
        """Check if the directory has any NetworkPolicy manifests."""
        # Simplified: check if file path contains 'network' keyword
        return "network" in file_path.lower()

    def _scan_k8s_document_regex(
        self, doc: str, file_path: str, scan_id: str
    ) -> None:
        """Fallback regex-based scanning for K8s documents."""
        if r"privileged:\s*true" in doc:
            line_no = self._find_line_number(doc, "privileged")
            self._add_finding(
                "CKV_K8S_1", file_path, line_no, "container",
                "Remove 'privileged: true'",
            )
        if r"hostNetwork:\s*true" in doc:
            line_no = self._find_line_number(doc, "hostNetwork")
            self._add_finding(
                "CKV_K8S_2", file_path, line_no, "pod",
                "Remove 'hostNetwork: true'",
            )
        if r"hostPID:\s*true" in doc:
            line_no = self._find_line_number(doc, "hostPID")
            self._add_finding(
                "CKV_K8S_3", file_path, line_no, "pod",
                "Remove 'hostPID: true'",
            )
        if r"hostIPC:\s*true" in doc:
            line_no = self._find_line_number(doc, "hostIPC")
            self._add_finding(
                "CKV_K8S_4", file_path, line_no, "pod",
                "Remove 'hostIPC: true'",
            )

    # ------------------------------------------------------------------
    # Terraform Scanning
    # ------------------------------------------------------------------

    def _scan_terraform(self, file_path: str, scan_id: str) -> None:
        """Scan Terraform files for security issues."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            self._scan_terraform_content(content, file_path, scan_id)
        except Exception as e:
            logger.error("Failed to scan Terraform file %s: %s", file_path, e)

    def _scan_terraform_content(
        self, content: str, file_path: str, scan_id: str
    ) -> None:
        """Scan Terraform content for security issues."""
        lines = content.split("\n")

        in_resource = False
        resource_type = ""
        resource_name = ""
        brace_depth = 0

        for line_no, line in enumerate(lines, 1):
            stripped = line.strip()

            # Track resource blocks
            resource_match = re.match(
                r'resource\s+"([^"]+)"\s+"([^"]+)"', stripped
            )
            if resource_match:
                in_resource = True
                resource_type = resource_match.group(1)
                resource_name = resource_match.group(2)
                brace_depth = 1
                continue

            if in_resource:
                brace_depth += stripped.count("{")
                brace_depth -= stripped.count("}")
                if brace_depth <= 0:
                    in_resource = False
                    continue

                resource = f"{resource_type}.{resource_name}"

                # CKV_TF_1: Public S3 bucket
                if resource_type == "aws_s3_bucket":
                    if re.search(r'acl\s*=\s*"public-read"', stripped):
                        self._add_finding(
                            "CKV_TF_1", file_path, line_no, resource,
                            "Remove 'public-read' ACL. Use bucket policy with specific principals.",
                        )
                    if re.search(r'acl\s*=\s*"public-read-write"', stripped):
                        self._add_finding(
                            "CKV_TF_1", file_path, line_no, resource,
                            "Remove 'public-read-write' ACL. Use bucket policy with specific principals.",
                        )

                # CKV_TF_2: Open security group
                if resource_type == "aws_security_group":
                    if "0.0.0.0/0" in stripped:
                        self._add_finding(
                            "CKV_TF_2", file_path, line_no, resource,
                            "Restrict CIDR block instead of 0.0.0.0/0. Use specific IP ranges.",
                        )

                # CKV_TF_3: Unencrypted storage
                if resource_type in (
                    "aws_db_instance", "aws_rds_cluster", "aws_ebs_volume",
                    "aws_s3_bucket", "aws_dynamodb_table",
                ):
                    if re.search(r'encrypted\s*=\s*false', stripped):
                        self._add_finding(
                            "CKV_TF_3", file_path, line_no, resource,
                            "Enable encryption by setting 'encrypted = true'",
                        )
                    if "encrypted" not in content.lower() and resource_type in (
                        "aws_db_instance", "aws_ebs_volume",
                    ):
                        # Check if encryption is explicitly missing
                        if line_no == len(lines):
                            self._add_finding(
                                "CKV_TF_3", file_path, 1, resource,
                                "Add encryption configuration (encrypted = true)",
                            )

                # CKV_TF_4: Hardcoded credentials
                if re.search(
                    r'(?i)(password|secret|token|key)\s*=\s*"[^"]+"',
                    stripped,
                ):
                    # Exclude variable references and data sources
                    if "var." not in stripped and "data." not in stripped:
                        self._add_finding(
                            "CKV_TF_4", file_path, line_no, resource,
                            "Use variables or secret management instead of hardcoded credentials",
                        )

    # ------------------------------------------------------------------
    # Helm Chart Scanning
    # ------------------------------------------------------------------

    def _scan_helm_chart(self, file_path: str, scan_id: str) -> None:
        """Scan Helm values.yaml for security configuration."""
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                content = f.read()
            self._scan_helm_content(content, file_path, scan_id)
        except Exception as e:
            logger.error("Failed to scan Helm chart %s: %s", file_path, e)

    def _scan_helm_content(
        self, content: str, file_path: str, scan_id: str
    ) -> None:
        """Scan Helm values.yaml content for security issues."""
        try:
            import yaml
            values = yaml.safe_load(content)
        except Exception:
            # Fallback to regex
            self._scan_helm_regex(content, file_path, scan_id)
            return

        if not values or not isinstance(values, dict):
            return

        # CKV_HELM_1: Security context
        if "securityContext" not in values:
            # Check nested in podSecurityContext
            has_pod_sc = False
            for key in values:
                if isinstance(values[key], dict):
                    if "podSecurityContext" in values[key] or "securityContext" in values[key]:
                        has_pod_sc = True
                        break
            if not has_pod_sc:
                self._add_finding(
                    "CKV_HELM_1", file_path, 1, "values.yaml",
                    "Define securityContext in values.yaml (runAsNonRoot, readOnlyRootFilesystem)",
                )

        # CKV_HELM_2: Image tag pinning
        image = values.get("image", {})
        if isinstance(image, dict):
            tag = image.get("tag", "")
            if tag in ("latest", "", None):
                self._add_finding(
                    "CKV_HELM_2", file_path, 1, "values.yaml/image",
                    "Pin image tag to a specific version instead of 'latest'",
                )

        # CKV_HELM_3: Resource limits
        resources = values.get("resources", {})
        if not resources or not isinstance(resources, dict):
            # Check nested in containers
            has_limits = False
            for key, val in values.items():
                if isinstance(val, dict) and "resources" in val:
                    res = val.get("resources", {})
                    if res and isinstance(res, dict) and "limits" in res:
                        has_limits = True
                        break
            if not has_limits:
                self._add_finding(
                    "CKV_HELM_3", file_path, 1, "values.yaml",
                    "Define resource limits (memory, CPU) in values.yaml",
                )

    def _scan_helm_regex(
        self, content: str, file_path: str, scan_id: str
    ) -> None:
        """Fallback regex-based Helm scanning."""
        # Check for security context
        if "securityContext" not in content:
            self._add_finding(
                "CKV_HELM_1", file_path, 1, "values.yaml",
                "Define securityContext in values.yaml",
            )
        # Check for latest tag
        if re.search(r'tag:\s*latest', content):
            self._add_finding(
                "CKV_HELM_2", file_path, 1, "values.yaml",
                "Pin image tag to a specific version",
            )

    # ------------------------------------------------------------------
    # Trivy Integration
    # ------------------------------------------------------------------

    def _run_trivy_filesystem_scan(
        self, source_path: str, scan_id: str
    ) -> List[TrivyResult]:
        """Run Trivy filesystem scan for IaC misconfigurations."""
        if not self.trivy_available:
            return []

        results: List[TrivyResult] = []
        try:
            cmd = [
                "trivy", "filesystem",
                "--scanners", "misconfig",
                "--format", "json",
                "--quiet",
                source_path,
            ]
            output = subprocess.run(
                cmd, capture_output=True, text=True, timeout=300,
            )
            if output.returncode == 0 and output.stdout:
                try:
                    report = json.loads(output.stdout)
                    for result_data in report.get("Results", []):
                        trivy_result = TrivyResult(
                            target=result_data.get("Target", ""),
                            misconfigurations=result_data.get(
                                "Misconfigurations", []
                            ),
                        )
                        results.append(trivy_result)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse Trivy JSON output")
        except subprocess.TimeoutExpired:
            logger.warning("Trivy filesystem scan timed out")
        except Exception as e:
            logger.error("Trivy scan failed: %s", e)

        # Convert Trivy results to findings
        for tr in results:
            for mc in tr.misconfigurations:
                finding = ContainerFinding(
                    policy_id=mc.get("ID", "TRIVY-IAC"),
                    rule_name=mc.get("Title", "Trivy Finding"),
                    description=mc.get("Description", "") + "\n" + mc.get("Message", ""),
                    severity=self._map_trivy_severity(mc.get("Severity", "UNKNOWN")),
                    cwe=mc.get("CWEIDs", ["CWE-1008"])[0] if mc.get("CWEIDs") else "CWE-1008",
                    file_path=tr.target,
                    line_number=mc.get("CauseMetadata", {}).get("StartLine", 1),
                    resource=mc.get("Type", "unknown"),
                    remediation=mc.get("Resolution", "Review and fix the misconfiguration"),
                )
                self.findings.append(finding)

        return results

    def _run_trivy_image_scan(self, image_name: str) -> List[TrivyResult]:
        """Run Trivy image vulnerability scan."""
        if not self.trivy_available:
            return []

        results: List[TrivyResult] = []
        try:
            cmd = [
                "trivy", "image",
                "--scanners", "vuln",
                "--format", "json",
                "--quiet",
                image_name,
            ]
            output = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600,
            )
            if output.returncode == 0 and output.stdout:
                try:
                    report = json.loads(output.stdout)
                    for result_data in report.get("Results", []):
                        trivy_result = TrivyResult(
                            target=result_data.get("Target", ""),
                            vulnerabilities=result_data.get(
                                "Vulnerabilities", []
                            ),
                        )
                        results.append(trivy_result)
                except json.JSONDecodeError:
                    logger.warning("Failed to parse Trivy image scan output")
        except subprocess.TimeoutExpired:
            logger.warning("Trivy image scan timed out")
        except Exception as e:
            logger.error("Trivy image scan failed: %s", e)

        return results

    def _trivy_results_to_findings(
        self, results: List[TrivyResult], scan_id: str
    ) -> List[ContainerFinding]:
        """Convert Trivy vulnerability results to ContainerFindings."""
        findings: List[ContainerFinding] = []
        for tr in results:
            for vuln in tr.vulnerabilities:
                finding = ContainerFinding(
                    policy_id=vuln.get("VulnerabilityID", "CVE-UNKNOWN"),
                    rule_name=vuln.get("Title", "Container Vulnerability"),
                    description=f"{vuln.get('Description', '')}\nInstalled: {vuln.get('InstalledVersion', 'unknown')}\nFixed: {vuln.get('FixedVersion', 'N/A')}",
                    severity=self._map_trivy_severity(vuln.get("Severity", "UNKNOWN")),
                    cwe=vuln.get("CweIDs", ["CWE-1008"])[0] if vuln.get("CweIDs") else "CWE-1008",
                    file_path=tr.target,
                    line_number=1,
                    resource=vuln.get("PkgName", "unknown"),
                    remediation=f"Upgrade to {vuln.get('FixedVersion', 'latest')}",
                )
                findings.append(finding)
        return findings

    def _map_trivy_severity(self, severity: str) -> str:
        """Map Trivy severity to our severity levels."""
        mapping = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "LOW",
            "UNKNOWN": "INFO",
        }
        return mapping.get(severity.upper(), "INFO")

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _add_finding(
        self,
        policy_id: str,
        file_path: str,
        line_number: int,
        resource: str,
        remediation: str,
    ) -> None:
        """Add a finding to the findings list."""
        policy = self._get_policy(policy_id)
        if policy is None:
            return

        finding = ContainerFinding(
            policy_id=policy_id,
            rule_name=policy["name"],
            description=policy["description"],
            severity=policy["severity"],
            cwe=policy["cwe"],
            file_path=file_path,
            line_number=line_number,
            resource=resource,
            remediation=remediation,
        )
        self.findings.append(finding)

    def _get_policy(self, policy_id: str) -> Optional[Dict[str, str]]:
        """Get policy definition by ID."""
        for category_policies in self.policies.values():
            for policy in category_policies:
                if policy["id"] == policy_id:
                    return policy
        return None

    def _find_line_number(self, content: str, keyword: str) -> int:
        """Find the line number of a keyword in content."""
        for i, line in enumerate(content.split("\n"), 1):
            if keyword in line:
                return i
        return 1

    def _findings_to_vulnerabilities(
        self, scan_id: str
    ) -> List[Vulnerability]:
        """Convert ContainerFindings to Vulnerability objects."""
        vulns: List[Vulnerability] = []
        for f in self.findings:
            vuln = Vulnerability(
                scan_id=scan_id,
                file_path=f.file_path,
                line_number=f.line_number,
                severity=f.severity,
                category=f"Container/IaC: {f.rule_name}",
                cwe_id=f.cwe,
                cwe_name=f.rule_name,
                title=(
                    f"{f.rule_name}: {f.resource}"
                    if f.resource and len(f.resource) < 80
                    else f.rule_name
                ),
                description=f"[{f.policy_id}] {f.description}\n\nResource: {f.resource}",
                code_snippet=f.resource,
                fix_suggestion=f.remediation,
                tool_source="container_scanner",
                confidence="HIGH",
            )
            vulns.append(vuln)
        return vulns

    # ------------------------------------------------------------------
    # Checkov-style Policy Engine
    # ------------------------------------------------------------------

    def load_custom_policies(self, policies_path: str) -> int:
        """
        Load custom Checkov-style policies from YAML files.

        Args:
            policies_path: Path to directory containing policy YAML files

        Returns:
            Number of policies loaded
        """
        import yaml

        count = 0
        policy_dir = Path(policies_path)
        if not policy_dir.exists():
            return 0

        for policy_file in policy_dir.rglob("*.yaml"):
            try:
                with open(policy_file, "r", encoding="utf-8") as f:
                    policy = yaml.safe_load(f)

                if not policy or "policies" not in policy:
                    continue

                for p in policy["policies"]:
                    category = p.get("category", "custom")
                    if category not in self.policies:
                        self.policies[category] = []
                    self.policies[category].append({
                        "id": p.get("id", f"CUSTOM_{count}"),
                        "name": p.get("name", "Custom Policy"),
                        "description": p.get("description", ""),
                        "severity": p.get("severity", "MEDIUM"),
                        "cwe": p.get("cwe", "CWE-1008"),
                    })
                    count += 1

            except Exception as e:
                logger.warning("Failed to load policy file %s: %s", policy_file, e)

        return count

    def get_policy_summary(self) -> Dict[str, Any]:
        """Get summary of all loaded policies."""
        summary: Dict[str, Any] = {}
        for category, policies in self.policies.items():
            summary[category] = {
                "count": len(policies),
                "policies": [
                    {"id": p["id"], "name": p["name"], "severity": p["severity"]}
                    for p in policies
                ],
            }
        return summary
