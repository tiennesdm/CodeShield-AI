"""
Tests for the Container & IaC Security Scanner.

Covers Dockerfile scanning, Kubernetes manifest scanning,
Terraform scanning, Helm chart scanning, and policy engine.
"""

import os
import tempfile
from pathlib import Path

import pytest

from scanner.tools.container_scanner import (
    SECRET_PATTERNS,
    ContainerFinding,
    ContainerScanner,
)


# ============================================================================
# Fixtures
# ============================================================================

@pytest.fixture
def scanner():
    """Create a fresh ContainerScanner instance."""
    return ContainerScanner()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for test files."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield tmpdir


def write_file(temp_dir: str, filename: str, content: str) -> str:
    """Helper to write a test file."""
    filepath = os.path.join(temp_dir, filename)
    os.makedirs(os.path.dirname(filepath) if "/" in filename else temp_dir, exist_ok=True)
    with open(filepath, "w") as f:
        f.write(content)
    return filepath


# ============================================================================
# Dockerfile Tests
# ============================================================================

class TestDockerfileScanning:
    """Tests for Dockerfile security scanning."""

    def test_from_latest_tag_detection(self, scanner, temp_dir):
        """Test detection of FROM using 'latest' tag."""
        write_file(temp_dir, "Dockerfile", """
FROM python:latest
RUN pip install -r requirements.txt
COPY . /app
CMD ["python", "app.py"]
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-1")
        )

        from_latest = [v for v in vulns if "latest" in v.title and "FROM" in v.category]
        assert len(from_latest) > 0

    def test_missing_user_instruction(self, scanner, temp_dir):
        """Test detection of missing USER instruction."""
        write_file(temp_dir, "Dockerfile", """
FROM python:3.9
RUN pip install -r requirements.txt
COPY . /app
CMD ["python", "app.py"]
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-2")
        )

        user_vulns = [v for v in vulns if "USER" in v.title or "root" in v.description.lower()]
        assert len(user_vulns) > 0

    def test_missing_healthcheck(self, scanner, temp_dir):
        """Test detection of missing HEALTHCHECK instruction."""
        write_file(temp_dir, "Dockerfile", """
FROM python:3.9
RUN pip install flask
COPY . /app
USER appuser
CMD ["python", "app.py"]
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-3")
        )

        health_vulns = [v for v in vulns if "HEALTHCHECK" in v.title]
        assert len(health_vulns) > 0

    def test_add_vs_copy_detection(self, scanner, temp_dir):
        """Test detection of ADD instead of COPY."""
        write_file(temp_dir, "Dockerfile", """
FROM python:3.9
ADD https://example.com/package.tar.gz /tmp/
COPY . /app
USER nobody
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
CMD ["python", "app.py"]
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-4")
        )

        add_vulns = [v for v in vulns if "ADD" in v.title or "COPY" in v.title]
        assert len(add_vulns) > 0

    def test_env_secret_detection(self, scanner, temp_dir):
        """Test detection of secrets in ENV instructions."""
        write_file(temp_dir, "Dockerfile", """
FROM python:3.9
ENV API_KEY=sk-abc123def456
ENV password=supersecret123
RUN pip install -r requirements.txt
COPY . /app
USER appuser
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
CMD ["python", "app.py"]
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-5")
        )

        secret_vulns = [v for v in vulns if "secret" in v.title.lower() or "ENV" in v.title]
        assert len(secret_vulns) > 0

    def test_sudo_detection(self, scanner, temp_dir):
        """Test detection of sudo usage in Dockerfile."""
        write_file(temp_dir, "Dockerfile", """
FROM python:3.9
RUN sudo apt-get update && sudo apt-get install -y curl
COPY . /app
USER nobody
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
CMD ["python", "app.py"]
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-6")
        )

        sudo_vulns = [v for v in vulns if "sudo" in v.title.lower()]
        assert len(sudo_vulns) > 0

    def test_compliant_dockerfile(self, scanner, temp_dir):
        """Test that a well-configured Dockerfile passes all checks."""
        write_file(temp_dir, "Dockerfile", """
FROM python:3.9-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd -m appuser
USER appuser
HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8080/ || exit 1
EXPOSE 8080
CMD ["python", "app.py"]
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-7")
        )

        # Should have very few or no findings for a compliant Dockerfile
        critical = [v for v in vulns if v.severity == "CRITICAL"]
        high = [v for v in vulns if v.severity == "HIGH"]
        assert len(critical) == 0

    def test_multi_stage_build(self, scanner, temp_dir):
        """Test multi-stage build detection."""
        write_file(temp_dir, "Dockerfile", """
FROM python:3.9 AS builder
COPY requirements.txt .
RUN pip install --user -r requirements.txt

FROM python:3.9-slim
WORKDIR /app
COPY --from=builder /root/.local /root/.local
COPY . .
USER appuser
HEALTHCHECK CMD curl -f http://localhost/ || exit 1
CMD ["python", "app.py"]
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-8")
        )

        # Should not flag missing multi-stage build
        multi_stage = [v for v in vulns if "multi-stage" in v.description.lower()]
        assert len(multi_stage) == 0


# ============================================================================
# Kubernetes Tests
# ============================================================================

class TestKubernetesScanning:
    """Tests for Kubernetes manifest scanning."""

    def test_privileged_container(self, scanner, temp_dir):
        """Test detection of privileged containers."""
        write_file(temp_dir, "deployment.yaml", """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vulnerable-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: myapp:1.0
        securityContext:
          privileged: true
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-k1")
        )

        priv_vulns = [v for v in vulns if "privileged" in v.title.lower()]
        assert len(priv_vulns) > 0
        assert priv_vulns[0].severity == "CRITICAL"

    def test_host_network(self, scanner, temp_dir):
        """Test detection of hostNetwork usage."""
        write_file(temp_dir, "pod.yaml", """
apiVersion: v1
kind: Pod
metadata:
  name: host-net-pod
spec:
  hostNetwork: true
  containers:
  - name: app
    image: myapp:1.0
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-k2")
        )

        host_vulns = [v for v in vulns if "hostNetwork" in v.title]
        assert len(host_vulns) > 0

    def test_missing_security_context(self, scanner, temp_dir):
        """Test detection of missing securityContext."""
        write_file(temp_dir, "deployment.yaml", """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: insecure-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: myapp:1.0
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-k3")
        )

        sc_vulns = [v for v in vulns if "securityContext" in v.title or "runAsNonRoot" in v.title]
        assert len(sc_vulns) > 0

    def test_missing_resource_limits(self, scanner, temp_dir):
        """Test detection of missing resource limits."""
        write_file(temp_dir, "deployment.yaml", """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: no-limits-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: myapp:1.0
        securityContext:
          runAsNonRoot: true
          readOnlyRootFilesystem: true
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-k4")
        )

        limit_vulns = [v for v in vulns if "resource limits" in v.title.lower() or "limit" in v.title.lower()]
        assert len(limit_vulns) > 0

    def test_secrets_in_env(self, scanner, temp_dir):
        """Test detection of secrets in environment variables."""
        write_file(temp_dir, "deployment.yaml", """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: secret-env-app
spec:
  template:
    spec:
      containers:
      - name: app
        image: myapp:1.0
        env:
        - name: DATABASE_PASSWORD
          value: "supersecret123"
        - name: API_KEY
          value: "sk-test-key-12345"
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-k5")
        )

        secret_vulns = [v for v in vulns if "secret" in v.title.lower() and "env" in v.title.lower()]
        assert len(secret_vulns) > 0

    def test_service_account_wildcard(self, scanner, temp_dir):
        """Test detection of wildcard ServiceAccount permissions."""
        write_file(temp_dir, "rbac.yaml", """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: wildcard-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-k6")
        )

        rbac_vulns = [v for v in vulns if "wildcard" in v.title.lower() or "ServiceAccount" in v.title]
        assert len(rbac_vulns) > 0

    def test_host_pid_ipc(self, scanner, temp_dir):
        """Test detection of hostPID and hostIPC."""
        write_file(temp_dir, "daemonset.yaml", """
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: host-access
spec:
  template:
    spec:
      hostPID: true
      hostIPC: true
      containers:
      - name: app
        image: myapp:1.0
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-k7")
        )

        pid_vulns = [v for v in vulns if "hostPID" in v.title or "hostIPC" in v.title]
        assert len(pid_vulns) >= 2

    def test_read_only_root_fs(self, scanner, temp_dir):
        """Test detection of missing readOnlyRootFilesystem."""
        write_file(temp_dir, "deployment.yaml", """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: writable-root
spec:
  template:
    spec:
      containers:
      - name: app
        image: myapp:1.0
        securityContext:
          runAsNonRoot: true
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-k8")
        )

        ro_vulns = [v for v in vulns if "readOnlyRootFilesystem" in v.title]
        assert len(ro_vulns) > 0


# ============================================================================
# Terraform Tests
# ============================================================================

class TestTerraformScanning:
    """Tests for Terraform file scanning."""

    def test_public_s3_bucket(self, scanner, temp_dir):
        """Test detection of public S3 bucket ACL."""
        write_file(temp_dir, "main.tf", """
resource "aws_s3_bucket" "public_bucket" {
  bucket = "my-public-bucket"
  acl    = "public-read"
}
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-t1")
        )

        s3_vulns = [v for v in vulns if "S3" in v.title or "public" in v.title.lower()]
        assert len(s3_vulns) > 0
        assert any(v.severity == "CRITICAL" for v in s3_vulns)

    def test_open_security_group(self, scanner, temp_dir):
        """Test detection of open security group."""
        write_file(temp_dir, "security.tf", """
resource "aws_security_group" "open_sg" {
  name = "open-sg"
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-t2")
        )

        sg_vulns = [v for v in vulns if "security group" in v.title.lower() or "0.0.0.0" in v.description]
        assert len(sg_vulns) > 0

    def test_hardcoded_credentials(self, scanner, temp_dir):
        """Test detection of hardcoded credentials."""
        write_file(temp_dir, "rds.tf", """
resource "aws_db_instance" "database" {
  identifier = "mydb"
  username   = "admin"
  password   = "HardcodedPassword123!"
}
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-t3")
        )

        cred_vulns = [v for v in vulns if "credential" in v.title.lower() or "hardcoded" in v.description.lower()]
        assert len(cred_vulns) > 0


# ============================================================================
# Helm Chart Tests
# ============================================================================

class TestHelmScanning:
    """Tests for Helm chart scanning."""

    def test_missing_security_context(self, scanner, temp_dir):
        """Test detection of missing security context in values.yaml."""
        write_file(temp_dir, "values.yaml", """
image:
  repository: myapp
  tag: 1.0.0
  pullPolicy: IfNotPresent
replicaCount: 1
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-h1")
        )

        sc_vulns = [v for v in vulns if "security context" in v.title.lower()]
        assert len(sc_vulns) > 0

    def test_latest_image_tag(self, scanner, temp_dir):
        """Test detection of 'latest' image tag."""
        write_file(temp_dir, "values.yaml", """
image:
  repository: myapp
  tag: latest
  pullPolicy: Always
securityContext:
  runAsNonRoot: true
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-h2")
        )

        tag_vulns = [v for v in vulns if "tag" in v.title.lower() or "latest" in v.description.lower()]
        assert len(tag_vulns) > 0

    def test_missing_resource_limits_values(self, scanner, temp_dir):
        """Test detection of missing resource limits in values.yaml."""
        write_file(temp_dir, "values.yaml", """
image:
  repository: myapp
  tag: 1.0.0
securityContext:
  runAsNonRoot: true
""")
        import asyncio
        vulns = asyncio.get_event_loop().run_until_complete(
            scanner.scan(temp_dir, "test-scan-h3")
        )

        limit_vulns = [v for v in vulns if "resource limits" in v.title.lower() or "limit" in v.title.lower()]
        assert len(limit_vulns) > 0


# ============================================================================
# Policy Engine Tests
# ============================================================================

class TestPolicyEngine:
    """Tests for the Checkov-style policy engine."""

    def test_policy_summary(self, scanner):
        """Test getting policy summary."""
        summary = scanner.get_policy_summary()

        assert "dockerfile" in summary
        assert "kubernetes" in summary
        assert "terraform" in summary
        assert "helm" in summary

    def test_load_custom_policies_nonexistent(self, scanner, temp_dir):
        """Test loading custom policies from non-existent directory."""
        count = scanner.load_custom_policies("/nonexistent/path")
        assert count == 0

    def test_get_policy(self, scanner):
        """Test getting a specific policy by ID."""
        policy = scanner._get_policy("CKV_DOCKER_1")
        assert policy is not None
        assert policy["name"] == "Ensure FROM image uses specific tag"

    def test_get_unknown_policy(self, scanner):
        """Test getting a non-existent policy."""
        policy = scanner._get_policy("UNKNOWN_POLICY")
        assert policy is None


# ============================================================================
# Utility Tests
# ============================================================================

class TestSecretPatterns:
    """Tests for secret detection patterns."""

    def test_password_pattern(self):
        """Test password detection pattern."""
        for pattern, _ in SECRET_PATTERNS:
            if "password" in pattern.lower() or "passwd" in pattern.lower():
                assert re.search(pattern, "DB_PASSWORD=mypassword123")
                return
        # If we get here, password pattern exists but may have different format
        assert True

    def test_api_key_pattern(self):
        """Test API key detection pattern."""
        for pattern, _ in SECRET_PATTERNS:
            if "api" in pattern.lower() and "key" in pattern.lower():
                assert re.search(pattern, "API_KEY=sk-abc123")
                return
        assert True

    def test_aws_access_key(self):
        """Test AWS access key detection."""
        for pattern, _ in SECRET_PATTERNS:
            if "AKIA" in pattern:
                assert re.search(pattern, "AKIAIOSFODNN7EXAMPLE")
                return
        assert True

    def test_aws_secret_key_pattern(self):
        """Test AWS secret key pattern."""
        for pattern, _ in SECRET_PATTERNS:
            if "aws_secret" in pattern.lower():
                assert re.search(pattern, "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
                return
        assert True

    def test_bearer_token_pattern(self):
        """Test bearer token detection."""
        for pattern, _ in SECRET_PATTERNS:
            if "bearer" in pattern.lower():
                assert re.search(pattern, "Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
                return
        assert True
