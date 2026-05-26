"""
Enterprise Authentication & Authorization Data Models

Defines Pydantic models for RBAC, Team Management, Organization Hierarchy,
and Immutable Audit Logging with hash-chain tamper detection.

Organization Hierarchy:
    Organization -> Teams -> Projects -> Scans
    Permissions are inherited down the hierarchy.

Roles:
    super_admin  -> Full platform access across all tenants
    tenant_admin -> Organization-level admin, user/billing management
    security_lead-> Can create scans, view all findings, configure policies
    developer    -> Can view own scans, create scans, view findings
    viewer       -> Read-only access to assigned scans and findings
"""

from __future__ import annotations

import hashlib
import secrets
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set
from uuid import uuid4, UUID

from pydantic import BaseModel, Field, field_validator


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class RoleName(str, Enum):
    """Built-in role names."""
    SUPER_ADMIN = "super_admin"
    TENANT_ADMIN = "tenant_admin"
    SECURITY_LEAD = "security_lead"
    DEVELOPER = "developer"
    VIEWER = "viewer"


class Permission(str, Enum):
    """Granular permissions in the format resource:action."""
    # Scan permissions
    SCAN_CREATE = "scan:create"
    SCAN_READ = "scan:read"
    SCAN_READ_ALL = "scan:read_all"
    SCAN_DELETE = "scan:delete"
    SCAN_EXECUTE = "scan:execute"

    # Vulnerability permissions
    VULN_READ = "vuln:read"
    VULN_READ_ALL = "vuln:read_all"
    VULN_WRITE = "vuln:write"
    VULN_ASSIGN = "vuln:assign"
    VULN_DISMISS = "vuln:dismiss"

    # Policy permissions
    POLICY_MANAGE = "policy:manage"
    POLICY_READ = "policy:read"

    # Report permissions
    REPORT_GENERATE = "report:generate"
    REPORT_READ = "report:read"
    REPORT_EXPORT = "report:export"

    # User & Team permissions
    USER_MANAGE = "user:manage"
    USER_READ = "user:read"
    TEAM_MANAGE = "team:manage"
    TEAM_READ = "team:read"

    # Organization permissions
    ORG_MANAGE = "org:manage"
    ORG_READ = "org:read"
    ORG_BILLING = "org:billing"

    # Compliance permissions
    COMPLIANCE_READ = "compliance:read"
    COMPLIANCE_MANAGE = "compliance:manage"

    # Integration permissions
    INTEGRATION_MANAGE = "integration:manage"
    INTEGRATION_READ = "integration:read"

    # Audit permissions
    AUDIT_READ = "audit:read"
    AUDIT_EXPORT = "audit:export"

    # Settings permissions
    SETTINGS_MANAGE = "settings:manage"
    SETTINGS_READ = "settings:read"

    # Admin permissions
    PLATFORM_ADMIN = "platform:admin"
    TENANT_ADMIN_PERM = "tenant:admin"


class ResourceType(str, Enum):
    """Types of resources for access control."""
    ORGANIZATION = "organization"
    TEAM = "team"
    PROJECT = "project"
    SCAN = "scan"
    VULNERABILITY = "vulnerability"
    POLICY = "policy"
    REPORT = "report"
    USER = "user"


class AuditAction(str, Enum):
    """Actions that can be recorded in the audit log."""
    USER_LOGIN = "user:login"
    USER_LOGOUT = "user:logout"
    USER_CREATED = "user:created"
    USER_UPDATED = "user:updated"
    USER_DELETED = "user:deleted"
    USER_ROLE_CHANGED = "user:role_changed"
    TEAM_CREATED = "team:created"
    TEAM_UPDATED = "team:updated"
    TEAM_DELETED = "team:deleted"
    TEAM_MEMBER_ADDED = "team:member_added"
    TEAM_MEMBER_REMOVED = "team:member_removed"
    ORG_CREATED = "org:created"
    ORG_UPDATED = "org:updated"
    SCAN_CREATED = "scan:created"
    SCAN_STARTED = "scan:started"
    SCAN_COMPLETED = "scan:completed"
    SCAN_DELETED = "scan:deleted"
    VULN_ASSIGNED = "vuln:assigned"
    VULN_DISMISSED = "vuln:dismissed"
    VULN_REMEDIATED = "vuln:remediated"
    POLICY_CREATED = "policy:created"
    POLICY_UPDATED = "policy:updated"
    POLICY_DELETED = "policy:deleted"
    POLICY_VIOLATION = "policy:violation"
    REPORT_GENERATED = "report:generated"
    REPORT_EXPORTED = "report:exported"
    INTEGRATION_CONFIGURED = "integration:configured"
    INTEGRATION_REMOVED = "integration:removed"
    SETTINGS_CHANGED = "settings:changed"
    COMPLIANCE_EXPORTED = "compliance:exported"
    PERMISSION_DENIED = "permission:denied"
    ACCESS_GRANTED = "access:granted"


class AuditResult(str, Enum):
    """Result of an audited action."""
    SUCCESS = "success"
    FAILURE = "failure"
    DENIED = "denied"
    ERROR = "error"


class SLASeverity(str, Enum):
    """Severity levels for SLA tracking."""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class SSOProvider(str, Enum):
    """Supported SSO providers."""
    SAML = "saml"
    OIDC = "oidc"
    LDAP = "ldap"
    AZURE_AD = "azure_ad"
    GOOGLE = "google"


# ---------------------------------------------------------------------------
# Role-to-Permission Mapping
# ---------------------------------------------------------------------------

ROLE_PERMISSIONS: Dict[RoleName, List[Permission]] = {
    RoleName.SUPER_ADMIN: [
        # Full platform access
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_READ_ALL,
        Permission.SCAN_DELETE, Permission.SCAN_EXECUTE,
        Permission.VULN_READ, Permission.VULN_READ_ALL, Permission.VULN_WRITE,
        Permission.VULN_ASSIGN, Permission.VULN_DISMISS,
        Permission.POLICY_MANAGE, Permission.POLICY_READ,
        Permission.REPORT_GENERATE, Permission.REPORT_READ, Permission.REPORT_EXPORT,
        Permission.USER_MANAGE, Permission.USER_READ,
        Permission.TEAM_MANAGE, Permission.TEAM_READ,
        Permission.ORG_MANAGE, Permission.ORG_READ, Permission.ORG_BILLING,
        Permission.COMPLIANCE_READ, Permission.COMPLIANCE_MANAGE,
        Permission.INTEGRATION_MANAGE, Permission.INTEGRATION_READ,
        Permission.AUDIT_READ, Permission.AUDIT_EXPORT,
        Permission.SETTINGS_MANAGE, Permission.SETTINGS_READ,
        Permission.PLATFORM_ADMIN, Permission.TENANT_ADMIN_PERM,
    ],
    RoleName.TENANT_ADMIN: [
        # Organization-level admin
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_READ_ALL,
        Permission.SCAN_EXECUTE,
        Permission.VULN_READ, Permission.VULN_READ_ALL, Permission.VULN_ASSIGN,
        Permission.POLICY_MANAGE, Permission.POLICY_READ,
        Permission.REPORT_GENERATE, Permission.REPORT_READ, Permission.REPORT_EXPORT,
        Permission.USER_MANAGE, Permission.USER_READ,
        Permission.TEAM_MANAGE, Permission.TEAM_READ,
        Permission.ORG_READ, Permission.ORG_BILLING,
        Permission.COMPLIANCE_READ, Permission.COMPLIANCE_MANAGE,
        Permission.INTEGRATION_MANAGE, Permission.INTEGRATION_READ,
        Permission.AUDIT_READ, Permission.AUDIT_EXPORT,
        Permission.SETTINGS_MANAGE, Permission.SETTINGS_READ,
        Permission.TENANT_ADMIN_PERM,
    ],
    RoleName.SECURITY_LEAD: [
        # Security team lead
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_READ_ALL,
        Permission.SCAN_EXECUTE,
        Permission.VULN_READ, Permission.VULN_READ_ALL, Permission.VULN_WRITE,
        Permission.VULN_ASSIGN, Permission.VULN_DISMISS,
        Permission.POLICY_MANAGE, Permission.POLICY_READ,
        Permission.REPORT_GENERATE, Permission.REPORT_READ, Permission.REPORT_EXPORT,
        Permission.USER_READ,
        Permission.TEAM_READ,
        Permission.ORG_READ,
        Permission.COMPLIANCE_READ, Permission.COMPLIANCE_MANAGE,
        Permission.INTEGRATION_READ,
        Permission.AUDIT_READ,
        Permission.SETTINGS_READ,
    ],
    RoleName.DEVELOPER: [
        # Developer
        Permission.SCAN_CREATE, Permission.SCAN_READ, Permission.SCAN_EXECUTE,
        Permission.VULN_READ,
        Permission.POLICY_READ,
        Permission.REPORT_READ,
        Permission.TEAM_READ,
        Permission.ORG_READ,
        Permission.COMPLIANCE_READ,
        Permission.SETTINGS_READ,
    ],
    RoleName.VIEWER: [
        # Read-only viewer
        Permission.SCAN_READ,
        Permission.VULN_READ,
        Permission.REPORT_READ,
        Permission.TEAM_READ,
        Permission.ORG_READ,
        Permission.COMPLIANCE_READ,
    ],
}


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------

class Organization(BaseModel):
    """
    Top-level organization (tenant) in the hierarchy.

    Organizations contain Teams, which contain Projects, which contain Scans.
    """
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    slug: str = ""
    description: Optional[str] = None

    def model_post_init(self, __context) -> None:
        """Auto-generate slug from name if not provided."""
        if not self.slug and self.name:
            self.slug = self.name.lower().replace(" ", "-").replace("_", "-")[:50]
    plan: str = "enterprise"  # free, team, enterprise
    status: str = "active"  # active, suspended, archived
    settings: Dict[str, Any] = Field(default_factory=dict)
    billing_email: Optional[str] = None
    admin_user_ids: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return self.model_dump()


class Team(BaseModel):
    """
    Team within an Organization.

    Teams group users and can be assigned scans/projects.
    Permissions are inherited from Organization and overridden at Team level.
    """
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    description: Optional[str] = None
    organization_id: str
    member_ids: List[str] = Field(default_factory=list)
    project_ids: List[str] = Field(default_factory=list)
    scan_ids: List[str] = Field(default_factory=list)
    team_lead_id: Optional[str] = None
    status: str = "active"  # active, archived
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return self.model_dump()


class Project(BaseModel):
    """
    Project within a Team.

    Projects contain Scans and represent a codebase or application.
    """
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    description: Optional[str] = None
    organization_id: str
    team_id: Optional[str] = None
    scan_ids: List[str] = Field(default_factory=list)
    repository_url: Optional[str] = None
    default_branch: str = "main"
    languages: List[str] = Field(default_factory=list)
    risk_threshold: int = 50  # 0-100
    status: str = "active"
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return self.model_dump()


class Role(BaseModel):
    """
    Role definition with permission set.

    Roles can be built-in or custom. Custom roles can have any subset
    of permissions, but cannot exceed the permissions of the creating user's role.
    """
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    description: Optional[str] = None
    permissions: List[str] = Field(default_factory=list)
    is_builtin: bool = True
    organization_id: Optional[str] = None  # None for global roles
    created_by: Optional[str] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def has_permission(self, permission: Permission) -> bool:
        """Check if role has a specific permission."""
        return permission.value in self.permissions

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return self.model_dump()


class User(BaseModel):
    """
    User account in the system.

    Users belong to an Organization and can be members of multiple Teams.
    A user's effective permissions are the union of their role permissions
    and any team-specific overrides.
    """
    id: str = Field(default_factory=lambda: str(uuid4()))
    email: str
    username: str = ""
    full_name: Optional[str] = None
    role: str = RoleName.VIEWER.value  # primary role

    def model_post_init(self, __context) -> None:
        """Auto-generate username from email if not provided."""
        if not self.username and self.email:
            self.username = self.email.split("@")[0][:30]
    organization_id: Optional[str] = None
    team_ids: List[str] = Field(default_factory=list)
    project_ids: List[str] = Field(default_factory=list)
    status: str = "active"  # active, inactive, suspended, pending
    last_login: Optional[datetime] = None
    login_count: int = 0
    mfa_enabled: bool = False
    sso_provider: Optional[str] = None
    sso_subject_id: Optional[str] = None  # ID from SSO provider
    api_key_hash: Optional[str] = None
    avatar_url: Optional[str] = None
    preferences: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def is_super_admin(self) -> bool:
        """Check if user is a super admin."""
        return self.role == RoleName.SUPER_ADMIN.value

    def is_tenant_admin(self) -> bool:
        """Check if user is a tenant admin."""
        return self.role in (RoleName.TENANT_ADMIN.value, RoleName.SUPER_ADMIN.value)

    def get_permissions(self) -> Set[str]:
        """Get all permissions for this user based on their role."""
        try:
            role_name = RoleName(self.role)
            return {p.value for p in ROLE_PERMISSIONS.get(role_name, [])}
        except ValueError:
            return set()

    def has_permission(self, permission: Permission) -> bool:
        """Check if user has a specific permission."""
        if self.is_super_admin():
            return True
        perms = self.get_permissions()
        return permission.value in perms

    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Serialize to dictionary."""
        data = self.model_dump()
        if not include_sensitive:
            data.pop("api_key_hash", None)
            data.pop("sso_subject_id", None)
        return data


class ResourceAccess(BaseModel):
    """
    Access control entry for a specific resource.

    Grants or denies a user or team access to a specific resource
    with optional permission overrides.
    """
    id: str = Field(default_factory=lambda: str(uuid4()))
    resource_type: str  # organization, team, project, scan
    resource_id: str
    user_id: Optional[str] = None
    team_id: Optional[str] = None
    permissions: List[str] = Field(default_factory=list)
    granted_by: Optional[str] = None
    expires_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))

    def is_expired(self) -> bool:
        """Check if access grant has expired."""
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) > self.expires_at

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return self.model_dump()


class AuditLogEntry(BaseModel):
    """
    Immutable audit log entry with hash-chain tamper detection.

    Each entry contains:
    - A unique sequential ID
    - A SHA-256 hash of the entry content
    - The hash of the previous entry (hash chain)
    - Who performed the action
    - What action was performed
    - On what resource
    - When it occurred
    - The result

    The hash chain ensures that if any entry is modified, all subsequent
    entries will have invalid previous_hash values.
    """
    id: str = Field(default_factory=lambda: str(uuid4()))
    sequence_number: int = 0  # Monotonically increasing sequence
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    actor_id: str  # User ID who performed the action
    actor_type: str = "user"  # user, system, api_key, sso
    actor_name: Optional[str] = None
    action: str  # AuditAction value
    resource_type: str  # ResourceType value
    resource_id: Optional[str] = None
    resource_name: Optional[str] = None
    organization_id: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)
    result: str = AuditResult.SUCCESS.value  # success, failure, denied, error
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    previous_hash: Optional[str] = None  # Hash of previous entry (hash chain)
    entry_hash: Optional[str] = None  # Hash of this entry's content
    signature: Optional[str] = None  # Optional digital signature

    def compute_hash(self) -> str:
        """
        Compute SHA-256 hash of this entry's canonical content.

        The hash covers all fields except entry_hash and signature itself,
        ensuring the integrity of the entry data.
        """
        content = (
            f"{self.sequence_number}|"
            f"{self.timestamp.isoformat()}|"
            f"{self.actor_id}|"
            f"{self.actor_type}|"
            f"{self.actor_name or ''}|"
            f"{self.action}|"
            f"{self.resource_type}|"
            f"{self.resource_id or ''}|"
            f"{self.resource_name or ''}|"
            f"{self.organization_id or ''}|"
            f"{self._serialize_details()}|"
            f"{self.result}|"
            f"{self.ip_address or ''}|"
            f"{self.session_id or ''}|"
            f"{self.previous_hash or ''}"
        )
        return hashlib.sha256(content.encode("utf-8")).hexdigest()

    def _serialize_details(self) -> str:
        """Serialize details dict to a stable string representation."""
        if not self.details:
            return ""
        items = sorted(self.details.items())
        parts = []
        for k, v in items:
            parts.append(f"{k}={v}")
        return ";".join(parts)

    def verify_integrity(self) -> bool:
        """Verify the entry's hash matches its content."""
        if not self.entry_hash:
            return False
        return self.compute_hash() == self.entry_hash

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary."""
        return self.model_dump()


class AuditLogExport(BaseModel):
    """Export format for audit log data."""
    format: str  # csv, json
    entries: List[AuditLogEntry] = Field(default_factory=list)
    exported_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    exported_by: Optional[str] = None
    entry_count: int = 0
    hash_chain_valid: bool = True

    def to_csv(self) -> str:
        """Export entries as CSV string."""
        import csv
        import io

        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            "sequence_number", "timestamp", "actor_id", "actor_name",
            "action", "resource_type", "resource_id", "resource_name",
            "result", "ip_address", "details", "previous_hash", "entry_hash",
        ])
        for entry in self.entries:
            writer.writerow([
                entry.sequence_number,
                entry.timestamp.isoformat(),
                entry.actor_id,
                entry.actor_name or "",
                entry.action,
                entry.resource_type,
                entry.resource_id or "",
                entry.resource_name or "",
                entry.result,
                entry.ip_address or "",
                entry._serialize_details(),
                entry.previous_hash or "",
                entry.entry_hash or "",
            ])
        return output.getvalue()

    def to_jsonl(self) -> str:
        """Export entries as JSON Lines string."""
        import json
        lines = []
        for entry in self.entries:
            lines.append(json.dumps(entry.to_dict(), default=str))
        return "\n".join(lines)


class SLADefinition(BaseModel):
    """SLA definition for vulnerability remediation by severity."""
    severity: str
    days_to_remediate: int
    reminder_days: int = 2  # Days before SLA to send reminder
    escalation_days: int = 1  # Days after SLA breach to escalate
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class SLATracking(BaseModel):
    """Tracks SLA status for a single vulnerability."""
    vulnerability_id: str
    scan_id: str
    severity: str
    detected_at: datetime
    sla_deadline: datetime
    remediated_at: Optional[datetime] = None
    assigned_to: Optional[str] = None
    status: str = "open"  # open, in_progress, remediated, breached, dismissed
    breached: bool = False
    breach_duration_hours: Optional[float] = None
    reminders_sent: int = 0
    escalations_sent: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)

    @property
    def days_remaining(self) -> int:
        """Days remaining until SLA deadline (computed property)."""
        now = datetime.now(timezone.utc)
        if self.status in ("remediated", "dismissed"):
            return 0
        delta = self.sla_deadline - now
        return max(0, delta.days)

    @property
    def is_breached(self) -> bool:
        """Check if SLA has been breached (computed property)."""
        if self.status in ("remediated", "dismissed"):
            return False
        return datetime.now(timezone.utc) > self.sla_deadline

    @property
    def hours_overdue(self) -> float:
        """Hours past SLA deadline (0 if not breached)."""
        if not self.is_breached:
            return 0.0
        delta = datetime.now(timezone.utc) - self.sla_deadline
        return delta.total_seconds() / 3600

    def check_breach(self) -> bool:
        """Check if SLA has been breached and update tracked state."""
        if self.status in ("remediated", "dismissed"):
            self.breached = False
            return False
        now = datetime.now(timezone.utc)
        self.breached = now > self.sla_deadline
        if self.breached and self.remediated_at:
            self.breach_duration_hours = (
                self.remediated_at - self.sla_deadline
            ).total_seconds() / 3600
        return self.breached

    def to_dict(self) -> Dict[str, Any]:
        """Serialize to dictionary with computed properties expanded."""
        self.check_breach()
        data = self.model_dump()
        data["days_remaining"] = self.days_remaining
        data["is_breached"] = self.is_breached
        data["hours_overdue"] = round(self.hours_overdue, 2)
        return data


# Default SLA definitions (calendar days)
DEFAULT_SLA_DEFINITIONS: List[SLADefinition] = [
    SLADefinition(severity="CRITICAL", days_to_remediate=7, reminder_days=2, escalation_days=1,
                  description="Critical vulnerabilities must be remediated within 7 calendar days"),
    SLADefinition(severity="HIGH", days_to_remediate=15, reminder_days=3, escalation_days=2,
                  description="High severity vulnerabilities must be remediated within 15 calendar days"),
    SLADefinition(severity="MEDIUM", days_to_remediate=30, reminder_days=5, escalation_days=3,
                  description="Medium severity vulnerabilities must be remediated within 30 calendar days"),
    SLADefinition(severity="LOW", days_to_remediate=90, reminder_days=14, escalation_days=7,
                  description="Low severity vulnerabilities must be remediated within 90 calendar days"),
]


# Convenience factory functions

def create_builtin_role(role_name: RoleName) -> Role:
    """Create a built-in role with standard permissions."""
    return Role(
        name=role_name.value,
        description=_get_role_description(role_name),
        permissions=[p.value for p in ROLE_PERMISSIONS[role_name]],
        is_builtin=True,
    )


def _get_role_description(role_name: RoleName) -> str:
    """Get description for a built-in role."""
    descriptions = {
        RoleName.SUPER_ADMIN: "Full platform access across all tenants. Can manage everything.",
        RoleName.TENANT_ADMIN: "Organization-level administrator. Can manage users, billing, and organization settings.",
        RoleName.SECURITY_LEAD: "Security team lead. Can create scans, view all findings, manage policies and compliance.",
        RoleName.DEVELOPER: "Developer. Can view own scans, create scans, and view findings.",
        RoleName.VIEWER: "Read-only viewer. Can view assigned scans and findings only.",
    }
    return descriptions.get(role_name, "Custom role")
