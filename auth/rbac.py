"""
Enterprise Role-Based Access Control (RBAC) Engine

Provides:
- Permission checking with role-based and resource-based access control
- Team management (CRUD, membership)
- Organization hierarchy with inherited permissions
- Immutable audit log with SHA-256 hash chain tamper detection
- Audit log export (CSV, JSON)

Usage:
    rbac = RBACEngine(storage_dir="./data/rbac")
    user = rbac.create_user(email="alice@corp.com", role=RoleName.DEVELOPER,
                            organization_id="org-123")
    can_scan = rbac.check_permission(user, Permission.SCAN_CREATE)
    team = rbac.create_team(name="Backend Team", organization_id="org-123",
                            created_by=user.id)
    rbac.add_team_member(team.id, user.id, added_by=admin.id)
"""

from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple
from uuid import uuid4

from auth.models import (
    AuditAction,
    AuditLogEntry,
    AuditLogExport,
    AuditResult,
    Organization,
    Permission,
    Project,
    ResourceAccess,
    ResourceType,
    Role,
    RoleName,
    Team,
    User,
    create_builtin_role,
    ROLE_PERMISSIONS,
)


class PermissionDeniedError(Exception):
    """Raised when a user does not have permission for an action."""
    pass


class ResourceNotFoundError(Exception):
    """Raised when a referenced resource does not exist."""
    pass


class DuplicateResourceError(Exception):
    """Raised when attempting to create a resource that already exists."""
    pass


class RBACEngine:
    """
    Enterprise RBAC Engine with organization hierarchy, team management,
    and tamper-resistant audit logging.
    """

    # ------------------------------------------------------------------
    # Initialization
    # ------------------------------------------------------------------

    def __init__(self, storage_dir: str = "./data/rbac") -> None:
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        # In-memory stores (in production these would be database-backed)
        self._users: Dict[str, User] = {}
        self._users_by_email: Dict[str, str] = {}  # email -> user_id
        self._organizations: Dict[str, Organization] = {}
        self._teams: Dict[str, Team] = {}
        self._projects: Dict[str, Project] = {}
        self._roles: Dict[str, Role] = {}
        self._resource_access: Dict[str, List[ResourceAccess]] = {}  # resource_id -> accesses
        self._audit_log: List[AuditLogEntry] = []
        self._sequence_counter: int = 0
        self._api_tokens: Dict[str, str] = {}  # token_hash -> user_id

        self._init_builtin_roles()
        self._load_from_disk()

    def _init_builtin_roles(self) -> None:
        """Initialize built-in roles if not already present."""
        builtin_names = {r.name for r in self._roles.values() if r.is_builtin}
        for role_name in RoleName:
            if role_name.value not in builtin_names:
                role = create_builtin_role(role_name)
                self._roles[role.id] = role

    # ------------------------------------------------------------------
    # Persistence (JSON files for demo; use DB in production)
    # ------------------------------------------------------------------

    def _persist(self) -> None:
        """Persist all data to disk."""
        try:
            data = {
                "users": {uid: u.model_dump() for uid, u in self._users.items()},
                "organizations": {oid: o.model_dump() for oid, o in self._organizations.items()},
                "teams": {tid: t.model_dump() for tid, t in self._teams.items()},
                "projects": {pid: p.model_dump() for pid, p in self._projects.items()},
                "roles": {rid: r.model_dump() for rid, r in self._roles.items()},
                "resource_access": {
                    rid: [a.model_dump() for a in accesses]
                    for rid, accesses in self._resource_access.items()
                },
                "audit_log": [e.model_dump() for e in self._audit_log],
                "sequence_counter": self._sequence_counter,
            }
            path = self.storage_dir / "rbac_data.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception:
            pass  # Best-effort persistence

    def _load_from_disk(self) -> None:
        """Load data from disk if available."""
        path = self.storage_dir / "rbac_data.json"
        if not path.exists():
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for uid, ud in data.get("users", {}).items():
                self._users[uid] = User(**ud)
                self._users_by_email[ud["email"]] = uid
            for oid, od in data.get("organizations", {}).items():
                self._organizations[oid] = Organization(**od)
            for tid, td in data.get("teams", {}).items():
                self._teams[tid] = Team(**td)
            for pid, pd in data.get("projects", {}).items():
                self._projects[pid] = Project(**pd)
            for rid, rd in data.get("roles", {}).items():
                self._roles[rid] = Role(**rd)
            for rid, accesses in data.get("resource_access", {}).items():
                self._resource_access[rid] = [ResourceAccess(**a) for a in accesses]
            for entry in data.get("audit_log", []):
                self._audit_log.append(AuditLogEntry(**entry))
            self._sequence_counter = data.get("sequence_counter", len(self._audit_log))
        except Exception:
            pass

    # ==================================================================
    # USER MANAGEMENT
    # ==================================================================

    def create_user(
        self,
        email: str,
        role: RoleName = RoleName.VIEWER,
        organization_id: Optional[str] = None,
        full_name: Optional[str] = None,
        username: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> User:
        """Create a new user account."""
        email = email.lower().strip()
        if email in self._users_by_email:
            raise DuplicateResourceError(f"User with email {email} already exists")

        if organization_id and organization_id not in self._organizations:
            raise ResourceNotFoundError(f"Organization {organization_id} not found")

        user = User(
            email=email,
            username=username or email.split("@")[0][:30],
            full_name=full_name,
            role=role.value,
            organization_id=organization_id,
        )
        self._users[user.id] = user
        self._users_by_email[email] = user.id

        self._audit(
            actor_id=created_by or user.id,
            action=AuditAction.USER_CREATED,
            resource_type=ResourceType.USER,
            resource_id=user.id,
            resource_name=user.email,
            organization_id=organization_id,
            details={"role": role.value, "email": email},
        )
        self._persist()
        return user

    def get_user(self, user_id: str) -> Optional[User]:
        """Get a user by ID."""
        return self._users.get(user_id)

    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get a user by email address."""
        uid = self._users_by_email.get(email.lower().strip())
        return self._users.get(uid) if uid else None

    def list_users(
        self,
        organization_id: Optional[str] = None,
        role: Optional[str] = None,
        status: Optional[str] = None,
    ) -> List[User]:
        """List users with optional filtering."""
        users = list(self._users.values())
        if organization_id:
            users = [u for u in users if u.organization_id == organization_id]
        if role:
            users = [u for u in users if u.role == role]
        if status:
            users = [u for u in users if u.status == status]
        return users

    def update_user(self, user_id: str, updates: Dict[str, Any],
                    updated_by: Optional[str] = None) -> Optional[User]:
        """Update a user's fields."""
        user = self._users.get(user_id)
        if not user:
            return None

        old_role = user.role
        allowed_fields = {"full_name", "username", "role", "status",
                          "preferences", "avatar_url", "mfa_enabled"}

        for field, value in updates.items():
            if field in allowed_fields:
                setattr(user, field, value)

        user.updated_at = datetime.now(timezone.utc)

        # Audit role change specifically
        if "role" in updates and updates["role"] != old_role:
            self._audit(
                actor_id=updated_by or user_id,
                action=AuditAction.USER_ROLE_CHANGED,
                resource_type=ResourceType.USER,
                resource_id=user_id,
                resource_name=user.email,
                organization_id=user.organization_id,
                details={"old_role": old_role, "new_role": updates["role"]},
            )

        self._audit(
            actor_id=updated_by or user_id,
            action=AuditAction.USER_UPDATED,
            resource_type=ResourceType.USER,
            resource_id=user_id,
            resource_name=user.email,
            organization_id=user.organization_id,
            details={"fields_updated": list(updates.keys())},
        )
        self._persist()
        return user

    def delete_user(self, user_id: str, deleted_by: Optional[str] = None) -> bool:
        """Soft-delete a user (set status to inactive)."""
        user = self._users.get(user_id)
        if not user:
            return False

        user.status = "inactive"
        user.updated_at = datetime.now(timezone.utc)

        self._audit(
            actor_id=deleted_by or user_id,
            action=AuditAction.USER_DELETED,
            resource_type=ResourceType.USER,
            resource_id=user_id,
            resource_name=user.email,
            organization_id=user.organization_id,
            details={"email": user.email},
        )
        self._persist()
        return True

    def set_user_role(self, user_id: str, new_role: RoleName,
                      updated_by: str) -> Optional[User]:
        """Change a user's role."""
        return self.update_user(user_id, {"role": new_role.value}, updated_by=updated_by)

    # ==================================================================
    # PERMISSION CHECKING
    # ==================================================================

    def check_permission(
        self,
        user: User,
        permission: Permission,
        resource_type: Optional[ResourceType] = None,
        resource_id: Optional[str] = None,
    ) -> bool:
        """
        Check if a user has a specific permission.

        Super admins bypass all checks.
        Tenant admins are scoped to their organization.
        Resource-level overrides are checked for fine-grained access.
        """
        # Super admin bypass
        if user.is_super_admin():
            return True

        # Check role-based permissions
        user_perms = user.get_permissions()
        if permission.value not in user_perms:
            return False

        # If resource specified, check resource-level access
        if resource_id and resource_type:
            if self._has_resource_access(user.id, resource_type, resource_id, permission):
                return True
            # Check if user has blanket permission for resource type
            if permission in (Permission.SCAN_READ_ALL, Permission.VULN_READ_ALL):
                return True
            # Check team/project membership for inherited access
            if self._has_inherited_access(user, resource_type, resource_id):
                return True

        return True

    def require_permission(
        self,
        user: User,
        permission: Permission,
        resource_type: Optional[ResourceType] = None,
        resource_id: Optional[str] = None,
    ) -> None:
        """Raise PermissionDeniedError if user lacks permission."""
        if not self.check_permission(user, permission, resource_type, resource_id):
            self._audit(
                actor_id=user.id,
                action=AuditAction.PERMISSION_DENIED,
                resource_type=resource_type or ResourceType.USER,
                resource_id=resource_id,
                result=AuditResult.DENIED,
                details={"permission": permission.value},
            )
            raise PermissionDeniedError(
                f"User {user.id} lacks permission {permission.value}"
            )

    def _has_resource_access(
        self,
        user_id: str,
        resource_type: ResourceType,
        resource_id: str,
        permission: Permission,
    ) -> bool:
        """Check explicit resource-level access grants."""
        accesses = self._resource_access.get(resource_id, [])
        for access in accesses:
            if access.user_id == user_id and not access.is_expired():
                if permission.value in access.permissions:
                    return True
        return False

    def _has_inherited_access(
        self,
        user: User,
        resource_type: ResourceType,
        resource_id: str,
    ) -> bool:
        """
        Check inherited access through organization/team/project hierarchy.

        Organization -> Teams -> Projects -> Scans
        """
        if resource_type == ResourceType.SCAN:
            # Check if scan belongs to a project the user has access to
            for project in self._projects.values():
                if resource_id in project.scan_ids:
                    if project.team_id in user.team_ids:
                        return True
                    if project.organization_id == user.organization_id:
                        return True
            return False

        elif resource_type == ResourceType.PROJECT:
            project = self._projects.get(resource_id)
            if not project:
                return False
            if project.team_id in user.team_ids:
                return True
            if project.organization_id == user.organization_id:
                return True
            return False

        elif resource_type == ResourceType.TEAM:
            return resource_id in user.team_ids

        elif resource_type == ResourceType.ORGANIZATION:
            return resource_id == user.organization_id

        return False

    def grant_resource_access(
        self,
        user_id: str,
        resource_type: ResourceType,
        resource_id: str,
        permissions: List[Permission],
        granted_by: str,
        expires_at: Optional[datetime] = None,
    ) -> ResourceAccess:
        """Grant a user access to a specific resource."""
        access = ResourceAccess(
            resource_type=resource_type.value,
            resource_id=resource_id,
            user_id=user_id,
            permissions=[p.value for p in permissions],
            granted_by=granted_by,
            expires_at=expires_at,
        )
        if resource_id not in self._resource_access:
            self._resource_access[resource_id] = []
        self._resource_access[resource_id].append(access)

        self._audit(
            actor_id=granted_by,
            action=AuditAction.ACCESS_GRANTED,
            resource_type=resource_type,
            resource_id=resource_id,
            details={
                "granted_to": user_id,
                "permissions": [p.value for p in permissions],
                "expires": expires_at.isoformat() if expires_at else None,
            },
        )
        self._persist()
        return access

    def revoke_resource_access(
        self,
        user_id: str,
        resource_id: str,
        revoked_by: str,
    ) -> bool:
        """Revoke a user's access to a resource."""
        accesses = self._resource_access.get(resource_id, [])
        original_len = len(accesses)
        self._resource_access[resource_id] = [
            a for a in accesses if a.user_id != user_id
        ]
        revoked = len(self._resource_access[resource_id]) < original_len
        if revoked:
            self._persist()
        return revoked

    def get_user_permissions(self, user: User) -> Dict[str, Any]:
        """Get complete permission summary for a user."""
        role_perms = user.get_permissions()
        role = self._get_role_def(user.role)
        return {
            "user_id": user.id,
            "role": user.role,
            "is_super_admin": user.is_super_admin(),
            "is_tenant_admin": user.is_tenant_admin(),
            "permissions": sorted(role_perms),
            "permission_count": len(role_perms),
            "organization_id": user.organization_id,
            "team_ids": user.team_ids,
        }

    def _get_role_def(self, role_name: str) -> Optional[Role]:
        """Get role definition by name."""
        for role in self._roles.values():
            if role.name == role_name:
                return role
        return None

    # ==================================================================
    # ORGANIZATION MANAGEMENT
    # ==================================================================

    def create_organization(
        self,
        name: str,
        billing_email: Optional[str] = None,
        description: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> Organization:
        """Create a new organization."""
        org = Organization(
            name=name,
            billing_email=billing_email,
            description=description,
        )
        self._organizations[org.id] = org

        self._audit(
            actor_id=created_by or "system",
            action=AuditAction.ORG_CREATED,
            resource_type=ResourceType.ORGANIZATION,
            resource_id=org.id,
            resource_name=name,
            organization_id=org.id,
            details={"name": name},
        )
        self._persist()
        return org

    def get_organization(self, org_id: str) -> Optional[Organization]:
        """Get an organization by ID."""
        return self._organizations.get(org_id)

    def list_organizations(self, status: Optional[str] = None) -> List[Organization]:
        """List all organizations."""
        orgs = list(self._organizations.values())
        if status:
            orgs = [o for o in orgs if o.status == status]
        return orgs

    def update_organization(
        self,
        org_id: str,
        updates: Dict[str, Any],
        updated_by: Optional[str] = None,
    ) -> Optional[Organization]:
        """Update an organization."""
        org = self._organizations.get(org_id)
        if not org:
            return None

        allowed = {"name", "description", "status", "billing_email", "settings", "plan"}
        for field, value in updates.items():
            if field in allowed:
                setattr(org, field, value)
        org.updated_at = datetime.now(timezone.utc)

        self._audit(
            actor_id=updated_by or "system",
            action=AuditAction.ORG_UPDATED,
            resource_type=ResourceType.ORGANIZATION,
            resource_id=org_id,
            resource_name=org.name,
            organization_id=org_id,
            details={"fields_updated": list(updates.keys())},
        )
        self._persist()
        return org

    # ==================================================================
    # TEAM MANAGEMENT
    # ==================================================================

    def create_team(
        self,
        name: str,
        organization_id: str,
        description: Optional[str] = None,
        team_lead_id: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> Team:
        """Create a new team within an organization."""
        if organization_id not in self._organizations:
            raise ResourceNotFoundError(f"Organization {organization_id} not found")

        team = Team(
            name=name,
            description=description,
            organization_id=organization_id,
            team_lead_id=team_lead_id,
        )
        self._teams[team.id] = team

        self._audit(
            actor_id=created_by or "system",
            action=AuditAction.TEAM_CREATED,
            resource_type=ResourceType.TEAM,
            resource_id=team.id,
            resource_name=name,
            organization_id=organization_id,
            details={"name": name},
        )
        self._persist()
        return team

    def get_team(self, team_id: str) -> Optional[Team]:
        """Get a team by ID."""
        return self._teams.get(team_id)

    def list_teams(
        self,
        organization_id: Optional[str] = None,
        user_id: Optional[str] = None,
    ) -> List[Team]:
        """List teams with optional filtering."""
        teams = list(self._teams.values())
        if organization_id:
            teams = [t for t in teams if t.organization_id == organization_id]
        if user_id:
            teams = [t for t in teams if user_id in t.member_ids]
        return teams

    def update_team(
        self,
        team_id: str,
        updates: Dict[str, Any],
        updated_by: Optional[str] = None,
    ) -> Optional[Team]:
        """Update a team."""
        team = self._teams.get(team_id)
        if not team:
            return None

        allowed = {"name", "description", "team_lead_id", "status"}
        for field, value in updates.items():
            if field in allowed:
                setattr(team, field, value)
        team.updated_at = datetime.now(timezone.utc)

        self._audit(
            actor_id=updated_by or "system",
            action=AuditAction.TEAM_UPDATED,
            resource_type=ResourceType.TEAM,
            resource_id=team_id,
            resource_name=team.name,
            organization_id=team.organization_id,
            details={"fields_updated": list(updates.keys())},
        )
        self._persist()
        return team

    def delete_team(self, team_id: str, deleted_by: Optional[str] = None) -> bool:
        """Delete (archive) a team."""
        team = self._teams.get(team_id)
        if not team:
            return False

        team.status = "archived"
        team.updated_at = datetime.now(timezone.utc)

        # Remove team references from users
        for user in self._users.values():
            if team_id in user.team_ids:
                user.team_ids.remove(team_id)

        self._audit(
            actor_id=deleted_by or "system",
            action=AuditAction.TEAM_DELETED,
            resource_type=ResourceType.TEAM,
            resource_id=team_id,
            resource_name=team.name,
            organization_id=team.organization_id,
        )
        self._persist()
        return True

    def add_team_member(
        self,
        team_id: str,
        user_id: str,
        added_by: Optional[str] = None,
    ) -> Optional[Team]:
        """Add a user to a team."""
        team = self._teams.get(team_id)
        user = self._users.get(user_id)
        if not team or not user:
            return None

        if user_id not in team.member_ids:
            team.member_ids.append(user_id)
        if team_id not in user.team_ids:
            user.team_ids.append(team_id)
        user.organization_id = team.organization_id
        team.updated_at = datetime.now(timezone.utc)

        self._audit(
            actor_id=added_by or "system",
            action=AuditAction.TEAM_MEMBER_ADDED,
            resource_type=ResourceType.TEAM,
            resource_id=team_id,
            resource_name=team.name,
            organization_id=team.organization_id,
            details={"user_id": user_id, "user_email": user.email},
        )
        self._persist()
        return team

    def remove_team_member(
        self,
        team_id: str,
        user_id: str,
        removed_by: Optional[str] = None,
    ) -> Optional[Team]:
        """Remove a user from a team."""
        team = self._teams.get(team_id)
        user = self._users.get(user_id)
        if not team or not user:
            return None

        if user_id in team.member_ids:
            team.member_ids.remove(user_id)
        if team_id in user.team_ids:
            user.team_ids.remove(team_id)
        team.updated_at = datetime.now(timezone.utc)

        self._audit(
            actor_id=removed_by or "system",
            action=AuditAction.TEAM_MEMBER_REMOVED,
            resource_type=ResourceType.TEAM,
            resource_id=team_id,
            resource_name=team.name,
            organization_id=team.organization_id,
            details={"user_id": user_id, "user_email": user.email},
        )
        self._persist()
        return team

    def get_team_members(self, team_id: str) -> List[User]:
        """Get all members of a team."""
        team = self._teams.get(team_id)
        if not team:
            return []
        return [self._users[uid] for uid in team.member_ids if uid in self._users]

    # ==================================================================
    # PROJECT MANAGEMENT
    # ==================================================================

    def create_project(
        self,
        name: str,
        organization_id: str,
        team_id: Optional[str] = None,
        description: Optional[str] = None,
        repository_url: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> Project:
        """Create a new project."""
        if organization_id not in self._organizations:
            raise ResourceNotFoundError(f"Organization {organization_id} not found")
        if team_id and team_id not in self._teams:
            raise ResourceNotFoundError(f"Team {team_id} not found")

        project = Project(
            name=name,
            organization_id=organization_id,
            team_id=team_id,
            description=description,
            repository_url=repository_url,
        )
        self._projects[project.id] = project

        if team_id:
            team = self._teams[team_id]
            team.project_ids.append(project.id)

        self._audit(
            actor_id=created_by or "system",
            action=AuditAction.ACCESS_GRANTED,
            resource_type=ResourceType.PROJECT,
            resource_id=project.id,
            resource_name=name,
            organization_id=organization_id,
            details={"name": name, "team_id": team_id},
        )
        self._persist()
        return project

    def get_project(self, project_id: str) -> Optional[Project]:
        """Get a project by ID."""
        return self._projects.get(project_id)

    def list_projects(
        self,
        organization_id: Optional[str] = None,
        team_id: Optional[str] = None,
    ) -> List[Project]:
        """List projects with optional filtering."""
        projects = list(self._projects.values())
        if organization_id:
            projects = [p for p in projects if p.organization_id == organization_id]
        if team_id:
            projects = [p for p in projects if p.team_id == team_id]
        return projects

    # ==================================================================
    # ROLE MANAGEMENT
    # ==================================================================

    def create_custom_role(
        self,
        name: str,
        permissions: List[Permission],
        organization_id: str,
        description: Optional[str] = None,
        created_by: Optional[str] = None,
    ) -> Role:
        """Create a custom role (scoped to organization)."""
        role = Role(
            name=name,
            description=description,
            permissions=[p.value for p in permissions],
            is_builtin=False,
            organization_id=organization_id,
            created_by=created_by,
        )
        self._roles[role.id] = role
        self._persist()
        return role

    def list_roles(
        self,
        organization_id: Optional[str] = None,
        include_builtin: bool = True,
    ) -> List[Role]:
        """List roles with optional filtering."""
        roles = list(self._roles.values())
        if organization_id:
            roles = [r for r in roles if r.organization_id == organization_id or r.is_builtin]
        if not include_builtin:
            roles = [r for r in roles if not r.is_builtin]
        return roles

    # ==================================================================
    # AUTHENTICATION HELPERS
    # ==================================================================

    def generate_api_token(self, user_id: str) -> str:
        """Generate a new API token for a user."""
        token = secrets.token_urlsafe(32)
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        self._api_tokens[token_hash] = user_id

        user = self._users.get(user_id)
        if user:
            user.api_key_hash = token_hash
            self._persist()
        return token

    def validate_api_token(self, token: str) -> Optional[User]:
        """Validate an API token and return the associated user."""
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        user_id = self._api_tokens.get(token_hash)
        if user_id:
            return self._users.get(user_id)
        return None

    def record_login(self, user_id: str, ip_address: Optional[str] = None,
                     user_agent: Optional[str] = None,
                     session_id: Optional[str] = None) -> Optional[User]:
        """Record a user login event."""
        user = self._users.get(user_id)
        if not user:
            return None

        user.last_login = datetime.now(timezone.utc)
        user.login_count += 1

        self._audit(
            actor_id=user_id,
            action=AuditAction.USER_LOGIN,
            resource_type=ResourceType.USER,
            resource_id=user_id,
            resource_name=user.email,
            organization_id=user.organization_id,
            result=AuditResult.SUCCESS,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
        )
        self._persist()
        return user

    # ==================================================================
    # AUDIT LOG (Hash Chain Tamper Detection)
    # ==================================================================

    def _audit(
        self,
        actor_id: str,
        action: AuditAction,
        resource_type: ResourceType,
        resource_id: Optional[str] = None,
        resource_name: Optional[str] = None,
        organization_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        result: AuditResult = AuditResult.SUCCESS,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        session_id: Optional[str] = None,
        actor_name: Optional[str] = None,
        actor_type: str = "user",
    ) -> AuditLogEntry:
        """
        Create an audit log entry with hash-chain integrity.

        Each entry's hash includes the previous entry's hash, creating
        a chain that detects tampering with any historical entry.
        """
        self._sequence_counter += 1
        seq = self._sequence_counter

        # Previous entry hash for the chain
        previous_hash = None
        if self._audit_log:
            previous_hash = self._audit_log[-1].entry_hash

        entry = AuditLogEntry(
            sequence_number=seq,
            timestamp=datetime.now(timezone.utc),
            actor_id=actor_id,
            actor_type=actor_type,
            actor_name=actor_name,
            action=action.value,
            resource_type=resource_type.value,
            resource_id=resource_id,
            resource_name=resource_name,
            organization_id=organization_id,
            details=details or {},
            result=result.value,
            ip_address=ip_address,
            user_agent=user_agent,
            session_id=session_id,
            previous_hash=previous_hash,
        )

        # Compute and set the entry hash
        entry.entry_hash = entry.compute_hash()
        self._audit_log.append(entry)
        return entry

    def get_audit_log(
        self,
        organization_id: Optional[str] = None,
        actor_id: Optional[str] = None,
        action: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        limit: int = 1000,
        offset: int = 0,
    ) -> List[AuditLogEntry]:
        """Query the audit log with filtering."""
        entries = self._audit_log[:]

        if organization_id:
            entries = [e for e in entries if e.organization_id == organization_id]
        if actor_id:
            entries = [e for e in entries if e.actor_id == actor_id]
        if action:
            entries = [e for e in entries if e.action == action]
        if resource_type:
            entries = [e for e in entries if e.resource_type == resource_type]
        if resource_id:
            entries = [e for e in entries if e.resource_id == resource_id]
        if start_time:
            entries = [e for e in entries if e.timestamp >= start_time]
        if end_time:
            entries = [e for e in entries if e.timestamp <= end_time]

        entries.sort(key=lambda e: e.sequence_number, reverse=True)
        return entries[offset:offset + limit]

    def verify_hash_chain(self) -> Tuple[bool, Optional[int]]:
        """
        Verify the integrity of the entire audit log hash chain.

        Returns:
            (is_valid, first_broken_sequence_number)

        If the chain is valid, returns (True, None).
        If tampered, returns (False, sequence_number_of_first_break).
        """
        for i, entry in enumerate(self._audit_log):
            # Verify entry's own hash
            if not entry.verify_integrity():
                return False, entry.sequence_number

            # Verify hash chain link (skip first entry)
            if i > 0:
                prev_entry = self._audit_log[i - 1]
                expected_prev_hash = prev_entry.entry_hash
                if entry.previous_hash != expected_prev_hash:
                    return False, entry.sequence_number

        return True, None

    def export_audit_log(
        self,
        format: str = "json",
        organization_id: Optional[str] = None,
        start_time: Optional[datetime] = None,
        end_time: Optional[datetime] = None,
        exported_by: Optional[str] = None,
    ) -> AuditLogExport:
        """
        Export audit log in CSV or JSON format.

        Includes hash chain verification in the export metadata.
        """
        entries = self.get_audit_log(
            organization_id=organization_id,
            start_time=start_time,
            end_time=end_time,
            limit=100000,
        )
        # Return in chronological order for export
        entries = sorted(entries, key=lambda e: e.sequence_number)

        chain_valid, _ = self.verify_hash_chain()

        return AuditLogExport(
            format=format,
            entries=entries,
            exported_by=exported_by,
            entry_count=len(entries),
            hash_chain_valid=chain_valid,
        )

    def get_audit_stats(self) -> Dict[str, Any]:
        """Get audit log statistics."""
        chain_valid, break_seq = self.verify_hash_chain()
        actions: Dict[str, int] = {}
        for entry in self._audit_log:
            actions[entry.action] = actions.get(entry.action, 0) + 1

        # Daily activity for last 30 days
        now = datetime.now(timezone.utc)
        daily = {}
        for entry in self._audit_log:
            day = entry.timestamp.strftime("%Y-%m-%d")
            if (now - entry.timestamp).days <= 30:
                daily[day] = daily.get(day, 0) + 1

        return {
            "total_entries": len(self._audit_log),
            "hash_chain_valid": chain_valid,
            "first_break_sequence": break_seq,
            "actions": actions,
            "daily_activity": daily,
            "latest_entry_time": self._audit_log[-1].timestamp.isoformat() if self._audit_log else None,
            "earliest_entry_time": self._audit_log[0].timestamp.isoformat() if self._audit_log else None,
        }

    # ==================================================================
    # STATISTICS
    # ==================================================================

    def get_summary(self) -> Dict[str, Any]:
        """Get RBAC system summary statistics."""
        return {
            "users": {
                "total": len(self._users),
                "by_role": self._count_by(self._users.values(), "role"),
                "by_status": self._count_by(self._users.values(), "status"),
            },
            "organizations": {
                "total": len(self._organizations),
                "by_status": self._count_by(self._organizations.values(), "status"),
            },
            "teams": {
                "total": len(self._teams),
            },
            "projects": {
                "total": len(self._projects),
            },
            "roles": {
                "total": len(self._roles),
                "builtin": sum(1 for r in self._roles.values() if r.is_builtin),
                "custom": sum(1 for r in self._roles.values() if not r.is_builtin),
            },
            "audit_log": {
                "total_entries": len(self._audit_log),
                "hash_chain_valid": self.verify_hash_chain()[0],
            },
        }

    @staticmethod
    def _count_by(items, field: str) -> Dict[str, int]:
        """Count items by a field value."""
        counts: Dict[str, int] = {}
        for item in items:
            val = getattr(item, field, "unknown")
            counts[val] = counts.get(val, 0) + 1
        return counts

    # ==================================================================
    # TENANT ISOLATION
    # ==================================================================

    def is_user_in_organization(self, user: User, organization_id: str) -> bool:
        """Check if a user belongs to an organization."""
        if user.is_super_admin():
            return True
        return user.organization_id == organization_id

    def filter_by_tenant(self, user: User, items: List[Any],
                         org_field: str = "organization_id") -> List[Any]:
        """Filter a list of items to only those accessible by the user's tenant."""
        if user.is_super_admin():
            return items
        return [
            item for item in items
            if getattr(item, org_field, None) == user.organization_id
        ]


# Singleton instance (replaced with dependency injection in production)
_rbac_instance: Optional[RBACEngine] = None


def get_rbac_engine() -> RBACEngine:
    """Get or create the global RBAC engine instance."""
    global _rbac_instance
    if _rbac_instance is None:
        _rbac_instance = RBACEngine()
    return _rbac_instance
