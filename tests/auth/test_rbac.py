"""
Tests for auth.rbac module - RBAC Engine.
"""

import pytest
from datetime import datetime, timezone, timedelta

from auth.rbac import RBACEngine, PermissionDeniedError
from auth.models import (
    AuditAction, AuditResult, Organization, Permission, ResourceType,
    RoleName, Team, User,
)


class TestRBACEngine:
    def setup_method(self):
        self.rbac = RBACEngine(storage_dir="./test_tmp/rbac_test")
        # Clear any existing data
        self.rbac._users.clear()
        self.rbac._users_by_email.clear()
        self.rbac._organizations.clear()
        self.rbac._teams.clear()
        self.rbac._projects.clear()
        self.rbac._audit_log.clear()
        self.rbac._sequence_counter = 0

    def test_create_user(self):
        user = self.rbac.create_user(email="alice@corp.com", role=RoleName.DEVELOPER)
        assert user.email == "alice@corp.com"
        assert user.role == "developer"
        assert user.id in self.rbac._users

    def test_create_user_duplicate_email(self):
        self.rbac.create_user(email="alice@corp.com")
        with pytest.raises(Exception):
            self.rbac.create_user(email="alice@corp.com")

    def test_get_user(self):
        user = self.rbac.create_user(email="bob@corp.com", role=RoleName.SECURITY_LEAD)
        found = self.rbac.get_user(user.id)
        assert found is not None
        assert found.id == user.id

    def test_list_users_filtering(self):
        self.rbac.create_user(email="a@corp.com", role=RoleName.DEVELOPER)
        self.rbac.create_user(email="b@corp.com", role=RoleName.VIEWER)
        devs = self.rbac.list_users(role="developer")
        assert len(devs) == 1
        viewers = self.rbac.list_users(role="viewer")
        assert len(viewers) == 1

    def test_update_user(self):
        user = self.rbac.create_user(email="charlie@corp.com", role=RoleName.VIEWER)
        updated = self.rbac.update_user(user.id, {"full_name": "Charlie Brown"})
        assert updated is not None
        assert updated.full_name == "Charlie Brown"

    def test_set_user_role(self):
        user = self.rbac.create_user(email="dave@corp.com", role=RoleName.VIEWER)
        updated = self.rbac.set_user_role(user.id, RoleName.SECURITY_LEAD, "system")
        assert updated is not None
        assert updated.role == "security_lead"

    def test_delete_user(self):
        user = self.rbac.create_user(email="eve@corp.com")
        result = self.rbac.delete_user(user.id)
        assert result is True
        found = self.rbac.get_user(user.id)
        assert found.status == "inactive"

    # --- Permission Checking ---

    def test_check_permission_super_admin(self):
        admin = self.rbac.create_user(email="admin@corp.com", role=RoleName.SUPER_ADMIN)
        assert self.rbac.check_permission(admin, Permission.SCAN_DELETE) is True
        assert self.rbac.check_permission(admin, Permission.PLATFORM_ADMIN) is True

    def test_check_permission_developer(self):
        dev = self.rbac.create_user(email="dev@corp.com", role=RoleName.DEVELOPER)
        assert self.rbac.check_permission(dev, Permission.SCAN_CREATE) is True
        assert self.rbac.check_permission(dev, Permission.SCAN_READ) is True
        assert self.rbac.check_permission(dev, Permission.USER_MANAGE) is False
        assert self.rbac.check_permission(dev, Permission.VULN_READ) is True

    def test_check_permission_viewer(self):
        viewer = self.rbac.create_user(email="view@corp.com", role=RoleName.VIEWER)
        assert self.rbac.check_permission(viewer, Permission.SCAN_READ) is True
        assert self.rbac.check_permission(viewer, Permission.SCAN_CREATE) is False

    def test_require_permission_raises(self):
        viewer = self.rbac.create_user(email="view2@corp.com", role=RoleName.VIEWER)
        with pytest.raises(PermissionDeniedError):
            self.rbac.require_permission(viewer, Permission.SCAN_CREATE)

    def test_require_permission_success(self):
        admin = self.rbac.create_user(email="admin2@corp.com", role=RoleName.SUPER_ADMIN)
        self.rbac.require_permission(admin, Permission.SCAN_CREATE)

    # --- Organization Management ---

    def test_create_organization(self):
        org = self.rbac.create_organization(name="Acme Corp", billing_email="billing@acme.com")
        assert org.name == "Acme Corp"
        assert org.billing_email == "billing@acme.com"
        assert org.id in self.rbac._organizations

    def test_get_organization(self):
        org = self.rbac.create_organization(name="Test Org")
        found = self.rbac.get_organization(org.id)
        assert found is not None
        assert found.name == "Test Org"

    def test_update_organization(self):
        org = self.rbac.create_organization(name="Old Name")
        updated = self.rbac.update_organization(org.id, {"name": "New Name"})
        assert updated is not None
        assert updated.name == "New Name"

    # --- Team Management ---

    def test_create_team(self):
        org = self.rbac.create_organization(name="Parent Org")
        team = self.rbac.create_team(name="Backend Team", organization_id=org.id)
        assert team.name == "Backend Team"
        assert team.organization_id == org.id

    def test_create_team_no_org(self):
        with pytest.raises(Exception):
            self.rbac.create_team(name="Orphan Team", organization_id="nonexistent")

    def test_add_team_member(self):
        org = self.rbac.create_organization(name="Org")
        team = self.rbac.create_team(name="Team", organization_id=org.id)
        user = self.rbac.create_user(email="member@corp.com", role=RoleName.DEVELOPER)
        result = self.rbac.add_team_member(team.id, user.id)
        assert result is not None
        assert user.id in team.member_ids
        assert team.id in user.team_ids

    def test_remove_team_member(self):
        org = self.rbac.create_organization(name="Org")
        team = self.rbac.create_team(name="Team", organization_id=org.id)
        user = self.rbac.create_user(email="member2@corp.com", role=RoleName.DEVELOPER)
        self.rbac.add_team_member(team.id, user.id)
        result = self.rbac.remove_team_member(team.id, user.id)
        assert result is not None
        assert user.id not in team.member_ids

    def test_get_team_members(self):
        org = self.rbac.create_organization(name="Org")
        team = self.rbac.create_team(name="Team", organization_id=org.id)
        user1 = self.rbac.create_user(email="u1@corp.com")
        user2 = self.rbac.create_user(email="u2@corp.com")
        self.rbac.add_team_member(team.id, user1.id)
        self.rbac.add_team_member(team.id, user2.id)
        members = self.rbac.get_team_members(team.id)
        assert len(members) == 2

    def test_delete_team(self):
        org = self.rbac.create_organization(name="Org")
        team = self.rbac.create_team(name="Team", organization_id=org.id)
        result = self.rbac.delete_team(team.id)
        assert result is True
        assert team.status == "archived"

    # --- Project Management ---

    def test_create_project(self):
        org = self.rbac.create_organization(name="Org")
        project = self.rbac.create_project(name="Web App", organization_id=org.id)
        assert project.name == "Web App"
        assert project.organization_id == org.id

    def test_list_projects(self):
        org = self.rbac.create_organization(name="Org")
        self.rbac.create_project(name="P1", organization_id=org.id)
        self.rbac.create_project(name="P2", organization_id=org.id)
        projects = self.rbac.list_projects(organization_id=org.id)
        assert len(projects) == 2

    # --- Role Management ---

    def test_list_roles(self):
        roles = self.rbac.list_roles()
        role_names = {r.name for r in roles}
        assert "super_admin" in role_names
        assert "tenant_admin" in role_names
        assert "security_lead" in role_names
        assert "developer" in role_names
        assert "viewer" in role_names

    def test_create_custom_role(self):
        org = self.rbac.create_organization(name="Org")
        role = self.rbac.create_custom_role(
            name="Custom Role",
            permissions=[Permission.SCAN_READ, Permission.VULN_READ],
            organization_id=org.id,
        )
        assert role.name == "Custom Role"
        assert role.is_builtin is False
        assert Permission.SCAN_READ.value in role.permissions

    # --- Authentication Helpers ---

    def test_record_login(self):
        user = self.rbac.create_user(email="login@corp.com")
        result = self.rbac.record_login(user.id, ip_address="1.2.3.4")
        assert result is not None
        assert result.last_login is not None
        assert result.login_count == 1

    # --- Audit Log ---

    def test_audit_log_creation(self):
        entry = self.rbac._audit(
            actor_id="user-1",
            action=AuditAction.SCAN_CREATED,
            resource_type=ResourceType.SCAN,
            resource_id="scan-1",
            details={"tool": "semgrep"},
        )
        assert entry.sequence_number == 1
        assert entry.entry_hash is not None
        assert len(self.rbac._audit_log) == 1

    def test_audit_log_hash_chain(self):
        self.rbac._audit(
            actor_id="u1", action=AuditAction.SCAN_CREATED,
            resource_type=ResourceType.SCAN, resource_id="s1",
        )
        self.rbac._audit(
            actor_id="u1", action=AuditAction.SCAN_STARTED,
            resource_type=ResourceType.SCAN, resource_id="s1",
        )
        self.rbac._audit(
            actor_id="u1", action=AuditAction.SCAN_COMPLETED,
            resource_type=ResourceType.SCAN, resource_id="s1",
        )
        assert len(self.rbac._audit_log) == 3
        is_valid, break_seq = self.rbac.verify_hash_chain()
        assert is_valid is True
        assert break_seq is None

    def test_audit_log_filtering(self):
        self.rbac._audit(
            actor_id="u1", action=AuditAction.SCAN_CREATED,
            resource_type=ResourceType.SCAN, resource_id="s1",
        )
        self.rbac._audit(
            actor_id="u2", action=AuditAction.USER_CREATED,
            resource_type=ResourceType.USER, resource_id="u3",
        )
        scan_entries = self.rbac.get_audit_log(action="scan:created")
        assert len(scan_entries) == 1
        user_entries = self.rbac.get_audit_log(action="user:created")
        assert len(user_entries) == 1

    def test_audit_log_export(self):
        self.rbac._audit(
            actor_id="u1", action=AuditAction.SCAN_CREATED,
            resource_type=ResourceType.SCAN, resource_id="s1",
        )
        export = self.rbac.export_audit_log(format="csv")
        assert export.entry_count == 1
        assert export.hash_chain_valid is True
        csv_content = export.to_csv()
        assert "sequence_number" in csv_content
        assert "1" in csv_content

    def test_audit_stats(self):
        self.rbac._audit(
            actor_id="u1", action=AuditAction.SCAN_CREATED,
            resource_type=ResourceType.SCAN, resource_id="s1",
        )
        self.rbac._audit(
            actor_id="u1", action=AuditAction.SCAN_COMPLETED,
            resource_type=ResourceType.SCAN, resource_id="s1",
        )
        stats = self.rbac.get_audit_stats()
        assert stats["total_entries"] == 2
        assert stats["hash_chain_valid"] is True

    # --- Resource Access ---

    def test_grant_and_check_resource_access(self):
        user = self.rbac.create_user(email="res@corp.com", role=RoleName.VIEWER)
        self.rbac.grant_resource_access(
            user_id=user.id,
            resource_type=ResourceType.SCAN,
            resource_id="scan-special",
            permissions=[Permission.SCAN_READ, Permission.VULN_READ],
            granted_by="admin",
        )
        assert self.rbac._has_resource_access(
            user.id, ResourceType.SCAN, "scan-special", Permission.SCAN_READ
        ) is True

    def test_revoke_resource_access(self):
        user = self.rbac.create_user(email="rev@corp.com", role=RoleName.VIEWER)
        self.rbac.grant_resource_access(
            user_id=user.id, resource_type=ResourceType.SCAN,
            resource_id="scan-x", permissions=[Permission.SCAN_READ],
            granted_by="admin",
        )
        result = self.rbac.revoke_resource_access(user.id, "scan-x", "admin")
        assert result is True

    # --- Tenant Isolation ---

    def test_tenant_isolation(self):
        org1 = self.rbac.create_organization(name="Org 1")
        user1 = self.rbac.create_user(email="u1@corp.com", organization_id=org1.id)
        assert self.rbac.is_user_in_organization(user1, org1.id) is True

    # --- Summary ---

    def test_get_summary(self):
        summary = self.rbac.get_summary()
        assert "users" in summary
        assert "organizations" in summary
        assert "teams" in summary
        assert "roles" in summary
        assert "audit_log" in summary
