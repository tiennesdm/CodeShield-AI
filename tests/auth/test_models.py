"""
Tests for auth.models module.
"""

import pytest
from datetime import datetime, timezone, timedelta

from auth.models import (
    AuditLogEntry, Organization, Permission, Role, RoleName,
    SLADefinition, SLATracking, Team, User, create_builtin_role,
    ROLE_PERMISSIONS, DEFAULT_SLA_DEFINITIONS,
)


class TestUser:
    def test_user_creation(self):
        user = User(email="alice@corp.com", role=RoleName.DEVELOPER.value)
        assert user.email == "alice@corp.com"
        assert user.role == "developer"
        assert user.username == "alice"
        assert user.status == "active"
        assert user.id is not None

    def test_user_is_super_admin(self):
        admin = User(email="admin@corp.com", role=RoleName.SUPER_ADMIN.value)
        assert admin.is_super_admin() is True
        dev = User(email="dev@corp.com", role=RoleName.DEVELOPER.value)
        assert dev.is_super_admin() is False

    def test_user_is_tenant_admin(self):
        ta = User(email="ta@corp.com", role=RoleName.TENANT_ADMIN.value)
        assert ta.is_tenant_admin() is True
        dev = User(email="dev@corp.com", role=RoleName.DEVELOPER.value)
        assert dev.is_tenant_admin() is False

    def test_user_permissions(self):
        admin = User(email="admin@corp.com", role=RoleName.SUPER_ADMIN.value)
        perms = admin.get_permissions()
        assert Permission.SCAN_CREATE.value in perms
        assert Permission.USER_MANAGE.value in perms
        assert Permission.PLATFORM_ADMIN.value in perms

        viewer = User(email="view@corp.com", role=RoleName.VIEWER.value)
        v_perms = viewer.get_permissions()
        assert Permission.SCAN_READ.value in v_perms
        assert Permission.SCAN_CREATE.value not in v_perms

    def test_user_has_permission(self):
        admin = User(email="admin@corp.com", role=RoleName.SUPER_ADMIN.value)
        assert admin.has_permission(Permission.SCAN_DELETE) is True
        viewer = User(email="view@corp.com", role=RoleName.VIEWER.value)
        assert viewer.has_permission(Permission.SCAN_READ) is True
        assert viewer.has_permission(Permission.SCAN_CREATE) is False

    def test_to_dict_excludes_sensitive(self):
        user = User(email="test@corp.com")
        data = user.to_dict()
        assert "api_key_hash" not in data
        assert "sso_subject_id" not in data

        data_sensitive = user.to_dict(include_sensitive=True)
        assert "api_key_hash" in data_sensitive


class TestOrganization:
    def test_organization_creation(self):
        org = Organization(name="Acme Corp")
        assert org.name == "Acme Corp"
        assert org.slug == "acme-corp"
        assert org.status == "active"
        assert org.plan == "enterprise"

    def test_custom_slug(self):
        org = Organization(name="Acme Corp", slug="custom")
        assert org.slug == "custom"


class TestTeam:
    def test_team_creation(self):
        team = Team(name="Backend", organization_id="org-123")
        assert team.name == "Backend"
        assert team.organization_id == "org-123"
        assert team.member_ids == []
        assert team.status == "active"


class TestRole:
    def test_builtin_role(self):
        role = create_builtin_role(RoleName.SECURITY_LEAD)
        assert role.name == "security_lead"
        assert role.is_builtin is True
        assert Permission.SCAN_CREATE.value in role.permissions

    def test_has_permission(self):
        role = create_builtin_role(RoleName.DEVELOPER)
        assert role.has_permission(Permission.SCAN_READ) is True
        assert role.has_permission(Permission.USER_MANAGE) is False


class TestAuditLogEntry:
    def test_compute_hash(self):
        from datetime import datetime, timezone
        ts = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        entry = AuditLogEntry(
            sequence_number=1,
            timestamp=ts,
            actor_id="user-1",
            actor_type="user",
            action="scan:create",
            resource_type="scan",
            resource_id="scan-1",
            result="success",
        )
        hash1 = entry.compute_hash()
        assert hash1 is not None
        assert len(hash1) == 64  # SHA-256 hex length

        # Same data should produce same hash
        entry2 = AuditLogEntry(
            sequence_number=1,
            timestamp=ts,
            actor_id="user-1",
            actor_type="user",
            action="scan:create",
            resource_type="scan",
            resource_id="scan-1",
            result="success",
        )
        assert entry.compute_hash() == entry2.compute_hash()

        # Different data should produce different hash
        entry3 = AuditLogEntry(
            sequence_number=2,
            timestamp=ts,
            actor_id="user-1",
            actor_type="user",
            action="scan:create",
            resource_type="scan",
            resource_id="scan-1",
            result="success",
        )
        assert entry.compute_hash() != entry3.compute_hash()

    def test_hash_chain_integrity(self):
        from datetime import datetime, timezone
        ts = datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)
        entry1 = AuditLogEntry(
            sequence_number=1, timestamp=ts, actor_id="u1", actor_type="user",
            action="scan:create", resource_type="scan", resource_id="s1",
            result="success",
        )
        entry1.entry_hash = entry1.compute_hash()

        entry2 = AuditLogEntry(
            sequence_number=2, timestamp=ts, actor_id="u1", actor_type="user",
            action="scan:delete", resource_type="scan", resource_id="s1",
            result="success", previous_hash=entry1.entry_hash,
        )
        entry2.entry_hash = entry2.compute_hash()

        assert entry1.verify_integrity() is True
        assert entry2.verify_integrity() is True
        assert entry2.previous_hash == entry1.entry_hash


class TestSLADefinition:
    def test_default_sla_definitions(self):
        assert len(DEFAULT_SLA_DEFINITIONS) == 4
        critical = [d for d in DEFAULT_SLA_DEFINITIONS if d.severity == "CRITICAL"][0]
        assert critical.days_to_remediate == 7
        high = [d for d in DEFAULT_SLA_DEFINITIONS if d.severity == "HIGH"][0]
        assert high.days_to_remediate == 15


class TestSLATracking:
    def test_sla_days_remaining(self):
        now = datetime.now(timezone.utc)
        tracking = SLATracking(
            vulnerability_id="v1", scan_id="s1", severity="CRITICAL",
            detected_at=now, sla_deadline=now + timedelta(days=5),
        )
        # Allow for timing variations (should be 4 or 5 days)
        assert 4 <= tracking.days_remaining <= 5

    def test_sla_breach_detection(self):
        now = datetime.now(timezone.utc)
        tracking = SLATracking(
            vulnerability_id="v1", scan_id="s1", severity="CRITICAL",
            detected_at=now - timedelta(days=10), sla_deadline=now - timedelta(days=3),
        )
        assert tracking.is_breached is True
        assert tracking.hours_overdue > 0

    def test_remediated_not_breached(self):
        now = datetime.now(timezone.utc)
        tracking = SLATracking(
            vulnerability_id="v1", scan_id="s1", severity="CRITICAL",
            detected_at=now - timedelta(days=5), sla_deadline=now + timedelta(days=2),
            remediated_at=now, status="remediated",
        )
        assert tracking.is_breached is False
        assert tracking.hours_overdue == 0
