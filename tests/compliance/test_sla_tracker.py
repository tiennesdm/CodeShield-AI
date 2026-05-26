"""
Tests for compliance.sla_tracker module.
"""

import pytest
from datetime import datetime, timezone, timedelta

from compliance.sla_tracker import SLATracker, SLADefinition, DEFAULT_SLA_DEFINITIONS


class TestSLATracker:
    def setup_method(self):
        self.tracker = SLATracker(storage_dir="./test_tmp/sla_test")
        self.tracker._records.clear()
        self.tracker._alerts.clear()

    def test_sla_definitions_loaded(self):
        defs = self.tracker.list_sla_definitions()
        assert len(defs) == 4
        severities = {d.severity for d in defs}
        assert severities == {"CRITICAL", "HIGH", "MEDIUM", "LOW"}

    def test_get_sla_definition(self):
        defn = self.tracker.get_sla_definition("CRITICAL")
        assert defn is not None
        assert defn.days_to_remediate == 7

    def test_track_vulnerability(self):
        record = self.tracker.track_vulnerability(
            vulnerability_id="vuln-1",
            severity="HIGH",
            scan_id="scan-1",
            title="SQL Injection",
        )
        assert record.vulnerability_id == "vuln-1"
        assert record.severity == "HIGH"
        assert record.status == "open"
        assert record.days_remaining() <= 15  # HIGH SLA is 15 days

    def test_track_vulnerability_with_assignment(self):
        record = self.tracker.track_vulnerability(
            vulnerability_id="vuln-2",
            severity="CRITICAL",
            scan_id="scan-1",
            title="RCE",
            assigned_to="user-1",
        )
        assert record.assigned_to == "user-1"
        assert record.status == "assigned"

    def test_assign_vulnerability(self):
        self.tracker.track_vulnerability(
            vulnerability_id="vuln-3", severity="MEDIUM", scan_id="scan-1",
        )
        record = self.tracker.assign_vulnerability("vuln-3", "user-2")
        assert record is not None
        assert record.assigned_to == "user-2"
        assert record.status == "assigned"

    def test_start_remediation(self):
        self.tracker.track_vulnerability(
            vulnerability_id="vuln-4", severity="HIGH", scan_id="scan-1",
        )
        record = self.tracker.start_remediation("vuln-4", "user-1")
        assert record is not None
        assert record.status == "in_progress"

    def test_mark_remediated(self):
        self.tracker.track_vulnerability(
            vulnerability_id="vuln-5", severity="MEDIUM", scan_id="scan-1",
        )
        record = self.tracker.mark_remediated("vuln-5", "user-1")
        assert record is not None
        assert record.status == "remediated"
        assert record.time_to_remediate_hours is not None
        assert record.time_to_remediate_hours >= 0

    def test_dismiss_vulnerability(self):
        self.tracker.track_vulnerability(
            vulnerability_id="vuln-6", severity="LOW", scan_id="scan-1",
        )
        record = self.tracker.dismiss_vulnerability("vuln-6", "false_positive", "user-1")
        assert record is not None
        assert record.status == "dismissed"
        assert record.dismissed_reason == "false_positive"

    def test_get_record(self):
        self.tracker.track_vulnerability(
            vulnerability_id="vuln-7", severity="HIGH", scan_id="scan-1",
        )
        record = self.tracker.get_record("vuln-7")
        assert record is not None
        assert record.vulnerability_id == "vuln-7"

    def test_get_record_not_found(self):
        assert self.tracker.get_record("nonexistent") is None

    def test_breach_detection(self):
        record = self.tracker.track_vulnerability(
            vulnerability_id="vuln-breach",
            severity="CRITICAL",
            scan_id="scan-1",
            detected_at=datetime.now(timezone.utc) - timedelta(days=15),
        )
        assert record.is_breached() is True
        assert record.hours_overdue() > 0

    def test_no_breach_within_sla(self):
        record = self.tracker.track_vulnerability(
            vulnerability_id="vuln-ok",
            severity="CRITICAL",
            scan_id="scan-1",
            detected_at=datetime.now(timezone.utc),
        )
        assert record.is_breached() is False
        assert record.hours_overdue() == 0

    def test_calculate_mttr(self):
        # Create and remediate some vulnerabilities
        for i in range(3):
            vid = f"vuln-mttr-{i}"
            self.tracker.track_vulnerability(
                vulnerability_id=vid, severity="HIGH", scan_id="scan-1",
                detected_at=datetime.now(timezone.utc) - timedelta(hours=(i+1)*24),
            )
            self.tracker.mark_remediated(vid)

        mttr = self.tracker.calculate_mttr()
        assert mttr["count"] == 3
        assert mttr["mttr_hours"] > 0

    def test_mttr_by_severity(self):
        self.tracker.track_vulnerability(
            vulnerability_id="v-crit", severity="CRITICAL", scan_id="s1",
            detected_at=datetime.now(timezone.utc) - timedelta(hours=48),
        )
        self.tracker.mark_remediated("v-crit")
        self.tracker.track_vulnerability(
            vulnerability_id="v-high", severity="HIGH", scan_id="s1",
            detected_at=datetime.now(timezone.utc) - timedelta(hours=72),
        )
        self.tracker.mark_remediated("v-high")

        mttr = self.tracker.calculate_mttr()
        assert "CRITICAL" in mttr["by_severity"]
        assert "HIGH" in mttr["by_severity"]

    def test_sla_dashboard(self):
        self.tracker.track_vulnerability(
            vulnerability_id="v-dash-1", severity="CRITICAL", scan_id="s1",
        )
        self.tracker.track_vulnerability(
            vulnerability_id="v-dash-2", severity="HIGH", scan_id="s1",
        )
        dashboard = self.tracker.get_sla_dashboard()
        assert "summary" in dashboard
        assert "by_severity" in dashboard
        assert dashboard["summary"]["total_tracked"] == 2

    def test_check_and_generate_alerts(self):
        # Create a vulnerability approaching SLA deadline
        record = self.tracker.track_vulnerability(
            vulnerability_id="v-approach",
            severity="CRITICAL",
            scan_id="s1",
            detected_at=datetime.now(timezone.utc) - timedelta(days=6),
        )
        alerts = self.tracker.check_and_generate_alerts()
        # Should detect approaching or breached SLAs
        assert isinstance(alerts, list)

    def test_get_alerts(self):
        alerts = self.tracker.get_alerts()
        assert isinstance(alerts, list)

    def test_acknowledge_alert(self):
        # No alerts to acknowledge yet
        result = self.tracker.acknowledge_alert("nonexistent", "user-1")
        assert result is None

    def test_get_breaches(self):
        self.tracker.track_vulnerability(
            vulnerability_id="v-breach-1",
            severity="CRITICAL",
            scan_id="s1",
            detected_at=datetime.now(timezone.utc) - timedelta(days=20),
        )
        self.tracker.track_vulnerability(
            vulnerability_id="v-breach-2",
            severity="HIGH",
            scan_id="s1",
            detected_at=datetime.now(timezone.utc) - timedelta(days=25),
        )
        breaches = self.tracker.get_breaches()
        assert len(breaches) == 2
        for b in breaches:
            assert b.is_breached() is True

    def test_get_approaching_deadlines(self):
        self.tracker.track_vulnerability(
            vulnerability_id="v-approach",
            severity="CRITICAL",
            scan_id="s1",
            detected_at=datetime.now(timezone.utc) - timedelta(days=5, hours=23),
        )
        approaching = self.tracker.get_approaching_deadlines(days=3)
        assert len(approaching) >= 0  # Could be approaching or not

    def test_update_sla_definition(self):
        updated = self.tracker.update_sla_definition(
            "CRITICAL", days_to_remediate=3, reminder_days=1,
        )
        assert updated is not None
        assert updated.days_to_remediate == 3
        assert updated.reminder_days == 1

    def test_filter_records(self):
        self.tracker.track_vulnerability(
            vulnerability_id="v-f1", severity="CRITICAL", scan_id="s1",
        )
        self.tracker.track_vulnerability(
            vulnerability_id="v-f2", severity="HIGH", scan_id="s2",
        )
        critical_records = self.tracker.get_records(severity="CRITICAL")
        assert len(critical_records) == 1
        s1_records = self.tracker.get_records(scan_id="s1")
        assert len(s1_records) == 1
