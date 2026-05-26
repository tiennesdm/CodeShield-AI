"""
Enterprise Vulnerability SLA Tracker

Tracks vulnerability remediation SLAs with:
- Per-severity SLA definitions (CRITICAL: 7 days, HIGH: 15 days, etc.)
- SLA monitoring per vulnerability
- Breach detection and alerts
- MTTR calculation per severity

Usage:
    tracker = SLATracker()
    tracker.track_vulnerability(vuln_id="v-1", severity="CRITICAL", scan_id="s-1")
    breaches = tracker.get_breaches()
    mttr = tracker.calculate_mttr("CRITICAL")
"""

from __future__ import annotations

import json
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from uuid import uuid4

from pydantic import BaseModel, Field


class SLADefinition(BaseModel):
    """SLA definition for a specific severity level."""
    severity: str
    days_to_remediate: int
    reminder_days: int = 2
    escalation_days: int = 1
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class SLAEvent(BaseModel):
    """An event in the vulnerability SLA lifecycle."""
    event_type: str  # detected, assigned, remediation_started, remediated, dismissed
    timestamp: datetime
    actor_id: Optional[str] = None
    notes: Optional[str] = None


class SLATrackingRecord(BaseModel):
    """Complete SLA tracking record for a single vulnerability."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    vulnerability_id: str
    scan_id: str
    severity: str
    title: Optional[str] = None
    category: Optional[str] = None
    detected_at: datetime
    sla_deadline: datetime
    assigned_to: Optional[str] = None
    assigned_at: Optional[datetime] = None
    remediated_at: Optional[datetime] = None
    dismissed_at: Optional[datetime] = None
    dismissed_reason: Optional[str] = None
    status: str = "open"  # open, assigned, in_progress, remediated, breached, dismissed
    events: List[SLAEvent] = Field(default_factory=list)
    reminders_sent: int = 0
    last_reminder_at: Optional[datetime] = None
    escalations_sent: int = 0
    last_escalation_at: Optional[datetime] = None
    breach_duration_hours: Optional[float] = None
    time_to_remediate_hours: Optional[float] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

    def days_remaining(self) -> int:
        """Days remaining until SLA deadline."""
        now = datetime.now(timezone.utc)
        if self.status in ("remediated", "dismissed"):
            return 0
        delta = self.sla_deadline - now
        return max(0, delta.days)

    def is_breached(self) -> bool:
        """Check if SLA has been breached."""
        if self.status in ("remediated", "dismissed"):
            return False
        return datetime.now(timezone.utc) > self.sla_deadline

    def hours_overdue(self) -> float:
        """Hours past SLA deadline (0 if not breached)."""
        if not self.is_breached():
            return 0.0
        delta = datetime.now(timezone.utc) - self.sla_deadline
        return delta.total_seconds() / 3600

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "vulnerability_id": self.vulnerability_id,
            "scan_id": self.scan_id,
            "severity": self.severity,
            "title": self.title,
            "category": self.category,
            "detected_at": self.detected_at.isoformat(),
            "sla_deadline": self.sla_deadline.isoformat(),
            "assigned_to": self.assigned_to,
            "assigned_at": self.assigned_at.isoformat() if self.assigned_at else None,
            "remediated_at": self.remediated_at.isoformat() if self.remediated_at else None,
            "dismissed_at": self.dismissed_at.isoformat() if self.dismissed_at else None,
            "status": self.status,
            "days_remaining": self.days_remaining(),
            "is_breached": self.is_breached(),
            "hours_overdue": round(self.hours_overdue(), 2),
            "reminders_sent": self.reminders_sent,
            "escalations_sent": self.escalations_sent,
            "time_to_remediate_hours": round(self.time_to_remediate_hours, 2) if self.time_to_remediate_hours else None,
            "metadata": self.metadata,
        }


class SLABreachAlert(BaseModel):
    """An SLA breach alert notification."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    tracking_record_id: str
    vulnerability_id: str
    severity: str
    alert_type: str  # approaching, breached, escalated
    message: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    acknowledged: bool = False
    acknowledged_at: Optional[datetime] = None
    acknowledged_by: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


# Default SLA definitions
DEFAULT_SLA_DEFINITIONS: List[SLADefinition] = [
    SLADefinition(
        severity="CRITICAL", days_to_remediate=7,
        reminder_days=2, escalation_days=1,
        description="Critical vulnerabilities must be remediated within 7 calendar days",
    ),
    SLADefinition(
        severity="HIGH", days_to_remediate=15,
        reminder_days=3, escalation_days=2,
        description="High severity vulnerabilities must be remediated within 15 calendar days",
    ),
    SLADefinition(
        severity="MEDIUM", days_to_remediate=30,
        reminder_days=5, escalation_days=3,
        description="Medium severity vulnerabilities must be remediated within 30 calendar days",
    ),
    SLADefinition(
        severity="LOW", days_to_remediate=90,
        reminder_days=14, escalation_days=7,
        description="Low severity vulnerabilities must be remediated within 90 calendar days",
    ),
]


class SLATracker:
    """
    Enterprise SLA tracker for vulnerability remediation.

    Monitors each vulnerability's lifecycle from detection through remediation,
    tracking against severity-based SLA deadlines and generating alerts
    for approaching or breached SLAs.
    """

    def __init__(self, storage_dir: str = "./data/sla") -> None:
        self.storage_dir = Path(storage_dir)
        self.storage_dir.mkdir(parents=True, exist_ok=True)

        self._sla_definitions: Dict[str, SLADefinition] = {}
        for d in DEFAULT_SLA_DEFINITIONS:
            self._sla_definitions[d.severity] = d

        self._records: Dict[str, SLATrackingRecord] = {}  # vuln_id -> record
        self._alerts: List[SLABreachAlert] = []

        self._load_from_disk()

    def _persist(self) -> None:
        """Persist data to disk."""
        try:
            data = {
                "records": {k: v.model_dump() for k, v in self._records.items()},
                "alerts": [a.model_dump() for a in self._alerts],
                "sla_definitions": {k: v.model_dump() for k, v in self._sla_definitions.items()},
            }
            path = self.storage_dir / "sla_data.json"
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
        except Exception:
            pass

    def _load_from_disk(self) -> None:
        """Load data from disk."""
        path = self.storage_dir / "sla_data.json"
        if not path.exists():
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for vid, rd in data.get("records", {}).items():
                # Reconstruct datetime fields
                for df in ["detected_at", "sla_deadline", "assigned_at",
                           "remediated_at", "dismissed_at", "last_reminder_at", "last_escalation_at"]:
                    if rd.get(df):
                        try:
                            rd[df] = datetime.fromisoformat(rd[df])
                        except (ValueError, TypeError):
                            pass
                for ev in rd.get("events", []):
                    if ev.get("timestamp"):
                        try:
                            ev["timestamp"] = datetime.fromisoformat(ev["timestamp"])
                        except (ValueError, TypeError):
                            pass
                self._records[vid] = SLATrackingRecord(**rd)
            for alert_data in data.get("alerts", []):
                for df in ["created_at", "acknowledged_at"]:
                    if alert_data.get(df):
                        try:
                            alert_data[df] = datetime.fromisoformat(alert_data[df])
                        except (ValueError, TypeError):
                            pass
                self._alerts.append(SLABreachAlert(**alert_data))
        except Exception:
            pass

    # ------------------------------------------------------------------
    # SLA Configuration
    # ------------------------------------------------------------------

    def get_sla_definition(self, severity: str) -> Optional[SLADefinition]:
        """Get SLA definition for a severity level."""
        return self._sla_definitions.get(severity)

    def list_sla_definitions(self) -> List[SLADefinition]:
        """List all SLA definitions."""
        return list(self._sla_definitions.values())

    def update_sla_definition(
        self,
        severity: str,
        days_to_remediate: Optional[int] = None,
        reminder_days: Optional[int] = None,
        escalation_days: Optional[int] = None,
    ) -> Optional[SLADefinition]:
        """Update an SLA definition."""
        sla = self._sla_definitions.get(severity)
        if not sla:
            return None
        if days_to_remediate is not None:
            sla.days_to_remediate = days_to_remediate
        if reminder_days is not None:
            sla.reminder_days = reminder_days
        if escalation_days is not None:
            sla.escalation_days = escalation_days
        self._persist()
        return sla

    # ------------------------------------------------------------------
    # Vulnerability Tracking
    # ------------------------------------------------------------------

    def track_vulnerability(
        self,
        vulnerability_id: str,
        severity: str,
        scan_id: str,
        title: Optional[str] = None,
        category: Optional[str] = None,
        detected_at: Optional[datetime] = None,
        assigned_to: Optional[str] = None,
    ) -> SLATrackingRecord:
        """
        Start tracking SLA for a newly detected vulnerability.

        Args:
            vulnerability_id: Unique ID of the vulnerability
            severity: Severity level (CRITICAL, HIGH, MEDIUM, LOW)
            scan_id: ID of the scan that found the vulnerability
            title: Optional vulnerability title
            category: Optional vulnerability category
            detected_at: When the vulnerability was detected (default: now)
            assigned_to: Optional user ID to assign the vulnerability to
        """
        if vulnerability_id in self._records:
            return self._records[vulnerability_id]

        severity = severity.upper()
        now = detected_at or datetime.now(timezone.utc)

        # Calculate SLA deadline
        sla_def = self._sla_definitions.get(severity)
        if sla_def:
            sla_deadline = now + timedelta(days=sla_def.days_to_remediate)
        else:
            sla_deadline = now + timedelta(days=30)  # Default fallback

        record = SLATrackingRecord(
            vulnerability_id=vulnerability_id,
            scan_id=scan_id,
            severity=severity,
            title=title,
            category=category,
            detected_at=now,
            sla_deadline=sla_deadline,
            assigned_to=assigned_to,
            assigned_at=now if assigned_to else None,
            status="assigned" if assigned_to else "open",
            events=[SLAEvent(
                event_type="detected",
                timestamp=now,
                notes=f"Vulnerability detected with severity {severity}",
            )],
        )

        if assigned_to:
            record.events.append(SLAEvent(
                event_type="assigned",
                timestamp=now,
                notes=f"Assigned to {assigned_to}",
            ))

        self._records[vulnerability_id] = record
        self._persist()
        return record

    def get_record(self, vulnerability_id: str) -> Optional[SLATrackingRecord]:
        """Get tracking record for a vulnerability."""
        return self._records.get(vulnerability_id)

    def assign_vulnerability(
        self,
        vulnerability_id: str,
        assigned_to: str,
        actor_id: Optional[str] = None,
    ) -> Optional[SLATrackingRecord]:
        """Assign a vulnerability to a user."""
        record = self._records.get(vulnerability_id)
        if not record:
            return None

        record.assigned_to = assigned_to
        record.assigned_at = datetime.now(timezone.utc)
        record.status = "assigned"
        record.events.append(SLAEvent(
            event_type="assigned",
            timestamp=datetime.now(timezone.utc),
            actor_id=actor_id,
            notes=f"Assigned to {assigned_to}",
        ))
        self._persist()
        return record

    def start_remediation(
        self,
        vulnerability_id: str,
        actor_id: Optional[str] = None,
    ) -> Optional[SLATrackingRecord]:
        """Mark a vulnerability as being actively remediated."""
        record = self._records.get(vulnerability_id)
        if not record:
            return None

        record.status = "in_progress"
        record.events.append(SLAEvent(
            event_type="remediation_started",
            timestamp=datetime.now(timezone.utc),
            actor_id=actor_id,
        ))
        self._persist()
        return record

    def mark_remediated(
        self,
        vulnerability_id: str,
        actor_id: Optional[str] = None,
    ) -> Optional[SLATrackingRecord]:
        """Mark a vulnerability as remediated."""
        record = self._records.get(vulnerability_id)
        if not record:
            return None

        now = datetime.now(timezone.utc)
        record.remediated_at = now
        record.status = "remediated"

        # Calculate time to remediate
        delta = now - record.detected_at
        record.time_to_remediate_hours = delta.total_seconds() / 3600

        # Record breach duration if applicable
        if now > record.sla_deadline:
            record.breach_duration_hours = (now - record.sla_deadline).total_seconds() / 3600

        record.events.append(SLAEvent(
            event_type="remediated",
            timestamp=now,
            actor_id=actor_id,
            notes=f"Remediated in {record.time_to_remediate_hours:.1f} hours",
        ))
        self._persist()
        return record

    def dismiss_vulnerability(
        self,
        vulnerability_id: str,
        reason: str,
        actor_id: Optional[str] = None,
    ) -> Optional[SLATrackingRecord]:
        """Dismiss a vulnerability (e.g., false positive, accepted risk)."""
        record = self._records.get(vulnerability_id)
        if not record:
            return None

        now = datetime.now(timezone.utc)
        record.dismissed_at = now
        record.dismissed_reason = reason
        record.status = "dismissed"
        record.events.append(SLAEvent(
            event_type="dismissed",
            timestamp=now,
            actor_id=actor_id,
            notes=f"Dismissed: {reason}",
        ))
        self._persist()
        return record

    # ------------------------------------------------------------------
    # SLA Monitoring & Alerts
    # ------------------------------------------------------------------

    def check_and_generate_alerts(self) -> List[SLABreachAlert]:
        """
        Check all open vulnerabilities and generate alerts for:
        - Approaching SLA deadline
        - Breached SLA
        - Escalation needed (breach + escalation period)

        Returns list of newly generated alerts.
        """
        now = datetime.now(timezone.utc)
        new_alerts: List[SLABreachAlert] = []

        for record in self._records.values():
            if record.status in ("remediated", "dismissed"):
                continue

            sla_def = self._sla_definitions.get(record.severity)
            if not sla_def:
                continue

            # Check for approaching SLA
            time_to_deadline = record.sla_deadline - now
            approaching_threshold = timedelta(days=sla_def.reminder_days)

            if timedelta(0) < time_to_deadline <= approaching_threshold:
                # Check if we already sent a reminder recently
                if (record.last_reminder_at is None or
                        (now - record.last_reminder_at).days >= 1):
                    record.reminders_sent += 1
                    record.last_reminder_at = now
                    alert = SLABreachAlert(
                        tracking_record_id=record.id,
                        vulnerability_id=record.vulnerability_id,
                        severity=record.severity,
                        alert_type="approaching",
                        message=(
                            f"SLA approaching for {record.severity} vulnerability "
                            f"{record.vulnerability_id}: {record.days_remaining()} days remaining. "
                            f"Deadline: {record.sla_deadline.strftime('%Y-%m-%d')}"
                        ),
                    )
                    self._alerts.append(alert)
                    new_alerts.append(alert)

            # Check for breached SLA
            elif record.is_breached():
                escalation_threshold = timedelta(days=sla_def.escalation_days)
                time_since_breach = now - record.sla_deadline

                if time_since_breach <= escalation_threshold:
                    # Initial breach alert
                    if record.escalations_sent == 0:
                        record.escalations_sent += 1
                        record.last_escalation_at = now
                        alert = SLABreachAlert(
                            tracking_record_id=record.id,
                            vulnerability_id=record.vulnerability_id,
                            severity=record.severity,
                            alert_type="breached",
                            message=(
                                f"SLA BREACHED for {record.severity} vulnerability "
                                f"{record.vulnerability_id}. Overdue by {record.hours_overdue():.1f} hours. "
                                f"Deadline was: {record.sla_deadline.strftime('%Y-%m-%d')}"
                            ),
                        )
                        self._alerts.append(alert)
                        new_alerts.append(alert)
                else:
                    # Escalated - repeated breach
                    if (record.last_escalation_at is None or
                            (now - record.last_escalation_at).days >= 1):
                        record.escalations_sent += 1
                        record.last_escalation_at = now
                        alert = SLABreachAlert(
                            tracking_record_id=record.id,
                            vulnerability_id=record.vulnerability_id,
                            severity=record.severity,
                            alert_type="escalated",
                            message=(
                                f"SLA ESCALATED for {record.severity} vulnerability "
                                f"{record.vulnerability_id}. Overdue by {record.hours_overdue():.1f} hours. "
                                f"Escalation #{record.escalations_sent}. Immediate action required!"
                            ),
                        )
                        self._alerts.append(alert)
                        new_alerts.append(alert)

        if new_alerts:
            self._persist()
        return new_alerts

    def get_alerts(
        self,
        severity: Optional[str] = None,
        alert_type: Optional[str] = None,
        acknowledged: Optional[bool] = None,
        limit: int = 1000,
    ) -> List[SLABreachAlert]:
        """Get SLA alerts with optional filtering."""
        alerts = self._alerts[:]
        if severity:
            alerts = [a for a in alerts if a.severity == severity]
        if alert_type:
            alerts = [a for a in alerts if a.alert_type == alert_type]
        if acknowledged is not None:
            alerts = [a for a in alerts if a.acknowledged == acknowledged]
        return sorted(alerts, key=lambda a: a.created_at, reverse=True)[:limit]

    def acknowledge_alert(
        self,
        alert_id: str,
        acknowledged_by: str,
    ) -> Optional[SLABreachAlert]:
        """Acknowledge an SLA alert."""
        for alert in self._alerts:
            if alert.id == alert_id:
                alert.acknowledged = True
                alert.acknowledged_by = acknowledged_by
                alert.acknowledged_at = datetime.now(timezone.utc)
                self._persist()
                return alert
        return None

    def get_breaches(self) -> List[SLATrackingRecord]:
        """Get all currently breached SLA records."""
        return [
            r for r in self._records.values()
            if r.is_breached() and r.status not in ("remediated", "dismissed")
        ]

    def get_approaching_deadlines(self, days: int = 3) -> List[SLATrackingRecord]:
        """Get vulnerabilities approaching SLA deadline within specified days."""
        now = datetime.now(timezone.utc)
        approaching: List[SLATrackingRecord] = []
        for r in self._records.values():
            if r.status in ("remediated", "dismissed"):
                continue
            time_left = r.sla_deadline - now
            if timedelta(0) < time_left <= timedelta(days=days):
                approaching.append(r)
        return approaching

    # ------------------------------------------------------------------
    # MTTR Calculation
    # ------------------------------------------------------------------

    def calculate_mttr(
        self,
        severity: Optional[str] = None,
        start_date: Optional[datetime] = None,
        end_date: Optional[datetime] = None,
    ) -> Dict[str, Any]:
        """
        Calculate Mean Time To Remediate (MTTR) for vulnerabilities.

        Args:
            severity: Filter by severity level, or None for all
            start_date: Filter detections after this date
            end_date: Filter detections before this date

        Returns:
            Dict with mttr_hours, count, breakdown by severity
        """
        records = list(self._records.values())

        # Filter remediated records
        remediated = [r for r in records if r.status == "remediated"
                      and r.time_to_remediate_hours is not None]

        if severity:
            remediated = [r for r in remediated if r.severity == severity.upper()]
        if start_date:
            remediated = [r for r in remediated if r.detected_at >= start_date]
        if end_date:
            remediated = [r for r in remediated if r.detected_at <= end_date]

        if not remediated:
            return {
                "mttr_hours": 0.0,
                "mttr_days": 0.0,
                "count": 0,
                "by_severity": {},
            }

        total_hours = sum(r.time_to_remediate_hours or 0 for r in remediated)
        count = len(remediated)
        mttr_hours = total_hours / count

        # Breakdown by severity
        by_severity: Dict[str, Dict[str, float]] = {}
        sev_groups: Dict[str, List[float]] = {}
        for r in remediated:
            sev = r.severity
            if sev not in sev_groups:
                sev_groups[sev] = []
            sev_groups[sev].append(r.time_to_remediate_hours or 0)

        for sev, times in sev_groups.items():
            by_severity[sev] = {
                "mttr_hours": round(sum(times) / len(times), 2),
                "mttr_days": round(sum(times) / len(times) / 24, 2),
                "count": len(times),
                "min_hours": round(min(times), 2),
                "max_hours": round(max(times), 2),
            }

        return {
            "mttr_hours": round(mttr_hours, 2),
            "mttr_days": round(mttr_hours / 24, 2),
            "count": count,
            "by_severity": by_severity,
            "min_hours": round(min(r.time_to_remediate_hours or 0 for r in remediated), 2),
            "max_hours": round(max(r.time_to_remediate_hours or 0 for r in remediated), 2),
        }

    # ------------------------------------------------------------------
    # Statistics & Dashboard
    # ------------------------------------------------------------------

    def get_sla_dashboard(self) -> Dict[str, Any]:
        """Get SLA tracking dashboard data."""
        now = datetime.now(timezone.utc)
        records = list(self._records.values())

        open_records = [r for r in records if r.status not in ("remediated", "dismissed")]
        breached = [r for r in open_records if r.is_breached()]
        approaching = self.get_approaching_deadlines(days=3)
        remediated = [r for r in records if r.status == "remediated"]

        # By severity breakdown
        by_severity: Dict[str, Dict[str, int]] = {}
        for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            sev_records = [r for r in open_records if r.severity == sev]
            sev_breached = [r for r in sev_records if r.is_breached()]
            by_severity[sev] = {
                "open": len(sev_records),
                "breached": len(sev_breached),
                "approaching": len([r for r in sev_records if r.days_remaining() <= 3]),
                "on_track": len([r for r in sev_records if r.days_remaining() > 3 and not r.is_breached()]),
            }

        # SLA compliance rate
        total_tracked = len(records)
        if total_tracked > 0:
            met_sla = sum(1 for r in remediated if r.breach_duration_hours is None)
            compliance_rate = (met_sla / total_tracked) * 100 if total_tracked > 0 else 0
        else:
            compliance_rate = 0.0

        return {
            "generated_at": now.isoformat(),
            "summary": {
                "total_tracked": total_tracked,
                "open": len(open_records),
                "remediated": len(remediated),
                "breached": len(breached),
                "approaching_deadline": len(approaching),
                "compliance_rate": round(compliance_rate, 1),
                "pending_alerts": len([a for a in self._alerts if not a.acknowledged]),
            },
            "by_severity": by_severity,
            "mttr": self.calculate_mttr(),
            "top_breaches": [r.to_dict() for r in sorted(breached, key=lambda x: x.hours_overdue(), reverse=True)[:10]],
            "top_approaching": [r.to_dict() for r in sorted(approaching, key=lambda x: x.days_remaining())[:10]],
        }

    def get_records(
        self,
        severity: Optional[str] = None,
        status: Optional[str] = None,
        scan_id: Optional[str] = None,
        assigned_to: Optional[str] = None,
    ) -> List[SLATrackingRecord]:
        """Get tracking records with filtering."""
        records = list(self._records.values())
        if severity:
            records = [r for r in records if r.severity == severity.upper()]
        if status:
            records = [r for r in records if r.status == status]
        if scan_id:
            records = [r for r in records if r.scan_id == scan_id]
        if assigned_to:
            records = [r for r in records if r.assigned_to == assigned_to]
        return records


# Singleton
_sla_tracker: Optional[SLATracker] = None


def get_sla_tracker() -> SLATracker:
    """Get or create the global SLA tracker."""
    global _sla_tracker
    if _sla_tracker is None:
        _sla_tracker = SLATracker()
    return _sla_tracker
