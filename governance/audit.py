"""
Append-only audit trail for governed LLM interactions.

Implements the "accountability" pillar: every governed call produces a tamper-
evident record (each entry stores the hash of the previous entry, forming a
hash chain) written as JSON Lines. This gives a verifiable history that can be
shown to auditors or a security director.
"""

from __future__ import annotations

import json
import threading
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from hashlib import sha256
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class AuditRecord:
    """A single governance event."""

    event: str
    actor: str
    provider: str
    model: str
    decision: str  # allowed | blocked | flagged
    record_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    timestamp: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    details: Dict[str, Any] = field(default_factory=dict)
    prev_hash: str = ""
    hash: str = ""

    def compute_hash(self) -> str:
        payload = {
            "record_id": self.record_id,
            "timestamp": self.timestamp,
            "event": self.event,
            "actor": self.actor,
            "provider": self.provider,
            "model": self.model,
            "decision": self.decision,
            "details": self.details,
            "prev_hash": self.prev_hash,
        }
        encoded = json.dumps(payload, sort_keys=True).encode("utf-8")
        return sha256(encoded).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class AuditTrail:
    """Thread-safe, append-only, hash-chained audit log."""

    def __init__(self, path: str = "./data/ai_governance_audit.jsonl") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._last_hash = self._read_last_hash()

    def _read_last_hash(self) -> str:
        if not self.path.exists():
            return ""
        last = ""
        try:
            with self.path.open("r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        last = line
            if last:
                return json.loads(last).get("hash", "")
        except (OSError, json.JSONDecodeError):
            return ""
        return ""

    def record(
        self,
        event: str,
        *,
        actor: str,
        provider: str,
        model: str,
        decision: str,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditRecord:
        with self._lock:
            rec = AuditRecord(
                event=event,
                actor=actor,
                provider=provider,
                model=model,
                decision=decision,
                details=details or {},
                prev_hash=self._last_hash,
            )
            rec.hash = rec.compute_hash()
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec.to_dict()) + "\n")
            self._last_hash = rec.hash
            return rec

    def read_all(self) -> List[Dict[str, Any]]:
        if not self.path.exists():
            return []
        out: List[Dict[str, Any]] = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    out.append(json.loads(line))
        return out

    def verify(self) -> bool:
        """Verify the integrity of the hash chain. Returns True if intact."""
        prev = ""
        for entry in self.read_all():
            rec = AuditRecord(
                event=entry["event"],
                actor=entry["actor"],
                provider=entry["provider"],
                model=entry["model"],
                decision=entry["decision"],
                record_id=entry["record_id"],
                timestamp=entry["timestamp"],
                details=entry.get("details", {}),
                prev_hash=entry.get("prev_hash", ""),
            )
            if rec.prev_hash != prev:
                return False
            if rec.compute_hash() != entry.get("hash"):
                return False
            prev = entry["hash"]
        return True


_audit_trail: Optional[AuditTrail] = None


def get_audit_trail(path: Optional[str] = None) -> AuditTrail:
    """Get (or create) the process-wide audit trail singleton."""
    global _audit_trail
    if _audit_trail is None or path is not None:
        _audit_trail = AuditTrail(path or "./data/ai_governance_audit.jsonl")
    return _audit_trail
