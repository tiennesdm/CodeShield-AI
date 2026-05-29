"""
SQLite-based datastore for CodeShield AI.

A drop-in replacement for :class:`database.json_db.JSONDatabase` that stores
each scan as a row (with the full result serialized to a JSON column) in a
single SQLite file. This scales far better than one file per scan for
concurrency, listing, filtering, and stats, while still requiring zero external
services.

All blocking sqlite3 calls are dispatched via ``asyncio.to_thread`` so the
public API stays async and matches JSONDatabase exactly.
"""

import asyncio
import json
import sqlite3
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from models.vulnerability import ScanResult
from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)


def _serialize_datetime(obj: Any) -> Any:
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Type {type(obj)} not serializable")


class SQLiteDatabase:
    """SQLite-backed scan store with the same interface as JSONDatabase."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        settings = get_settings()
        if db_path is None:
            db_path = str(settings.data_dir / "codeshield.db")
        self.db_path = db_path
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        # A lock guards writes; SQLite handles its own locking too, but this
        # keeps our connection usage simple and predictable.
        self._lock = threading.Lock()
        self._init_db()
        logger.info("SQLite database initialized at %s", self.db_path)

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL;")
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id     TEXT PRIMARY KEY,
                    name        TEXT,
                    status      TEXT,
                    risk_score  INTEGER DEFAULT 0,
                    created_at  TEXT,
                    updated_at  TEXT,
                    data        TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_status ON scans(status)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_scans_updated ON scans(updated_at)"
            )

    # ------------------------------------------------------------------
    # Sync workers (run via to_thread)
    # ------------------------------------------------------------------
    def _save_sync(self, scan_result: ScanResult) -> None:
        data = json.dumps(scan_result.model_dump(), default=_serialize_datetime)
        now = datetime.now(timezone.utc).isoformat()
        created = (
            scan_result.start_time.isoformat()
            if getattr(scan_result, "start_time", None)
            else now
        )
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO scans (scan_id, name, status, risk_score, created_at, updated_at, data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(scan_id) DO UPDATE SET
                    name=excluded.name, status=excluded.status,
                    risk_score=excluded.risk_score, updated_at=excluded.updated_at,
                    data=excluded.data
                """,
                (
                    scan_result.scan_id,
                    scan_result.name,
                    scan_result.status,
                    int(getattr(scan_result, "risk_score", 0) or 0),
                    created,
                    now,
                    data,
                ),
            )

    def _row_to_scan(self, row: sqlite3.Row) -> Optional[ScanResult]:
        try:
            return ScanResult(**json.loads(row["data"]))
        except Exception as e:  # pragma: no cover - corrupt row
            logger.warning("Failed to deserialize scan %s: %s", row["scan_id"], e)
            return None

    def _get_sync(self, scan_id: str) -> Optional[ScanResult]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return self._row_to_scan(row) if row else None

    def _list_sync(
        self, limit: int, offset: int, status: Optional[str]
    ) -> List[ScanResult]:
        query = "SELECT * FROM scans"
        params: List[Any] = []
        if status:
            query += " WHERE status = ?"
            params.append(status)
        query += " ORDER BY updated_at DESC LIMIT ? OFFSET ?"
        params += [limit, offset]
        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()
        out = [self._row_to_scan(r) for r in rows]
        return [s for s in out if s is not None]

    def _delete_sync(self, scan_id: str) -> bool:
        with self._lock, self._connect() as conn:
            cur = conn.execute("DELETE FROM scans WHERE scan_id = ?", (scan_id,))
            return cur.rowcount > 0

    def _exists_sync(self, scan_id: str) -> bool:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM scans WHERE scan_id = ?", (scan_id,)
            ).fetchone()
        return row is not None

    # ------------------------------------------------------------------
    # Async public API (mirrors JSONDatabase)
    # ------------------------------------------------------------------
    async def save_scan(self, scan_result: ScanResult) -> None:
        await asyncio.to_thread(self._save_sync, scan_result)
        logger.debug("Saved scan %s to SQLite", scan_result.scan_id)

    async def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        return await asyncio.to_thread(self._get_sync, scan_id)

    async def list_scans(
        self, limit: int = 100, offset: int = 0, status: Optional[str] = None
    ) -> List[ScanResult]:
        return await asyncio.to_thread(self._list_sync, limit, offset, status)

    async def delete_scan(self, scan_id: str) -> bool:
        deleted = await asyncio.to_thread(self._delete_sync, scan_id)
        if deleted:
            logger.info("Deleted scan %s", scan_id)
        return deleted

    async def scan_exists(self, scan_id: str) -> bool:
        return await asyncio.to_thread(self._exists_sync, scan_id)

    async def get_stats(self) -> Dict[str, Any]:
        scans = await self.list_scans(limit=100000)
        stats: Dict[str, Any] = {
            "total_scans": len(scans),
            "by_status": {"pending": 0, "running": 0, "completed": 0, "failed": 0},
            "total_vulnerabilities": 0,
            "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        }
        for scan in scans:
            stats["by_status"][scan.status] = stats["by_status"].get(scan.status, 0) + 1
            stats["total_vulnerabilities"] += len(scan.vulnerabilities)
            for sev, count in (scan.stats or {}).items():
                if sev.lower() in stats["by_severity"]:
                    stats["by_severity"][sev.lower()] += count
        return stats

    async def update_scan_status(
        self,
        scan_id: str,
        status: str,
        progress: Optional[int] = None,
        error_message: Optional[str] = None,
    ) -> Optional[ScanResult]:
        scan = await self.get_scan(scan_id)
        if not scan:
            return None
        scan.status = status
        if progress is not None:
            scan.progress = progress
        if error_message:
            scan.error_message = error_message
        if status in ("completed", "failed"):
            scan.end_time = datetime.now(timezone.utc)
            if scan.start_time:
                scan.scan_duration = int(
                    (scan.end_time - scan.start_time).total_seconds()
                )
        await self.save_scan(scan)
        return scan

    async def update_scan_result(
        self, scan_id: str, scan_result: ScanResult
    ) -> Optional[ScanResult]:
        if not await self.scan_exists(scan_id):
            return None
        await self.save_scan(scan_result)
        return scan_result
