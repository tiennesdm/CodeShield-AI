"""Tests for the SQLite datastore (drop-in for JSONDatabase)."""

from datetime import datetime, timezone

import pytest

from database.sqlite_db import SQLiteDatabase
from models.vulnerability import ScanResult, Vulnerability


def _scan(scan_id: str, status: str = "completed", risk: int = 10) -> ScanResult:
    return ScanResult(
        scan_id=scan_id,
        name=f"Scan {scan_id}",
        source_type="zip",
        source_path="/tmp/x",
        status=status,
        start_time=datetime.now(timezone.utc),
        risk_score=risk,
        vulnerabilities=[
            Vulnerability(
                scan_id=scan_id, file_path="a.py", line_number=1, severity="HIGH",
                category="SQL Injection", title="x", description="d", tool_source="bandit",
            )
        ],
        stats={"total": 1, "critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
    )


@pytest.fixture
def db(tmp_path):
    return SQLiteDatabase(str(tmp_path / "test.db"))


async def test_save_and_get(db):
    await db.save_scan(_scan("s1"))
    got = await db.get_scan("s1")
    assert got is not None
    assert got.scan_id == "s1"
    assert len(got.vulnerabilities) == 1
    assert got.risk_score == 10


async def test_get_missing(db):
    assert await db.get_scan("nope") is None


async def test_upsert(db):
    await db.save_scan(_scan("s1", status="running"))
    await db.save_scan(_scan("s1", status="completed"))
    got = await db.get_scan("s1")
    assert got.status == "completed"
    # still a single row
    assert len(await db.list_scans()) == 1


async def test_list_and_filter(db):
    await db.save_scan(_scan("a", status="completed"))
    await db.save_scan(_scan("b", status="failed"))
    await db.save_scan(_scan("c", status="completed"))
    assert len(await db.list_scans()) == 3
    assert len(await db.list_scans(status="completed")) == 2
    assert len(await db.list_scans(limit=1)) == 1


async def test_delete(db):
    await db.save_scan(_scan("s1"))
    assert await db.delete_scan("s1") is True
    assert await db.delete_scan("s1") is False
    assert await db.get_scan("s1") is None


async def test_exists(db):
    await db.save_scan(_scan("s1"))
    assert await db.scan_exists("s1") is True
    assert await db.scan_exists("nope") is False


async def test_stats(db):
    await db.save_scan(_scan("a", status="completed"))
    await db.save_scan(_scan("b", status="failed"))
    stats = await db.get_stats()
    assert stats["total_scans"] == 2
    assert stats["by_status"]["completed"] == 1
    assert stats["by_status"]["failed"] == 1
    assert stats["total_vulnerabilities"] == 2
    assert stats["by_severity"]["high"] == 2


async def test_update_status(db):
    await db.save_scan(_scan("s1", status="running"))
    updated = await db.update_scan_status("s1", "completed", progress=100)
    assert updated.status == "completed"
    assert updated.progress == 100
    assert updated.end_time is not None
    assert await db.update_scan_status("missing", "completed") is None


async def test_update_result(db):
    await db.save_scan(_scan("s1"))
    new = _scan("s1", risk=99)
    res = await db.update_scan_result("s1", new)
    assert res is not None
    assert (await db.get_scan("s1")).risk_score == 99
    assert await db.update_scan_result("missing", new) is None


def test_factory_selects_sqlite(monkeypatch, tmp_path):
    monkeypatch.setenv("DB_BACKEND", "sqlite")
    monkeypatch.setenv("DB_PATH", str(tmp_path / "f.db"))
    from utils.config import get_settings
    get_settings.cache_clear()
    from database import get_database
    db = get_database()
    assert isinstance(db, SQLiteDatabase)
    get_settings.cache_clear()
