"""
JSON-based database for CodeShield AI.

Simple file-based storage for scan results. No SQL database required.
Scans are stored as individual JSON files in the data directory.
"""

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import aiofiles

from models.vulnerability import ScanResult
from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)


class JSONDatabase:
    """
    Simple JSON file-based database for scan results.

    Each scan is stored as a separate JSON file named {scan_id}.json.
    All scans are stored in the configured data directory.
    """

    def __init__(self) -> None:
        """Initialize the database with the data directory."""
        settings = get_settings()
        self.data_dir = settings.data_dir / "scans"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        logger.info("JSON database initialized at %s", self.data_dir)

    def _get_scan_path(self, scan_id: str) -> Path:
        """Get the file path for a scan."""
        return self.data_dir / f"{scan_id}.json"

    async def save_scan(self, scan_result: ScanResult) -> None:
        """
        Save or update a scan result.

        Args:
            scan_result: The scan result to save
        """
        file_path = self._get_scan_path(scan_result.scan_id)
        data = scan_result.model_dump()

        # Convert datetime objects to ISO format strings
        def serialize_datetime(obj: Any) -> Any:
            if isinstance(obj, datetime):
                return obj.isoformat()
            raise TypeError(f"Type {type(obj)} not serializable")

        temp_file_path = file_path.with_name(f"{scan_result.scan_id}.{os.getpid()}.tmp")
        try:
            async with aiofiles.open(temp_file_path, "w", encoding="utf-8") as f:
                await f.write(json.dumps(data, default=serialize_datetime, indent=2))
            await asyncio.to_thread(os.replace, temp_file_path, file_path)
            logger.debug("Saved scan %s to %s", scan_result.scan_id, file_path)
        except Exception as e:
            if temp_file_path.exists():
                try:
                    temp_file_path.unlink()
                except Exception:
                    pass
            logger.error("Failed to save scan %s: %s", scan_result.scan_id, e)
            raise

    async def get_scan(self, scan_id: str) -> Optional[ScanResult]:
        """
        Retrieve a scan by ID.

        Args:
            scan_id: The scan ID

        Returns:
            ScanResult if found, None otherwise
        """
        file_path = self._get_scan_path(scan_id)

        if not file_path.exists():
            logger.debug("Scan %s not found", scan_id)
            return None

        try:
            async with aiofiles.open(file_path, "r", encoding="utf-8") as f:
                content = await f.read()
                data = json.loads(content)
                return ScanResult(**data)
        except Exception as e:
            logger.error("Failed to load scan %s: %s", scan_id, e)
            return None

    async def list_scans(
        self,
        limit: int = 100,
        offset: int = 0,
        status: Optional[str] = None,
    ) -> List[ScanResult]:
        """
        List all scans with optional filtering.

        Args:
            limit: Maximum number of results
            offset: Number of results to skip
            status: Filter by status

        Returns:
            List of scan results, newest first
        """
        scans: List[ScanResult] = []

        try:
            # Use asyncio.to_thread for sync glob/stat operations
            files = await asyncio.to_thread(self._get_sorted_scan_files)

            for file_path in files:
                try:
                    async with aiofiles.open(file_path, "r", encoding="utf-8") as f:
                        content = await f.read()
                        data = json.loads(content)
                        scan = ScanResult(**data)

                        if status and scan.status != status:
                            continue

                        scans.append(scan)
                except Exception as e:
                    logger.warning("Failed to load scan from %s: %s", file_path, e)
                    continue

        except Exception as e:
            logger.error("Failed to list scans: %s", e)

        return scans[offset : offset + limit]

    def _get_sorted_scan_files(self) -> List[Path]:
        """Get scan files sorted by modification time (newest first). Sync operation."""
        try:
            files = list(self.data_dir.glob("*.json"))
            files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
            return files
        except Exception:
            return []

    async def delete_scan(self, scan_id: str) -> bool:
        """
        Delete a scan by ID.

        Args:
            scan_id: The scan ID to delete

        Returns:
            True if deleted, False if not found
        """
        file_path = self._get_scan_path(scan_id)

        if not file_path.exists():
            return False

        try:
            await asyncio.to_thread(file_path.unlink)
            logger.info("Deleted scan %s", scan_id)
            return True
        except Exception as e:
            logger.error("Failed to delete scan %s: %s", scan_id, e)
            return False

    async def scan_exists(self, scan_id: str) -> bool:
        """Check if a scan exists."""
        return await asyncio.to_thread(self._get_scan_path(scan_id).exists)

    async def get_stats(self) -> Dict[str, Any]:
        """
        Get database statistics.

        Returns:
            Dictionary with total scans, counts by status, etc.
        """
        scans = await self.list_scans(limit=10000)

        stats = {
            "total_scans": len(scans),
            "by_status": {
                "pending": 0,
                "running": 0,
                "completed": 0,
                "failed": 0,
            },
            "total_vulnerabilities": 0,
            "by_severity": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
            },
        }

        for scan in scans:
            stats["by_status"][scan.status] = stats["by_status"].get(scan.status, 0) + 1
            stats["total_vulnerabilities"] += len(scan.vulnerabilities)
            for sev, count in scan.stats.items():
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
        """
        Update the status of a scan.

        Args:
            scan_id: The scan ID
            status: New status
            progress: Optional progress percentage
            error_message: Optional error message

        Returns:
            Updated ScanResult or None if not found
        """
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
                scan.scan_duration = int((scan.end_time - scan.start_time).total_seconds())

        await self.save_scan(scan)
        return scan

    async def update_scan_result(self, scan_id: str, scan_result: ScanResult) -> Optional[ScanResult]:
        """
        Update a scan with new results.

        Args:
            scan_id: The scan ID
            scan_result: The updated scan result

        Returns:
            Updated ScanResult or None if not found
        """
        existing = await self.get_scan(scan_id)
        if not existing:
            return None

        await self.save_scan(scan_result)
        return scan_result
