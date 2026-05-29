"""
In-process async job queue with a bounded worker pool and disk persistence.

Usage::

    queue = JobQueue(concurrency=2)
    await queue.start()
    job_id = await queue.enqueue(my_async_fn, arg1, name="scan", kw=1)
    job = await queue.wait(job_id)
    await queue.stop()

Job records are persisted as JSON under ``<data_dir>/jobs`` so they can be
inspected (e.g. by the dashboard) and survive within the process lifetime.
"""

from __future__ import annotations

import asyncio
import json
import time
import uuid
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

from utils.config import get_settings
from utils.logger import get_logger

logger = get_logger(__name__)


class JobStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


@dataclass
class Job:
    """A unit of background work and its lifecycle state."""

    id: str
    name: str
    status: str = JobStatus.PENDING.value
    progress: int = 0
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    finished_at: Optional[float] = None
    result: Any = None
    error: Optional[str] = None

    @property
    def duration(self) -> Optional[float]:
        if self.started_at and self.finished_at:
            return round(self.finished_at - self.started_at, 3)
        return None

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["duration"] = self.duration
        return d


class JobQueue:
    """A bounded-concurrency async job queue with persisted records."""

    def __init__(
        self,
        concurrency: int = 2,
        persist_dir: Optional[str] = None,
        keep_result: bool = True,
    ) -> None:
        self.concurrency = max(1, concurrency)
        if persist_dir is None:
            persist_dir = str(get_settings().data_dir / "jobs")
        self.persist_dir = Path(persist_dir)
        self.persist_dir.mkdir(parents=True, exist_ok=True)
        self.keep_result = keep_result

        self._queue: asyncio.Queue = asyncio.Queue()
        self._jobs: Dict[str, Job] = {}
        self._workers: List[asyncio.Task] = []
        self._running = False

    # ------------------------------------------------------------------
    async def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._workers = [
            asyncio.create_task(self._worker(i)) for i in range(self.concurrency)
        ]
        logger.info("JobQueue started with %d workers", self.concurrency)

    async def stop(self) -> None:
        self._running = False
        for w in self._workers:
            w.cancel()
        for w in self._workers:
            try:
                await w
            except asyncio.CancelledError:
                pass
        self._workers = []
        logger.info("JobQueue stopped")

    # ------------------------------------------------------------------
    async def enqueue(
        self,
        func: Callable[..., Any],
        *args: Any,
        name: Optional[str] = None,
        **kwargs: Any,
    ) -> str:
        """Schedule ``func(*args, **kwargs)`` and return a job id."""
        job_id = uuid.uuid4().hex[:12]
        job = Job(id=job_id, name=name or getattr(func, "__name__", "job"))
        self._jobs[job_id] = job
        self._persist(job)
        await self._queue.put((job_id, func, args, kwargs))
        return job_id

    def get_job(self, job_id: str) -> Optional[Job]:
        return self._jobs.get(job_id)

    def list_jobs(
        self, limit: int = 100, status: Optional[str] = None
    ) -> List[Job]:
        jobs = sorted(self._jobs.values(), key=lambda j: j.created_at, reverse=True)
        if status:
            jobs = [j for j in jobs if j.status == status]
        return jobs[:limit]

    async def wait(self, job_id: str, timeout: float = 10.0) -> Optional[Job]:
        """Block until a job reaches a terminal state (for tests/sync flows)."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            job = self._jobs.get(job_id)
            if job and job.status in (
                JobStatus.COMPLETED.value,
                JobStatus.FAILED.value,
                JobStatus.CANCELLED.value,
            ):
                return job
            await asyncio.sleep(0.02)
        return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> bool:
        """Cancel a job that has not started yet."""
        job = self._jobs.get(job_id)
        if job and job.status == JobStatus.PENDING.value:
            job.status = JobStatus.CANCELLED.value
            job.finished_at = time.time()
            self._persist(job)
            return True
        return False

    # ------------------------------------------------------------------
    async def _worker(self, idx: int) -> None:
        while self._running:
            try:
                job_id, func, args, kwargs = await self._queue.get()
            except asyncio.CancelledError:
                break
            job = self._jobs.get(job_id)
            try:
                if not job or job.status == JobStatus.CANCELLED.value:
                    continue
                job.status = JobStatus.RUNNING.value
                job.started_at = time.time()
                self._persist(job)
                try:
                    result = func(*args, **kwargs)
                    if asyncio.iscoroutine(result):
                        result = await result
                    job.result = result if self.keep_result else None
                    job.status = JobStatus.COMPLETED.value
                    job.progress = 100
                except asyncio.CancelledError:
                    raise
                except Exception as exc:
                    job.status = JobStatus.FAILED.value
                    job.error = str(exc)
                    logger.error("Job %s (%s) failed: %s", job_id, job.name, exc)
                finally:
                    job.finished_at = time.time()
                    self._persist(job)
            except asyncio.CancelledError:
                break
            finally:
                self._queue.task_done()

    def _persist(self, job: Job) -> None:
        try:
            payload = job.to_dict()
            # Result may not be JSON-serializable; store a repr fallback.
            (self.persist_dir / f"{job.id}.json").write_text(
                json.dumps(payload, default=str), encoding="utf-8"
            )
        except Exception as e:  # pragma: no cover - defensive
            logger.debug("Failed to persist job %s: %s", job.id, e)


_job_queue: Optional[JobQueue] = None


def get_job_queue() -> JobQueue:
    """Get (or create) the process-wide job queue singleton."""
    global _job_queue
    if _job_queue is None:
        settings = get_settings()
        _job_queue = JobQueue(concurrency=getattr(settings, "job_concurrency", 2))
    return _job_queue
