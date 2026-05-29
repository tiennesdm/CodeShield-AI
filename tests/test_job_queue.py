"""Tests for the in-process async job queue."""

import asyncio

import pytest

from jobs.queue import JobQueue, JobStatus


@pytest.fixture
async def queue(tmp_path):
    q = JobQueue(concurrency=2, persist_dir=str(tmp_path / "jobs"))
    await q.start()
    yield q
    await q.stop()


async def test_async_job_completes(queue):
    async def work(x):
        await asyncio.sleep(0.01)
        return x * 2

    job_id = await queue.enqueue(work, 21, name="double")
    job = await queue.wait(job_id, timeout=5)
    assert job.status == JobStatus.COMPLETED.value
    assert job.result == 42
    assert job.progress == 100
    assert job.duration is not None


async def test_sync_job_completes(queue):
    def work():
        return "ok"

    job_id = await queue.enqueue(work)
    job = await queue.wait(job_id, timeout=5)
    assert job.status == JobStatus.COMPLETED.value
    assert job.result == "ok"


async def test_failed_job(queue):
    async def boom():
        raise ValueError("nope")

    job_id = await queue.enqueue(boom, name="boom")
    job = await queue.wait(job_id, timeout=5)
    assert job.status == JobStatus.FAILED.value
    assert "nope" in job.error


async def test_concurrency_runs_in_parallel(queue):
    order = []

    async def slow(n):
        order.append(("start", n))
        await asyncio.sleep(0.05)
        order.append(("end", n))
        return n

    ids = [await queue.enqueue(slow, i) for i in range(2)]
    for jid in ids:
        await queue.wait(jid, timeout=5)
    # With concurrency=2 both should have started before either ended.
    starts = [e for e in order if e[0] == "start"]
    assert len(starts) == 2


async def test_persistence_file_written(queue, tmp_path):
    job_id = await queue.enqueue(lambda: 1)
    await queue.wait(job_id, timeout=5)
    assert (tmp_path / "jobs" / f"{job_id}.json").exists()


async def test_list_and_get(queue):
    jid = await queue.enqueue(lambda: 1, name="a")
    await queue.wait(jid, timeout=5)
    assert queue.get_job(jid) is not None
    jobs = queue.list_jobs()
    assert any(j.id == jid for j in jobs)
    assert queue.list_jobs(status=JobStatus.COMPLETED.value)


async def test_cancel_pending(tmp_path):
    q = JobQueue(concurrency=1, persist_dir=str(tmp_path / "j"))
    # not started -> nothing consumes the queue
    jid = await q.enqueue(lambda: 1)
    assert q.cancel(jid) is True
    assert q.get_job(jid).status == JobStatus.CANCELLED.value
