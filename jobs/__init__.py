"""
Lightweight async job queue for CodeShield AI.

An in-process worker-pool queue with disk-persisted job records (no external
broker like Redis required). It gives durable-ish, inspectable background
execution for long-running work (scans, report generation, etc.) and presents a
small, swappable interface that could later be backed by Celery/RQ without
changing call sites.
"""

from jobs.queue import Job, JobQueue, JobStatus, get_job_queue

__all__ = ["Job", "JobQueue", "JobStatus", "get_job_queue"]
