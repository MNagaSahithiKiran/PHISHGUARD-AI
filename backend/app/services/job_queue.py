import asyncio
import json
import time
from typing import Dict, Any, Optional, Callable, Awaitable
from dataclasses import dataclass, asdict
from enum import Enum

from app.core.config import settings
from app.core.logging import logger

try:
    import redis.asyncio as aioredis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False


class JobStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"


@dataclass
class ScanJob:
    job_id: str
    scan_id: str
    url: str
    status: JobStatus
    created_at: float
    started_at: Optional[float] = None
    completed_at: Optional[float] = None
    retry_count: int = 0
    max_retries: int = 3
    error: Optional[str] = None
    result: Optional[Dict[str, Any]] = None


class JobQueueManager:
    """Enterprise Asynchronous Background Queue Manager.
    Uses Redis when available with automatic fallback to an in-memory queue for dev/test.
    """

    def __init__(self, redis_url: str = settings.REDIS_URL):
        self.redis_url = redis_url
        self.redis_client = None
        self._in_memory_queue: asyncio.Queue = asyncio.Queue()
        self._in_memory_jobs: Dict[str, ScanJob] = {}
        self._is_redis_connected = False
        self._running = False
        self._worker_task: Optional[asyncio.Task] = None

    async def connect(self) -> bool:
        """Attempts connection to Redis, falling back to in-memory queue if unavailable."""
        if HAS_REDIS and self.redis_url:
            try:
                self.redis_client = aioredis.from_url(
                    self.redis_url,
                    socket_connect_timeout=2.0,
                    decode_responses=True,
                )
                await self.redis_client.ping()
                self._is_redis_connected = True
                logger.info("Background Job Queue: Connected to Redis successfully.")
                return True
            except Exception as e:
                logger.warning(
                    f"Background Job Queue: Redis unavailable ({e}). Operating in resilient in-memory mode."
                )
                self._is_redis_connected = False
                self.redis_client = None
                return False
        return False

    async def enqueue(self, scan_id: str, url: str) -> ScanJob:
        """Enqueues a new scan job."""
        job = ScanJob(
            job_id=f"job_{scan_id}",
            scan_id=scan_id,
            url=url,
            status=JobStatus.QUEUED,
            created_at=time.time(),
        )

        if self._is_redis_connected and self.redis_client:
            try:
                payload = json.dumps(asdict(job))
                await self.redis_client.lpush("phishguard:scan_jobs", payload)
                await self.redis_client.set(f"phishguard:job:{job.job_id}", payload, ex=3600)
                logger.info(f"Enqueued job {job.job_id} to Redis queue.")
                return job
            except Exception as e:
                logger.error(f"Redis enqueue failed ({e}), falling back to in-memory.")

        # In-memory fallback
        self._in_memory_jobs[job.job_id] = job
        await self._in_memory_queue.put(job)
        logger.info(f"Enqueued job {job.job_id} to in-memory queue.")
        return job

    async def get_job(self, job_id: str) -> Optional[ScanJob]:
        """Retrieves job state."""
        if self._is_redis_connected and self.redis_client:
            try:
                raw = await self.redis_client.get(f"phishguard:job:{job_id}")
                if raw:
                    data = json.loads(raw)
                    data["status"] = JobStatus(data["status"])
                    return ScanJob(**data)
            except Exception:
                pass

        return self._in_memory_jobs.get(job_id)

    async def update_job_status(
        self,
        job_id: str,
        status: JobStatus,
        result: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None
    ) -> None:
        """Updates job lifecycle status."""
        job = await self.get_job(job_id)
        if not job:
            return

        job.status = status
        if status == JobStatus.RUNNING and not job.started_at:
            job.started_at = time.time()
        elif status in (JobStatus.COMPLETED, JobStatus.FAILED, JobStatus.TIMEOUT, JobStatus.BLOCKED):
            job.completed_at = time.time()

        if result:
            job.result = result
        if error:
            job.error = error

        if self._is_redis_connected and self.redis_client:
            try:
                payload = json.dumps(asdict(job))
                await self.redis_client.set(f"phishguard:job:{job.job_id}", payload, ex=3600)
            except Exception:
                pass

        self._in_memory_jobs[job_id] = job

    def get_stats(self) -> Dict[str, Any]:
        """Returns queue operational health metrics."""
        return {
            "backend": "redis" if self._is_redis_connected else "in-memory",
            "redis_connected": self._is_redis_connected,
            "in_memory_queue_length": self._in_memory_queue.qsize(),
            "total_tracked_jobs": len(self._in_memory_jobs),
        }


job_queue = JobQueueManager()
