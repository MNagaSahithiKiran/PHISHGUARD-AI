from fastapi import APIRouter, Depends, Response, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import text
from typing import Dict, Any

from app.db.session import get_db
from app.core.config import settings
from app.schemas.health import HealthResponse
from app.services.job_queue import job_queue
from app.services.model_registry import model_registry

router = APIRouter(tags=["Health"])


@router.get("/health", response_model=HealthResponse)
async def check_health(db: AsyncSession = Depends(get_db)):
    """General health overview endpoint confirming API, DB, Redis, and Model connectivity."""
    db_ok = False
    try:
        await db.execute(text("SELECT 1"))
        db_ok = True
    except Exception:
        db_ok = False

    queue_stats = job_queue.get_stats()
    redis_connected = queue_stats.get("redis_connected", False)
    redis_backend = queue_stats.get("backend", "in_memory")
    if redis_connected:
        redis_status = "operational"
    elif redis_backend == "in_memory":
        redis_status = "REDIS_UNAVAILABLE (in_memory_fallback)"
    else:
        redis_status = "REDIS_UNAVAILABLE"

    model_health = model_registry.validate_health()
    overall_status = model_health.get("overall_status", "healthy")

    is_overall_healthy = db_ok and (overall_status in ["healthy", "degraded"])

    return HealthResponse(
        status="healthy" if is_overall_healthy else "degraded",
        version=settings.VERSION,
        project_name=settings.PROJECT_NAME,
        environment=settings.ENVIRONMENT,
        database_connected=db_ok,
        redis_status=redis_status,
        model_registry_status=overall_status,
        api_status="healthy",
    )


@router.get("/health/live")
async def liveness_probe():
    """Liveness probe: returns 200 OK if the application process is running and accepting events."""
    return {
        "status": "alive",
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
    }


@router.get("/health/ready")
async def readiness_probe(response: Response, db: AsyncSession = Depends(get_db)):
    """Readiness probe: validates database, job queue, and AI model registry status."""
    checks: Dict[str, Any] = {}
    is_ready = True

    # 1. Check Database
    try:
        await db.execute(text("SELECT 1"))
        checks["database"] = {"status": "connected"}
    except Exception as e:
        checks["database"] = {"status": "error", "detail": str(e)}
        is_ready = False

    # 2. Check Queue
    queue_stats = job_queue.get_stats()
    checks["queue"] = {
        "status": "operational",
        "backend": queue_stats["backend"],
        "redis_connected": queue_stats["redis_connected"],
        "pending_jobs": queue_stats["in_memory_queue_length"],
    }

    # 3. Check Model Registry
    model_health = model_registry.validate_health()
    checks["models"] = {
        "status": model_health["overall_status"],
        "active_models": model_health["active_models_count"],
    }

    if not is_ready:
        response.status_code = status.HTTP_503_SERVICE_UNAVAILABLE

    return {
        "ready": is_ready,
        "status": "ready" if is_ready else "not_ready",
        "version": settings.VERSION,
        "environment": settings.ENVIRONMENT,
        "checks": checks,
    }
