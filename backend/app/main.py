import sys
import time
from collections import defaultdict
from contextlib import asynccontextmanager
from pathlib import Path

# Ensure backend root is on sys.path so both `import app...` and `import backend.app...` work
_backend_dir = Path(__file__).resolve().parent.parent
if str(_backend_dir) not in sys.path:
    sys.path.insert(0, str(_backend_dir))
from fastapi import FastAPI, Request, Response, status
from fastapi.responses import JSONResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from app.core.config import settings
from app.core.logging import logger
from app.core.security import hash_password
from app.core.correlation import CorrelationIdMiddleware, get_correlation_id
from app.db.session import init_db, AsyncSessionLocal
from app.models.user import User
from app.api.routes import api_router
from app.services.job_queue import job_queue

# In-memory sliding window rate limiter
_rate_limits = defaultdict(list)


def is_rate_limited(key: str, limit: int = 60, window_seconds: int = 60) -> bool:
    now = time.time()
    cutoff = now - window_seconds
    timestamps = [t for t in _rate_limits[key] if t > cutoff]
    if len(timestamps) >= limit:
        return True
    timestamps.append(now)
    _rate_limits[key] = timestamps
    return False


async def seed_default_admin():
    """Seeds default admin credentials if no administrator user exists."""
    async with AsyncSessionLocal() as session:
        try:
            res = await session.execute(select(User).where(User.role == "admin"))
            admin = res.scalar_one_or_none()
            if not admin:
                logger.info(f"Seeding default admin user: {settings.ADMIN_DEFAULT_EMAIL}")
                new_admin = User(
                    email=settings.ADMIN_DEFAULT_EMAIL.lower(),
                    hashed_password=hash_password(settings.ADMIN_DEFAULT_PASSWORD),
                    full_name="SOC Administrator",
                    role="admin",
                    is_active=True,
                )
                session.add(new_admin)
                await session.commit()
                logger.info("Default admin user created successfully.")
        except Exception as e:
            logger.warning(f"Admin seeding check failed: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup actions
    logger.info(f"Starting {settings.PROJECT_NAME} v{settings.VERSION} [{settings.ENVIRONMENT}]")
    await init_db()
    await seed_default_admin()
    await job_queue.connect()
    yield
    # Shutdown actions
    logger.info(f"Shutting down {settings.PROJECT_NAME}")


# Conditionally expose API documentation based on environment and policy
docs_url = (
    "/docs"
    if (settings.ENVIRONMENT != "production" or settings.ENABLE_DOCS_IN_PRODUCTION)
    else None
)
redoc_url = (
    "/redoc"
    if (settings.ENVIRONMENT != "production" or settings.ENABLE_DOCS_IN_PRODUCTION)
    else None
)

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION,
    lifespan=lifespan,
    docs_url=docs_url,
    redoc_url=redoc_url,
)

# Correlation ID Middleware (must be first to stamp every request)
app.add_middleware(CorrelationIdMiddleware)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.BACKEND_CORS_ORIGINS,
    allow_origin_regex=r"^https:\/\/.*\.vercel\.app$",
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)



@app.middleware("http")
async def security_and_rate_limiting_middleware(request: Request, call_next):
    client_ip = request.client.host if request.client else "unknown"
    path = request.url.path

    # 1. Enforce payload size limits (prevent resource exhaustion)
    content_length = request.headers.get("content-length")
    if content_length and int(content_length) > settings.MAX_CONTENT_LENGTH_BYTES:
        return JSONResponse(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            content={
                "detail": f"Payload too large. Maximum permitted request body is {settings.MAX_CONTENT_LENGTH_BYTES} bytes."
            },
        )

    # 2. Granular Rate Limiting Checks
    if path.endswith("/auth/login") and request.method == "POST":
        if is_rate_limited(f"login_{client_ip}", limit=settings.LOGIN_RATE_LIMIT_PER_MINUTE, window_seconds=60):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Too many login attempts. Please wait 60 seconds."},
            )

    if path.endswith("/auth/register") and request.method == "POST":
        if is_rate_limited(f"register_{client_ip}", limit=10, window_seconds=60):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Too many registration attempts. Please slow down."},
            )

    if path.endswith("/api/v1/scans") and request.method == "POST":
        if is_rate_limited(f"scan_{client_ip}", limit=settings.RATE_LIMIT_PER_MINUTE, window_seconds=60):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Rate limit exceeded for website scans. Please wait."},
            )

    if "/intelligence/analyze" in path and request.method == "POST":
        if is_rate_limited(f"analyze_{client_ip}", limit=30, window_seconds=60):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Analysis rate limit reached. Please retry in a moment."},
            )

    if path.endswith("/report.pdf") and request.method == "GET":
        if is_rate_limited(f"report_{client_ip}", limit=30, window_seconds=60):
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={"detail": "Report download rate limit reached."},
            )

    # 3. Process Request
    response: Response = await call_next(request)

    # 4. Enforce Strict Security Headers
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data: http: https: blob:; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline';"
    )

    if settings.ENVIRONMENT == "production":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

    return response


# Global Exception Handler preventing stack trace leakage
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    cid = get_correlation_id()
    logger.error(f"Unhandled server error on {request.method} {request.url.path} (CID: {cid}): {exc}")

    # In production, never expose raw traceback or internal exception details
    if settings.ENVIRONMENT == "production" and not settings.DEBUG:
        detail_msg = "An internal server error occurred. Please contact the security administrator."
    else:
        detail_msg = str(exc)

    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "detail": detail_msg,
            "correlation_id": cid,
        },
    )


frontend_dist = Path(__file__).resolve().parent.parent.parent / "frontend" / "dist"


# Root endpoint: Serves full React Web Platform to browsers, and JSON info to API clients
@app.get("/", tags=["Root"])
async def root(request: Request):
    accept = request.headers.get("accept", "")
    format_param = request.query_params.get("format")
    is_browser_html_request = "text/html" in accept

    # If a real browser requests the root URL and the compiled SPA exists, serve the React Web Platform
    if is_browser_html_request and format_param != "json":
        index_file = frontend_dist / "index.html"
        if index_file.exists():
            return FileResponse(index_file)

    return {
        "name": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "tagline": "Detect. Explain. Protect.",
        "status": "operational",
        "docs_url": docs_url or "disabled in production",
        "api_v1": settings.API_V1_STR,
    }


# Mount static screenshot directory
screenshot_dir = Path(__file__).resolve().parent.parent / "storage" / "screenshots"
screenshot_dir.mkdir(parents=True, exist_ok=True)
app.mount("/api/v1/screenshots", StaticFiles(directory=str(screenshot_dir)), name="screenshots")

# Mount v1 routes
app.include_router(api_router, prefix=settings.API_V1_STR)

# Top-level health endpoints for orchestration/monitoring
from app.api.routes.health import router as health_router
app.include_router(health_router)

# Mount Frontend SPA static assets and client-side routing fallback
if frontend_dist.exists():
    assets_dir = frontend_dist / "assets"
    if assets_dir.exists():
        app.mount("/assets", StaticFiles(directory=str(assets_dir)), name="frontend_static_assets")

    @app.get("/{full_path:path}", include_in_schema=False)
    async def serve_spa_routes(full_path: str):
        # Do not intercept API, docs, or OpenAPI routes
        if (
            full_path.startswith("api/")
            or full_path.startswith("health")
            or full_path.startswith("docs")
            or full_path.startswith("redoc")
            or full_path.startswith("openapi.json")
        ):
            return JSONResponse(status_code=status.HTTP_404_NOT_FOUND, content={"detail": "Not Found"})

        target_file = frontend_dist / full_path
        if full_path and target_file.is_file():
            return FileResponse(target_file)
        return FileResponse(frontend_dist / "index.html")


if __name__ == "__main__":
    import os
    import uvicorn
    port = int(os.environ.get("PORT", 8000))
    host = os.environ.get("HOST", "0.0.0.0")
    uvicorn.run("app.main:app", host=host, port=port, reload=settings.DEBUG)


