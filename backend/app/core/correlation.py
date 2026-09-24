import uuid
from contextvars import ContextVar
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

# Context variable accessible anywhere across the current asynchronous request context
correlation_id_ctx: ContextVar[str] = ContextVar("correlation_id_ctx", default="")


def get_correlation_id() -> str:
    """Returns the correlation ID for the active request, or generates a fallback."""
    cid = correlation_id_ctx.get()
    return cid if cid else str(uuid.uuid4())


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """ASGI Middleware extracting or generating unique request correlation IDs."""

    async def dispatch(self, request: Request, call_next) -> Response:
        cid = (
            request.headers.get("X-Correlation-ID")
            or request.headers.get("X-Request-ID")
            or str(uuid.uuid4())
        )
        token = correlation_id_ctx.set(cid)

        try:
            response: Response = await call_next(request)
            response.headers["X-Correlation-ID"] = cid
            response.headers["X-Request-ID"] = cid
            return response
        finally:
            correlation_id_ctx.reset(token)
