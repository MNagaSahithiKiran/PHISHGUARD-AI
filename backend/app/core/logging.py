import json
import logging
import sys
import time
from typing import Any, Dict
from app.core.config import settings
from app.core.correlation import get_correlation_id

SENSITIVE_KEYS = {"password", "token", "secret", "cookie", "authorization", "api_key", "credentials"}


class StructuredJsonFormatter(logging.Formatter):
    """Formats log records as single-line structured JSON with correlation IDs and secret scrubbing."""

    def format(self, record: logging.LogRecord) -> str:
        correlation_id = get_correlation_id()
        log_entry: Dict[str, Any] = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(record.created)),
            "level": record.levelname,
            "correlation_id": correlation_id,
            "logger": record.name,
            "message": self._sanitize_message(record.getMessage()),
            "file": f"{record.filename}:{record.lineno}",
        }

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)

    def _sanitize_message(self, message: str) -> str:
        # Prevent accidental log leakage of bearer tokens or basic passwords
        lower = message.lower()
        for key in SENSITIVE_KEYS:
            if f"{key}=" in lower or f'"{key}"' in lower:
                return "[REDACTED - SENSITIVE SECURITY DATA DETECTED]"
        return message


def setup_logging():
    log_level = getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO)

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    handler = logging.StreamHandler(sys.stdout)
    if settings.LOG_FORMAT == "json":
        handler.setFormatter(StructuredJsonFormatter())
    else:
        text_format = "%(asctime)s [%(levelname)s] [%(name)s] %(message)s"
        handler.setFormatter(logging.Formatter(text_format))

    root_logger.handlers = [handler]

    # Silence verbose 3rd party logs
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("aiosqlite").setLevel(logging.WARNING)
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    return logging.getLogger("phishguard")


logger = setup_logging()
