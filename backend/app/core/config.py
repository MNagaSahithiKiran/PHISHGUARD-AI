import os
from typing import List, Union, Optional
from pydantic import field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    PROJECT_NAME: str = "PhishGuard AI"
    VERSION: str = "1.0.0-phase8"
    DESCRIPTION: str = "Production-grade cybersecurity platform for intelligent phishing detection"
    ENVIRONMENT: str = "development"  # development | test | production
    DEBUG: bool = True
    API_V1_STR: str = "/api/v1"

    # Security & Tokens
    SECRET_KEY: str = "dev-insecure-secret-key-change-in-production-phishguard-2026"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60 * 24  # 24 hours
    ALLOWED_HOSTS: Union[List[str], str] = ["localhost", "127.0.0.1", "testserver"]

    # Default Admin Configuration
    ADMIN_DEFAULT_EMAIL: str = "admin@phishguard.ai"
    ADMIN_DEFAULT_PASSWORD: str = "Admin@PhishGuard2026!"

    # CORS
    BACKEND_CORS_ORIGINS: Union[List[str], str] = [
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8080",
        "http://127.0.0.1:8080",
    ]

    @field_validator("BACKEND_CORS_ORIGINS", "ALLOWED_HOSTS", mode="before")
    @classmethod
    def assemble_string_or_list(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                import json
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return [str(v)]

    # Database
    DATABASE_URL: str = "sqlite+aiosqlite:///./phishguard.db"

    # Background Job Queue & Cache (Redis)
    REDIS_URL: str = "redis://localhost:6379/0"

    # Idempotency & Rate Limiting
    IDEMPOTENCY_WINDOW_SECONDS: int = 300  # 5 minutes
    RATE_LIMIT_PER_MINUTE: int = 60
    LOGIN_RATE_LIMIT_PER_MINUTE: int = 15

    # URL Scanner Security & Fetch Safety Guardrails
    URL_FETCH_TIMEOUT_SECONDS: int = 10
    MAX_SCAN_TIMEOUT_SECONDS: int = 30
    MAX_CONTENT_LENGTH_BYTES: int = 10 * 1024 * 1024  # 10 MB limit
    MAX_SCREENSHOT_SIZE_BYTES: int = 5 * 1024 * 1024  # 5 MB limit
    ENABLE_SSRF_PROTECTION: bool = True
    ALLOW_PRIVATE_IPS: bool = False

    # AI Models Directory
    MODEL_DIRECTORY: str = "ml/models"

    # Observability & Logging
    LOG_LEVEL: str = "INFO"
    LOG_FORMAT: str = "text"  # text | json
    ENABLE_DOCS_IN_PRODUCTION: bool = False

    # Data Retention (Days)
    RETENTION_DAYS_SCREENSHOTS: int = 30
    RETENTION_DAYS_AUDIT_LOGS: int = 90

    ALLOW_SQLITE_IN_PRODUCTION: bool = False

    @model_validator(mode="after")
    def validate_production_environment(self) -> "Settings":
        """Fail fast if required production secrets or security postures are violated."""
        if self.ENVIRONMENT == "production":
            # 1. Enforce strong cryptographic secret
            if (
                self.SECRET_KEY.startswith("dev-")
                or "REPLACE_WITH" in self.SECRET_KEY
                or len(self.SECRET_KEY) < 32
            ):
                raise ValueError(
                    "FAIL FAST: In production, SECRET_KEY must be a cryptographically "
                    "secure secret of at least 32 characters supplied via environment."
                )

            # 2. Forbid DEBUG in production
            if self.DEBUG:
                raise ValueError("FAIL FAST: DEBUG must be set to False in production.")

            # 3. Forbid SQLite in production unless explicitly permitted (e.g. cloud demo)
            if not self.ALLOW_SQLITE_IN_PRODUCTION and self.DATABASE_URL.startswith("sqlite"):
                raise ValueError(
                    "FAIL FAST: SQLite is not permitted in production. Configure a production "
                    "PostgreSQL DATABASE_URL (postgresql+asyncpg://...) or set ALLOW_SQLITE_IN_PRODUCTION=true."
                )

            # 4. Forbid wildcard hosts or CORS in production unless explicitly permitted for cloud demo
            if not self.ALLOW_SQLITE_IN_PRODUCTION:
                if "*" in self.ALLOWED_HOSTS:
                    raise ValueError(
                        "FAIL FAST: Wildcard '*' in ALLOWED_HOSTS is forbidden in production."
                    )
                if "*" in self.BACKEND_CORS_ORIGINS:
                    raise ValueError(
                        "FAIL FAST: Wildcard '*' in BACKEND_CORS_ORIGINS is forbidden in production."
                    )

        return self

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )


settings = Settings()
