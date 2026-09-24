from collections.abc import AsyncGenerator
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import NullPool, QueuePool
from app.core.config import settings
from app.core.logging import logger
from app.db.base import Base

# Configure engine with fallback and clean connection pooling
database_url = settings.DATABASE_URL
engine_kwargs = {
    "echo": settings.DEBUG and False,
    "future": True,
}

if database_url.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
    if ":memory:" in database_url:
        engine_kwargs["poolclass"] = NullPool
else:
    # Production PostgreSQL connection pooling parameters
    engine_kwargs["pool_size"] = 20
    engine_kwargs["max_overflow"] = 10
    engine_kwargs["pool_pre_ping"] = True
    engine_kwargs["pool_recycle"] = 3600
    engine_kwargs["pool_timeout"] = 30

engine = create_async_engine(database_url, **engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)


async def init_db() -> None:
    """Initializes tables for development/testing if they don't already exist.
    In production, database migrations (Alembic) manage schema lifecycle without destructive actions.
    """
    if settings.ENVIRONMENT != "production":
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            if database_url.startswith("sqlite"):
                new_columns = [
                    ("scans", "canonical_url", "TEXT"),
                    ("scans", "final_url", "TEXT"),
                    ("scans", "redirect_chain", "TEXT"),
                    ("scan_results", "model_version", "VARCHAR(64)"),
                    ("scan_results", "feature_version", "VARCHAR(64)"),
                    ("scan_results", "preprocessing_version", "VARCHAR(64)"),
                    ("scan_results", "decision_policy_version", "VARCHAR(64)"),
                    ("scan_results", "url_feature_hash", "VARCHAR(64)"),
                    ("scan_results", "dom_snapshot_hash", "VARCHAR(64)"),
                    ("scan_results", "screenshot_hash", "VARCHAR(64)"),
                    ("scan_results", "model_input_hash", "VARCHAR(64)"),
                    ("scan_results", "prediction_hash", "VARCHAR(64)"),
                    ("scan_results", "live_content_changed", "BOOLEAN DEFAULT 0"),
                    ("scan_results", "content_change_notice", "TEXT"),
                    ("scan_results", "reproducibility_data", "TEXT"),
                    ("fusion_analyses", "url_feature_hash", "VARCHAR(64)"),
                    ("fusion_analyses", "dom_snapshot_hash", "VARCHAR(64)"),
                    ("fusion_analyses", "screenshot_hash", "VARCHAR(64)"),
                    ("fusion_analyses", "model_input_hash", "VARCHAR(64)"),
                    ("fusion_analyses", "prediction_hash", "VARCHAR(64)"),
                    ("fusion_analyses", "live_content_changed", "BOOLEAN DEFAULT 0"),
                    ("fusion_analyses", "content_change_notice", "TEXT"),
                    ("fusion_analyses", "reproducibility_data", "TEXT"),
                ]
                for table, col, col_type in new_columns:
                    try:
                        from sqlalchemy import text
                        await conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {col} {col_type};"))
                    except Exception:
                        pass
        logger.info("Database schema verified and initialized.")
    else:
        logger.info("Production mode: schema creation delegated to Alembic migrations.")


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """Dependency for providing an async database session per request."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
        except Exception as e:
            await session.rollback()
            raise e
        finally:
            await session.close()
