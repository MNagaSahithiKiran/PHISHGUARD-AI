#!/usr/bin/env python3
"""PhishGuard AI - Database Migration Runner
Executes Alembic migrations forward to 'head' safely.
"""

import sys
from pathlib import Path
from alembic.config import Config
from alembic import command

# Add backend directory to sys.path
backend_dir = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(backend_dir))

from app.core.config import settings
from app.core.logging import logger


def run_migrations():
    logger.info(f"Running database migrations for environment: {settings.ENVIRONMENT}")
    alembic_ini_path = backend_dir / "alembic.ini"
    alembic_cfg = Config(str(alembic_ini_path))
    alembic_cfg.set_main_option("script_location", str(backend_dir / "alembic"))
    alembic_cfg.set_main_option("sqlalchemy.url", settings.DATABASE_URL)

    try:
        command.upgrade(alembic_cfg, "head")
        logger.info("Database migration upgrade to 'head' completed successfully.")
    except Exception as e:
        logger.error(f"Database migration failed: {e}")
        sys.exit(1)


if __name__ == "__main__":
    run_migrations()
