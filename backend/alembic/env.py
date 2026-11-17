"""Alembic environment configuration for SentinelAgent.

Loads database configuration securely from app settings without exposing
passwords in logs or version-controlled files.
"""

import os
import sys
from logging.config import fileConfig

# Ensure backend and application directories are in sys.path
alembic_dir = os.path.dirname(os.path.abspath(__file__))
backend_dir = os.path.dirname(alembic_dir)
root_dir = os.path.dirname(backend_dir)
for p in (root_dir, backend_dir, os.path.join(backend_dir, "app")):
    if p not in sys.path:
        sys.path.insert(0, p)

from alembic import context
from sqlalchemy import pool

from app.core.config import get_settings
from app.db.connection import get_engine
from app.models import Base

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
# This line sets up loggers basically.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    """Safely obtain DATABASE_URL from pydantic settings."""
    settings = get_settings()
    if not settings.DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured.")
    url = settings.DATABASE_URL.get_secret_value().strip()
    if not url:
        raise RuntimeError("DATABASE_URL is empty.")
    return url


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL and not an Engine.
    Calls to context.execute() here emit the given string to the script output.
    """
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    Reuses SentinelAgent's engine initialization to ensure consistent
    pool configuration, pre-ping verification, and secure connection management.
    """
    connectable = get_engine()
    if connectable is None:
        raise RuntimeError("Database engine could not be initialized for migrations.")

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            compare_type=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
