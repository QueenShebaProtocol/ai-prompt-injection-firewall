"""Async database engine, session factory, and connection health check.

`engine`/`AsyncSessionLocal` are created at module scope, but creating a
SQLAlchemy async engine does no I/O by itself - the connection pool is lazy
and nothing actually touches the network until the first checkout. That
satisfies "do not open a connection at import time": importing this module
is always safe, even with no database reachable.
"""

import os

from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)

from src.database.models import init_schema as _create_all_tables

DATABASE_URL: str = os.environ.get(
    "DATABASE_URL",
    "postgresql+asyncpg://firewall_user:change_me@db:5432/firewall_db",
)

engine = create_async_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=5,
    max_overflow=10,
)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


async def get_session() -> AsyncSession:
    """Yield a session for the lifetime of a request, always closing it."""
    async with AsyncSessionLocal() as session:
        yield session


async def check_database_connection() -> bool:
    """Return True if the database answers a trivial query, False otherwise.

    Never raises - any connection or query failure is treated as "down".
    """
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        return True
    except Exception:
        return False


async def init_schema() -> None:
    """Create every table declared on `Base.metadata` if it doesn't exist yet.

    This replaces a SQL init script: the project's tree has no `sql/`
    directory, so the gateway bootstraps its own schema at startup
    (see docker-compose.yml) instead of relying on a mounted .sql file.

    Delegates to `models.init_schema(engine)` (P3's models.py already
    defines the create_all logic) instead of duplicating it here.
    """
    await _create_all_tables(engine)