from sqlalchemy.ext.asyncio import create_async_engine, AsyncEngine
from sqlalchemy import text
from contextlib import asynccontextmanager
import asyncio

from .core.config import settings

engine: AsyncEngine = create_async_engine(
    settings.DATABASE_URL,
    pool_pre_ping=True,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
    pool_timeout=settings.DB_POOL_TIMEOUT,
    pool_recycle=settings.DB_POOL_RECYCLE,
    echo=settings.SQL_ECHO,
)

@asynccontextmanager
async def lifespan(app):
    # warm-up (opțional)
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
    except Exception:
        pass
    yield
    await engine.dispose()

async def db_ping(timeout_sec: int = 2):
    async with asyncio.timeout(timeout_sec):
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))