"""
Database engine + session factory (async SQLAlchemy 2.x)
"""
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from sqlalchemy import create_engine
from backend.models.models import Base
from config import settings

# ── Async engine (used at runtime) ───────────────────────────────────────────
async_engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=10,
    max_overflow=20,
    echo=settings.DEBUG,
)

AsyncSessionLocal = async_sessionmaker(
    bind=async_engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autoflush=False,
    autocommit=False,
)

# ── Sync engine (used only for Alembic migrations) ───────────────────────────
sync_engine = create_engine(settings.SYNC_DATABASE_URL, echo=False)


async def get_db() -> AsyncSession:
    """FastAPI dependency: yields an async DB session."""
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()


async def init_db():
    """Create all tables on startup (dev convenience; use Alembic in prod)."""
    async with async_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
