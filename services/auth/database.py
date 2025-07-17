"""Database management for the authentication service."""

from typing import AsyncGenerator

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.pool import NullPool

from shared.config import get_settings
from .models import Base

settings = get_settings()


class DatabaseManager:
    """Database manager for the authentication service."""
    
    def __init__(self):
        self.engine = create_async_engine(
            settings.async_database_url,
            **settings.get_engine_config(),
            poolclass=NullPool if settings.is_testing else None,
        )
        self.SessionLocal = async_sessionmaker(
            self.engine,
            class_=AsyncSession,
            **settings.get_session_config(),
        )
    
    async def create_tables(self) -> None:
        """Create database tables."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    
    async def drop_tables(self) -> None:
        """Drop database tables."""
        async with self.engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
    
    async def get_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get database session."""
        async with self.SessionLocal() as session:
            try:
                yield session
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()
    
    async def close(self) -> None:
        """Close database connection."""
        await self.engine.dispose()


# Global database manager instance
db_manager = DatabaseManager()


async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Dependency to get database session."""
    async for session in db_manager.get_session():
        yield session