"""
Database Connection Management

Database connection, session management, and MongoDB connections.
"""

import os
import logging
from typing import Optional, Dict, Any, AsyncGenerator
from contextlib import asynccontextmanager
from urllib.parse import quote_plus

from sqlalchemy import create_engine, MetaData
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import StaticPool
import asyncpg
from motor.motor_asyncio import AsyncIOMotorClient
import redis.asyncio as redis
from elasticsearch import AsyncElasticsearch
import asyncio

from .models.base import Base

logger = logging.getLogger(__name__)


class DatabaseConfig:
    """Database configuration settings."""
    
    def __init__(self):
        # PostgreSQL settings
        self.postgres_host = os.getenv('POSTGRES_HOST', 'localhost')
        self.postgres_port = int(os.getenv('POSTGRES_PORT', '5432'))
        self.postgres_user = os.getenv('POSTGRES_USER', 'mcp_user')
        self.postgres_password = os.getenv('POSTGRES_PASSWORD', 'mcp_password')
        self.postgres_db = os.getenv('POSTGRES_DB', 'mcp_security')
        
        # MongoDB settings
        self.mongodb_host = os.getenv('MONGODB_HOST', 'localhost')
        self.mongodb_port = int(os.getenv('MONGODB_PORT', '27017'))
        self.mongodb_user = os.getenv('MONGODB_USER', 'mcp_user')
        self.mongodb_password = os.getenv('MONGODB_PASSWORD', 'mcp_password')
        self.mongodb_db = os.getenv('MONGODB_DB', 'mcp_security')
        
        # Redis settings
        self.redis_host = os.getenv('REDIS_HOST', 'localhost')
        self.redis_port = int(os.getenv('REDIS_PORT', '6379'))
        self.redis_password = os.getenv('REDIS_PASSWORD')
        self.redis_db = int(os.getenv('REDIS_DB', '0'))
        
        # Elasticsearch settings
        self.elasticsearch_host = os.getenv('ELASTICSEARCH_HOST', 'localhost')
        self.elasticsearch_port = int(os.getenv('ELASTICSEARCH_PORT', '9200'))
        self.elasticsearch_user = os.getenv('ELASTICSEARCH_USER')
        self.elasticsearch_password = os.getenv('ELASTICSEARCH_PASSWORD')
        
        # Connection pool settings
        self.pool_size = int(os.getenv('DB_POOL_SIZE', '20'))
        self.max_overflow = int(os.getenv('DB_MAX_OVERFLOW', '30'))
        self.pool_timeout = int(os.getenv('DB_POOL_TIMEOUT', '30'))
        self.pool_recycle = int(os.getenv('DB_POOL_RECYCLE', '3600'))
    
    def get_postgres_url(self, async_driver: bool = False) -> str:
        """Get PostgreSQL connection URL."""
        driver = "postgresql+asyncpg" if async_driver else "postgresql"
        password = quote_plus(self.postgres_password)
        return (
            f"{driver}://{self.postgres_user}:{password}@"
            f"{self.postgres_host}:{self.postgres_port}/{self.postgres_db}"
        )
    
    def get_mongodb_url(self) -> str:
        """Get MongoDB connection URL."""
        if self.mongodb_user and self.mongodb_password:
            auth = f"{quote_plus(self.mongodb_user)}:{quote_plus(self.mongodb_password)}@"
        else:
            auth = ""
        
        return f"mongodb://{auth}{self.mongodb_host}:{self.mongodb_port}/{self.mongodb_db}"
    
    def get_redis_url(self) -> str:
        """Get Redis connection URL."""
        auth = f":{self.redis_password}@" if self.redis_password else ""
        return f"redis://{auth}{self.redis_host}:{self.redis_port}/{self.redis_db}"
    
    def get_elasticsearch_url(self) -> str:
        """Get Elasticsearch connection URL."""
        auth = f"{self.elasticsearch_user}:{self.elasticsearch_password}@" if self.elasticsearch_user else ""
        return f"http://{auth}{self.elasticsearch_host}:{self.elasticsearch_port}"


class DatabaseManager:
    """Centralized database connection manager."""
    
    def __init__(self, config: Optional[DatabaseConfig] = None):
        self.config = config or DatabaseConfig()
        
        # PostgreSQL connections
        self.sync_engine = None
        self.async_engine = None
        self.sync_session_factory = None
        self.async_session_factory = None
        
        # MongoDB connection
        self.mongodb_client = None
        self.mongodb_db = None
        
        # Redis connection
        self.redis_client = None
        
        # Elasticsearch connection
        self.elasticsearch_client = None
        
        self._initialized = False
    
    async def initialize(self):
        """Initialize all database connections."""
        if self._initialized:
            return
        
        try:
            # Initialize PostgreSQL
            await self._init_postgresql()
            
            # Initialize MongoDB
            await self._init_mongodb()
            
            # Initialize Redis
            await self._init_redis()
            
            # Initialize Elasticsearch
            await self._init_elasticsearch()
            
            self._initialized = True
            logger.info("Database connections initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize database connections: {e}")
            await self.close()
            raise
    
    async def _init_postgresql(self):
        """Initialize PostgreSQL connections."""
        # Sync engine
        self.sync_engine = create_engine(
            self.config.get_postgres_url(async_driver=False),
            pool_size=self.config.pool_size,
            max_overflow=self.config.max_overflow,
            pool_timeout=self.config.pool_timeout,
            pool_recycle=self.config.pool_recycle,
            echo=os.getenv('SQL_ECHO', 'false').lower() == 'true'
        )
        
        # Async engine
        self.async_engine = create_async_engine(
            self.config.get_postgres_url(async_driver=True),
            pool_size=self.config.pool_size,
            max_overflow=self.config.max_overflow,
            pool_timeout=self.config.pool_timeout,
            pool_recycle=self.config.pool_recycle,
            echo=os.getenv('SQL_ECHO', 'false').lower() == 'true'
        )
        
        # Session factories
        self.sync_session_factory = sessionmaker(
            bind=self.sync_engine,
            autocommit=False,
            autoflush=False
        )
        
        self.async_session_factory = async_sessionmaker(
            bind=self.async_engine,
            class_=AsyncSession,
            autocommit=False,
            autoflush=False
        )
        
        # Test connection
        async with self.async_engine.begin() as conn:
            await conn.run_sync(lambda sync_conn: sync_conn.execute("SELECT 1"))
        
        logger.info("PostgreSQL connection initialized")
    
    async def _init_mongodb(self):
        """Initialize MongoDB connection."""
        try:
            self.mongodb_client = AsyncIOMotorClient(self.config.get_mongodb_url())
            self.mongodb_db = self.mongodb_client[self.config.mongodb_db]
            
            # Test connection
            await self.mongodb_client.admin.command('ping')
            logger.info("MongoDB connection initialized")
            
        except Exception as e:
            logger.warning(f"MongoDB connection failed: {e}")
            self.mongodb_client = None
            self.mongodb_db = None
    
    async def _init_redis(self):
        """Initialize Redis connection."""
        try:
            self.redis_client = redis.from_url(
                self.config.get_redis_url(),
                encoding="utf-8",
                decode_responses=True,
                max_connections=self.config.pool_size
            )
            
            # Test connection
            await self.redis_client.ping()
            logger.info("Redis connection initialized")
            
        except Exception as e:
            logger.warning(f"Redis connection failed: {e}")
            self.redis_client = None
    
    async def _init_elasticsearch(self):
        """Initialize Elasticsearch connection."""
        try:
            if self.config.elasticsearch_user:
                auth = (self.config.elasticsearch_user, self.config.elasticsearch_password)
            else:
                auth = None
            
            self.elasticsearch_client = AsyncElasticsearch(
                [f"{self.config.elasticsearch_host}:{self.config.elasticsearch_port}"],
                http_auth=auth,
                verify_certs=False,
                max_retries=3,
                retry_on_timeout=True
            )
            
            # Test connection
            if await self.elasticsearch_client.ping():
                logger.info("Elasticsearch connection initialized")
            else:
                raise Exception("Elasticsearch ping failed")
                
        except Exception as e:
            logger.warning(f"Elasticsearch connection failed: {e}")
            if self.elasticsearch_client:
                await self.elasticsearch_client.close()
            self.elasticsearch_client = None
    
    def get_sync_session(self) -> Session:
        """Get synchronous database session."""
        if not self.sync_session_factory:
            raise RuntimeError("Database not initialized")
        return self.sync_session_factory()
    
    @asynccontextmanager
    async def get_async_session(self) -> AsyncGenerator[AsyncSession, None]:
        """Get asynchronous database session."""
        if not self.async_session_factory:
            raise RuntimeError("Database not initialized")
        
        async with self.async_session_factory() as session:
            try:
                yield session
                await session.commit()
            except Exception:
                await session.rollback()
                raise
            finally:
                await session.close()
    
    def get_mongodb_collection(self, collection_name: str):
        """Get MongoDB collection."""
        if not self.mongodb_db:
            raise RuntimeError("MongoDB not initialized")
        return self.mongodb_db[collection_name]
    
    def get_redis_client(self):
        """Get Redis client."""
        if not self.redis_client:
            raise RuntimeError("Redis not initialized")
        return self.redis_client
    
    def get_elasticsearch_client(self):
        """Get Elasticsearch client."""
        if not self.elasticsearch_client:
            raise RuntimeError("Elasticsearch not initialized")
        return self.elasticsearch_client
    
    async def create_tables(self):
        """Create all database tables."""
        if not self.async_engine:
            raise RuntimeError("Database not initialized")
        
        async with self.async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        logger.info("Database tables created")
    
    async def drop_tables(self):
        """Drop all database tables."""
        if not self.async_engine:
            raise RuntimeError("Database not initialized")
        
        async with self.async_engine.begin() as conn:
            await conn.run_sync(Base.metadata.drop_all)
        
        logger.info("Database tables dropped")
    
    async def check_health(self) -> Dict[str, bool]:
        """Check health of all database connections."""
        health = {}
        
        # PostgreSQL health
        try:
            if self.async_engine:
                async with self.async_engine.begin() as conn:
                    await conn.run_sync(lambda sync_conn: sync_conn.execute("SELECT 1"))
                health['postgresql'] = True
            else:
                health['postgresql'] = False
        except Exception:
            health['postgresql'] = False
        
        # MongoDB health
        try:
            if self.mongodb_client:
                await self.mongodb_client.admin.command('ping')
                health['mongodb'] = True
            else:
                health['mongodb'] = False
        except Exception:
            health['mongodb'] = False
        
        # Redis health
        try:
            if self.redis_client:
                await self.redis_client.ping()
                health['redis'] = True
            else:
                health['redis'] = False
        except Exception:
            health['redis'] = False
        
        # Elasticsearch health
        try:
            if self.elasticsearch_client:
                health['elasticsearch'] = await self.elasticsearch_client.ping()
            else:
                health['elasticsearch'] = False
        except Exception:
            health['elasticsearch'] = False
        
        return health
    
    async def close(self):
        """Close all database connections."""
        try:
            if self.async_engine:
                await self.async_engine.dispose()
            
            if self.sync_engine:
                self.sync_engine.dispose()
            
            if self.mongodb_client:
                self.mongodb_client.close()
            
            if self.redis_client:
                await self.redis_client.close()
            
            if self.elasticsearch_client:
                await self.elasticsearch_client.close()
            
            logger.info("Database connections closed")
            
        except Exception as e:
            logger.error(f"Error closing database connections: {e}")


# Global database manager instance
db_manager = DatabaseManager()


# Convenience functions for common operations
async def get_db_session() -> AsyncGenerator[AsyncSession, None]:
    """Get database session (FastAPI dependency)."""
    async with db_manager.get_async_session() as session:
        yield session


async def get_mongodb_collection(collection_name: str):
    """Get MongoDB collection (FastAPI dependency)."""
    return db_manager.get_mongodb_collection(collection_name)


async def get_redis_client():
    """Get Redis client (FastAPI dependency)."""
    return db_manager.get_redis_client()


async def get_elasticsearch_client():
    """Get Elasticsearch client (FastAPI dependency)."""
    return db_manager.get_elasticsearch_client()


# Database initialization function
async def init_database():
    """Initialize database connections."""
    await db_manager.initialize()


# Database cleanup function
async def close_database():
    """Close database connections."""
    await db_manager.close()


# Context manager for database session
@asynccontextmanager
async def database_session() -> AsyncGenerator[AsyncSession, None]:
    """Context manager for database session."""
    async with db_manager.get_async_session() as session:
        yield session