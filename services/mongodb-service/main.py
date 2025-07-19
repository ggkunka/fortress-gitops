"""
MongoDB Service - Main Application

This service provides MongoDB-based SBOM document storage and management
for the MCP Security Platform.
"""

import asyncio
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware

from shared.config.settings import get_settings
from shared.observability.logging import setup_logging, get_logger
from shared.observability.metrics import setup_metrics, get_metrics
from shared.observability.tracing import setup_tracing
from shared.middleware.security import SecurityMiddleware
from shared.middleware.rate_limiting import RateLimitingMiddleware
from shared.middleware.request_id import RequestIDMiddleware
from shared.events.event_bus import EventBus

from .models.sbom import MongoDBConnection
from .services.sbom_repository import SBOMRepository
from .services.sbom_processor import SBOMProcessor
from .api.sbom_api import router as sbom_router
from .api import sbom_api

# Global instances
mongo_connection = None
sbom_repository = None
sbom_processor = None
event_bus = None

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global mongo_connection, sbom_repository, sbom_processor, event_bus
    
    try:
        # Initialize configuration
        settings = get_settings()
        
        # Setup observability
        setup_logging(service_name="mongodb-service")
        setup_metrics(service_name="mongodb-service")
        setup_tracing(service_name="mongodb-service")
        
        # Initialize MongoDB connection
        mongo_connection = MongoDBConnection()
        await mongo_connection.connect()
        
        # Initialize event bus
        event_bus = EventBus(
            redis_url=settings.redis_url,
            service_name="mongodb-service"
        )
        await event_bus.connect()
        
        # Initialize SBOM repository
        sbom_repository = SBOMRepository()
        await sbom_repository.initialize()
        
        # Initialize SBOM processor
        sbom_processor = SBOMProcessor(sbom_repository, event_bus)
        
        # Set global instances for dependency injection
        sbom_api.sbom_repository = sbom_repository
        sbom_api.sbom_processor = sbom_processor
        
        logger.info("MongoDB service started successfully")
        
        yield
        
    except Exception as e:
        logger.error(f"Failed to start MongoDB service: {e}")
        raise
    finally:
        # Cleanup
        if event_bus:
            await event_bus.disconnect()
        
        if mongo_connection:
            await mongo_connection.disconnect()
        
        logger.info("MongoDB service stopped")


def create_app() -> FastAPI:
    """Create FastAPI application."""
    settings = get_settings()
    
    app = FastAPI(
        title="MongoDB Service",
        description="MongoDB-based SBOM document storage and management",
        version="1.0.0",
        lifespan=lifespan
    )
    
    # Add CORS middleware
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    
    # Add custom middleware
    app.add_middleware(SecurityMiddleware)
    app.add_middleware(RateLimitingMiddleware)
    app.add_middleware(RequestIDMiddleware)
    
    # Include routers
    app.include_router(
        sbom_router,
        prefix="/api/v1/sbom",
        tags=["sbom"]
    )
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "service": "mongodb-service",
            "version": "1.0.0"
        }
    
    @app.get("/metrics")
    async def get_service_metrics():
        """Get service metrics."""
        metrics = get_metrics()
        
        service_metrics = {
            "service": "mongodb-service",
            "mongodb_connection": "connected" if mongo_connection and mongo_connection.client else "disconnected",
            "sbom_repository": sbom_repository.get_stats() if sbom_repository else {},
            "sbom_processor": sbom_processor.get_stats() if sbom_processor else {}
        }
        
        return service_metrics
    
    @app.get("/")
    async def root():
        """Root endpoint with service information."""
        return {
            "service": "MCP Security Platform - MongoDB Service",
            "version": "1.0.0",
            "description": "MongoDB-based SBOM document storage and management",
            "endpoints": {
                "health": "/health",
                "metrics": "/metrics",
                "api": "/api/v1/sbom",
                "docs": "/docs"
            }
        }
    
    return app


def get_mongo_connection() -> MongoDBConnection:
    """Get MongoDB connection instance."""
    if mongo_connection is None:
        raise RuntimeError("MongoDB connection not initialized")
    return mongo_connection


def get_sbom_repository() -> SBOMRepository:
    """Get SBOM repository instance."""
    if sbom_repository is None:
        raise RuntimeError("SBOM repository not initialized")
    return sbom_repository


def get_sbom_processor() -> SBOMProcessor:
    """Get SBOM processor instance."""
    if sbom_processor is None:
        raise RuntimeError("SBOM processor not initialized")
    return sbom_processor


def get_event_bus() -> EventBus:
    """Get event bus instance."""
    if event_bus is None:
        raise RuntimeError("Event bus not initialized")
    return event_bus


# Create application instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8010,
        reload=True,
        log_level="info"
    )