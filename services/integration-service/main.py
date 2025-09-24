"""
Integration Service - External System Integration Hub

This service provides centralized integration capabilities with third-party
security tools, cloud services, and external data sources.
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
from shared.database.connection import init_db

from .services.integration_manager import IntegrationManager
from .services.siem_connector import SIEMConnector
from .services.cloud_connector import CloudConnector
from .services.threat_feed_connector import ThreatFeedConnector
from .services.vulnerability_feed_connector import VulnerabilityFeedConnector
from .services.ticketing_connector import TicketingConnector
from .api.integration_api import router as integration_router

# Global instances
integration_manager = None
event_bus = None

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global integration_manager, event_bus
    
    try:
        # Initialize configuration
        settings = get_settings()
        
        # Setup observability
        setup_logging(service_name="integration")
        setup_metrics(service_name="integration")
        setup_tracing(service_name="integration")
        
        # Initialize database
        await init_db()
        
        # Initialize event bus
        event_bus = EventBus(
            redis_url=settings.redis_url,
            service_name="integration"
        )
        await event_bus.connect()
        
        # Initialize connectors
        siem_connector = SIEMConnector()
        cloud_connector = CloudConnector()
        threat_feed_connector = ThreatFeedConnector()
        vulnerability_feed_connector = VulnerabilityFeedConnector()
        ticketing_connector = TicketingConnector()
        
        # Initialize integration manager
        integration_manager = IntegrationManager(
            event_bus=event_bus,
            siem_connector=siem_connector,
            cloud_connector=cloud_connector,
            threat_feed_connector=threat_feed_connector,
            vulnerability_feed_connector=vulnerability_feed_connector,
            ticketing_connector=ticketing_connector
        )
        
        await integration_manager.start()
        
        logger.info("Integration service started successfully")
        
        yield
        
    except Exception as e:
        logger.error(f"Failed to start integration service: {e}")
        raise
    finally:
        # Cleanup
        if integration_manager:
            await integration_manager.stop()
        
        if event_bus:
            await event_bus.disconnect()
        
        logger.info("Integration service stopped")


def create_app() -> FastAPI:
    """Create FastAPI application."""
    settings = get_settings()
    
    app = FastAPI(
        title="Integration Service",
        description="External system integration hub for the MCP Security Platform",
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
        integration_router,
        prefix="/api/v1/integration",
        tags=["integration"]
    )
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "service": "integration",
            "version": "1.0.0"
        }
    
    @app.get("/metrics")
    async def get_service_metrics():
        """Get service metrics."""
        metrics = get_metrics()
        
        service_metrics = {
            "service": "integration",
            "integration_manager": integration_manager.get_stats() if integration_manager else {}
        }
        
        return service_metrics
    
    @app.get("/")
    async def root():
        """Root endpoint with service information."""
        return {
            "service": "MCP Security Platform - Integration Service",
            "version": "1.0.0",
            "description": "External system integration hub",
            "endpoints": {
                "health": "/health",
                "metrics": "/metrics",
                "api": "/api/v1/integration",
                "docs": "/docs"
            }
        }
    
    return app


def get_integration_manager() -> IntegrationManager:
    """Get integration manager instance."""
    if integration_manager is None:
        raise RuntimeError("Integration manager not initialized")
    return integration_manager


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
        port=8004,
        reload=True,
        log_level="info"
    )