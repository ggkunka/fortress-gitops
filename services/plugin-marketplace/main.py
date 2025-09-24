"""
Plugin Marketplace Service - Plugin Discovery, Installation and Management Hub

This service provides a comprehensive marketplace for security plugins including
discovery, installation, lifecycle management, and community features.
"""

import asyncio
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles

from shared.config.settings import get_settings
from shared.observability.logging import setup_logging, get_logger
from shared.observability.metrics import setup_metrics, get_metrics
from shared.observability.tracing import setup_tracing
from shared.middleware.security import SecurityMiddleware
from shared.middleware.rate_limiting import RateLimitingMiddleware
from shared.middleware.request_id import RequestIDMiddleware
from shared.events.event_bus import EventBus
from shared.database.connection import init_db

from .services.marketplace_manager import MarketplaceManager
from .services.plugin_registry import PluginRegistry
from .services.plugin_installer import PluginInstaller
from .services.plugin_validator import PluginValidator
from .services.plugin_executor import PluginExecutor
from .services.community_manager import CommunityManager
from .api.marketplace_api import router as marketplace_router
from .api.plugin_api import router as plugin_router
from .api.community_api import router as community_router

# Global instances
marketplace_manager = None
plugin_registry = None
plugin_installer = None
plugin_validator = None
plugin_executor = None
community_manager = None
event_bus = None

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global (marketplace_manager, plugin_registry, plugin_installer, 
            plugin_validator, plugin_executor, community_manager, event_bus)
    
    try:
        # Initialize configuration
        settings = get_settings()
        
        # Setup observability
        setup_logging(service_name="plugin-marketplace")
        setup_metrics(service_name="plugin-marketplace")
        setup_tracing(service_name="plugin-marketplace")
        
        # Initialize database
        await init_db()
        
        # Initialize event bus
        event_bus = EventBus(
            redis_url=settings.redis_url,
            service_name="plugin-marketplace"
        )
        await event_bus.connect()
        
        # Initialize core services
        plugin_registry = PluginRegistry()
        await plugin_registry.start()
        
        plugin_validator = PluginValidator()
        await plugin_validator.start()
        
        plugin_installer = PluginInstaller(
            registry=plugin_registry,
            validator=plugin_validator
        )
        await plugin_installer.start()
        
        plugin_executor = PluginExecutor(
            registry=plugin_registry,
            event_bus=event_bus
        )
        await plugin_executor.start()
        
        community_manager = CommunityManager(
            event_bus=event_bus
        )
        await community_manager.start()
        
        # Initialize marketplace manager
        marketplace_manager = MarketplaceManager(
            registry=plugin_registry,
            installer=plugin_installer,
            validator=plugin_validator,
            executor=plugin_executor,
            community=community_manager,
            event_bus=event_bus
        )
        await marketplace_manager.start()
        
        logger.info("Plugin Marketplace service started successfully")
        
        yield
        
    except Exception as e:
        logger.error(f"Failed to start plugin marketplace service: {e}")
        raise
    finally:
        # Cleanup
        if marketplace_manager:
            await marketplace_manager.stop()
        
        if plugin_executor:
            await plugin_executor.stop()
        
        if plugin_installer:
            await plugin_installer.stop()
        
        if plugin_validator:
            await plugin_validator.stop()
        
        if plugin_registry:
            await plugin_registry.stop()
        
        if community_manager:
            await community_manager.stop()
        
        if event_bus:
            await event_bus.disconnect()
        
        logger.info("Plugin Marketplace service stopped")


def create_app() -> FastAPI:
    """Create FastAPI application."""
    settings = get_settings()
    
    app = FastAPI(
        title="Plugin Marketplace Service",
        description="Comprehensive plugin marketplace for the MCP Security Platform",
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
    
    # Mount static files for plugin assets and UI
    if hasattr(settings, 'static_files_path'):
        app.mount("/static", StaticFiles(directory=settings.static_files_path), name="static")
    
    # Include routers
    app.include_router(
        marketplace_router,
        prefix="/api/v1/marketplace",
        tags=["marketplace"]
    )
    
    app.include_router(
        plugin_router,
        prefix="/api/v1/plugins",
        tags=["plugins"]
    )
    
    app.include_router(
        community_router,
        prefix="/api/v1/community",
        tags=["community"]
    )
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "service": "plugin-marketplace",
            "version": "1.0.0"
        }
    
    @app.get("/metrics")
    async def get_service_metrics():
        """Get service metrics."""
        metrics = get_metrics()
        
        service_metrics = {
            "service": "plugin-marketplace",
            "marketplace_manager": marketplace_manager.get_stats() if marketplace_manager else {},
            "plugin_registry": plugin_registry.get_stats() if plugin_registry else {},
            "plugin_installer": plugin_installer.get_stats() if plugin_installer else {},
            "plugin_executor": plugin_executor.get_stats() if plugin_executor else {},
            "community_manager": community_manager.get_stats() if community_manager else {}
        }
        
        return service_metrics
    
    @app.get("/")
    async def root():
        """Root endpoint with service information."""
        return {
            "service": "MCP Security Platform - Plugin Marketplace",
            "version": "1.0.0",
            "description": "Comprehensive plugin marketplace with discovery, installation, and management",
            "endpoints": {
                "health": "/health",
                "metrics": "/metrics",
                "marketplace": "/api/v1/marketplace",
                "plugins": "/api/v1/plugins",
                "community": "/api/v1/community",
                "docs": "/docs"
            }
        }
    
    return app


def get_marketplace_manager() -> MarketplaceManager:
    """Get marketplace manager instance."""
    if marketplace_manager is None:
        raise RuntimeError("Marketplace manager not initialized")
    return marketplace_manager


def get_plugin_registry() -> PluginRegistry:
    """Get plugin registry instance."""
    if plugin_registry is None:
        raise RuntimeError("Plugin registry not initialized")
    return plugin_registry


def get_plugin_installer() -> PluginInstaller:
    """Get plugin installer instance."""
    if plugin_installer is None:
        raise RuntimeError("Plugin installer not initialized")
    return plugin_installer


def get_plugin_validator() -> PluginValidator:
    """Get plugin validator instance."""
    if plugin_validator is None:
        raise RuntimeError("Plugin validator not initialized")
    return plugin_validator


def get_plugin_executor() -> PluginExecutor:
    """Get plugin executor instance."""
    if plugin_executor is None:
        raise RuntimeError("Plugin executor not initialized")
    return plugin_executor


def get_community_manager() -> CommunityManager:
    """Get community manager instance."""
    if community_manager is None:
        raise RuntimeError("Community manager not initialized")
    return community_manager


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
        port=8005,
        reload=True,
        log_level="info"
    )