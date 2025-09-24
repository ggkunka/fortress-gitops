"""
Reporting Service - Main Application

This service provides comprehensive reporting and analytics capabilities
for the MCP Security Platform.
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

from .services.report_generator import ReportGenerator
from .services.data_collector import DataCollector
from .services.chart_generator import ChartGenerator
from .services.report_scheduler import ReportScheduler
from .api.reporting_api import router as reporting_router

# Global instances
data_collector = None
chart_generator = None
report_generator = None
report_scheduler = None
event_bus = None

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global data_collector, chart_generator, report_generator, report_scheduler, event_bus
    
    try:
        # Initialize configuration
        settings = get_settings()
        
        # Setup observability
        setup_logging(service_name="reporting")
        setup_metrics(service_name="reporting")
        setup_tracing(service_name="reporting")
        
        # Initialize database
        await init_db()
        
        # Initialize event bus
        event_bus = EventBus(
            redis_url=settings.redis_url,
            service_name="reporting"
        )
        await event_bus.connect()
        
        # Initialize data collector
        data_collector = DataCollector()
        await data_collector.start()
        
        # Initialize chart generator
        chart_generator = ChartGenerator()
        
        # Initialize report generator
        report_generator = ReportGenerator(
            data_collector=data_collector,
            chart_generator=chart_generator
        )
        await report_generator.start()
        
        # Initialize report scheduler
        report_scheduler = ReportScheduler(
            report_generator=report_generator,
            event_bus=event_bus
        )
        await report_scheduler.start()
        
        logger.info("Reporting service started successfully")
        
        yield
        
    except Exception as e:
        logger.error(f"Failed to start reporting service: {e}")
        raise
    finally:
        # Cleanup
        if report_scheduler:
            await report_scheduler.stop()
        
        if report_generator:
            await report_generator.stop()
        
        if data_collector:
            await data_collector.stop()
        
        if event_bus:
            await event_bus.disconnect()
        
        logger.info("Reporting service stopped")


def create_app() -> FastAPI:
    """Create FastAPI application."""
    settings = get_settings()
    
    app = FastAPI(
        title="Reporting Service",
        description="Comprehensive reporting and analytics platform",
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
    
    # Mount static files for report assets
    if hasattr(settings, 'static_files_path'):
        app.mount("/static", StaticFiles(directory=settings.static_files_path), name="static")
    
    # Include routers
    app.include_router(
        reporting_router,
        prefix="/api/v1/reporting",
        tags=["reporting"]
    )
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "service": "reporting",
            "version": "1.0.0"
        }
    
    @app.get("/metrics")
    async def get_service_metrics():
        """Get service metrics."""
        metrics = get_metrics()
        
        service_metrics = {
            "service": "reporting",
            "data_collector": data_collector.get_stats() if data_collector else {},
            "report_generator": report_generator.get_stats() if report_generator else {},
            "report_scheduler": report_scheduler.get_stats() if report_scheduler else {}
        }
        
        return service_metrics
    
    @app.get("/")
    async def root():
        """Root endpoint with service information."""
        return {
            "service": "MCP Security Platform - Reporting Service",
            "version": "1.0.0",
            "description": "Comprehensive reporting and analytics platform",
            "endpoints": {
                "health": "/health",
                "metrics": "/metrics",
                "api": "/api/v1/reporting",
                "docs": "/docs"
            }
        }
    
    return app


def get_data_collector() -> DataCollector:
    """Get data collector instance."""
    if data_collector is None:
        raise RuntimeError("Data collector not initialized")
    return data_collector


def get_chart_generator() -> ChartGenerator:
    """Get chart generator instance."""
    if chart_generator is None:
        raise RuntimeError("Chart generator not initialized")
    return chart_generator


def get_report_generator() -> ReportGenerator:
    """Get report generator instance."""
    if report_generator is None:
        raise RuntimeError("Report generator not initialized")
    return report_generator


def get_report_scheduler() -> ReportScheduler:
    """Get report scheduler instance."""
    if report_scheduler is None:
        raise RuntimeError("Report scheduler not initialized")
    return report_scheduler


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
        port=8003,
        reload=True,
        log_level="info"
    )