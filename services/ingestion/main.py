"""Main application for the ingestion service."""

import asyncio
import signal
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, Any

from fastapi import FastAPI, Request, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
import structlog
import uvicorn

from shared.config import get_settings
from .api import ingestion_router, health_router, metrics_router
from .services.event_bus import EventBusService
from .services.validation import ValidationService
from .services.metrics import MetricsService
from .utils.logging import setup_logging, IngestionLogger, get_correlation_id
from .utils.error_handling import setup_error_handlers

# Get configuration
settings = get_settings()

# Setup logging
setup_logging(
    service_name="ingestion",
    log_level=settings.log_level,
    json_format=settings.environment != "development",
)

logger = structlog.get_logger()
ingestion_logger = IngestionLogger()

# Global service instances
event_bus_service: EventBusService = None
validation_service: ValidationService = None
metrics_service: MetricsService = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    startup_start = datetime.utcnow()
    
    # Initialize services
    global event_bus_service, validation_service, metrics_service
    
    try:
        # Initialize services
        logger.info("Starting ingestion service...")
        
        # Initialize metrics service
        metrics_service = MetricsService()
        app.state.metrics_service = metrics_service
        
        # Initialize validation service
        validation_service = ValidationService()
        app.state.validation_service = validation_service
        
        # Initialize event bus service
        event_bus_service = EventBusService()
        await event_bus_service.connect()
        app.state.event_bus_service = event_bus_service
        
        # Update module-level service instances for dependency injection
        import services.ingestion.api.ingestion as ingestion_api
        import services.ingestion.api.health as health_api
        import services.ingestion.api.metrics as metrics_api
        
        ingestion_api.event_bus = event_bus_service
        ingestion_api.validation_service = validation_service
        ingestion_api.metrics_service = metrics_service
        
        health_api.event_bus = event_bus_service
        health_api.validation_service = validation_service
        health_api.metrics_service = metrics_service
        
        metrics_api.metrics_service = metrics_service
        
        # Check service health
        component_health = {
            "event_bus": event_bus_service.is_connected,
            "validation": True,  # Always healthy once instantiated
            "metrics": True,     # Always healthy once instantiated
        }
        
        startup_time = (datetime.utcnow() - startup_start).total_seconds()
        
        ingestion_logger.log_service_startup(
            components=component_health,
            startup_time=startup_time,
        )
        
        logger.info(
            "Ingestion service started successfully",
            startup_time=startup_time,
            components=component_health,
        )
        
        yield
        
    except Exception as e:
        logger.error("Failed to start ingestion service", error=str(e))
        raise
    
    finally:
        # Shutdown services
        logger.info("Shutting down ingestion service...")
        
        uptime = (datetime.utcnow() - startup_start).total_seconds()
        
        if event_bus_service:
            await event_bus_service.disconnect()
        
        ingestion_logger.log_service_shutdown(uptime=uptime, graceful=True)
        
        logger.info("Ingestion service shutdown complete")


# Create FastAPI application
app = FastAPI(
    title="MCP Security Platform - Ingestion Service",
    description="Data ingestion service for SBOM, CVE, and runtime behavior data",
    version="1.0.0",
    lifespan=lifespan,
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(GZipMiddleware, minimum_size=1000)


@app.middleware("http")
async def add_correlation_id(request: Request, call_next):
    """Add correlation ID to requests."""
    correlation_id = request.headers.get("X-Correlation-ID", get_correlation_id())
    request.state.correlation_id = correlation_id
    
    response = await call_next(request)
    response.headers["X-Correlation-ID"] = correlation_id
    
    return response


@app.middleware("http")
async def add_request_id(request: Request, call_next):
    """Add unique request ID to requests."""
    request_id = get_correlation_id()
    request.state.request_id = request_id
    
    response = await call_next(request)
    response.headers["X-Request-ID"] = request_id
    
    return response


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log HTTP requests and responses."""
    start_time = datetime.utcnow()
    
    # Log request
    logger.info(
        "HTTP request received",
        method=request.method,
        url=str(request.url),
        client_ip=request.client.host,
        user_agent=request.headers.get("user-agent"),
        correlation_id=getattr(request.state, "correlation_id", None),
        request_id=getattr(request.state, "request_id", None),
    )
    
    # Process request
    response = await call_next(request)
    
    # Calculate response time
    response_time = (datetime.utcnow() - start_time).total_seconds()
    
    # Log response
    logger.info(
        "HTTP response sent",
        method=request.method,
        url=str(request.url),
        status_code=response.status_code,
        response_time=response_time,
        correlation_id=getattr(request.state, "correlation_id", None),
        request_id=getattr(request.state, "request_id", None),
    )
    
    return response


@app.middleware("http")
async def error_handling_middleware(request: Request, call_next):
    """Global error handling middleware."""
    try:
        response = await call_next(request)
        return response
    except Exception as e:
        logger.error(
            "Unhandled exception in request processing",
            error=str(e),
            method=request.method,
            url=str(request.url),
            correlation_id=getattr(request.state, "correlation_id", None),
            request_id=getattr(request.state, "request_id", None),
        )
        
        return JSONResponse(
            status_code=500,
            content={
                "error": "Internal server error",
                "message": "An unexpected error occurred",
                "correlation_id": getattr(request.state, "correlation_id", None),
                "request_id": getattr(request.state, "request_id", None),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )


# Setup error handlers
setup_error_handlers(app)

# Include routers
app.include_router(ingestion_router)
app.include_router(health_router)
app.include_router(metrics_router)


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "ingestion",
        "version": "1.0.0",
        "status": "healthy",
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/info")
async def service_info():
    """Service information endpoint."""
    return {
        "service": "ingestion",
        "version": "1.0.0",
        "description": "Data ingestion service for SBOM, CVE, and runtime behavior data",
        "supported_data_types": ["sbom", "cve", "runtime"],
        "endpoints": [
            "/api/v1/ingestion/sbom",
            "/api/v1/ingestion/cve",
            "/api/v1/ingestion/runtime",
            "/api/v1/ingestion/batch",
            "/health",
            "/metrics",
        ],
        "timestamp": datetime.utcnow().isoformat(),
    }


def handle_shutdown_signal(signum, frame):
    """Handle shutdown signals."""
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    sys.exit(0)


if __name__ == "__main__":
    # Register signal handlers
    signal.signal(signal.SIGTERM, handle_shutdown_signal)
    signal.signal(signal.SIGINT, handle_shutdown_signal)
    
    # Run the application
    uvicorn.run(
        "main:app",
        host=settings.host,
        port=settings.port,
        log_level=settings.log_level.lower(),
        reload=settings.environment == "development",
        workers=1,  # Use single worker for async app
    )