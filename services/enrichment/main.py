"""Main application for the enrichment service."""

import asyncio
import signal
import sys
from contextlib import asynccontextmanager
from typing import Dict, Any

import structlog
import uvicorn
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from shared.config import get_settings
from shared.logging import setup_logging

from .services import (
    EnrichmentEngine, EventSubscriber, ThreatIntelligenceService,
    MitreAttackService, EnrichmentProcessor, CachingService
)
from .schemas.enrichment import (
    EnrichmentRequest, EnrichmentResponse, EnrichmentTask,
    EnrichmentStatus, DataType, EnrichmentType
)
from .api import health, metrics, enrichment

# Initialize settings and logging
settings = get_settings()
setup_logging(settings.log_level)
logger = structlog.get_logger()

# Global service instances
enrichment_engine: EnrichmentEngine = None
event_subscriber: EventSubscriber = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global enrichment_engine, event_subscriber
    
    try:
        logger.info("Starting enrichment service")
        
        # Initialize services
        enrichment_engine = EnrichmentEngine()
        event_subscriber = EventSubscriber(enrichment_engine)
        
        # Start services
        await enrichment_engine.start()
        await event_subscriber.start()
        
        logger.info("Enrichment service started successfully")
        
        yield
        
    except Exception as e:
        logger.error("Failed to start enrichment service", error=str(e))
        raise
    finally:
        try:
            logger.info("Stopping enrichment service")
            
            # Stop services
            if event_subscriber:
                await event_subscriber.stop()
            
            if enrichment_engine:
                await enrichment_engine.stop()
            
            logger.info("Enrichment service stopped successfully")
            
        except Exception as e:
            logger.error("Error stopping enrichment service", error=str(e))


# Create FastAPI application
app = FastAPI(
    title="MCP Security Platform - Enrichment Service",
    description="Data enrichment service with threat intelligence and MITRE ATT&CK mappings",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan
)

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Dependency to get enrichment engine
def get_enrichment_engine() -> EnrichmentEngine:
    """Get the enrichment engine instance."""
    if not enrichment_engine:
        raise HTTPException(status_code=503, detail="Enrichment engine not available")
    return enrichment_engine


def get_event_subscriber() -> EventSubscriber:
    """Get the event subscriber instance."""
    if not event_subscriber:
        raise HTTPException(status_code=503, detail="Event subscriber not available")
    return event_subscriber


# Include API routers
app.include_router(health.router, prefix="/health", tags=["Health"])
app.include_router(metrics.router, prefix="/metrics", tags=["Metrics"])
app.include_router(enrichment.router, prefix="/api/v1", tags=["Enrichment"])


@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "enrichment",
        "version": "1.0.0",
        "status": "running",
        "description": "MCP Security Platform - Enrichment Service"
    }


@app.post("/api/v1/enrich", response_model=Dict[str, Any])
async def enrich_data(
    request: EnrichmentRequest,
    background_tasks: BackgroundTasks,
    engine: EnrichmentEngine = Depends(get_enrichment_engine)
):
    """Submit data for enrichment."""
    try:
        logger.info(
            "Enrichment request received",
            request_id=request.request_id,
            data_type=request.data_type,
            enrichment_types=request.enrichment_types
        )
        
        # Submit for enrichment
        task_id = await engine.enrich_data(request)
        
        return {
            "message": "Enrichment request submitted successfully",
            "task_id": task_id,
            "request_id": request.request_id,
            "status": "submitted"
        }
        
    except Exception as e:
        logger.error(
            "Error processing enrichment request",
            request_id=request.request_id,
            error=str(e)
        )
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/enrich/{task_id}/status")
async def get_enrichment_status(
    task_id: str,
    engine: EnrichmentEngine = Depends(get_enrichment_engine)
):
    """Get the status of an enrichment task."""
    try:
        task = await engine.get_enrichment_status(task_id)
        
        if not task:
            raise HTTPException(status_code=404, detail="Task not found")
        
        return {
            "task_id": task.task_id,
            "request_id": task.request.request_id,
            "status": task.status.value,
            "created_at": task.created_at.isoformat(),
            "started_at": task.started_at.isoformat() if task.started_at else None,
            "completed_at": task.completed_at.isoformat() if task.completed_at else None,
            "assigned_worker": task.assigned_worker,
            "retry_count": task.retry_count,
            "error": task.error,
            "result": task.result.model_dump() if task.result else None,
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error getting enrichment status", task_id=task_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/api/v1/enrich/{task_id}/cancel")
async def cancel_enrichment(
    task_id: str,
    engine: EnrichmentEngine = Depends(get_enrichment_engine)
):
    """Cancel an enrichment task."""
    try:
        success = await engine.cancel_enrichment(task_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="Task not found or cannot be cancelled")
        
        return {
            "message": "Enrichment task cancelled successfully",
            "task_id": task_id,
            "status": "cancelled"
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Error cancelling enrichment", task_id=task_id, error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.get("/api/v1/stats")
async def get_service_stats(
    engine: EnrichmentEngine = Depends(get_enrichment_engine),
    subscriber: EventSubscriber = Depends(get_event_subscriber)
):
    """Get service statistics."""
    try:
        engine_stats = engine.get_stats()
        subscriber_stats = subscriber.get_stats()
        
        return {
            "service": "enrichment",
            "timestamp": engine_stats["timestamp"],
            "engine": engine_stats,
            "event_subscriber": subscriber_stats,
        }
        
    except Exception as e:
        logger.error("Error getting service stats", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler."""
    logger.error(
        "Unhandled exception",
        path=request.url.path,
        method=request.method,
        error=str(exc),
        exc_info=True
    )
    
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "message": "An unexpected error occurred",
            "path": request.url.path,
        }
    )


def signal_handler(signum, frame):
    """Handle shutdown signals."""
    logger.info(f"Received signal {signum}, shutting down gracefully...")
    sys.exit(0)


def main():
    """Main function to run the enrichment service."""
    # Set up signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Configure server
    host = getattr(settings, 'enrichment_host', '0.0.0.0')
    port = getattr(settings, 'enrichment_port', 8082)
    workers = getattr(settings, 'enrichment_workers', 1)
    log_level = getattr(settings, 'log_level', 'info').lower()
    
    logger.info(
        "Starting enrichment service",
        host=host,
        port=port,
        workers=workers,
        log_level=log_level
    )
    
    # Run the server
    uvicorn.run(
        "services.enrichment.main:app",
        host=host,
        port=port,
        workers=workers,
        log_level=log_level,
        reload=False,
        access_log=True,
    )


if __name__ == "__main__":
    main()