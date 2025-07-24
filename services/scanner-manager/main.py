"""
Scanner Manager Service - Main Application

Orchestrates security scanning operations across multiple scanner plugins.
Manages scan scheduling, resource allocation, and result aggregation.
"""

import asyncio
import signal
import sys
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from fastapi import BackgroundTasks, Depends, FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import structlog
import uvicorn

from shared.config import get_settings
from shared.event_bus import EventBus, get_event_bus
from shared.observability import setup_logging, setup_metrics, setup_tracing

from .models.scan_models import (
    ScanRequest, ScanResponse, ScanStatus, ScanResult,
    ScheduledScan, ScanStatistics, PluginStatus
)
from .services.scan_orchestrator import ScanOrchestrator
from .services.plugin_manager import PluginManager
from .services.scheduler import ScanScheduler
from .services.resource_manager import ResourceManager

# Setup logging
setup_logging()
logger = structlog.get_logger(__name__)

# Configuration
settings = get_settings()

# Global services
scan_orchestrator: ScanOrchestrator = None
plugin_manager: PluginManager = None
scan_scheduler: ScanScheduler = None
resource_manager: ResourceManager = None
event_bus: EventBus = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global scan_orchestrator, plugin_manager, scan_scheduler, resource_manager, event_bus
    
    logger.info("Starting Scanner Manager Service")
    
    try:
        # Initialize event bus
        event_bus = get_event_bus()
        await event_bus.connect()
        logger.info("Event bus connected")
        
        # Initialize resource manager
        resource_manager = ResourceManager()
        await resource_manager.initialize()
        logger.info("Resource manager initialized")
        
        # Initialize plugin manager
        plugin_manager = PluginManager(event_bus=event_bus)
        await plugin_manager.initialize()
        await plugin_manager.discover_plugins()
        logger.info("Plugin manager initialized", plugin_count=len(plugin_manager.get_available_plugins()))
        
        # Initialize scan orchestrator
        scan_orchestrator = ScanOrchestrator(
            plugin_manager=plugin_manager,
            resource_manager=resource_manager,
            event_bus=event_bus
        )
        await scan_orchestrator.initialize()
        logger.info("Scan orchestrator initialized")
        
        # Initialize scheduler
        scan_scheduler = ScanScheduler(
            orchestrator=scan_orchestrator,
            event_bus=event_bus
        )
        await scan_scheduler.initialize()
        logger.info("Scan scheduler initialized")
        
        # Start background tasks
        scheduler_task = asyncio.create_task(scan_scheduler.start())
        
        # Setup graceful shutdown
        def signal_handler(signum, frame):
            logger.info("Received shutdown signal")
            scheduler_task.cancel()
            asyncio.create_task(shutdown())
        
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)
        
        logger.info("Scanner Manager Service started successfully")
        
        yield
        
    except Exception as e:
        logger.error("Failed to start Scanner Manager Service", error=str(e))
        raise
    finally:
        # Shutdown
        logger.info("Shutting down Scanner Manager Service")
        
        # Cancel background tasks
        if 'scheduler_task' in locals():
            scheduler_task.cancel()
        
        # Cleanup services
        if scan_scheduler:
            await scan_scheduler.stop()
        if scan_orchestrator:
            await scan_orchestrator.cleanup()
        if plugin_manager:
            await plugin_manager.cleanup()
        if resource_manager:
            await resource_manager.cleanup()
        if event_bus:
            await event_bus.disconnect()
        
        logger.info("Scanner Manager Service stopped")


async def shutdown():
    """Graceful shutdown."""
    logger.info("Performing graceful shutdown...")
    
    # Cancel all running tasks
    tasks = [t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
    for task in tasks:
        task.cancel()
    
    # Wait for tasks to complete
    await asyncio.gather(*tasks, return_exceptions=True)


# Create FastAPI app
app = FastAPI(
    title="MCP Security Platform - Scanner Manager",
    description="Orchestrates and manages security scanning operations",
    version="1.0.0",
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
    openapi_url="/openapi.json" if not settings.is_production else None,
    lifespan=lifespan,
)

# Setup observability
setup_metrics(app)
setup_tracing(app)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    try:
        # Check service health
        health_status = {
            "status": "healthy",
            "version": "1.0.0",
            "timestamp": datetime.utcnow().isoformat(),
            "services": {
                "plugin_manager": "healthy" if plugin_manager and plugin_manager.is_healthy() else "unhealthy",
                "scan_orchestrator": "healthy" if scan_orchestrator and scan_orchestrator.is_healthy() else "unhealthy",
                "scan_scheduler": "healthy" if scan_scheduler and scan_scheduler.is_healthy() else "unhealthy",
                "resource_manager": "healthy" if resource_manager and resource_manager.is_healthy() else "unhealthy",
                "event_bus": "healthy" if event_bus and event_bus.is_connected() else "unhealthy",
            },
            "plugins": {
                "available": len(plugin_manager.get_available_plugins()) if plugin_manager else 0,
                "active": len(plugin_manager.get_active_plugins()) if plugin_manager else 0,
                "failed": len(plugin_manager.get_failed_plugins()) if plugin_manager else 0,
            },
            "scans": {
                "running": len(scan_orchestrator.get_running_scans()) if scan_orchestrator else 0,
                "queued": len(scan_orchestrator.get_queued_scans()) if scan_orchestrator else 0,
            }
        }
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content=health_status,
        )
    
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={
                "status": "unhealthy",
                "error": str(e),
            },
        )


# Metrics endpoint
@app.get("/metrics")
async def metrics():
    """Metrics endpoint for Prometheus."""
    try:
        metrics_data = {
            "scans_total": scan_orchestrator.get_scan_count() if scan_orchestrator else 0,
            "scans_running": len(scan_orchestrator.get_running_scans()) if scan_orchestrator else 0,
            "scans_queued": len(scan_orchestrator.get_queued_scans()) if scan_orchestrator else 0,
            "plugins_available": len(plugin_manager.get_available_plugins()) if plugin_manager else 0,
            "plugins_active": len(plugin_manager.get_active_plugins()) if plugin_manager else 0,
            "resource_usage": resource_manager.get_usage_stats() if resource_manager else {},
        }
        
        return JSONResponse(content=metrics_data)
    
    except Exception as e:
        logger.error("Metrics collection failed", error=str(e))
        return JSONResponse(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            content={"error": f"Metrics collection failed: {str(e)}"}
        )


# Scanner Management Endpoints

@app.post("/api/v1/scans", response_model=ScanResponse)
async def create_scan(
    request: ScanRequest,
    background_tasks: BackgroundTasks
):
    """Create a new security scan."""
    try:
        if not scan_orchestrator:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Scanner service not available"
            )
        
        # Validate request
        if not request.target:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Target is required"
            )
        
        # Create scan
        scan_id = await scan_orchestrator.create_scan(request)
        
        logger.info("Scan created", scan_id=scan_id, target=request.target, scanners=request.scanners)
        
        # Start scan in background
        background_tasks.add_task(scan_orchestrator.execute_scan, scan_id)
        
        return ScanResponse(
            scan_id=scan_id,
            status=ScanStatus.QUEUED,
            message="Scan created and queued for execution",
            created_at=datetime.utcnow()
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to create scan", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create scan: {str(e)}"
        )


@app.get("/api/v1/scans/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str):
    """Get scan status and results."""
    try:
        if not scan_orchestrator:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Scanner service not available"
            )
        
        scan_result = await scan_orchestrator.get_scan_result(scan_id)
        
        if not scan_result:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan {scan_id} not found"
            )
        
        return scan_result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get scan", scan_id=scan_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get scan: {str(e)}"
        )


@app.get("/api/v1/scans", response_model=List[ScanResult])
async def list_scans(
    status_filter: Optional[ScanStatus] = None,
    limit: int = 50,
    offset: int = 0
):
    """List scans with optional filtering."""
    try:
        if not scan_orchestrator:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Scanner service not available"
            )
        
        scans = await scan_orchestrator.list_scans(
            status_filter=status_filter,
            limit=limit,
            offset=offset
        )
        
        return scans
        
    except Exception as e:
        logger.error("Failed to list scans", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list scans: {str(e)}"
        )


@app.delete("/api/v1/scans/{scan_id}")
async def cancel_scan(scan_id: str):
    """Cancel a running scan."""
    try:
        if not scan_orchestrator:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Scanner service not available"
            )
        
        success = await scan_orchestrator.cancel_scan(scan_id)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Scan {scan_id} not found or cannot be cancelled"
            )
        
        logger.info("Scan cancelled", scan_id=scan_id)
        
        return {"message": f"Scan {scan_id} cancelled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to cancel scan", scan_id=scan_id, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to cancel scan: {str(e)}"
        )


# Plugin Management Endpoints

@app.get("/api/v1/plugins", response_model=List[PluginStatus])
async def list_plugins():
    """List available scanner plugins."""
    try:
        if not plugin_manager:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Plugin manager not available"
            )
        
        plugins = plugin_manager.get_plugin_statuses()
        return plugins
        
    except Exception as e:
        logger.error("Failed to list plugins", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list plugins: {str(e)}"
        )


@app.post("/api/v1/plugins/{plugin_name}/enable")
async def enable_plugin(plugin_name: str):
    """Enable a scanner plugin."""
    try:
        if not plugin_manager:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Plugin manager not available"
            )
        
        success = await plugin_manager.enable_plugin(plugin_name)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Plugin {plugin_name} not found"
            )
        
        logger.info("Plugin enabled", plugin_name=plugin_name)
        
        return {"message": f"Plugin {plugin_name} enabled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to enable plugin", plugin_name=plugin_name, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to enable plugin: {str(e)}"
        )


@app.post("/api/v1/plugins/{plugin_name}/disable")
async def disable_plugin(plugin_name: str):
    """Disable a scanner plugin."""
    try:
        if not plugin_manager:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Plugin manager not available"
            )
        
        success = await plugin_manager.disable_plugin(plugin_name)
        
        if not success:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"Plugin {plugin_name} not found"
            )
        
        logger.info("Plugin disabled", plugin_name=plugin_name)
        
        return {"message": f"Plugin {plugin_name} disabled successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to disable plugin", plugin_name=plugin_name, error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to disable plugin: {str(e)}"
        )


# Scheduling Endpoints

@app.post("/api/v1/schedules", response_model=ScheduledScan)
async def create_schedule(schedule_request: dict):
    """Create a scheduled scan."""
    try:
        if not scan_scheduler:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Scheduler service not available"
            )
        
        schedule = await scan_scheduler.create_schedule(schedule_request)
        
        logger.info("Schedule created", schedule_id=schedule.schedule_id)
        
        return schedule
        
    except Exception as e:
        logger.error("Failed to create schedule", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create schedule: {str(e)}"
        )


@app.get("/api/v1/statistics", response_model=ScanStatistics)
async def get_statistics():
    """Get scanning statistics."""
    try:
        if not scan_orchestrator:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Scanner service not available"
            )
        
        stats = await scan_orchestrator.get_statistics()
        return stats
        
    except Exception as e:
        logger.error("Failed to get statistics", error=str(e))
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to get statistics: {str(e)}"
        )


def main():
    """Main entry point."""
    uvicorn.run(
        "services.scanner_manager.main:app",
        host=settings.host,
        port=settings.port,
        workers=1,
        log_level=settings.log_level.lower(),
        reload=settings.debug,
        access_log=settings.access_log_enabled,
    )


if __name__ == "__main__":
    main()