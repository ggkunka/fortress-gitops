"""Health check endpoints for the ingestion service."""

from typing import Dict, Any
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import JSONResponse
import structlog

from ..services.event_bus import EventBusService
from ..services.validation import ValidationService
from ..services.metrics import MetricsService

router = APIRouter(prefix="/health", tags=["health"])
logger = structlog.get_logger()

# Service instances - these will be initialized in main.py
event_bus: EventBusService = None
validation_service: ValidationService = None
metrics_service: MetricsService = None


def get_event_bus() -> EventBusService:
    """Get event bus service instance."""
    if event_bus is None:
        raise HTTPException(status_code=500, detail="Event bus service not initialized")
    return event_bus


def get_validation_service() -> ValidationService:
    """Get validation service instance."""
    if validation_service is None:
        raise HTTPException(status_code=500, detail="Validation service not initialized")
    return validation_service


def get_metrics_service() -> MetricsService:
    """Get metrics service instance."""
    if metrics_service is None:
        raise HTTPException(status_code=500, detail="Metrics service not initialized")
    return metrics_service


@router.get("/")
async def health_check(
    eb_service: EventBusService = Depends(get_event_bus),
    val_service: ValidationService = Depends(get_validation_service),
    met_service: MetricsService = Depends(get_metrics_service),
):
    """Comprehensive health check for the ingestion service."""
    try:
        # Check all service components
        health_checks = {
            "event_bus": await eb_service.health_check(),
            "validation": await val_service.health_check(),
            "metrics": await met_service.health_check(),
        }
        
        # Determine overall health
        overall_status = "healthy"
        for service_name, check_result in health_checks.items():
            if check_result.get("status") != "healthy":
                overall_status = "degraded"
                break
        
        # Get metrics summary for health context
        metrics_summary = met_service.get_health_metrics()
        
        health_response = {
            "service": "ingestion",
            "status": overall_status,
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0",
            "components": health_checks,
            "metrics": metrics_summary,
        }
        
        status_code = 200 if overall_status == "healthy" else 503
        
        return JSONResponse(
            status_code=status_code,
            content=health_response
        )
    
    except Exception as e:
        logger.error("Health check failed", error=str(e))
        
        return JSONResponse(
            status_code=500,
            content={
                "service": "ingestion",
                "status": "unhealthy",
                "timestamp": datetime.utcnow().isoformat(),
                "error": str(e),
            }
        )


@router.get("/ready")
async def readiness_check(
    eb_service: EventBusService = Depends(get_event_bus),
    val_service: ValidationService = Depends(get_validation_service),
    met_service: MetricsService = Depends(get_metrics_service),
):
    """Kubernetes readiness probe."""
    try:
        # Check if critical services are ready
        if not eb_service.is_connected:
            return JSONResponse(
                status_code=503,
                content={
                    "ready": False,
                    "message": "Event bus not connected",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )
        
        # Test validation service
        validation_health = await val_service.health_check()
        if validation_health.get("status") != "healthy":
            return JSONResponse(
                status_code=503,
                content={
                    "ready": False,
                    "message": "Validation service not healthy",
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )
        
        return JSONResponse(
            status_code=200,
            content={
                "ready": True,
                "message": "Service is ready to accept requests",
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
    
    except Exception as e:
        logger.error("Readiness check failed", error=str(e))
        
        return JSONResponse(
            status_code=500,
            content={
                "ready": False,
                "message": f"Readiness check failed: {str(e)}",
                "timestamp": datetime.utcnow().isoformat(),
            }
        )


@router.get("/live")
async def liveness_check():
    """Kubernetes liveness probe."""
    try:
        # Simple liveness check - service is running
        return JSONResponse(
            status_code=200,
            content={
                "live": True,
                "message": "Service is alive",
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
    
    except Exception as e:
        logger.error("Liveness check failed", error=str(e))
        
        return JSONResponse(
            status_code=500,
            content={
                "live": False,
                "message": f"Liveness check failed: {str(e)}",
                "timestamp": datetime.utcnow().isoformat(),
            }
        )


@router.get("/startup")
async def startup_check(
    eb_service: EventBusService = Depends(get_event_bus),
    val_service: ValidationService = Depends(get_validation_service),
    met_service: MetricsService = Depends(get_metrics_service),
):
    """Kubernetes startup probe."""
    try:
        # Check if all services are initialized and started
        checks = {
            "event_bus_connected": eb_service.is_connected,
            "validation_service_ready": True,  # Always ready once instantiated
            "metrics_service_ready": True,     # Always ready once instantiated
        }
        
        if all(checks.values()):
            return JSONResponse(
                status_code=200,
                content={
                    "started": True,
                    "message": "Service startup complete",
                    "checks": checks,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )
        else:
            return JSONResponse(
                status_code=503,
                content={
                    "started": False,
                    "message": "Service startup incomplete",
                    "checks": checks,
                    "timestamp": datetime.utcnow().isoformat(),
                }
            )
    
    except Exception as e:
        logger.error("Startup check failed", error=str(e))
        
        return JSONResponse(
            status_code=500,
            content={
                "started": False,
                "message": f"Startup check failed: {str(e)}",
                "timestamp": datetime.utcnow().isoformat(),
            }
        )


@router.get("/services")
async def service_status(
    eb_service: EventBusService = Depends(get_event_bus),
    val_service: ValidationService = Depends(get_validation_service),
    met_service: MetricsService = Depends(get_metrics_service),
):
    """Get detailed status of all service components."""
    try:
        service_statuses = {
            "event_bus": await eb_service.health_check(),
            "validation": await val_service.health_check(),
            "metrics": await met_service.health_check(),
        }
        
        # Add additional service details
        service_statuses["event_bus"]["channels"] = await eb_service.get_all_channels()
        service_statuses["validation"]["schema_count"] = len(val_service.schema_mapping)
        
        return JSONResponse(
            status_code=200,
            content={
                "services": service_statuses,
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
    
    except Exception as e:
        logger.error("Service status check failed", error=str(e))
        
        return JSONResponse(
            status_code=500,
            content={
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )


@router.get("/dependencies")
async def dependency_check(
    eb_service: EventBusService = Depends(get_event_bus),
):
    """Check status of external dependencies."""
    try:
        dependencies = {
            "redis": {
                "connected": eb_service.is_connected,
                "url": eb_service.redis_url,
            }
        }
        
        # Get Redis-specific health info if connected
        if eb_service.is_connected:
            redis_health = await eb_service.health_check()
            dependencies["redis"].update({
                "ping": redis_health.get("redis_ping", False),
                "version": redis_health.get("redis_version"),
                "uptime": redis_health.get("redis_uptime"),
            })
        
        overall_status = "healthy" if all(
            dep.get("connected", False) for dep in dependencies.values()
        ) else "degraded"
        
        return JSONResponse(
            status_code=200,
            content={
                "status": overall_status,
                "dependencies": dependencies,
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
    
    except Exception as e:
        logger.error("Dependency check failed", error=str(e))
        
        return JSONResponse(
            status_code=500,
            content={
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )