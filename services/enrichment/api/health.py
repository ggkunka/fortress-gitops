"""Health check endpoints for the enrichment service."""

from typing import Dict, Any
from datetime import datetime

import structlog
from fastapi import APIRouter, HTTPException

from ..services import (
    EnrichmentEngine, ThreatIntelligenceService, MitreAttackService,
    EnrichmentProcessor, CachingService, EventSubscriber
)

logger = structlog.get_logger()
router = APIRouter()


@router.get("/")
async def health_check() -> Dict[str, Any]:
    """Basic health check endpoint."""
    return {
        "status": "healthy",
        "service": "enrichment",
        "timestamp": datetime.utcnow().isoformat(),
        "version": "1.0.0"
    }


@router.get("/live")
async def liveness_probe() -> Dict[str, Any]:
    """Kubernetes liveness probe endpoint."""
    return {
        "status": "alive",
        "timestamp": datetime.utcnow().isoformat()
    }


@router.get("/ready")
async def readiness_probe() -> Dict[str, Any]:
    """Kubernetes readiness probe endpoint."""
    try:
        # Check if core services are ready
        # Note: In a real implementation, you'd inject these dependencies
        # For now, we'll return a basic readiness check
        
        return {
            "status": "ready",
            "timestamp": datetime.utcnow().isoformat(),
            "checks": {
                "service": "ready"
            }
        }
        
    except Exception as e:
        logger.error("Readiness check failed", error=str(e))
        raise HTTPException(status_code=503, detail="Service not ready")


@router.get("/detailed")
async def detailed_health_check() -> Dict[str, Any]:
    """Detailed health check with component status."""
    try:
        health_status = {
            "status": "healthy",
            "service": "enrichment",
            "timestamp": datetime.utcnow().isoformat(),
            "version": "1.0.0",
            "components": {}
        }
        
        # Note: In a real implementation, you'd inject service dependencies
        # and call their health_check methods here
        
        # Mock component checks for now
        health_status["components"] = {
            "enrichment_engine": {"status": "healthy", "message": "Service running"},
            "threat_intelligence": {"status": "healthy", "message": "Service running"},
            "mitre_attack": {"status": "healthy", "message": "Service running"},
            "enrichment_processor": {"status": "healthy", "message": "Service running"},
            "caching": {"status": "healthy", "message": "Service running"},
            "event_subscriber": {"status": "healthy", "message": "Service running"},
        }
        
        # Determine overall status
        component_statuses = [comp["status"] for comp in health_status["components"].values()]
        if any(status != "healthy" for status in component_statuses):
            health_status["status"] = "degraded"
        
        return health_status
        
    except Exception as e:
        logger.error("Detailed health check failed", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))