"""Metrics endpoints for the ingestion service."""

from typing import Dict, Any, Optional
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse, Response
from prometheus_client import generate_latest, CollectorRegistry, CONTENT_TYPE_LATEST
import structlog

from ..services.metrics import MetricsService

router = APIRouter(prefix="/metrics", tags=["metrics"])
logger = structlog.get_logger()

# Service instances - these will be initialized in main.py
metrics_service: MetricsService = None


def get_metrics_service() -> MetricsService:
    """Get metrics service instance."""
    if metrics_service is None:
        raise HTTPException(status_code=500, detail="Metrics service not initialized")
    return metrics_service


@router.get("/")
async def get_prometheus_metrics(
    met_service: MetricsService = Depends(get_metrics_service),
):
    """Get Prometheus metrics in standard format."""
    try:
        # Generate Prometheus metrics
        metrics_output = generate_latest(met_service.registry)
        
        return Response(
            content=metrics_output,
            media_type=CONTENT_TYPE_LATEST
        )
    
    except Exception as e:
        logger.error("Failed to generate Prometheus metrics", error=str(e))
        
        return Response(
            content=f"# Error generating metrics: {str(e)}\n",
            media_type=CONTENT_TYPE_LATEST,
            status_code=500
        )


@router.get("/summary")
async def get_metrics_summary(
    met_service: MetricsService = Depends(get_metrics_service),
):
    """Get comprehensive metrics summary."""
    try:
        summary = met_service.get_metrics_summary()
        
        return JSONResponse(
            status_code=200,
            content=summary
        )
    
    except Exception as e:
        logger.error("Failed to get metrics summary", error=str(e))
        
        return JSONResponse(
            status_code=500,
            content={
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )


@router.get("/health")
async def get_health_metrics(
    met_service: MetricsService = Depends(get_metrics_service),
):
    """Get health-related metrics."""
    try:
        health_metrics = met_service.get_health_metrics()
        
        return JSONResponse(
            status_code=200,
            content=health_metrics
        )
    
    except Exception as e:
        logger.error("Failed to get health metrics", error=str(e))
        
        return JSONResponse(
            status_code=500,
            content={
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )


@router.get("/data-type/{data_type}")
async def get_data_type_metrics(
    data_type: str,
    met_service: MetricsService = Depends(get_metrics_service),
):
    """Get metrics for a specific data type."""
    try:
        # Validate data type
        valid_types = ["sbom", "cve", "runtime"]
        if data_type not in valid_types:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid data type. Must be one of: {valid_types}"
            )
        
        metrics = met_service.get_data_type_metrics(data_type)
        
        return JSONResponse(
            status_code=200,
            content=metrics
        )
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Failed to get data type metrics", data_type=data_type, error=str(e))
        
        return JSONResponse(
            status_code=500,
            content={
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )


@router.get("/ingestion")
async def get_ingestion_metrics(
    data_type: Optional[str] = Query(None, description="Filter by data type"),
    met_service: MetricsService = Depends(get_metrics_service),
):
    """Get ingestion-specific metrics."""
    try:
        summary = met_service.get_metrics_summary()
        
        ingestion_metrics = {
            "timestamp": summary["timestamp"],
            "uptime_seconds": summary["uptime_seconds"],
            "total_requests": summary["ingestion_requests"],
            "validation_results": summary["validation_results"],
            "event_publications": summary["event_publications"],
            "error_counts": summary["error_counts"],
            "processing_times": summary["processing_times"],
            "data_sizes": summary["data_sizes"],
        }
        
        # Filter by data type if specified
        if data_type:
            filtered_metrics = {
                "data_type": data_type,
                "timestamp": ingestion_metrics["timestamp"],
                "uptime_seconds": ingestion_metrics["uptime_seconds"],
                "requests": {},
                "validations": {},
                "events": {},
                "processing_times": {},
                "data_sizes": {},
            }
            
            # Filter each metric category
            for key, value in ingestion_metrics["total_requests"].items():
                if key.startswith(f"{data_type}_"):
                    status = key.replace(f"{data_type}_", "")
                    filtered_metrics["requests"][status] = value
            
            for key, value in ingestion_metrics["validation_results"].items():
                if key.startswith(f"{data_type}_"):
                    result = key.replace(f"{data_type}_", "")
                    filtered_metrics["validations"][result] = value
            
            for key, value in ingestion_metrics["event_publications"].items():
                if key.startswith(f"{data_type}_"):
                    status = key.replace(f"{data_type}_", "")
                    filtered_metrics["events"][status] = value
            
            for key, value in ingestion_metrics["processing_times"].items():
                if key.startswith(data_type):
                    filtered_metrics["processing_times"][key] = value
            
            if data_type in ingestion_metrics["data_sizes"]:
                filtered_metrics["data_sizes"] = ingestion_metrics["data_sizes"][data_type]
            
            ingestion_metrics = filtered_metrics
        
        return JSONResponse(
            status_code=200,
            content=ingestion_metrics
        )
    
    except Exception as e:
        logger.error("Failed to get ingestion metrics", error=str(e))
        
        return JSONResponse(
            status_code=500,
            content={
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )


@router.get("/performance")
async def get_performance_metrics(
    met_service: MetricsService = Depends(get_metrics_service),
):
    """Get performance-related metrics."""
    try:
        summary = met_service.get_metrics_summary()
        
        performance_metrics = {
            "timestamp": summary["timestamp"],
            "uptime_seconds": summary["uptime_seconds"],
            "processing_times": summary["processing_times"],
            "data_sizes": summary["data_sizes"],
            "throughput": {},
            "error_rate": {},
        }
        
        # Calculate throughput (requests per second)
        uptime_seconds = summary["uptime_seconds"]
        if uptime_seconds > 0:
            for key, count in summary["ingestion_requests"].items():
                if key.endswith("_success"):
                    data_type = key.replace("_success", "")
                    performance_metrics["throughput"][data_type] = count / uptime_seconds
        
        # Calculate error rates
        for data_type in ["sbom", "cve", "runtime"]:
            success_count = summary["ingestion_requests"].get(f"{data_type}_success", 0)
            error_count = summary["ingestion_requests"].get(f"{data_type}_error", 0)
            failed_count = summary["ingestion_requests"].get(f"{data_type}_failed", 0)
            
            total_count = success_count + error_count + failed_count
            if total_count > 0:
                error_rate = (error_count + failed_count) / total_count
                performance_metrics["error_rate"][data_type] = error_rate
        
        return JSONResponse(
            status_code=200,
            content=performance_metrics
        )
    
    except Exception as e:
        logger.error("Failed to get performance metrics", error=str(e))
        
        return JSONResponse(
            status_code=500,
            content={
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )


@router.get("/errors")
async def get_error_metrics(
    met_service: MetricsService = Depends(get_metrics_service),
):
    """Get error-related metrics."""
    try:
        summary = met_service.get_metrics_summary()
        
        error_metrics = {
            "timestamp": summary["timestamp"],
            "uptime_seconds": summary["uptime_seconds"],
            "total_errors": summary["error_counts"],
            "validation_failures": {},
            "failed_requests": {},
        }
        
        # Extract validation failures
        for key, count in summary["validation_results"].items():
            if key.endswith("_invalid"):
                data_type = key.replace("_invalid", "")
                error_metrics["validation_failures"][data_type] = count
        
        # Extract failed requests
        for key, count in summary["ingestion_requests"].items():
            if key.endswith("_failed") or key.endswith("_error"):
                status = key.split("_")[-1]
                data_type = key.replace(f"_{status}", "")
                if data_type not in error_metrics["failed_requests"]:
                    error_metrics["failed_requests"][data_type] = {}
                error_metrics["failed_requests"][data_type][status] = count
        
        return JSONResponse(
            status_code=200,
            content=error_metrics
        )
    
    except Exception as e:
        logger.error("Failed to get error metrics", error=str(e))
        
        return JSONResponse(
            status_code=500,
            content={
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )


@router.post("/reset")
async def reset_metrics(
    met_service: MetricsService = Depends(get_metrics_service),
):
    """Reset all metrics (for testing/debugging)."""
    try:
        met_service.reset_metrics()
        
        return JSONResponse(
            status_code=200,
            content={
                "message": "Metrics reset successfully",
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
    
    except Exception as e:
        logger.error("Failed to reset metrics", error=str(e))
        
        return JSONResponse(
            status_code=500,
            content={
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )


@router.post("/cleanup")
async def cleanup_metrics(
    max_age_hours: int = Query(24, description="Maximum age of metrics data in hours"),
    met_service: MetricsService = Depends(get_metrics_service),
):
    """Clean up old metrics data."""
    try:
        met_service.cleanup_old_data(max_age_hours)
        
        return JSONResponse(
            status_code=200,
            content={
                "message": f"Metrics data older than {max_age_hours} hours cleaned up",
                "timestamp": datetime.utcnow().isoformat(),
            }
        )
    
    except Exception as e:
        logger.error("Failed to cleanup metrics", error=str(e))
        
        return JSONResponse(
            status_code=500,
            content={
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }
        )