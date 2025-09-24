"""
InfluxDB Service - Main Application

This service provides InfluxDB-based time-series metrics storage and analysis
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

from .services.metrics_repository import MetricsRepository
from .services.metrics_processor import MetricsProcessor
from .api.metrics_api import router as metrics_router
from .api import metrics_api

# Global instances
metrics_repository = None
metrics_processor = None
event_bus = None

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global metrics_repository, metrics_processor, event_bus
    
    try:
        # Initialize configuration
        settings = get_settings()
        
        # Setup observability
        setup_logging(service_name="influxdb-service")
        setup_metrics(service_name="influxdb-service")
        setup_tracing(service_name="influxdb-service")
        
        # Initialize event bus
        event_bus = EventBus(
            redis_url=settings.redis_url,
            service_name="influxdb-service"
        )
        await event_bus.connect()
        
        # Initialize metrics repository
        metrics_repository = MetricsRepository()
        await metrics_repository.initialize()
        
        # Initialize metrics processor
        metrics_processor = MetricsProcessor(metrics_repository, event_bus)
        await metrics_processor.start()
        
        # Set global instances for dependency injection
        metrics_api.metrics_repository = metrics_repository
        metrics_api.metrics_processor = metrics_processor
        
        # Subscribe to relevant events
        await event_bus.subscribe("security.threat.detected", _handle_threat_event)
        await event_bus.subscribe("security.vulnerability.found", _handle_vulnerability_event)
        await event_bus.subscribe("security.incident.created", _handle_incident_event)
        await event_bus.subscribe("system.performance.metric", _handle_performance_event)
        await event_bus.subscribe("compliance.check.completed", _handle_compliance_event)
        await event_bus.subscribe("network.traffic.analyzed", _handle_network_event)
        await event_bus.subscribe("audit.event.logged", _handle_audit_event)
        
        logger.info("InfluxDB service started successfully")
        
        yield
        
    except Exception as e:
        logger.error(f"Failed to start InfluxDB service: {e}")
        raise
    finally:
        # Cleanup
        if metrics_processor:
            await metrics_processor.stop()
        
        if metrics_repository:
            await metrics_repository.close()
        
        if event_bus:
            await event_bus.disconnect()
        
        logger.info("InfluxDB service stopped")


def create_app() -> FastAPI:
    """Create FastAPI application."""
    settings = get_settings()
    
    app = FastAPI(
        title="InfluxDB Service",
        description="Time-series metrics storage and analysis for security data",
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
        metrics_router,
        prefix="/api/v1/metrics",
        tags=["metrics"]
    )
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "service": "influxdb-service",
            "version": "1.0.0"
        }
    
    @app.get("/metrics")
    async def get_service_metrics():
        """Get service metrics."""
        metrics = get_metrics()
        
        service_metrics = {
            "service": "influxdb-service",
            "repository": metrics_repository.get_stats() if metrics_repository else {},
            "processor": metrics_processor.get_stats() if metrics_processor else {}
        }
        
        return service_metrics
    
    @app.get("/")
    async def root():
        """Root endpoint with service information."""
        return {
            "service": "MCP Security Platform - InfluxDB Service",
            "version": "1.0.0",
            "description": "Time-series metrics storage and analysis for security data",
            "endpoints": {
                "health": "/health",
                "metrics": "/metrics",
                "api": "/api/v1/metrics",
                "docs": "/docs"
            }
        }
    
    return app


def get_metrics_repository() -> MetricsRepository:
    """Get metrics repository instance."""
    if metrics_repository is None:
        raise RuntimeError("Metrics repository not initialized")
    return metrics_repository


def get_metrics_processor() -> MetricsProcessor:
    """Get metrics processor instance."""
    if metrics_processor is None:
        raise RuntimeError("Metrics processor not initialized")
    return metrics_processor


def get_event_bus() -> EventBus:
    """Get event bus instance."""
    if event_bus is None:
        raise RuntimeError("Event bus not initialized")
    return event_bus


# Event handlers
async def _handle_threat_event(event_data: Dict[str, Any]):
    """Handle threat detection events."""
    try:
        from .models.metrics import create_threat_metric, Severity
        
        metric = create_threat_metric(
            threat_type=event_data.get("threat_type", "unknown"),
            severity=Severity(event_data.get("severity", "medium")),
            confidence=event_data.get("confidence", 0.5),
            source=event_data.get("source", "event_bus"),
            source_ip=event_data.get("source_ip"),
            destination_ip=event_data.get("destination_ip"),
            attack_vector=event_data.get("attack_vector"),
            mitre_technique=event_data.get("mitre_technique")
        )
        
        await metrics_processor.process_metric(metric)
        
    except Exception as e:
        logger.error(f"Error handling threat event: {e}")


async def _handle_vulnerability_event(event_data: Dict[str, Any]):
    """Handle vulnerability detection events."""
    try:
        from .models.metrics import create_vulnerability_metric, Severity
        
        metric = create_vulnerability_metric(
            component_name=event_data.get("component_name", "unknown"),
            severity=Severity(event_data.get("severity", "medium")),
            source=event_data.get("source", "event_bus"),
            cve_id=event_data.get("cve_id"),
            cvss_score=event_data.get("cvss_score"),
            component_version=event_data.get("component_version"),
            is_exploitable=event_data.get("is_exploitable", False),
            has_patch=event_data.get("has_patch", False)
        )
        
        await metrics_processor.process_metric(metric)
        
    except Exception as e:
        logger.error(f"Error handling vulnerability event: {e}")


async def _handle_incident_event(event_data: Dict[str, Any]):
    """Handle incident creation events."""
    try:
        from .models.metrics import create_incident_metric, Severity
        
        metric = create_incident_metric(
            incident_id=event_data.get("incident_id", "unknown"),
            incident_type=event_data.get("incident_type", "unknown"),
            severity=Severity(event_data.get("severity", "medium")),
            status=event_data.get("status", "open"),
            source=event_data.get("source", "event_bus"),
            assigned_to=event_data.get("assigned_to"),
            response_time=event_data.get("response_time"),
            affected_systems=event_data.get("affected_systems", [])
        )
        
        await metrics_processor.process_metric(metric)
        
    except Exception as e:
        logger.error(f"Error handling incident event: {e}")


async def _handle_performance_event(event_data: Dict[str, Any]):
    """Handle performance metric events."""
    try:
        from .models.metrics import create_performance_metric
        
        metric = create_performance_metric(
            source=event_data.get("source", "event_bus"),
            cpu_usage=event_data.get("cpu_usage"),
            memory_usage=event_data.get("memory_usage"),
            disk_usage=event_data.get("disk_usage"),
            network_in=event_data.get("network_in"),
            network_out=event_data.get("network_out"),
            response_time=event_data.get("response_time"),
            error_rate=event_data.get("error_rate")
        )
        
        await metrics_processor.process_metric(metric)
        
    except Exception as e:
        logger.error(f"Error handling performance event: {e}")


async def _handle_compliance_event(event_data: Dict[str, Any]):
    """Handle compliance check events."""
    try:
        from .models.metrics import create_compliance_metric
        
        metric = create_compliance_metric(
            framework=event_data.get("framework", "unknown"),
            control_id=event_data.get("control_id", "unknown"),
            compliance_score=event_data.get("compliance_score", 0.0),
            is_compliant=event_data.get("is_compliant", False),
            violations_count=event_data.get("violations_count", 0),
            source=event_data.get("source", "event_bus"),
            remediation_required=event_data.get("remediation_required", False)
        )
        
        await metrics_processor.process_metric(metric)
        
    except Exception as e:
        logger.error(f"Error handling compliance event: {e}")


async def _handle_network_event(event_data: Dict[str, Any]):
    """Handle network traffic events."""
    try:
        from .models.metrics import create_network_metric
        
        metric = create_network_metric(
            protocol=event_data.get("protocol", "unknown"),
            source_ip=event_data.get("source_ip", "0.0.0.0"),
            destination_ip=event_data.get("destination_ip", "0.0.0.0"),
            source_port=event_data.get("source_port", 0),
            destination_port=event_data.get("destination_port", 0),
            bytes_transferred=event_data.get("bytes_transferred", 0),
            packets_count=event_data.get("packets_count", 0),
            source=event_data.get("source", "event_bus"),
            is_blocked=event_data.get("is_blocked", False),
            is_suspicious=event_data.get("is_suspicious", False),
            threat_score=event_data.get("threat_score")
        )
        
        await metrics_processor.process_metric(metric)
        
    except Exception as e:
        logger.error(f"Error handling network event: {e}")


async def _handle_audit_event(event_data: Dict[str, Any]):
    """Handle audit log events."""
    try:
        from .models.metrics import create_audit_metric
        
        metric = create_audit_metric(
            event_type=event_data.get("event_type", "unknown"),
            user_id=event_data.get("user_id", "unknown"),
            resource=event_data.get("resource", "unknown"),
            action=event_data.get("action", "unknown"),
            success=event_data.get("success", True),
            source=event_data.get("source", "event_bus"),
            source_ip=event_data.get("source_ip"),
            user_agent=event_data.get("user_agent"),
            session_id=event_data.get("session_id")
        )
        
        await metrics_processor.process_metric(metric)
        
    except Exception as e:
        logger.error(f"Error handling audit event: {e}")


# Create application instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8011,
        reload=True,
        log_level="info"
    )