"""
Correlation Engine Service - Main Entry Point

This service provides event correlation and pattern detection capabilities
for the MCP Security Platform.
"""

import asyncio
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

from shared.config import get_settings
from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.observability.middleware import ObservabilityMiddleware
from shared.security.headers import SecurityHeadersMiddleware
from shared.security.rate_limiting import RateLimitingMiddleware
from shared.event_bus import EventBus

from .models import correlation
from .services.correlation_engine import CorrelationEngine
from .services.rule_engine import RuleEngine
from .services.pattern_matcher import PatternMatcher
from .services.event_correlator import EventCorrelator
from .api import correlation_api, rules_api, health_api, metrics_api

# Initialize components
logger = get_logger(__name__)
metrics = get_metrics()
settings = get_settings()

# Global service instances
correlation_engine: CorrelationEngine = None
rule_engine: RuleEngine = None
pattern_matcher: PatternMatcher = None
event_correlator: EventCorrelator = None
event_bus: EventBus = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management."""
    global correlation_engine, rule_engine, pattern_matcher, event_correlator, event_bus
    
    logger.info("Starting Correlation Engine service...")
    
    try:
        # Initialize database connections
        await correlation.init_db()
        
        # Initialize event bus
        event_bus = EventBus(
            redis_url=settings.redis_url,
            service_name="correlation-engine"
        )
        await event_bus.connect()
        
        # Initialize core services
        pattern_matcher = PatternMatcher()
        rule_engine = RuleEngine()
        event_correlator = EventCorrelator(
            pattern_matcher=pattern_matcher,
            rule_engine=rule_engine
        )
        
        correlation_engine = CorrelationEngine(
            event_correlator=event_correlator,
            event_bus=event_bus
        )
        
        # Start correlation engine
        await correlation_engine.start()
        
        logger.info("Correlation Engine service started successfully")
        metrics.service_started.inc()
        
        yield
        
    except Exception as e:
        logger.error(f"Failed to start Correlation Engine service: {e}")
        metrics.service_errors.inc()
        raise
    finally:
        # Cleanup
        logger.info("Shutting down Correlation Engine service...")
        
        if correlation_engine:
            await correlation_engine.stop()
        
        if event_bus:
            await event_bus.disconnect()
        
        await correlation.close_db()
        
        logger.info("Correlation Engine service stopped")


# Create FastAPI application
app = FastAPI(
    title="MCP Correlation Engine",
    description="Event correlation and pattern detection service",
    version="1.0.0",
    lifespan=lifespan,
    docs_url="/docs" if settings.environment == "development" else None,
    redoc_url="/redoc" if settings.environment == "development" else None,
    openapi_url="/openapi.json" if settings.environment == "development" else None,
)

# Add middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RateLimitingMiddleware)
app.add_middleware(ObservabilityMiddleware)

# Include routers
app.include_router(
    health_api.router,
    prefix="/health",
    tags=["health"]
)

app.include_router(
    metrics_api.router,
    prefix="/metrics",
    tags=["metrics"]
)

app.include_router(
    correlation_api.router,
    prefix="/api/v1/correlation",
    tags=["correlation"]
)

app.include_router(
    rules_api.router,
    prefix="/api/v1/rules",
    tags=["rules"]
)


@app.get("/")
@traced("correlation_engine_root")
async def root():
    """Root endpoint."""
    return {
        "service": "MCP Correlation Engine",
        "version": "1.0.0",
        "status": "running",
        "features": [
            "Event correlation",
            "Pattern detection",
            "Rule management",
            "Real-time processing",
            "Temporal analysis"
        ]
    }


def get_correlation_engine() -> CorrelationEngine:
    """Get correlation engine instance."""
    if correlation_engine is None:
        raise HTTPException(
            status_code=503,
            detail="Correlation engine not initialized"
        )
    return correlation_engine


def get_rule_engine() -> RuleEngine:
    """Get rule engine instance."""
    if rule_engine is None:
        raise HTTPException(
            status_code=503,
            detail="Rule engine not initialized"
        )
    return rule_engine


def get_pattern_matcher() -> PatternMatcher:
    """Get pattern matcher instance."""
    if pattern_matcher is None:
        raise HTTPException(
            status_code=503,
            detail="Pattern matcher not initialized"
        )
    return pattern_matcher


def get_event_correlator() -> EventCorrelator:
    """Get event correlator instance."""
    if event_correlator is None:
        raise HTTPException(
            status_code=503,
            detail="Event correlator not initialized"
        )
    return event_correlator


if __name__ == "__main__":
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8003,
        reload=settings.environment == "development",
        log_level="info",
        access_log=True,
    )