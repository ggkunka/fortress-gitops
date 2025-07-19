"""
Risk Assessment Service - Main Application

This service provides comprehensive risk assessment capabilities
with LLM integration for enhanced security analysis.
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
from shared.database.connection import init_db

from .services.llm_client import LLMManager
from .services.risk_calculator import RiskCalculator
from .services.risk_assessment_engine import RiskAssessmentEngine
from .api.risk_assessment_api import router as risk_assessment_router

# Global instances
llm_manager = None
risk_calculator = None
risk_assessment_engine = None
event_bus = None

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global llm_manager, risk_calculator, risk_assessment_engine, event_bus
    
    try:
        # Initialize configuration
        settings = get_settings()
        
        # Setup observability
        setup_logging(service_name="risk-assessment")
        setup_metrics(service_name="risk-assessment")
        setup_tracing(service_name="risk-assessment")
        
        # Initialize database
        await init_db()
        
        # Initialize event bus
        event_bus = EventBus(
            redis_url=settings.redis_url,
            service_name="risk-assessment"
        )
        await event_bus.connect()
        
        # Initialize LLM manager
        llm_manager = LLMManager()
        
        # Initialize risk calculator
        risk_calculator = RiskCalculator()
        
        # Initialize risk assessment engine
        risk_assessment_engine = RiskAssessmentEngine(
            llm_manager=llm_manager,
            risk_calculator=risk_calculator,
            event_bus=event_bus
        )
        
        # Start risk assessment engine
        await risk_assessment_engine.start()
        
        logger.info("Risk assessment service started successfully")
        
        yield
        
    except Exception as e:
        logger.error(f"Failed to start risk assessment service: {e}")
        raise
    finally:
        # Cleanup
        if risk_assessment_engine:
            await risk_assessment_engine.stop()
        
        if event_bus:
            await event_bus.disconnect()
        
        logger.info("Risk assessment service stopped")


def create_app() -> FastAPI:
    """Create FastAPI application."""
    app = FastAPI(
        title="Risk Assessment Service",
        description="Comprehensive risk assessment with LLM integration",
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
        risk_assessment_router,
        prefix="/api/v1/risk-assessment",
        tags=["risk-assessment"]
    )
    
    @app.get("/health")
    async def health_check():
        """Health check endpoint."""
        return {
            "status": "healthy",
            "service": "risk-assessment",
            "version": "1.0.0"
        }
    
    @app.get("/metrics")
    async def get_service_metrics():
        """Get service metrics."""
        metrics = get_metrics()
        
        service_metrics = {
            "service": "risk-assessment",
            "llm_manager": llm_manager.get_client_stats() if llm_manager else {},
            "risk_calculator": risk_calculator.get_risk_metrics() if risk_calculator else {},
            "assessment_engine": risk_assessment_engine.get_stats() if risk_assessment_engine else {}
        }
        
        return service_metrics
    
    return app


def get_llm_manager() -> LLMManager:
    """Get LLM manager instance."""
    if llm_manager is None:
        raise RuntimeError("LLM manager not initialized")
    return llm_manager


def get_risk_calculator() -> RiskCalculator:
    """Get risk calculator instance."""
    if risk_calculator is None:
        raise RuntimeError("Risk calculator not initialized")
    return risk_calculator


def get_risk_assessment_engine() -> RiskAssessmentEngine:
    """Get risk assessment engine instance."""
    if risk_assessment_engine is None:
        raise RuntimeError("Risk assessment engine not initialized")
    return risk_assessment_engine


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
        port=8002,
        reload=True,
        log_level="info"
    )