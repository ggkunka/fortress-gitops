"""Main application for the analysis-service service."""

import asyncio
import signal
import sys
from contextlib import asynccontextmanager
from datetime import datetime
from typing import Dict, Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
import uvicorn
import structlog

from shared.config.settings import get_settings
from shared.database.connection import get_database_engine
from shared.events.event_bus import get_event_bus
from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import get_tracer

from .api.analysis_api import router as analysis_router
from .services.analysis_engine import AnalysisEngine

# Initialize components
settings = get_settings()
logger = get_logger(__name__)
metrics = get_metrics()
tracer = get_tracer(__name__)

# Global variables for services
analysis_engine: AnalysisEngine = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global analysis_engine
    
    try:
        logger.info("Starting analysis-service service")
        
        # Initialize database connection
        engine = get_database_engine()
        logger.info("Database connection established")
        
        # Initialize event bus
        event_bus = await get_event_bus()
        logger.info("Event bus connection established")
        
        # Initialize analysis engine
        analysis_engine = AnalysisEngine(event_bus)
        await analysis_engine.start()
        logger.info("Analysis engine started")
        
        # Set global analysis engine for dependency injection
        app.state.analysis_engine = analysis_engine
        
        logger.info("Analysis-service service started successfully")
        yield
        
    except Exception as e:
        logger.error("Failed to start analysis-service service", error=str(e))
        raise
    finally:
        logger.info("Shutting down analysis-service service")
        
        # Stop analysis engine
        if analysis_engine:
            await analysis_engine.stop()
            logger.info("Analysis engine stopped")

# Create FastAPI application
app = FastAPI(
    title="MCP Security Platform - Analysis Service",
    description="Security analysis and vulnerability assessment service",
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

# Include API routers
app.include_router(analysis_router)

@app.get("/")
async def root():
    """Root endpoint."""
    return {
        "service": "analysis-service",
        "version": "1.0.0", 
        "status": "running",
        "description": "Security analysis and vulnerability assessment service",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health")
async def health_check():
    """Health check endpoint."""
    try:
        # Check analysis engine status
        engine_status = "unknown"
        if hasattr(app.state, 'analysis_engine') and app.state.analysis_engine:
            engine_status = "running" if app.state.analysis_engine.is_running else "stopped"
        
        return {
            "status": "healthy",
            "service": "analysis-service",
            "version": "1.0.0",
            "components": {
                "analysis_engine": engine_status
            },
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Health check failed: {e}")
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            }
        )

@app.get("/health/live")
async def liveness_probe():
    """Kubernetes liveness probe."""
    return {"status": "alive"}

@app.get("/health/ready")
async def readiness_probe():
    """Kubernetes readiness probe."""
    try:
        # Check if analysis engine is ready
        if hasattr(app.state, 'analysis_engine') and app.state.analysis_engine:
            if app.state.analysis_engine.is_running:
                return {"status": "ready"}
        
        return JSONResponse(
            status_code=503,
            content={"status": "not ready"}
        )
    except Exception:
        return JSONResponse(
            status_code=503,
            content={"status": "not ready"}
        )

@app.get("/metrics")
async def get_metrics():
    """Prometheus metrics endpoint."""
    try:
        engine_stats = {}
        if hasattr(app.state, 'analysis_engine') and app.state.analysis_engine:
            engine_stats = app.state.analysis_engine.get_stats()
        
        return {
            "service": "analysis-service",
            "version": "1.0.0",
            "analysis_engine": engine_stats,
            "timestamp": datetime.utcnow().isoformat()
        }
    except Exception as e:
        logger.error(f"Failed to get metrics: {e}")
        return {
            "service": "analysis-service",
            "error": str(e),
            "timestamp": datetime.utcnow().isoformat()
        }

def main():
    """Main function to run the analysis-service service."""
    # Set up signal handlers
    def signal_handler(signum, frame):
        logger.info(f"Received signal {signum}, shutting down gracefully...")
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("Starting analysis-service service", port=8083)
    
    # Run the server
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8083,
        workers=1,
        log_level="info",
        reload=False,
        access_log=True,
    )

if __name__ == "__main__":
    main()
