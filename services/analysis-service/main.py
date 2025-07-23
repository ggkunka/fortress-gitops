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

# Initialize logger
logger = structlog.get_logger()

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    try:
        logger.info("Starting analysis-service service")
        yield
    except Exception as e:
        logger.error("Failed to start analysis-service service", error=str(e))
        raise
    finally:
        logger.info("Shutting down analysis-service service")

# Create FastAPI application
app = FastAPI(
    title="MCP Security Platform - Analysis-service Service",
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
    return {
        "status": "healthy",
        "service": "analysis-service",
        "version": "1.0.0",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health/live")
async def liveness_probe():
    """Kubernetes liveness probe."""
    return {"status": "alive"}

@app.get("/health/ready")
async def readiness_probe():
    """Kubernetes readiness probe."""
    return {"status": "ready"}

@app.get("/metrics")
async def metrics():
    """Prometheus metrics endpoint."""
    return {
        "service": "analysis-service",
        "uptime": 0,
        "requests_total": 0,
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
