"""Main application for the API Gateway service."""

import asyncio
import signal
import sys
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.responses import JSONResponse
import redis.asyncio as redis
import structlog
import uvicorn

from .settings import get_settings

settings = get_settings()
logger = structlog.get_logger()

# Global instances
redis_client: redis.Redis = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global redis_client
    
    # Startup
    logger.info("Starting API Gateway service")
    
    # Initialize Redis client
    redis_client = redis.from_url(settings.redis_url)
    
    # Test Redis connection
    try:
        await redis_client.ping()
        logger.info("Redis connection established")
    except Exception as e:
        logger.error("Failed to connect to Redis", error=str(e))
        sys.exit(1)
    
    # Setup graceful shutdown
    def signal_handler(signum, frame):
        logger.info("Received shutdown signal")
        asyncio.create_task(shutdown())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("API Gateway service started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down API Gateway service")
    
    # Close connections
    if redis_client:
        await redis_client.close()
    
    logger.info("API Gateway service stopped")


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
    title="MCP Security Platform - API Gateway",
    description="API Gateway service for the MCP Security Assessment Platform",
    version="0.1.0",
    docs_url="/docs" if not settings.debug else None,
    redoc_url="/redoc" if not settings.debug else None,
    openapi_url="/openapi.json" if not settings.debug else None,
    lifespan=lifespan,
)


# Basic API endpoints


# Health check endpoint
@app.get("/health")
async def health_check():
    """Health check endpoint."""
    try:
        # Check Redis connection
        await redis_client.ping()
        
        # Check service health
        health_status = {
            "status": "healthy",
            "version": "0.1.0",
            "timestamp": int(asyncio.get_event_loop().time()),
            "services": {
                "redis": "healthy",
                "proxy": "healthy",
            },
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
    # This would return Prometheus metrics
    return Response(
        content="# Metrics would be here\n",
        media_type="text/plain",
    )


# Ready endpoint
@app.get("/ready")
async def ready():
    """Readiness probe endpoint."""
    try:
        # Check if all services are ready
        await redis_client.ping()
        
        return JSONResponse(
            status_code=status.HTTP_200_OK,
            content={"status": "ready"},
        )
    
    except Exception:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "not ready"},
        )


# Basic API endpoints for testing
@app.get("/dashboard/overview")
async def get_dashboard_overview():
    """Get security dashboard overview."""
    return {
        "securityScore": 87.3,
        "totalAssets": 1247,
        "criticalVulnerabilities": 23,
        "activeThreats": 5,
        "complianceScore": 94.2,
        "lastUpdated": "2024-09-21T00:00:00Z",
        "trends": {
            "securityScore": "+2.1%",
            "vulnerabilities": "-15%",
            "threats": "+1",
            "compliance": "+0.8%"
        }
    }

@app.get("/clusters")
async def get_clusters():
    """Get cluster information."""
    return [
        {
            "id": "fortress-prod",
            "name": "Fortress Production",
            "status": "healthy",
            "nodes": 12,
            "pods": 247,
            "services": 89,
            "version": "v1.28.2",
            "region": "us-east-1",
            "provider": "AWS",
            "lastScan": "2024-09-21T00:00:00Z",
            "securityScore": 92.1,
            "vulnerabilities": {"critical": 2, "high": 8, "medium": 15, "low": 23}
        }
    ]

@app.get("/pods")
async def get_pods():
    """Get pod information."""
    return [
        {
            "name": "auth-service-5875f8b854-75kjt",
            "namespace": "mcp-security",
            "status": "Running",
            "ready": "1/1",
            "restarts": 0,
            "age": "28h",
            "node": "fortress",
            "image": "mcp-security/auth-service:latest"
        }
    ]

@app.get("/vulnerabilities")
async def get_vulnerabilities():
    """Get vulnerability information."""
    return [
        {
            "id": "CVE-2024-1234",
            "severity": "Critical",
            "cvssScore": 9.8,
            "title": "Remote Code Execution in Container Runtime",
            "description": "A critical vulnerability allowing remote code execution through container escape.",
            "affectedImages": ["nginx:1.20", "redis:6.2"],
            "patchAvailable": True,
            "exploitAvailable": True,
            "publishedDate": "2024-01-15",
            "lastModified": "2024-01-20"
        }
    ]


# Error handlers
@app.exception_handler(404)
async def not_found_handler(request: Request, exc: HTTPException):
    """Handle 404 errors."""
    return JSONResponse(
        status_code=status.HTTP_404_NOT_FOUND,
        content={
            "error": "Not Found",
            "message": "The requested resource was not found",
            "path": request.url.path,
        },
    )


@app.exception_handler(500)
async def internal_error_handler(request: Request, exc: HTTPException):
    """Handle 500 errors."""
    logger.error("Internal server error", path=request.url.path, error=str(exc))
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "Internal Server Error",
            "message": "An unexpected error occurred",
        },
    )


@app.exception_handler(503)
async def service_unavailable_handler(request: Request, exc: HTTPException):
    """Handle 503 errors."""
    return JSONResponse(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        content={
            "error": "Service Unavailable",
            "message": "The service is temporarily unavailable",
        },
    )


def main():
    """Main entry point."""
    uvicorn.run(
        "services.gateway.main:app",
        host=settings.host,
        port=settings.port,
        workers=1,  # Gateway should run as single process
        log_level=settings.log_level.lower(),
        reload=settings.debug,
        access_log=True,
    )


if __name__ == "__main__":
    main()