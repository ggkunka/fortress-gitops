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

from shared.config import get_settings
from .config import get_gateway_config
from .middleware import setup_middleware
from .proxy import GatewayProxy

settings = get_settings()
gateway_config = get_gateway_config()
logger = structlog.get_logger()

# Global instances
redis_client: redis.Redis = None
gateway_proxy: GatewayProxy = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan manager."""
    global redis_client, gateway_proxy
    
    # Startup
    logger.info("Starting API Gateway service")
    
    # Initialize Redis client
    redis_client = redis.from_url(
        str(settings.redis_url),
        **settings.get_connection_config(),
    )
    
    # Test Redis connection
    try:
        await redis_client.ping()
        logger.info("Redis connection established")
    except Exception as e:
        logger.error("Failed to connect to Redis", error=str(e))
        sys.exit(1)
    
    # Initialize gateway proxy
    gateway_proxy = GatewayProxy(redis_client)
    
    # Start health checks
    health_check_task = asyncio.create_task(gateway_proxy.start_health_checks())
    
    # Setup graceful shutdown
    def signal_handler(signum, frame):
        logger.info("Received shutdown signal")
        health_check_task.cancel()
        asyncio.create_task(shutdown())
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    logger.info("API Gateway service started successfully")
    
    yield
    
    # Shutdown
    logger.info("Shutting down API Gateway service")
    
    # Cancel health check task
    health_check_task.cancel()
    
    # Close connections
    if gateway_proxy:
        await gateway_proxy.close()
    
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
    docs_url="/docs" if not settings.is_production else None,
    redoc_url="/redoc" if not settings.is_production else None,
    openapi_url="/openapi.json" if not settings.is_production else None,
    lifespan=lifespan,
)


# Setup middleware
@app.on_event("startup")
async def setup_app_middleware():
    """Setup middleware after Redis client is available."""
    if redis_client:
        setup_middleware(app, redis_client)


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


# Catch-all route for proxying
@app.api_route("/{path:path}", methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
async def proxy_handler(request: Request, path: str):
    """Handle all requests and proxy them to appropriate services."""
    try:
        if not gateway_proxy:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Gateway proxy not initialized",
            )
        
        return await gateway_proxy.proxy_request(request)
    
    except HTTPException:
        raise
    except Exception as e:
        logger.error("Proxy request failed", error=str(e), path=path)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal server error",
        )


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
        access_log=settings.access_log_enabled,
    )


if __name__ == "__main__":
    main()