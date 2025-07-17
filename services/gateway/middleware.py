"""Middleware for the API Gateway service."""

import time
import uuid
from typing import Callable, Dict, Optional, Tuple
from urllib.parse import urlparse

from fastapi import Request, Response, HTTPException, status
from fastapi.middleware.base import BaseHTTPMiddleware
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send
import structlog
import redis.asyncio as redis

from shared.config import get_settings
from .config import get_gateway_config

settings = get_settings()
gateway_config = get_gateway_config()
logger = structlog.get_logger()


class RequestIDMiddleware(BaseHTTPMiddleware):
    """Middleware to add request ID to headers."""
    
    def __init__(self, app: ASGIApp, header_name: str = "X-Request-ID"):
        super().__init__(app)
        self.header_name = header_name
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add request ID to request and response headers."""
        # Generate or extract request ID
        request_id = request.headers.get(self.header_name) or str(uuid.uuid4())
        
        # Add to request state
        request.state.request_id = request_id
        
        # Process request
        response = await call_next(request)
        
        # Add request ID to response headers
        response.headers[self.header_name] = request_id
        
        return response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Middleware to add security headers."""
    
    def __init__(self, app: ASGIApp, headers: Dict[str, str]):
        super().__init__(app)
        self.headers = headers
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Add security headers to response."""
        response = await call_next(request)
        
        # Add security headers
        for header, value in self.headers.items():
            response.headers[header] = value
        
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware for rate limiting."""
    
    def __init__(
        self,
        app: ASGIApp,
        redis_client: redis.Redis,
        requests: int = 100,
        window: int = 60,
        key_func: str = "ip",
    ):
        super().__init__(app)
        self.redis = redis_client
        self.requests = requests
        self.window = window
        self.key_func = key_func
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Apply rate limiting."""
        # Generate rate limit key
        key = await self._get_rate_limit_key(request)
        
        # Check rate limit
        current_requests = await self._get_current_requests(key)
        
        if current_requests >= self.requests:
            # Rate limit exceeded
            reset_time = await self._get_reset_time(key)
            
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "error": "Rate limit exceeded",
                    "message": f"Too many requests. Limit: {self.requests} per {self.window} seconds",
                    "retry_after": reset_time,
                },
                headers={
                    "X-RateLimit-Limit": str(self.requests),
                    "X-RateLimit-Remaining": "0",
                    "X-RateLimit-Reset": str(reset_time),
                    "Retry-After": str(reset_time),
                },
            )
        
        # Increment request count
        await self._increment_requests(key)
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers
        remaining = max(0, self.requests - current_requests - 1)
        reset_time = await self._get_reset_time(key)
        
        response.headers["X-RateLimit-Limit"] = str(self.requests)
        response.headers["X-RateLimit-Remaining"] = str(remaining)
        response.headers["X-RateLimit-Reset"] = str(reset_time)
        
        return response
    
    async def _get_rate_limit_key(self, request: Request) -> str:
        """Generate rate limit key."""
        if self.key_func == "ip":
            client_ip = request.client.host if request.client else "unknown"
            return f"rate_limit:ip:{client_ip}"
        elif self.key_func == "user":
            user_id = getattr(request.state, "user_id", None)
            if user_id:
                return f"rate_limit:user:{user_id}"
            else:
                client_ip = request.client.host if request.client else "unknown"
                return f"rate_limit:ip:{client_ip}"
        elif self.key_func == "api_key":
            api_key = request.headers.get("X-API-Key")
            if api_key:
                return f"rate_limit:api_key:{api_key}"
            else:
                client_ip = request.client.host if request.client else "unknown"
                return f"rate_limit:ip:{client_ip}"
        else:
            client_ip = request.client.host if request.client else "unknown"
            return f"rate_limit:ip:{client_ip}"
    
    async def _get_current_requests(self, key: str) -> int:
        """Get current request count."""
        try:
            value = await self.redis.get(key)
            return int(value) if value else 0
        except Exception:
            return 0
    
    async def _increment_requests(self, key: str) -> None:
        """Increment request count."""
        try:
            await self.redis.incr(key)
            await self.redis.expire(key, self.window)
        except Exception:
            pass
    
    async def _get_reset_time(self, key: str) -> int:
        """Get reset time for rate limit."""
        try:
            ttl = await self.redis.ttl(key)
            return max(0, ttl) if ttl > 0 else self.window
        except Exception:
            return self.window


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for request logging."""
    
    def __init__(self, app: ASGIApp, log_format: str = "combined"):
        super().__init__(app)
        self.log_format = log_format
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Log request and response."""
        start_time = time.time()
        
        # Extract request info
        method = request.method
        url = str(request.url)
        user_agent = request.headers.get("User-Agent", "")
        client_ip = request.client.host if request.client else "unknown"
        request_id = getattr(request.state, "request_id", "unknown")
        
        # Process request
        try:
            response = await call_next(request)
            status_code = response.status_code
            error = None
        except Exception as e:
            status_code = 500
            error = str(e)
            response = JSONResponse(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                content={"error": "Internal server error"},
            )
        
        # Calculate processing time
        processing_time = time.time() - start_time
        
        # Log request
        log_data = {
            "request_id": request_id,
            "method": method,
            "url": url,
            "status_code": status_code,
            "processing_time": processing_time,
            "client_ip": client_ip,
            "user_agent": user_agent,
        }
        
        if error:
            log_data["error"] = error
        
        if status_code >= 400:
            logger.warning("Request failed", **log_data)
        else:
            logger.info("Request processed", **log_data)
        
        # Add processing time header
        response.headers["X-Processing-Time"] = str(processing_time)
        
        return response


class RequestSizeLimitMiddleware(BaseHTTPMiddleware):
    """Middleware to limit request size."""
    
    def __init__(self, app: ASGIApp, max_size: int = 10_000_000):
        super().__init__(app)
        self.max_size = max_size
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Check request size limit."""
        content_length = request.headers.get("content-length")
        
        if content_length and int(content_length) > self.max_size:
            return JSONResponse(
                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                content={
                    "error": "Request entity too large",
                    "message": f"Request size exceeds maximum allowed size of {self.max_size} bytes",
                },
            )
        
        return await call_next(request)


class CircuitBreakerMiddleware(BaseHTTPMiddleware):
    """Middleware for circuit breaker pattern."""
    
    def __init__(
        self,
        app: ASGIApp,
        redis_client: redis.Redis,
        threshold: int = 5,
        timeout: int = 60,
        recovery_timeout: int = 30,
    ):
        super().__init__(app)
        self.redis = redis_client
        self.threshold = threshold
        self.timeout = timeout
        self.recovery_timeout = recovery_timeout
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Apply circuit breaker pattern."""
        service_name = self._get_service_name(request)
        
        # Check circuit breaker state
        state = await self._get_circuit_state(service_name)
        
        if state == "open":
            # Circuit is open, reject request
            return JSONResponse(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                content={
                    "error": "Service unavailable",
                    "message": "Circuit breaker is open",
                },
            )
        elif state == "half_open":
            # Circuit is half-open, allow limited requests
            if not await self._allow_request(service_name):
                return JSONResponse(
                    status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                    content={
                        "error": "Service unavailable",
                        "message": "Circuit breaker is half-open",
                    },
                )
        
        # Process request
        try:
            response = await call_next(request)
            
            # Record success
            if response.status_code < 500:
                await self._record_success(service_name)
            else:
                await self._record_failure(service_name)
            
            return response
        except Exception as e:
            # Record failure
            await self._record_failure(service_name)
            raise e
    
    def _get_service_name(self, request: Request) -> str:
        """Extract service name from request."""
        # This would be implemented based on routing logic
        path = request.url.path
        if path.startswith("/api/v1/auth"):
            return "auth"
        elif path.startswith("/api/v1/scans"):
            return "scanner"
        elif path.startswith("/api/v1/analysis"):
            return "analyzer"
        elif path.startswith("/api/v1/reports"):
            return "reports"
        elif path.startswith("/api/v1/notifications"):
            return "notifications"
        else:
            return "unknown"
    
    async def _get_circuit_state(self, service_name: str) -> str:
        """Get circuit breaker state."""
        try:
            state = await self.redis.get(f"circuit_breaker:{service_name}:state")
            return state.decode() if state else "closed"
        except Exception:
            return "closed"
    
    async def _allow_request(self, service_name: str) -> bool:
        """Check if request is allowed in half-open state."""
        try:
            key = f"circuit_breaker:{service_name}:half_open_requests"
            count = await self.redis.incr(key)
            await self.redis.expire(key, self.recovery_timeout)
            return count <= 3  # Allow up to 3 requests in half-open state
        except Exception:
            return True
    
    async def _record_success(self, service_name: str) -> None:
        """Record successful request."""
        try:
            # Reset failure count
            await self.redis.delete(f"circuit_breaker:{service_name}:failures")
            
            # Close circuit if it was half-open
            state = await self._get_circuit_state(service_name)
            if state == "half_open":
                await self.redis.set(f"circuit_breaker:{service_name}:state", "closed")
        except Exception:
            pass
    
    async def _record_failure(self, service_name: str) -> None:
        """Record failed request."""
        try:
            key = f"circuit_breaker:{service_name}:failures"
            failures = await self.redis.incr(key)
            await self.redis.expire(key, self.timeout)
            
            # Open circuit if threshold is reached
            if failures >= self.threshold:
                await self.redis.set(f"circuit_breaker:{service_name}:state", "open")
                await self.redis.expire(f"circuit_breaker:{service_name}:state", self.timeout)
                
                # Schedule transition to half-open
                await self.redis.set(
                    f"circuit_breaker:{service_name}:half_open_time",
                    int(time.time()) + self.timeout
                )
        except Exception:
            pass


class HealthCheckMiddleware(BaseHTTPMiddleware):
    """Middleware for health check endpoints."""
    
    def __init__(self, app: ASGIApp, health_check_path: str = "/health"):
        super().__init__(app)
        self.health_check_path = health_check_path
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        """Handle health check requests."""
        if request.url.path == self.health_check_path:
            return JSONResponse(
                status_code=status.HTTP_200_OK,
                content={
                    "status": "healthy",
                    "timestamp": int(time.time()),
                    "version": "0.1.0",
                },
            )
        
        return await call_next(request)


def setup_middleware(app: ASGIApp, redis_client: redis.Redis) -> None:
    """Set up middleware for the gateway."""
    
    # Health check middleware (highest priority)
    app.add_middleware(
        HealthCheckMiddleware,
        health_check_path=gateway_config.health_check_path,
    )
    
    # Request size limit middleware
    app.add_middleware(
        RequestSizeLimitMiddleware,
        max_size=gateway_config.max_request_size,
    )
    
    # CORS middleware
    if gateway_config.security.cors_enabled:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=gateway_config.security.cors_origins,
            allow_credentials=True,
            allow_methods=gateway_config.security.cors_methods,
            allow_headers=gateway_config.security.cors_headers,
        )
    
    # Security headers middleware
    app.add_middleware(
        SecurityHeadersMiddleware,
        headers=gateway_config.security.security_headers,
    )
    
    # Request ID middleware
    if gateway_config.security.request_id_enabled:
        app.add_middleware(
            RequestIDMiddleware,
            header_name=gateway_config.security.request_id_header,
        )
    
    # Rate limiting middleware
    if gateway_config.rate_limit.enabled:
        app.add_middleware(
            RateLimitMiddleware,
            redis_client=redis_client,
            requests=gateway_config.rate_limit.requests,
            window=gateway_config.rate_limit.window,
            key_func=gateway_config.rate_limit.key_func,
        )
    
    # Circuit breaker middleware
    if gateway_config.circuit_breaker_enabled:
        app.add_middleware(
            CircuitBreakerMiddleware,
            redis_client=redis_client,
            threshold=gateway_config.circuit_breaker_threshold,
            timeout=gateway_config.circuit_breaker_timeout,
            recovery_timeout=gateway_config.circuit_breaker_recovery_timeout,
        )
    
    # Request logging middleware (lowest priority)
    if gateway_config.access_log_enabled:
        app.add_middleware(
            RequestLoggingMiddleware,
            log_format=gateway_config.access_log_format,
        )