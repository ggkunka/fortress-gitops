"""
Observability middleware for FastAPI applications.
"""

import time
import uuid
from typing import Callable, Dict, Any, Optional
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from opentelemetry import trace
from opentelemetry.trace import Status, StatusCode
from opentelemetry.semconv.trace import SpanAttributes

from .logging import set_correlation_id, set_request_id, set_user_id, get_logger
from .metrics import get_metrics
from .tracing import get_current_span, inject_trace_context


class ObservabilityMiddleware(BaseHTTPMiddleware):
    """
    Middleware to add observability to FastAPI applications.
    
    Provides:
    - Request/response logging with correlation IDs
    - Prometheus metrics collection
    - Distributed tracing
    - Performance monitoring
    """
    
    def __init__(self, app, service_name: str):
        super().__init__(app)
        self.service_name = service_name
        self.logger = get_logger(f"{service_name}.middleware")
        self.metrics = get_metrics()
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Generate correlation and request IDs
        correlation_id = self._get_or_generate_correlation_id(request)
        request_id = str(uuid.uuid4())
        
        # Set context
        set_correlation_id(correlation_id)
        set_request_id(request_id)
        
        # Extract user ID from request if available
        user_id = self._extract_user_id(request)
        if user_id:
            set_user_id(user_id)
        
        # Record start time
        start_time = time.time()
        
        # Get current span for tracing
        span = get_current_span()
        if span:
            self._add_span_attributes(span, request, correlation_id, request_id, user_id)
        
        # Get request size
        request_size = self._get_request_size(request)
        
        # Log request
        self.logger.info(
            "HTTP request started",
            method=request.method,
            url=str(request.url),
            user_agent=request.headers.get("user-agent"),
            client_ip=self._get_client_ip(request),
            request_size=request_size
        )
        
        try:
            # Process request
            response = await call_next(request)
            
            # Calculate duration
            duration = time.time() - start_time
            
            # Get response size
            response_size = self._get_response_size(response)
            
            # Record metrics
            if self.metrics:
                self._record_metrics(request, response, duration, request_size, response_size)
            
            # Update span
            if span:
                self._update_span_on_success(span, response, duration, response_size)
            
            # Add correlation headers to response
            response.headers["X-Correlation-ID"] = correlation_id
            response.headers["X-Request-ID"] = request_id
            
            # Log response
            self.logger.info(
                "HTTP request completed",
                method=request.method,
                url=str(request.url),
                status_code=response.status_code,
                duration_ms=duration * 1000,
                response_size=response_size
            )
            
            return response
            
        except Exception as e:
            # Calculate duration
            duration = time.time() - start_time
            
            # Record error metrics
            if self.metrics:
                self._record_error_metrics(request, duration)
            
            # Update span with error
            if span:
                self._update_span_on_error(span, e, duration)
            
            # Log error
            self.logger.error(
                "HTTP request failed",
                method=request.method,
                url=str(request.url),
                duration_ms=duration * 1000,
                error=str(e),
                error_type=type(e).__name__
            )
            
            raise
    
    def _get_or_generate_correlation_id(self, request: Request) -> str:
        """Get correlation ID from headers or generate new one."""
        correlation_id = (
            request.headers.get("X-Correlation-ID") or
            request.headers.get("x-correlation-id") or
            request.headers.get("correlation-id") or
            str(uuid.uuid4())
        )
        return correlation_id
    
    def _extract_user_id(self, request: Request) -> Optional[str]:
        """Extract user ID from request headers or JWT token."""
        # Try to get from custom header
        user_id = request.headers.get("X-User-ID")
        if user_id:
            return user_id
        
        # Try to extract from Authorization header (JWT)
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                import jwt
                token = auth_header.split(" ")[1]
                # Decode without verification for user ID extraction
                # In production, you'd verify the token properly
                payload = jwt.decode(token, options={"verify_signature": False})
                return payload.get("sub") or payload.get("user_id")
            except Exception:
                pass
        
        return None
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""
        # Check for forwarded headers
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        # Fallback to client
        return request.client.host if request.client else "unknown"
    
    def _get_request_size(self, request: Request) -> int:
        """Get request content length."""
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                return int(content_length)
            except ValueError:
                pass
        return 0
    
    def _get_response_size(self, response: Response) -> int:
        """Get response content length."""
        content_length = response.headers.get("content-length")
        if content_length:
            try:
                return int(content_length)
            except ValueError:
                pass
        
        # Try to estimate from body if available
        if hasattr(response, 'body') and response.body:
            return len(response.body)
        
        return 0
    
    def _add_span_attributes(self, span, request: Request, correlation_id: str, 
                           request_id: str, user_id: Optional[str]):
        """Add attributes to tracing span."""
        span.set_attribute(SpanAttributes.HTTP_METHOD, request.method)
        span.set_attribute(SpanAttributes.HTTP_URL, str(request.url))
        span.set_attribute(SpanAttributes.HTTP_SCHEME, request.url.scheme)
        span.set_attribute(SpanAttributes.HTTP_HOST, request.url.hostname or "unknown")
        span.set_attribute(SpanAttributes.HTTP_TARGET, request.url.path)
        span.set_attribute("http.correlation_id", correlation_id)
        span.set_attribute("http.request_id", request_id)
        
        if user_id:
            span.set_attribute(SpanAttributes.ENDUSER_ID, user_id)
        
        user_agent = request.headers.get("user-agent")
        if user_agent:
            span.set_attribute(SpanAttributes.HTTP_USER_AGENT, user_agent)
        
        client_ip = self._get_client_ip(request)
        span.set_attribute("http.client_ip", client_ip)
    
    def _update_span_on_success(self, span, response: Response, duration: float, response_size: int):
        """Update span on successful response."""
        span.set_attribute(SpanAttributes.HTTP_STATUS_CODE, response.status_code)
        span.set_attribute("http.response.duration", duration)
        
        if response_size > 0:
            span.set_attribute(SpanAttributes.HTTP_RESPONSE_CONTENT_LENGTH, response_size)
        
        # Set span status
        if 200 <= response.status_code < 400:
            span.set_status(Status(StatusCode.OK))
        else:
            span.set_status(Status(StatusCode.ERROR, f"HTTP {response.status_code}"))
    
    def _update_span_on_error(self, span, error: Exception, duration: float):
        """Update span on error."""
        span.set_attribute("http.response.duration", duration)
        span.record_exception(error)
        span.set_status(Status(StatusCode.ERROR, str(error)))
    
    def _record_metrics(self, request: Request, response: Response, duration: float,
                       request_size: int, response_size: int):
        """Record Prometheus metrics."""
        endpoint = self._get_endpoint_pattern(request)
        
        self.metrics.record_http_request(
            method=request.method,
            endpoint=endpoint,
            status_code=response.status_code,
            duration=duration,
            request_size=request_size,
            response_size=response_size
        )
    
    def _record_error_metrics(self, request: Request, duration: float):
        """Record error metrics."""
        endpoint = self._get_endpoint_pattern(request)
        
        self.metrics.record_http_request(
            method=request.method,
            endpoint=endpoint,
            status_code=500,  # Default to 500 for exceptions
            duration=duration
        )
    
    def _get_endpoint_pattern(self, request: Request) -> str:
        """Get endpoint pattern for metrics (remove IDs, etc.)."""
        path = request.url.path
        
        # Simple pattern matching to remove IDs
        import re
        
        # Replace UUIDs
        path = re.sub(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '/{id}', path)
        
        # Replace numeric IDs
        path = re.sub(r'/\d+', '/{id}', path)
        
        # Replace other common patterns
        path = re.sub(r'/[a-zA-Z0-9_-]{20,}', '/{token}', path)
        
        return path


class SecurityMiddleware(BaseHTTPMiddleware):
    """Security-focused middleware."""
    
    def __init__(self, app, service_name: str):
        super().__init__(app)
        self.service_name = service_name
        self.logger = get_logger(f"{service_name}.security")
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        # Security logging
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get("user-agent", "unknown")
        
        # Check for suspicious patterns
        suspicious_patterns = [
            "sql", "union", "select", "drop", "insert", "update", "delete",
            "<script", "javascript:", "onload=", "onerror=",
            "../", "..\\", "/etc/passwd", "/proc/", "cmd.exe"
        ]
        
        url_lower = str(request.url).lower()
        body_content = ""
        
        # Read body for inspection (be careful with large bodies)
        if request.headers.get("content-type", "").startswith("application/json"):
            try:
                body = await request.body()
                if len(body) < 10000:  # Only check small bodies
                    body_content = body.decode('utf-8', errors='ignore').lower()
            except Exception:
                pass
        
        # Check for suspicious patterns
        for pattern in suspicious_patterns:
            if pattern in url_lower or pattern in body_content:
                self.logger.security(
                    f"Suspicious request pattern detected: {pattern}",
                    client_ip=client_ip,
                    user_agent=user_agent,
                    url=str(request.url),
                    pattern=pattern
                )
                break
        
        # Log all authentication attempts
        if "/auth/" in request.url.path:
            self.logger.audit(
                "Authentication endpoint accessed",
                client_ip=client_ip,
                user_agent=user_agent,
                endpoint=request.url.path,
                method=request.method
            )
        
        response = await call_next(request)
        
        # Security headers are now handled by SecurityHeadersMiddleware
        # This basic implementation is kept for backward compatibility
        
        return response
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"


class RateLimitingMiddleware(BaseHTTPMiddleware):
    """Rate limiting middleware."""
    
    def __init__(self, app, service_name: str, redis_client=None):
        super().__init__(app)
        self.service_name = service_name
        self.redis_client = redis_client
        self.logger = get_logger(f"{service_name}.ratelimit")
        
        # Default rate limits
        self.default_limits = {
            "per_ip": {"requests": 1000, "window": 3600},  # 1000/hour per IP
            "per_user": {"requests": 5000, "window": 3600},  # 5000/hour per user
            "auth_endpoints": {"requests": 10, "window": 600},  # 10/10min for auth
        }
    
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if not self.redis_client:
            # Rate limiting disabled without Redis
            return await call_next(request)
        
        client_ip = self._get_client_ip(request)
        user_id = self._extract_user_id(request)
        endpoint = request.url.path
        
        # Check rate limits
        rate_limit_exceeded = False
        
        try:
            # Check IP-based rate limit
            if await self._check_rate_limit(f"ip:{client_ip}", 
                                          self.default_limits["per_ip"]["requests"],
                                          self.default_limits["per_ip"]["window"]):
                rate_limit_exceeded = True
                limit_type = "ip"
            
            # Check user-based rate limit
            elif user_id and await self._check_rate_limit(f"user:{user_id}",
                                                        self.default_limits["per_user"]["requests"],
                                                        self.default_limits["per_user"]["window"]):
                rate_limit_exceeded = True
                limit_type = "user"
            
            # Check auth endpoint rate limit
            elif "/auth/" in endpoint and await self._check_rate_limit(f"auth:{client_ip}",
                                                                     self.default_limits["auth_endpoints"]["requests"],
                                                                     self.default_limits["auth_endpoints"]["window"]):
                rate_limit_exceeded = True
                limit_type = "auth"
            
            if rate_limit_exceeded:
                self.logger.security(
                    "Rate limit exceeded",
                    client_ip=client_ip,
                    user_id=user_id,
                    endpoint=endpoint,
                    limit_type=limit_type
                )
                
                from starlette.responses import JSONResponse
                return JSONResponse(
                    status_code=429,
                    content={"error": "Rate limit exceeded"},
                    headers={"Retry-After": "3600"}
                )
        
        except Exception as e:
            self.logger.error(f"Rate limiting error: {e}")
            # Continue without rate limiting on error
        
        return await call_next(request)
    
    async def _check_rate_limit(self, key: str, limit: int, window: int) -> bool:
        """Check if rate limit is exceeded."""
        try:
            current = await self.redis_client.get(key)
            
            if current is None:
                # First request
                await self.redis_client.setex(key, window, 1)
                return False
            
            current_count = int(current)
            
            if current_count >= limit:
                return True
            
            # Increment counter
            await self.redis_client.incr(key)
            return False
            
        except Exception:
            # Allow request on Redis error
            return False
    
    def _get_client_ip(self, request: Request) -> str:
        """Get client IP address from request."""
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()
        
        real_ip = request.headers.get("X-Real-IP")
        if real_ip:
            return real_ip
        
        return request.client.host if request.client else "unknown"
    
    def _extract_user_id(self, request: Request) -> Optional[str]:
        """Extract user ID from request."""
        user_id = request.headers.get("X-User-ID")
        if user_id:
            return user_id
        
        auth_header = request.headers.get("Authorization", "")
        if auth_header.startswith("Bearer "):
            try:
                import jwt
                token = auth_header.split(" ")[1]
                payload = jwt.decode(token, options={"verify_signature": False})
                return payload.get("sub") or payload.get("user_id")
            except Exception:
                pass
        
        return None