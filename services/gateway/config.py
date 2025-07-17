"""Configuration for the API Gateway service."""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from shared.config import get_settings

settings = get_settings()


class ServiceEndpoint(BaseModel):
    """Configuration for a service endpoint."""
    
    name: str
    url: str
    health_check_path: str = "/health"
    timeout: int = 30
    retries: int = 3
    circuit_breaker_enabled: bool = True
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout: int = 60


class RouteConfig(BaseModel):
    """Configuration for a route."""
    
    path: str
    service: str
    methods: List[str] = ["GET", "POST", "PUT", "DELETE", "PATCH"]
    auth_required: bool = True
    rate_limit: Optional[Dict[str, int]] = None
    timeout: int = 30
    strip_path: bool = True
    preserve_host: bool = False


class LoadBalancerConfig(BaseModel):
    """Configuration for load balancing."""
    
    algorithm: str = "round_robin"  # round_robin, least_connections, weighted_round_robin
    health_check_enabled: bool = True
    health_check_interval: int = 30
    health_check_timeout: int = 5
    max_fails: int = 3
    fail_timeout: int = 60


class RateLimitConfig(BaseModel):
    """Configuration for rate limiting."""
    
    enabled: bool = True
    requests: int = 100
    window: int = 60
    burst: int = 10
    key_func: str = "ip"  # ip, user, api_key
    storage: str = "redis"


class CacheConfig(BaseModel):
    """Configuration for response caching."""
    
    enabled: bool = True
    ttl: int = 300
    vary_headers: List[str] = ["Authorization", "Accept"]
    cache_control: bool = True
    etag_enabled: bool = True


class SecurityConfig(BaseModel):
    """Configuration for security features."""
    
    cors_enabled: bool = True
    cors_origins: List[str] = ["*"]
    cors_methods: List[str] = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"]
    cors_headers: List[str] = ["*"]
    
    csrf_enabled: bool = True
    csrf_cookie_name: str = "csrf_token"
    csrf_header_name: str = "X-CSRF-Token"
    
    request_id_enabled: bool = True
    request_id_header: str = "X-Request-ID"
    
    security_headers: Dict[str, str] = {
        "X-Content-Type-Options": "nosniff",
        "X-Frame-Options": "DENY",
        "X-XSS-Protection": "1; mode=block",
        "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
        "Referrer-Policy": "strict-origin-when-cross-origin",
    }


class GatewayConfig(BaseModel):
    """Main gateway configuration."""
    
    # Service endpoints
    services: Dict[str, ServiceEndpoint] = {
        "auth": ServiceEndpoint(
            name="auth",
            url="http://localhost:8001",
            health_check_path="/health",
        ),
        "scanner": ServiceEndpoint(
            name="scanner",
            url="http://localhost:8002",
            health_check_path="/health",
        ),
        "analyzer": ServiceEndpoint(
            name="analyzer",
            url="http://localhost:8003",
            health_check_path="/health",
        ),
        "reports": ServiceEndpoint(
            name="reports",
            url="http://localhost:8004",
            health_check_path="/health",
        ),
        "notifications": ServiceEndpoint(
            name="notifications",
            url="http://localhost:8005",
            health_check_path="/health",
        ),
    }
    
    # Route configurations
    routes: List[RouteConfig] = [
        # Authentication routes
        RouteConfig(
            path="/api/v1/auth/register",
            service="auth",
            methods=["POST"],
            auth_required=False,
            rate_limit={"requests": 10, "window": 60},
        ),
        RouteConfig(
            path="/api/v1/auth/login",
            service="auth",
            methods=["POST"],
            auth_required=False,
            rate_limit={"requests": 10, "window": 60},
        ),
        RouteConfig(
            path="/api/v1/auth/logout",
            service="auth",
            methods=["POST"],
            auth_required=True,
        ),
        RouteConfig(
            path="/api/v1/auth/refresh",
            service="auth",
            methods=["POST"],
            auth_required=False,
            rate_limit={"requests": 20, "window": 60},
        ),
        RouteConfig(
            path="/api/v1/auth/me",
            service="auth",
            methods=["GET"],
            auth_required=True,
        ),
        RouteConfig(
            path="/api/v1/auth/users",
            service="auth",
            methods=["GET", "POST"],
            auth_required=True,
        ),
        RouteConfig(
            path="/api/v1/auth/users/{user_id}",
            service="auth",
            methods=["GET", "PUT", "DELETE"],
            auth_required=True,
        ),
        RouteConfig(
            path="/api/v1/auth/roles",
            service="auth",
            methods=["GET", "POST"],
            auth_required=True,
        ),
        RouteConfig(
            path="/api/v1/auth/permissions",
            service="auth",
            methods=["GET", "POST"],
            auth_required=True,
        ),
        RouteConfig(
            path="/api/v1/auth/api-keys",
            service="auth",
            methods=["GET", "POST"],
            auth_required=True,
        ),
        
        # Scanner routes
        RouteConfig(
            path="/api/v1/scans",
            service="scanner",
            methods=["GET", "POST"],
            auth_required=True,
            rate_limit={"requests": 50, "window": 60},
        ),
        RouteConfig(
            path="/api/v1/scans/{scan_id}",
            service="scanner",
            methods=["GET", "PUT", "DELETE"],
            auth_required=True,
        ),
        RouteConfig(
            path="/api/v1/scans/{scan_id}/start",
            service="scanner",
            methods=["POST"],
            auth_required=True,
        ),
        RouteConfig(
            path="/api/v1/scans/{scan_id}/stop",
            service="scanner",
            methods=["POST"],
            auth_required=True,
        ),
        RouteConfig(
            path="/api/v1/scans/{scan_id}/results",
            service="scanner",
            methods=["GET"],
            auth_required=True,
        ),
        
        # Analyzer routes
        RouteConfig(
            path="/api/v1/analysis",
            service="analyzer",
            methods=["GET", "POST"],
            auth_required=True,
            rate_limit={"requests": 30, "window": 60},
        ),
        RouteConfig(
            path="/api/v1/analysis/{analysis_id}",
            service="analyzer",
            methods=["GET", "PUT", "DELETE"],
            auth_required=True,
        ),
        RouteConfig(
            path="/api/v1/analysis/{analysis_id}/results",
            service="analyzer",
            methods=["GET"],
            auth_required=True,
        ),
        RouteConfig(
            path="/api/v1/vulnerabilities",
            service="analyzer",
            methods=["GET"],
            auth_required=True,
        ),
        RouteConfig(
            path="/api/v1/vulnerabilities/{vuln_id}",
            service="analyzer",
            methods=["GET", "PUT"],
            auth_required=True,
        ),
        
        # Reports routes
        RouteConfig(
            path="/api/v1/reports",
            service="reports",
            methods=["GET", "POST"],
            auth_required=True,
            rate_limit={"requests": 20, "window": 60},
        ),
        RouteConfig(
            path="/api/v1/reports/{report_id}",
            service="reports",
            methods=["GET", "PUT", "DELETE"],
            auth_required=True,
        ),
        RouteConfig(
            path="/api/v1/reports/{report_id}/download",
            service="reports",
            methods=["GET"],
            auth_required=True,
        ),
        RouteConfig(
            path="/api/v1/reports/templates",
            service="reports",
            methods=["GET", "POST"],
            auth_required=True,
        ),
        
        # Notifications routes
        RouteConfig(
            path="/api/v1/notifications",
            service="notifications",
            methods=["GET", "POST"],
            auth_required=True,
        ),
        RouteConfig(
            path="/api/v1/notifications/{notification_id}",
            service="notifications",
            methods=["GET", "PUT", "DELETE"],
            auth_required=True,
        ),
        RouteConfig(
            path="/api/v1/notifications/channels",
            service="notifications",
            methods=["GET", "POST"],
            auth_required=True,
        ),
        RouteConfig(
            path="/api/v1/notifications/channels/{channel_id}",
            service="notifications",
            methods=["GET", "PUT", "DELETE"],
            auth_required=True,
        ),
    ]
    
    # Load balancer configuration
    load_balancer: LoadBalancerConfig = LoadBalancerConfig()
    
    # Rate limiting configuration
    rate_limit: RateLimitConfig = RateLimitConfig()
    
    # Cache configuration
    cache: CacheConfig = CacheConfig()
    
    # Security configuration
    security: SecurityConfig = SecurityConfig()
    
    # Gateway-specific settings
    max_request_size: int = 10_000_000  # 10MB
    request_timeout: int = 30
    response_timeout: int = 30
    keepalive_timeout: int = 5
    
    # Metrics and monitoring
    metrics_enabled: bool = True
    metrics_path: str = "/metrics"
    health_check_path: str = "/health"
    
    # Logging
    access_log_enabled: bool = True
    access_log_format: str = "combined"
    request_tracing_enabled: bool = True
    
    # Circuit breaker
    circuit_breaker_enabled: bool = True
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout: int = 60
    circuit_breaker_recovery_timeout: int = 30


def get_gateway_config() -> GatewayConfig:
    """Get gateway configuration."""
    return GatewayConfig()