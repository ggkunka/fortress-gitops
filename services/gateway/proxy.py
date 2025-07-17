"""Proxy functionality for the API Gateway service."""

import asyncio
import time
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin, urlparse

import httpx
from fastapi import Request, Response, HTTPException, status
from fastapi.responses import StreamingResponse
import structlog
import redis.asyncio as redis

from .config import get_gateway_config, ServiceEndpoint, RouteConfig

gateway_config = get_gateway_config()
logger = structlog.get_logger()


class LoadBalancer:
    """Load balancer for service instances."""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.services: Dict[str, List[ServiceEndpoint]] = {}
        self.current_index: Dict[str, int] = {}
        self.health_status: Dict[str, Dict[str, bool]] = {}
    
    async def add_service(self, service_name: str, endpoint: ServiceEndpoint) -> None:
        """Add a service endpoint."""
        if service_name not in self.services:
            self.services[service_name] = []
            self.current_index[service_name] = 0
            self.health_status[service_name] = {}
        
        self.services[service_name].append(endpoint)
        self.health_status[service_name][endpoint.url] = True
    
    async def get_service_endpoint(self, service_name: str) -> Optional[ServiceEndpoint]:
        """Get a service endpoint using load balancing."""
        if service_name not in self.services:
            return None
        
        endpoints = self.services[service_name]
        healthy_endpoints = [
            ep for ep in endpoints
            if self.health_status[service_name].get(ep.url, True)
        ]
        
        if not healthy_endpoints:
            # No healthy endpoints, return the first one anyway
            return endpoints[0] if endpoints else None
        
        # Round-robin load balancing
        if gateway_config.load_balancer.algorithm == "round_robin":
            index = self.current_index[service_name] % len(healthy_endpoints)
            self.current_index[service_name] += 1
            return healthy_endpoints[index]
        
        # Least connections (simplified - just return first healthy)
        elif gateway_config.load_balancer.algorithm == "least_connections":
            return healthy_endpoints[0]
        
        # Default to round-robin
        else:
            index = self.current_index[service_name] % len(healthy_endpoints)
            self.current_index[service_name] += 1
            return healthy_endpoints[index]
    
    async def mark_unhealthy(self, service_name: str, endpoint_url: str) -> None:
        """Mark an endpoint as unhealthy."""
        if service_name in self.health_status:
            self.health_status[service_name][endpoint_url] = False
            
            # Store failure time in Redis
            await self.redis.set(
                f"health:{service_name}:{endpoint_url}:last_failure",
                int(time.time()),
                ex=gateway_config.load_balancer.fail_timeout,
            )
    
    async def mark_healthy(self, service_name: str, endpoint_url: str) -> None:
        """Mark an endpoint as healthy."""
        if service_name in self.health_status:
            self.health_status[service_name][endpoint_url] = True
            
            # Remove failure time from Redis
            await self.redis.delete(f"health:{service_name}:{endpoint_url}:last_failure")
    
    async def health_check(self) -> None:
        """Perform health checks on all service endpoints."""
        for service_name, endpoints in self.services.items():
            for endpoint in endpoints:
                try:
                    async with httpx.AsyncClient() as client:
                        response = await client.get(
                            urljoin(endpoint.url, endpoint.health_check_path),
                            timeout=gateway_config.load_balancer.health_check_timeout,
                        )
                        
                        if response.status_code == 200:
                            await self.mark_healthy(service_name, endpoint.url)
                        else:
                            await self.mark_unhealthy(service_name, endpoint.url)
                
                except Exception as e:
                    logger.warning(
                        "Health check failed",
                        service=service_name,
                        endpoint=endpoint.url,
                        error=str(e),
                    )
                    await self.mark_unhealthy(service_name, endpoint.url)


class ProxyClient:
    """HTTP client for proxying requests."""
    
    def __init__(self, load_balancer: LoadBalancer):
        self.load_balancer = load_balancer
        self.client = httpx.AsyncClient(
            timeout=httpx.Timeout(
                connect=5.0,
                read=30.0,
                write=30.0,
                pool=30.0,
            ),
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )
    
    async def proxy_request(
        self,
        service_name: str,
        request: Request,
        route_config: RouteConfig,
    ) -> Response:
        """Proxy a request to a service."""
        # Get service endpoint
        endpoint = await self.load_balancer.get_service_endpoint(service_name)
        if not endpoint:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"Service '{service_name}' not available",
            )
        
        # Build target URL
        target_url = self._build_target_url(endpoint, request, route_config)
        
        # Prepare headers
        headers = await self._prepare_headers(request, route_config)
        
        # Prepare request body
        body = await self._prepare_body(request)
        
        # Make the request with retries
        for attempt in range(endpoint.retries + 1):
            try:
                response = await self.client.request(
                    method=request.method,
                    url=target_url,
                    headers=headers,
                    content=body,
                    timeout=route_config.timeout,
                )
                
                # Mark endpoint as healthy on success
                await self.load_balancer.mark_healthy(service_name, endpoint.url)
                
                # Return response
                return await self._create_response(response, route_config)
            
            except Exception as e:
                logger.warning(
                    "Request failed",
                    service=service_name,
                    endpoint=endpoint.url,
                    attempt=attempt + 1,
                    error=str(e),
                )
                
                # Mark endpoint as unhealthy on failure
                await self.load_balancer.mark_unhealthy(service_name, endpoint.url)
                
                # Retry with exponential backoff
                if attempt < endpoint.retries:
                    await asyncio.sleep(2 ** attempt)
                    
                    # Try to get a different endpoint
                    new_endpoint = await self.load_balancer.get_service_endpoint(service_name)
                    if new_endpoint and new_endpoint.url != endpoint.url:
                        endpoint = new_endpoint
                        target_url = self._build_target_url(endpoint, request, route_config)
                else:
                    # All retries exhausted
                    raise HTTPException(
                        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                        detail=f"Service '{service_name}' is unavailable",
                    )
    
    def _build_target_url(
        self,
        endpoint: ServiceEndpoint,
        request: Request,
        route_config: RouteConfig,
    ) -> str:
        """Build target URL for the request."""
        path = request.url.path
        
        # Strip route prefix if configured
        if route_config.strip_path:
            # Remove the matched route prefix
            route_prefix = route_config.path.split('{')[0].rstrip('/')
            if path.startswith(route_prefix):
                path = path[len(route_prefix):]
        
        # Ensure path starts with /
        if not path.startswith('/'):
            path = '/' + path
        
        # Build full URL
        target_url = urljoin(endpoint.url, path)
        
        # Add query parameters
        if request.url.query:
            target_url += '?' + request.url.query
        
        return target_url
    
    async def _prepare_headers(self, request: Request, route_config: RouteConfig) -> Dict[str, str]:
        """Prepare headers for the proxied request."""
        headers = {}
        
        # Copy relevant headers
        for name, value in request.headers.items():
            name_lower = name.lower()
            
            # Skip headers that shouldn't be forwarded
            if name_lower in ['host', 'content-length', 'connection', 'upgrade']:
                continue
            
            headers[name] = value
        
        # Set Host header if preserve_host is disabled
        if not route_config.preserve_host:
            # This would be set based on the target service
            pass
        
        # Add forwarded headers
        if request.client:
            headers['X-Forwarded-For'] = request.client.host
        headers['X-Forwarded-Proto'] = request.url.scheme
        headers['X-Forwarded-Host'] = request.url.hostname or ''
        
        # Add request ID if available
        if hasattr(request.state, 'request_id'):
            headers['X-Request-ID'] = request.state.request_id
        
        return headers
    
    async def _prepare_body(self, request: Request) -> Optional[bytes]:
        """Prepare request body."""
        if request.method in ['GET', 'DELETE', 'HEAD']:
            return None
        
        try:
            return await request.body()
        except Exception:
            return None
    
    async def _create_response(self, upstream_response: httpx.Response, route_config: RouteConfig) -> Response:
        """Create FastAPI response from upstream response."""
        # Prepare headers
        headers = {}
        for name, value in upstream_response.headers.items():
            name_lower = name.lower()
            
            # Skip headers that shouldn't be forwarded
            if name_lower in ['content-length', 'connection', 'upgrade', 'transfer-encoding']:
                continue
            
            headers[name] = value
        
        # Handle streaming responses
        if upstream_response.headers.get('content-type', '').startswith('application/octet-stream'):
            return StreamingResponse(
                content=upstream_response.aiter_bytes(),
                status_code=upstream_response.status_code,
                headers=headers,
                media_type=upstream_response.headers.get('content-type'),
            )
        
        # Handle regular responses
        content = upstream_response.content
        
        return Response(
            content=content,
            status_code=upstream_response.status_code,
            headers=headers,
            media_type=upstream_response.headers.get('content-type'),
        )
    
    async def close(self) -> None:
        """Close the HTTP client."""
        await self.client.aclose()


class Router:
    """Request router for the API Gateway."""
    
    def __init__(self, routes: List[RouteConfig]):
        self.routes = routes
        self._build_route_tree()
    
    def _build_route_tree(self) -> None:
        """Build internal route tree for fast matching."""
        self.static_routes = {}
        self.dynamic_routes = []
        
        for route in self.routes:
            if '{' in route.path:
                # Dynamic route
                self.dynamic_routes.append(route)
            else:
                # Static route
                self.static_routes[route.path] = route
    
    def find_route(self, path: str, method: str) -> Optional[Tuple[RouteConfig, Dict[str, str]]]:
        """Find matching route for a request."""
        # Check static routes first
        if path in self.static_routes:
            route = self.static_routes[path]
            if method in route.methods:
                return route, {}
        
        # Check dynamic routes
        for route in self.dynamic_routes:
            if method in route.methods:
                path_params = self._match_dynamic_route(route.path, path)
                if path_params is not None:
                    return route, path_params
        
        return None
    
    def _match_dynamic_route(self, pattern: str, path: str) -> Optional[Dict[str, str]]:
        """Match dynamic route pattern against path."""
        pattern_parts = pattern.split('/')
        path_parts = path.split('/')
        
        if len(pattern_parts) != len(path_parts):
            return None
        
        params = {}
        for pattern_part, path_part in zip(pattern_parts, path_parts):
            if pattern_part.startswith('{') and pattern_part.endswith('}'):
                # Parameter part
                param_name = pattern_part[1:-1]
                params[param_name] = path_part
            elif pattern_part != path_part:
                # Static part doesn't match
                return None
        
        return params


class GatewayProxy:
    """Main proxy class for the API Gateway."""
    
    def __init__(self, redis_client: redis.Redis):
        self.redis = redis_client
        self.load_balancer = LoadBalancer(redis_client)
        self.proxy_client = ProxyClient(self.load_balancer)
        self.router = Router(gateway_config.routes)
        
        # Initialize services
        self._initialize_services()
    
    def _initialize_services(self) -> None:
        """Initialize service endpoints."""
        for service_name, endpoint in gateway_config.services.items():
            asyncio.create_task(self.load_balancer.add_service(service_name, endpoint))
    
    async def start_health_checks(self) -> None:
        """Start periodic health checks."""
        if gateway_config.load_balancer.health_check_enabled:
            while True:
                await self.load_balancer.health_check()
                await asyncio.sleep(gateway_config.load_balancer.health_check_interval)
    
    async def proxy_request(self, request: Request) -> Response:
        """Proxy a request to the appropriate service."""
        # Find matching route
        route_match = self.router.find_route(request.url.path, request.method)
        
        if not route_match:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Route not found",
            )
        
        route_config, path_params = route_match
        
        # Add path parameters to request state
        request.state.path_params = path_params
        
        # Check if authentication is required
        if route_config.auth_required:
            # This would be handled by authentication middleware
            pass
        
        # Apply route-specific rate limiting
        if route_config.rate_limit:
            # This would be handled by rate limiting middleware
            pass
        
        # Proxy the request
        return await self.proxy_client.proxy_request(
            service_name=route_config.service,
            request=request,
            route_config=route_config,
        )
    
    async def close(self) -> None:
        """Close the proxy."""
        await self.proxy_client.close()