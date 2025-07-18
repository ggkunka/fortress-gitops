"""
Security headers implementation for MCP Security Platform.
"""

from typing import Dict, List, Optional, Union
from dataclasses import dataclass, field
from enum import Enum
import re
from urllib.parse import urlparse

from ..observability.logging import get_logger


class CSPDirective(Enum):
    """Content Security Policy directives."""
    DEFAULT_SRC = "default-src"
    SCRIPT_SRC = "script-src"
    STYLE_SRC = "style-src"
    IMG_SRC = "img-src"
    CONNECT_SRC = "connect-src"
    FONT_SRC = "font-src"
    OBJECT_SRC = "object-src"
    MEDIA_SRC = "media-src"
    FRAME_SRC = "frame-src"
    WORKER_SRC = "worker-src"
    CHILD_SRC = "child-src"
    FORM_ACTION = "form-action"
    FRAME_ANCESTORS = "frame-ancestors"
    BASE_URI = "base-uri"
    MANIFEST_SRC = "manifest-src"


class ReferrerPolicy(Enum):
    """Referrer policy values."""
    NO_REFERRER = "no-referrer"
    NO_REFERRER_WHEN_DOWNGRADE = "no-referrer-when-downgrade"
    ORIGIN = "origin"
    ORIGIN_WHEN_CROSS_ORIGIN = "origin-when-cross-origin"
    SAME_ORIGIN = "same-origin"
    STRICT_ORIGIN = "strict-origin"
    STRICT_ORIGIN_WHEN_CROSS_ORIGIN = "strict-origin-when-cross-origin"
    UNSAFE_URL = "unsafe-url"


class SameSitePolicy(Enum):
    """SameSite cookie policy values."""
    STRICT = "Strict"
    LAX = "Lax"
    NONE = "None"


@dataclass
class SecurityHeadersConfig:
    """Configuration for security headers."""
    
    # Content Security Policy
    enable_csp: bool = True
    csp_directives: Dict[CSPDirective, List[str]] = field(default_factory=lambda: {
        CSPDirective.DEFAULT_SRC: ["'self'"],
        CSPDirective.SCRIPT_SRC: ["'self'", "'unsafe-inline'"],
        CSPDirective.STYLE_SRC: ["'self'", "'unsafe-inline'"],
        CSPDirective.IMG_SRC: ["'self'", "data:", "https:"],
        CSPDirective.CONNECT_SRC: ["'self'"],
        CSPDirective.FONT_SRC: ["'self'"],
        CSPDirective.OBJECT_SRC: ["'none'"],
        CSPDirective.FRAME_ANCESTORS: ["'none'"],
        CSPDirective.BASE_URI: ["'self'"],
        CSPDirective.FORM_ACTION: ["'self'"]
    })
    csp_report_only: bool = False
    csp_report_uri: Optional[str] = None
    
    # HSTS (HTTP Strict Transport Security)
    enable_hsts: bool = True
    hsts_max_age: int = 31536000  # 1 year
    hsts_include_subdomains: bool = True
    hsts_preload: bool = False
    
    # X-Frame-Options
    enable_x_frame_options: bool = True
    x_frame_options: str = "DENY"
    
    # X-Content-Type-Options
    enable_x_content_type_options: bool = True
    
    # X-XSS-Protection
    enable_x_xss_protection: bool = True
    x_xss_protection_mode: str = "1; mode=block"
    
    # Referrer Policy
    enable_referrer_policy: bool = True
    referrer_policy: ReferrerPolicy = ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN
    
    # Permissions Policy
    enable_permissions_policy: bool = True
    permissions_policy: Dict[str, List[str]] = field(default_factory=lambda: {
        "geolocation": [],
        "microphone": [],
        "camera": [],
        "payment": [],
        "usb": [],
        "magnetometer": [],
        "gyroscope": [],
        "accelerometer": []
    })
    
    # Cross-Origin Policies
    enable_cross_origin_embedder_policy: bool = True
    cross_origin_embedder_policy: str = "require-corp"
    
    enable_cross_origin_opener_policy: bool = True
    cross_origin_opener_policy: str = "same-origin"
    
    enable_cross_origin_resource_policy: bool = True
    cross_origin_resource_policy: str = "same-origin"
    
    # Server identification
    remove_server_header: bool = True
    custom_server_header: Optional[str] = None
    
    # Powered-by header
    remove_powered_by: bool = True
    
    # Additional custom headers
    custom_headers: Dict[str, str] = field(default_factory=dict)
    
    # Cookie security
    secure_cookies: bool = True
    httponly_cookies: bool = True
    samesite_cookies: SameSitePolicy = SameSitePolicy.LAX
    
    # API-specific settings
    api_cors_origins: List[str] = field(default_factory=list)
    api_cors_methods: List[str] = field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "OPTIONS"])
    api_cors_headers: List[str] = field(default_factory=lambda: ["Content-Type", "Authorization", "X-Requested-With"])
    api_cors_credentials: bool = False
    api_cors_max_age: int = 86400


class SecurityHeadersManager:
    """Manages security headers for HTTP responses."""
    
    def __init__(self, config: SecurityHeadersConfig = None):
        self.config = config or SecurityHeadersConfig()
        self.logger = get_logger("security_headers")
    
    def get_security_headers(self, request_path: str = None, is_api: bool = False) -> Dict[str, str]:
        """
        Generate security headers for a response.
        
        Args:
            request_path: The request path for context-specific headers
            is_api: Whether this is an API response
            
        Returns:
            Dictionary of security headers
        """
        headers = {}
        
        # Content Security Policy
        if self.config.enable_csp and not is_api:
            csp_header = self._build_csp_header()
            if csp_header:
                header_name = "Content-Security-Policy-Report-Only" if self.config.csp_report_only else "Content-Security-Policy"
                headers[header_name] = csp_header
        
        # HSTS
        if self.config.enable_hsts:
            hsts_value = f"max-age={self.config.hsts_max_age}"
            if self.config.hsts_include_subdomains:
                hsts_value += "; includeSubDomains"
            if self.config.hsts_preload:
                hsts_value += "; preload"
            headers["Strict-Transport-Security"] = hsts_value
        
        # X-Frame-Options
        if self.config.enable_x_frame_options:
            headers["X-Frame-Options"] = self.config.x_frame_options
        
        # X-Content-Type-Options
        if self.config.enable_x_content_type_options:
            headers["X-Content-Type-Options"] = "nosniff"
        
        # X-XSS-Protection
        if self.config.enable_x_xss_protection and not is_api:
            headers["X-XSS-Protection"] = self.config.x_xss_protection_mode
        
        # Referrer Policy
        if self.config.enable_referrer_policy:
            headers["Referrer-Policy"] = self.config.referrer_policy.value
        
        # Permissions Policy
        if self.config.enable_permissions_policy:
            permissions_header = self._build_permissions_policy_header()
            if permissions_header:
                headers["Permissions-Policy"] = permissions_header
        
        # Cross-Origin Policies
        if self.config.enable_cross_origin_embedder_policy:
            headers["Cross-Origin-Embedder-Policy"] = self.config.cross_origin_embedder_policy
        
        if self.config.enable_cross_origin_opener_policy:
            headers["Cross-Origin-Opener-Policy"] = self.config.cross_origin_opener_policy
        
        if self.config.enable_cross_origin_resource_policy:
            headers["Cross-Origin-Resource-Policy"] = self.config.cross_origin_resource_policy
        
        # Server header
        if self.config.remove_server_header:
            headers["Server"] = self.config.custom_server_header or ""
        
        # Custom headers
        headers.update(self.config.custom_headers)
        
        # API-specific CORS headers
        if is_api:
            cors_headers = self._build_cors_headers()
            headers.update(cors_headers)
        
        return headers
    
    def _build_csp_header(self) -> str:
        """Build Content Security Policy header value."""
        directives = []
        
        for directive, sources in self.config.csp_directives.items():
            if sources:
                directive_str = f"{directive.value} {' '.join(sources)}"
                directives.append(directive_str)
        
        # Add report-uri if configured
        if self.config.csp_report_uri:
            directives.append(f"report-uri {self.config.csp_report_uri}")
        
        return "; ".join(directives)
    
    def _build_permissions_policy_header(self) -> str:
        """Build Permissions Policy header value."""
        policies = []
        
        for feature, allowlist in self.config.permissions_policy.items():
            if allowlist:
                allowlist_str = " ".join(f'"{origin}"' for origin in allowlist)
                policies.append(f"{feature}=({allowlist_str})")
            else:
                policies.append(f"{feature}=()")
        
        return ", ".join(policies)
    
    def _build_cors_headers(self) -> Dict[str, str]:
        """Build CORS headers for API responses."""
        headers = {}
        
        if self.config.api_cors_origins:
            if "*" in self.config.api_cors_origins:
                headers["Access-Control-Allow-Origin"] = "*"
            else:
                # For multiple specific origins, this would need to be handled
                # in middleware based on the actual request origin
                headers["Access-Control-Allow-Origin"] = self.config.api_cors_origins[0]
        
        if self.config.api_cors_methods:
            headers["Access-Control-Allow-Methods"] = ", ".join(self.config.api_cors_methods)
        
        if self.config.api_cors_headers:
            headers["Access-Control-Allow-Headers"] = ", ".join(self.config.api_cors_headers)
        
        if self.config.api_cors_credentials:
            headers["Access-Control-Allow-Credentials"] = "true"
        
        headers["Access-Control-Max-Age"] = str(self.config.api_cors_max_age)
        
        return headers
    
    def validate_csp_source(self, source: str) -> bool:
        """Validate a CSP source value."""
        # Keywords
        keywords = ["'self'", "'unsafe-inline'", "'unsafe-eval'", "'none'", "'strict-dynamic'", "'unsafe-hashes'"]
        if source in keywords:
            return True
        
        # Schemes
        if source.endswith(":"):
            return source.lower() in ["data:", "blob:", "filesystem:", "https:", "http:", "ws:", "wss:"]
        
        # Hosts
        if source.startswith("*."):
            domain = source[2:]
            return self._is_valid_domain(domain)
        
        # URLs
        try:
            parsed = urlparse(source)
            return bool(parsed.netloc or parsed.scheme)
        except:
            return False
    
    def _is_valid_domain(self, domain: str) -> bool:
        """Validate domain name."""
        if not domain:
            return False
        
        # Basic domain validation
        domain_pattern = re.compile(
            r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$'
        )
        return bool(domain_pattern.match(domain))
    
    def add_csp_source(self, directive: CSPDirective, source: str):
        """Add a source to a CSP directive."""
        if self.validate_csp_source(source):
            if directive not in self.config.csp_directives:
                self.config.csp_directives[directive] = []
            
            if source not in self.config.csp_directives[directive]:
                self.config.csp_directives[directive].append(source)
                self.logger.info(f"Added CSP source {source} to {directive.value}")
        else:
            self.logger.warning(f"Invalid CSP source: {source}")
    
    def remove_csp_source(self, directive: CSPDirective, source: str):
        """Remove a source from a CSP directive."""
        if directive in self.config.csp_directives:
            if source in self.config.csp_directives[directive]:
                self.config.csp_directives[directive].remove(source)
                self.logger.info(f"Removed CSP source {source} from {directive.value}")
    
    def update_cors_origins(self, origins: List[str]):
        """Update CORS allowed origins."""
        self.config.api_cors_origins = origins
        self.logger.info(f"Updated CORS origins: {origins}")
    
    def get_cookie_attributes(self) -> Dict[str, Union[str, bool]]:
        """Get secure cookie attributes."""
        attributes = {}
        
        if self.config.secure_cookies:
            attributes["secure"] = True
        
        if self.config.httponly_cookies:
            attributes["httponly"] = True
        
        attributes["samesite"] = self.config.samesite_cookies.value
        
        return attributes


class SecurityHeadersMiddleware:
    """Middleware for applying security headers to responses."""
    
    def __init__(self, config: SecurityHeadersConfig = None):
        self.headers_manager = SecurityHeadersManager(config)
        self.logger = get_logger("security_headers.middleware")
    
    async def __call__(self, request, call_next):
        """Apply security headers to response."""
        response = await call_next(request)
        
        # Determine if this is an API request
        is_api = self._is_api_request(request)
        
        # Get security headers
        security_headers = self.headers_manager.get_security_headers(
            request_path=str(request.url.path),
            is_api=is_api
        )
        
        # Apply headers to response
        for name, value in security_headers.items():
            if value:  # Only set non-empty headers
                response.headers[name] = value
        
        # Handle CORS preflight requests
        if request.method == "OPTIONS" and is_api:
            self._handle_preflight_request(request, response)
        
        # Remove headers that should be hidden
        if self.headers_manager.config.remove_powered_by:
            response.headers.pop("X-Powered-By", None)
        
        if self.headers_manager.config.remove_server_header and not self.headers_manager.config.custom_server_header:
            response.headers.pop("Server", None)
        
        return response
    
    def _is_api_request(self, request) -> bool:
        """Determine if request is for API endpoint."""
        path = str(request.url.path).lower()
        api_patterns = ["/api/", "/v1/", "/v2/", "/graphql", "/webhook"]
        return any(pattern in path for pattern in api_patterns)
    
    def _handle_preflight_request(self, request, response):
        """Handle CORS preflight requests."""
        # Check if origin is allowed
        origin = request.headers.get("origin")
        if origin and self._is_origin_allowed(origin):
            response.headers["Access-Control-Allow-Origin"] = origin
        
        # Handle requested method
        requested_method = request.headers.get("access-control-request-method")
        if requested_method and requested_method in self.headers_manager.config.api_cors_methods:
            response.headers["Access-Control-Allow-Methods"] = ", ".join(
                self.headers_manager.config.api_cors_methods
            )
        
        # Handle requested headers
        requested_headers = request.headers.get("access-control-request-headers")
        if requested_headers:
            headers_list = [h.strip() for h in requested_headers.split(",")]
            allowed_headers = [h for h in headers_list if h.lower() in 
                             [ah.lower() for ah in self.headers_manager.config.api_cors_headers]]
            if allowed_headers:
                response.headers["Access-Control-Allow-Headers"] = ", ".join(allowed_headers)
    
    def _is_origin_allowed(self, origin: str) -> bool:
        """Check if origin is in allowed CORS origins."""
        if not self.headers_manager.config.api_cors_origins:
            return False
        
        if "*" in self.headers_manager.config.api_cors_origins:
            return True
        
        return origin in self.headers_manager.config.api_cors_origins


def create_security_headers_middleware(config: SecurityHeadersConfig = None):
    """Create security headers middleware."""
    return SecurityHeadersMiddleware(config)


def create_production_security_config() -> SecurityHeadersConfig:
    """Create production-ready security headers configuration."""
    return SecurityHeadersConfig(
        # Strict CSP
        csp_directives={
            CSPDirective.DEFAULT_SRC: ["'self'"],
            CSPDirective.SCRIPT_SRC: ["'self'"],
            CSPDirective.STYLE_SRC: ["'self'"],
            CSPDirective.IMG_SRC: ["'self'", "data:", "https:"],
            CSPDirective.CONNECT_SRC: ["'self'"],
            CSPDirective.FONT_SRC: ["'self'"],
            CSPDirective.OBJECT_SRC: ["'none'"],
            CSPDirective.FRAME_SRC: ["'none'"],
            CSPDirective.FRAME_ANCESTORS: ["'none'"],
            CSPDirective.BASE_URI: ["'self'"],
            CSPDirective.FORM_ACTION: ["'self'"]
        },
        
        # Strong HSTS
        hsts_max_age=63072000,  # 2 years
        hsts_include_subdomains=True,
        hsts_preload=True,
        
        # Strict frame options
        x_frame_options="DENY",
        
        # Strict referrer policy
        referrer_policy=ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN,
        
        # Restrictive permissions
        permissions_policy={
            "geolocation": [],
            "microphone": [],
            "camera": [],
            "payment": [],
            "usb": [],
            "magnetometer": [],
            "gyroscope": [],
            "accelerometer": [],
            "fullscreen": [],
            "sync-xhr": []
        },
        
        # Cross-origin policies
        cross_origin_embedder_policy="require-corp",
        cross_origin_opener_policy="same-origin",
        cross_origin_resource_policy="same-origin",
        
        # Cookie security
        secure_cookies=True,
        httponly_cookies=True,
        samesite_cookies=SameSitePolicy.STRICT,
        
        # Hide server info
        remove_server_header=True,
        remove_powered_by=True
    )


def create_development_security_config() -> SecurityHeadersConfig:
    """Create development-friendly security headers configuration."""
    return SecurityHeadersConfig(
        # Relaxed CSP for development
        csp_directives={
            CSPDirective.DEFAULT_SRC: ["'self'"],
            CSPDirective.SCRIPT_SRC: ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
            CSPDirective.STYLE_SRC: ["'self'", "'unsafe-inline'"],
            CSPDirective.IMG_SRC: ["'self'", "data:", "https:", "http:"],
            CSPDirective.CONNECT_SRC: ["'self'", "ws:", "wss:"],
            CSPDirective.FONT_SRC: ["'self'", "data:"],
            CSPDirective.OBJECT_SRC: ["'none'"],
            CSPDirective.FRAME_ANCESTORS: ["'self'"],
            CSPDirective.BASE_URI: ["'self'"]
        },
        csp_report_only=True,  # Report-only mode for development
        
        # Shorter HSTS for development
        hsts_max_age=300,  # 5 minutes
        hsts_include_subdomains=False,
        hsts_preload=False,
        
        # Relaxed frame options
        x_frame_options="SAMEORIGIN",
        
        # Relaxed referrer policy
        referrer_policy=ReferrerPolicy.ORIGIN_WHEN_CROSS_ORIGIN,
        
        # Relaxed cookie security
        secure_cookies=False,  # Allow non-HTTPS in development
        samesite_cookies=SameSitePolicy.LAX
    )