"""Security configuration for the MCP Security Assessment Platform."""

from typing import List, Optional
from pydantic import Field, SecretStr
from .base import BaseConfig


class SecurityConfig(BaseConfig):
    """Security configuration settings."""
    
    # JWT settings
    jwt_secret_key: SecretStr = Field(
        default=SecretStr("your-super-secret-jwt-key-change-in-production"),
        description="JWT secret key"
    )
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    jwt_access_token_expire_minutes: int = Field(
        default=30, description="JWT access token expiration in minutes"
    )
    jwt_refresh_token_expire_days: int = Field(
        default=7, description="JWT refresh token expiration in days"
    )
    
    # API Key settings
    api_key_header: str = Field(default="X-API-Key", description="API key header name")
    api_key_length: int = Field(default=32, description="API key length")
    api_key_prefix: str = Field(default="mcp_", description="API key prefix")
    
    # Password settings
    password_min_length: int = Field(default=8, description="Minimum password length")
    password_require_uppercase: bool = Field(default=True, description="Require uppercase in password")
    password_require_lowercase: bool = Field(default=True, description="Require lowercase in password")
    password_require_numbers: bool = Field(default=True, description="Require numbers in password")
    password_require_symbols: bool = Field(default=True, description="Require symbols in password")
    password_hash_rounds: int = Field(default=12, description="Password hash rounds")
    
    # Session settings
    session_secret_key: SecretStr = Field(
        default=SecretStr("your-super-secret-session-key-change-in-production"),
        description="Session secret key"
    )
    session_cookie_name: str = Field(default="mcp_session", description="Session cookie name")
    session_cookie_secure: bool = Field(default=True, description="Session cookie secure flag")
    session_cookie_httponly: bool = Field(default=True, description="Session cookie httponly flag")
    session_cookie_samesite: str = Field(default="strict", description="Session cookie samesite")
    
    # CSRF settings
    csrf_enabled: bool = Field(default=True, description="Enable CSRF protection")
    csrf_secret_key: SecretStr = Field(
        default=SecretStr("your-super-secret-csrf-key-change-in-production"),
        description="CSRF secret key"
    )
    csrf_token_expiry: int = Field(default=3600, description="CSRF token expiry in seconds")
    
    # Rate limiting settings
    rate_limit_enabled: bool = Field(default=True, description="Enable rate limiting")
    rate_limit_requests: int = Field(default=100, description="Rate limit requests per window")
    rate_limit_window: int = Field(default=60, description="Rate limit window in seconds")
    rate_limit_storage: str = Field(default="redis", description="Rate limit storage backend")
    
    # Authentication settings
    auth_enabled: bool = Field(default=True, description="Enable authentication")
    auth_require_email_verification: bool = Field(
        default=True, description="Require email verification"
    )
    auth_max_login_attempts: int = Field(default=5, description="Max login attempts")
    auth_lockout_duration: int = Field(default=900, description="Lockout duration in seconds")
    
    # OAuth settings
    oauth_enabled: bool = Field(default=False, description="Enable OAuth")
    oauth_providers: List[str] = Field(default=[], description="OAuth providers")
    oauth_redirect_uri: str = Field(
        default="http://localhost:8000/auth/oauth/callback",
        description="OAuth redirect URI"
    )
    
    # Multi-factor authentication settings
    mfa_enabled: bool = Field(default=False, description="Enable MFA")
    mfa_issuer: str = Field(default="MCP Security Platform", description="MFA issuer")
    mfa_backup_codes_count: int = Field(default=10, description="MFA backup codes count")
    
    # Encryption settings
    encryption_key: SecretStr = Field(
        default=SecretStr("your-super-secret-encryption-key-32-chars"),
        description="Encryption key (32 characters)"
    )
    encryption_algorithm: str = Field(default="AES-256-GCM", description="Encryption algorithm")
    
    # TLS settings
    tls_enabled: bool = Field(default=True, description="Enable TLS")
    tls_cert_file: Optional[str] = Field(default=None, description="TLS certificate file")
    tls_key_file: Optional[str] = Field(default=None, description="TLS key file")
    tls_ca_file: Optional[str] = Field(default=None, description="TLS CA file")
    tls_verify_mode: str = Field(default="required", description="TLS verification mode")
    
    # HSTS settings
    hsts_enabled: bool = Field(default=True, description="Enable HSTS")
    hsts_max_age: int = Field(default=31536000, description="HSTS max age in seconds")
    hsts_include_subdomains: bool = Field(default=True, description="HSTS include subdomains")
    hsts_preload: bool = Field(default=True, description="HSTS preload")
    
    # Content Security Policy settings
    csp_enabled: bool = Field(default=True, description="Enable CSP")
    csp_policy: str = Field(
        default="default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
        description="CSP policy"
    )
    
    # Security headers settings
    security_headers_enabled: bool = Field(default=True, description="Enable security headers")
    x_frame_options: str = Field(default="DENY", description="X-Frame-Options header")
    x_content_type_options: str = Field(default="nosniff", description="X-Content-Type-Options header")
    x_xss_protection: str = Field(default="1; mode=block", description="X-XSS-Protection header")
    referrer_policy: str = Field(default="strict-origin-when-cross-origin", description="Referrer-Policy header")
    
    # Audit settings
    audit_enabled: bool = Field(default=True, description="Enable audit logging")
    audit_log_sensitive_data: bool = Field(default=False, description="Log sensitive data in audit")
    audit_retention_days: int = Field(default=90, description="Audit log retention in days")
    
    # Vulnerability scanner settings
    scanner_max_concurrent_scans: int = Field(default=10, description="Max concurrent scans")
    scanner_scan_timeout: int = Field(default=3600, description="Scan timeout in seconds")
    scanner_result_retention_days: int = Field(default=365, description="Scan result retention in days")
    
    # Kubernetes security settings
    k8s_rbac_enabled: bool = Field(default=True, description="Enable Kubernetes RBAC")
    k8s_network_policies_enabled: bool = Field(default=True, description="Enable network policies")
    k8s_pod_security_standards: str = Field(default="restricted", description="Pod security standards")
    k8s_admission_controller_enabled: bool = Field(default=True, description="Enable admission controller")
    
    # Secrets management settings
    secrets_backend: str = Field(default="kubernetes", description="Secrets backend")
    secrets_encryption_enabled: bool = Field(default=True, description="Enable secrets encryption")
    secrets_rotation_enabled: bool = Field(default=True, description="Enable secrets rotation")
    secrets_rotation_days: int = Field(default=90, description="Secrets rotation interval in days")
    
    @property
    def jwt_secret(self) -> str:
        """Get JWT secret key."""
        return self.jwt_secret_key.get_secret_value()
    
    @property
    def session_secret(self) -> str:
        """Get session secret key."""
        return self.session_secret_key.get_secret_value()
    
    @property
    def csrf_secret(self) -> str:
        """Get CSRF secret key."""
        return self.csrf_secret_key.get_secret_value()
    
    @property
    def encryption_secret(self) -> str:
        """Get encryption key."""
        return self.encryption_key.get_secret_value()
    
    def get_jwt_config(self) -> dict:
        """Get JWT configuration."""
        return {
            "secret_key": self.jwt_secret,
            "algorithm": self.jwt_algorithm,
            "access_token_expire_minutes": self.jwt_access_token_expire_minutes,
            "refresh_token_expire_days": self.jwt_refresh_token_expire_days,
        }
    
    def get_password_config(self) -> dict:
        """Get password configuration."""
        return {
            "min_length": self.password_min_length,
            "require_uppercase": self.password_require_uppercase,
            "require_lowercase": self.password_require_lowercase,
            "require_numbers": self.password_require_numbers,
            "require_symbols": self.password_require_symbols,
            "hash_rounds": self.password_hash_rounds,
        }
    
    def get_rate_limit_config(self) -> dict:
        """Get rate limiting configuration."""
        return {
            "enabled": self.rate_limit_enabled,
            "requests": self.rate_limit_requests,
            "window": self.rate_limit_window,
            "storage": self.rate_limit_storage,
        }
    
    def get_security_headers(self) -> dict:
        """Get security headers configuration."""
        headers = {}
        
        if self.security_headers_enabled:
            headers.update({
                "X-Frame-Options": self.x_frame_options,
                "X-Content-Type-Options": self.x_content_type_options,
                "X-XSS-Protection": self.x_xss_protection,
                "Referrer-Policy": self.referrer_policy,
            })
        
        if self.hsts_enabled:
            hsts_value = f"max-age={self.hsts_max_age}"
            if self.hsts_include_subdomains:
                hsts_value += "; includeSubDomains"
            if self.hsts_preload:
                hsts_value += "; preload"
            headers["Strict-Transport-Security"] = hsts_value
        
        if self.csp_enabled:
            headers["Content-Security-Policy"] = self.csp_policy
        
        return headers