"""Simple settings for the gateway service."""

import os
from pydantic_settings import BaseSettings


class GatewaySettings(BaseSettings):
    """Gateway service settings."""
    
    # Application
    app_name: str = "MCP Security Gateway"
    app_version: str = "0.1.0"
    
    # Server
    host: str = "0.0.0.0"
    port: int = 8081
    debug: bool = False
    
    # Database
    database_url: str = "postgresql://mcp_user:SecureUserPassword123!@postgresql:5432/mcp_security"
    
    # Redis
    redis_url: str = "redis://redis-master:6379/0"
    
    # Logging
    log_level: str = "info"
    
    # Services
    auth_service_url: str = "http://auth-service:8080"
    
    class Config:
        env_file = ".env"
        case_sensitive = False


def get_settings() -> GatewaySettings:
    """Get gateway settings."""
    return GatewaySettings()
