"""Base configuration classes for the MCP Security Assessment Platform."""

from typing import Any, Dict, Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class BaseConfig(BaseSettings):
    """Base configuration class with common settings."""
    
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )
    
    # Application settings
    app_name: str = Field(default="MCP Security Platform", description="Application name")
    app_version: str = Field(default="0.1.0", description="Application version")
    debug: bool = Field(default=False, description="Enable debug mode")
    environment: str = Field(default="development", description="Environment name")
    
    # Server settings
    host: str = Field(default="0.0.0.0", description="Server host")
    port: int = Field(default=8000, description="Server port")
    workers: int = Field(default=1, description="Number of worker processes")
    
    # API settings
    api_prefix: str = Field(default="/api/v1", description="API prefix")
    docs_url: Optional[str] = Field(default="/docs", description="API documentation URL")
    redoc_url: Optional[str] = Field(default="/redoc", description="ReDoc documentation URL")
    openapi_url: Optional[str] = Field(default="/openapi.json", description="OpenAPI JSON URL")
    
    # Request settings
    max_request_size: int = Field(default=10_000_000, description="Maximum request size in bytes")
    request_timeout: int = Field(default=30, description="Request timeout in seconds")
    
    # Health check settings
    health_check_path: str = Field(default="/health", description="Health check endpoint")
    
    # Metrics settings
    metrics_path: str = Field(default="/metrics", description="Metrics endpoint")
    enable_metrics: bool = Field(default=True, description="Enable metrics collection")
    
    # CORS settings
    cors_origins: list[str] = Field(default=["*"], description="CORS allowed origins")
    cors_methods: list[str] = Field(default=["*"], description="CORS allowed methods")
    cors_headers: list[str] = Field(default=["*"], description="CORS allowed headers")
    
    @property
    def is_production(self) -> bool:
        """Check if running in production environment."""
        return self.environment.lower() == "production"
    
    @property
    def is_development(self) -> bool:
        """Check if running in development environment."""
        return self.environment.lower() == "development"
    
    @property
    def is_testing(self) -> bool:
        """Check if running in testing environment."""
        return self.environment.lower() == "test"
    
    def get_service_info(self) -> Dict[str, Any]:
        """Get service information for health checks."""
        return {
            "name": self.app_name,
            "version": self.app_version,
            "environment": self.environment,
            "debug": self.debug,
        }