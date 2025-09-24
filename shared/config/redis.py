"""Redis configuration for the MCP Security Assessment Platform."""

from typing import Optional
from pydantic import Field, RedisDsn, computed_field
from pydantic_core import MultiHostUrl
from .base import BaseConfig


class RedisConfig(BaseConfig):
    """Redis configuration settings."""
    
    # Redis connection settings
    redis_host: str = Field(default="localhost", description="Redis host")
    redis_port: int = Field(default=6379, description="Redis port")
    redis_password: Optional[str] = Field(default=None, description="Redis password")
    redis_db: int = Field(default=0, description="Redis database number")
    
    # Connection pool settings
    redis_pool_size: int = Field(default=10, description="Redis connection pool size")
    redis_max_connections: int = Field(default=20, description="Redis max connections")
    redis_retry_on_timeout: bool = Field(default=True, description="Retry on timeout")
    
    # Timeout settings
    redis_socket_timeout: int = Field(default=5, description="Redis socket timeout in seconds")
    redis_socket_connect_timeout: int = Field(default=5, description="Redis socket connect timeout")
    redis_health_check_interval: int = Field(default=30, description="Redis health check interval")
    
    # SSL settings
    redis_ssl: bool = Field(default=False, description="Enable Redis SSL")
    redis_ssl_cert_reqs: Optional[str] = Field(default=None, description="Redis SSL certificate requirements")
    redis_ssl_ca_certs: Optional[str] = Field(default=None, description="Redis SSL CA certificates path")
    redis_ssl_certfile: Optional[str] = Field(default=None, description="Redis SSL certificate file")
    redis_ssl_keyfile: Optional[str] = Field(default=None, description="Redis SSL key file")
    
    # Cluster settings
    redis_cluster: bool = Field(default=False, description="Enable Redis cluster mode")
    redis_cluster_nodes: list[str] = Field(default=[], description="Redis cluster nodes")
    
    # Cache settings
    cache_default_ttl: int = Field(default=300, description="Default cache TTL in seconds")
    cache_key_prefix: str = Field(default="mcp:", description="Cache key prefix")
    
    # Session settings
    session_ttl: int = Field(default=3600, description="Session TTL in seconds")
    session_key_prefix: str = Field(default="session:", description="Session key prefix")
    
    # Rate limiting settings
    rate_limit_ttl: int = Field(default=60, description="Rate limit TTL in seconds")
    rate_limit_key_prefix: str = Field(default="rate_limit:", description="Rate limit key prefix")
    
    @computed_field
    @property
    def redis_url(self) -> RedisDsn:
        """Build Redis URL from components."""
        scheme = "rediss" if self.redis_ssl else "redis"
        return MultiHostUrl.build(
            scheme=scheme,
            password=self.redis_password,
            host=self.redis_host,
            port=self.redis_port,
            path=str(self.redis_db),
        )
    
    def get_connection_config(self) -> dict:
        """Get Redis connection configuration."""
        config = {
            "host": self.redis_host,
            "port": self.redis_port,
            "db": self.redis_db,
            "socket_timeout": self.redis_socket_timeout,
            "socket_connect_timeout": self.redis_socket_connect_timeout,
            "health_check_interval": self.redis_health_check_interval,
            "retry_on_timeout": self.redis_retry_on_timeout,
            "decode_responses": True,
            "encoding": "utf-8",
        }
        
        if self.redis_password:
            config["password"] = self.redis_password
        
        if self.redis_ssl:
            config["ssl"] = True
            if self.redis_ssl_cert_reqs:
                config["ssl_cert_reqs"] = self.redis_ssl_cert_reqs
            if self.redis_ssl_ca_certs:
                config["ssl_ca_certs"] = self.redis_ssl_ca_certs
            if self.redis_ssl_certfile:
                config["ssl_certfile"] = self.redis_ssl_certfile
            if self.redis_ssl_keyfile:
                config["ssl_keyfile"] = self.redis_ssl_keyfile
        
        return config
    
    def get_pool_config(self) -> dict:
        """Get Redis connection pool configuration."""
        return {
            "max_connections": self.redis_max_connections,
            "connection_pool_class_kwargs": {
                "health_check_interval": self.redis_health_check_interval,
            },
        }
    
    def get_cache_config(self) -> dict:
        """Get cache configuration."""
        return {
            "default_ttl": self.cache_default_ttl,
            "key_prefix": self.cache_key_prefix,
        }
    
    def get_session_config(self) -> dict:
        """Get session configuration."""
        return {
            "ttl": self.session_ttl,
            "key_prefix": self.session_key_prefix,
        }
    
    def get_rate_limit_config(self) -> dict:
        """Get rate limiting configuration."""
        return {
            "ttl": self.rate_limit_ttl,
            "key_prefix": self.rate_limit_key_prefix,
        }