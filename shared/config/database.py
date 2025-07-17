"""Database configuration for the MCP Security Assessment Platform."""

from typing import Optional
from pydantic import Field, PostgresDsn, computed_field
from pydantic_core import MultiHostUrl
from .base import BaseConfig


class DatabaseConfig(BaseConfig):
    """Database configuration settings."""
    
    # Database connection settings
    db_scheme: str = Field(default="postgresql+asyncpg", description="Database scheme")
    db_host: str = Field(default="localhost", description="Database host")
    db_port: int = Field(default=5432, description="Database port")
    db_user: str = Field(default="mcp_user", description="Database username")
    db_password: str = Field(default="mcp_password", description="Database password")
    db_name: str = Field(default="mcp_security", description="Database name")
    
    # Connection pool settings
    db_pool_size: int = Field(default=10, description="Database connection pool size")
    db_max_overflow: int = Field(default=20, description="Database max overflow connections")
    db_pool_timeout: int = Field(default=30, description="Database pool timeout in seconds")
    db_pool_recycle: int = Field(default=3600, description="Database pool recycle time in seconds")
    
    # Query settings
    db_query_timeout: int = Field(default=30, description="Database query timeout in seconds")
    db_command_timeout: int = Field(default=60, description="Database command timeout in seconds")
    
    # Migration settings
    db_migration_timeout: int = Field(default=300, description="Database migration timeout in seconds")
    
    # SSL settings
    db_ssl_mode: Optional[str] = Field(default=None, description="Database SSL mode")
    db_ssl_cert: Optional[str] = Field(default=None, description="Database SSL certificate path")
    db_ssl_key: Optional[str] = Field(default=None, description="Database SSL key path")
    db_ssl_ca: Optional[str] = Field(default=None, description="Database SSL CA certificate path")
    
    # Logging settings
    db_echo: bool = Field(default=False, description="Enable database query logging")
    db_echo_pool: bool = Field(default=False, description="Enable database pool logging")
    
    @computed_field
    @property
    def database_url(self) -> PostgresDsn:
        """Build database URL from components."""
        return MultiHostUrl.build(
            scheme=self.db_scheme,
            username=self.db_user,
            password=self.db_password,
            host=self.db_host,
            port=self.db_port,
            path=self.db_name,
        )
    
    @computed_field
    @property
    def async_database_url(self) -> str:
        """Get async database URL."""
        return str(self.database_url)
    
    @computed_field
    @property
    def sync_database_url(self) -> str:
        """Get sync database URL for Alembic."""
        return str(self.database_url).replace(
            "postgresql+asyncpg://", "postgresql://"
        )
    
    def get_engine_config(self) -> dict:
        """Get SQLAlchemy engine configuration."""
        config = {
            "pool_size": self.db_pool_size,
            "max_overflow": self.db_max_overflow,
            "pool_timeout": self.db_pool_timeout,
            "pool_recycle": self.db_pool_recycle,
            "echo": self.db_echo,
            "echo_pool": self.db_echo_pool,
        }
        
        # Add SSL configuration if provided
        if self.db_ssl_mode:
            connect_args = {"sslmode": self.db_ssl_mode}
            if self.db_ssl_cert:
                connect_args["sslcert"] = self.db_ssl_cert
            if self.db_ssl_key:
                connect_args["sslkey"] = self.db_ssl_key
            if self.db_ssl_ca:
                connect_args["sslrootcert"] = self.db_ssl_ca
            config["connect_args"] = connect_args
        
        return config
    
    def get_session_config(self) -> dict:
        """Get SQLAlchemy session configuration."""
        return {
            "expire_on_commit": False,
            "autoflush": False,
            "autocommit": False,
        }