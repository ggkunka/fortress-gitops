"""Logging configuration for the MCP Security Assessment Platform."""

import logging
from typing import Dict, List, Optional
from pydantic import Field
from .base import BaseConfig


class LoggingConfig(BaseConfig):
    """Logging configuration settings."""
    
    # Basic logging settings
    log_level: str = Field(default="INFO", description="Log level")
    log_format: str = Field(
        default="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        description="Log format"
    )
    log_date_format: str = Field(
        default="%Y-%m-%d %H:%M:%S",
        description="Log date format"
    )
    
    # Structured logging settings
    structured_logging: bool = Field(default=True, description="Enable structured logging")
    json_logging: bool = Field(default=True, description="Enable JSON logging")
    
    # File logging settings
    log_file: Optional[str] = Field(default=None, description="Log file path")
    log_file_max_size: int = Field(default=10_000_000, description="Log file max size in bytes")
    log_file_backup_count: int = Field(default=5, description="Log file backup count")
    
    # Console logging settings
    console_logging: bool = Field(default=True, description="Enable console logging")
    console_log_level: Optional[str] = Field(default=None, description="Console log level")
    
    # Syslog settings
    syslog_enabled: bool = Field(default=False, description="Enable syslog")
    syslog_host: str = Field(default="localhost", description="Syslog host")
    syslog_port: int = Field(default=514, description="Syslog port")
    syslog_facility: str = Field(default="local0", description="Syslog facility")
    
    # Remote logging settings
    remote_logging_enabled: bool = Field(default=False, description="Enable remote logging")
    remote_logging_url: Optional[str] = Field(default=None, description="Remote logging URL")
    remote_logging_api_key: Optional[str] = Field(default=None, description="Remote logging API key")
    
    # Logger-specific settings
    logger_levels: Dict[str, str] = Field(
        default={
            "uvicorn": "INFO",
            "sqlalchemy": "WARNING",
            "alembic": "INFO",
            "celery": "INFO",
            "kubernetes": "WARNING",
            "httpx": "WARNING",
            "redis": "WARNING",
        },
        description="Logger-specific log levels"
    )
    
    # Audit logging settings
    audit_logging: bool = Field(default=True, description="Enable audit logging")
    audit_log_file: Optional[str] = Field(default=None, description="Audit log file path")
    audit_log_level: str = Field(default="INFO", description="Audit log level")
    
    # Security logging settings
    security_logging: bool = Field(default=True, description="Enable security logging")
    security_log_file: Optional[str] = Field(default=None, description="Security log file path")
    security_log_level: str = Field(default="WARNING", description="Security log level")
    
    # Performance logging settings
    performance_logging: bool = Field(default=True, description="Enable performance logging")
    performance_log_file: Optional[str] = Field(default=None, description="Performance log file path")
    performance_log_level: str = Field(default="INFO", description="Performance log level")
    
    # Request logging settings
    request_logging: bool = Field(default=True, description="Enable request logging")
    request_log_headers: bool = Field(default=False, description="Log request headers")
    request_log_body: bool = Field(default=False, description="Log request body")
    request_log_response: bool = Field(default=False, description="Log response body")
    
    # Sensitive data filtering
    sensitive_fields: List[str] = Field(
        default=[
            "password",
            "token",
            "secret",
            "key",
            "authorization",
            "x-api-key",
            "x-auth-token",
            "cookie",
            "session",
        ],
        description="Sensitive fields to filter from logs"
    )
    
    # Log sampling settings
    log_sampling_enabled: bool = Field(default=False, description="Enable log sampling")
    log_sampling_rate: float = Field(default=0.1, description="Log sampling rate (0.0-1.0)")
    
    @property
    def effective_log_level(self) -> int:
        """Get effective log level as integer."""
        return getattr(logging, self.log_level.upper(), logging.INFO)
    
    @property
    def effective_console_log_level(self) -> int:
        """Get effective console log level as integer."""
        level = self.console_log_level or self.log_level
        return getattr(logging, level.upper(), logging.INFO)
    
    def get_logging_config(self) -> dict:
        """Get logging configuration dictionary."""
        config = {
            "version": 1,
            "disable_existing_loggers": False,
            "formatters": {
                "standard": {
                    "format": self.log_format,
                    "datefmt": self.log_date_format,
                },
                "json": {
                    "()": "pythonjsonlogger.jsonlogger.JsonFormatter",
                    "format": "%(asctime)s %(name)s %(levelname)s %(message)s",
                },
            },
            "handlers": {},
            "loggers": {
                "": {
                    "level": self.log_level,
                    "handlers": [],
                },
            },
        }
        
        # Add console handler
        if self.console_logging:
            config["handlers"]["console"] = {
                "class": "logging.StreamHandler",
                "level": self.console_log_level or self.log_level,
                "formatter": "json" if self.json_logging else "standard",
                "stream": "ext://sys.stdout",
            }
            config["loggers"][""]["handlers"].append("console")
        
        # Add file handler
        if self.log_file:
            config["handlers"]["file"] = {
                "class": "logging.handlers.RotatingFileHandler",
                "level": self.log_level,
                "formatter": "json" if self.json_logging else "standard",
                "filename": self.log_file,
                "maxBytes": self.log_file_max_size,
                "backupCount": self.log_file_backup_count,
            }
            config["loggers"][""]["handlers"].append("file")
        
        # Add syslog handler
        if self.syslog_enabled:
            config["handlers"]["syslog"] = {
                "class": "logging.handlers.SysLogHandler",
                "level": self.log_level,
                "formatter": "json" if self.json_logging else "standard",
                "address": (self.syslog_host, self.syslog_port),
                "facility": self.syslog_facility,
            }
            config["loggers"][""]["handlers"].append("syslog")
        
        # Add logger-specific levels
        for logger_name, level in self.logger_levels.items():
            config["loggers"][logger_name] = {
                "level": level,
                "handlers": [],
                "propagate": True,
            }
        
        return config
    
    def get_audit_config(self) -> dict:
        """Get audit logging configuration."""
        return {
            "enabled": self.audit_logging,
            "level": self.audit_log_level,
            "file": self.audit_log_file,
        }
    
    def get_security_config(self) -> dict:
        """Get security logging configuration."""
        return {
            "enabled": self.security_logging,
            "level": self.security_log_level,
            "file": self.security_log_file,
        }
    
    def get_performance_config(self) -> dict:
        """Get performance logging configuration."""
        return {
            "enabled": self.performance_logging,
            "level": self.performance_log_level,
            "file": self.performance_log_file,
        }