"""Settings management for the MCP Security Assessment Platform."""

from functools import lru_cache
from typing import Any, Dict, Type, TypeVar

from .base import BaseConfig
from .database import DatabaseConfig
from .redis import RedisConfig
from .logging import LoggingConfig
from .security import SecurityConfig
from .kubernetes import KubernetesConfig

ConfigType = TypeVar("ConfigType", bound=BaseConfig)


class Settings(
    BaseConfig,
    DatabaseConfig,
    RedisConfig,
    LoggingConfig,
    SecurityConfig,
    KubernetesConfig,
):
    """Combined settings for the MCP Security Assessment Platform."""
    
    # Application metadata
    app_name: str = "MCP Security Assessment Platform"
    app_version: str = "0.1.0"
    app_description: str = "A comprehensive security assessment platform for MCP environments"
    
    # Service-specific settings
    service_name: str = "mcp-security-platform"
    service_version: str = "0.1.0"
    service_type: str = "api"
    
    # Feature flags
    feature_scanner_enabled: bool = True
    feature_analyzer_enabled: bool = True
    feature_reports_enabled: bool = True
    feature_notifications_enabled: bool = True
    feature_audit_enabled: bool = True
    
    # Performance settings
    max_concurrent_requests: int = 100
    max_request_size: int = 10_000_000  # 10MB
    worker_timeout: int = 30
    keepalive_timeout: int = 5
    
    # Cache settings
    cache_enabled: bool = True
    cache_backend: str = "redis"
    cache_default_ttl: int = 300
    
    # Task queue settings
    task_queue_enabled: bool = True
    task_queue_backend: str = "redis"
    task_queue_default_queue: str = "default"
    
    # External services
    external_services: Dict[str, str] = {
        "vulnerability_db": "https://api.vulndb.com",
        "cve_api": "https://cve.circl.lu/api",
        "nvd_api": "https://services.nvd.nist.gov/rest/json",
    }
    
    # Scan settings
    scan_max_concurrent: int = 10
    scan_timeout: int = 3600
    scan_result_retention_days: int = 365
    scan_queue_name: str = "scan_queue"
    
    # Analysis settings
    analysis_max_concurrent: int = 5
    analysis_timeout: int = 1800
    analysis_result_retention_days: int = 365
    analysis_queue_name: str = "analysis_queue"
    
    # Report settings
    report_max_concurrent: int = 3
    report_timeout: int = 900
    report_result_retention_days: int = 365
    report_queue_name: str = "report_queue"
    
    # Notification settings
    notification_max_concurrent: int = 20
    notification_timeout: int = 30
    notification_retry_count: int = 3
    notification_queue_name: str = "notification_queue"
    
    def get_service_config(self) -> Dict[str, Any]:
        """Get service-specific configuration."""
        return {
            "name": self.service_name,
            "version": self.service_version,
            "type": self.service_type,
            "host": self.host,
            "port": self.port,
            "debug": self.debug,
            "environment": self.environment,
        }
    
    def get_feature_flags(self) -> Dict[str, bool]:
        """Get feature flags."""
        return {
            "scanner_enabled": self.feature_scanner_enabled,
            "analyzer_enabled": self.feature_analyzer_enabled,
            "reports_enabled": self.feature_reports_enabled,
            "notifications_enabled": self.feature_notifications_enabled,
            "audit_enabled": self.feature_audit_enabled,
        }
    
    def get_performance_config(self) -> Dict[str, Any]:
        """Get performance configuration."""
        return {
            "max_concurrent_requests": self.max_concurrent_requests,
            "max_request_size": self.max_request_size,
            "worker_timeout": self.worker_timeout,
            "keepalive_timeout": self.keepalive_timeout,
        }
    
    def get_task_queue_config(self) -> Dict[str, Any]:
        """Get task queue configuration."""
        return {
            "enabled": self.task_queue_enabled,
            "backend": self.task_queue_backend,
            "default_queue": self.task_queue_default_queue,
            "redis_url": str(self.redis_url),
        }
    
    def get_external_services_config(self) -> Dict[str, str]:
        """Get external services configuration."""
        return self.external_services.copy()
    
    def get_scan_config(self) -> Dict[str, Any]:
        """Get scan configuration."""
        return {
            "max_concurrent": self.scan_max_concurrent,
            "timeout": self.scan_timeout,
            "result_retention_days": self.scan_result_retention_days,
            "queue_name": self.scan_queue_name,
        }
    
    def get_analysis_config(self) -> Dict[str, Any]:
        """Get analysis configuration."""
        return {
            "max_concurrent": self.analysis_max_concurrent,
            "timeout": self.analysis_timeout,
            "result_retention_days": self.analysis_result_retention_days,
            "queue_name": self.analysis_queue_name,
        }
    
    def get_report_config(self) -> Dict[str, Any]:
        """Get report configuration."""
        return {
            "max_concurrent": self.report_max_concurrent,
            "timeout": self.report_timeout,
            "result_retention_days": self.report_result_retention_days,
            "queue_name": self.report_queue_name,
        }
    
    def get_notification_config(self) -> Dict[str, Any]:
        """Get notification configuration."""
        return {
            "max_concurrent": self.notification_max_concurrent,
            "timeout": self.notification_timeout,
            "retry_count": self.notification_retry_count,
            "queue_name": self.notification_queue_name,
        }
    
    def get_all_config(self) -> Dict[str, Any]:
        """Get all configuration as a dictionary."""
        return {
            "service": self.get_service_config(),
            "features": self.get_feature_flags(),
            "performance": self.get_performance_config(),
            "database": {
                "url": str(self.database_url),
                "engine": self.get_engine_config(),
                "session": self.get_session_config(),
            },
            "redis": {
                "url": str(self.redis_url),
                "connection": self.get_connection_config(),
                "cache": self.get_cache_config(),
            },
            "security": {
                "jwt": self.get_jwt_config(),
                "password": self.get_password_config(),
                "rate_limit": self.get_rate_limit_config(),
                "headers": self.get_security_headers(),
            },
            "kubernetes": {
                "client": self.get_client_config(),
                "resources": self.get_resource_requirements(),
                "security": self.get_security_context(),
                "hpa": self.get_hpa_config(),
                "flavor": self.get_flavor_config(),
            },
            "logging": self.get_logging_config(),
            "task_queue": self.get_task_queue_config(),
            "external_services": self.get_external_services_config(),
            "scan": self.get_scan_config(),
            "analysis": self.get_analysis_config(),
            "report": self.get_report_config(),
            "notification": self.get_notification_config(),
        }


@lru_cache()
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


def get_config(config_class: Type[ConfigType]) -> ConfigType:
    """Get configuration for a specific config class."""
    settings = get_settings()
    
    # Extract fields that belong to the config class
    config_fields = config_class.model_fields
    config_data = {}
    
    for field_name in config_fields:
        if hasattr(settings, field_name):
            config_data[field_name] = getattr(settings, field_name)
    
    return config_class(**config_data)


def reload_settings() -> Settings:
    """Reload settings (clear cache and create new instance)."""
    get_settings.cache_clear()
    return get_settings()