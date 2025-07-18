"""
Structured logging with correlation IDs for MCP Security Platform.
"""

import json
import logging
import uuid
import contextvars
from datetime import datetime
from typing import Dict, Any, Optional, Union
from functools import wraps
import structlog
from structlog.stdlib import LoggerFactory
import sys


# Context variable for correlation ID
correlation_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    'correlation_id', default=None
)

# Context variable for request ID
request_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    'request_id', default=None
)

# Context variable for user ID
user_id: contextvars.ContextVar[str] = contextvars.ContextVar(
    'user_id', default=None
)


class CorrelationIDProcessor:
    """Processor to add correlation ID to log records."""
    
    def __call__(self, logger, method_name, event_dict):
        # Add correlation ID if available
        corr_id = correlation_id.get(None)
        if corr_id:
            event_dict['correlation_id'] = corr_id
        
        # Add request ID if available
        req_id = request_id.get(None)
        if req_id:
            event_dict['request_id'] = req_id
        
        # Add user ID if available
        uid = user_id.get(None)
        if uid:
            event_dict['user_id'] = uid
        
        return event_dict


class SecurityProcessor:
    """Processor to sanitize sensitive information from logs."""
    
    SENSITIVE_FIELDS = {
        'password', 'secret', 'token', 'key', 'credential',
        'authorization', 'cookie', 'session', 'api_key'
    }
    
    def __call__(self, logger, method_name, event_dict):
        return self._sanitize_dict(event_dict)
    
    def _sanitize_dict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Recursively sanitize sensitive fields in dictionary."""
        if not isinstance(data, dict):
            return data
        
        sanitized = {}
        for key, value in data.items():
            if any(sensitive in key.lower() for sensitive in self.SENSITIVE_FIELDS):
                sanitized[key] = "[REDACTED]"
            elif isinstance(value, dict):
                sanitized[key] = self._sanitize_dict(value)
            elif isinstance(value, list):
                sanitized[key] = [
                    self._sanitize_dict(item) if isinstance(item, dict) else item
                    for item in value
                ]
            else:
                sanitized[key] = value
        
        return sanitized


class JSONRenderer:
    """Custom JSON renderer for structured logs."""
    
    def __call__(self, logger, name, event_dict):
        # Ensure timestamp is ISO format
        if 'timestamp' not in event_dict:
            event_dict['timestamp'] = datetime.utcnow().isoformat() + 'Z'
        
        # Add logger name
        event_dict['logger'] = name
        
        # Ensure level is uppercase
        if 'level' in event_dict:
            event_dict['level'] = event_dict['level'].upper()
        
        return json.dumps(event_dict, default=str, separators=(',', ':'))


class StructuredLogger:
    """Structured logger with correlation ID support."""
    
    def __init__(self, name: str, level: str = "INFO"):
        self.name = name
        self.logger = structlog.get_logger(name)
        self.level = level
    
    def _log(self, level: str, message: str, **kwargs):
        """Internal log method."""
        # Add service name and version
        kwargs.update({
            'service': self.name,
            'level': level,
            'message': message
        })
        
        # Add correlation context
        corr_id = correlation_id.get(None)
        if corr_id:
            kwargs['correlation_id'] = corr_id
        
        req_id = request_id.get(None)
        if req_id:
            kwargs['request_id'] = req_id
        
        uid = user_id.get(None)
        if uid:
            kwargs['user_id'] = uid
        
        # Log with appropriate level
        getattr(self.logger, level.lower())(message, **kwargs)
    
    def debug(self, message: str, **kwargs):
        self._log("DEBUG", message, **kwargs)
    
    def info(self, message: str, **kwargs):
        self._log("INFO", message, **kwargs)
    
    def warning(self, message: str, **kwargs):
        self._log("WARNING", message, **kwargs)
    
    def error(self, message: str, **kwargs):
        self._log("ERROR", message, **kwargs)
    
    def critical(self, message: str, **kwargs):
        self._log("CRITICAL", message, **kwargs)
    
    def audit(self, event: str, **kwargs):
        """Log audit events."""
        self._log("INFO", f"AUDIT: {event}", event_type="audit", **kwargs)
    
    def security(self, event: str, **kwargs):
        """Log security events."""
        self._log("WARNING", f"SECURITY: {event}", event_type="security", **kwargs)
    
    def performance(self, operation: str, duration: float, **kwargs):
        """Log performance metrics."""
        self._log("INFO", f"PERFORMANCE: {operation}", 
                 event_type="performance", 
                 operation=operation,
                 duration_ms=duration * 1000,
                 **kwargs)


def setup_logging(
    service_name: str,
    level: str = "INFO",
    format_type: str = "json",
    enable_correlation: bool = True
) -> None:
    """
    Set up structured logging for the service.
    
    Args:
        service_name: Name of the service
        level: Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL)
        format_type: Format type (json, console)
        enable_correlation: Enable correlation ID tracking
    """
    
    # Configure processors
    processors = [
        structlog.stdlib.filter_by_level,
        structlog.stdlib.add_logger_name,
        structlog.stdlib.add_log_level,
        structlog.stdlib.PositionalArgumentsFormatter(),
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.processors.StackInfoRenderer(),
        structlog.processors.format_exc_info,
        structlog.processors.UnicodeDecoder(),
        SecurityProcessor(),
    ]
    
    if enable_correlation:
        processors.insert(-1, CorrelationIDProcessor())
    
    # Add renderer based on format
    if format_type == "json":
        processors.append(JSONRenderer())
    else:
        processors.append(structlog.dev.ConsoleRenderer())
    
    # Configure structlog
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.make_filtering_bound_logger(
            getattr(logging, level.upper())
        ),
        logger_factory=LoggerFactory(),
        cache_logger_on_first_use=True,
    )
    
    # Configure standard library logging
    logging.basicConfig(
        format="%(message)s",
        stream=sys.stdout,
        level=getattr(logging, level.upper()),
    )
    
    # Set service name globally
    structlog.contextvars.bind_contextvars(service=service_name)


def get_logger(name: str) -> StructuredLogger:
    """Get a structured logger instance."""
    return StructuredLogger(name)


def with_correlation_id(corr_id: Optional[str] = None):
    """
    Decorator to set correlation ID for function execution.
    
    Args:
        corr_id: Correlation ID (auto-generated if None)
    """
    def decorator(func):
        @wraps(func)
        async def async_wrapper(*args, **kwargs):
            _corr_id = corr_id or str(uuid.uuid4())
            correlation_id.set(_corr_id)
            try:
                return await func(*args, **kwargs)
            finally:
                correlation_id.set(None)
        
        @wraps(func)
        def sync_wrapper(*args, **kwargs):
            _corr_id = corr_id or str(uuid.uuid4())
            correlation_id.set(_corr_id)
            try:
                return func(*args, **kwargs)
            finally:
                correlation_id.set(None)
        
        return async_wrapper if hasattr(func, '__code__') and func.__code__.co_flags & 0x80 else sync_wrapper
    
    return decorator


def set_correlation_id(corr_id: str):
    """Set correlation ID for current context."""
    correlation_id.set(corr_id)


def get_correlation_id() -> Optional[str]:
    """Get correlation ID from current context."""
    return correlation_id.get(None)


def set_request_id(req_id: str):
    """Set request ID for current context."""
    request_id.set(req_id)


def get_request_id() -> Optional[str]:
    """Get request ID from current context."""
    return request_id.get(None)


def set_user_id(uid: str):
    """Set user ID for current context."""
    user_id.set(uid)


def get_user_id() -> Optional[str]:
    """Get user ID from current context."""
    return user_id.get(None)


class LoggingContext:
    """Context manager for logging correlation."""
    
    def __init__(self, 
                 correlation_id: Optional[str] = None,
                 request_id: Optional[str] = None,
                 user_id: Optional[str] = None):
        self.correlation_id = correlation_id or str(uuid.uuid4())
        self.request_id = request_id
        self.user_id = user_id
        self.old_correlation_id = None
        self.old_request_id = None
        self.old_user_id = None
    
    def __enter__(self):
        # Save old values
        self.old_correlation_id = get_correlation_id()
        self.old_request_id = get_request_id()
        self.old_user_id = get_user_id()
        
        # Set new values
        set_correlation_id(self.correlation_id)
        if self.request_id:
            set_request_id(self.request_id)
        if self.user_id:
            set_user_id(self.user_id)
        
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # Restore old values
        if self.old_correlation_id:
            set_correlation_id(self.old_correlation_id)
        if self.old_request_id:
            set_request_id(self.old_request_id)
        if self.old_user_id:
            set_user_id(self.old_user_id)


# Audit logging utilities
class AuditLogger:
    """Specialized logger for audit events."""
    
    def __init__(self, service_name: str):
        self.logger = get_logger(f"{service_name}.audit")
    
    def log_access(self, user_id: str, resource: str, action: str, success: bool, **kwargs):
        """Log access events."""
        self.logger.audit(
            "resource_access",
            user_id=user_id,
            resource=resource,
            action=action,
            success=success,
            **kwargs
        )
    
    def log_authentication(self, user_id: str, method: str, success: bool, **kwargs):
        """Log authentication events."""
        self.logger.audit(
            "authentication",
            user_id=user_id,
            method=method,
            success=success,
            **kwargs
        )
    
    def log_authorization(self, user_id: str, permission: str, success: bool, **kwargs):
        """Log authorization events."""
        self.logger.audit(
            "authorization",
            user_id=user_id,
            permission=permission,
            success=success,
            **kwargs
        )
    
    def log_data_access(self, user_id: str, data_type: str, operation: str, 
                       record_count: int = 1, **kwargs):
        """Log data access events."""
        self.logger.audit(
            "data_access",
            user_id=user_id,
            data_type=data_type,
            operation=operation,
            record_count=record_count,
            **kwargs
        )
    
    def log_configuration_change(self, user_id: str, component: str, 
                                old_value: Any, new_value: Any, **kwargs):
        """Log configuration changes."""
        self.logger.audit(
            "configuration_change",
            user_id=user_id,
            component=component,
            old_value=str(old_value),
            new_value=str(new_value),
            **kwargs
        )


# Security logging utilities
class SecurityLogger:
    """Specialized logger for security events."""
    
    def __init__(self, service_name: str):
        self.logger = get_logger(f"{service_name}.security")
    
    def log_suspicious_activity(self, event: str, severity: str, **kwargs):
        """Log suspicious activities."""
        self.logger.security(
            f"suspicious_activity: {event}",
            severity=severity,
            **kwargs
        )
    
    def log_vulnerability_detected(self, vulnerability_id: str, severity: str, 
                                  component: str, **kwargs):
        """Log vulnerability detections."""
        self.logger.security(
            "vulnerability_detected",
            vulnerability_id=vulnerability_id,
            severity=severity,
            component=component,
            **kwargs
        )
    
    def log_threat_detected(self, threat_type: str, source_ip: str, **kwargs):
        """Log threat detections."""
        self.logger.security(
            "threat_detected",
            threat_type=threat_type,
            source_ip=source_ip,
            **kwargs
        )
    
    def log_rate_limit_exceeded(self, client_id: str, endpoint: str, **kwargs):
        """Log rate limit violations."""
        self.logger.security(
            "rate_limit_exceeded",
            client_id=client_id,
            endpoint=endpoint,
            **kwargs
        )
    
    def log_input_validation_failure(self, field: str, value_type: str, **kwargs):
        """Log input validation failures."""
        self.logger.security(
            "input_validation_failure",
            field=field,
            value_type=value_type,
            **kwargs
        )