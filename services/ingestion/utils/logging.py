"""Logging configuration for the ingestion service."""

import os
import sys
import json
from typing import Dict, Any, Optional
from datetime import datetime

import structlog
from structlog.stdlib import LoggerFactory
from structlog.dev import ConsoleRenderer
from structlog.processors import JSONRenderer, TimeStamper, add_log_level, StackInfoRenderer

from shared.config import get_settings

settings = get_settings()


def setup_logging(
    service_name: str = "ingestion",
    log_level: str = "INFO",
    json_format: bool = True,
    correlation_id: Optional[str] = None,
) -> None:
    """Set up structured logging for the ingestion service."""
    
    # Configure structlog
    shared_processors = [
        # Add timestamp
        TimeStamper(fmt="iso"),
        # Add log level
        add_log_level,
        # Add stack info for exceptions
        StackInfoRenderer(),
        # Add service context
        lambda logger, method_name, event_dict: {
            **event_dict,
            "service": service_name,
            "environment": os.getenv("ENVIRONMENT", "development"),
            "correlation_id": correlation_id,
        },
    ]
    
    if json_format:
        # Production JSON format
        processors = shared_processors + [JSONRenderer()]
    else:
        # Development console format
        processors = shared_processors + [ConsoleRenderer()]
    
    structlog.configure(
        processors=processors,
        wrapper_class=structlog.stdlib.BoundLogger,
        logger_factory=LoggerFactory(),
        context_class=dict,
        cache_logger_on_first_use=True,
    )
    
    # Configure standard library logging
    import logging
    
    # Set log level
    numeric_level = getattr(logging, log_level.upper(), logging.INFO)
    logging.basicConfig(
        level=numeric_level,
        format="%(message)s",
        stream=sys.stdout,
    )
    
    # Configure specific loggers
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.INFO)
    logging.getLogger("fastapi").setLevel(logging.INFO)
    logging.getLogger("redis").setLevel(logging.WARNING)


class IngestionLogger:
    """Structured logger for ingestion operations."""
    
    def __init__(self, service_name: str = "ingestion"):
        self.logger = structlog.get_logger().bind(service=service_name)
    
    def log_ingestion_start(
        self,
        data_type: str,
        ingestion_id: str,
        source_system: Optional[str] = None,
        data_size: Optional[int] = None,
        async_processing: bool = False,
    ) -> None:
        """Log ingestion start event."""
        self.logger.info(
            "Ingestion started",
            data_type=data_type,
            ingestion_id=ingestion_id,
            source_system=source_system,
            data_size=data_size,
            async_processing=async_processing,
            event_type="ingestion.started",
        )
    
    def log_ingestion_success(
        self,
        data_type: str,
        ingestion_id: str,
        processing_time: float,
        source_system: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log successful ingestion event."""
        self.logger.info(
            "Ingestion completed successfully",
            data_type=data_type,
            ingestion_id=ingestion_id,
            processing_time=processing_time,
            source_system=source_system,
            event_type="ingestion.success",
            **(additional_data or {}),
        )
    
    def log_ingestion_error(
        self,
        data_type: str,
        ingestion_id: str,
        error: str,
        error_type: str,
        processing_time: Optional[float] = None,
        source_system: Optional[str] = None,
        additional_data: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log ingestion error event."""
        self.logger.error(
            "Ingestion failed",
            data_type=data_type,
            ingestion_id=ingestion_id,
            error=error,
            error_type=error_type,
            processing_time=processing_time,
            source_system=source_system,
            event_type="ingestion.error",
            **(additional_data or {}),
        )
    
    def log_validation_failure(
        self,
        data_type: str,
        ingestion_id: str,
        errors: list,
        source_system: Optional[str] = None,
    ) -> None:
        """Log validation failure event."""
        self.logger.warning(
            "Data validation failed",
            data_type=data_type,
            ingestion_id=ingestion_id,
            error_count=len(errors),
            errors=errors[:5],  # Log first 5 errors
            source_system=source_system,
            event_type="validation.failed",
        )
    
    def log_event_publication(
        self,
        event_type: str,
        ingestion_id: str,
        success: bool,
        channel: Optional[str] = None,
        subscribers: Optional[int] = None,
        error: Optional[str] = None,
    ) -> None:
        """Log event publication event."""
        if success:
            self.logger.info(
                "Event published successfully",
                event_type=event_type,
                ingestion_id=ingestion_id,
                channel=channel,
                subscribers=subscribers,
                event_category="event.publication.success",
            )
        else:
            self.logger.error(
                "Event publication failed",
                event_type=event_type,
                ingestion_id=ingestion_id,
                channel=channel,
                error=error,
                event_category="event.publication.failed",
            )
    
    def log_batch_processing(
        self,
        data_type: str,
        ingestion_id: str,
        batch_size: int,
        successful_items: int,
        failed_items: int,
        processing_time: float,
        source_system: Optional[str] = None,
    ) -> None:
        """Log batch processing event."""
        self.logger.info(
            "Batch processing completed",
            data_type=data_type,
            ingestion_id=ingestion_id,
            batch_size=batch_size,
            successful_items=successful_items,
            failed_items=failed_items,
            success_rate=successful_items / batch_size if batch_size > 0 else 0,
            processing_time=processing_time,
            source_system=source_system,
            event_type="batch.processing.completed",
        )
    
    def log_service_startup(
        self,
        components: Dict[str, bool],
        startup_time: float,
    ) -> None:
        """Log service startup event."""
        self.logger.info(
            "Ingestion service started",
            components=components,
            startup_time=startup_time,
            all_components_healthy=all(components.values()),
            event_type="service.startup",
        )
    
    def log_service_shutdown(
        self,
        uptime: float,
        graceful: bool = True,
    ) -> None:
        """Log service shutdown event."""
        self.logger.info(
            "Ingestion service shutting down",
            uptime=uptime,
            graceful=graceful,
            event_type="service.shutdown",
        )
    
    def log_health_check(
        self,
        status: str,
        components: Dict[str, Any],
        response_time: float,
    ) -> None:
        """Log health check event."""
        self.logger.info(
            "Health check performed",
            status=status,
            components=components,
            response_time=response_time,
            event_type="health.check",
        )
    
    def log_metrics_collection(
        self,
        metrics_type: str,
        data_points: int,
        collection_time: float,
    ) -> None:
        """Log metrics collection event."""
        self.logger.debug(
            "Metrics collected",
            metrics_type=metrics_type,
            data_points=data_points,
            collection_time=collection_time,
            event_type="metrics.collection",
        )
    
    def log_dependency_issue(
        self,
        dependency: str,
        issue_type: str,
        error: str,
        retry_count: Optional[int] = None,
    ) -> None:
        """Log dependency issue event."""
        self.logger.warning(
            "Dependency issue detected",
            dependency=dependency,
            issue_type=issue_type,
            error=error,
            retry_count=retry_count,
            event_type="dependency.issue",
        )
    
    def log_rate_limit_exceeded(
        self,
        client_id: str,
        endpoint: str,
        limit: int,
        window: str,
    ) -> None:
        """Log rate limit exceeded event."""
        self.logger.warning(
            "Rate limit exceeded",
            client_id=client_id,
            endpoint=endpoint,
            limit=limit,
            window=window,
            event_type="rate_limit.exceeded",
        )
    
    def log_security_event(
        self,
        event_type: str,
        client_ip: str,
        user_agent: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log security-related event."""
        self.logger.warning(
            "Security event detected",
            security_event_type=event_type,
            client_ip=client_ip,
            user_agent=user_agent,
            details=details or {},
            event_type="security.event",
        )


class RequestLogger:
    """Logger for HTTP request/response logging."""
    
    def __init__(self):
        self.logger = structlog.get_logger().bind(component="http")
    
    def log_request(
        self,
        method: str,
        url: str,
        headers: Dict[str, str],
        client_ip: str,
        request_id: str,
        body_size: Optional[int] = None,
    ) -> None:
        """Log HTTP request."""
        self.logger.info(
            "HTTP request received",
            method=method,
            url=url,
            client_ip=client_ip,
            request_id=request_id,
            body_size=body_size,
            user_agent=headers.get("user-agent"),
            content_type=headers.get("content-type"),
            event_type="http.request",
        )
    
    def log_response(
        self,
        method: str,
        url: str,
        status_code: int,
        response_time: float,
        request_id: str,
        response_size: Optional[int] = None,
    ) -> None:
        """Log HTTP response."""
        self.logger.info(
            "HTTP response sent",
            method=method,
            url=url,
            status_code=status_code,
            response_time=response_time,
            request_id=request_id,
            response_size=response_size,
            event_type="http.response",
        )


def get_correlation_id() -> str:
    """Generate a correlation ID for request tracing."""
    import uuid
    return str(uuid.uuid4())


def add_correlation_id_to_logs(correlation_id: str) -> None:
    """Add correlation ID to all subsequent log entries."""
    import contextvars
    
    # Create context variable for correlation ID
    correlation_context = contextvars.ContextVar('correlation_id', default=None)
    correlation_context.set(correlation_id)
    
    # Configure structlog to include correlation ID
    structlog.configure(
        processors=[
            lambda logger, method_name, event_dict: {
                **event_dict,
                "correlation_id": correlation_context.get(),
            },
        ] + structlog.get_config()["processors"],
        wrapper_class=structlog.get_config()["wrapper_class"],
        logger_factory=structlog.get_config()["logger_factory"],
        context_class=structlog.get_config()["context_class"],
        cache_logger_on_first_use=structlog.get_config()["cache_logger_on_first_use"],
    )


class AuditLogger:
    """Logger for audit trail events."""
    
    def __init__(self):
        self.logger = structlog.get_logger().bind(component="audit")
    
    def log_data_access(
        self,
        user_id: str,
        action: str,
        resource: str,
        resource_id: str,
        client_ip: str,
        success: bool,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log data access event for audit trail."""
        self.logger.info(
            "Data access event",
            user_id=user_id,
            action=action,
            resource=resource,
            resource_id=resource_id,
            client_ip=client_ip,
            success=success,
            details=details or {},
            event_type="audit.data_access",
            timestamp=datetime.utcnow().isoformat(),
        )
    
    def log_configuration_change(
        self,
        user_id: str,
        component: str,
        old_config: Dict[str, Any],
        new_config: Dict[str, Any],
        client_ip: str,
    ) -> None:
        """Log configuration change event."""
        self.logger.info(
            "Configuration changed",
            user_id=user_id,
            component=component,
            old_config=old_config,
            new_config=new_config,
            client_ip=client_ip,
            event_type="audit.config_change",
            timestamp=datetime.utcnow().isoformat(),
        )