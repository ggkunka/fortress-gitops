"""Event bus middleware for processing events."""

import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Optional
from datetime import datetime

import structlog

from .base import EventMessage
from .exceptions import EventMiddlewareError


class EventMiddleware(ABC):
    """Abstract base class for event middleware."""
    
    @abstractmethod
    async def process_outbound(self, event: EventMessage) -> EventMessage:
        """Process an outbound event."""
        pass
    
    @abstractmethod
    async def process_inbound(self, event: EventMessage) -> EventMessage:
        """Process an inbound event."""
        pass


class LoggingMiddleware(EventMiddleware):
    """Middleware for logging events."""
    
    def __init__(self, service_name: str, log_level: str = "INFO"):
        self.service_name = service_name
        self.log_level = log_level.upper()
        self.logger = structlog.get_logger().bind(
            service=service_name,
            component="event_middleware"
        )
    
    async def process_outbound(self, event: EventMessage) -> EventMessage:
        """Log outbound events."""
        try:
            if self.log_level in ["DEBUG", "INFO"]:
                self.logger.info(
                    "Outbound event",
                    event_type=event.event_type,
                    event_id=event.event_id,
                    source_service=event.source_service,
                    correlation_id=event.correlation_id,
                    data_size=len(str(event.data)),
                )
            
            return event
        except Exception as e:
            self.logger.error("Error in logging middleware (outbound)", error=str(e))
            raise EventMiddlewareError(f"Logging middleware failed: {str(e)}")
    
    async def process_inbound(self, event: EventMessage) -> EventMessage:
        """Log inbound events."""
        try:
            if self.log_level in ["DEBUG", "INFO"]:
                self.logger.info(
                    "Inbound event",
                    event_type=event.event_type,
                    event_id=event.event_id,
                    source_service=event.source_service,
                    target_service=self.service_name,
                    correlation_id=event.correlation_id,
                    data_size=len(str(event.data)),
                )
            
            return event
        except Exception as e:
            self.logger.error("Error in logging middleware (inbound)", error=str(e))
            raise EventMiddlewareError(f"Logging middleware failed: {str(e)}")


class MetricsMiddleware(EventMiddleware):
    """Middleware for collecting event metrics."""
    
    def __init__(self, service_name: str, metrics_service: Optional[Any] = None):
        self.service_name = service_name
        self.metrics_service = metrics_service
        self.logger = structlog.get_logger().bind(
            service=service_name,
            component="event_metrics"
        )
    
    async def process_outbound(self, event: EventMessage) -> EventMessage:
        """Record outbound event metrics."""
        try:
            if self.metrics_service:
                # Record event publication
                self.metrics_service.record_event_publication(
                    event_type=event.event_type,
                    direction="outbound",
                    status="processing"
                )
                
                # Record data size
                data_size = len(str(event.data))
                self.metrics_service.record_event_data_size(
                    event_type=event.event_type,
                    size=data_size
                )
            
            # Add timing metadata
            event.metadata["outbound_timestamp"] = datetime.utcnow().isoformat()
            
            return event
        except Exception as e:
            self.logger.error("Error in metrics middleware (outbound)", error=str(e))
            raise EventMiddlewareError(f"Metrics middleware failed: {str(e)}")
    
    async def process_inbound(self, event: EventMessage) -> EventMessage:
        """Record inbound event metrics."""
        try:
            if self.metrics_service:
                # Record event reception
                self.metrics_service.record_event_reception(
                    event_type=event.event_type,
                    direction="inbound",
                    status="processing"
                )
                
                # Calculate processing delay if outbound timestamp exists
                if "outbound_timestamp" in event.metadata:
                    try:
                        outbound_time = datetime.fromisoformat(
                            event.metadata["outbound_timestamp"]
                        )
                        processing_delay = (datetime.utcnow() - outbound_time).total_seconds()
                        self.metrics_service.record_event_processing_delay(
                            event_type=event.event_type,
                            delay=processing_delay
                        )
                    except Exception:
                        pass
            
            # Add timing metadata
            event.metadata["inbound_timestamp"] = datetime.utcnow().isoformat()
            event.metadata["target_service"] = self.service_name
            
            return event
        except Exception as e:
            self.logger.error("Error in metrics middleware (inbound)", error=str(e))
            raise EventMiddlewareError(f"Metrics middleware failed: {str(e)}")


class ValidationMiddleware(EventMiddleware):
    """Middleware for validating events."""
    
    def __init__(self, service_name: str, validation_rules: Optional[Dict[str, Any]] = None):
        self.service_name = service_name
        self.validation_rules = validation_rules or {}
        self.logger = structlog.get_logger().bind(
            service=service_name,
            component="event_validation"
        )
    
    async def process_outbound(self, event: EventMessage) -> EventMessage:
        """Validate outbound events."""
        try:
            # Basic validation
            if not event.event_type:
                raise EventMiddlewareError("Event type is required")
            
            if not event.source_service:
                raise EventMiddlewareError("Source service is required")
            
            # Apply custom validation rules
            if event.event_type in self.validation_rules:
                rules = self.validation_rules[event.event_type]
                self._apply_validation_rules(event, rules)
            
            return event
        except Exception as e:
            self.logger.error("Error in validation middleware (outbound)", error=str(e))
            raise EventMiddlewareError(f"Validation middleware failed: {str(e)}")
    
    async def process_inbound(self, event: EventMessage) -> EventMessage:
        """Validate inbound events."""
        try:
            # Basic validation
            if not event.event_type:
                raise EventMiddlewareError("Event type is required")
            
            if not event.source_service:
                raise EventMiddlewareError("Source service is required")
            
            # Apply custom validation rules
            if event.event_type in self.validation_rules:
                rules = self.validation_rules[event.event_type]
                self._apply_validation_rules(event, rules)
            
            return event
        except Exception as e:
            self.logger.error("Error in validation middleware (inbound)", error=str(e))
            raise EventMiddlewareError(f"Validation middleware failed: {str(e)}")
    
    def _apply_validation_rules(self, event: EventMessage, rules: Dict[str, Any]) -> None:
        """Apply validation rules to an event."""
        # Required fields validation
        if "required_fields" in rules:
            for field in rules["required_fields"]:
                if field not in event.data:
                    raise EventMiddlewareError(f"Required field '{field}' is missing")
        
        # Data type validation
        if "field_types" in rules:
            for field, expected_type in rules["field_types"].items():
                if field in event.data:
                    if not isinstance(event.data[field], expected_type):
                        raise EventMiddlewareError(
                            f"Field '{field}' must be of type {expected_type.__name__}"
                        )
        
        # Value validation
        if "allowed_values" in rules:
            for field, allowed_values in rules["allowed_values"].items():
                if field in event.data:
                    if event.data[field] not in allowed_values:
                        raise EventMiddlewareError(
                            f"Field '{field}' must be one of {allowed_values}"
                        )


class TracingMiddleware(EventMiddleware):
    """Middleware for adding tracing information to events."""
    
    def __init__(self, service_name: str, trace_id_header: str = "X-Trace-ID"):
        self.service_name = service_name
        self.trace_id_header = trace_id_header
        self.logger = structlog.get_logger().bind(
            service=service_name,
            component="event_tracing"
        )
    
    async def process_outbound(self, event: EventMessage) -> EventMessage:
        """Add tracing information to outbound events."""
        try:
            # Add trace information
            event.metadata["trace_id"] = event.correlation_id or event.event_id
            event.metadata["span_id"] = event.event_id
            event.metadata["parent_span_id"] = event.metadata.get("parent_span_id")
            event.metadata["trace_service"] = self.service_name
            
            return event
        except Exception as e:
            self.logger.error("Error in tracing middleware (outbound)", error=str(e))
            raise EventMiddlewareError(f"Tracing middleware failed: {str(e)}")
    
    async def process_inbound(self, event: EventMessage) -> EventMessage:
        """Process tracing information from inbound events."""
        try:
            # Update trace information
            event.metadata["parent_span_id"] = event.metadata.get("span_id")
            event.metadata["current_service"] = self.service_name
            
            return event
        except Exception as e:
            self.logger.error("Error in tracing middleware (inbound)", error=str(e))
            raise EventMiddlewareError(f"Tracing middleware failed: {str(e)}")


class RateLimitingMiddleware(EventMiddleware):
    """Middleware for rate limiting events."""
    
    def __init__(
        self,
        service_name: str,
        max_events_per_second: int = 100,
        max_events_per_minute: int = 1000,
    ):
        self.service_name = service_name
        self.max_events_per_second = max_events_per_second
        self.max_events_per_minute = max_events_per_minute
        self.event_counts = {
            "second": {},
            "minute": {},
        }
        self.logger = structlog.get_logger().bind(
            service=service_name,
            component="event_rate_limiting"
        )
    
    async def process_outbound(self, event: EventMessage) -> EventMessage:
        """Apply rate limiting to outbound events."""
        try:
            current_time = int(time.time())
            current_second = current_time
            current_minute = current_time // 60
            
            # Check per-second rate limit
            if current_second not in self.event_counts["second"]:
                self.event_counts["second"] = {current_second: 0}
            
            if self.event_counts["second"][current_second] >= self.max_events_per_second:
                raise EventMiddlewareError(
                    f"Rate limit exceeded: {self.max_events_per_second} events per second"
                )
            
            # Check per-minute rate limit
            if current_minute not in self.event_counts["minute"]:
                self.event_counts["minute"] = {current_minute: 0}
            
            if self.event_counts["minute"][current_minute] >= self.max_events_per_minute:
                raise EventMiddlewareError(
                    f"Rate limit exceeded: {self.max_events_per_minute} events per minute"
                )
            
            # Increment counters
            self.event_counts["second"][current_second] += 1
            self.event_counts["minute"][current_minute] += 1
            
            # Clean up old counters
            self._cleanup_counters(current_second, current_minute)
            
            return event
        except Exception as e:
            self.logger.error("Error in rate limiting middleware (outbound)", error=str(e))
            raise EventMiddlewareError(f"Rate limiting middleware failed: {str(e)}")
    
    async def process_inbound(self, event: EventMessage) -> EventMessage:
        """Process inbound events (no rate limiting applied)."""
        return event
    
    def _cleanup_counters(self, current_second: int, current_minute: int) -> None:
        """Clean up old counters to prevent memory leaks."""
        # Keep only last 10 seconds of data
        self.event_counts["second"] = {
            k: v for k, v in self.event_counts["second"].items()
            if k >= current_second - 10
        }
        
        # Keep only last 10 minutes of data
        self.event_counts["minute"] = {
            k: v for k, v in self.event_counts["minute"].items()
            if k >= current_minute - 10
        }


class TransformationMiddleware(EventMiddleware):
    """Middleware for transforming event data."""
    
    def __init__(
        self,
        service_name: str,
        transformations: Optional[Dict[str, Dict[str, Any]]] = None,
    ):
        self.service_name = service_name
        self.transformations = transformations or {}
        self.logger = structlog.get_logger().bind(
            service=service_name,
            component="event_transformation"
        )
    
    async def process_outbound(self, event: EventMessage) -> EventMessage:
        """Transform outbound events."""
        try:
            if event.event_type in self.transformations:
                transformations = self.transformations[event.event_type]
                event = self._apply_transformations(event, transformations)
            
            return event
        except Exception as e:
            self.logger.error("Error in transformation middleware (outbound)", error=str(e))
            raise EventMiddlewareError(f"Transformation middleware failed: {str(e)}")
    
    async def process_inbound(self, event: EventMessage) -> EventMessage:
        """Transform inbound events."""
        try:
            if event.event_type in self.transformations:
                transformations = self.transformations[event.event_type]
                event = self._apply_transformations(event, transformations)
            
            return event
        except Exception as e:
            self.logger.error("Error in transformation middleware (inbound)", error=str(e))
            raise EventMiddlewareError(f"Transformation middleware failed: {str(e)}")
    
    def _apply_transformations(
        self,
        event: EventMessage,
        transformations: Dict[str, Any]
    ) -> EventMessage:
        """Apply transformations to an event."""
        # Field mapping
        if "field_mapping" in transformations:
            for old_field, new_field in transformations["field_mapping"].items():
                if old_field in event.data:
                    event.data[new_field] = event.data.pop(old_field)
        
        # Value mapping
        if "value_mapping" in transformations:
            for field, value_map in transformations["value_mapping"].items():
                if field in event.data and event.data[field] in value_map:
                    event.data[field] = value_map[event.data[field]]
        
        # Add computed fields
        if "computed_fields" in transformations:
            for field, computation in transformations["computed_fields"].items():
                if computation["type"] == "concat":
                    fields = computation["fields"]
                    separator = computation.get("separator", " ")
                    values = [str(event.data.get(f, "")) for f in fields]
                    event.data[field] = separator.join(values)
                elif computation["type"] == "timestamp":
                    event.data[field] = datetime.utcnow().isoformat()
        
        return event