"""
Distributed tracing with OpenTelemetry for MCP Security Platform.
"""

import os
import functools
from typing import Dict, Any, Optional, Callable, Union
from dataclasses import dataclass
from contextlib import contextmanager

from opentelemetry import trace, baggage
from opentelemetry.sdk.trace import TracerProvider, Span
from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
from opentelemetry.sdk.resources import Resource, SERVICE_NAME, SERVICE_VERSION
from opentelemetry.exporter.jaeger.thrift import JaegerExporter
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.instrumentation.httpx import HTTPXClientInstrumentor
from opentelemetry.instrumentation.psycopg2 import Psycopg2Instrumentor
from opentelemetry.instrumentation.redis import RedisInstrumentor
from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor
from opentelemetry.propagate import inject, extract
from opentelemetry.trace.propagation.tracecontext import TraceContextTextMapPropagator
from opentelemetry.baggage.propagation import W3CBaggagePropagator
from opentelemetry.propagators.composite import CompositeHTTPPropagator
from opentelemetry.trace import Status, StatusCode
from opentelemetry.semconv.trace import SpanAttributes


@dataclass
class TracingConfig:
    """Configuration for distributed tracing."""
    service_name: str
    service_version: str = "1.0.0"
    environment: str = "production"
    
    # Jaeger configuration
    jaeger_endpoint: Optional[str] = None
    jaeger_agent_host: str = "localhost"
    jaeger_agent_port: int = 6831
    
    # OTLP configuration  
    otlp_endpoint: Optional[str] = None
    otlp_headers: Dict[str, str] = None
    
    # Sampling configuration
    sampling_ratio: float = 1.0
    
    # Export configuration
    export_console: bool = False
    export_jaeger: bool = True
    export_otlp: bool = False
    
    # Instrumentation configuration
    instrument_fastapi: bool = True
    instrument_httpx: bool = True
    instrument_database: bool = True
    instrument_redis: bool = True


class TracingSetup:
    """Setup and configuration for distributed tracing."""
    
    def __init__(self, config: TracingConfig):
        self.config = config
        self.tracer_provider = None
        self.tracer = None
        self._setup_tracing()
    
    def _setup_tracing(self):
        """Setup OpenTelemetry tracing."""
        
        # Create resource
        resource = Resource.create({
            SERVICE_NAME: self.config.service_name,
            SERVICE_VERSION: self.config.service_version,
            "environment": self.config.environment,
            "service.instance.id": os.getenv("HOSTNAME", "unknown"),
        })
        
        # Create tracer provider
        self.tracer_provider = TracerProvider(resource=resource)
        
        # Setup exporters
        self._setup_exporters()
        
        # Set global tracer provider
        trace.set_tracer_provider(self.tracer_provider)
        
        # Setup propagators
        self._setup_propagators()
        
        # Setup instrumentations
        self._setup_instrumentations()
        
        # Get tracer
        self.tracer = trace.get_tracer(__name__)
    
    def _setup_exporters(self):
        """Setup span exporters."""
        
        if self.config.export_console:
            console_exporter = ConsoleSpanExporter()
            span_processor = BatchSpanProcessor(console_exporter)
            self.tracer_provider.add_span_processor(span_processor)
        
        if self.config.export_jaeger:
            if self.config.jaeger_endpoint:
                jaeger_exporter = JaegerExporter(
                    collector_endpoint=self.config.jaeger_endpoint,
                )
            else:
                jaeger_exporter = JaegerExporter(
                    agent_host_name=self.config.jaeger_agent_host,
                    agent_port=self.config.jaeger_agent_port,
                )
            
            span_processor = BatchSpanProcessor(jaeger_exporter)
            self.tracer_provider.add_span_processor(span_processor)
        
        if self.config.export_otlp and self.config.otlp_endpoint:
            otlp_exporter = OTLPSpanExporter(
                endpoint=self.config.otlp_endpoint,
                headers=self.config.otlp_headers or {}
            )
            span_processor = BatchSpanProcessor(otlp_exporter)
            self.tracer_provider.add_span_processor(span_processor)
    
    def _setup_propagators(self):
        """Setup trace propagators."""
        from opentelemetry import propagate
        
        propagate.set_global_textmap(
            CompositeHTTPPropagator([
                TraceContextTextMapPropagator(),
                W3CBaggagePropagator(),
            ])
        )
    
    def _setup_instrumentations(self):
        """Setup automatic instrumentation."""
        
        if self.config.instrument_fastapi:
            try:
                FastAPIInstrumentor().instrument()
            except Exception:
                pass  # FastAPI not available
        
        if self.config.instrument_httpx:
            try:
                HTTPXClientInstrumentor().instrument()
            except Exception:
                pass  # httpx not available
        
        if self.config.instrument_database:
            try:
                Psycopg2Instrumentor().instrument()
                SQLAlchemyInstrumentor().instrument()
            except Exception:
                pass  # Database libraries not available
        
        if self.config.instrument_redis:
            try:
                RedisInstrumentor().instrument()
            except Exception:
                pass  # Redis not available


class TracingContext:
    """Context manager for tracing operations."""
    
    def __init__(self, 
                 operation_name: str,
                 attributes: Dict[str, Any] = None,
                 baggage_items: Dict[str, str] = None,
                 parent_span: Optional[Span] = None):
        self.operation_name = operation_name
        self.attributes = attributes or {}
        self.baggage_items = baggage_items or {}
        self.parent_span = parent_span
        self.span = None
        self.token = None
    
    def __enter__(self) -> Span:
        tracer = trace.get_tracer(__name__)
        
        # Create span
        if self.parent_span:
            self.span = tracer.start_span(
                self.operation_name,
                context=trace.set_span_in_context(self.parent_span)
            )
        else:
            self.span = tracer.start_span(self.operation_name)
        
        # Set attributes
        for key, value in self.attributes.items():
            self.span.set_attribute(key, value)
        
        # Set baggage
        current_baggage = baggage.get_all()
        for key, value in self.baggage_items.items():
            current_baggage[key] = value
        
        if current_baggage:
            self.token = baggage.set_baggage_in_context(current_baggage)
        
        return self.span
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.span.set_status(Status(StatusCode.ERROR, str(exc_val)))
            self.span.record_exception(exc_val)
        else:
            self.span.set_status(Status(StatusCode.OK))
        
        self.span.end()


class SecurityTracing:
    """Security-specific tracing utilities."""
    
    @staticmethod
    def trace_authentication(user_id: str, method: str, success: bool) -> Dict[str, Any]:
        """Create tracing attributes for authentication events."""
        return {
            SpanAttributes.ENDUSER_ID: user_id,
            "auth.method": method,
            "auth.success": success,
            "event.type": "authentication"
        }
    
    @staticmethod
    def trace_authorization(user_id: str, resource: str, action: str, success: bool) -> Dict[str, Any]:
        """Create tracing attributes for authorization events."""
        return {
            SpanAttributes.ENDUSER_ID: user_id,
            "authz.resource": resource,
            "authz.action": action,
            "authz.success": success,
            "event.type": "authorization"
        }
    
    @staticmethod
    def trace_vulnerability_detection(vulnerability_id: str, severity: str, component: str) -> Dict[str, Any]:
        """Create tracing attributes for vulnerability detection."""
        return {
            "vulnerability.id": vulnerability_id,
            "vulnerability.severity": severity,
            "vulnerability.component": component,
            "event.type": "vulnerability_detection"
        }
    
    @staticmethod
    def trace_threat_analysis(threat_type: str, confidence: float, source: str) -> Dict[str, Any]:
        """Create tracing attributes for threat analysis."""
        return {
            "threat.type": threat_type,
            "threat.confidence": confidence,
            "threat.source": source,
            "event.type": "threat_analysis"
        }


class DataProcessingTracing:
    """Data processing specific tracing utilities."""
    
    @staticmethod
    def trace_data_ingestion(data_type: str, source: str, record_count: int) -> Dict[str, Any]:
        """Create tracing attributes for data ingestion."""
        return {
            "data.type": data_type,
            "data.source": source,
            "data.record_count": record_count,
            "event.type": "data_ingestion"
        }
    
    @staticmethod
    def trace_data_enrichment(enrichment_type: str, data_type: str, 
                             input_count: int, output_count: int) -> Dict[str, Any]:
        """Create tracing attributes for data enrichment."""
        return {
            "enrichment.type": enrichment_type,
            "data.type": data_type,
            "data.input_count": input_count,
            "data.output_count": output_count,
            "event.type": "data_enrichment"
        }
    
    @staticmethod
    def trace_data_analysis(analysis_type: str, data_type: str, findings_count: int) -> Dict[str, Any]:
        """Create tracing attributes for data analysis."""
        return {
            "analysis.type": analysis_type,
            "data.type": data_type,
            "analysis.findings_count": findings_count,
            "event.type": "data_analysis"
        }


def traced(operation_name: str = None, 
           attributes: Dict[str, Any] = None,
           record_exception: bool = True):
    """
    Decorator to automatically trace function execution.
    
    Args:
        operation_name: Name of the operation (defaults to function name)
        attributes: Additional attributes to add to span
        record_exception: Whether to record exceptions in span
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            op_name = operation_name or f"{func.__module__}.{func.__name__}"
            tracer = trace.get_tracer(__name__)
            
            with tracer.start_as_current_span(op_name) as span:
                # Add function attributes
                span.set_attribute("function.name", func.__name__)
                span.set_attribute("function.module", func.__module__)
                
                # Add custom attributes
                if attributes:
                    for key, value in attributes.items():
                        span.set_attribute(key, value)
                
                # Add arguments if they're safe to log
                safe_kwargs = {k: v for k, v in kwargs.items() 
                             if not any(sensitive in k.lower() 
                                      for sensitive in ['password', 'secret', 'token', 'key'])}
                
                if safe_kwargs:
                    span.set_attribute("function.kwargs", str(safe_kwargs))
                
                try:
                    result = await func(*args, **kwargs)
                    span.set_status(Status(StatusCode.OK))
                    return result
                except Exception as e:
                    if record_exception:
                        span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    raise
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            op_name = operation_name or f"{func.__module__}.{func.__name__}"
            tracer = trace.get_tracer(__name__)
            
            with tracer.start_as_current_span(op_name) as span:
                # Add function attributes
                span.set_attribute("function.name", func.__name__)
                span.set_attribute("function.module", func.__module__)
                
                # Add custom attributes
                if attributes:
                    for key, value in attributes.items():
                        span.set_attribute(key, value)
                
                # Add arguments if they're safe to log
                safe_kwargs = {k: v for k, v in kwargs.items() 
                             if not any(sensitive in k.lower() 
                                      for sensitive in ['password', 'secret', 'token', 'key'])}
                
                if safe_kwargs:
                    span.set_attribute("function.kwargs", str(safe_kwargs))
                
                try:
                    result = func(*args, **kwargs)
                    span.set_status(Status(StatusCode.OK))
                    return result
                except Exception as e:
                    if record_exception:
                        span.record_exception(e)
                    span.set_status(Status(StatusCode.ERROR, str(e)))
                    raise
        
        # Return appropriate wrapper based on function type
        import inspect
        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


@contextmanager
def trace_operation(operation_name: str, **attributes):
    """Context manager for tracing operations."""
    tracer = trace.get_tracer(__name__)
    
    with tracer.start_as_current_span(operation_name) as span:
        # Add attributes
        for key, value in attributes.items():
            span.set_attribute(key, value)
        
        try:
            yield span
            span.set_status(Status(StatusCode.OK))
        except Exception as e:
            span.record_exception(e)
            span.set_status(Status(StatusCode.ERROR, str(e)))
            raise


def add_span_attributes(span: Span, attributes: Dict[str, Any]):
    """Add multiple attributes to a span."""
    for key, value in attributes.items():
        span.set_attribute(key, value)


def add_span_event(span: Span, name: str, attributes: Dict[str, Any] = None):
    """Add an event to a span."""
    span.add_event(name, attributes or {})


def get_current_span() -> Optional[Span]:
    """Get the current active span."""
    return trace.get_current_span()


def get_trace_id() -> Optional[str]:
    """Get the current trace ID."""
    span = trace.get_current_span()
    if span and span.get_span_context().is_valid:
        return format(span.get_span_context().trace_id, '032x')
    return None


def get_span_id() -> Optional[str]:
    """Get the current span ID."""
    span = trace.get_current_span()
    if span and span.get_span_context().is_valid:
        return format(span.get_span_context().span_id, '016x')
    return None


def inject_trace_context(headers: Dict[str, str]) -> Dict[str, str]:
    """Inject trace context into HTTP headers."""
    inject(headers)
    return headers


def extract_trace_context(headers: Dict[str, str]) -> Any:
    """Extract trace context from HTTP headers."""
    return extract(headers)


class HTTPTracing:
    """HTTP-specific tracing utilities."""
    
    @staticmethod
    def trace_http_request(method: str, url: str, status_code: int, 
                          request_size: int = None, response_size: int = None) -> Dict[str, Any]:
        """Create tracing attributes for HTTP requests."""
        attributes = {
            SpanAttributes.HTTP_METHOD: method,
            SpanAttributes.HTTP_URL: url,
            SpanAttributes.HTTP_STATUS_CODE: status_code,
        }
        
        if request_size is not None:
            attributes[SpanAttributes.HTTP_REQUEST_CONTENT_LENGTH] = request_size
        
        if response_size is not None:
            attributes[SpanAttributes.HTTP_RESPONSE_CONTENT_LENGTH] = response_size
        
        return attributes
    
    @staticmethod
    def trace_database_operation(operation: str, database: str, table: str = None) -> Dict[str, Any]:
        """Create tracing attributes for database operations."""
        attributes = {
            SpanAttributes.DB_OPERATION: operation,
            SpanAttributes.DB_NAME: database,
            SpanAttributes.DB_SYSTEM: "postgresql",
        }
        
        if table:
            attributes[SpanAttributes.DB_SQL_TABLE] = table
        
        return attributes


def setup_tracing(config: TracingConfig) -> TracingSetup:
    """Setup distributed tracing with given configuration."""
    return TracingSetup(config)


def get_tracer(name: str) -> trace.Tracer:
    """Get a tracer for the given name."""
    return trace.get_tracer(name)


# Convenience functions for common tracing patterns
def trace_security_event(event_type: str, **attributes):
    """Trace a security event."""
    return trace_operation(f"security.{event_type}", event_type="security", **attributes)


def trace_data_processing(process_type: str, **attributes):
    """Trace a data processing operation."""
    return trace_operation(f"data.{process_type}", process_type="data_processing", **attributes)


def trace_external_call(service: str, operation: str, **attributes):
    """Trace an external service call."""
    return trace_operation(f"external.{service}.{operation}", 
                          service=service, operation=operation, **attributes)


# Global tracing setup instance
_global_tracing_setup: Optional[TracingSetup] = None


def init_tracing(config: TracingConfig) -> TracingSetup:
    """Initialize global tracing setup."""
    global _global_tracing_setup
    _global_tracing_setup = setup_tracing(config)
    return _global_tracing_setup


def get_tracing_setup() -> Optional[TracingSetup]:
    """Get global tracing setup instance."""
    return _global_tracing_setup