"""
Prometheus metrics for MCP Security Platform.
"""

import time
import functools
from typing import Dict, Any, Optional, List, Callable, Union
from contextvars import ContextVar
from dataclasses import dataclass
from enum import Enum

from prometheus_client import (
    Counter, Histogram, Gauge, Summary, Info, Enum as PrometheusEnum,
    CollectorRegistry, generate_latest, CONTENT_TYPE_LATEST,
    start_http_server, REGISTRY
)
from prometheus_client.openmetrics.exposition import CONTENT_TYPE_LATEST as OPENMETRICS_CONTENT_TYPE

# Context variable for labels
metric_labels: ContextVar[Dict[str, str]] = ContextVar('metric_labels', default={})


class MetricType(Enum):
    """Enum for metric types."""
    COUNTER = "counter"
    HISTOGRAM = "histogram"
    GAUGE = "gauge"
    SUMMARY = "summary"
    INFO = "info"
    ENUM = "enum"


@dataclass
class MetricConfig:
    """Configuration for a metric."""
    name: str
    description: str
    labels: List[str]
    metric_type: MetricType
    buckets: Optional[List[float]] = None
    unit: Optional[str] = None
    namespace: Optional[str] = None
    subsystem: Optional[str] = None


class MetricsRegistry:
    """Registry for application metrics."""
    
    def __init__(self, namespace: str = "mcp", registry: Optional[CollectorRegistry] = None):
        self.namespace = namespace
        self.registry = registry or REGISTRY
        self.metrics: Dict[str, Any] = {}
        self._setup_default_metrics()
    
    def _setup_default_metrics(self):
        """Set up default application metrics."""
        
        # HTTP request metrics
        self.http_requests_total = self.counter(
            "http_requests_total",
            "Total HTTP requests",
            ["method", "endpoint", "status_code"]
        )
        
        self.http_request_duration = self.histogram(
            "http_request_duration_seconds",
            "HTTP request duration",
            ["method", "endpoint"],
            buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0]
        )
        
        self.http_request_size = self.histogram(
            "http_request_size_bytes",
            "HTTP request size",
            ["method", "endpoint"],
            buckets=[100, 1000, 10000, 100000, 1000000]
        )
        
        self.http_response_size = self.histogram(
            "http_response_size_bytes",
            "HTTP response size",
            ["method", "endpoint"],
            buckets=[100, 1000, 10000, 100000, 1000000]
        )
        
        # Database metrics
        self.db_connections_active = self.gauge(
            "database_connections_active",
            "Active database connections",
            ["database", "pool"]
        )
        
        self.db_query_duration = self.histogram(
            "database_query_duration_seconds",
            "Database query duration",
            ["operation", "table"],
            buckets=[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0]
        )
        
        self.db_queries_total = self.counter(
            "database_queries_total",
            "Total database queries",
            ["operation", "table", "status"]
        )
        
        # Cache metrics
        self.cache_operations_total = self.counter(
            "cache_operations_total",
            "Total cache operations",
            ["operation", "cache", "result"]
        )
        
        self.cache_hit_ratio = self.gauge(
            "cache_hit_ratio",
            "Cache hit ratio",
            ["cache"]
        )
        
        # Security metrics
        self.vulnerabilities_detected = self.counter(
            "vulnerabilities_detected_total",
            "Total vulnerabilities detected",
            ["severity", "component", "source"]
        )
        
        self.security_events_total = self.counter(
            "security_events_total",
            "Total security events",
            ["event_type", "severity", "source"]
        )
        
        self.authentication_attempts = self.counter(
            "authentication_attempts_total",
            "Total authentication attempts",
            ["method", "result"]
        )
        
        # Business metrics
        self.data_ingestion_total = self.counter(
            "data_ingestion_total",
            "Total data ingestion events",
            ["data_type", "source", "status"]
        )
        
        self.data_enrichment_duration = self.histogram(
            "data_enrichment_duration_seconds",
            "Data enrichment processing time",
            ["enrichment_type", "data_type"],
            buckets=[0.1, 0.5, 1.0, 5.0, 10.0, 30.0, 60.0]
        )
        
        self.analysis_jobs_total = self.counter(
            "analysis_jobs_total",
            "Total analysis jobs",
            ["analysis_type", "status"]
        )
        
        self.notifications_sent = self.counter(
            "notifications_sent_total",
            "Total notifications sent",
            ["channel", "severity", "status"]
        )
        
        # System metrics
        self.process_cpu_seconds = self.counter(
            "process_cpu_seconds_total",
            "Total CPU time spent"
        )
        
        self.process_memory_bytes = self.gauge(
            "process_memory_bytes",
            "Process memory usage",
            ["type"]
        )
        
        self.process_open_fds = self.gauge(
            "process_open_fds",
            "Number of open file descriptors"
        )
        
        # Plugin metrics
        self.plugin_executions_total = self.counter(
            "plugin_executions_total",
            "Total plugin executions",
            ["plugin_name", "plugin_type", "status"]
        )
        
        self.plugin_execution_duration = self.histogram(
            "plugin_execution_duration_seconds",
            "Plugin execution duration",
            ["plugin_name", "plugin_type"],
            buckets=[0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0]
        )
    
    def counter(self, name: str, description: str, labels: List[str] = None) -> Counter:
        """Create or get a counter metric."""
        full_name = f"{self.namespace}_{name}"
        if full_name not in self.metrics:
            self.metrics[full_name] = Counter(
                full_name, description, labels or [], registry=self.registry
            )
        return self.metrics[full_name]
    
    def histogram(self, name: str, description: str, labels: List[str] = None, 
                  buckets: List[float] = None) -> Histogram:
        """Create or get a histogram metric."""
        full_name = f"{self.namespace}_{name}"
        if full_name not in self.metrics:
            self.metrics[full_name] = Histogram(
                full_name, description, labels or [], 
                buckets=buckets, registry=self.registry
            )
        return self.metrics[full_name]
    
    def gauge(self, name: str, description: str, labels: List[str] = None) -> Gauge:
        """Create or get a gauge metric."""
        full_name = f"{self.namespace}_{name}"
        if full_name not in self.metrics:
            self.metrics[full_name] = Gauge(
                full_name, description, labels or [], registry=self.registry
            )
        return self.metrics[full_name]
    
    def summary(self, name: str, description: str, labels: List[str] = None) -> Summary:
        """Create or get a summary metric."""
        full_name = f"{self.namespace}_{name}"
        if full_name not in self.metrics:
            self.metrics[full_name] = Summary(
                full_name, description, labels or [], registry=self.registry
            )
        return self.metrics[full_name]
    
    def info(self, name: str, description: str) -> Info:
        """Create or get an info metric."""
        full_name = f"{self.namespace}_{name}"
        if full_name not in self.metrics:
            self.metrics[full_name] = Info(
                full_name, description, registry=self.registry
            )
        return self.metrics[full_name]
    
    def enum_metric(self, name: str, description: str, states: List[str], 
                   labels: List[str] = None) -> PrometheusEnum:
        """Create or get an enum metric."""
        full_name = f"{self.namespace}_{name}"
        if full_name not in self.metrics:
            self.metrics[full_name] = PrometheusEnum(
                full_name, description, states=states, 
                labelnames=labels or [], registry=self.registry
            )
        return self.metrics[full_name]
    
    def get_metrics_text(self) -> str:
        """Get metrics in Prometheus text format."""
        return generate_latest(self.registry).decode('utf-8')
    
    def start_metrics_server(self, port: int = 9090):
        """Start Prometheus metrics HTTP server."""
        start_http_server(port, registry=self.registry)


class PrometheusMetrics:
    """Main metrics class for services."""
    
    def __init__(self, service_name: str, registry: Optional[CollectorRegistry] = None):
        self.service_name = service_name
        self.registry = MetricsRegistry(namespace=service_name, registry=registry)
        
        # Service info
        self.service_info = self.registry.info(
            "service_info",
            "Service information"
        )
        
        # Set service info
        self.service_info.info({
            'service': service_name,
            'version': '1.0.0',  # This should come from config
        })
    
    def record_http_request(self, method: str, endpoint: str, status_code: int, 
                           duration: float, request_size: int = 0, response_size: int = 0):
        """Record HTTP request metrics."""
        labels = [method, endpoint, str(status_code)]
        
        self.registry.http_requests_total.labels(*labels).inc()
        self.registry.http_request_duration.labels(method, endpoint).observe(duration)
        
        if request_size > 0:
            self.registry.http_request_size.labels(method, endpoint).observe(request_size)
        
        if response_size > 0:
            self.registry.http_response_size.labels(method, endpoint).observe(response_size)
    
    def record_db_query(self, operation: str, table: str, duration: float, success: bool = True):
        """Record database query metrics."""
        status = "success" if success else "error"
        
        self.registry.db_queries_total.labels(operation, table, status).inc()
        self.registry.db_query_duration.labels(operation, table).observe(duration)
    
    def update_db_connections(self, database: str, pool: str, count: int):
        """Update database connection count."""
        self.registry.db_connections_active.labels(database, pool).set(count)
    
    def record_cache_operation(self, operation: str, cache: str, hit: bool):
        """Record cache operation."""
        result = "hit" if hit else "miss"
        self.registry.cache_operations_total.labels(operation, cache, result).inc()
    
    def update_cache_hit_ratio(self, cache: str, ratio: float):
        """Update cache hit ratio."""
        self.registry.cache_hit_ratio.labels(cache).set(ratio)
    
    def record_vulnerability(self, severity: str, component: str, source: str):
        """Record vulnerability detection."""
        self.registry.vulnerabilities_detected.labels(severity, component, source).inc()
    
    def record_security_event(self, event_type: str, severity: str, source: str):
        """Record security event."""
        self.registry.security_events_total.labels(event_type, severity, source).inc()
    
    def record_authentication(self, method: str, success: bool):
        """Record authentication attempt."""
        result = "success" if success else "failure"
        self.registry.authentication_attempts.labels(method, result).inc()
    
    def record_data_ingestion(self, data_type: str, source: str, success: bool):
        """Record data ingestion event."""
        status = "success" if success else "error"
        self.registry.data_ingestion_total.labels(data_type, source, status).inc()
    
    def record_enrichment_duration(self, enrichment_type: str, data_type: str, duration: float):
        """Record data enrichment duration."""
        self.registry.data_enrichment_duration.labels(enrichment_type, data_type).observe(duration)
    
    def record_analysis_job(self, analysis_type: str, success: bool):
        """Record analysis job completion."""
        status = "success" if success else "error"
        self.registry.analysis_jobs_total.labels(analysis_type, status).inc()
    
    def record_notification(self, channel: str, severity: str, success: bool):
        """Record notification sending."""
        status = "success" if success else "error"
        self.registry.notifications_sent.labels(channel, severity, status).inc()
    
    def record_plugin_execution(self, plugin_name: str, plugin_type: str, 
                               duration: float, success: bool):
        """Record plugin execution."""
        status = "success" if success else "error"
        
        self.registry.plugin_executions_total.labels(plugin_name, plugin_type, status).inc()
        self.registry.plugin_execution_duration.labels(plugin_name, plugin_type).observe(duration)
    
    def update_memory_usage(self, memory_type: str, bytes_used: int):
        """Update memory usage metrics."""
        self.registry.process_memory_bytes.labels(memory_type).set(bytes_used)
    
    def get_metrics(self) -> str:
        """Get metrics in Prometheus format."""
        return self.registry.get_metrics_text()


# Decorators for automatic metrics collection
def timed(metric_name: str = None, labels: Dict[str, str] = None):
    """
    Decorator to time function execution and record as histogram.
    
    Args:
        metric_name: Custom metric name (defaults to function name)
        labels: Additional labels for the metric
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            start_time = time.time()
            function_name = metric_name or f"{func.__module__}.{func.__name__}"
            
            # Get metrics registry from first argument if it's a class instance
            metrics = None
            if args and hasattr(args[0], 'metrics'):
                metrics = args[0].metrics
            
            try:
                result = await func(*args, **kwargs)
                success = True
                return result
            except Exception as e:
                success = False
                raise
            finally:
                duration = time.time() - start_time
                
                if metrics and hasattr(metrics.registry, 'function_duration'):
                    label_values = [function_name, str(success)]
                    if labels:
                        label_values.extend(labels.values())
                    
                    metrics.registry.function_duration.labels(*label_values).observe(duration)
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            start_time = time.time()
            function_name = metric_name or f"{func.__module__}.{func.__name__}"
            
            # Get metrics registry from first argument if it's a class instance
            metrics = None
            if args and hasattr(args[0], 'metrics'):
                metrics = args[0].metrics
            
            try:
                result = func(*args, **kwargs)
                success = True
                return result
            except Exception as e:
                success = False
                raise
            finally:
                duration = time.time() - start_time
                
                if metrics and hasattr(metrics.registry, 'function_duration'):
                    label_values = [function_name, str(success)]
                    if labels:
                        label_values.extend(labels.values())
                    
                    metrics.registry.function_duration.labels(*label_values).observe(duration)
        
        # Return appropriate wrapper based on function type
        import inspect
        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


def counted(metric_name: str = None, labels: Dict[str, str] = None):
    """
    Decorator to count function calls.
    
    Args:
        metric_name: Custom metric name (defaults to function name)
        labels: Additional labels for the metric
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        async def async_wrapper(*args, **kwargs):
            function_name = metric_name or f"{func.__module__}.{func.__name__}"
            
            # Get metrics registry from first argument if it's a class instance
            metrics = None
            if args and hasattr(args[0], 'metrics'):
                metrics = args[0].metrics
            
            try:
                result = await func(*args, **kwargs)
                success = True
                return result
            except Exception as e:
                success = False
                raise
            finally:
                if metrics and hasattr(metrics.registry, 'function_calls'):
                    label_values = [function_name, str(success)]
                    if labels:
                        label_values.extend(labels.values())
                    
                    metrics.registry.function_calls.labels(*label_values).inc()
        
        @functools.wraps(func)
        def sync_wrapper(*args, **kwargs):
            function_name = metric_name or f"{func.__module__}.{func.__name__}"
            
            # Get metrics registry from first argument if it's a class instance
            metrics = None
            if args and hasattr(args[0], 'metrics'):
                metrics = args[0].metrics
            
            try:
                result = func(*args, **kwargs)
                success = True
                return result
            except Exception as e:
                success = False
                raise
            finally:
                if metrics and hasattr(metrics.registry, 'function_calls'):
                    label_values = [function_name, str(success)]
                    if labels:
                        label_values.extend(labels.values())
                    
                    metrics.registry.function_calls.labels(*label_values).inc()
        
        # Return appropriate wrapper based on function type
        import inspect
        if inspect.iscoroutinefunction(func):
            return async_wrapper
        else:
            return sync_wrapper
    
    return decorator


class MetricsCollector:
    """Utility class for collecting custom metrics."""
    
    def __init__(self, metrics: PrometheusMetrics):
        self.metrics = metrics
    
    def collect_system_metrics(self):
        """Collect system-level metrics."""
        import psutil
        import os
        
        # Memory metrics
        process = psutil.Process(os.getpid())
        memory_info = process.memory_info()
        
        self.metrics.update_memory_usage("rss", memory_info.rss)
        self.metrics.update_memory_usage("vms", memory_info.vms)
        
        # File descriptor count
        try:
            fd_count = process.num_fds()
            self.metrics.registry.process_open_fds.set(fd_count)
        except AttributeError:
            # num_fds() not available on Windows
            pass
        
        # CPU time
        cpu_times = process.cpu_times()
        self.metrics.registry.process_cpu_seconds._value._value = cpu_times.user + cpu_times.system


# Global metrics instance (will be initialized by each service)
_global_metrics: Optional[PrometheusMetrics] = None


def init_metrics(service_name: str, registry: Optional[CollectorRegistry] = None) -> PrometheusMetrics:
    """Initialize global metrics instance."""
    global _global_metrics
    _global_metrics = PrometheusMetrics(service_name, registry)
    return _global_metrics


def get_metrics() -> Optional[PrometheusMetrics]:
    """Get global metrics instance."""
    return _global_metrics