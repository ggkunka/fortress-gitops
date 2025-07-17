"""Metrics service for ingestion monitoring."""

import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional
from collections import defaultdict, Counter

import structlog
from prometheus_client import Counter as PrometheusCounter, Histogram, Gauge, CollectorRegistry

logger = structlog.get_logger()


class MetricsService:
    """Service for collecting and managing ingestion metrics."""
    
    def __init__(self, registry: Optional[CollectorRegistry] = None):
        """Initialize metrics service."""
        self.registry = registry or CollectorRegistry()
        self.start_time = datetime.utcnow()
        
        # Initialize Prometheus metrics
        self._init_prometheus_metrics()
        
        # Internal metrics storage
        self.metrics_data = {
            "ingestion_requests": defaultdict(int),
            "validation_results": defaultdict(int),
            "event_publications": defaultdict(int),
            "processing_times": defaultdict(list),
            "error_counts": defaultdict(int),
            "data_sizes": defaultdict(list),
        }
    
    def _init_prometheus_metrics(self):
        """Initialize Prometheus metrics."""
        # Counters
        self.ingestion_requests_total = PrometheusCounter(
            'ingestion_requests_total',
            'Total number of ingestion requests',
            ['data_type', 'status'],
            registry=self.registry
        )
        
        self.validation_results_total = PrometheusCounter(
            'validation_results_total',
            'Total number of validation results',
            ['data_type', 'result'],
            registry=self.registry
        )
        
        self.events_published_total = PrometheusCounter(
            'events_published_total',
            'Total number of events published',
            ['event_type', 'status'],
            registry=self.registry
        )
        
        self.errors_total = PrometheusCounter(
            'errors_total',
            'Total number of errors',
            ['error_type', 'component'],
            registry=self.registry
        )
        
        # Histograms
        self.request_duration_seconds = Histogram(
            'request_duration_seconds',
            'Request duration in seconds',
            ['data_type', 'endpoint'],
            registry=self.registry
        )
        
        self.validation_duration_seconds = Histogram(
            'validation_duration_seconds',
            'Validation duration in seconds',
            ['data_type'],
            registry=self.registry
        )
        
        self.event_publishing_duration_seconds = Histogram(
            'event_publishing_duration_seconds',
            'Event publishing duration in seconds',
            ['event_type'],
            registry=self.registry
        )
        
        self.data_size_bytes = Histogram(
            'data_size_bytes',
            'Size of ingested data in bytes',
            ['data_type'],
            registry=self.registry
        )
        
        # Gauges
        self.active_connections = Gauge(
            'active_connections',
            'Number of active connections',
            registry=self.registry
        )
        
        self.queue_size = Gauge(
            'queue_size',
            'Current queue size',
            ['queue_type'],
            registry=self.registry
        )
        
        self.last_successful_ingestion = Gauge(
            'last_successful_ingestion_timestamp',
            'Timestamp of last successful ingestion',
            ['data_type'],
            registry=self.registry
        )
    
    def record_ingestion_request(self, data_type: str, status: str):
        """Record an ingestion request."""
        self.ingestion_requests_total.labels(data_type=data_type, status=status).inc()
        self.metrics_data["ingestion_requests"][f"{data_type}_{status}"] += 1
        
        if status == "success":
            self.last_successful_ingestion.labels(data_type=data_type).set(time.time())
    
    def record_validation_result(self, data_type: str, result: str):
        """Record a validation result."""
        self.validation_results_total.labels(data_type=data_type, result=result).inc()
        self.metrics_data["validation_results"][f"{data_type}_{result}"] += 1
    
    def record_event_publication(self, event_type: str, status: str):
        """Record an event publication."""
        self.events_published_total.labels(event_type=event_type, status=status).inc()
        self.metrics_data["event_publications"][f"{event_type}_{status}"] += 1
    
    def record_error(self, error_type: str, component: str):
        """Record an error."""
        self.errors_total.labels(error_type=error_type, component=component).inc()
        self.metrics_data["error_counts"][f"{error_type}_{component}"] += 1
    
    def record_request_duration(self, data_type: str, endpoint: str, duration: float):
        """Record request duration."""
        self.request_duration_seconds.labels(data_type=data_type, endpoint=endpoint).observe(duration)
        self.metrics_data["processing_times"][f"{data_type}_{endpoint}"].append(duration)
    
    def record_validation_duration(self, data_type: str, duration: float):
        """Record validation duration."""
        self.validation_duration_seconds.labels(data_type=data_type).observe(duration)
        self.metrics_data["processing_times"][f"validation_{data_type}"].append(duration)
    
    def record_event_publishing_duration(self, event_type: str, duration: float):
        """Record event publishing duration."""
        self.event_publishing_duration_seconds.labels(event_type=event_type).observe(duration)
        self.metrics_data["processing_times"][f"event_{event_type}"].append(duration)
    
    def record_data_size(self, data_type: str, size_bytes: int):
        """Record data size."""
        self.data_size_bytes.labels(data_type=data_type).observe(size_bytes)
        self.metrics_data["data_sizes"][data_type].append(size_bytes)
    
    def set_active_connections(self, count: int):
        """Set active connections count."""
        self.active_connections.set(count)
    
    def set_queue_size(self, queue_type: str, size: int):
        """Set queue size."""
        self.queue_size.labels(queue_type=queue_type).set(size)
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get metrics summary."""
        uptime = datetime.utcnow() - self.start_time
        
        summary = {
            "uptime_seconds": uptime.total_seconds(),
            "timestamp": datetime.utcnow().isoformat(),
            "ingestion_requests": dict(self.metrics_data["ingestion_requests"]),
            "validation_results": dict(self.metrics_data["validation_results"]),
            "event_publications": dict(self.metrics_data["event_publications"]),
            "error_counts": dict(self.metrics_data["error_counts"]),
        }
        
        # Calculate processing time statistics
        processing_stats = {}
        for key, times in self.metrics_data["processing_times"].items():
            if times:
                processing_stats[key] = {
                    "count": len(times),
                    "min": min(times),
                    "max": max(times),
                    "avg": sum(times) / len(times),
                }
        summary["processing_times"] = processing_stats
        
        # Calculate data size statistics
        data_size_stats = {}
        for data_type, sizes in self.metrics_data["data_sizes"].items():
            if sizes:
                data_size_stats[data_type] = {
                    "count": len(sizes),
                    "min": min(sizes),
                    "max": max(sizes),
                    "avg": sum(sizes) / len(sizes),
                    "total": sum(sizes),
                }
        summary["data_sizes"] = data_size_stats
        
        return summary
    
    def get_health_metrics(self) -> Dict[str, Any]:
        """Get health-related metrics."""
        recent_errors = sum(
            count for key, count in self.metrics_data["error_counts"].items()
            if count > 0
        )
        
        total_requests = sum(self.metrics_data["ingestion_requests"].values())
        total_validations = sum(self.metrics_data["validation_results"].values())
        total_events = sum(self.metrics_data["event_publications"].values())
        
        return {
            "status": "healthy" if recent_errors == 0 else "degraded",
            "total_requests": total_requests,
            "total_validations": total_validations,
            "total_events_published": total_events,
            "total_errors": recent_errors,
            "uptime_seconds": (datetime.utcnow() - self.start_time).total_seconds(),
            "timestamp": datetime.utcnow().isoformat(),
        }
    
    def get_data_type_metrics(self, data_type: str) -> Dict[str, Any]:
        """Get metrics for a specific data type."""
        metrics = {
            "data_type": data_type,
            "requests": {},
            "validations": {},
            "events": {},
            "processing_times": {},
            "data_sizes": {},
        }
        
        # Filter metrics for this data type
        for key, value in self.metrics_data["ingestion_requests"].items():
            if key.startswith(f"{data_type}_"):
                status = key.replace(f"{data_type}_", "")
                metrics["requests"][status] = value
        
        for key, value in self.metrics_data["validation_results"].items():
            if key.startswith(f"{data_type}_"):
                result = key.replace(f"{data_type}_", "")
                metrics["validations"][result] = value
        
        for key, value in self.metrics_data["event_publications"].items():
            if key.startswith(f"{data_type}_"):
                status = key.replace(f"{data_type}_", "")
                metrics["events"][status] = value
        
        # Processing times
        for key, times in self.metrics_data["processing_times"].items():
            if key.startswith(data_type) and times:
                metrics["processing_times"][key] = {
                    "count": len(times),
                    "min": min(times),
                    "max": max(times),
                    "avg": sum(times) / len(times),
                }
        
        # Data sizes
        if data_type in self.metrics_data["data_sizes"]:
            sizes = self.metrics_data["data_sizes"][data_type]
            if sizes:
                metrics["data_sizes"] = {
                    "count": len(sizes),
                    "min": min(sizes),
                    "max": max(sizes),
                    "avg": sum(sizes) / len(sizes),
                    "total": sum(sizes),
                }
        
        return metrics
    
    def reset_metrics(self):
        """Reset all metrics."""
        logger.info("Resetting metrics")
        
        # Reset internal metrics
        self.metrics_data = {
            "ingestion_requests": defaultdict(int),
            "validation_results": defaultdict(int),
            "event_publications": defaultdict(int),
            "processing_times": defaultdict(list),
            "error_counts": defaultdict(int),
            "data_sizes": defaultdict(list),
        }
        
        # Reset start time
        self.start_time = datetime.utcnow()
    
    def cleanup_old_data(self, max_age_hours: int = 24):
        """Clean up old metrics data."""
        cutoff_time = datetime.utcnow() - timedelta(hours=max_age_hours)
        
        # For now, we'll just limit the size of processing times and data sizes
        max_entries = 1000
        
        for key, times in self.metrics_data["processing_times"].items():
            if len(times) > max_entries:
                self.metrics_data["processing_times"][key] = times[-max_entries:]
        
        for key, sizes in self.metrics_data["data_sizes"].items():
            if len(sizes) > max_entries:
                self.metrics_data["data_sizes"][key] = sizes[-max_entries:]
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on metrics service."""
        return {
            "service": "metrics",
            "status": "healthy",
            "uptime_seconds": (datetime.utcnow() - self.start_time).total_seconds(),
            "registry_collectors": len(self.registry._collector_to_names),
            "timestamp": datetime.utcnow().isoformat(),
        }