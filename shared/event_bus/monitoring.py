"""Event bus monitoring and health checks."""

import asyncio
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from collections import defaultdict, deque

import structlog
from .base import EventBusBase, EventMessage

logger = structlog.get_logger()


class EventBusMonitor:
    """Monitor for event bus health and performance."""
    
    def __init__(self, event_bus: EventBusBase, max_metrics_history: int = 1000):
        self.event_bus = event_bus
        self.logger = logger.bind(component="event_bus_monitor")
        
        # Metrics storage
        self.max_metrics_history = max_metrics_history
        self.message_metrics = deque(maxlen=max_metrics_history)
        self.error_metrics = deque(maxlen=max_metrics_history)
        self.latency_metrics = deque(maxlen=max_metrics_history)
        
        # Counters
        self.total_messages_published = 0
        self.total_messages_received = 0
        self.total_errors = 0
        self.total_subscriptions = 0
        
        # Event type counters
        self.event_type_counters = defaultdict(int)
        self.subscription_counters = defaultdict(int)
        
        # Health check configuration
        self.health_check_interval = 30  # seconds
        self.max_error_rate = 0.1  # 10% error rate threshold
        self.max_latency_ms = 5000  # 5 second latency threshold
        
        # Monitoring state
        self.is_monitoring = False
        self.monitor_task: Optional[asyncio.Task] = None
        
        # Alert callbacks
        self.alert_callbacks: List[Callable[[str, Dict[str, Any]], None]] = []
    
    def add_alert_callback(self, callback: Callable[[str, Dict[str, Any]], None]) -> None:
        """Add callback for alerts."""
        self.alert_callbacks.append(callback)
    
    def remove_alert_callback(self, callback: Callable[[str, Dict[str, Any]], None]) -> None:
        """Remove alert callback."""
        if callback in self.alert_callbacks:
            self.alert_callbacks.remove(callback)
    
    async def start_monitoring(self) -> None:
        """Start monitoring the event bus."""
        if self.is_monitoring:
            return
        
        self.is_monitoring = True
        self.monitor_task = asyncio.create_task(self._monitor_loop())
        self.logger.info("Event bus monitoring started")
    
    async def stop_monitoring(self) -> None:
        """Stop monitoring the event bus."""
        if not self.is_monitoring:
            return
        
        self.is_monitoring = False
        
        if self.monitor_task:
            self.monitor_task.cancel()
            try:
                await self.monitor_task
            except asyncio.CancelledError:
                pass
        
        self.logger.info("Event bus monitoring stopped")
    
    async def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        while self.is_monitoring:
            try:
                await self._perform_health_check()
                await asyncio.sleep(self.health_check_interval)
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error("Error in monitoring loop", error=str(e))
                await asyncio.sleep(5)  # Brief pause before retrying
    
    async def _perform_health_check(self) -> None:
        """Perform health check and trigger alerts if needed."""
        try:
            health_status = await self.get_health_status()
            
            # Check error rate
            if health_status["error_rate"] > self.max_error_rate:
                await self._trigger_alert(
                    "high_error_rate",
                    {
                        "error_rate": health_status["error_rate"],
                        "threshold": self.max_error_rate,
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )
            
            # Check latency
            if health_status["avg_latency_ms"] > self.max_latency_ms:
                await self._trigger_alert(
                    "high_latency",
                    {
                        "avg_latency_ms": health_status["avg_latency_ms"],
                        "threshold": self.max_latency_ms,
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )
            
            # Check connection status
            if not health_status["connection_healthy"]:
                await self._trigger_alert(
                    "connection_unhealthy",
                    {
                        "connection_status": health_status["connection_status"],
                        "timestamp": datetime.utcnow().isoformat(),
                    }
                )
            
        except Exception as e:
            self.logger.error("Error performing health check", error=str(e))
    
    async def _trigger_alert(self, alert_type: str, alert_data: Dict[str, Any]) -> None:
        """Trigger alert callbacks."""
        self.logger.warning(f"Event bus alert: {alert_type}", **alert_data)
        
        for callback in self.alert_callbacks:
            try:
                if asyncio.iscoroutinefunction(callback):
                    await callback(alert_type, alert_data)
                else:
                    callback(alert_type, alert_data)
            except Exception as e:
                self.logger.error("Error in alert callback", error=str(e))
    
    def record_message_published(self, event_type: str, latency_ms: float = 0.0) -> None:
        """Record a published message."""
        timestamp = datetime.utcnow()
        
        self.total_messages_published += 1
        self.event_type_counters[event_type] += 1
        
        self.message_metrics.append({
            "type": "published",
            "event_type": event_type,
            "timestamp": timestamp,
            "latency_ms": latency_ms,
        })
        
        if latency_ms > 0:
            self.latency_metrics.append({
                "latency_ms": latency_ms,
                "timestamp": timestamp,
                "operation": "publish",
                "event_type": event_type,
            })
    
    def record_message_received(self, event_type: str, latency_ms: float = 0.0) -> None:
        """Record a received message."""
        timestamp = datetime.utcnow()
        
        self.total_messages_received += 1
        
        self.message_metrics.append({
            "type": "received",
            "event_type": event_type,
            "timestamp": timestamp,
            "latency_ms": latency_ms,
        })
        
        if latency_ms > 0:
            self.latency_metrics.append({
                "latency_ms": latency_ms,
                "timestamp": timestamp,
                "operation": "receive",
                "event_type": event_type,
            })
    
    def record_subscription(self, event_pattern: str) -> None:
        """Record a new subscription."""
        self.total_subscriptions += 1
        self.subscription_counters[event_pattern] += 1
    
    def record_error(self, error_type: str, error_message: str, context: Dict[str, Any] = None) -> None:
        """Record an error."""
        timestamp = datetime.utcnow()
        
        self.total_errors += 1
        
        self.error_metrics.append({
            "error_type": error_type,
            "error_message": error_message,
            "timestamp": timestamp,
            "context": context or {},
        })
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get current health status."""
        now = datetime.utcnow()
        last_hour = now - timedelta(hours=1)
        
        # Get metrics from last hour
        recent_messages = [m for m in self.message_metrics if m["timestamp"] > last_hour]
        recent_errors = [e for e in self.error_metrics if e["timestamp"] > last_hour]
        recent_latencies = [l for l in self.latency_metrics if l["timestamp"] > last_hour]
        
        # Calculate error rate
        total_recent_messages = len(recent_messages)
        total_recent_errors = len(recent_errors)
        error_rate = total_recent_errors / max(total_recent_messages, 1)
        
        # Calculate average latency
        if recent_latencies:
            avg_latency_ms = sum(l["latency_ms"] for l in recent_latencies) / len(recent_latencies)
        else:
            avg_latency_ms = 0.0
        
        # Check connection health
        connection_healthy = True
        connection_status = "healthy"
        
        try:
            # Test connection with a simple operation
            if hasattr(self.event_bus, 'health_check'):
                health_result = await self.event_bus.health_check()
                connection_healthy = health_result.get("status") == "healthy"
                connection_status = health_result.get("status", "unknown")
        except Exception as e:
            connection_healthy = False
            connection_status = f"error: {str(e)}"
        
        return {
            "overall_status": "healthy" if connection_healthy and error_rate <= self.max_error_rate and avg_latency_ms <= self.max_latency_ms else "unhealthy",
            "connection_healthy": connection_healthy,
            "connection_status": connection_status,
            "error_rate": error_rate,
            "avg_latency_ms": avg_latency_ms,
            "total_messages_published": self.total_messages_published,
            "total_messages_received": self.total_messages_received,
            "total_errors": self.total_errors,
            "total_subscriptions": self.total_subscriptions,
            "recent_messages_count": total_recent_messages,
            "recent_errors_count": total_recent_errors,
            "timestamp": now.isoformat(),
        }
    
    def get_metrics_summary(self, time_window_hours: int = 1) -> Dict[str, Any]:
        """Get metrics summary for a time window."""
        now = datetime.utcnow()
        window_start = now - timedelta(hours=time_window_hours)
        
        # Filter metrics by time window
        window_messages = [m for m in self.message_metrics if m["timestamp"] > window_start]
        window_errors = [e for e in self.error_metrics if e["timestamp"] > window_start]
        window_latencies = [l for l in self.latency_metrics if l["timestamp"] > window_start]
        
        # Message statistics
        published_count = len([m for m in window_messages if m["type"] == "published"])
        received_count = len([m for m in window_messages if m["type"] == "received"])
        
        # Event type distribution
        event_type_distribution = defaultdict(int)
        for message in window_messages:
            event_type_distribution[message["event_type"]] += 1
        
        # Error statistics
        error_distribution = defaultdict(int)
        for error in window_errors:
            error_distribution[error["error_type"]] += 1
        
        # Latency statistics
        latencies = [l["latency_ms"] for l in window_latencies]
        latency_stats = {}
        
        if latencies:
            latencies.sort()
            latency_stats = {
                "min_ms": min(latencies),
                "max_ms": max(latencies),
                "avg_ms": sum(latencies) / len(latencies),
                "p50_ms": latencies[len(latencies) // 2] if latencies else 0,
                "p95_ms": latencies[int(len(latencies) * 0.95)] if latencies else 0,
                "p99_ms": latencies[int(len(latencies) * 0.99)] if latencies else 0,
            }
        
        return {
            "time_window_hours": time_window_hours,
            "window_start": window_start.isoformat(),
            "window_end": now.isoformat(),
            "message_stats": {
                "total_messages": len(window_messages),
                "published_count": published_count,
                "received_count": received_count,
                "messages_per_hour": len(window_messages) / time_window_hours,
            },
            "event_type_distribution": dict(event_type_distribution),
            "error_stats": {
                "total_errors": len(window_errors),
                "error_distribution": dict(error_distribution),
                "error_rate": len(window_errors) / max(len(window_messages), 1),
            },
            "latency_stats": latency_stats,
            "subscription_stats": {
                "total_subscriptions": self.total_subscriptions,
                "subscription_distribution": dict(self.subscription_counters),
            },
        }
    
    def get_real_time_stats(self) -> Dict[str, Any]:
        """Get real-time statistics."""
        now = datetime.utcnow()
        last_minute = now - timedelta(minutes=1)
        
        # Get very recent metrics
        recent_messages = [m for m in self.message_metrics if m["timestamp"] > last_minute]
        recent_errors = [e for e in self.error_metrics if e["timestamp"] > last_minute]
        
        return {
            "timestamp": now.isoformat(),
            "messages_last_minute": len(recent_messages),
            "errors_last_minute": len(recent_errors),
            "messages_per_second": len(recent_messages) / 60,
            "total_lifetime_messages": self.total_messages_published + self.total_messages_received,
            "total_lifetime_errors": self.total_errors,
            "monitoring_active": self.is_monitoring,
        }


class EventBusHealthChecker:
    """Standalone health checker for event bus."""
    
    def __init__(self, event_bus: EventBusBase):
        self.event_bus = event_bus
        self.logger = logger.bind(component="event_bus_health_checker")
    
    async def ping_test(self, timeout_seconds: float = 5.0) -> Dict[str, Any]:
        """Perform a ping test to check basic connectivity."""
        start_time = datetime.utcnow()
        
        try:
            # Test basic connection
            if hasattr(self.event_bus, 'health_check'):
                result = await asyncio.wait_for(
                    self.event_bus.health_check(),
                    timeout=timeout_seconds
                )
            else:
                # Fallback: try to check connection status
                result = {"status": "healthy" if self.event_bus.is_connected else "disconnected"}
            
            latency = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            return {
                "test": "ping",
                "status": "success",
                "latency_ms": latency,
                "result": result,
                "timestamp": datetime.utcnow().isoformat(),
            }
            
        except asyncio.TimeoutError:
            return {
                "test": "ping",
                "status": "timeout",
                "timeout_seconds": timeout_seconds,
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            return {
                "test": "ping",
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }
    
    async def publish_test(self, timeout_seconds: float = 5.0) -> Dict[str, Any]:
        """Test publishing a message."""
        start_time = datetime.utcnow()
        
        try:
            test_data = {
                "test": "health_check",
                "timestamp": start_time.isoformat(),
            }
            
            await asyncio.wait_for(
                self.event_bus.publish(
                    event_type="health.test",
                    data=test_data,
                    correlation_id=f"health_check_{start_time.timestamp()}"
                ),
                timeout=timeout_seconds
            )
            
            latency = (datetime.utcnow() - start_time).total_seconds() * 1000
            
            return {
                "test": "publish",
                "status": "success",
                "latency_ms": latency,
                "timestamp": datetime.utcnow().isoformat(),
            }
            
        except asyncio.TimeoutError:
            return {
                "test": "publish",
                "status": "timeout",
                "timeout_seconds": timeout_seconds,
                "timestamp": datetime.utcnow().isoformat(),
            }
        except Exception as e:
            return {
                "test": "publish",
                "status": "error",
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat(),
            }
    
    async def comprehensive_health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check."""
        overall_start = datetime.utcnow()
        
        # Run all tests
        ping_result = await self.ping_test()
        publish_result = await self.publish_test()
        
        # Determine overall status
        test_results = [ping_result, publish_result]
        successful_tests = [r for r in test_results if r["status"] == "success"]
        
        overall_status = "healthy" if len(successful_tests) == len(test_results) else "unhealthy"
        
        total_time = (datetime.utcnow() - overall_start).total_seconds() * 1000
        
        return {
            "overall_status": overall_status,
            "total_time_ms": total_time,
            "tests_passed": len(successful_tests),
            "tests_total": len(test_results),
            "test_results": {
                "ping": ping_result,
                "publish": publish_result,
            },
            "timestamp": datetime.utcnow().isoformat(),
        }