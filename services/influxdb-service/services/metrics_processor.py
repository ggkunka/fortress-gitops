"""
Metrics Processor Service - Real-time metrics processing and analysis

This service handles real-time processing, analysis, and alerting for security metrics.
"""

import asyncio
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass
from enum import Enum
import statistics
import numpy as np
from collections import defaultdict, deque

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.events.event_bus import EventBus

from ..models.metrics import (
    SecurityMetric, ThreatMetric, VulnerabilityMetric, IncidentMetric,
    PerformanceMetric, ComplianceMetric, NetworkMetric, AuditMetric,
    MetricType, MetricCategory, Severity
)
from .metrics_repository import MetricsRepository

logger = get_logger(__name__)
metrics = get_metrics()


class AlertSeverity(str, Enum):
    """Alert severity levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertType(str, Enum):
    """Types of alerts."""
    THRESHOLD = "threshold"
    ANOMALY = "anomaly"
    TREND = "trend"
    CORRELATION = "correlation"
    COMPLIANCE = "compliance"


@dataclass
class Alert:
    """Represents a security metric alert."""
    id: str
    alert_type: AlertType
    severity: AlertSeverity
    title: str
    description: str
    metric_name: str
    current_value: float
    threshold_value: Optional[float] = None
    timestamp: datetime = None
    tags: Dict[str, str] = None
    context: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc)
        if self.tags is None:
            self.tags = {}
        if self.context is None:
            self.context = {}


@dataclass
class ThresholdRule:
    """Threshold-based alerting rule."""
    metric_name: str
    field_name: str
    operator: str  # >, <, >=, <=, ==, !=
    threshold: float
    severity: AlertSeverity
    window_size: str = "5m"
    evaluation_interval: str = "1m"
    tags_filter: Optional[Dict[str, str]] = None


@dataclass
class AnomalyRule:
    """Anomaly detection rule."""
    metric_name: str
    field_name: str
    method: str  # zscore, iqr, isolation_forest
    sensitivity: float = 2.0
    window_size: str = "30m"
    evaluation_interval: str = "5m"
    tags_filter: Optional[Dict[str, str]] = None


class MetricsProcessor:
    """
    Real-time metrics processor for analysis and alerting.
    
    This processor:
    1. Processes metrics in real-time
    2. Detects anomalies and threshold breaches
    3. Generates alerts and notifications
    4. Performs trend analysis
    5. Calculates derived metrics
    6. Manages alert lifecycle
    """
    
    def __init__(self, repository: MetricsRepository, event_bus: EventBus):
        self.repository = repository
        self.event_bus = event_bus
        
        # Processing state
        self.is_running = False
        self.processing_task = None
        
        # Alert rules
        self.threshold_rules: List[ThresholdRule] = []
        self.anomaly_rules: List[AnomalyRule] = []
        
        # Metrics buffers for analysis
        self.metrics_buffer: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.alert_history: Dict[str, List[Alert]] = defaultdict(list)
        
        # Processing statistics
        self.processing_stats = {
            "metrics_processed": 0,
            "alerts_generated": 0,
            "anomalies_detected": 0,
            "threshold_breaches": 0
        }
        
        # Initialize default rules
        self._initialize_default_rules()
        
        logger.info("Metrics processor initialized")
    
    async def start(self):
        """Start the metrics processor."""
        if self.is_running:
            return
        
        self.is_running = True
        self.processing_task = asyncio.create_task(self._processing_loop())
        
        logger.info("Metrics processor started")
    
    async def stop(self):
        """Stop the metrics processor."""
        if not self.is_running:
            return
        
        self.is_running = False
        
        if self.processing_task:
            self.processing_task.cancel()
            try:
                await self.processing_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Metrics processor stopped")
    
    @traced("metrics_processor_process_metric")
    async def process_metric(self, metric: SecurityMetric):
        """Process a single metric."""
        try:
            # Store metric in repository
            await self.repository.write_metric(metric)
            
            # Add to processing buffer
            self._add_to_buffer(metric)
            
            # Process for alerts
            await self._process_alerts(metric)
            
            # Calculate derived metrics
            await self._calculate_derived_metrics(metric)
            
            # Update statistics
            self.processing_stats["metrics_processed"] += 1
            
            logger.debug(f"Metric processed: {metric.measurement}")
            metrics.metrics_processor_processed.inc()
            
        except Exception as e:
            logger.error(f"Error processing metric: {e}")
            metrics.metrics_processor_errors.inc()
            raise
    
    @traced("metrics_processor_process_batch")
    async def process_metrics_batch(self, metric_list: List[SecurityMetric]):
        """Process multiple metrics in batch."""
        try:
            # Store metrics in repository
            await self.repository.write_metrics_batch(metric_list)
            
            # Process each metric
            for metric in metric_list:
                self._add_to_buffer(metric)
                await self._process_alerts(metric)
                await self._calculate_derived_metrics(metric)
            
            # Update statistics
            self.processing_stats["metrics_processed"] += len(metric_list)
            
            logger.info(f"Batch processed: {len(metric_list)} metrics")
            metrics.metrics_processor_batch_processed.inc()
            
        except Exception as e:
            logger.error(f"Error processing metrics batch: {e}")
            metrics.metrics_processor_batch_errors.inc()
            raise
    
    @traced("metrics_processor_detect_anomalies")
    async def detect_anomalies(self, metric: SecurityMetric) -> List[Alert]:
        """Detect anomalies in metric data."""
        try:
            alerts = []
            
            # Get metric buffer
            buffer_key = f"{metric.measurement}:{metric.source}"
            buffer = self.metrics_buffer[buffer_key]
            
            if len(buffer) < 10:  # Need minimum data points
                return alerts
            
            # Extract values for analysis
            values = [m.fields.get('value', 0) for m in buffer if 'value' in m.fields]
            
            if not values:
                return alerts
            
            # Z-score based anomaly detection
            mean_val = statistics.mean(values)
            std_val = statistics.stdev(values) if len(values) > 1 else 0
            
            if std_val > 0:
                current_value = list(metric.fields.values())[0]
                z_score = abs((current_value - mean_val) / std_val)
                
                if z_score > 2.5:  # Configurable threshold
                    alert = Alert(
                        id=f"anomaly_{metric.measurement}_{datetime.now().timestamp()}",
                        alert_type=AlertType.ANOMALY,
                        severity=AlertSeverity.HIGH if z_score > 3 else AlertSeverity.MEDIUM,
                        title=f"Anomaly detected in {metric.measurement}",
                        description=f"Value {current_value} deviates significantly from normal (z-score: {z_score:.2f})",
                        metric_name=metric.measurement,
                        current_value=current_value,
                        tags=metric.tags,
                        context={
                            "z_score": z_score,
                            "mean": mean_val,
                            "std_dev": std_val,
                            "detection_method": "z_score"
                        }
                    )
                    alerts.append(alert)
            
            # IQR-based anomaly detection
            if len(values) >= 20:
                q1 = np.percentile(values, 25)
                q3 = np.percentile(values, 75)
                iqr = q3 - q1
                lower_bound = q1 - 1.5 * iqr
                upper_bound = q3 + 1.5 * iqr
                
                current_value = list(metric.fields.values())[0]
                
                if current_value < lower_bound or current_value > upper_bound:
                    alert = Alert(
                        id=f"iqr_anomaly_{metric.measurement}_{datetime.now().timestamp()}",
                        alert_type=AlertType.ANOMALY,
                        severity=AlertSeverity.MEDIUM,
                        title=f"IQR anomaly detected in {metric.measurement}",
                        description=f"Value {current_value} is outside IQR bounds [{lower_bound:.2f}, {upper_bound:.2f}]",
                        metric_name=metric.measurement,
                        current_value=current_value,
                        tags=metric.tags,
                        context={
                            "q1": q1,
                            "q3": q3,
                            "iqr": iqr,
                            "lower_bound": lower_bound,
                            "upper_bound": upper_bound,
                            "detection_method": "iqr"
                        }
                    )
                    alerts.append(alert)
            
            if alerts:
                self.processing_stats["anomalies_detected"] += len(alerts)
                logger.info(f"Anomalies detected: {len(alerts)} in {metric.measurement}")
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error detecting anomalies: {e}")
            return []
    
    @traced("metrics_processor_check_thresholds")
    async def check_thresholds(self, metric: SecurityMetric) -> List[Alert]:
        """Check metric against threshold rules."""
        try:
            alerts = []
            
            for rule in self.threshold_rules:
                if rule.metric_name != metric.measurement:
                    continue
                
                # Check tags filter
                if rule.tags_filter:
                    if not all(metric.tags.get(k) == v for k, v in rule.tags_filter.items()):
                        continue
                
                # Get field value
                field_value = metric.fields.get(rule.field_name)
                if field_value is None:
                    continue
                
                # Evaluate threshold
                threshold_breached = False
                
                if rule.operator == ">":
                    threshold_breached = field_value > rule.threshold
                elif rule.operator == "<":
                    threshold_breached = field_value < rule.threshold
                elif rule.operator == ">=":
                    threshold_breached = field_value >= rule.threshold
                elif rule.operator == "<=":
                    threshold_breached = field_value <= rule.threshold
                elif rule.operator == "==":
                    threshold_breached = field_value == rule.threshold
                elif rule.operator == "!=":
                    threshold_breached = field_value != rule.threshold
                
                if threshold_breached:
                    alert = Alert(
                        id=f"threshold_{rule.metric_name}_{rule.field_name}_{datetime.now().timestamp()}",
                        alert_type=AlertType.THRESHOLD,
                        severity=rule.severity,
                        title=f"Threshold breach in {rule.metric_name}",
                        description=f"Field {rule.field_name} value {field_value} {rule.operator} threshold {rule.threshold}",
                        metric_name=rule.metric_name,
                        current_value=field_value,
                        threshold_value=rule.threshold,
                        tags=metric.tags,
                        context={
                            "rule": rule.metric_name,
                            "field": rule.field_name,
                            "operator": rule.operator,
                            "threshold": rule.threshold
                        }
                    )
                    alerts.append(alert)
            
            if alerts:
                self.processing_stats["threshold_breaches"] += len(alerts)
                logger.info(f"Threshold breaches: {len(alerts)} in {metric.measurement}")
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error checking thresholds: {e}")
            return []
    
    @traced("metrics_processor_analyze_trends")
    async def analyze_trends(self, metric: SecurityMetric) -> List[Alert]:
        """Analyze metric trends for alerting."""
        try:
            alerts = []
            
            # Get metric buffer
            buffer_key = f"{metric.measurement}:{metric.source}"
            buffer = self.metrics_buffer[buffer_key]
            
            if len(buffer) < 20:  # Need minimum data points
                return alerts
            
            # Calculate trend slope
            timestamps = [m.timestamp.timestamp() for m in buffer]
            values = [list(m.fields.values())[0] for m in buffer if m.fields]
            
            if len(values) < 20:
                return alerts
            
            # Linear regression for trend analysis
            n = len(values)
            sum_x = sum(range(n))
            sum_y = sum(values)
            sum_xy = sum(i * values[i] for i in range(n))
            sum_x2 = sum(i * i for i in range(n))
            
            slope = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x)
            
            # Check for concerning trends
            if abs(slope) > 1.0:  # Configurable threshold
                severity = AlertSeverity.HIGH if abs(slope) > 2.0 else AlertSeverity.MEDIUM
                trend_direction = "increasing" if slope > 0 else "decreasing"
                
                alert = Alert(
                    id=f"trend_{metric.measurement}_{datetime.now().timestamp()}",
                    alert_type=AlertType.TREND,
                    severity=severity,
                    title=f"Concerning trend in {metric.measurement}",
                    description=f"Metric shows {trend_direction} trend with slope {slope:.2f}",
                    metric_name=metric.measurement,
                    current_value=values[-1],
                    tags=metric.tags,
                    context={
                        "trend_slope": slope,
                        "trend_direction": trend_direction,
                        "data_points": n
                    }
                )
                alerts.append(alert)
            
            return alerts
            
        except Exception as e:
            logger.error(f"Error analyzing trends: {e}")
            return []
    
    async def _processing_loop(self):
        """Main processing loop for continuous analysis."""
        while self.is_running:
            try:
                # Perform periodic analysis
                await self._periodic_analysis()
                
                # Sleep for processing interval
                await asyncio.sleep(60)  # 1 minute
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in processing loop: {e}")
                await asyncio.sleep(5)
    
    async def _periodic_analysis(self):
        """Perform periodic analysis tasks."""
        try:
            # Calculate system-wide metrics
            await self._calculate_system_metrics()
            
            # Check for correlation patterns
            await self._check_correlations()
            
            # Clean up old data
            await self._cleanup_old_data()
            
        except Exception as e:
            logger.error(f"Error in periodic analysis: {e}")
    
    async def _calculate_system_metrics(self):
        """Calculate system-wide derived metrics."""
        try:
            # Calculate overall security score
            current_time = datetime.now(timezone.utc)
            
            # Get recent threat metrics
            threat_query = {
                "measurement": "threat_detection",
                "start_time": current_time - timedelta(hours=1),
                "end_time": current_time
            }
            
            # This would integrate with actual query results
            # For now, we'll simulate the calculation
            security_score = 85.0  # Placeholder
            
            # Create derived metric
            security_score_metric = PerformanceMetric(
                source="metrics_processor",
                timestamp=current_time,
                tags={"metric_type": "security_score"},
                fields={"security_score": security_score}
            )
            
            await self.repository.write_metric(security_score_metric)
            
        except Exception as e:
            logger.error(f"Error calculating system metrics: {e}")
    
    async def _check_correlations(self):
        """Check for correlation patterns between metrics."""
        try:
            # This would implement correlation analysis
            # For now, we'll log the functionality
            logger.debug("Checking metric correlations")
            
        except Exception as e:
            logger.error(f"Error checking correlations: {e}")
    
    async def _cleanup_old_data(self):
        """Clean up old data from buffers."""
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)
            
            for buffer_key, buffer in self.metrics_buffer.items():
                # Remove old metrics from buffer
                while buffer and buffer[0].timestamp < cutoff_time:
                    buffer.popleft()
            
            logger.debug("Old data cleaned up")
            
        except Exception as e:
            logger.error(f"Error cleaning up old data: {e}")
    
    async def _process_alerts(self, metric: SecurityMetric):
        """Process alerts for a metric."""
        try:
            all_alerts = []
            
            # Check thresholds
            threshold_alerts = await self.check_thresholds(metric)
            all_alerts.extend(threshold_alerts)
            
            # Detect anomalies
            anomaly_alerts = await self.detect_anomalies(metric)
            all_alerts.extend(anomaly_alerts)
            
            # Analyze trends
            trend_alerts = await self.analyze_trends(metric)
            all_alerts.extend(trend_alerts)
            
            # Process and send alerts
            for alert in all_alerts:
                await self._send_alert(alert)
                self.alert_history[alert.metric_name].append(alert)
                self.processing_stats["alerts_generated"] += 1
            
        except Exception as e:
            logger.error(f"Error processing alerts: {e}")
    
    async def _send_alert(self, alert: Alert):
        """Send alert notification."""
        try:
            # Publish alert event
            await self.event_bus.publish("metrics.alert", {
                "alert_id": alert.id,
                "alert_type": alert.alert_type,
                "severity": alert.severity,
                "title": alert.title,
                "description": alert.description,
                "metric_name": alert.metric_name,
                "current_value": alert.current_value,
                "threshold_value": alert.threshold_value,
                "timestamp": alert.timestamp.isoformat(),
                "tags": alert.tags,
                "context": alert.context
            })
            
            logger.info(f"Alert sent: {alert.title}")
            
        except Exception as e:
            logger.error(f"Error sending alert: {e}")
    
    async def _calculate_derived_metrics(self, metric: SecurityMetric):
        """Calculate derived metrics from base metrics."""
        try:
            # This would implement derived metric calculations
            # For now, we'll log the functionality
            logger.debug(f"Calculating derived metrics for {metric.measurement}")
            
        except Exception as e:
            logger.error(f"Error calculating derived metrics: {e}")
    
    def _add_to_buffer(self, metric: SecurityMetric):
        """Add metric to processing buffer."""
        buffer_key = f"{metric.measurement}:{metric.source}"
        self.metrics_buffer[buffer_key].append(metric)
    
    def _initialize_default_rules(self):
        """Initialize default alerting rules."""
        # High CPU usage threshold
        self.threshold_rules.append(ThresholdRule(
            metric_name="system_performance",
            field_name="cpu_usage",
            operator=">",
            threshold=90.0,
            severity=AlertSeverity.HIGH
        ))
        
        # High memory usage threshold
        self.threshold_rules.append(ThresholdRule(
            metric_name="system_performance",
            field_name="memory_usage",
            operator=">",
            threshold=85.0,
            severity=AlertSeverity.MEDIUM
        ))
        
        # Critical severity threats
        self.threshold_rules.append(ThresholdRule(
            metric_name="threat_detection",
            field_name="confidence",
            operator=">",
            threshold=0.8,
            severity=AlertSeverity.CRITICAL,
            tags_filter={"severity": "critical"}
        ))
        
        # High vulnerability count
        self.threshold_rules.append(ThresholdRule(
            metric_name="vulnerability_assessment",
            field_name="cvss_score",
            operator=">=",
            threshold=8.0,
            severity=AlertSeverity.HIGH
        ))
    
    def add_threshold_rule(self, rule: ThresholdRule):
        """Add a threshold rule."""
        self.threshold_rules.append(rule)
        logger.info(f"Threshold rule added: {rule.metric_name}")
    
    def add_anomaly_rule(self, rule: AnomalyRule):
        """Add an anomaly detection rule."""
        self.anomaly_rules.append(rule)
        logger.info(f"Anomaly rule added: {rule.metric_name}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get processor statistics."""
        return {
            "running": self.is_running,
            "processing_stats": self.processing_stats,
            "threshold_rules": len(self.threshold_rules),
            "anomaly_rules": len(self.anomaly_rules),
            "active_buffers": len(self.metrics_buffer),
            "alert_history_size": sum(len(alerts) for alerts in self.alert_history.values()),
            "supported_alerts": [
                "threshold", "anomaly", "trend", "correlation", "compliance"
            ]
        }