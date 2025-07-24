"""
Analytics Models

Database models for metrics, trends, anomalies, and baselines.
"""

from datetime import datetime, timedelta
from enum import Enum
from typing import Optional, Dict, Any, List

from sqlalchemy import Column, String, Text, JSON, Enum as SQLEnum, ForeignKey, Boolean, Integer, Float, Index, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import uuid

from .base import BaseModel


class MetricType(str, Enum):
    """Types of metrics."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"
    RATE = "rate"
    PERCENTAGE = "percentage"


class MetricUnit(str, Enum):
    """Metric units."""
    COUNT = "count"
    SECONDS = "seconds"
    MILLISECONDS = "milliseconds"
    BYTES = "bytes"
    MEGABYTES = "megabytes"
    GIGABYTES = "gigabytes"
    PERCENTAGE = "percentage"
    RATIO = "ratio"
    SCORE = "score"


class TrendDirection(str, Enum):
    """Trend directions."""
    INCREASING = "increasing"
    DECREASING = "decreasing"
    STABLE = "stable"
    VOLATILE = "volatile"
    UNKNOWN = "unknown"


class AnomalyType(str, Enum):
    """Types of anomalies."""
    SPIKE = "spike"
    DIP = "dip"
    TREND_CHANGE = "trend_change"
    SEASONAL_DEVIATION = "seasonal_deviation"
    PATTERN_BREAK = "pattern_break"
    OUTLIER = "outlier"


class AnomalySeverity(str, Enum):
    """Anomaly severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class BaselineType(str, Enum):
    """Types of baselines."""
    HISTORICAL = "historical"
    ROLLING = "rolling"
    SEASONAL = "seasonal"
    MANUAL = "manual"
    PEER_COMPARISON = "peer_comparison"


class Metric(BaseModel):
    """Metric entity for tracking quantitative data."""
    
    __tablename__ = "metrics"
    
    # Metric identification
    name = Column(String(200), nullable=False)
    display_name = Column(String(250), nullable=True)
    description = Column(Text, nullable=True)
    metric_type = Column(SQLEnum(MetricType), nullable=False)
    
    # Metric properties
    unit = Column(SQLEnum(MetricUnit), nullable=False)
    aggregation_method = Column(String(50), default="sum", nullable=False)  # sum, avg, max, min, count
    
    # Metric value and timing
    value = Column(Float, nullable=False)
    timestamp = Column(JSON, nullable=False)
    
    # Metric dimensions and labels
    labels = Column(JSONB, default=dict, nullable=False)  # Key-value pairs for grouping
    dimensions = Column(JSONB, default=dict, nullable=False)  # Additional dimensions
    
    # Source information
    source_service = Column(String(100), nullable=True)
    source_component = Column(String(100), nullable=True)
    collection_method = Column(String(50), nullable=True)  # push, pull, calculated
    
    # Metric context
    target_type = Column(String(100), nullable=True)  # scan, vulnerability, user, etc.
    target_id = Column(String(200), nullable=True)
    
    # Data quality
    confidence_score = Column(Float, default=1.0, nullable=False)
    data_quality_flags = Column(JSONB, default=list, nullable=False)
    
    # Organization context
    organization_id = Column(UUID(as_uuid=True), nullable=True)
    project_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_metrics_name_timestamp', 'name', 'timestamp'),
        Index('idx_metrics_target', 'target_type', 'target_id'),
        Index('idx_metrics_organization', 'organization_id'),
        Index('idx_metrics_labels', 'labels'),  # GIN index for JSONB
    )
    
    def _validate(self) -> List[str]:
        """Custom validation for metric model."""
        errors = []
        
        if not self.name or len(self.name.strip()) == 0:
            errors.append("Metric name cannot be empty")
        
        if self.confidence_score < 0 or self.confidence_score > 1:
            errors.append("Confidence score must be between 0 and 1")
            
        return errors
    
    def get_normalized_value(self) -> float:
        """Get value normalized to a standard scale (0-1 for percentages, etc.)."""
        if self.unit == MetricUnit.PERCENTAGE:
            return min(max(self.value / 100.0, 0.0), 1.0)
        elif self.unit == MetricUnit.RATIO:
            return min(max(self.value, 0.0), 1.0)
        else:
            return self.value
    
    def matches_labels(self, label_filters: Dict[str, str]) -> bool:
        """Check if metric matches label filters."""
        for key, value in label_filters.items():
            if key not in self.labels or self.labels[key] != value:
                return False
        return True
    
    def get_metric_key(self) -> str:
        """Get unique key for this metric including labels."""
        label_str = "&".join(f"{k}={v}" for k, v in sorted(self.labels.items()))
        return f"{self.name}?{label_str}" if label_str else self.name


class Trend(BaseModel):
    """Trend analysis entity."""
    
    __tablename__ = "trends"
    
    # Trend identification
    metric_name = Column(String(200), nullable=False)
    trend_id = Column(String(100), unique=True, nullable=False)
    
    # Trend period
    period_start = Column(JSON, nullable=False)
    period_end = Column(JSON, nullable=False)
    period_duration_days = Column(Integer, nullable=False)
    
    # Trend analysis
    direction = Column(SQLEnum(TrendDirection), nullable=False)
    slope = Column(Float, nullable=False)  # Rate of change
    correlation_coefficient = Column(Float, nullable=False)  # R-squared
    
    # Trend statistics
    start_value = Column(Float, nullable=False)
    end_value = Column(Float, nullable=False)
    min_value = Column(Float, nullable=False)
    max_value = Column(Float, nullable=False)
    average_value = Column(Float, nullable=False)
    variance = Column(Float, nullable=False)
    
    # Trend properties
    volatility = Column(Float, nullable=False)  # Standard deviation
    seasonality_detected = Column(Boolean, default=False, nullable=False)
    cycle_length_days = Column(Integer, nullable=True)
    
    # Confidence and quality
    confidence_score = Column(Float, nullable=False)
    data_points_count = Column(Integer, nullable=False)
    missing_data_percentage = Column(Float, default=0.0, nullable=False)
    
    # Trend context
    labels = Column(JSONB, default=dict, nullable=False)
    dimensions = Column(JSONB, default=dict, nullable=False)
    
    # Analysis metadata
    analysis_algorithm = Column(String(100), nullable=False)
    algorithm_parameters = Column(JSONB, default=dict, nullable=False)
    analyzed_at = Column(JSON, nullable=False)
    
    # Forecasting
    forecast_next_period = Column(Float, nullable=True)
    forecast_confidence = Column(Float, nullable=True)
    forecast_upper_bound = Column(Float, nullable=True)
    forecast_lower_bound = Column(Float, nullable=True)
    
    # Organization context
    organization_id = Column(UUID(as_uuid=True), nullable=True)
    project_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Indexes
    __table_args__ = (
        Index('idx_trends_metric_period', 'metric_name', 'period_start', 'period_end'),
        Index('idx_trends_direction', 'direction'),
        Index('idx_trends_confidence', 'confidence_score'),
    )
    
    def _validate(self) -> List[str]:
        """Custom validation for trend model."""
        errors = []
        
        if not self.trend_id or len(self.trend_id.strip()) == 0:
            errors.append("Trend ID cannot be empty")
        
        if not self.metric_name or len(self.metric_name.strip()) == 0:
            errors.append("Metric name cannot be empty")
        
        if self.correlation_coefficient < -1 or self.correlation_coefficient > 1:
            errors.append("Correlation coefficient must be between -1 and 1")
        
        if self.confidence_score < 0 or self.confidence_score > 1:
            errors.append("Confidence score must be between 0 and 1")
            
        return errors
    
    def is_significant(self) -> bool:
        """Check if trend is statistically significant."""
        return (
            self.confidence_score >= 0.8 and
            abs(self.correlation_coefficient) >= 0.7 and
            self.data_points_count >= 10
        )
    
    def get_change_percentage(self) -> float:
        """Calculate percentage change over the trend period."""
        if self.start_value == 0:
            return float('inf') if self.end_value > 0 else 0
        return ((self.end_value - self.start_value) / self.start_value) * 100
    
    def get_trend_strength(self) -> str:
        """Get qualitative assessment of trend strength."""
        abs_corr = abs(self.correlation_coefficient)
        if abs_corr >= 0.9:
            return "very_strong"
        elif abs_corr >= 0.7:
            return "strong"
        elif abs_corr >= 0.5:
            return "moderate"
        elif abs_corr >= 0.3:
            return "weak"
        else:
            return "very_weak"
    
    def predict_next_value(self, days_ahead: int = 1) -> Dict[str, float]:
        """Predict value for future date based on trend."""
        if not self.slope:
            return {"prediction": self.end_value, "confidence": 0.0}
        
        predicted_value = self.end_value + (self.slope * days_ahead)
        
        # Adjust confidence based on prediction distance
        confidence_decay = max(0.1, 1.0 - (days_ahead / 30.0))  # Decay over 30 days
        prediction_confidence = self.confidence_score * confidence_decay
        
        return {
            "prediction": predicted_value,
            "confidence": prediction_confidence,
            "days_ahead": days_ahead
        }


class Anomaly(BaseModel):
    """Anomaly detection entity."""
    
    __tablename__ = "anomalies"
    
    # Anomaly identification
    anomaly_id = Column(String(100), unique=True, nullable=False)
    metric_name = Column(String(200), nullable=False)
    anomaly_type = Column(SQLEnum(AnomalyType), nullable=False)
    
    # Anomaly timing
    detected_at = Column(JSON, nullable=False)
    start_time = Column(JSON, nullable=False)
    end_time = Column(JSON, nullable=True)
    duration_minutes = Column(Integer, nullable=True)
    
    # Anomaly properties
    severity = Column(SQLEnum(AnomalySeverity), nullable=False)
    confidence_score = Column(Float, nullable=False)
    deviation_score = Column(Float, nullable=False)  # How far from normal
    
    # Anomaly values
    anomalous_value = Column(Float, nullable=False)
    expected_value = Column(Float, nullable=False)
    baseline_value = Column(Float, nullable=True)
    deviation_percentage = Column(Float, nullable=False)
    
    # Detection details
    detection_algorithm = Column(String(100), nullable=False)
    algorithm_parameters = Column(JSONB, default=dict, nullable=False)
    detection_threshold = Column(Float, nullable=False)
    
    # Context information
    labels = Column(JSONB, default=dict, nullable=False)
    dimensions = Column(JSONB, default=dict, nullable=False)
    contributing_factors = Column(JSONB, default=list, nullable=False)
    
    # Resolution tracking
    is_resolved = Column(Boolean, default=False, nullable=False)
    resolved_at = Column(JSON, nullable=True)
    resolution_notes = Column(Text, nullable=True)
    false_positive = Column(Boolean, default=False, nullable=False)
    
    # Impact assessment
    business_impact = Column(String(50), nullable=True)
    affected_systems = Column(JSONB, default=list, nullable=False)
    impact_score = Column(Float, nullable=True)
    
    # Root cause analysis
    root_cause = Column(Text, nullable=True)
    related_events = Column(JSONB, default=list, nullable=False)
    correlation_id = Column(String(100), nullable=True)
    
    # Organization context
    organization_id = Column(UUID(as_uuid=True), nullable=True)
    project_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Indexes
    __table_args__ = (
        Index('idx_anomalies_metric_time', 'metric_name', 'detected_at'),
        Index('idx_anomalies_severity', 'severity'),
        Index('idx_anomalies_type', 'anomaly_type'),
        Index('idx_anomalies_confidence', 'confidence_score'),
        Index('idx_anomalies_resolved', 'is_resolved'),
    )
    
    def _validate(self) -> List[str]:
        """Custom validation for anomaly model."""
        errors = []
        
        if not self.anomaly_id or len(self.anomaly_id.strip()) == 0:
            errors.append("Anomaly ID cannot be empty")
        
        if not self.metric_name or len(self.metric_name.strip()) == 0:
            errors.append("Metric name cannot be empty")
        
        if self.confidence_score < 0 or self.confidence_score > 1:
            errors.append("Confidence score must be between 0 and 1")
        
        if self.deviation_score < 0:
            errors.append("Deviation score must be non-negative")
            
        return errors
    
    def calculate_severity(self) -> AnomalySeverity:
        """Calculate anomaly severity based on deviation and impact."""
        abs_deviation = abs(self.deviation_percentage)
        
        if abs_deviation >= 100 or self.confidence_score >= 0.95:
            self.severity = AnomalySeverity.CRITICAL
        elif abs_deviation >= 50 or self.confidence_score >= 0.9:
            self.severity = AnomalySeverity.HIGH
        elif abs_deviation >= 25 or self.confidence_score >= 0.8:
            self.severity = AnomalySeverity.MEDIUM
        elif abs_deviation >= 10 or self.confidence_score >= 0.7:
            self.severity = AnomalySeverity.LOW
        else:
            self.severity = AnomalySeverity.INFO
        
        return self.severity
    
    def resolve(self, notes: Optional[str] = None, false_positive: bool = False):
        """Mark anomaly as resolved."""
        self.is_resolved = True
        self.resolved_at = datetime.utcnow().isoformat()
        self.resolution_notes = notes
        self.false_positive = false_positive
    
    def is_actionable(self) -> bool:
        """Check if anomaly requires action."""
        return (
            not self.is_resolved and
            not self.false_positive and
            self.severity in [AnomalySeverity.CRITICAL, AnomalySeverity.HIGH] and
            self.confidence_score >= 0.8
        )
    
    def get_duration_hours(self) -> Optional[float]:
        """Get anomaly duration in hours."""
        if not self.duration_minutes:
            return None
        return self.duration_minutes / 60.0
    
    def is_ongoing(self) -> bool:
        """Check if anomaly is still ongoing."""
        return not self.end_time and not self.is_resolved


class Baseline(BaseModel):
    """Baseline entity for establishing normal behavior patterns."""
    
    __tablename__ = "baselines"
    
    # Baseline identification
    baseline_id = Column(String(100), unique=True, nullable=False)
    metric_name = Column(String(200), nullable=False)
    baseline_type = Column(SQLEnum(BaselineType), nullable=False)
    
    # Baseline period
    training_period_start = Column(JSON, nullable=False)
    training_period_end = Column(JSON, nullable=False)
    training_duration_days = Column(Integer, nullable=False)
    
    # Baseline statistics
    mean_value = Column(Float, nullable=False)
    median_value = Column(Float, nullable=False)
    standard_deviation = Column(Float, nullable=False)
    min_value = Column(Float, nullable=False)
    max_value = Column(Float, nullable=False)
    
    # Percentiles for anomaly detection
    percentile_5 = Column(Float, nullable=False)
    percentile_95 = Column(Float, nullable=False)
    percentile_99 = Column(Float, nullable=False)
    
    # Baseline quality
    data_points_count = Column(Integer, nullable=False)
    confidence_score = Column(Float, nullable=False)
    stability_score = Column(Float, nullable=False)
    
    # Seasonal patterns
    has_seasonality = Column(Boolean, default=False, nullable=False)
    seasonal_patterns = Column(JSONB, default=dict, nullable=False)
    seasonal_strength = Column(Float, nullable=True)
    
    # Context and filters
    labels = Column(JSONB, default=dict, nullable=False)
    dimensions = Column(JSONB, default=dict, nullable=False)
    
    # Baseline management
    is_active = Column(Boolean, default=True, nullable=False)
    created_at_analysis = Column(JSON, nullable=False)
    last_updated_analysis = Column(JSON, nullable=False)
    next_update_due = Column(JSON, nullable=True)
    
    # Update frequency
    update_frequency_days = Column(Integer, default=7, nullable=False)
    auto_update_enabled = Column(Boolean, default=True, nullable=False)
    
    # Validation metrics
    prediction_accuracy = Column(Float, nullable=True)
    false_positive_rate = Column(Float, nullable=True)
    false_negative_rate = Column(Float, nullable=True)
    
    # Organization context
    organization_id = Column(UUID(as_uuid=True), nullable=True)
    project_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Unique constraint
    __table_args__ = (
        UniqueConstraint('metric_name', 'baseline_type', 'labels', name='uq_baseline_metric_type'),
        Index('idx_baselines_metric', 'metric_name'),
        Index('idx_baselines_active', 'is_active'),
        Index('idx_baselines_update_due', 'next_update_due'),
    )
    
    def _validate(self) -> List[str]:
        """Custom validation for baseline model."""
        errors = []
        
        if not self.baseline_id or len(self.baseline_id.strip()) == 0:
            errors.append("Baseline ID cannot be empty")
        
        if not self.metric_name or len(self.metric_name.strip()) == 0:
            errors.append("Metric name cannot be empty")
        
        if self.confidence_score < 0 or self.confidence_score > 1:
            errors.append("Confidence score must be between 0 and 1")
        
        if self.data_points_count <= 0:
            errors.append("Data points count must be positive")
        
        if self.standard_deviation < 0:
            errors.append("Standard deviation must be non-negative")
            
        return errors
    
    def is_value_normal(self, value: float, sensitivity: float = 2.0) -> bool:
        """Check if a value is within normal baseline range."""
        lower_bound = self.mean_value - (sensitivity * self.standard_deviation)
        upper_bound = self.mean_value + (sensitivity * self.standard_deviation)
        return lower_bound <= value <= upper_bound
    
    def calculate_deviation_score(self, value: float) -> float:
        """Calculate how many standard deviations away from baseline."""
        if self.standard_deviation == 0:
            return 0.0
        return abs(value - self.mean_value) / self.standard_deviation
    
    def needs_update(self) -> bool:
        """Check if baseline needs updating."""
        if not self.auto_update_enabled or not self.next_update_due:
            return False
        
        update_due = datetime.fromisoformat(self.next_update_due.replace('Z', '+00:00'))
        return datetime.utcnow() >= update_due.replace(tzinfo=None)
    
    def schedule_next_update(self):
        """Schedule next baseline update."""
        next_update = datetime.utcnow() + timedelta(days=self.update_frequency_days)
        self.next_update_due = next_update.isoformat()
    
    def update_baseline(self, new_metrics: List[float]):
        """Update baseline with new metric data."""
        if not new_metrics:
            return
        
        # Recalculate statistics
        import statistics
        
        self.mean_value = statistics.mean(new_metrics)
        self.median_value = statistics.median(new_metrics)
        self.standard_deviation = statistics.stdev(new_metrics) if len(new_metrics) > 1 else 0.0
        self.min_value = min(new_metrics)
        self.max_value = max(new_metrics)
        
        # Calculate percentiles
        sorted_metrics = sorted(new_metrics)
        n = len(sorted_metrics)
        
        self.percentile_5 = sorted_metrics[int(0.05 * n)]
        self.percentile_95 = sorted_metrics[int(0.95 * n)]
        self.percentile_99 = sorted_metrics[int(0.99 * n)]
        
        # Update metadata
        self.data_points_count = len(new_metrics)
        self.last_updated_analysis = datetime.utcnow().isoformat()
        self.schedule_next_update()
        
        # Recalculate confidence based on data stability
        self.calculate_confidence_score()
    
    def calculate_confidence_score(self):
        """Calculate baseline confidence based on data quality and stability."""
        base_confidence = 0.5
        
        # Data quantity factor
        if self.data_points_count >= 100:
            quantity_factor = 1.0
        elif self.data_points_count >= 50:
            quantity_factor = 0.9
        elif self.data_points_count >= 20:
            quantity_factor = 0.8
        else:
            quantity_factor = 0.6
        
        # Stability factor (lower standard deviation relative to mean is better)
        if self.mean_value != 0:
            cv = self.standard_deviation / abs(self.mean_value)  # Coefficient of variation
            stability_factor = max(0.5, 1.0 - min(cv, 1.0))
        else:
            stability_factor = 0.7
        
        # Training period factor (longer periods are better)
        if self.training_duration_days >= 30:
            period_factor = 1.0
        elif self.training_duration_days >= 14:
            period_factor = 0.9
        elif self.training_duration_days >= 7:
            period_factor = 0.8
        else:
            period_factor = 0.6
        
        self.confidence_score = base_confidence * quantity_factor * stability_factor * period_factor
        self.stability_score = stability_factor
    
    def get_normal_range(self, confidence_level: float = 0.95) -> Dict[str, float]:
        """Get normal value range for given confidence level."""
        if confidence_level == 0.95:
            return {"lower": self.percentile_5, "upper": self.percentile_95}
        elif confidence_level == 0.99:
            return {"lower": self.percentile_5, "upper": self.percentile_99}
        else:
            # Use standard deviation approach
            z_score = 1.96 if confidence_level == 0.95 else 2.58  # 99%
            margin = z_score * self.standard_deviation
            return {
                "lower": self.mean_value - margin,
                "upper": self.mean_value + margin
            }