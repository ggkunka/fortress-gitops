"""
InfluxDB Models for Time-Series Metrics Storage

This module defines the data models and structures for storing time-series
security metrics in InfluxDB.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from dataclasses import dataclass, field
from pydantic import BaseModel, Field, validator

from shared.observability.logging import get_logger
from shared.config.settings import get_settings

logger = get_logger(__name__)


class MetricType(str, Enum):
    """Types of security metrics."""
    COUNTER = "counter"
    GAUGE = "gauge"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"
    TIMER = "timer"


class MetricCategory(str, Enum):
    """Categories of security metrics."""
    SECURITY = "security"
    PERFORMANCE = "performance"
    SYSTEM = "system"
    NETWORK = "network"
    APPLICATION = "application"
    COMPLIANCE = "compliance"
    THREAT = "threat"
    VULNERABILITY = "vulnerability"
    INCIDENT = "incident"
    AUDIT = "audit"


class Severity(str, Enum):
    """Severity levels for security metrics."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class MetricUnit(str, Enum):
    """Units for metric values."""
    COUNT = "count"
    PERCENTAGE = "percentage"
    BYTES = "bytes"
    SECONDS = "seconds"
    MILLISECONDS = "milliseconds"
    REQUESTS_PER_SECOND = "requests_per_second"
    ERRORS_PER_SECOND = "errors_per_second"
    BYTES_PER_SECOND = "bytes_per_second"


@dataclass
class MetricTag:
    """Represents a tag for categorizing metrics."""
    key: str
    value: str
    
    def __post_init__(self):
        if not self.key or not self.value:
            raise ValueError("Tag key and value cannot be empty")


@dataclass
class MetricField:
    """Represents a field in a metric measurement."""
    name: str
    value: Union[int, float, str, bool]
    unit: Optional[MetricUnit] = None
    
    def __post_init__(self):
        if not self.name:
            raise ValueError("Field name cannot be empty")


class SecurityMetric(BaseModel):
    """Base model for security metrics."""
    measurement: str = Field(..., description="InfluxDB measurement name")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    tags: Dict[str, str] = Field(default_factory=dict)
    fields: Dict[str, Union[int, float, str, bool]] = Field(default_factory=dict)
    category: MetricCategory = Field(...)
    metric_type: MetricType = Field(...)
    source: str = Field(..., description="Source system or service")
    description: Optional[str] = None
    
    @validator('timestamp')
    def validate_timestamp(cls, v):
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v
    
    @validator('tags')
    def validate_tags(cls, v):
        # Ensure all tag values are strings
        return {k: str(val) for k, val in v.items()}
    
    class Config:
        use_enum_values = True


class ThreatMetric(SecurityMetric):
    """Metric for threat detection events."""
    measurement: str = "threat_detection"
    category: MetricCategory = MetricCategory.THREAT
    metric_type: MetricType = MetricType.COUNTER
    
    threat_type: str = Field(..., description="Type of threat detected")
    severity: Severity = Field(...)
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score")
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    user_agent: Optional[str] = None
    attack_vector: Optional[str] = None
    mitre_technique: Optional[str] = None
    
    def __init__(self, **data):
        super().__init__(**data)
        self.tags.update({
            "threat_type": self.threat_type,
            "severity": self.severity,
            "attack_vector": self.attack_vector or "unknown",
            "mitre_technique": self.mitre_technique or "unknown"
        })
        self.fields.update({
            "confidence": self.confidence,
            "detected": 1
        })


class VulnerabilityMetric(SecurityMetric):
    """Metric for vulnerability assessment results."""
    measurement: str = "vulnerability_assessment"
    category: MetricCategory = MetricCategory.VULNERABILITY
    metric_type: MetricType = MetricType.GAUGE
    
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    severity: Severity = Field(...)
    component_name: str = Field(...)
    component_version: Optional[str] = None
    is_exploitable: bool = Field(default=False)
    has_patch: bool = Field(default=False)
    exploit_available: bool = Field(default=False)
    
    def __init__(self, **data):
        super().__init__(**data)
        self.tags.update({
            "cve_id": self.cve_id or "unknown",
            "severity": self.severity,
            "component_name": self.component_name,
            "component_version": self.component_version or "unknown"
        })
        self.fields.update({
            "cvss_score": self.cvss_score or 0.0,
            "is_exploitable": self.is_exploitable,
            "has_patch": self.has_patch,
            "exploit_available": self.exploit_available
        })


class IncidentMetric(SecurityMetric):
    """Metric for security incident tracking."""
    measurement: str = "security_incident"
    category: MetricCategory = MetricCategory.INCIDENT
    metric_type: MetricType = MetricType.COUNTER
    
    incident_id: str = Field(...)
    incident_type: str = Field(...)
    severity: Severity = Field(...)
    status: str = Field(...)
    assigned_to: Optional[str] = None
    response_time: Optional[float] = None  # seconds
    resolution_time: Optional[float] = None  # seconds
    affected_systems: Optional[List[str]] = Field(default_factory=list)
    
    def __init__(self, **data):
        super().__init__(**data)
        self.tags.update({
            "incident_id": self.incident_id,
            "incident_type": self.incident_type,
            "severity": self.severity,
            "status": self.status,
            "assigned_to": self.assigned_to or "unassigned"
        })
        self.fields.update({
            "response_time": self.response_time or 0.0,
            "resolution_time": self.resolution_time or 0.0,
            "affected_systems_count": len(self.affected_systems or [])
        })


class PerformanceMetric(SecurityMetric):
    """Metric for system performance monitoring."""
    measurement: str = "system_performance"
    category: MetricCategory = MetricCategory.PERFORMANCE
    metric_type: MetricType = MetricType.GAUGE
    
    cpu_usage: Optional[float] = Field(None, ge=0.0, le=100.0)
    memory_usage: Optional[float] = Field(None, ge=0.0, le=100.0)
    disk_usage: Optional[float] = Field(None, ge=0.0, le=100.0)
    network_in: Optional[float] = Field(None, ge=0.0)
    network_out: Optional[float] = Field(None, ge=0.0)
    response_time: Optional[float] = Field(None, ge=0.0)
    error_rate: Optional[float] = Field(None, ge=0.0, le=100.0)
    
    def __init__(self, **data):
        super().__init__(**data)
        self.fields.update({
            k: v for k, v in {
                "cpu_usage": self.cpu_usage,
                "memory_usage": self.memory_usage,
                "disk_usage": self.disk_usage,
                "network_in": self.network_in,
                "network_out": self.network_out,
                "response_time": self.response_time,
                "error_rate": self.error_rate
            }.items() if v is not None
        })


class ComplianceMetric(SecurityMetric):
    """Metric for compliance monitoring."""
    measurement: str = "compliance_check"
    category: MetricCategory = MetricCategory.COMPLIANCE
    metric_type: MetricType = MetricType.GAUGE
    
    framework: str = Field(..., description="Compliance framework (e.g., SOC2, ISO27001)")
    control_id: str = Field(..., description="Control identifier")
    compliance_score: float = Field(ge=0.0, le=100.0)
    is_compliant: bool = Field(...)
    violations_count: int = Field(ge=0)
    remediation_required: bool = Field(default=False)
    
    def __init__(self, **data):
        super().__init__(**data)
        self.tags.update({
            "framework": self.framework,
            "control_id": self.control_id,
            "is_compliant": str(self.is_compliant).lower()
        })
        self.fields.update({
            "compliance_score": self.compliance_score,
            "violations_count": self.violations_count,
            "remediation_required": self.remediation_required
        })


class NetworkMetric(SecurityMetric):
    """Metric for network security monitoring."""
    measurement: str = "network_security"
    category: MetricCategory = MetricCategory.NETWORK
    metric_type: MetricType = MetricType.COUNTER
    
    protocol: str = Field(...)
    source_ip: str = Field(...)
    destination_ip: str = Field(...)
    source_port: int = Field(...)
    destination_port: int = Field(...)
    bytes_transferred: int = Field(ge=0)
    packets_count: int = Field(ge=0)
    is_blocked: bool = Field(default=False)
    is_suspicious: bool = Field(default=False)
    threat_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    
    def __init__(self, **data):
        super().__init__(**data)
        self.tags.update({
            "protocol": self.protocol,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": str(self.source_port),
            "destination_port": str(self.destination_port),
            "is_blocked": str(self.is_blocked).lower(),
            "is_suspicious": str(self.is_suspicious).lower()
        })
        self.fields.update({
            "bytes_transferred": self.bytes_transferred,
            "packets_count": self.packets_count,
            "threat_score": self.threat_score or 0.0
        })


class AuditMetric(SecurityMetric):
    """Metric for audit trail events."""
    measurement: str = "audit_event"
    category: MetricCategory = MetricCategory.AUDIT
    metric_type: MetricType = MetricType.COUNTER
    
    event_type: str = Field(...)
    user_id: str = Field(...)
    resource: str = Field(...)
    action: str = Field(...)
    success: bool = Field(...)
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    
    def __init__(self, **data):
        super().__init__(**data)
        self.tags.update({
            "event_type": self.event_type,
            "user_id": self.user_id,
            "resource": self.resource,
            "action": self.action,
            "success": str(self.success).lower(),
            "source_ip": self.source_ip or "unknown"
        })
        self.fields.update({
            "event_count": 1
        })


class MetricQuery(BaseModel):
    """Query model for retrieving metrics."""
    measurement: str = Field(...)
    start_time: datetime = Field(...)
    end_time: datetime = Field(...)
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)
    fields: Optional[List[str]] = Field(default_factory=list)
    group_by: Optional[List[str]] = Field(default_factory=list)
    aggregation: Optional[str] = Field(None, regex="^(mean|sum|count|min|max|last|first)$")
    interval: Optional[str] = Field(None, regex="^\\d+[smhd]$")  # e.g., "5m", "1h", "1d"
    limit: Optional[int] = Field(None, ge=1, le=10000)
    
    @validator('start_time', 'end_time')
    def validate_timestamps(cls, v):
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v
    
    @validator('end_time')
    def validate_time_range(cls, v, values):
        if 'start_time' in values and v <= values['start_time']:
            raise ValueError("end_time must be after start_time")
        return v


class MetricAggregation(BaseModel):
    """Aggregated metric result."""
    measurement: str
    timestamp: datetime
    tags: Dict[str, str]
    value: Union[int, float]
    count: int
    
    @validator('timestamp')
    def validate_timestamp(cls, v):
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v


class MetricSummary(BaseModel):
    """Summary statistics for metrics."""
    measurement: str
    time_range: Dict[str, datetime]
    total_points: int
    avg_value: Optional[float] = None
    min_value: Optional[float] = None
    max_value: Optional[float] = None
    sum_value: Optional[float] = None
    percentiles: Optional[Dict[str, float]] = Field(default_factory=dict)
    tags_distribution: Optional[Dict[str, Dict[str, int]]] = Field(default_factory=dict)


# Metric factory functions
def create_threat_metric(
    threat_type: str,
    severity: Severity,
    confidence: float,
    source: str,
    **kwargs
) -> ThreatMetric:
    """Create a threat detection metric."""
    return ThreatMetric(
        threat_type=threat_type,
        severity=severity,
        confidence=confidence,
        source=source,
        **kwargs
    )


def create_vulnerability_metric(
    component_name: str,
    severity: Severity,
    source: str,
    **kwargs
) -> VulnerabilityMetric:
    """Create a vulnerability assessment metric."""
    return VulnerabilityMetric(
        component_name=component_name,
        severity=severity,
        source=source,
        **kwargs
    )


def create_incident_metric(
    incident_id: str,
    incident_type: str,
    severity: Severity,
    status: str,
    source: str,
    **kwargs
) -> IncidentMetric:
    """Create a security incident metric."""
    return IncidentMetric(
        incident_id=incident_id,
        incident_type=incident_type,
        severity=severity,
        status=status,
        source=source,
        **kwargs
    )


def create_performance_metric(
    source: str,
    **kwargs
) -> PerformanceMetric:
    """Create a system performance metric."""
    return PerformanceMetric(
        source=source,
        **kwargs
    )


def create_compliance_metric(
    framework: str,
    control_id: str,
    compliance_score: float,
    is_compliant: bool,
    violations_count: int,
    source: str,
    **kwargs
) -> ComplianceMetric:
    """Create a compliance monitoring metric."""
    return ComplianceMetric(
        framework=framework,
        control_id=control_id,
        compliance_score=compliance_score,
        is_compliant=is_compliant,
        violations_count=violations_count,
        source=source,
        **kwargs
    )


def create_network_metric(
    protocol: str,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    bytes_transferred: int,
    packets_count: int,
    source: str,
    **kwargs
) -> NetworkMetric:
    """Create a network security metric."""
    return NetworkMetric(
        protocol=protocol,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        bytes_transferred=bytes_transferred,
        packets_count=packets_count,
        source=source,
        **kwargs
    )


def create_audit_metric(
    event_type: str,
    user_id: str,
    resource: str,
    action: str,
    success: bool,
    source: str,
    **kwargs
) -> AuditMetric:
    """Create an audit event metric."""
    return AuditMetric(
        event_type=event_type,
        user_id=user_id,
        resource=resource,
        action=action,
        success=success,
        source=source,
        **kwargs
    )