"""
ClickHouse Models for OLAP Analytics

This module defines the data models and structures for storing analytical data
in ClickHouse for high-performance OLAP queries.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Union
from enum import Enum
from dataclasses import dataclass, field
from pydantic import BaseModel, Field, validator
import uuid

from shared.observability.logging import get_logger
from shared.config.settings import get_settings

logger = get_logger(__name__)


class AnalyticsTable(str, Enum):
    """Analytics table names in ClickHouse."""
    SECURITY_EVENTS = "security_events"
    THREAT_INTELLIGENCE = "threat_intelligence"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    NETWORK_FLOWS = "network_flows"
    USER_BEHAVIOR = "user_behavior"
    COMPLIANCE_AUDIT = "compliance_audit"
    INCIDENT_ANALYSIS = "incident_analysis"
    PERFORMANCE_METRICS = "performance_metrics"
    ASSET_INVENTORY = "asset_inventory"
    RISK_ASSESSMENT = "risk_assessment"


class EventType(str, Enum):
    """Types of security events."""
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    NETWORK_ACCESS = "network_access"
    FILE_ACCESS = "file_access"
    SYSTEM_CHANGE = "system_change"
    MALWARE_DETECTION = "malware_detection"
    INTRUSION_ATTEMPT = "intrusion_attempt"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"


class ThreatLevel(str, Enum):
    """Threat severity levels."""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ComplianceFramework(str, Enum):
    """Compliance frameworks."""
    SOC2 = "soc2"
    ISO27001 = "iso27001"
    GDPR = "gdpr"
    HIPAA = "hipaa"
    PCI_DSS = "pci_dss"
    NIST = "nist"
    SOX = "sox"
    FISMA = "fisma"


class BaseAnalyticsModel(BaseModel):
    """Base model for analytics data."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    date: str = Field(default_factory=lambda: datetime.now(timezone.utc).strftime('%Y-%m-%d'))
    hour: int = Field(default_factory=lambda: datetime.now(timezone.utc).hour)
    
    @validator('timestamp')
    def validate_timestamp(cls, v):
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v
    
    @validator('date', pre=True, always=True)
    def set_date(cls, v, values):
        if 'timestamp' in values:
            return values['timestamp'].strftime('%Y-%m-%d')
        return v
    
    @validator('hour', pre=True, always=True)
    def set_hour(cls, v, values):
        if 'timestamp' in values:
            return values['timestamp'].hour
        return v
    
    class Config:
        use_enum_values = True


class SecurityEvent(BaseAnalyticsModel):
    """Security event model for analytics."""
    event_type: EventType = Field(...)
    source_ip: str = Field(...)
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    user_id: Optional[str] = None
    username: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    asset_id: Optional[str] = None
    asset_name: Optional[str] = None
    asset_type: Optional[str] = None
    resource: Optional[str] = None
    action: Optional[str] = None
    result: Optional[str] = None
    threat_level: ThreatLevel = Field(...)
    confidence_score: float = Field(ge=0.0, le=1.0)
    raw_log: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    
    # Geolocation data
    source_country: Optional[str] = None
    source_city: Optional[str] = None
    source_latitude: Optional[float] = None
    source_longitude: Optional[float] = None
    
    # Detection information
    detection_method: Optional[str] = None
    detection_rule: Optional[str] = None
    false_positive_probability: Optional[float] = Field(None, ge=0.0, le=1.0)
    
    # Response information
    blocked: bool = Field(default=False)
    quarantined: bool = Field(default=False)
    investigated: bool = Field(default=False)
    resolved: bool = Field(default=False)
    
    # Timing information
    processing_time: Optional[float] = None
    detection_time: Optional[float] = None
    response_time: Optional[float] = None


class ThreatIntelligence(BaseAnalyticsModel):
    """Threat intelligence model for analytics."""
    threat_type: str = Field(...)
    threat_family: Optional[str] = None
    threat_actor: Optional[str] = None
    campaign: Optional[str] = None
    ioc_type: str = Field(...)  # IP, domain, hash, etc.
    ioc_value: str = Field(...)
    confidence_score: float = Field(ge=0.0, le=1.0)
    threat_level: ThreatLevel = Field(...)
    
    # Attribution
    source: str = Field(...)
    source_reliability: str = Field(...)
    first_seen: datetime = Field(...)
    last_seen: datetime = Field(...)
    
    # Context
    description: Optional[str] = None
    ttps: List[str] = Field(default_factory=list)  # MITRE ATT&CK techniques
    kill_chain_phases: List[str] = Field(default_factory=list)
    
    # Enrichment
    tags: Dict[str, str] = Field(default_factory=dict)
    attributes: Dict[str, Any] = Field(default_factory=dict)
    
    # Validation
    is_active: bool = Field(default=True)
    is_whitelisted: bool = Field(default=False)
    validation_status: str = Field(default="unvalidated")


class VulnerabilityAnalysis(BaseAnalyticsModel):
    """Vulnerability analysis model for analytics."""
    cve_id: Optional[str] = None
    vulnerability_id: str = Field(...)
    title: str = Field(...)
    description: Optional[str] = None
    
    # Severity scoring
    cvss_base_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_temporal_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_environmental_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    severity_level: ThreatLevel = Field(...)
    
    # Affected assets
    asset_id: str = Field(...)
    asset_name: str = Field(...)
    asset_type: str = Field(...)
    asset_criticality: str = Field(...)
    
    # Vulnerability details
    component_name: str = Field(...)
    component_version: Optional[str] = None
    component_vendor: Optional[str] = None
    
    # Status
    status: str = Field(...)  # open, patched, mitigated, false_positive
    discovery_date: datetime = Field(...)
    patch_available: bool = Field(default=False)
    patch_date: Optional[datetime] = None
    remediation_date: Optional[datetime] = None
    
    # Risk assessment
    exploitability: str = Field(...)
    impact: str = Field(...)
    risk_score: float = Field(ge=0.0, le=10.0)
    business_impact: str = Field(...)
    
    # Exploitation
    exploit_available: bool = Field(default=False)
    exploit_in_wild: bool = Field(default=False)
    weaponized: bool = Field(default=False)
    
    # Compliance
    compliance_violations: List[str] = Field(default_factory=list)
    regulatory_requirements: List[str] = Field(default_factory=list)
    
    # Metadata
    tags: Dict[str, str] = Field(default_factory=dict)
    attributes: Dict[str, Any] = Field(default_factory=dict)


class NetworkFlow(BaseAnalyticsModel):
    """Network flow model for analytics."""
    flow_id: str = Field(...)
    
    # Network layer
    source_ip: str = Field(...)
    destination_ip: str = Field(...)
    source_port: int = Field(...)
    destination_port: int = Field(...)
    protocol: str = Field(...)
    
    # Traffic metrics
    bytes_sent: int = Field(ge=0)
    bytes_received: int = Field(ge=0)
    packets_sent: int = Field(ge=0)
    packets_received: int = Field(ge=0)
    duration: float = Field(ge=0.0)
    
    # Flow characteristics
    flow_direction: str = Field(...)  # inbound, outbound, internal
    flow_type: str = Field(...)  # tcp, udp, icmp, etc.
    tcp_flags: Optional[str] = None
    
    # Security analysis
    is_malicious: bool = Field(default=False)
    is_suspicious: bool = Field(default=False)
    is_encrypted: bool = Field(default=False)
    threat_score: float = Field(ge=0.0, le=10.0)
    
    # Geolocation
    source_country: Optional[str] = None
    source_asn: Optional[str] = None
    destination_country: Optional[str] = None
    destination_asn: Optional[str] = None
    
    # Application layer
    application_protocol: Optional[str] = None
    http_method: Optional[str] = None
    http_status_code: Optional[int] = None
    http_user_agent: Optional[str] = None
    dns_query: Optional[str] = None
    tls_sni: Optional[str] = None
    
    # Detection
    detection_rules: List[str] = Field(default_factory=list)
    blocked_by_firewall: bool = Field(default=False)
    blocked_by_ips: bool = Field(default=False)
    
    # Metadata
    tags: Dict[str, str] = Field(default_factory=dict)
    attributes: Dict[str, Any] = Field(default_factory=dict)


class UserBehavior(BaseAnalyticsModel):
    """User behavior model for analytics."""
    user_id: str = Field(...)
    username: str = Field(...)
    user_type: str = Field(...)  # employee, contractor, service_account, etc.
    department: Optional[str] = None
    role: Optional[str] = None
    
    # Session information
    session_id: Optional[str] = None
    session_duration: Optional[float] = None
    
    # Access patterns
    source_ip: str = Field(...)
    source_location: Optional[str] = None
    device_id: Optional[str] = None
    device_type: Optional[str] = None
    user_agent: Optional[str] = None
    
    # Activity metrics
    login_count: int = Field(ge=0)
    failed_login_count: int = Field(ge=0)
    resource_access_count: int = Field(ge=0)
    data_transfer_bytes: int = Field(ge=0)
    
    # Behavioral indicators
    off_hours_activity: bool = Field(default=False)
    unusual_location: bool = Field(default=False)
    privilege_escalation: bool = Field(default=False)
    data_exfiltration_risk: bool = Field(default=False)
    
    # Risk scoring
    risk_score: float = Field(ge=0.0, le=10.0)
    anomaly_score: float = Field(ge=0.0, le=1.0)
    baseline_deviation: float = Field(ge=0.0)
    
    # Actions taken
    actions_performed: List[str] = Field(default_factory=list)
    resources_accessed: List[str] = Field(default_factory=list)
    permissions_used: List[str] = Field(default_factory=list)
    
    # Metadata
    tags: Dict[str, str] = Field(default_factory=dict)
    attributes: Dict[str, Any] = Field(default_factory=dict)


class ComplianceAudit(BaseAnalyticsModel):
    """Compliance audit model for analytics."""
    audit_id: str = Field(...)
    framework: ComplianceFramework = Field(...)
    control_id: str = Field(...)
    control_name: str = Field(...)
    control_category: str = Field(...)
    
    # Audit details
    audit_type: str = Field(...)  # automated, manual, continuous
    auditor: str = Field(...)
    audit_scope: str = Field(...)
    
    # Compliance status
    compliance_status: str = Field(...)  # compliant, non_compliant, partial
    compliance_score: float = Field(ge=0.0, le=100.0)
    
    # Findings
    findings_count: int = Field(ge=0)
    critical_findings: int = Field(ge=0)
    high_findings: int = Field(ge=0)
    medium_findings: int = Field(ge=0)
    low_findings: int = Field(ge=0)
    
    # Evidence
    evidence_collected: List[str] = Field(default_factory=list)
    evidence_quality: str = Field(...)
    
    # Remediation
    remediation_required: bool = Field(default=False)
    remediation_deadline: Optional[datetime] = None
    remediation_status: str = Field(default="pending")
    remediation_effort: Optional[str] = None
    
    # Risk assessment
    risk_level: ThreatLevel = Field(...)
    business_impact: str = Field(...)
    regulatory_impact: str = Field(...)
    
    # Metadata
    tags: Dict[str, str] = Field(default_factory=dict)
    attributes: Dict[str, Any] = Field(default_factory=dict)


class IncidentAnalysis(BaseAnalyticsModel):
    """Incident analysis model for analytics."""
    incident_id: str = Field(...)
    incident_type: str = Field(...)
    incident_category: str = Field(...)
    
    # Incident details
    title: str = Field(...)
    description: Optional[str] = None
    severity: ThreatLevel = Field(...)
    priority: str = Field(...)
    status: str = Field(...)
    
    # Timeline
    created_at: datetime = Field(...)
    first_response_at: Optional[datetime] = None
    escalated_at: Optional[datetime] = None
    resolved_at: Optional[datetime] = None
    closed_at: Optional[datetime] = None
    
    # Metrics
    detection_time: Optional[float] = None
    response_time: Optional[float] = None
    containment_time: Optional[float] = None
    resolution_time: Optional[float] = None
    
    # Impact assessment
    affected_systems: List[str] = Field(default_factory=list)
    affected_users: List[str] = Field(default_factory=list)
    affected_data: List[str] = Field(default_factory=list)
    business_impact: str = Field(...)
    financial_impact: Optional[float] = None
    
    # Response team
    assigned_to: str = Field(...)
    response_team: List[str] = Field(default_factory=list)
    escalation_level: int = Field(ge=0)
    
    # Root cause analysis
    root_cause: Optional[str] = None
    contributing_factors: List[str] = Field(default_factory=list)
    lessons_learned: List[str] = Field(default_factory=list)
    
    # Remediation
    remediation_actions: List[str] = Field(default_factory=list)
    preventive_measures: List[str] = Field(default_factory=list)
    
    # Metadata
    tags: Dict[str, str] = Field(default_factory=dict)
    attributes: Dict[str, Any] = Field(default_factory=dict)


@dataclass
class AnalyticsQuery:
    """Query model for analytics data."""
    table: AnalyticsTable
    select_fields: List[str] = field(default_factory=list)
    where_conditions: List[str] = field(default_factory=list)
    group_by: List[str] = field(default_factory=list)
    order_by: List[str] = field(default_factory=list)
    limit: Optional[int] = None
    offset: Optional[int] = None
    
    # Time range
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    # Aggregations
    aggregations: Dict[str, str] = field(default_factory=dict)
    
    # Filters
    filters: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnalyticsResult:
    """Result model for analytics queries."""
    query: AnalyticsQuery
    data: List[Dict[str, Any]]
    total_rows: int
    execution_time: float
    metadata: Dict[str, Any] = field(default_factory=dict)


# Factory functions for creating analytics models
def create_security_event(
    event_type: EventType,
    source_ip: str,
    threat_level: ThreatLevel,
    confidence_score: float,
    **kwargs
) -> SecurityEvent:
    """Create a security event."""
    return SecurityEvent(
        event_type=event_type,
        source_ip=source_ip,
        threat_level=threat_level,
        confidence_score=confidence_score,
        **kwargs
    )


def create_threat_intelligence(
    threat_type: str,
    ioc_type: str,
    ioc_value: str,
    confidence_score: float,
    threat_level: ThreatLevel,
    source: str,
    source_reliability: str,
    first_seen: datetime,
    last_seen: datetime,
    **kwargs
) -> ThreatIntelligence:
    """Create a threat intelligence record."""
    return ThreatIntelligence(
        threat_type=threat_type,
        ioc_type=ioc_type,
        ioc_value=ioc_value,
        confidence_score=confidence_score,
        threat_level=threat_level,
        source=source,
        source_reliability=source_reliability,
        first_seen=first_seen,
        last_seen=last_seen,
        **kwargs
    )


def create_vulnerability_analysis(
    vulnerability_id: str,
    title: str,
    severity_level: ThreatLevel,
    asset_id: str,
    asset_name: str,
    asset_type: str,
    asset_criticality: str,
    component_name: str,
    status: str,
    discovery_date: datetime,
    exploitability: str,
    impact: str,
    risk_score: float,
    business_impact: str,
    **kwargs
) -> VulnerabilityAnalysis:
    """Create a vulnerability analysis record."""
    return VulnerabilityAnalysis(
        vulnerability_id=vulnerability_id,
        title=title,
        severity_level=severity_level,
        asset_id=asset_id,
        asset_name=asset_name,
        asset_type=asset_type,
        asset_criticality=asset_criticality,
        component_name=component_name,
        status=status,
        discovery_date=discovery_date,
        exploitability=exploitability,
        impact=impact,
        risk_score=risk_score,
        business_impact=business_impact,
        **kwargs
    )


def create_network_flow(
    flow_id: str,
    source_ip: str,
    destination_ip: str,
    source_port: int,
    destination_port: int,
    protocol: str,
    bytes_sent: int,
    bytes_received: int,
    packets_sent: int,
    packets_received: int,
    duration: float,
    flow_direction: str,
    flow_type: str,
    threat_score: float,
    **kwargs
) -> NetworkFlow:
    """Create a network flow record."""
    return NetworkFlow(
        flow_id=flow_id,
        source_ip=source_ip,
        destination_ip=destination_ip,
        source_port=source_port,
        destination_port=destination_port,
        protocol=protocol,
        bytes_sent=bytes_sent,
        bytes_received=bytes_received,
        packets_sent=packets_sent,
        packets_received=packets_received,
        duration=duration,
        flow_direction=flow_direction,
        flow_type=flow_type,
        threat_score=threat_score,
        **kwargs
    )