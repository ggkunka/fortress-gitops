"""
Metrics API - REST endpoints for time-series metrics operations
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.security.sanitization import sanitize_input

from ..models.metrics import (
    SecurityMetric, ThreatMetric, VulnerabilityMetric, IncidentMetric,
    PerformanceMetric, ComplianceMetric, NetworkMetric, AuditMetric,
    MetricQuery, MetricAggregation, MetricSummary, MetricType, MetricCategory,
    Severity, create_threat_metric, create_vulnerability_metric,
    create_incident_metric, create_performance_metric, create_compliance_metric,
    create_network_metric, create_audit_metric
)
from ..services.metrics_repository import MetricsRepository
from ..services.metrics_processor import MetricsProcessor, ThresholdRule, AnomalyRule, AlertSeverity

logger = get_logger(__name__)
metrics = get_metrics()

router = APIRouter()

# Global instances (would be injected in real implementation)
metrics_repository = None
metrics_processor = None


class CreateThreatMetricRequest(BaseModel):
    """Request model for creating threat metrics."""
    threat_type: str = Field(..., min_length=1, max_length=100)
    severity: Severity = Field(...)
    confidence: float = Field(..., ge=0.0, le=1.0)
    source: str = Field(..., min_length=1, max_length=255)
    source_ip: Optional[str] = Field(None, max_length=45)
    destination_ip: Optional[str] = Field(None, max_length=45)
    user_agent: Optional[str] = Field(None, max_length=500)
    attack_vector: Optional[str] = Field(None, max_length=100)
    mitre_technique: Optional[str] = Field(None, max_length=50)
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class CreateVulnerabilityMetricRequest(BaseModel):
    """Request model for creating vulnerability metrics."""
    component_name: str = Field(..., min_length=1, max_length=255)
    severity: Severity = Field(...)
    source: str = Field(..., min_length=1, max_length=255)
    cve_id: Optional[str] = Field(None, max_length=50)
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    component_version: Optional[str] = Field(None, max_length=50)
    is_exploitable: bool = Field(default=False)
    has_patch: bool = Field(default=False)
    exploit_available: bool = Field(default=False)
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class CreateIncidentMetricRequest(BaseModel):
    """Request model for creating incident metrics."""
    incident_id: str = Field(..., min_length=1, max_length=255)
    incident_type: str = Field(..., min_length=1, max_length=100)
    severity: Severity = Field(...)
    status: str = Field(..., min_length=1, max_length=50)
    source: str = Field(..., min_length=1, max_length=255)
    assigned_to: Optional[str] = Field(None, max_length=255)
    response_time: Optional[float] = Field(None, ge=0.0)
    resolution_time: Optional[float] = Field(None, ge=0.0)
    affected_systems: Optional[List[str]] = Field(default_factory=list)
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class CreatePerformanceMetricRequest(BaseModel):
    """Request model for creating performance metrics."""
    source: str = Field(..., min_length=1, max_length=255)
    cpu_usage: Optional[float] = Field(None, ge=0.0, le=100.0)
    memory_usage: Optional[float] = Field(None, ge=0.0, le=100.0)
    disk_usage: Optional[float] = Field(None, ge=0.0, le=100.0)
    network_in: Optional[float] = Field(None, ge=0.0)
    network_out: Optional[float] = Field(None, ge=0.0)
    response_time: Optional[float] = Field(None, ge=0.0)
    error_rate: Optional[float] = Field(None, ge=0.0, le=100.0)
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class CreateComplianceMetricRequest(BaseModel):
    """Request model for creating compliance metrics."""
    framework: str = Field(..., min_length=1, max_length=50)
    control_id: str = Field(..., min_length=1, max_length=50)
    compliance_score: float = Field(..., ge=0.0, le=100.0)
    is_compliant: bool = Field(...)
    violations_count: int = Field(..., ge=0)
    source: str = Field(..., min_length=1, max_length=255)
    remediation_required: bool = Field(default=False)
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class CreateNetworkMetricRequest(BaseModel):
    """Request model for creating network metrics."""
    protocol: str = Field(..., min_length=1, max_length=20)
    source_ip: str = Field(..., min_length=1, max_length=45)
    destination_ip: str = Field(..., min_length=1, max_length=45)
    source_port: int = Field(..., ge=1, le=65535)
    destination_port: int = Field(..., ge=1, le=65535)
    bytes_transferred: int = Field(..., ge=0)
    packets_count: int = Field(..., ge=0)
    source: str = Field(..., min_length=1, max_length=255)
    is_blocked: bool = Field(default=False)
    is_suspicious: bool = Field(default=False)
    threat_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class CreateAuditMetricRequest(BaseModel):
    """Request model for creating audit metrics."""
    event_type: str = Field(..., min_length=1, max_length=100)
    user_id: str = Field(..., min_length=1, max_length=255)
    resource: str = Field(..., min_length=1, max_length=255)
    action: str = Field(..., min_length=1, max_length=100)
    success: bool = Field(...)
    source: str = Field(..., min_length=1, max_length=255)
    source_ip: Optional[str] = Field(None, max_length=45)
    user_agent: Optional[str] = Field(None, max_length=500)
    session_id: Optional[str] = Field(None, max_length=255)
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class MetricQueryRequest(BaseModel):
    """Request model for querying metrics."""
    measurement: str = Field(..., min_length=1, max_length=100)
    start_time: datetime = Field(...)
    end_time: datetime = Field(...)
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)
    fields: Optional[List[str]] = Field(default_factory=list)
    group_by: Optional[List[str]] = Field(default_factory=list)
    aggregation: Optional[str] = Field(None, regex="^(mean|sum|count|min|max|last|first)$")
    interval: Optional[str] = Field(None, regex="^\\d+[smhd]$")
    limit: Optional[int] = Field(None, ge=1, le=10000)


class CreateThresholdRuleRequest(BaseModel):
    """Request model for creating threshold rules."""
    metric_name: str = Field(..., min_length=1, max_length=100)
    field_name: str = Field(..., min_length=1, max_length=100)
    operator: str = Field(..., regex="^(>|<|>=|<=|==|!=)$")
    threshold: float = Field(...)
    severity: AlertSeverity = Field(...)
    window_size: str = Field("5m", regex="^\\d+[smhd]$")
    evaluation_interval: str = Field("1m", regex="^\\d+[smhd]$")
    tags_filter: Optional[Dict[str, str]] = Field(default_factory=dict)


class CreateAnomalyRuleRequest(BaseModel):
    """Request model for creating anomaly rules."""
    metric_name: str = Field(..., min_length=1, max_length=100)
    field_name: str = Field(..., min_length=1, max_length=100)
    method: str = Field(..., regex="^(zscore|iqr|isolation_forest)$")
    sensitivity: float = Field(2.0, ge=0.1, le=10.0)
    window_size: str = Field("30m", regex="^\\d+[smhd]$")
    evaluation_interval: str = Field("5m", regex="^\\d+[smhd]$")
    tags_filter: Optional[Dict[str, str]] = Field(default_factory=dict)


def get_metrics_repository() -> MetricsRepository:
    """Get metrics repository instance."""
    global metrics_repository
    if metrics_repository is None:
        raise RuntimeError("Metrics repository not initialized")
    return metrics_repository


def get_metrics_processor() -> MetricsProcessor:
    """Get metrics processor instance."""
    global metrics_processor
    if metrics_processor is None:
        raise RuntimeError("Metrics processor not initialized")
    return metrics_processor


@router.post("/metrics/threat", response_model=Dict[str, Any])
@traced("metrics_api_create_threat_metric")
async def create_threat_metric(
    request: CreateThreatMetricRequest,
    background_tasks: BackgroundTasks,
    repository: MetricsRepository = Depends(get_metrics_repository),
    processor: MetricsProcessor = Depends(get_metrics_processor)
):
    """Create a threat detection metric."""
    try:
        # Sanitize inputs
        threat_type = sanitize_input(request.threat_type, max_length=100)
        source = sanitize_input(request.source, max_length=255)
        
        # Create metric
        metric = create_threat_metric(
            threat_type=threat_type,
            severity=request.severity,
            confidence=request.confidence,
            source=source,
            source_ip=request.source_ip,
            destination_ip=request.destination_ip,
            user_agent=request.user_agent,
            attack_vector=request.attack_vector,
            mitre_technique=request.mitre_technique,
            timestamp=request.timestamp
        )
        
        # Add custom tags
        if request.tags:
            metric.tags.update(request.tags)
        
        # Process metric
        background_tasks.add_task(processor.process_metric, metric)
        
        logger.info(f"Threat metric created: {threat_type}")
        metrics.metrics_api_threat_metrics_created.inc()
        
        return {
            "message": "Threat metric created successfully",
            "metric_type": "threat",
            "threat_type": threat_type,
            "severity": request.severity,
            "confidence": request.confidence,
            "timestamp": metric.timestamp.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating threat metric: {e}")
        metrics.metrics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/metrics/vulnerability", response_model=Dict[str, Any])
@traced("metrics_api_create_vulnerability_metric")
async def create_vulnerability_metric(
    request: CreateVulnerabilityMetricRequest,
    background_tasks: BackgroundTasks,
    repository: MetricsRepository = Depends(get_metrics_repository),
    processor: MetricsProcessor = Depends(get_metrics_processor)
):
    """Create a vulnerability assessment metric."""
    try:
        # Sanitize inputs
        component_name = sanitize_input(request.component_name, max_length=255)
        source = sanitize_input(request.source, max_length=255)
        
        # Create metric
        metric = create_vulnerability_metric(
            component_name=component_name,
            severity=request.severity,
            source=source,
            cve_id=request.cve_id,
            cvss_score=request.cvss_score,
            component_version=request.component_version,
            is_exploitable=request.is_exploitable,
            has_patch=request.has_patch,
            exploit_available=request.exploit_available,
            timestamp=request.timestamp
        )
        
        # Add custom tags
        if request.tags:
            metric.tags.update(request.tags)
        
        # Process metric
        background_tasks.add_task(processor.process_metric, metric)
        
        logger.info(f"Vulnerability metric created: {component_name}")
        metrics.metrics_api_vulnerability_metrics_created.inc()
        
        return {
            "message": "Vulnerability metric created successfully",
            "metric_type": "vulnerability",
            "component_name": component_name,
            "severity": request.severity,
            "cve_id": request.cve_id,
            "timestamp": metric.timestamp.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating vulnerability metric: {e}")
        metrics.metrics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/metrics/incident", response_model=Dict[str, Any])
@traced("metrics_api_create_incident_metric")
async def create_incident_metric(
    request: CreateIncidentMetricRequest,
    background_tasks: BackgroundTasks,
    repository: MetricsRepository = Depends(get_metrics_repository),
    processor: MetricsProcessor = Depends(get_metrics_processor)
):
    """Create a security incident metric."""
    try:
        # Sanitize inputs
        incident_id = sanitize_input(request.incident_id, max_length=255)
        incident_type = sanitize_input(request.incident_type, max_length=100)
        status = sanitize_input(request.status, max_length=50)
        source = sanitize_input(request.source, max_length=255)
        
        # Create metric
        metric = create_incident_metric(
            incident_id=incident_id,
            incident_type=incident_type,
            severity=request.severity,
            status=status,
            source=source,
            assigned_to=request.assigned_to,
            response_time=request.response_time,
            resolution_time=request.resolution_time,
            affected_systems=request.affected_systems,
            timestamp=request.timestamp
        )
        
        # Add custom tags
        if request.tags:
            metric.tags.update(request.tags)
        
        # Process metric
        background_tasks.add_task(processor.process_metric, metric)
        
        logger.info(f"Incident metric created: {incident_id}")
        metrics.metrics_api_incident_metrics_created.inc()
        
        return {
            "message": "Incident metric created successfully",
            "metric_type": "incident",
            "incident_id": incident_id,
            "incident_type": incident_type,
            "severity": request.severity,
            "status": status,
            "timestamp": metric.timestamp.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating incident metric: {e}")
        metrics.metrics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/metrics/performance", response_model=Dict[str, Any])
@traced("metrics_api_create_performance_metric")
async def create_performance_metric(
    request: CreatePerformanceMetricRequest,
    background_tasks: BackgroundTasks,
    repository: MetricsRepository = Depends(get_metrics_repository),
    processor: MetricsProcessor = Depends(get_metrics_processor)
):
    """Create a system performance metric."""
    try:
        # Sanitize inputs
        source = sanitize_input(request.source, max_length=255)
        
        # Create metric
        metric = create_performance_metric(
            source=source,
            cpu_usage=request.cpu_usage,
            memory_usage=request.memory_usage,
            disk_usage=request.disk_usage,
            network_in=request.network_in,
            network_out=request.network_out,
            response_time=request.response_time,
            error_rate=request.error_rate,
            timestamp=request.timestamp
        )
        
        # Add custom tags
        if request.tags:
            metric.tags.update(request.tags)
        
        # Process metric
        background_tasks.add_task(processor.process_metric, metric)
        
        logger.info(f"Performance metric created: {source}")
        metrics.metrics_api_performance_metrics_created.inc()
        
        return {
            "message": "Performance metric created successfully",
            "metric_type": "performance",
            "source": source,
            "timestamp": metric.timestamp.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating performance metric: {e}")
        metrics.metrics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/metrics/compliance", response_model=Dict[str, Any])
@traced("metrics_api_create_compliance_metric")
async def create_compliance_metric(
    request: CreateComplianceMetricRequest,
    background_tasks: BackgroundTasks,
    repository: MetricsRepository = Depends(get_metrics_repository),
    processor: MetricsProcessor = Depends(get_metrics_processor)
):
    """Create a compliance monitoring metric."""
    try:
        # Sanitize inputs
        framework = sanitize_input(request.framework, max_length=50)
        control_id = sanitize_input(request.control_id, max_length=50)
        source = sanitize_input(request.source, max_length=255)
        
        # Create metric
        metric = create_compliance_metric(
            framework=framework,
            control_id=control_id,
            compliance_score=request.compliance_score,
            is_compliant=request.is_compliant,
            violations_count=request.violations_count,
            source=source,
            remediation_required=request.remediation_required,
            timestamp=request.timestamp
        )
        
        # Add custom tags
        if request.tags:
            metric.tags.update(request.tags)
        
        # Process metric
        background_tasks.add_task(processor.process_metric, metric)
        
        logger.info(f"Compliance metric created: {framework}:{control_id}")
        metrics.metrics_api_compliance_metrics_created.inc()
        
        return {
            "message": "Compliance metric created successfully",
            "metric_type": "compliance",
            "framework": framework,
            "control_id": control_id,
            "compliance_score": request.compliance_score,
            "is_compliant": request.is_compliant,
            "timestamp": metric.timestamp.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating compliance metric: {e}")
        metrics.metrics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/metrics/network", response_model=Dict[str, Any])
@traced("metrics_api_create_network_metric")
async def create_network_metric(
    request: CreateNetworkMetricRequest,
    background_tasks: BackgroundTasks,
    repository: MetricsRepository = Depends(get_metrics_repository),
    processor: MetricsProcessor = Depends(get_metrics_processor)
):
    """Create a network security metric."""
    try:
        # Sanitize inputs
        protocol = sanitize_input(request.protocol, max_length=20)
        source_ip = sanitize_input(request.source_ip, max_length=45)
        destination_ip = sanitize_input(request.destination_ip, max_length=45)
        source = sanitize_input(request.source, max_length=255)
        
        # Create metric
        metric = create_network_metric(
            protocol=protocol,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=request.source_port,
            destination_port=request.destination_port,
            bytes_transferred=request.bytes_transferred,
            packets_count=request.packets_count,
            source=source,
            is_blocked=request.is_blocked,
            is_suspicious=request.is_suspicious,
            threat_score=request.threat_score,
            timestamp=request.timestamp
        )
        
        # Add custom tags
        if request.tags:
            metric.tags.update(request.tags)
        
        # Process metric
        background_tasks.add_task(processor.process_metric, metric)
        
        logger.info(f"Network metric created: {protocol} {source_ip}:{request.source_port} -> {destination_ip}:{request.destination_port}")
        metrics.metrics_api_network_metrics_created.inc()
        
        return {
            "message": "Network metric created successfully",
            "metric_type": "network",
            "protocol": protocol,
            "source_ip": source_ip,
            "destination_ip": destination_ip,
            "bytes_transferred": request.bytes_transferred,
            "timestamp": metric.timestamp.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating network metric: {e}")
        metrics.metrics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/metrics/audit", response_model=Dict[str, Any])
@traced("metrics_api_create_audit_metric")
async def create_audit_metric(
    request: CreateAuditMetricRequest,
    background_tasks: BackgroundTasks,
    repository: MetricsRepository = Depends(get_metrics_repository),
    processor: MetricsProcessor = Depends(get_metrics_processor)
):
    """Create an audit event metric."""
    try:
        # Sanitize inputs
        event_type = sanitize_input(request.event_type, max_length=100)
        user_id = sanitize_input(request.user_id, max_length=255)
        resource = sanitize_input(request.resource, max_length=255)
        action = sanitize_input(request.action, max_length=100)
        source = sanitize_input(request.source, max_length=255)
        
        # Create metric
        metric = create_audit_metric(
            event_type=event_type,
            user_id=user_id,
            resource=resource,
            action=action,
            success=request.success,
            source=source,
            source_ip=request.source_ip,
            user_agent=request.user_agent,
            session_id=request.session_id,
            timestamp=request.timestamp
        )
        
        # Add custom tags
        if request.tags:
            metric.tags.update(request.tags)
        
        # Process metric
        background_tasks.add_task(processor.process_metric, metric)
        
        logger.info(f"Audit metric created: {event_type} by {user_id}")
        metrics.metrics_api_audit_metrics_created.inc()
        
        return {
            "message": "Audit metric created successfully",
            "metric_type": "audit",
            "event_type": event_type,
            "user_id": user_id,
            "resource": resource,
            "action": action,
            "success": request.success,
            "timestamp": metric.timestamp.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating audit metric: {e}")
        metrics.metrics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/metrics/query", response_model=Dict[str, Any])
@traced("metrics_api_query_metrics")
async def query_metrics(
    request: MetricQueryRequest,
    repository: MetricsRepository = Depends(get_metrics_repository)
):
    """Query metrics with filtering and aggregation."""
    try:
        # Create query object
        query = MetricQuery(
            measurement=request.measurement,
            start_time=request.start_time,
            end_time=request.end_time,
            tags=request.tags,
            fields=request.fields,
            group_by=request.group_by,
            aggregation=request.aggregation,
            interval=request.interval,
            limit=request.limit
        )
        
        # Execute query
        results = await repository.query_metrics(query)
        
        return {
            "measurement": request.measurement,
            "time_range": {
                "start": request.start_time.isoformat(),
                "end": request.end_time.isoformat()
            },
            "results": results,
            "count": len(results),
            "query_params": request.dict()
        }
        
    except Exception as e:
        logger.error(f"Error querying metrics: {e}")
        metrics.metrics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/metrics/{measurement}/summary", response_model=Dict[str, Any])
@traced("metrics_api_get_summary")
async def get_metrics_summary(
    measurement: str,
    start_time: datetime = Query(...),
    end_time: datetime = Query(...),
    tags: Optional[str] = Query(None, description="JSON string of tags filter"),
    repository: MetricsRepository = Depends(get_metrics_repository)
):
    """Get comprehensive metrics summary."""
    try:
        # Parse tags filter
        tags_filter = None
        if tags:
            import json
            tags_filter = json.loads(tags)
        
        # Get summary
        summary = await repository.get_metric_summary(
            measurement=measurement,
            start_time=start_time,
            end_time=end_time,
            tags=tags_filter
        )
        
        return {
            "measurement": measurement,
            "time_range": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat()
            },
            "summary": summary.dict()
        }
        
    except Exception as e:
        logger.error(f"Error getting metrics summary: {e}")
        metrics.metrics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/metrics/{measurement}/realtime", response_model=Dict[str, Any])
@traced("metrics_api_get_realtime")
async def get_realtime_metrics(
    measurement: str,
    window_size: str = Query("5m", regex="^\\d+[smhd]$"),
    tags: Optional[str] = Query(None, description="JSON string of tags filter"),
    repository: MetricsRepository = Depends(get_metrics_repository)
):
    """Get real-time metrics."""
    try:
        # Parse tags filter
        tags_filter = None
        if tags:
            import json
            tags_filter = json.loads(tags)
        
        # Get real-time metrics
        results = await repository.get_real_time_metrics(
            measurement=measurement,
            window_size=window_size,
            tags=tags_filter
        )
        
        return {
            "measurement": measurement,
            "window_size": window_size,
            "results": results,
            "count": len(results),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting real-time metrics: {e}")
        metrics.metrics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/alerts/threshold-rule", response_model=Dict[str, Any])
@traced("metrics_api_create_threshold_rule")
async def create_threshold_rule(
    request: CreateThresholdRuleRequest,
    processor: MetricsProcessor = Depends(get_metrics_processor)
):
    """Create a threshold-based alerting rule."""
    try:
        # Create threshold rule
        rule = ThresholdRule(
            metric_name=request.metric_name,
            field_name=request.field_name,
            operator=request.operator,
            threshold=request.threshold,
            severity=request.severity,
            window_size=request.window_size,
            evaluation_interval=request.evaluation_interval,
            tags_filter=request.tags_filter if request.tags_filter else None
        )
        
        # Add rule to processor
        processor.add_threshold_rule(rule)
        
        logger.info(f"Threshold rule created: {request.metric_name}")
        metrics.metrics_api_threshold_rules_created.inc()
        
        return {
            "message": "Threshold rule created successfully",
            "rule_type": "threshold",
            "metric_name": request.metric_name,
            "field_name": request.field_name,
            "operator": request.operator,
            "threshold": request.threshold,
            "severity": request.severity
        }
        
    except Exception as e:
        logger.error(f"Error creating threshold rule: {e}")
        metrics.metrics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/alerts/anomaly-rule", response_model=Dict[str, Any])
@traced("metrics_api_create_anomaly_rule")
async def create_anomaly_rule(
    request: CreateAnomalyRuleRequest,
    processor: MetricsProcessor = Depends(get_metrics_processor)
):
    """Create an anomaly detection rule."""
    try:
        # Create anomaly rule
        rule = AnomalyRule(
            metric_name=request.metric_name,
            field_name=request.field_name,
            method=request.method,
            sensitivity=request.sensitivity,
            window_size=request.window_size,
            evaluation_interval=request.evaluation_interval,
            tags_filter=request.tags_filter if request.tags_filter else None
        )
        
        # Add rule to processor
        processor.add_anomaly_rule(rule)
        
        logger.info(f"Anomaly rule created: {request.metric_name}")
        metrics.metrics_api_anomaly_rules_created.inc()
        
        return {
            "message": "Anomaly rule created successfully",
            "rule_type": "anomaly",
            "metric_name": request.metric_name,
            "field_name": request.field_name,
            "method": request.method,
            "sensitivity": request.sensitivity
        }
        
    except Exception as e:
        logger.error(f"Error creating anomaly rule: {e}")
        metrics.metrics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/statistics", response_model=Dict[str, Any])
@traced("metrics_api_get_statistics")
async def get_statistics(
    repository: MetricsRepository = Depends(get_metrics_repository),
    processor: MetricsProcessor = Depends(get_metrics_processor)
):
    """Get comprehensive metrics statistics."""
    try:
        repository_stats = repository.get_stats()
        processor_stats = processor.get_stats()
        
        return {
            "service": "influxdb-service",
            "repository": repository_stats,
            "processor": processor_stats,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        metrics.metrics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/metrics/{measurement}", response_model=Dict[str, Any])
@traced("metrics_api_delete_metrics")
async def delete_metrics(
    measurement: str,
    start_time: datetime = Query(...),
    end_time: datetime = Query(...),
    predicate: Optional[str] = Query(None, description="Additional delete predicate"),
    repository: MetricsRepository = Depends(get_metrics_repository)
):
    """Delete metrics within a time range."""
    try:
        # Delete metrics
        success = await repository.delete_metrics(
            measurement=measurement,
            start_time=start_time,
            end_time=end_time,
            predicate=predicate
        )
        
        if success:
            logger.info(f"Metrics deleted: {measurement}")
            metrics.metrics_api_metrics_deleted.inc()
            
            return {
                "message": "Metrics deleted successfully",
                "measurement": measurement,
                "time_range": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat()
                }
            }
        else:
            raise HTTPException(status_code=500, detail="Failed to delete metrics")
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting metrics: {e}")
        metrics.metrics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")