"""
Analytics API - REST endpoints for OLAP analytics operations
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

from ..models.analytics import (
    SecurityEvent, ThreatIntelligence, VulnerabilityAnalysis, NetworkFlow,
    UserBehavior, ComplianceAudit, IncidentAnalysis, AnalyticsTable,
    AnalyticsQuery, EventType, ThreatLevel, ComplianceFramework,
    create_security_event, create_threat_intelligence, create_vulnerability_analysis,
    create_network_flow
)
from ..services.analytics_repository import AnalyticsRepository
from ..services.analytics_processor import AnalyticsProcessor, ProcessingRule, AggregationRule

logger = get_logger(__name__)
metrics = get_metrics()

router = APIRouter()

# Global instances (would be injected in real implementation)
analytics_repository = None
analytics_processor = None


class CreateSecurityEventRequest(BaseModel):
    """Request model for creating security events."""
    event_type: EventType = Field(...)
    source_ip: str = Field(..., min_length=1, max_length=45)
    destination_ip: Optional[str] = Field(None, max_length=45)
    source_port: Optional[int] = Field(None, ge=1, le=65535)
    destination_port: Optional[int] = Field(None, ge=1, le=65535)
    protocol: Optional[str] = Field(None, max_length=20)
    user_id: Optional[str] = Field(None, max_length=255)
    username: Optional[str] = Field(None, max_length=255)
    user_agent: Optional[str] = Field(None, max_length=500)
    session_id: Optional[str] = Field(None, max_length=255)
    asset_id: Optional[str] = Field(None, max_length=255)
    asset_name: Optional[str] = Field(None, max_length=255)
    asset_type: Optional[str] = Field(None, max_length=100)
    resource: Optional[str] = Field(None, max_length=255)
    action: Optional[str] = Field(None, max_length=100)
    result: Optional[str] = Field(None, max_length=100)
    threat_level: ThreatLevel = Field(...)
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    raw_log: Optional[str] = Field(None, max_length=10000)
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)
    attributes: Optional[Dict[str, Any]] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class CreateThreatIntelRequest(BaseModel):
    """Request model for creating threat intelligence."""
    threat_type: str = Field(..., min_length=1, max_length=100)
    threat_family: Optional[str] = Field(None, max_length=100)
    threat_actor: Optional[str] = Field(None, max_length=100)
    campaign: Optional[str] = Field(None, max_length=100)
    ioc_type: str = Field(..., min_length=1, max_length=50)
    ioc_value: str = Field(..., min_length=1, max_length=500)
    confidence_score: float = Field(..., ge=0.0, le=1.0)
    threat_level: ThreatLevel = Field(...)
    source: str = Field(..., min_length=1, max_length=255)
    source_reliability: str = Field(..., min_length=1, max_length=50)
    first_seen: datetime = Field(...)
    last_seen: datetime = Field(...)
    description: Optional[str] = Field(None, max_length=1000)
    ttps: Optional[List[str]] = Field(default_factory=list)
    kill_chain_phases: Optional[List[str]] = Field(default_factory=list)
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)
    attributes: Optional[Dict[str, Any]] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class CreateVulnAnalysisRequest(BaseModel):
    """Request model for creating vulnerability analysis."""
    cve_id: Optional[str] = Field(None, max_length=50)
    vulnerability_id: str = Field(..., min_length=1, max_length=255)
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    cvss_base_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    severity_level: ThreatLevel = Field(...)
    asset_id: str = Field(..., min_length=1, max_length=255)
    asset_name: str = Field(..., min_length=1, max_length=255)
    asset_type: str = Field(..., min_length=1, max_length=100)
    asset_criticality: str = Field(..., min_length=1, max_length=50)
    component_name: str = Field(..., min_length=1, max_length=255)
    component_version: Optional[str] = Field(None, max_length=50)
    component_vendor: Optional[str] = Field(None, max_length=100)
    status: str = Field(..., min_length=1, max_length=50)
    discovery_date: datetime = Field(...)
    exploitability: str = Field(..., min_length=1, max_length=50)
    impact: str = Field(..., min_length=1, max_length=50)
    risk_score: float = Field(..., ge=0.0, le=10.0)
    business_impact: str = Field(..., min_length=1, max_length=50)
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)
    attributes: Optional[Dict[str, Any]] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class CreateNetworkFlowRequest(BaseModel):
    """Request model for creating network flows."""
    flow_id: str = Field(..., min_length=1, max_length=255)
    source_ip: str = Field(..., min_length=1, max_length=45)
    destination_ip: str = Field(..., min_length=1, max_length=45)
    source_port: int = Field(..., ge=1, le=65535)
    destination_port: int = Field(..., ge=1, le=65535)
    protocol: str = Field(..., min_length=1, max_length=20)
    bytes_sent: int = Field(..., ge=0)
    bytes_received: int = Field(..., ge=0)
    packets_sent: int = Field(..., ge=0)
    packets_received: int = Field(..., ge=0)
    duration: float = Field(..., ge=0.0)
    flow_direction: str = Field(..., min_length=1, max_length=50)
    flow_type: str = Field(..., min_length=1, max_length=50)
    threat_score: float = Field(..., ge=0.0, le=10.0)
    is_malicious: bool = Field(default=False)
    is_suspicious: bool = Field(default=False)
    is_encrypted: bool = Field(default=False)
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)
    attributes: Optional[Dict[str, Any]] = Field(default_factory=dict)
    timestamp: Optional[datetime] = None


class AnalyticsQueryRequest(BaseModel):
    """Request model for analytics queries."""
    table: AnalyticsTable = Field(...)
    select_fields: Optional[List[str]] = Field(default_factory=list)
    where_conditions: Optional[List[str]] = Field(default_factory=list)
    group_by: Optional[List[str]] = Field(default_factory=list)
    order_by: Optional[List[str]] = Field(default_factory=list)
    limit: Optional[int] = Field(None, ge=1, le=10000)
    offset: Optional[int] = Field(None, ge=0)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    aggregations: Optional[Dict[str, str]] = Field(default_factory=dict)
    filters: Optional[Dict[str, Any]] = Field(default_factory=dict)


class CreateProcessingRuleRequest(BaseModel):
    """Request model for creating processing rules."""
    name: str = Field(..., min_length=1, max_length=255)
    condition: str = Field(..., min_length=1, max_length=500)
    action: str = Field(..., min_length=1, max_length=100)
    priority: int = Field(1, ge=1, le=10)
    enabled: bool = Field(True)
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict)


def get_analytics_repository() -> AnalyticsRepository:
    """Get analytics repository instance."""
    global analytics_repository
    if analytics_repository is None:
        raise RuntimeError("Analytics repository not initialized")
    return analytics_repository


def get_analytics_processor() -> AnalyticsProcessor:
    """Get analytics processor instance."""
    global analytics_processor
    if analytics_processor is None:
        raise RuntimeError("Analytics processor not initialized")
    return analytics_processor


@router.post("/events/security", response_model=Dict[str, Any])
@traced("analytics_api_create_security_event")
async def create_security_event(
    request: CreateSecurityEventRequest,
    background_tasks: BackgroundTasks,
    repository: AnalyticsRepository = Depends(get_analytics_repository),
    processor: AnalyticsProcessor = Depends(get_analytics_processor)
):
    """Create a security event for analytics."""
    try:
        # Sanitize inputs
        source_ip = sanitize_input(request.source_ip, max_length=45)
        destination_ip = sanitize_input(request.destination_ip, max_length=45) if request.destination_ip else None
        
        # Create security event
        event = create_security_event(
            event_type=request.event_type,
            source_ip=source_ip,
            threat_level=request.threat_level,
            confidence_score=request.confidence_score,
            destination_ip=destination_ip,
            source_port=request.source_port,
            destination_port=request.destination_port,
            protocol=request.protocol,
            user_id=request.user_id,
            username=request.username,
            user_agent=request.user_agent,
            session_id=request.session_id,
            asset_id=request.asset_id,
            asset_name=request.asset_name,
            asset_type=request.asset_type,
            resource=request.resource,
            action=request.action,
            result=request.result,
            raw_log=request.raw_log,
            tags=request.tags or {},
            attributes=request.attributes or {},
            timestamp=request.timestamp
        )
        
        # Process event
        background_tasks.add_task(processor.process_security_event, event)
        
        logger.info(f"Security event created: {event.id}")
        metrics.analytics_api_security_events_created.inc()
        
        return {
            "message": "Security event created successfully",
            "event_id": event.id,
            "event_type": request.event_type,
            "threat_level": request.threat_level,
            "timestamp": event.timestamp.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating security event: {e}")
        metrics.analytics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/events/threat-intelligence", response_model=Dict[str, Any])
@traced("analytics_api_create_threat_intelligence")
async def create_threat_intelligence(
    request: CreateThreatIntelRequest,
    background_tasks: BackgroundTasks,
    repository: AnalyticsRepository = Depends(get_analytics_repository),
    processor: AnalyticsProcessor = Depends(get_analytics_processor)
):
    """Create threat intelligence data for analytics."""
    try:
        # Sanitize inputs
        threat_type = sanitize_input(request.threat_type, max_length=100)
        ioc_type = sanitize_input(request.ioc_type, max_length=50)
        ioc_value = sanitize_input(request.ioc_value, max_length=500)
        source = sanitize_input(request.source, max_length=255)
        
        # Create threat intelligence
        threat = create_threat_intelligence(
            threat_type=threat_type,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            confidence_score=request.confidence_score,
            threat_level=request.threat_level,
            source=source,
            source_reliability=request.source_reliability,
            first_seen=request.first_seen,
            last_seen=request.last_seen,
            threat_family=request.threat_family,
            threat_actor=request.threat_actor,
            campaign=request.campaign,
            description=request.description,
            ttps=request.ttps or [],
            kill_chain_phases=request.kill_chain_phases or [],
            tags=request.tags or {},
            attributes=request.attributes or {},
            timestamp=request.timestamp
        )
        
        # Process threat intelligence
        background_tasks.add_task(processor.process_threat_intelligence, threat)
        
        logger.info(f"Threat intelligence created: {threat.id}")
        metrics.analytics_api_threat_intel_created.inc()
        
        return {
            "message": "Threat intelligence created successfully",
            "threat_id": threat.id,
            "threat_type": request.threat_type,
            "ioc_type": request.ioc_type,
            "ioc_value": request.ioc_value,
            "timestamp": threat.timestamp.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating threat intelligence: {e}")
        metrics.analytics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/events/vulnerability-analysis", response_model=Dict[str, Any])
@traced("analytics_api_create_vulnerability_analysis")
async def create_vulnerability_analysis(
    request: CreateVulnAnalysisRequest,
    background_tasks: BackgroundTasks,
    repository: AnalyticsRepository = Depends(get_analytics_repository),
    processor: AnalyticsProcessor = Depends(get_analytics_processor)
):
    """Create vulnerability analysis data for analytics."""
    try:
        # Sanitize inputs
        vulnerability_id = sanitize_input(request.vulnerability_id, max_length=255)
        title = sanitize_input(request.title, max_length=255)
        asset_id = sanitize_input(request.asset_id, max_length=255)
        asset_name = sanitize_input(request.asset_name, max_length=255)
        component_name = sanitize_input(request.component_name, max_length=255)
        
        # Create vulnerability analysis
        vuln = create_vulnerability_analysis(
            vulnerability_id=vulnerability_id,
            title=title,
            severity_level=request.severity_level,
            asset_id=asset_id,
            asset_name=asset_name,
            asset_type=request.asset_type,
            asset_criticality=request.asset_criticality,
            component_name=component_name,
            status=request.status,
            discovery_date=request.discovery_date,
            exploitability=request.exploitability,
            impact=request.impact,
            risk_score=request.risk_score,
            business_impact=request.business_impact,
            cve_id=request.cve_id,
            description=request.description,
            cvss_base_score=request.cvss_base_score,
            component_version=request.component_version,
            component_vendor=request.component_vendor,
            tags=request.tags or {},
            attributes=request.attributes or {},
            timestamp=request.timestamp
        )
        
        # Process vulnerability analysis
        background_tasks.add_task(processor.process_vulnerability_analysis, vuln)
        
        logger.info(f"Vulnerability analysis created: {vuln.id}")
        metrics.analytics_api_vulnerability_analysis_created.inc()
        
        return {
            "message": "Vulnerability analysis created successfully",
            "vulnerability_id": vuln.id,
            "asset_id": request.asset_id,
            "component_name": request.component_name,
            "severity_level": request.severity_level,
            "timestamp": vuln.timestamp.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating vulnerability analysis: {e}")
        metrics.analytics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/events/network-flow", response_model=Dict[str, Any])
@traced("analytics_api_create_network_flow")
async def create_network_flow(
    request: CreateNetworkFlowRequest,
    background_tasks: BackgroundTasks,
    repository: AnalyticsRepository = Depends(get_analytics_repository),
    processor: AnalyticsProcessor = Depends(get_analytics_processor)
):
    """Create network flow data for analytics."""
    try:
        # Sanitize inputs
        flow_id = sanitize_input(request.flow_id, max_length=255)
        source_ip = sanitize_input(request.source_ip, max_length=45)
        destination_ip = sanitize_input(request.destination_ip, max_length=45)
        protocol = sanitize_input(request.protocol, max_length=20)
        
        # Create network flow
        flow = create_network_flow(
            flow_id=flow_id,
            source_ip=source_ip,
            destination_ip=destination_ip,
            source_port=request.source_port,
            destination_port=request.destination_port,
            protocol=protocol,
            bytes_sent=request.bytes_sent,
            bytes_received=request.bytes_received,
            packets_sent=request.packets_sent,
            packets_received=request.packets_received,
            duration=request.duration,
            flow_direction=request.flow_direction,
            flow_type=request.flow_type,
            threat_score=request.threat_score,
            is_malicious=request.is_malicious,
            is_suspicious=request.is_suspicious,
            is_encrypted=request.is_encrypted,
            tags=request.tags or {},
            attributes=request.attributes or {},
            timestamp=request.timestamp
        )
        
        # Process network flow
        background_tasks.add_task(processor.process_network_flow, flow)
        
        logger.info(f"Network flow created: {flow.id}")
        metrics.analytics_api_network_flows_created.inc()
        
        return {
            "message": "Network flow created successfully",
            "flow_id": flow.id,
            "source_ip": request.source_ip,
            "destination_ip": request.destination_ip,
            "threat_score": request.threat_score,
            "timestamp": flow.timestamp.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating network flow: {e}")
        metrics.analytics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/query", response_model=Dict[str, Any])
@traced("analytics_api_execute_query")
async def execute_analytics_query(
    request: AnalyticsQueryRequest,
    repository: AnalyticsRepository = Depends(get_analytics_repository)
):
    """Execute an analytics query."""
    try:
        # Create query object
        query = AnalyticsQuery(
            table=request.table,
            select_fields=request.select_fields,
            where_conditions=request.where_conditions,
            group_by=request.group_by,
            order_by=request.order_by,
            limit=request.limit,
            offset=request.offset,
            start_time=request.start_time,
            end_time=request.end_time,
            aggregations=request.aggregations,
            filters=request.filters
        )
        
        # Execute query
        result = await repository.execute_query(query)
        
        return {
            "table": request.table,
            "results": result.data,
            "total_rows": result.total_rows,
            "execution_time": result.execution_time,
            "metadata": result.metadata
        }
        
    except Exception as e:
        logger.error(f"Error executing analytics query: {e}")
        metrics.analytics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/events/security", response_model=Dict[str, Any])
@traced("analytics_api_get_security_events")
async def get_security_events(
    start_time: datetime = Query(...),
    end_time: datetime = Query(...),
    event_types: Optional[str] = Query(None, description="Comma-separated list of event types"),
    threat_levels: Optional[str] = Query(None, description="Comma-separated list of threat levels"),
    source_ips: Optional[str] = Query(None, description="Comma-separated list of source IPs"),
    limit: int = Query(1000, ge=1, le=10000),
    repository: AnalyticsRepository = Depends(get_analytics_repository)
):
    """Get security events with filtering."""
    try:
        # Parse filters
        event_types_list = event_types.split(",") if event_types else None
        threat_levels_list = threat_levels.split(",") if threat_levels else None
        source_ips_list = source_ips.split(",") if source_ips else None
        
        # Get events
        events = await repository.get_security_events(
            start_time=start_time,
            end_time=end_time,
            event_types=event_types_list,
            threat_levels=threat_levels_list,
            source_ips=source_ips_list,
            limit=limit
        )
        
        return {
            "events": events,
            "count": len(events),
            "time_range": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat()
            },
            "filters": {
                "event_types": event_types_list,
                "threat_levels": threat_levels_list,
                "source_ips": source_ips_list
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting security events: {e}")
        metrics.analytics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/statistics/threats", response_model=Dict[str, Any])
@traced("analytics_api_get_threat_statistics")
async def get_threat_statistics(
    start_time: datetime = Query(...),
    end_time: datetime = Query(...),
    group_by: str = Query("threat_level", regex="^(threat_level|event_type|source_ip)$"),
    repository: AnalyticsRepository = Depends(get_analytics_repository)
):
    """Get threat statistics with grouping."""
    try:
        stats = await repository.get_threat_statistics(
            start_time=start_time,
            end_time=end_time,
            group_by=group_by
        )
        
        return {
            "statistics": stats,
            "group_by": group_by,
            "time_range": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat()
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting threat statistics: {e}")
        metrics.analytics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/trends/vulnerabilities", response_model=Dict[str, Any])
@traced("analytics_api_get_vulnerability_trends")
async def get_vulnerability_trends(
    start_time: datetime = Query(...),
    end_time: datetime = Query(...),
    time_bucket: str = Query("1 DAY", regex="^(1 HOUR|1 DAY|1 WEEK)$"),
    repository: AnalyticsRepository = Depends(get_analytics_repository)
):
    """Get vulnerability trends over time."""
    try:
        trends = await repository.get_vulnerability_trends(
            start_time=start_time,
            end_time=end_time,
            time_bucket=time_bucket
        )
        
        return {
            "trends": trends,
            "time_bucket": time_bucket,
            "time_range": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat()
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting vulnerability trends: {e}")
        metrics.analytics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/analysis/network-traffic", response_model=Dict[str, Any])
@traced("analytics_api_get_network_traffic_analysis")
async def get_network_traffic_analysis(
    start_time: datetime = Query(...),
    end_time: datetime = Query(...),
    aggregation_level: str = Query("source_ip", regex="^(source_ip|destination_ip|destination_port|protocol)$"),
    repository: AnalyticsRepository = Depends(get_analytics_repository)
):
    """Get network traffic analysis."""
    try:
        analysis = await repository.get_network_traffic_analysis(
            start_time=start_time,
            end_time=end_time,
            aggregation_level=aggregation_level
        )
        
        return {
            "analysis": analysis,
            "aggregation_level": aggregation_level,
            "time_range": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat()
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting network traffic analysis: {e}")
        metrics.analytics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/dashboard/security", response_model=Dict[str, Any])
@traced("analytics_api_get_security_dashboard")
async def get_security_dashboard(
    time_range: str = Query("24h", regex="^(1h|24h|7d|30d)$"),
    include_trends: bool = Query(True),
    processor: AnalyticsProcessor = Depends(get_analytics_processor)
):
    """Get comprehensive security dashboard data."""
    try:
        dashboard = await processor.get_security_dashboard(
            time_range=time_range,
            include_trends=include_trends
        )
        
        return dashboard
        
    except Exception as e:
        logger.error(f"Error getting security dashboard: {e}")
        metrics.analytics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/dashboard/compliance", response_model=Dict[str, Any])
@traced("analytics_api_get_compliance_dashboard")
async def get_compliance_dashboard(
    framework: Optional[ComplianceFramework] = Query(None),
    repository: AnalyticsRepository = Depends(get_analytics_repository)
):
    """Get compliance dashboard data."""
    try:
        dashboard = await repository.get_compliance_dashboard(
            framework=framework.value if framework else None
        )
        
        return dashboard
        
    except Exception as e:
        logger.error(f"Error getting compliance dashboard: {e}")
        metrics.analytics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/rules/processing", response_model=Dict[str, Any])
@traced("analytics_api_create_processing_rule")
async def create_processing_rule(
    request: CreateProcessingRuleRequest,
    processor: AnalyticsProcessor = Depends(get_analytics_processor)
):
    """Create a processing rule."""
    try:
        from ..services.analytics_processor import ProcessingRule
        
        # Create processing rule
        rule = ProcessingRule(
            name=request.name,
            condition=request.condition,
            action=request.action,
            priority=request.priority,
            enabled=request.enabled,
            parameters=request.parameters
        )
        
        # Add rule to processor
        processor.add_processing_rule(rule)
        
        logger.info(f"Processing rule created: {request.name}")
        metrics.analytics_api_processing_rules_created.inc()
        
        return {
            "message": "Processing rule created successfully",
            "rule_name": request.name,
            "condition": request.condition,
            "action": request.action,
            "priority": request.priority,
            "enabled": request.enabled
        }
        
    except Exception as e:
        logger.error(f"Error creating processing rule: {e}")
        metrics.analytics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/statistics", response_model=Dict[str, Any])
@traced("analytics_api_get_statistics")
async def get_statistics(
    repository: AnalyticsRepository = Depends(get_analytics_repository),
    processor: AnalyticsProcessor = Depends(get_analytics_processor)
):
    """Get comprehensive analytics statistics."""
    try:
        repository_stats = repository.get_stats()
        processor_stats = processor.get_stats()
        
        return {
            "service": "clickhouse-service",
            "repository": repository_stats,
            "processor": processor_stats,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        metrics.analytics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/events/{table}/{event_id}", response_model=Dict[str, Any])
@traced("analytics_api_delete_event")
async def delete_event(
    table: AnalyticsTable,
    event_id: str,
    repository: AnalyticsRepository = Depends(get_analytics_repository)
):
    """Delete a specific event from analytics data."""
    try:
        # This would implement event deletion
        # For now, we'll just return a success message
        logger.info(f"Event deletion requested: {event_id} from {table}")
        
        return {
            "message": "Event deletion requested",
            "table": table,
            "event_id": event_id,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error deleting event: {e}")
        metrics.analytics_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")