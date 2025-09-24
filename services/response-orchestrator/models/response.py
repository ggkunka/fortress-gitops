"""
Response Orchestrator Models - Database models for incident response
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from uuid import UUID, uuid4
from enum import Enum

from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, Text, JSON, ForeignKey, Index
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, Session
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.engine import create_engine

from shared.database.connection import get_db_session

Base = declarative_base()


class IncidentStatus(str, Enum):
    """Incident status."""
    DETECTED = "detected"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"


class IncidentSeverity(str, Enum):
    """Incident severity."""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ResponseActionType(str, Enum):
    """Response action types."""
    INVESTIGATION = "investigation"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    NOTIFICATION = "notification"
    DOCUMENTATION = "documentation"


class ResponseActionStatus(str, Enum):
    """Response action status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PlaybookStatus(str, Enum):
    """Playbook status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    DEPRECATED = "deprecated"


class Incident(Base):
    """Incident model."""
    __tablename__ = "incidents"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    correlation_result_id = Column(PGUUID(as_uuid=True), index=True)
    risk_assessment_id = Column(PGUUID(as_uuid=True), index=True)
    
    # Basic incident info
    title = Column(String(255), nullable=False)
    description = Column(Text)
    severity = Column(String(20), nullable=False)  # IncidentSeverity enum
    status = Column(String(20), nullable=False, default=IncidentStatus.DETECTED)
    
    # Classification
    incident_type = Column(String(100), nullable=False)
    category = Column(String(100))
    subcategory = Column(String(100))
    
    # Timing
    detected_at = Column(DateTime, default=datetime.now)
    acknowledged_at = Column(DateTime)
    contained_at = Column(DateTime)
    resolved_at = Column(DateTime)
    closed_at = Column(DateTime)
    
    # Impact and scope
    impact_score = Column(Float, nullable=False)  # 0-100
    affected_systems = Column(JSON)  # List of affected systems
    affected_users = Column(JSON)  # List of affected users
    business_impact = Column(Text)
    
    # Response data
    response_playbook_id = Column(PGUUID(as_uuid=True), ForeignKey("response_playbooks.id"))
    escalation_level = Column(Integer, default=1)
    escalation_rules = Column(JSON)
    
    # Assignments
    assigned_to = Column(String(255))
    assigned_team = Column(String(255))
    incident_commander = Column(String(255))
    
    # Metrics
    detection_time = Column(Float)  # Time to detect (seconds)
    response_time = Column(Float)  # Time to respond (seconds)
    resolution_time = Column(Float)  # Time to resolve (seconds)
    
    # External references
    external_ticket_id = Column(String(255))
    external_system = Column(String(100))
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    created_by = Column(String(255))
    updated_by = Column(String(255))
    metadata = Column(JSON)
    tags = Column(JSON)
    
    # Relationships
    response_actions = relationship("ResponseAction", back_populates="incident")
    playbook = relationship("ResponsePlaybook", back_populates="incidents")
    
    __table_args__ = (
        Index("idx_incidents_status_severity", "status", "severity"),
        Index("idx_incidents_detected_at", "detected_at"),
        Index("idx_incidents_assigned_to", "assigned_to"),
    )


class ResponsePlaybook(Base):
    """Response playbook model."""
    __tablename__ = "response_playbooks"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Playbook info
    name = Column(String(255), nullable=False)
    description = Column(Text)
    version = Column(String(20), default="1.0")
    
    # Trigger conditions
    trigger_conditions = Column(JSON, nullable=False)
    incident_types = Column(JSON)  # List of incident types
    severity_levels = Column(JSON)  # List of severity levels
    
    # Playbook steps
    steps = Column(JSON, nullable=False)  # List of playbook steps
    decision_tree = Column(JSON)  # Decision tree for conditional steps
    
    # Configuration
    auto_execute = Column(Boolean, default=False)
    require_approval = Column(Boolean, default=True)
    timeout_minutes = Column(Integer, default=60)
    
    # Metrics
    execution_count = Column(Integer, default=0)
    success_rate = Column(Float, default=0.0)
    avg_execution_time = Column(Float, default=0.0)
    
    # Status
    status = Column(String(20), default=PlaybookStatus.ACTIVE)
    is_default = Column(Boolean, default=False)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    created_by = Column(String(255))
    updated_by = Column(String(255))
    
    # Relationships
    incidents = relationship("Incident", back_populates="playbook")
    
    __table_args__ = (
        Index("idx_response_playbooks_status", "status"),
        Index("idx_response_playbooks_auto_execute", "auto_execute"),
    )


class ResponseAction(Base):
    """Response action model."""
    __tablename__ = "response_actions"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    incident_id = Column(PGUUID(as_uuid=True), ForeignKey("incidents.id"), nullable=False)
    
    # Action details
    action_name = Column(String(255), nullable=False)
    action_type = Column(String(50), nullable=False)  # ResponseActionType enum
    description = Column(Text)
    
    # Execution details
    executor = Column(String(255))  # Who/what executes this action
    execution_method = Column(String(50))  # manual, automated, api, script
    command = Column(Text)  # Command or script to execute
    parameters = Column(JSON)  # Action parameters
    
    # Status and timing
    status = Column(String(20), default=ResponseActionStatus.PENDING)
    priority = Column(Integer, default=5)  # 1-10
    order_index = Column(Integer, nullable=False)
    
    # Timing
    scheduled_at = Column(DateTime)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    timeout_at = Column(DateTime)
    
    # Results
    result = Column(JSON)  # Action execution result
    output = Column(Text)  # Action output/logs
    error_message = Column(Text)  # Error details if failed
    
    # Dependencies
    depends_on = Column(JSON)  # List of action IDs this depends on
    blocks = Column(JSON)  # List of action IDs this blocks
    
    # Approval workflow
    requires_approval = Column(Boolean, default=False)
    approved_by = Column(String(255))
    approved_at = Column(DateTime)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    metadata = Column(JSON)
    
    # Relationships
    incident = relationship("Incident", back_populates="response_actions")
    
    __table_args__ = (
        Index("idx_response_actions_incident_id", "incident_id"),
        Index("idx_response_actions_status", "status"),
        Index("idx_response_actions_priority", "priority"),
        Index("idx_response_actions_order", "order_index"),
    )


class EscalationRule(Base):
    """Escalation rule model."""
    __tablename__ = "escalation_rules"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Rule details
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Trigger conditions
    trigger_conditions = Column(JSON, nullable=False)
    severity_threshold = Column(String(20))  # IncidentSeverity enum
    time_threshold = Column(Integer)  # Minutes
    status_conditions = Column(JSON)  # List of status conditions
    
    # Escalation actions
    escalation_actions = Column(JSON, nullable=False)
    notification_targets = Column(JSON)  # Who to notify
    escalation_level = Column(Integer, nullable=False)
    
    # Configuration
    is_active = Column(Boolean, default=True)
    auto_escalate = Column(Boolean, default=True)
    max_escalations = Column(Integer, default=3)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    created_by = Column(String(255))
    
    __table_args__ = (
        Index("idx_escalation_rules_active", "is_active"),
        Index("idx_escalation_rules_level", "escalation_level"),
    )


class NotificationTemplate(Base):
    """Notification template model."""
    __tablename__ = "notification_templates"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Template details
    name = Column(String(255), nullable=False)
    description = Column(Text)
    template_type = Column(String(50), nullable=False)  # email, sms, slack, etc.
    
    # Template content
    subject_template = Column(String(500))
    body_template = Column(Text, nullable=False)
    variables = Column(JSON)  # Available template variables
    
    # Targeting
    target_roles = Column(JSON)  # List of roles to notify
    target_individuals = Column(JSON)  # List of specific individuals
    
    # Configuration
    is_active = Column(Boolean, default=True)
    priority = Column(Integer, default=5)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    created_by = Column(String(255))
    
    __table_args__ = (
        Index("idx_notification_templates_type", "template_type"),
        Index("idx_notification_templates_active", "is_active"),
    )


class ResponseMetrics(Base):
    """Response metrics model."""
    __tablename__ = "response_metrics"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Time period
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    
    # Incident metrics
    total_incidents = Column(Integer, default=0)
    incidents_by_severity = Column(JSON)  # Breakdown by severity
    incidents_by_type = Column(JSON)  # Breakdown by type
    
    # Timing metrics
    avg_detection_time = Column(Float, default=0.0)
    avg_response_time = Column(Float, default=0.0)
    avg_resolution_time = Column(Float, default=0.0)
    
    # Performance metrics
    successful_responses = Column(Integer, default=0)
    failed_responses = Column(Integer, default=0)
    escalated_incidents = Column(Integer, default=0)
    
    # Playbook metrics
    playbook_executions = Column(Integer, default=0)
    automated_actions = Column(Integer, default=0)
    manual_actions = Column(Integer, default=0)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    metadata = Column(JSON)
    
    __table_args__ = (
        Index("idx_response_metrics_period", "period_start", "period_end"),
    )


class ResponseIntegration(Base):
    """Response integration model."""
    __tablename__ = "response_integrations"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Integration details
    name = Column(String(255), nullable=False)
    integration_type = Column(String(50), nullable=False)  # soar, itsm, chat, etc.
    description = Column(Text)
    
    # Configuration
    endpoint_url = Column(String(500))
    authentication_config = Column(JSON)  # Auth configuration
    integration_config = Column(JSON)  # Integration-specific config
    
    # Capabilities
    supported_actions = Column(JSON)  # List of supported actions
    webhook_url = Column(String(500))
    api_version = Column(String(20))
    
    # Status
    is_active = Column(Boolean, default=True)
    is_healthy = Column(Boolean, default=True)
    last_health_check = Column(DateTime)
    
    # Metrics
    total_calls = Column(Integer, default=0)
    successful_calls = Column(Integer, default=0)
    failed_calls = Column(Integer, default=0)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    created_by = Column(String(255))
    
    __table_args__ = (
        Index("idx_response_integrations_type", "integration_type"),
        Index("idx_response_integrations_active", "is_active"),
    )


# Database utility functions
def create_incident(
    title: str,
    correlation_result_id: UUID,
    severity: IncidentSeverity,
    incident_type: str,
    impact_score: float,
    created_by: str,
    description: Optional[str] = None,
    **kwargs
) -> Incident:
    """Create a new incident."""
    incident = Incident(
        title=title,
        correlation_result_id=correlation_result_id,
        severity=severity,
        incident_type=incident_type,
        impact_score=impact_score,
        created_by=created_by,
        description=description,
        **kwargs
    )
    return incident


def create_response_action(
    incident_id: UUID,
    action_name: str,
    action_type: ResponseActionType,
    order_index: int,
    executor: str = "system",
    execution_method: str = "automated",
    **kwargs
) -> ResponseAction:
    """Create a new response action."""
    action = ResponseAction(
        incident_id=incident_id,
        action_name=action_name,
        action_type=action_type,
        order_index=order_index,
        executor=executor,
        execution_method=execution_method,
        **kwargs
    )
    return action


def get_db() -> Session:
    """Get database session."""
    return get_db_session()