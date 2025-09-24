"""
EventStore Models for Event Sourcing

This module defines the data models and structures for event sourcing
using EventStore, including events, streams, and projections.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Any
from enum import Enum
from pydantic import BaseModel, Field, validator
import uuid

from shared.observability.logging import get_logger
from shared.config.settings import get_settings

logger = get_logger(__name__)


class EventType(str, Enum):
    """Types of events in the system."""
    # Security Events
    SECURITY_ALERT_CREATED = "security_alert_created"
    SECURITY_ALERT_UPDATED = "security_alert_updated"
    SECURITY_ALERT_RESOLVED = "security_alert_resolved"
    VULNERABILITY_DETECTED = "vulnerability_detected"
    THREAT_DETECTED = "threat_detected"
    INCIDENT_CREATED = "incident_created"
    INCIDENT_UPDATED = "incident_updated"
    INCIDENT_RESOLVED = "incident_resolved"
    
    # User Events
    USER_LOGIN = "user_login"
    USER_LOGOUT = "user_logout"
    USER_CREATED = "user_created"
    USER_UPDATED = "user_updated"
    USER_DELETED = "user_deleted"
    PERMISSION_GRANTED = "permission_granted"
    PERMISSION_REVOKED = "permission_revoked"
    
    # Asset Events
    ASSET_DISCOVERED = "asset_discovered"
    ASSET_UPDATED = "asset_updated"
    ASSET_REMOVED = "asset_removed"
    ASSET_SCANNED = "asset_scanned"
    
    # Compliance Events
    COMPLIANCE_CHECK_STARTED = "compliance_check_started"
    COMPLIANCE_CHECK_COMPLETED = "compliance_check_completed"
    COMPLIANCE_VIOLATION_DETECTED = "compliance_violation_detected"
    COMPLIANCE_REMEDIATION_STARTED = "compliance_remediation_started"
    
    # Policy Events
    POLICY_CREATED = "policy_created"
    POLICY_UPDATED = "policy_updated"
    POLICY_DELETED = "policy_deleted"
    POLICY_VIOLATION = "policy_violation"
    
    # Integration Events
    INTEGRATION_CONNECTED = "integration_connected"
    INTEGRATION_DISCONNECTED = "integration_disconnected"
    DATA_INGESTED = "data_ingested"
    SCAN_COMPLETED = "scan_completed"
    
    # System Events
    SERVICE_STARTED = "service_started"
    SERVICE_STOPPED = "service_stopped"
    CONFIGURATION_CHANGED = "configuration_changed"
    BACKUP_CREATED = "backup_created"
    SNAPSHOT_CREATED = "snapshot_created"
    
    # Response Events
    RESPONSE_INITIATED = "response_initiated"
    RESPONSE_COMPLETED = "response_completed"
    NOTIFICATION_SENT = "notification_sent"
    ESCALATION_TRIGGERED = "escalation_triggered"


class AggregateType(str, Enum):
    """Types of aggregates in the domain."""
    SECURITY_ALERT = "security_alert"
    VULNERABILITY = "vulnerability"
    THREAT = "threat"
    INCIDENT = "incident"
    USER = "user"
    ASSET = "asset"
    POLICY = "policy"
    COMPLIANCE_CHECK = "compliance_check"
    INTEGRATION = "integration"
    SCAN = "scan"
    RESPONSE = "response"
    NOTIFICATION = "notification"


class BaseEventModel(BaseModel):
    """Base model for event-related entities."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    @validator('created_at', 'updated_at')
    def validate_timestamps(cls, v):
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v
    
    class Config:
        use_enum_values = True


class Event(BaseEventModel):
    """Event model for event sourcing."""
    stream_name: str = Field(...)
    event_type: EventType = Field(...)
    event_data: Dict[str, Any] = Field(...)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Aggregate information
    aggregate_id: Optional[str] = None
    aggregate_type: Optional[AggregateType] = None
    
    # Event correlation
    correlation_id: Optional[str] = None
    causation_id: Optional[str] = None
    
    # Event versioning
    version: int = Field(default=0, ge=0)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Event metadata
    event_size: int = Field(default=0, ge=0)
    content_type: str = Field(default="application/json")
    
    @validator('timestamp')
    def validate_timestamp(cls, v):
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v


class EventStream(BaseEventModel):
    """Event stream model."""
    stream_name: str = Field(...)
    aggregate_type: AggregateType = Field(...)
    description: Optional[str] = None
    
    # Stream configuration
    retention_days: Optional[int] = Field(None, ge=1, le=3650)
    snapshot_frequency: int = Field(default=100, ge=1, le=10000)
    
    # Stream state
    current_version: int = Field(default=0, ge=0)
    event_count: int = Field(default=0, ge=0)
    first_event_timestamp: Optional[datetime] = None
    last_event_timestamp: Optional[datetime] = None
    
    # Stream metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Stream status
    is_active: bool = Field(default=True)
    is_deleted: bool = Field(default=False)
    deleted_at: Optional[datetime] = None


class EventMetadata(BaseModel):
    """Event metadata model."""
    correlation_id: Optional[str] = None
    causation_id: Optional[str] = None
    user_id: Optional[str] = None
    session_id: Optional[str] = None
    request_id: Optional[str] = None
    source_service: Optional[str] = None
    source_version: Optional[str] = None
    client_ip: Optional[str] = None
    user_agent: Optional[str] = None
    trace_id: Optional[str] = None
    span_id: Optional[str] = None
    
    # Event context
    tenant_id: Optional[str] = None
    organization_id: Optional[str] = None
    environment: Optional[str] = None
    
    # Custom metadata
    custom_fields: Dict[str, Any] = Field(default_factory=dict)


class Snapshot(BaseEventModel):
    """Snapshot model for aggregate state."""
    stream_name: str = Field(...)
    aggregate_id: str = Field(...)
    version: int = Field(ge=0)
    snapshot_data: Dict[str, Any] = Field(...)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Snapshot information
    snapshot_type: str = Field(default="aggregate_state")
    compression: Optional[str] = None
    checksum: Optional[str] = None
    size_bytes: int = Field(default=0, ge=0)


class ProjectionState(BaseEventModel):
    """Projection state model."""
    projection_name: str = Field(...)
    last_processed_position: int = Field(default=0, ge=0)
    last_processed_event_id: Optional[str] = None
    last_processed_timestamp: Optional[datetime] = None
    
    # Projection status
    status: str = Field(default="running")  # running, stopped, rebuilding, error
    error_message: Optional[str] = None
    
    # Projection configuration
    query: Optional[str] = None
    filters: Dict[str, Any] = Field(default_factory=dict)
    
    # Statistics
    events_processed: int = Field(default=0, ge=0)
    processing_rate: float = Field(default=0.0, ge=0.0)
    
    # Metadata
    metadata: Dict[str, Any] = Field(default_factory=dict)


class StreamPosition(BaseModel):
    """Stream position model for tracking event positions."""
    stream_name: str = Field(...)
    position: int = Field(ge=0)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    # Position metadata
    event_id: Optional[str] = None
    event_type: Optional[EventType] = None
    checkpoint_name: Optional[str] = None


class EventQuery(BaseModel):
    """Event query model for complex event filtering."""
    stream_names: Optional[List[str]] = Field(default_factory=list)
    event_types: Optional[List[EventType]] = Field(default_factory=list)
    aggregate_types: Optional[List[AggregateType]] = Field(default_factory=list)
    aggregate_ids: Optional[List[str]] = Field(default_factory=list)
    
    # Time range
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    # Version range
    from_version: Optional[int] = Field(None, ge=0)
    to_version: Optional[int] = Field(None, ge=0)
    
    # Correlation
    correlation_ids: Optional[List[str]] = Field(default_factory=list)
    causation_ids: Optional[List[str]] = Field(default_factory=list)
    
    # Metadata filters
    metadata_filters: Dict[str, Any] = Field(default_factory=dict)
    
    # Query options
    limit: int = Field(1000, ge=1, le=10000)
    offset: int = Field(0, ge=0)
    forward: bool = Field(default=True)
    include_metadata: bool = Field(default=True)


class EventQueryResult(BaseModel):
    """Event query result model."""
    events: List[Event] = Field(default_factory=list)
    total_count: int = Field(default=0, ge=0)
    has_more: bool = Field(default=False)
    
    # Query metadata
    query: EventQuery
    execution_time_ms: float = Field(default=0.0, ge=0.0)
    from_cache: bool = Field(default=False)
    
    # Result metadata
    oldest_event_timestamp: Optional[datetime] = None
    newest_event_timestamp: Optional[datetime] = None


class EventSubscription(BaseEventModel):
    """Event subscription model for real-time event streaming."""
    subscription_name: str = Field(...)
    stream_patterns: List[str] = Field(default_factory=list)
    event_type_filters: Optional[List[EventType]] = Field(default_factory=list)
    
    # Subscription configuration
    from_position: str = Field(default="end")  # start, end, specific position
    include_system_events: bool = Field(default=False)
    buffer_size: int = Field(default=1000, ge=1, le=10000)
    
    # Subscription status
    status: str = Field(default="active")  # active, paused, stopped, error
    last_checkpoint: Optional[str] = None
    last_event_timestamp: Optional[datetime] = None
    
    # Statistics
    events_received: int = Field(default=0, ge=0)
    events_processed: int = Field(default=0, ge=0)
    events_failed: int = Field(default=0, ge=0)
    
    # Configuration
    metadata: Dict[str, Any] = Field(default_factory=dict)


class EventReplay(BaseEventModel):
    """Event replay model for event reprocessing."""
    replay_name: str = Field(...)
    source_streams: List[str] = Field(default_factory=list)
    target_handlers: List[str] = Field(default_factory=list)
    
    # Replay configuration
    from_position: str = Field(...)  # timestamp, version, or event_id
    to_position: Optional[str] = None
    replay_speed: float = Field(default=1.0, ge=0.1, le=100.0)
    
    # Replay status
    status: str = Field(default="pending")  # pending, running, completed, failed, paused
    progress_percentage: float = Field(default=0.0, ge=0.0, le=100.0)
    current_position: Optional[str] = None
    
    # Statistics
    events_replayed: int = Field(default=0, ge=0)
    events_failed: int = Field(default=0, ge=0)
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    
    # Configuration
    options: Dict[str, Any] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)


# Factory functions for creating event models
def create_event(
    stream_name: str,
    event_type: EventType,
    event_data: Dict[str, Any],
    metadata: Dict[str, Any] = None,
    **kwargs
) -> Event:
    """Create an event."""
    return Event(
        stream_name=stream_name,
        event_type=event_type,
        event_data=event_data,
        metadata=metadata or {},
        **kwargs
    )


def create_event_stream(
    stream_name: str,
    aggregate_type: AggregateType,
    **kwargs
) -> EventStream:
    """Create an event stream."""
    return EventStream(
        stream_name=stream_name,
        aggregate_type=aggregate_type,
        **kwargs
    )


def create_snapshot(
    stream_name: str,
    aggregate_id: str,
    version: int,
    snapshot_data: Dict[str, Any],
    **kwargs
) -> Snapshot:
    """Create a snapshot."""
    return Snapshot(
        stream_name=stream_name,
        aggregate_id=aggregate_id,
        version=version,
        snapshot_data=snapshot_data,
        **kwargs
    )


def create_projection_state(
    projection_name: str,
    **kwargs
) -> ProjectionState:
    """Create a projection state."""
    return ProjectionState(
        projection_name=projection_name,
        **kwargs
    )


def create_event_subscription(
    subscription_name: str,
    stream_patterns: List[str],
    **kwargs
) -> EventSubscription:
    """Create an event subscription."""
    return EventSubscription(
        subscription_name=subscription_name,
        stream_patterns=stream_patterns,
        **kwargs
    )