"""
Event types and data structures for the plugin system.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

from pydantic import BaseModel, Field


class EventType(str, Enum):
    """Standard event types in the MCP platform."""
    
    # Security events
    VULNERABILITY_DETECTED = "security.vulnerability_detected"
    THREAT_DETECTED = "security.threat_detected"
    INCIDENT_CREATED = "security.incident_created"
    INCIDENT_UPDATED = "security.incident_updated"
    ALERT_TRIGGERED = "security.alert_triggered"
    
    # System events
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    HEALTH_CHECK = "system.health_check"
    CONFIG_UPDATED = "system.config_updated"
    
    # Plugin events
    PLUGIN_LOADED = "plugin.loaded"
    PLUGIN_UNLOADED = "plugin.unloaded"
    PLUGIN_ERROR = "plugin.error"
    PLUGIN_CONFIG_UPDATED = "plugin.config_updated"
    
    # Analysis events
    ANALYSIS_STARTED = "analysis.started"
    ANALYSIS_COMPLETED = "analysis.completed"
    ANALYSIS_FAILED = "analysis.failed"
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    
    # Enrichment events
    ENRICHMENT_REQUESTED = "enrichment.requested"
    ENRICHMENT_COMPLETED = "enrichment.completed"
    ENRICHMENT_FAILED = "enrichment.failed"
    
    # Notification events
    NOTIFICATION_SENT = "notification.sent"
    NOTIFICATION_FAILED = "notification.failed"
    ESCALATION_TRIGGERED = "notification.escalation_triggered"
    
    # Data events
    DATA_INGESTED = "data.ingested"
    DATA_PROCESSED = "data.processed"
    DATA_ENRICHED = "data.enriched"
    DATA_EXPORTED = "data.exported"
    
    # Custom events (plugins can define their own)
    CUSTOM = "custom"


class EventPriority(str, Enum):
    """Event priority levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class EventStatus(str, Enum):
    """Event processing status."""
    PENDING = "pending"
    PROCESSING = "processing"
    PROCESSED = "processed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SecurityEvent(BaseModel):
    """Base security event structure."""
    
    # Event identification
    event_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique event identifier")
    event_type: Union[EventType, str] = Field(..., description="Type of event")
    event_name: str = Field("", description="Human-readable event name")
    
    # Timing
    timestamp: datetime = Field(default_factory=datetime.now, description="Event occurrence time")
    created_at: datetime = Field(default_factory=datetime.now, description="Event creation time")
    
    # Source information
    source: str = Field("", description="Event source system/component")
    source_id: str = Field("", description="Source identifier")
    source_type: str = Field("", description="Type of source (plugin, service, etc.)")
    
    # Event data
    data: Dict[str, Any] = Field(default_factory=dict, description="Event payload data")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Event metadata")
    
    # Classification
    priority: EventPriority = Field(EventPriority.MEDIUM, description="Event priority")
    severity: Optional[str] = Field(None, description="Security severity level")
    category: str = Field("", description="Event category")
    subcategory: str = Field("", description="Event subcategory")
    
    # Relationships
    related_events: List[str] = Field(default_factory=list, description="Related event IDs")
    parent_event_id: Optional[str] = Field(None, description="Parent event ID")
    correlation_id: Optional[str] = Field(None, description="Correlation identifier")
    
    # Processing information
    status: EventStatus = Field(EventStatus.PENDING, description="Processing status")
    processed_by: List[str] = Field(default_factory=list, description="Components that processed this event")
    processing_errors: List[str] = Field(default_factory=list, description="Processing errors")
    
    # Tags and labels
    tags: List[str] = Field(default_factory=list, description="Event tags")
    labels: Dict[str, str] = Field(default_factory=dict, description="Event labels")
    
    # TTL and retention
    ttl_seconds: Optional[int] = Field(None, description="Time to live in seconds")
    retain_until: Optional[datetime] = Field(None, description="Retention deadline")
    
    class Config:
        use_enum_values = True


class PluginEvent(BaseModel):
    """Plugin-specific event structure."""
    
    # Event identification
    event_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique event identifier")
    event_type: str = Field(..., description="Plugin-specific event type")
    
    # Plugin information
    plugin_id: str = Field(..., description="Plugin identifier")
    plugin_name: str = Field("", description="Plugin name")
    plugin_version: str = Field("", description="Plugin version")
    
    # Timing
    timestamp: datetime = Field(default_factory=datetime.now, description="Event timestamp")
    
    # Event data
    data: Dict[str, Any] = Field(default_factory=dict, description="Plugin event data")
    context: Dict[str, Any] = Field(default_factory=dict, description="Event context")
    
    # Processing
    target_plugins: List[str] = Field(default_factory=list, description="Target plugin IDs")
    broadcast: bool = Field(False, description="Broadcast to all interested plugins")
    
    # Metadata
    priority: EventPriority = Field(EventPriority.MEDIUM, description="Event priority")
    correlation_id: Optional[str] = Field(None, description="Correlation identifier")
    
    class Config:
        use_enum_values = True


class EventFilter(BaseModel):
    """Event filtering configuration."""
    
    # Type filtering
    event_types: List[str] = Field(default_factory=list, description="Event types to include")
    exclude_types: List[str] = Field(default_factory=list, description="Event types to exclude")
    
    # Source filtering
    sources: List[str] = Field(default_factory=list, description="Sources to include")
    exclude_sources: List[str] = Field(default_factory=list, description="Sources to exclude")
    
    # Priority filtering
    min_priority: Optional[EventPriority] = Field(None, description="Minimum priority")
    max_priority: Optional[EventPriority] = Field(None, description="Maximum priority")
    
    # Tag filtering
    required_tags: List[str] = Field(default_factory=list, description="Required tags")
    forbidden_tags: List[str] = Field(default_factory=list, description="Forbidden tags")
    
    # Label filtering
    required_labels: Dict[str, str] = Field(default_factory=dict, description="Required labels")
    forbidden_labels: Dict[str, str] = Field(default_factory=dict, description="Forbidden labels")
    
    # Time filtering
    min_age_seconds: Optional[int] = Field(None, description="Minimum event age in seconds")
    max_age_seconds: Optional[int] = Field(None, description="Maximum event age in seconds")
    
    # Data filtering (JSONPath expressions)
    data_filters: List[str] = Field(default_factory=list, description="JSONPath filters for event data")


class EventSubscription(BaseModel):
    """Event subscription configuration."""
    
    # Subscription identification
    subscription_id: str = Field(default_factory=lambda: str(uuid4()), description="Unique subscription ID")
    subscriber_id: str = Field(..., description="Subscriber identifier (plugin ID)")
    subscription_name: str = Field("", description="Human-readable subscription name")
    
    # Filtering
    filters: EventFilter = Field(default_factory=EventFilter, description="Event filters")
    
    # Delivery configuration
    delivery_mode: str = Field("async", description="Delivery mode: async, sync, batch")
    batch_size: int = Field(1, description="Batch size for batch delivery")
    batch_timeout: int = Field(30, description="Batch timeout in seconds")
    
    # Retry configuration
    max_retries: int = Field(3, description="Maximum retry attempts")
    retry_delay: int = Field(5, description="Retry delay in seconds")
    
    # Flow control
    max_queue_size: int = Field(1000, description="Maximum queue size")
    backpressure_policy: str = Field("drop", description="Backpressure policy: drop, block, error")
    
    # State
    active: bool = Field(True, description="Subscription active state")
    created_at: datetime = Field(default_factory=datetime.now, description="Subscription creation time")
    updated_at: datetime = Field(default_factory=datetime.now, description="Last update time")
    
    # Statistics
    events_delivered: int = Field(0, description="Total events delivered")
    events_failed: int = Field(0, description="Total delivery failures")
    last_delivery: Optional[datetime] = Field(None, description="Last successful delivery")


class EventMetrics(BaseModel):
    """Event system metrics."""
    
    # Counters
    total_events: int = Field(0, description="Total events processed")
    events_by_type: Dict[str, int] = Field(default_factory=dict, description="Events by type")
    events_by_source: Dict[str, int] = Field(default_factory=dict, description="Events by source")
    events_by_priority: Dict[str, int] = Field(default_factory=dict, description="Events by priority")
    
    # Processing metrics
    average_processing_time: float = Field(0.0, description="Average processing time in seconds")
    failed_events: int = Field(0, description="Total failed events")
    
    # Queue metrics
    current_queue_size: int = Field(0, description="Current queue size")
    max_queue_size: int = Field(0, description="Maximum queue size reached")
    
    # Subscription metrics
    active_subscriptions: int = Field(0, description="Active subscriptions")
    total_deliveries: int = Field(0, description="Total event deliveries")
    failed_deliveries: int = Field(0, description="Failed deliveries")
    
    # Time window
    window_start: datetime = Field(default_factory=datetime.now, description="Metrics window start")
    window_end: datetime = Field(default_factory=datetime.now, description="Metrics window end")