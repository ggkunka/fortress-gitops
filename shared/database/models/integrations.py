"""
Integration Models - Database models for external system integrations

This module defines the database models for managing external system integrations
including SIEM, cloud platforms, threat feeds, and ticketing systems.
"""

import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum

from sqlalchemy import Column, String, Text, Integer, Boolean, DateTime, Float, JSON, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import relationship
from pydantic import BaseModel, Field

from .base import BaseModel as SharedBaseModel


class IntegrationType(str, Enum):
    """Integration type enumeration."""
    SIEM = "siem"
    CLOUD_SECURITY = "cloud_security"
    THREAT_INTELLIGENCE = "threat_intelligence"
    VULNERABILITY_MANAGEMENT = "vulnerability_management"
    TICKETING = "ticketing"
    CI_CD = "ci_cd"
    NOTIFICATION = "notification"
    STORAGE = "storage"
    MONITORING = "monitoring"
    CUSTOM = "custom"


class IntegrationStatus(str, Enum):
    """Integration status enumeration."""
    PENDING = "pending"
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    DEPRECATED = "deprecated"
    SUSPENDED = "suspended"


class ConnectionStatus(str, Enum):
    """Connection status enumeration."""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    FAILED = "failed"
    TIMEOUT = "timeout"


class DataSyncStatus(str, Enum):
    """Data synchronization status enumeration."""
    SYNCHRONIZED = "synchronized"
    SYNCING = "syncing"
    FAILED = "failed"
    PENDING = "pending"
    PARTIAL = "partial"


class Integration(SharedBaseModel):
    """Integration model for external system connections."""
    
    __tablename__ = "integrations"
    
    # Basic information
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    integration_type = Column(String(50), nullable=False, index=True)
    provider = Column(String(100), nullable=False, index=True)  # e.g., "splunk", "aws", "jira"
    
    # Configuration
    config = Column(JSON, nullable=False, default={})
    credentials = Column(JSON, nullable=False, default={})  # Encrypted in production
    version = Column(String(50))
    capabilities = Column(ARRAY(String), default=[])
    
    # Status
    status = Column(String(50), default=IntegrationStatus.PENDING, index=True)
    is_enabled = Column(Boolean, default=True, index=True)
    is_bidirectional = Column(Boolean, default=False)
    
    # Connection details
    endpoint_url = Column(String(500))
    authentication_method = Column(String(50))  # api_key, oauth, basic, certificate
    timeout = Column(Integer, default=30)
    retry_attempts = Column(Integer, default=3)
    
    # Operational settings
    priority = Column(Integer, default=5)  # 1-10, higher = more priority
    health_check_interval = Column(Integer, default=300)  # seconds
    sync_interval = Column(Integer, default=3600)  # seconds
    
    # Metadata
    settings = Column(JSON, default={})
    tags = Column(ARRAY(String), default=[])
    
    # Audit fields
    created_by = Column(String(255), nullable=False)
    updated_by = Column(String(255))
    
    # Statistics
    connection_count = Column(Integer, default=0)
    last_sync_at = Column(DateTime)
    total_data_transferred = Column(Integer, default=0)  # bytes
    error_count = Column(Integer, default=0)
    
    # Relationships
    connection_logs = relationship("IntegrationConnectionLog", back_populates="integration")
    sync_logs = relationship("IntegrationSyncLog", back_populates="integration")
    webhooks = relationship("IntegrationWebhook", back_populates="integration")
    
    # Indexes
    __table_args__ = (
        Index('idx_integration_type_provider', 'integration_type', 'provider'),
        Index('idx_integration_status_enabled', 'status', 'is_enabled'),
        Index('idx_integration_created_by', 'created_by'),
        Index('idx_integration_last_sync', 'last_sync_at'),
    )


class IntegrationConnectionLog(SharedBaseModel):
    """Connection log model for tracking integration connection attempts."""
    
    __tablename__ = "integration_connection_logs"
    
    integration_id = Column(UUID(as_uuid=True), ForeignKey("integrations.id"), nullable=False, index=True)
    
    # Connection details
    connection_status = Column(String(50), nullable=False, index=True)
    attempt_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    response_time = Column(Float)  # milliseconds
    
    # Connection metadata
    endpoint = Column(String(500))
    method = Column(String(10))  # GET, POST, etc.
    status_code = Column(Integer)
    
    # Error details
    error_message = Column(Text)
    error_code = Column(String(50))
    stack_trace = Column(Text)
    
    # Context
    triggered_by = Column(String(255))  # user_id or system
    context = Column(JSON, default={})
    
    # Relationships
    integration = relationship("Integration", back_populates="connection_logs")
    
    # Indexes
    __table_args__ = (
        Index('idx_connection_log_integration_status', 'integration_id', 'connection_status'),
        Index('idx_connection_log_attempt_time', 'attempt_at'),
    )


class IntegrationSyncLog(SharedBaseModel):
    """Sync log model for tracking data synchronization operations."""
    
    __tablename__ = "integration_sync_logs"
    
    integration_id = Column(UUID(as_uuid=True), ForeignKey("integrations.id"), nullable=False, index=True)
    
    # Sync details
    sync_type = Column(String(50), nullable=False)  # pull, push, bidirectional
    status = Column(String(50), nullable=False, index=True)
    started_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    completed_at = Column(DateTime)
    duration = Column(Integer)  # seconds
    
    # Data metrics
    records_processed = Column(Integer, default=0)
    records_successful = Column(Integer, default=0)
    records_failed = Column(Integer, default=0)
    data_size = Column(Integer, default=0)  # bytes
    
    # Error details
    error_message = Column(Text)
    error_details = Column(JSON, default={})
    
    # Context
    triggered_by = Column(String(255))  # user_id or system
    sync_parameters = Column(JSON, default={})
    
    # Relationships
    integration = relationship("Integration", back_populates="sync_logs")
    
    # Indexes
    __table_args__ = (
        Index('idx_sync_log_integration_status', 'integration_id', 'status'),
        Index('idx_sync_log_started_time', 'started_at'),
        Index('idx_sync_log_sync_type', 'sync_type'),
    )


class IntegrationWebhook(SharedBaseModel):
    """Webhook model for integration event notifications."""
    
    __tablename__ = "integration_webhooks"
    
    integration_id = Column(UUID(as_uuid=True), ForeignKey("integrations.id"), nullable=False, index=True)
    
    # Webhook configuration
    name = Column(String(255), nullable=False)
    description = Column(Text)
    webhook_url = Column(String(500), nullable=False)
    secret_token = Column(String(255))  # For webhook verification
    
    # Event configuration
    events = Column(ARRAY(String), nullable=False)  # List of events to trigger on
    is_active = Column(Boolean, default=True, index=True)
    
    # HTTP configuration
    headers = Column(JSON, default={})
    timeout = Column(Integer, default=30)
    retry_attempts = Column(Integer, default=3)
    
    # Template configuration
    payload_template = Column(JSON, default={})
    content_type = Column(String(100), default="application/json")
    
    # Statistics
    total_calls = Column(Integer, default=0)
    successful_calls = Column(Integer, default=0)
    failed_calls = Column(Integer, default=0)
    last_called_at = Column(DateTime)
    
    # Audit
    created_by = Column(String(255), nullable=False)
    
    # Relationships
    integration = relationship("Integration", back_populates="webhooks")
    delivery_logs = relationship("WebhookDeliveryLog", back_populates="webhook")
    
    # Indexes
    __table_args__ = (
        Index('idx_webhook_integration_active', 'integration_id', 'is_active'),
        Index('idx_webhook_events', 'events'),
    )


class WebhookDeliveryLog(SharedBaseModel):
    """Webhook delivery log for tracking webhook calls."""
    
    __tablename__ = "webhook_delivery_logs"
    
    webhook_id = Column(UUID(as_uuid=True), ForeignKey("integration_webhooks.id"), nullable=False, index=True)
    
    # Delivery details
    event_type = Column(String(100), nullable=False, index=True)
    delivered_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    response_time = Column(Float)  # milliseconds
    
    # HTTP details
    status_code = Column(Integer)
    response_body = Column(Text)
    request_headers = Column(JSON, default={})
    response_headers = Column(JSON, default={})
    
    # Payload
    payload = Column(JSON, nullable=False)
    payload_size = Column(Integer)  # bytes
    
    # Error details
    error_message = Column(Text)
    retry_count = Column(Integer, default=0)
    
    # Success status
    is_successful = Column(Boolean, nullable=False, index=True)
    
    # Relationships
    webhook = relationship("IntegrationWebhook", back_populates="delivery_logs")
    
    # Indexes
    __table_args__ = (
        Index('idx_delivery_log_webhook_event', 'webhook_id', 'event_type'),
        Index('idx_delivery_log_delivered_time', 'delivered_at'),
        Index('idx_delivery_log_success', 'is_successful'),
    )


class IntegrationTemplate(SharedBaseModel):
    """Integration template model for pre-configured integration setups."""
    
    __tablename__ = "integration_templates"
    
    # Template information
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    integration_type = Column(String(50), nullable=False, index=True)
    provider = Column(String(100), nullable=False, index=True)
    version = Column(String(50))
    
    # Template configuration
    config_template = Column(JSON, nullable=False, default={})
    credentials_template = Column(JSON, nullable=False, default={})
    required_fields = Column(ARRAY(String), default=[])
    optional_fields = Column(ARRAY(String), default=[])
    
    # Capabilities and requirements
    capabilities = Column(ARRAY(String), default=[])
    requirements = Column(JSON, default={})
    
    # Template metadata
    is_active = Column(Boolean, default=True, index=True)
    is_community = Column(Boolean, default=False)
    is_verified = Column(Boolean, default=False)
    
    # Usage statistics
    usage_count = Column(Integer, default=0)
    rating_average = Column(Float, default=0.0)
    rating_count = Column(Integer, default=0)
    
    # Documentation
    documentation = Column(Text)
    setup_guide = Column(Text)
    troubleshooting_guide = Column(Text)
    
    # Audit
    created_by = Column(String(255), nullable=False)
    
    # Indexes
    __table_args__ = (
        Index('idx_template_type_provider', 'integration_type', 'provider'),
        Index('idx_template_active_verified', 'is_active', 'is_verified'),
        Index('idx_template_usage_rating', 'usage_count', 'rating_average'),
    )


class IntegrationMetrics(SharedBaseModel):
    """Integration metrics model for performance and usage tracking."""
    
    __tablename__ = "integration_metrics"
    
    integration_id = Column(UUID(as_uuid=True), ForeignKey("integrations.id"), nullable=False, index=True)
    
    # Time period
    metric_date = Column(DateTime, nullable=False, index=True)
    period_type = Column(String(20), nullable=False)  # hour, day, week, month
    
    # Connection metrics
    connection_attempts = Column(Integer, default=0)
    successful_connections = Column(Integer, default=0)
    failed_connections = Column(Integer, default=0)
    average_response_time = Column(Float, default=0.0)
    
    # Data transfer metrics
    data_pulled = Column(Integer, default=0)  # bytes
    data_pushed = Column(Integer, default=0)  # bytes
    records_processed = Column(Integer, default=0)
    sync_operations = Column(Integer, default=0)
    
    # Error metrics
    total_errors = Column(Integer, default=0)
    error_rate = Column(Float, default=0.0)  # percentage
    
    # Performance metrics
    uptime_percentage = Column(Float, default=0.0)
    throughput = Column(Float, default=0.0)  # records per second
    
    # Relationships
    integration = relationship("Integration")
    
    # Indexes
    __table_args__ = (
        Index('idx_metrics_integration_date', 'integration_id', 'metric_date'),
        Index('idx_metrics_period_type', 'period_type'),
    )


# Pydantic models for API

class IntegrationCreate(BaseModel):
    """Request model for creating an integration."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    integration_type: IntegrationType
    provider: str = Field(..., min_length=1, max_length=100)
    config: Dict[str, Any] = Field(default_factory=dict)
    credentials: Dict[str, Any] = Field(default_factory=dict)
    version: Optional[str] = Field(None, max_length=50)
    capabilities: List[str] = Field(default_factory=list)
    is_enabled: bool = Field(default=True)
    is_bidirectional: bool = Field(default=False)
    endpoint_url: Optional[str] = Field(None, max_length=500)
    authentication_method: Optional[str] = Field(None, max_length=50)
    timeout: int = Field(default=30, ge=1, le=300)
    retry_attempts: int = Field(default=3, ge=0, le=10)
    priority: int = Field(default=5, ge=1, le=10)
    health_check_interval: int = Field(default=300, ge=60, le=3600)
    sync_interval: int = Field(default=3600, ge=300, le=86400)
    settings: Dict[str, Any] = Field(default_factory=dict)
    tags: List[str] = Field(default_factory=list)
    created_by: str = Field(..., min_length=1, max_length=255)


class IntegrationUpdate(BaseModel):
    """Request model for updating an integration."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    config: Optional[Dict[str, Any]] = None
    credentials: Optional[Dict[str, Any]] = None
    capabilities: Optional[List[str]] = None
    is_enabled: Optional[bool] = None
    is_bidirectional: Optional[bool] = None
    endpoint_url: Optional[str] = Field(None, max_length=500)
    timeout: Optional[int] = Field(None, ge=1, le=300)
    retry_attempts: Optional[int] = Field(None, ge=0, le=10)
    priority: Optional[int] = Field(None, ge=1, le=10)
    health_check_interval: Optional[int] = Field(None, ge=60, le=3600)
    sync_interval: Optional[int] = Field(None, ge=300, le=86400)
    settings: Optional[Dict[str, Any]] = None
    tags: Optional[List[str]] = None
    updated_by: str = Field(..., min_length=1, max_length=255)


class IntegrationResponse(BaseModel):
    """Response model for integration data."""
    id: str
    name: str
    description: Optional[str]
    integration_type: str
    provider: str
    config: Dict[str, Any]
    version: Optional[str]
    capabilities: List[str]
    status: str
    is_enabled: bool
    is_bidirectional: bool
    endpoint_url: Optional[str]
    authentication_method: Optional[str]
    timeout: int
    retry_attempts: int
    priority: int
    health_check_interval: int
    sync_interval: int
    settings: Dict[str, Any]
    tags: List[str]
    created_by: str
    updated_by: Optional[str]
    created_at: datetime
    updated_at: datetime
    connection_count: int
    last_sync_at: Optional[datetime]
    error_count: int
    
    class Config:
        from_attributes = True


class WebhookCreate(BaseModel):
    """Request model for creating a webhook."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    webhook_url: str = Field(..., min_length=1, max_length=500)
    secret_token: Optional[str] = Field(None, max_length=255)
    events: List[str] = Field(..., min_items=1)
    headers: Dict[str, str] = Field(default_factory=dict)
    timeout: int = Field(default=30, ge=1, le=300)
    retry_attempts: int = Field(default=3, ge=0, le=10)
    payload_template: Dict[str, Any] = Field(default_factory=dict)
    content_type: str = Field(default="application/json", max_length=100)
    created_by: str = Field(..., min_length=1, max_length=255)


class WebhookResponse(BaseModel):
    """Response model for webhook data."""
    id: str
    integration_id: str
    name: str
    description: Optional[str]
    webhook_url: str
    events: List[str]
    is_active: bool
    headers: Dict[str, str]
    timeout: int
    retry_attempts: int
    payload_template: Dict[str, Any]
    content_type: str
    total_calls: int
    successful_calls: int
    failed_calls: int
    last_called_at: Optional[datetime]
    created_by: str
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class ConnectionLogResponse(BaseModel):
    """Response model for connection log data."""
    id: str
    integration_id: str
    connection_status: str
    attempt_at: datetime
    response_time: Optional[float]
    endpoint: Optional[str]
    method: Optional[str]
    status_code: Optional[int]
    error_message: Optional[str]
    error_code: Optional[str]
    triggered_by: Optional[str]
    
    class Config:
        from_attributes = True


class SyncLogResponse(BaseModel):
    """Response model for sync log data."""
    id: str
    integration_id: str
    sync_type: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime]
    duration: Optional[int]
    records_processed: int
    records_successful: int
    records_failed: int
    data_size: int
    error_message: Optional[str]
    triggered_by: Optional[str]
    
    class Config:
        from_attributes = True


# Factory functions

def create_integration(
    name: str,
    integration_type: IntegrationType,
    provider: str,
    config: Dict[str, Any],
    credentials: Dict[str, Any],
    created_by: str,
    **kwargs
) -> Integration:
    """Create a new integration instance."""
    integration = Integration(
        id=uuid.uuid4(),
        name=name,
        integration_type=integration_type.value,
        provider=provider,
        config=config,
        credentials=credentials,
        created_by=created_by,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        **kwargs
    )
    
    return integration


def create_webhook(
    integration_id: uuid.UUID,
    name: str,
    webhook_url: str,
    events: List[str],
    created_by: str,
    **kwargs
) -> IntegrationWebhook:
    """Create a new webhook instance."""
    webhook = IntegrationWebhook(
        id=uuid.uuid4(),
        integration_id=integration_id,
        name=name,
        webhook_url=webhook_url,
        events=events,
        created_by=created_by,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        **kwargs
    )
    
    return webhook