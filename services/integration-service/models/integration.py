"""
Integration Models - Database models for external system integrations
"""

from datetime import datetime
from enum import Enum
from typing import Dict, List, Optional, Any
from uuid import UUID, uuid4

from sqlalchemy import Column, String, DateTime, Boolean, Text, JSON, Integer, ForeignKey
from sqlalchemy.dialects.postgresql import UUID as SQLAlchemyUUID, JSONB
from sqlalchemy.orm import relationship, Session
from pydantic import BaseModel, Field

from shared.database.models.base import BaseModel as SQLAlchemyBase
from shared.database.connection import get_db


class IntegrationType(str, Enum):
    """Integration types."""
    SIEM = "siem"
    CLOUD = "cloud"
    THREAT_FEED = "threat_feed"
    VULNERABILITY_FEED = "vulnerability_feed"
    TICKETING = "ticketing"
    NOTIFICATION = "notification"
    CUSTOM = "custom"


class IntegrationStatus(str, Enum):
    """Integration status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    ERROR = "error"
    PENDING = "pending"
    DISABLED = "disabled"


class ConnectionStatus(str, Enum):
    """Connection status."""
    CONNECTED = "connected"
    DISCONNECTED = "disconnected"
    CONNECTING = "connecting"
    FAILED = "failed"
    UNKNOWN = "unknown"


class DataSyncStatus(str, Enum):
    """Data synchronization status."""
    SYNCHRONIZED = "synchronized"
    SYNCING = "syncing"
    OUT_OF_SYNC = "out_of_sync"
    SYNC_FAILED = "sync_failed"
    NEVER_SYNCED = "never_synced"


# SQLAlchemy Models

class Integration(SQLAlchemyBase):
    """External system integration configuration."""
    __tablename__ = "integrations"
    
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    integration_type = Column(String(50), nullable=False, index=True)
    provider = Column(String(100), nullable=False, index=True)
    version = Column(String(50))
    
    # Configuration
    config = Column(JSONB, nullable=False, default={})
    credentials = Column(JSONB, nullable=False, default={})  # Encrypted
    capabilities = Column(JSONB, nullable=False, default=[])
    settings = Column(JSONB, nullable=False, default={})
    
    # Status
    status = Column(String(50), nullable=False, default="inactive", index=True)
    connection_status = Column(String(50), nullable=False, default="unknown")
    data_sync_status = Column(String(50), nullable=False, default="never_synced")
    last_sync_at = Column(DateTime)
    last_health_check = Column(DateTime)
    health_check_interval = Column(Integer, default=300)  # seconds
    
    # Metadata
    is_enabled = Column(Boolean, nullable=False, default=True)
    is_bidirectional = Column(Boolean, nullable=False, default=False)
    priority = Column(Integer, default=0)
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    
    # Audit fields
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String(255), nullable=False)
    updated_by = Column(String(255))
    
    # Relationships
    connection_logs = relationship("IntegrationConnectionLog", back_populates="integration", cascade="all, delete-orphan")
    sync_logs = relationship("IntegrationSyncLog", back_populates="integration", cascade="all, delete-orphan")
    webhooks = relationship("IntegrationWebhook", back_populates="integration", cascade="all, delete-orphan")


class IntegrationConnectionLog(SQLAlchemyBase):
    """Integration connection attempt logs."""
    __tablename__ = "integration_connection_logs"
    
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid4)
    integration_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("integrations.id"), nullable=False, index=True)
    
    # Connection details
    attempt_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    connection_status = Column(String(50), nullable=False)
    response_time = Column(Integer)  # milliseconds
    error_message = Column(Text)
    error_details = Column(JSONB)
    
    # Health check data
    health_data = Column(JSONB)
    capabilities_detected = Column(JSONB)
    version_detected = Column(String(50))
    
    # Relationship
    integration = relationship("Integration", back_populates="connection_logs")


class IntegrationSyncLog(SQLAlchemyBase):
    """Integration data synchronization logs."""
    __tablename__ = "integration_sync_logs"
    
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid4)
    integration_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("integrations.id"), nullable=False, index=True)
    
    # Sync details
    sync_type = Column(String(50), nullable=False)  # pull, push, bidirectional
    started_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    completed_at = Column(DateTime)
    duration = Column(Integer)  # seconds
    
    # Status and results
    status = Column(String(50), nullable=False)
    records_processed = Column(Integer, default=0)
    records_successful = Column(Integer, default=0)
    records_failed = Column(Integer, default=0)
    records_skipped = Column(Integer, default=0)
    
    # Error handling
    error_message = Column(Text)
    error_details = Column(JSONB)
    
    # Sync metadata
    sync_metadata = Column(JSONB)
    data_checksum = Column(String(64))
    
    # Relationship
    integration = relationship("Integration", back_populates="sync_logs")


class IntegrationWebhook(SQLAlchemyBase):
    """Integration webhook configurations."""
    __tablename__ = "integration_webhooks"
    
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid4)
    integration_id = Column(SQLAlchemyUUID(as_uuid=True), ForeignKey("integrations.id"), nullable=False, index=True)
    
    # Webhook details
    name = Column(String(255), nullable=False)
    description = Column(Text)
    webhook_url = Column(String(1000), nullable=False)
    secret_token = Column(String(255))  # Encrypted
    
    # Configuration
    events = Column(JSONB, nullable=False, default=[])  # Events to trigger webhook
    headers = Column(JSONB, nullable=False, default={})
    payload_template = Column(Text)
    timeout = Column(Integer, default=30)  # seconds
    
    # Status
    is_active = Column(Boolean, nullable=False, default=True)
    last_triggered = Column(DateTime)
    success_count = Column(Integer, default=0)
    failure_count = Column(Integer, default=0)
    
    # Audit fields
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String(255), nullable=False)
    
    # Relationship
    integration = relationship("Integration", back_populates="webhooks")


class IntegrationTemplate(SQLAlchemyBase):
    """Pre-configured integration templates."""
    __tablename__ = "integration_templates"
    
    id = Column(SQLAlchemyUUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    integration_type = Column(String(50), nullable=False, index=True)
    provider = Column(String(100), nullable=False, index=True)
    version = Column(String(50))
    
    # Template configuration
    config_template = Column(JSONB, nullable=False, default={})
    required_fields = Column(JSONB, nullable=False, default=[])
    optional_fields = Column(JSONB, nullable=False, default=[])
    default_settings = Column(JSONB, nullable=False, default={})
    capabilities = Column(JSONB, nullable=False, default=[])
    
    # Documentation
    documentation_url = Column(String(1000))
    setup_instructions = Column(Text)
    troubleshooting_guide = Column(Text)
    
    # Status
    is_active = Column(Boolean, nullable=False, default=True)
    is_community = Column(Boolean, nullable=False, default=False)
    usage_count = Column(Integer, default=0)
    
    # Audit fields
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)
    updated_at = Column(DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by = Column(String(255), nullable=False)


# Pydantic Models for API

class IntegrationBase(BaseModel):
    """Base integration model."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    integration_type: IntegrationType
    provider: str = Field(..., min_length=1, max_length=100)
    version: Optional[str] = Field(None, max_length=50)
    config: Dict[str, Any] = Field(default_factory=dict)
    capabilities: List[str] = Field(default_factory=list)
    settings: Dict[str, Any] = Field(default_factory=dict)
    is_enabled: bool = True
    is_bidirectional: bool = False
    priority: int = 0
    health_check_interval: int = Field(300, ge=60, le=3600)


class IntegrationCreate(IntegrationBase):
    """Integration creation model."""
    credentials: Dict[str, Any] = Field(..., description="Integration credentials")
    created_by: str = Field(..., min_length=1, max_length=255)


class IntegrationUpdate(BaseModel):
    """Integration update model."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    config: Optional[Dict[str, Any]] = None
    credentials: Optional[Dict[str, Any]] = None
    settings: Optional[Dict[str, Any]] = None
    is_enabled: Optional[bool] = None
    is_bidirectional: Optional[bool] = None
    priority: Optional[int] = None
    health_check_interval: Optional[int] = Field(None, ge=60, le=3600)
    updated_by: str = Field(..., min_length=1, max_length=255)


class IntegrationResponse(IntegrationBase):
    """Integration response model."""
    id: UUID
    status: IntegrationStatus
    connection_status: ConnectionStatus
    data_sync_status: DataSyncStatus
    last_sync_at: Optional[datetime] = None
    last_health_check: Optional[datetime] = None
    retry_count: int
    max_retries: int
    created_at: datetime
    updated_at: datetime
    created_by: str
    updated_by: Optional[str] = None
    
    class Config:
        from_attributes = True


class WebhookCreate(BaseModel):
    """Webhook creation model."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    webhook_url: str = Field(..., min_length=1, max_length=1000)
    secret_token: Optional[str] = Field(None, max_length=255)
    events: List[str] = Field(..., min_items=1)
    headers: Dict[str, str] = Field(default_factory=dict)
    payload_template: Optional[str] = None
    timeout: int = Field(30, ge=5, le=300)
    created_by: str = Field(..., min_length=1, max_length=255)


class WebhookResponse(BaseModel):
    """Webhook response model."""
    id: UUID
    integration_id: UUID
    name: str
    description: Optional[str] = None
    webhook_url: str
    events: List[str]
    headers: Dict[str, str]
    payload_template: Optional[str] = None
    timeout: int
    is_active: bool
    last_triggered: Optional[datetime] = None
    success_count: int
    failure_count: int
    created_at: datetime
    updated_at: datetime
    created_by: str
    
    class Config:
        from_attributes = True


class ConnectionLogResponse(BaseModel):
    """Connection log response model."""
    id: UUID
    integration_id: UUID
    attempt_at: datetime
    connection_status: ConnectionStatus
    response_time: Optional[int] = None
    error_message: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None
    health_data: Optional[Dict[str, Any]] = None
    capabilities_detected: Optional[List[str]] = None
    version_detected: Optional[str] = None
    
    class Config:
        from_attributes = True


class SyncLogResponse(BaseModel):
    """Sync log response model."""
    id: UUID
    integration_id: UUID
    sync_type: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration: Optional[int] = None
    status: DataSyncStatus
    records_processed: int
    records_successful: int
    records_failed: int
    records_skipped: int
    error_message: Optional[str] = None
    error_details: Optional[Dict[str, Any]] = None
    sync_metadata: Optional[Dict[str, Any]] = None
    data_checksum: Optional[str] = None
    
    class Config:
        from_attributes = True


# Helper functions

def create_integration(
    name: str,
    integration_type: IntegrationType,
    provider: str,
    config: Dict[str, Any],
    credentials: Dict[str, Any],
    created_by: str,
    **kwargs
) -> Integration:
    """Create a new integration."""
    return Integration(
        name=name,
        integration_type=integration_type,
        provider=provider,
        config=config,
        credentials=credentials,  # Will be encrypted by service
        created_by=created_by,
        **kwargs
    )


def create_webhook(
    integration_id: UUID,
    name: str,
    webhook_url: str,
    events: List[str],
    created_by: str,
    **kwargs
) -> IntegrationWebhook:
    """Create a new webhook."""
    return IntegrationWebhook(
        integration_id=integration_id,
        name=name,
        webhook_url=webhook_url,
        events=events,
        created_by=created_by,
        **kwargs
    )