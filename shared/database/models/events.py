"""
Event Models

Database models for events, event logs, and notifications.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List

from sqlalchemy import Column, String, Text, JSON, Enum as SQLEnum, ForeignKey, Boolean, Integer, Float, Index
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import uuid

from .base import BaseModel


class EventType(str, Enum):
    """Types of system events."""
    SCAN_STARTED = "scan.started"
    SCAN_COMPLETED = "scan.completed"
    SCAN_FAILED = "scan.failed"
    VULNERABILITY_DETECTED = "vulnerability.detected"
    VULNERABILITY_RESOLVED = "vulnerability.resolved"
    POLICY_VIOLATION = "policy.violation"
    COMPLIANCE_CHECK = "compliance.check"
    USER_LOGIN = "user.login"
    USER_LOGOUT = "user.logout"
    USER_CREATED = "user.created"
    SYSTEM_ALERT = "system.alert"
    INTEGRATION_EVENT = "integration.event"
    AUDIT_EVENT = "audit.event"
    SECURITY_EVENT = "security.event"
    ERROR_EVENT = "error.event"
    CUSTOM_EVENT = "custom.event"


class EventSeverity(str, Enum):
    """Event severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class EventStatus(str, Enum):
    """Event processing status."""
    PENDING = "pending"
    PROCESSING = "processing"
    PROCESSED = "processed"
    FAILED = "failed"
    IGNORED = "ignored"


class NotificationType(str, Enum):
    """Types of notifications."""
    EMAIL = "email"
    SLACK = "slack"
    WEBHOOK = "webhook"
    SMS = "sms"
    PUSH = "push"
    IN_APP = "in_app"


class NotificationStatus(str, Enum):
    """Notification delivery status."""
    PENDING = "pending"
    SENT = "sent"
    DELIVERED = "delivered"
    FAILED = "failed"
    BOUNCED = "bounced"
    UNSUBSCRIBED = "unsubscribed"


class Event(BaseModel):
    """System event entity."""
    
    __tablename__ = "events"
    
    # Event identification
    event_id = Column(String(100), unique=True, nullable=False)
    event_type = Column(SQLEnum(EventType), nullable=False)
    event_name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    
    # Event classification
    severity = Column(SQLEnum(EventSeverity), default=EventSeverity.INFO, nullable=False)
    category = Column(String(100), nullable=True)
    tags = Column(JSONB, default=list, nullable=False)
    
    # Event source
    source_service = Column(String(100), nullable=True)
    source_component = Column(String(100), nullable=True)
    source_user_id = Column(UUID(as_uuid=True), nullable=True)
    source_ip = Column(String(45), nullable=True)
    
    # Event target
    target_type = Column(String(100), nullable=True)
    target_id = Column(String(200), nullable=True)
    target_name = Column(String(300), nullable=True)
    
    # Event data
    event_data = Column(JSONB, default=dict, nullable=False)
    context = Column(JSONB, default=dict, nullable=False)
    correlation_id = Column(String(100), nullable=True)
    trace_id = Column(String(100), nullable=True)
    
    # Timing
    event_timestamp = Column(JSON, nullable=False)
    ingestion_timestamp = Column(JSON, nullable=False)
    
    # Processing
    status = Column(SQLEnum(EventStatus), default=EventStatus.PENDING, nullable=False)
    processed_at = Column(JSON, nullable=True)
    processing_duration_ms = Column(Integer, nullable=True)
    retry_count = Column(Integer, default=0, nullable=False)
    
    # Organization context
    organization_id = Column(UUID(as_uuid=True), nullable=True)
    project_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Event relationships
    parent_event_id = Column(UUID(as_uuid=True), ForeignKey("events.id"), nullable=True)
    root_event_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Notification flags
    notification_sent = Column(Boolean, default=False, nullable=False)
    alert_triggered = Column(Boolean, default=False, nullable=False)
    
    # Indexes for performance
    __table_args__ = (
        Index('idx_events_timestamp', 'event_timestamp'),
        Index('idx_events_type_severity', 'event_type', 'severity'),
        Index('idx_events_organization', 'organization_id'),
        Index('idx_events_correlation', 'correlation_id'),
        Index('idx_events_status', 'status'),
    )
    
    # Relationships
    parent_event = relationship("Event", remote_side="Event.id")
    child_events = relationship("Event", backref="parent", remote_side="Event.parent_event_id")
    event_logs = relationship("EventLog", back_populates="event", cascade="all, delete-orphan")
    notifications = relationship("Notification", back_populates="event")
    
    def _validate(self) -> List[str]:
        """Custom validation for event model."""
        errors = []
        
        if not self.event_id or len(self.event_id.strip()) == 0:
            errors.append("Event ID cannot be empty")
        
        if not self.event_name or len(self.event_name.strip()) == 0:
            errors.append("Event name cannot be empty")
            
        return errors
    
    def mark_processed(self, duration_ms: Optional[int] = None):
        """Mark event as processed."""
        self.status = EventStatus.PROCESSED
        self.processed_at = datetime.utcnow().isoformat()
        if duration_ms:
            self.processing_duration_ms = duration_ms
    
    def mark_failed(self, error_message: str):
        """Mark event as failed with error message."""
        self.status = EventStatus.FAILED
        self.processed_at = datetime.utcnow().isoformat()
        self.set_metadata("error_message", error_message)
    
    def increment_retry(self):
        """Increment retry count."""
        self.retry_count += 1
        self.status = EventStatus.PENDING
    
    def is_actionable(self) -> bool:
        """Check if event requires action."""
        return self.severity in [EventSeverity.CRITICAL, EventSeverity.HIGH]
    
    def should_alert(self) -> bool:
        """Check if event should trigger alerts."""
        return (
            self.severity in [EventSeverity.CRITICAL, EventSeverity.HIGH] and
            not self.alert_triggered
        )
    
    def get_event_chain(self) -> List["Event"]:
        """Get the chain of related events."""
        chain = [self]
        
        # Add parent events
        current = self.parent_event
        while current:
            chain.insert(0, current)
            current = current.parent_event
        
        # Add child events recursively
        def add_children(event):
            for child in event.child_events:
                chain.append(child)
                add_children(child)
        
        add_children(self)
        return chain


class EventLog(BaseModel):
    """Detailed event log entry."""
    
    __tablename__ = "event_logs"
    
    # Relationship to event
    event_id = Column(UUID(as_uuid=True), ForeignKey("events.id"), nullable=False)
    
    # Log entry details
    log_level = Column(String(20), nullable=False)  # DEBUG, INFO, WARN, ERROR
    message = Column(Text, nullable=False)
    details = Column(JSONB, default=dict, nullable=False)
    
    # Log source
    logger_name = Column(String(200), nullable=True)
    module_name = Column(String(100), nullable=True)
    function_name = Column(String(100), nullable=True)
    line_number = Column(Integer, nullable=True)
    
    # Timing
    log_timestamp = Column(JSON, nullable=False)
    
    # Context
    thread_id = Column(String(50), nullable=True)
    process_id = Column(String(50), nullable=True)
    session_id = Column(String(100), nullable=True)
    
    # Exception information
    exception_type = Column(String(200), nullable=True)
    exception_message = Column(Text, nullable=True)
    stack_trace = Column(Text, nullable=True)
    
    # Performance metrics
    duration_ms = Column(Integer, nullable=True)
    memory_usage_mb = Column(Float, nullable=True)
    cpu_usage_percent = Column(Float, nullable=True)
    
    # Additional metadata
    extra_data = Column(JSONB, default=dict, nullable=False)
    
    # Indexes
    __table_args__ = (
        Index('idx_event_logs_timestamp', 'log_timestamp'),
        Index('idx_event_logs_level', 'log_level'),
        Index('idx_event_logs_event', 'event_id'),
    )
    
    # Relationships
    event = relationship("Event", back_populates="event_logs")
    
    def _validate(self) -> List[str]:
        """Custom validation for event log model."""
        errors = []
        
        if not self.message or len(self.message.strip()) == 0:
            errors.append("Log message cannot be empty")
        
        if self.log_level not in ["DEBUG", "INFO", "WARN", "ERROR", "CRITICAL"]:
            errors.append("Invalid log level")
            
        return errors
    
    def is_error(self) -> bool:
        """Check if this is an error log entry."""
        return self.log_level in ["ERROR", "CRITICAL"]
    
    def has_exception(self) -> bool:
        """Check if log entry contains exception information."""
        return bool(self.exception_type or self.exception_message or self.stack_trace)


class Notification(BaseModel):
    """Notification entity for event-driven alerts."""
    
    __tablename__ = "notifications"
    
    # Relationship to event
    event_id = Column(UUID(as_uuid=True), ForeignKey("events.id"), nullable=True)
    
    # Notification details
    notification_id = Column(String(100), unique=True, nullable=False)
    title = Column(String(300), nullable=False)
    message = Column(Text, nullable=False)
    notification_type = Column(SQLEnum(NotificationType), nullable=False)
    
    # Recipients
    recipient_type = Column(String(50), nullable=False)  # user, role, group, email
    recipient_id = Column(String(200), nullable=False)
    recipient_address = Column(String(500), nullable=True)  # email, phone, webhook URL
    
    # Content and formatting
    template_id = Column(String(100), nullable=True)
    template_data = Column(JSONB, default=dict, nullable=False)
    formatted_content = Column(JSONB, default=dict, nullable=False)
    
    # Delivery settings
    priority = Column(String(20), default="normal", nullable=False)  # low, normal, high, urgent
    delivery_method = Column(String(50), nullable=True)
    retry_policy = Column(JSONB, default=dict, nullable=False)
    
    # Status and tracking
    status = Column(SQLEnum(NotificationStatus), default=NotificationStatus.PENDING, nullable=False)
    sent_at = Column(JSON, nullable=True)
    delivered_at = Column(JSON, nullable=True)
    read_at = Column(JSON, nullable=True)
    
    # Delivery attempts
    attempt_count = Column(Integer, default=0, nullable=False)
    max_attempts = Column(Integer, default=3, nullable=False)
    last_attempt_at = Column(JSON, nullable=True)
    next_attempt_at = Column(JSON, nullable=True)
    
    # Error handling
    error_message = Column(Text, nullable=True)
    error_code = Column(String(50), nullable=True)
    
    # External tracking
    external_id = Column(String(200), nullable=True)  # ID from external service
    external_status = Column(String(50), nullable=True)
    tracking_data = Column(JSONB, default=dict, nullable=False)
    
    # Organization context
    organization_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Preferences and settings
    user_preferences = Column(JSONB, default=dict, nullable=False)
    unsubscribe_token = Column(String(100), nullable=True)
    
    # Indexes
    __table_args__ = (
        Index('idx_notifications_status', 'status'),
        Index('idx_notifications_recipient', 'recipient_type', 'recipient_id'),
        Index('idx_notifications_sent_at', 'sent_at'),
        Index('idx_notifications_next_attempt', 'next_attempt_at'),
    )
    
    # Relationships
    event = relationship("Event", back_populates="notifications")
    
    def _validate(self) -> List[str]:
        """Custom validation for notification model."""
        errors = []
        
        if not self.notification_id or len(self.notification_id.strip()) == 0:
            errors.append("Notification ID cannot be empty")
        
        if not self.title or len(self.title.strip()) == 0:
            errors.append("Notification title cannot be empty")
        
        if not self.message or len(self.message.strip()) == 0:
            errors.append("Notification message cannot be empty")
        
        if not self.recipient_id or len(self.recipient_id.strip()) == 0:
            errors.append("Recipient ID cannot be empty")
        
        if self.attempt_count > self.max_attempts:
            errors.append("Attempt count cannot exceed max attempts")
            
        return errors
    
    def mark_sent(self, external_id: Optional[str] = None):
        """Mark notification as sent."""
        self.status = NotificationStatus.SENT
        self.sent_at = datetime.utcnow().isoformat()
        self.attempt_count += 1
        if external_id:
            self.external_id = external_id
    
    def mark_delivered(self):
        """Mark notification as delivered."""
        self.status = NotificationStatus.DELIVERED
        self.delivered_at = datetime.utcnow().isoformat()
    
    def mark_failed(self, error_message: str, error_code: Optional[str] = None):
        """Mark notification as failed."""
        self.status = NotificationStatus.FAILED
        self.error_message = error_message
        self.error_code = error_code
        self.last_attempt_at = datetime.utcnow().isoformat()
        self.attempt_count += 1
        
        # Calculate next attempt time if retries available
        if self.attempt_count < self.max_attempts:
            delay_minutes = 2 ** self.attempt_count  # Exponential backoff
            next_attempt = datetime.utcnow()
            next_attempt = next_attempt.replace(minute=next_attempt.minute + delay_minutes)
            self.next_attempt_at = next_attempt.isoformat()
            self.status = NotificationStatus.PENDING
    
    def should_retry(self) -> bool:
        """Check if notification should be retried."""
        return (
            self.status == NotificationStatus.PENDING and
            self.attempt_count < self.max_attempts and
            (not self.next_attempt_at or 
             datetime.fromisoformat(self.next_attempt_at.replace('Z', '+00:00')) <= datetime.utcnow())
        )
    
    def is_expired(self) -> bool:
        """Check if notification has expired."""
        if not hasattr(self, 'expires_at') or not self.metadata.get('expires_at'):
            return False
        
        expires_dt = datetime.fromisoformat(self.metadata['expires_at'].replace('Z', '+00:00'))
        return datetime.utcnow() > expires_dt.replace(tzinfo=None)
    
    def get_delivery_summary(self) -> Dict[str, Any]:
        """Get notification delivery summary."""
        return {
            "notification_id": self.notification_id,
            "type": self.notification_type.value,
            "status": self.status.value,
            "recipient": self.recipient_address or self.recipient_id,
            "attempts": self.attempt_count,
            "sent_at": self.sent_at,
            "delivered_at": self.delivered_at,
            "error": self.error_message
        }