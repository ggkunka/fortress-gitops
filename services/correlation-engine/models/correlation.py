"""
Correlation Engine Database Models

Defines the database schema for correlation engine data including
correlation rules, events, results, and state management.
"""

from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any
from uuid import UUID, uuid4

from sqlalchemy import (
    Column, String, Integer, DateTime, Boolean, Text, JSON, 
    ForeignKey, Index, CheckConstraint, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, Session
from sqlalchemy.sql import func

from shared.database.connection import get_db_session

Base = declarative_base()


class CorrelationRuleStatus(str, Enum):
    """Correlation rule status."""
    ACTIVE = "active"
    INACTIVE = "inactive"
    TESTING = "testing"
    DEPRECATED = "deprecated"


class CorrelationEventStatus(str, Enum):
    """Correlation event status."""
    PENDING = "pending"
    PROCESSING = "processing"
    CORRELATED = "correlated"
    TIMEOUT = "timeout"
    ERROR = "error"


class CorrelationResultStatus(str, Enum):
    """Correlation result status."""
    ACTIVE = "active"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class CorrelationRule(Base):
    """Correlation rule model."""
    __tablename__ = "correlation_rules"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    name = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Rule definition
    rule_dsl = Column(Text, nullable=False)  # Domain-specific language
    rule_type = Column(String(50), nullable=False)  # sequence, threshold, pattern
    
    # Temporal settings
    time_window = Column(Integer, nullable=False)  # seconds
    max_events = Column(Integer, default=1000)
    
    # Status and metadata
    status = Column(String(20), default=CorrelationRuleStatus.ACTIVE)
    priority = Column(Integer, default=5)  # 1-10, 10 being highest
    
    # Thresholds
    threshold_count = Column(Integer, default=1)
    threshold_timeframe = Column(Integer, default=300)  # seconds
    
    # Configuration
    configuration = Column(JSONB, default=dict)
    
    # Audit fields
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    created_by = Column(String(255))
    updated_by = Column(String(255))
    
    # Relationships
    events = relationship("CorrelationEvent", back_populates="rule")
    results = relationship("CorrelationResult", back_populates="rule")
    
    # Indexes
    __table_args__ = (
        Index("idx_correlation_rules_status", "status"),
        Index("idx_correlation_rules_type", "rule_type"),
        Index("idx_correlation_rules_priority", "priority"),
        Index("idx_correlation_rules_created_at", "created_at"),
        UniqueConstraint("name", name="uq_correlation_rules_name"),
    )


class CorrelationEvent(Base):
    """Correlation event model."""
    __tablename__ = "correlation_events"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    rule_id = Column(PGUUID(as_uuid=True), ForeignKey("correlation_rules.id"), nullable=False)
    
    # Event data
    event_id = Column(String(255), nullable=False)  # Original event ID
    event_type = Column(String(100), nullable=False)
    event_data = Column(JSONB, nullable=False)
    
    # Correlation metadata
    correlation_key = Column(String(255), nullable=False)  # Groups related events
    sequence_number = Column(Integer, default=1)
    
    # Timing
    event_timestamp = Column(DateTime, nullable=False)
    processed_at = Column(DateTime, default=func.now())
    
    # Status
    status = Column(String(20), default=CorrelationEventStatus.PENDING)
    
    # Relationships
    rule = relationship("CorrelationRule", back_populates="events")
    
    # Indexes
    __table_args__ = (
        Index("idx_correlation_events_rule_id", "rule_id"),
        Index("idx_correlation_events_correlation_key", "correlation_key"),
        Index("idx_correlation_events_event_type", "event_type"),
        Index("idx_correlation_events_timestamp", "event_timestamp"),
        Index("idx_correlation_events_status", "status"),
        Index("idx_correlation_events_processed_at", "processed_at"),
    )


class CorrelationResult(Base):
    """Correlation result model."""
    __tablename__ = "correlation_results"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    rule_id = Column(PGUUID(as_uuid=True), ForeignKey("correlation_rules.id"), nullable=False)
    
    # Result data
    correlation_key = Column(String(255), nullable=False)
    title = Column(String(255), nullable=False)
    description = Column(Text)
    
    # Severity and confidence
    severity = Column(String(20), nullable=False)  # low, medium, high, critical
    confidence = Column(Integer, nullable=False)  # 1-100
    risk_score = Column(Integer, nullable=False)  # 1-100
    
    # Event details
    event_count = Column(Integer, nullable=False)
    event_ids = Column(JSONB, nullable=False)  # List of related event IDs
    
    # Timing
    first_event_at = Column(DateTime, nullable=False)
    last_event_at = Column(DateTime, nullable=False)
    correlation_window = Column(Integer, nullable=False)  # seconds
    
    # Status and workflow
    status = Column(String(20), default=CorrelationResultStatus.ACTIVE)
    acknowledged_at = Column(DateTime)
    acknowledged_by = Column(String(255))
    resolved_at = Column(DateTime)
    resolved_by = Column(String(255))
    
    # Additional data
    metadata = Column(JSONB, default=dict)
    tags = Column(JSONB, default=list)
    
    # Audit fields
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    rule = relationship("CorrelationRule", back_populates="results")
    
    # Indexes
    __table_args__ = (
        Index("idx_correlation_results_rule_id", "rule_id"),
        Index("idx_correlation_results_correlation_key", "correlation_key"),
        Index("idx_correlation_results_severity", "severity"),
        Index("idx_correlation_results_status", "status"),
        Index("idx_correlation_results_created_at", "created_at"),
        Index("idx_correlation_results_first_event_at", "first_event_at"),
        Index("idx_correlation_results_risk_score", "risk_score"),
        CheckConstraint("confidence >= 1 AND confidence <= 100", name="ck_confidence_range"),
        CheckConstraint("risk_score >= 1 AND risk_score <= 100", name="ck_risk_score_range"),
    )


class CorrelationState(Base):
    """Correlation state model for tracking ongoing correlations."""
    __tablename__ = "correlation_states"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    rule_id = Column(PGUUID(as_uuid=True), ForeignKey("correlation_rules.id"), nullable=False)
    
    # State identification
    correlation_key = Column(String(255), nullable=False)
    state_hash = Column(String(64), nullable=False)  # Hash of current state
    
    # State data
    state_data = Column(JSONB, nullable=False)
    event_count = Column(Integer, default=0)
    
    # Timing
    started_at = Column(DateTime, default=func.now())
    last_updated = Column(DateTime, default=func.now(), onupdate=func.now())
    expires_at = Column(DateTime, nullable=False)
    
    # Status
    is_active = Column(Boolean, default=True)
    
    # Indexes
    __table_args__ = (
        Index("idx_correlation_states_rule_id", "rule_id"),
        Index("idx_correlation_states_correlation_key", "correlation_key"),
        Index("idx_correlation_states_expires_at", "expires_at"),
        Index("idx_correlation_states_active", "is_active"),
        Index("idx_correlation_states_last_updated", "last_updated"),
        UniqueConstraint("rule_id", "correlation_key", name="uq_correlation_states_rule_key"),
    )


class CorrelationMetrics(Base):
    """Correlation metrics model."""
    __tablename__ = "correlation_metrics"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    rule_id = Column(PGUUID(as_uuid=True), ForeignKey("correlation_rules.id"), nullable=False)
    
    # Metrics data
    events_processed = Column(Integer, default=0)
    correlations_found = Column(Integer, default=0)
    false_positives = Column(Integer, default=0)
    
    # Performance metrics
    avg_processing_time = Column(Integer, default=0)  # milliseconds
    max_processing_time = Column(Integer, default=0)  # milliseconds
    
    # Time period
    period_start = Column(DateTime, nullable=False)
    period_end = Column(DateTime, nullable=False)
    
    # Audit fields
    created_at = Column(DateTime, default=func.now())
    
    # Indexes
    __table_args__ = (
        Index("idx_correlation_metrics_rule_id", "rule_id"),
        Index("idx_correlation_metrics_period", "period_start", "period_end"),
        Index("idx_correlation_metrics_created_at", "created_at"),
    )


# Database initialization
async def init_db():
    """Initialize database tables."""
    from shared.database.connection import get_engine
    
    engine = get_engine()
    # Create tables
    Base.metadata.create_all(bind=engine)
    
    # Create indexes if not exists
    # Additional custom indexes can be added here


async def close_db():
    """Close database connections."""
    from shared.database.connection import get_engine
    
    engine = get_engine()
    if hasattr(engine, 'dispose'):
        engine.dispose()


# Helper functions
def get_db() -> Session:
    """Get database session."""
    return get_db_session()


def create_correlation_rule(
    name: str,
    rule_dsl: str,
    rule_type: str,
    time_window: int,
    description: str = None,
    configuration: Dict[str, Any] = None,
    created_by: str = None
) -> CorrelationRule:
    """Create a new correlation rule."""
    return CorrelationRule(
        name=name,
        description=description,
        rule_dsl=rule_dsl,
        rule_type=rule_type,
        time_window=time_window,
        configuration=configuration or {},
        created_by=created_by
    )


def create_correlation_event(
    rule_id: UUID,
    event_id: str,
    event_type: str,
    event_data: Dict[str, Any],
    correlation_key: str,
    event_timestamp: datetime,
    sequence_number: int = 1
) -> CorrelationEvent:
    """Create a new correlation event."""
    return CorrelationEvent(
        rule_id=rule_id,
        event_id=event_id,
        event_type=event_type,
        event_data=event_data,
        correlation_key=correlation_key,
        event_timestamp=event_timestamp,
        sequence_number=sequence_number
    )


def create_correlation_result(
    rule_id: UUID,
    correlation_key: str,
    title: str,
    description: str,
    severity: str,
    confidence: int,
    risk_score: int,
    event_count: int,
    event_ids: List[str],
    first_event_at: datetime,
    last_event_at: datetime,
    correlation_window: int,
    metadata: Dict[str, Any] = None,
    tags: List[str] = None
) -> CorrelationResult:
    """Create a new correlation result."""
    return CorrelationResult(
        rule_id=rule_id,
        correlation_key=correlation_key,
        title=title,
        description=description,
        severity=severity,
        confidence=confidence,
        risk_score=risk_score,
        event_count=event_count,
        event_ids=event_ids,
        first_event_at=first_event_at,
        last_event_at=last_event_at,
        correlation_window=correlation_window,
        metadata=metadata or {},
        tags=tags or []
    )