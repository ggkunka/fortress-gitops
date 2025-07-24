"""
Analysis Service Database Models

Defines the database schema for analysis service data including
analysis results, patterns, anomalies, and behavioral insights.
"""

from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any
from uuid import UUID, uuid4

from sqlalchemy import (
    Column, String, Integer, DateTime, Boolean, Text, JSON, Float,
    ForeignKey, Index, CheckConstraint, UniqueConstraint
)
from sqlalchemy.dialects.postgresql import UUID as PGUUID, JSONB
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship, Session
from sqlalchemy.sql import func

from shared.database.connection import get_db_session

Base = declarative_base()


class AnalysisType(str, Enum):
    """Analysis types."""
    ANOMALY_DETECTION = "anomaly_detection"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis" 
    PATTERN_ANALYSIS = "pattern_analysis"
    THREAT_ANALYSIS = "threat_analysis"
    RISK_ANALYSIS = "risk_analysis"
    BASELINE_ANALYSIS = "baseline_analysis"


class AnalysisStatus(str, Enum):
    """Analysis status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class SeverityLevel(str, Enum):
    """Severity levels."""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AnalysisJob(Base):
    """Analysis job model."""
    __tablename__ = "analysis_jobs"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Job metadata
    name = Column(String(255), nullable=False)
    description = Column(Text)
    analysis_type = Column(String(50), nullable=False)
    
    # Input configuration
    input_source = Column(String(100), nullable=False)  # correlation_result, event_stream, etc.
    input_config = Column(JSONB, nullable=False)
    
    # Analysis configuration
    analysis_config = Column(JSONB, default=dict)
    parameters = Column(JSONB, default=dict)
    
    # Scheduling
    schedule = Column(String(100))  # cron expression
    priority = Column(Integer, default=5)  # 1-10
    
    # Status and timing
    status = Column(String(20), default=AnalysisStatus.PENDING)
    started_at = Column(DateTime)
    completed_at = Column(DateTime)
    execution_time = Column(Float)  # seconds
    
    # Results summary
    results_count = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    
    # Error handling
    error_message = Column(Text)
    retry_count = Column(Integer, default=0)
    max_retries = Column(Integer, default=3)
    
    # Audit fields
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    created_by = Column(String(255))
    
    # Relationships
    results = relationship("AnalysisResult", back_populates="job", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index("idx_analysis_jobs_status", "status"),
        Index("idx_analysis_jobs_type", "analysis_type"),
        Index("idx_analysis_jobs_priority", "priority"),
        Index("idx_analysis_jobs_created_at", "created_at"),
    )


class AnalysisResult(Base):
    """Analysis result model."""
    __tablename__ = "analysis_results"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    job_id = Column(PGUUID(as_uuid=True), ForeignKey("analysis_jobs.id"), nullable=False)
    
    # Result metadata
    title = Column(String(500), nullable=False)
    description = Column(Text)
    analysis_type = Column(String(50), nullable=False)
    
    # Severity and confidence
    severity = Column(String(20), nullable=False)
    confidence_score = Column(Float, nullable=False)  # 0.0-1.0
    risk_score = Column(Integer, nullable=False)  # 0-100
    
    # Analysis details
    finding_type = Column(String(100), nullable=False)
    affected_entities = Column(JSONB, default=list)
    evidence = Column(JSONB, default=dict)
    
    # Context and metadata
    context_data = Column(JSONB, default=dict)
    analysis_metadata = Column(JSONB, default=dict)
    
    # Statistical data
    baseline_deviation = Column(Float)
    z_score = Column(Float)
    p_value = Column(Float)
    
    # Time-based information
    observation_window = Column(Integer)  # seconds
    first_observed = Column(DateTime)
    last_observed = Column(DateTime)
    
    # Recommendations
    recommendations = Column(JSONB, default=list)
    remediation_steps = Column(JSONB, default=list)
    
    # Status tracking
    is_active = Column(Boolean, default=True)
    acknowledged_at = Column(DateTime)
    acknowledged_by = Column(String(255))
    resolved_at = Column(DateTime)
    resolved_by = Column(String(255))
    
    # Audit fields
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    
    # Relationships
    job = relationship("AnalysisJob", back_populates="results")
    findings = relationship("AnalysisFinding", back_populates="result", cascade="all, delete-orphan")
    
    # Indexes
    __table_args__ = (
        Index("idx_analysis_results_job_id", "job_id"),
        Index("idx_analysis_results_severity", "severity"),
        Index("idx_analysis_results_type", "analysis_type"),
        Index("idx_analysis_results_finding_type", "finding_type"),
        Index("idx_analysis_results_confidence", "confidence_score"),
        Index("idx_analysis_results_risk_score", "risk_score"),
        Index("idx_analysis_results_created_at", "created_at"),
        CheckConstraint("confidence_score >= 0.0 AND confidence_score <= 1.0", name="ck_confidence_range"),
        CheckConstraint("risk_score >= 0 AND risk_score <= 100", name="ck_risk_score_range"),
    )


class AnalysisFinding(Base):
    """Individual analysis finding model."""
    __tablename__ = "analysis_findings"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    result_id = Column(PGUUID(as_uuid=True), ForeignKey("analysis_results.id"), nullable=False)
    
    # Finding details
    finding_id = Column(String(255), nullable=False)  # Unique identifier
    finding_name = Column(String(255), nullable=False)
    finding_description = Column(Text)
    
    # Classification
    category = Column(String(100), nullable=False)
    subcategory = Column(String(100))
    tags = Column(JSONB, default=list)
    
    # Location and context
    source_entity = Column(String(255))
    target_entity = Column(String(255))
    affected_resource = Column(String(255))
    
    # Evidence and details
    evidence_data = Column(JSONB, default=dict)
    technical_details = Column(JSONB, default=dict)
    
    # Scoring
    severity_score = Column(Integer, nullable=False)  # 0-100
    likelihood_score = Column(Integer, nullable=False)  # 0-100
    impact_score = Column(Integer, nullable=False)  # 0-100
    
    # Timing
    first_detected = Column(DateTime, nullable=False)
    last_detected = Column(DateTime, nullable=False)
    
    # Status
    is_false_positive = Column(Boolean, default=False)
    is_suppressed = Column(Boolean, default=False)
    
    # Audit fields
    created_at = Column(DateTime, default=func.now())
    
    # Relationships
    result = relationship("AnalysisResult", back_populates="findings")
    
    # Indexes
    __table_args__ = (
        Index("idx_analysis_findings_result_id", "result_id"),
        Index("idx_analysis_findings_category", "category"),
        Index("idx_analysis_findings_severity", "severity_score"),
        Index("idx_analysis_findings_first_detected", "first_detected"),
        UniqueConstraint("finding_id", "result_id", name="uq_finding_id_result"),
    )


class BaselineProfile(Base):
    """Baseline profile for anomaly detection."""
    __tablename__ = "baseline_profiles"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Profile identification
    entity_type = Column(String(100), nullable=False)
    entity_id = Column(String(255), nullable=False)
    profile_name = Column(String(255), nullable=False)
    
    # Profile data
    baseline_data = Column(JSONB, nullable=False)
    statistical_metrics = Column(JSONB, default=dict)
    
    # Configuration
    learning_period_days = Column(Integer, default=30)
    sensitivity_threshold = Column(Float, default=2.0)  # Z-score threshold
    
    # Training information
    training_start = Column(DateTime, nullable=False)
    training_end = Column(DateTime, nullable=False)
    samples_count = Column(Integer, nullable=False)
    
    # Status
    is_active = Column(Boolean, default=True)
    last_updated = Column(DateTime, default=func.now())
    next_update = Column(DateTime)
    
    # Version control
    version = Column(String(20), default="1.0")
    
    # Audit fields
    created_at = Column(DateTime, default=func.now())
    created_by = Column(String(255))
    
    # Indexes
    __table_args__ = (
        Index("idx_baseline_profiles_entity", "entity_type", "entity_id"),
        Index("idx_baseline_profiles_active", "is_active"),
        Index("idx_baseline_profiles_last_updated", "last_updated"),
        UniqueConstraint("entity_type", "entity_id", "profile_name", name="uq_baseline_profile"),
    )


class BehaviorPattern(Base):
    """Behavior pattern model."""
    __tablename__ = "behavior_patterns"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Pattern identification
    pattern_name = Column(String(255), nullable=False)
    pattern_type = Column(String(100), nullable=False)
    pattern_signature = Column(Text, nullable=False)
    
    # Pattern definition
    pattern_rules = Column(JSONB, nullable=False)
    detection_logic = Column(JSONB, nullable=False)
    
    # Metadata
    description = Column(Text)
    category = Column(String(100), nullable=False)
    tags = Column(JSONB, default=list)
    
    # Performance metrics
    true_positives = Column(Integer, default=0)
    false_positives = Column(Integer, default=0)
    accuracy = Column(Float, default=0.0)
    
    # Configuration
    confidence_threshold = Column(Float, default=0.7)
    is_enabled = Column(Boolean, default=True)
    
    # Versioning
    version = Column(String(20), default="1.0")
    parent_pattern_id = Column(PGUUID(as_uuid=True), ForeignKey("behavior_patterns.id"))
    
    # Audit fields
    created_at = Column(DateTime, default=func.now())
    updated_at = Column(DateTime, default=func.now(), onupdate=func.now())
    created_by = Column(String(255))
    
    # Relationships
    children = relationship("BehaviorPattern", backref="parent", remote_side=[id])
    
    # Indexes
    __table_args__ = (
        Index("idx_behavior_patterns_type", "pattern_type"),
        Index("idx_behavior_patterns_category", "category"),
        Index("idx_behavior_patterns_enabled", "is_enabled"),
        Index("idx_behavior_patterns_accuracy", "accuracy"),
        UniqueConstraint("pattern_name", "version", name="uq_pattern_name_version"),
    )


class AnomalyDetection(Base):
    """Anomaly detection record."""
    __tablename__ = "anomaly_detections"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Detection metadata
    detection_name = Column(String(255), nullable=False)
    anomaly_type = Column(String(100), nullable=False)
    
    # Source information
    source_entity = Column(String(255), nullable=False)
    source_data = Column(JSONB, nullable=False)
    
    # Statistical analysis
    baseline_value = Column(Float)
    observed_value = Column(Float)
    deviation = Column(Float)
    z_score = Column(Float, nullable=False)
    p_value = Column(Float)
    
    # Confidence and severity
    confidence = Column(Float, nullable=False)
    severity = Column(String(20), nullable=False)
    anomaly_score = Column(Integer, nullable=False)  # 0-100
    
    # Context
    detection_window = Column(Integer, nullable=False)  # seconds
    context_data = Column(JSONB, default=dict)
    
    # Timing
    detected_at = Column(DateTime, nullable=False)
    window_start = Column(DateTime, nullable=False)
    window_end = Column(DateTime, nullable=False)
    
    # Status
    is_confirmed = Column(Boolean, default=False)
    is_false_positive = Column(Boolean, default=False)
    
    # Audit fields
    created_at = Column(DateTime, default=func.now())
    
    # Indexes
    __table_args__ = (
        Index("idx_anomaly_detections_type", "anomaly_type"),
        Index("idx_anomaly_detections_entity", "source_entity"),
        Index("idx_anomaly_detections_severity", "severity"),
        Index("idx_anomaly_detections_detected_at", "detected_at"),
        Index("idx_anomaly_detections_z_score", "z_score"),
        CheckConstraint("confidence >= 0.0 AND confidence <= 1.0", name="ck_anomaly_confidence_range"),
        CheckConstraint("anomaly_score >= 0 AND anomaly_score <= 100", name="ck_anomaly_score_range"),
    )


# Database initialization
def get_db() -> Session:
    """Get database session."""
    return get_db_session()


async def init_db():
    """Initialize database tables."""
    from shared.database.connection import get_engine
    
    engine = get_engine()
    Base.metadata.create_all(bind=engine)


async def close_db():
    """Close database connections."""
    from shared.database.connection import get_engine
    
    engine = get_engine()
    if hasattr(engine, 'dispose'):
        engine.dispose()


# Helper functions
def create_analysis_job(
    name: str,
    analysis_type: AnalysisType,
    input_source: str,
    input_config: Dict[str, Any],
    description: str = None,
    analysis_config: Dict[str, Any] = None,
    parameters: Dict[str, Any] = None,
    created_by: str = None
) -> AnalysisJob:
    """Create a new analysis job."""
    return AnalysisJob(
        name=name,
        description=description,
        analysis_type=analysis_type.value,
        input_source=input_source,
        input_config=input_config,
        analysis_config=analysis_config or {},
        parameters=parameters or {},
        created_by=created_by
    )


def create_analysis_result(
    job_id: UUID,
    title: str,
    analysis_type: AnalysisType,
    severity: SeverityLevel,
    confidence_score: float,
    risk_score: int,
    finding_type: str,
    description: str = None,
    affected_entities: List[str] = None,
    evidence: Dict[str, Any] = None,
    recommendations: List[str] = None
) -> AnalysisResult:
    """Create a new analysis result."""
    return AnalysisResult(
        job_id=job_id,
        title=title,
        description=description,
        analysis_type=analysis_type.value,
        severity=severity.value,
        confidence_score=confidence_score,
        risk_score=risk_score,
        finding_type=finding_type,
        affected_entities=affected_entities or [],
        evidence=evidence or {},
        recommendations=recommendations or []
    )