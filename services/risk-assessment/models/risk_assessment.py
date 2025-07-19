"""
Risk Assessment Models - Database models for risk assessment
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


class RiskLevel(str, Enum):
    """Risk levels."""
    INFORMATIONAL = "informational"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class RiskAssessmentStatus(str, Enum):
    """Risk assessment status."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    REVIEWED = "reviewed"


class RiskCategory(str, Enum):
    """Risk categories."""
    SECURITY = "security"
    COMPLIANCE = "compliance"
    OPERATIONAL = "operational"
    FINANCIAL = "financial"
    REPUTATIONAL = "reputational"
    TECHNICAL = "technical"


class RiskAssessment(Base):
    """Risk assessment model."""
    __tablename__ = "risk_assessments"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    correlation_result_id = Column(PGUUID(as_uuid=True), index=True)
    
    # Basic assessment info
    title = Column(String(255), nullable=False)
    description = Column(Text)
    risk_level = Column(String(20), nullable=False)  # RiskLevel enum
    risk_score = Column(Float, nullable=False)  # 0-100
    confidence_score = Column(Float, nullable=False)  # 0-100
    
    # Risk categorization
    risk_category = Column(String(50), nullable=False)  # RiskCategory enum
    risk_subcategory = Column(String(100))
    
    # Assessment details
    impact_score = Column(Float, nullable=False)  # 0-100
    likelihood_score = Column(Float, nullable=False)  # 0-100
    vulnerability_score = Column(Float)  # 0-100
    threat_score = Column(Float)  # 0-100
    
    # Context and analysis
    context_data = Column(JSON)  # Additional context
    analysis_data = Column(JSON)  # Detailed analysis
    recommendations = Column(JSON)  # List of recommendations
    
    # LLM analysis
    llm_analysis = Column(JSON)  # LLM-generated analysis
    llm_confidence = Column(Float)  # LLM confidence score
    llm_reasoning = Column(Text)  # LLM reasoning
    
    # Status and tracking
    status = Column(String(20), nullable=False, default=RiskAssessmentStatus.PENDING)
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    completed_at = Column(DateTime)
    
    # Audit trail
    created_by = Column(String(255))
    updated_by = Column(String(255))
    reviewed_by = Column(String(255))
    reviewed_at = Column(DateTime)
    
    # Metadata
    metadata = Column(JSON)
    tags = Column(JSON)  # List of tags
    
    # Relationships
    factors = relationship("RiskFactor", back_populates="assessment")
    mitigations = relationship("RiskMitigation", back_populates="assessment")
    
    __table_args__ = (
        Index("idx_risk_assessments_level_status", "risk_level", "status"),
        Index("idx_risk_assessments_created_at", "created_at"),
        Index("idx_risk_assessments_risk_score", "risk_score"),
    )


class RiskFactor(Base):
    """Risk factor model."""
    __tablename__ = "risk_factors"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    assessment_id = Column(PGUUID(as_uuid=True), ForeignKey("risk_assessments.id"), nullable=False)
    
    # Factor details
    factor_name = Column(String(255), nullable=False)
    factor_type = Column(String(50), nullable=False)  # vulnerability, threat, asset, etc.
    factor_description = Column(Text)
    
    # Scoring
    weight = Column(Float, nullable=False)  # 0-1
    impact = Column(Float, nullable=False)  # 0-100
    likelihood = Column(Float)  # 0-100
    
    # Data
    factor_data = Column(JSON)
    evidence = Column(JSON)  # Supporting evidence
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    
    # Relationships
    assessment = relationship("RiskAssessment", back_populates="factors")
    
    __table_args__ = (
        Index("idx_risk_factors_assessment_id", "assessment_id"),
        Index("idx_risk_factors_type", "factor_type"),
    )


class RiskMitigation(Base):
    """Risk mitigation model."""
    __tablename__ = "risk_mitigations"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    assessment_id = Column(PGUUID(as_uuid=True), ForeignKey("risk_assessments.id"), nullable=False)
    
    # Mitigation details
    mitigation_name = Column(String(255), nullable=False)
    mitigation_type = Column(String(50), nullable=False)  # preventive, detective, corrective
    description = Column(Text)
    
    # Effectiveness
    effectiveness_score = Column(Float, nullable=False)  # 0-100
    implementation_cost = Column(Float)  # 0-100
    implementation_time = Column(Integer)  # days
    
    # Status
    status = Column(String(20), nullable=False, default="recommended")
    priority = Column(Integer, nullable=False, default=5)  # 1-10
    
    # Implementation
    implementation_plan = Column(JSON)
    assigned_to = Column(String(255))
    due_date = Column(DateTime)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    
    # Relationships
    assessment = relationship("RiskAssessment", back_populates="mitigations")
    
    __table_args__ = (
        Index("idx_risk_mitigations_assessment_id", "assessment_id"),
        Index("idx_risk_mitigations_status", "status"),
        Index("idx_risk_mitigations_priority", "priority"),
    )


class RiskTemplate(Base):
    """Risk assessment template model."""
    __tablename__ = "risk_templates"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Template details
    name = Column(String(255), nullable=False)
    description = Column(Text)
    category = Column(String(50), nullable=False)
    
    # Template configuration
    template_config = Column(JSON, nullable=False)
    factor_templates = Column(JSON)  # Predefined factors
    mitigation_templates = Column(JSON)  # Predefined mitigations
    
    # Scoring parameters
    impact_weights = Column(JSON)
    likelihood_weights = Column(JSON)
    
    # Status
    is_active = Column(Boolean, default=True)
    version = Column(String(20), default="1.0")
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    created_by = Column(String(255))
    
    __table_args__ = (
        Index("idx_risk_templates_category", "category"),
        Index("idx_risk_templates_active", "is_active"),
    )


class RiskProfile(Base):
    """Risk profile model for entities."""
    __tablename__ = "risk_profiles"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Entity identification
    entity_type = Column(String(50), nullable=False)  # user, host, application, etc.
    entity_id = Column(String(255), nullable=False)
    entity_name = Column(String(255))
    
    # Risk scoring
    overall_risk_score = Column(Float, nullable=False, default=0.0)
    risk_level = Column(String(20), nullable=False, default=RiskLevel.LOW)
    risk_trend = Column(String(20))  # increasing, decreasing, stable
    
    # Score breakdown
    security_score = Column(Float, default=0.0)
    compliance_score = Column(Float, default=0.0)
    operational_score = Column(Float, default=0.0)
    
    # Historical data
    score_history = Column(JSON)  # Time series of scores
    incident_count = Column(Integer, default=0)
    last_incident_date = Column(DateTime)
    
    # Profile data
    profile_data = Column(JSON)
    behavioral_patterns = Column(JSON)
    anomaly_indicators = Column(JSON)
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    updated_at = Column(DateTime, default=datetime.now, onupdate=datetime.now)
    last_assessed_at = Column(DateTime)
    
    __table_args__ = (
        Index("idx_risk_profiles_entity", "entity_type", "entity_id"),
        Index("idx_risk_profiles_risk_level", "risk_level"),
        Index("idx_risk_profiles_score", "overall_risk_score"),
    )


class RiskContext(Base):
    """Risk context model for environmental factors."""
    __tablename__ = "risk_contexts"

    id = Column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    
    # Context identification
    context_type = Column(String(50), nullable=False)  # threat_landscape, vulnerability_intel, etc.
    context_name = Column(String(255), nullable=False)
    
    # Context data
    context_data = Column(JSON, nullable=False)
    threat_intelligence = Column(JSON)
    vulnerability_data = Column(JSON)
    compliance_requirements = Column(JSON)
    
    # Validity and freshness
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime)
    last_updated = Column(DateTime, default=datetime.now)
    
    # Source information
    source = Column(String(255))
    source_reliability = Column(Float)  # 0-1
    
    # Metadata
    created_at = Column(DateTime, default=datetime.now)
    metadata = Column(JSON)
    
    __table_args__ = (
        Index("idx_risk_contexts_type", "context_type"),
        Index("idx_risk_contexts_active", "is_active"),
    )


# Database utility functions
def create_risk_assessment(
    title: str,
    correlation_result_id: UUID,
    risk_level: RiskLevel,
    risk_score: float,
    confidence_score: float,
    risk_category: RiskCategory,
    impact_score: float,
    likelihood_score: float,
    created_by: str,
    description: Optional[str] = None,
    **kwargs
) -> RiskAssessment:
    """Create a new risk assessment."""
    assessment = RiskAssessment(
        title=title,
        correlation_result_id=correlation_result_id,
        risk_level=risk_level,
        risk_score=risk_score,
        confidence_score=confidence_score,
        risk_category=risk_category,
        impact_score=impact_score,
        likelihood_score=likelihood_score,
        created_by=created_by,
        description=description,
        **kwargs
    )
    return assessment


def get_db() -> Session:
    """Get database session."""
    return get_db_session()