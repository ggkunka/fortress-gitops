"""
Risk Assessment API - REST endpoints for risk assessment operations
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.security.sanitization import sanitize_input

from ..models.risk_assessment import (
    RiskAssessment, RiskFactor, RiskMitigation, RiskProfile, 
    RiskLevel, RiskCategory, RiskAssessmentStatus, get_db
)
from ..services.risk_assessment_engine import RiskAssessmentEngine, AssessmentRequest
from ..main import get_risk_assessment_engine

logger = get_logger(__name__)
metrics = get_metrics()

router = APIRouter()


class CreateAssessmentRequest(BaseModel):
    """Request model for creating risk assessments."""
    correlation_result_id: UUID = Field(..., description="Correlation result ID")
    assessment_type: str = Field(..., regex="^(manual|automated|scheduled)$")
    priority: int = Field(5, ge=1, le=10)
    context: Optional[Dict[str, Any]] = Field(default_factory=dict)
    requested_by: str = Field(..., min_length=1, max_length=255)


class UpdateAssessmentRequest(BaseModel):
    """Request model for updating risk assessments."""
    status: Optional[RiskAssessmentStatus] = None
    risk_level: Optional[RiskLevel] = None
    risk_score: Optional[float] = Field(None, ge=0, le=100)
    confidence_score: Optional[float] = Field(None, ge=0, le=100)
    description: Optional[str] = Field(None, max_length=1000)
    updated_by: str = Field(..., min_length=1, max_length=255)


class CreateMitigationRequest(BaseModel):
    """Request model for creating risk mitigations."""
    mitigation_name: str = Field(..., min_length=1, max_length=255)
    mitigation_type: str = Field(..., regex="^(preventive|detective|corrective|recovery)$")
    description: str = Field(..., max_length=1000)
    effectiveness_score: float = Field(..., ge=0, le=100)
    implementation_cost: float = Field(..., ge=0, le=100)
    implementation_time: int = Field(..., ge=1)
    priority: int = Field(5, ge=1, le=10)
    assigned_to: Optional[str] = Field(None, max_length=255)
    due_date: Optional[datetime] = None


@router.get("/assessments")
@traced("risk_assessment_api_get_assessments")
async def get_risk_assessments(
    status: Optional[RiskAssessmentStatus] = None,
    risk_level: Optional[RiskLevel] = None,
    risk_category: Optional[RiskCategory] = None,
    min_score: Optional[float] = Query(None, ge=0, le=100),
    max_score: Optional[float] = Query(None, ge=0, le=100),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Get risk assessments with filtering and pagination."""
    try:
        query = db.query(RiskAssessment)
        
        # Apply filters
        if status:
            query = query.filter(RiskAssessment.status == status)
        
        if risk_level:
            query = query.filter(RiskAssessment.risk_level == risk_level)
        
        if risk_category:
            query = query.filter(RiskAssessment.risk_category == risk_category)
        
        if min_score is not None:
            query = query.filter(RiskAssessment.risk_score >= min_score)
        
        if max_score is not None:
            query = query.filter(RiskAssessment.risk_score <= max_score)
        
        if start_date:
            query = query.filter(RiskAssessment.created_at >= start_date)
        
        if end_date:
            query = query.filter(RiskAssessment.created_at <= end_date)
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering
        assessments = query.order_by(
            RiskAssessment.risk_score.desc(),
            RiskAssessment.created_at.desc()
        ).offset(offset).limit(limit).all()
        
        # Format results
        formatted_assessments = []
        for assessment in assessments:
            formatted_assessments.append({
                "id": str(assessment.id),
                "correlation_result_id": str(assessment.correlation_result_id),
                "title": assessment.title,
                "description": assessment.description,
                "risk_level": assessment.risk_level,
                "risk_score": assessment.risk_score,
                "confidence_score": assessment.confidence_score,
                "risk_category": assessment.risk_category,
                "status": assessment.status,
                "created_at": assessment.created_at.isoformat(),
                "updated_at": assessment.updated_at.isoformat(),
                "completed_at": assessment.completed_at.isoformat() if assessment.completed_at else None,
                "created_by": assessment.created_by,
                "updated_by": assessment.updated_by
            })
        
        return {
            "assessments": formatted_assessments,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        logger.error(f"Error getting risk assessments: {e}")
        metrics.risk_assessment_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/assessments/{assessment_id}")
@traced("risk_assessment_api_get_assessment")
async def get_risk_assessment(
    assessment_id: UUID,
    db: Session = Depends(get_db)
):
    """Get a specific risk assessment with details."""
    try:
        assessment = db.query(RiskAssessment).filter(
            RiskAssessment.id == assessment_id
        ).first()
        
        if not assessment:
            raise HTTPException(status_code=404, detail="Risk assessment not found")
        
        # Get related risk factors
        factors = db.query(RiskFactor).filter(
            RiskFactor.assessment_id == assessment_id
        ).all()
        
        # Get related mitigations
        mitigations = db.query(RiskMitigation).filter(
            RiskMitigation.assessment_id == assessment_id
        ).all()
        
        # Format factors
        formatted_factors = []
        for factor in factors:
            formatted_factors.append({
                "id": str(factor.id),
                "factor_name": factor.factor_name,
                "factor_type": factor.factor_type,
                "factor_description": factor.factor_description,
                "weight": factor.weight,
                "impact": factor.impact,
                "likelihood": factor.likelihood,
                "factor_data": factor.factor_data,
                "evidence": factor.evidence,
                "created_at": factor.created_at.isoformat()
            })
        
        # Format mitigations
        formatted_mitigations = []
        for mitigation in mitigations:
            formatted_mitigations.append({
                "id": str(mitigation.id),
                "mitigation_name": mitigation.mitigation_name,
                "mitigation_type": mitigation.mitigation_type,
                "description": mitigation.description,
                "effectiveness_score": mitigation.effectiveness_score,
                "implementation_cost": mitigation.implementation_cost,
                "implementation_time": mitigation.implementation_time,
                "status": mitigation.status,
                "priority": mitigation.priority,
                "assigned_to": mitigation.assigned_to,
                "due_date": mitigation.due_date.isoformat() if mitigation.due_date else None,
                "created_at": mitigation.created_at.isoformat()
            })
        
        return {
            "id": str(assessment.id),
            "correlation_result_id": str(assessment.correlation_result_id),
            "title": assessment.title,
            "description": assessment.description,
            "risk_level": assessment.risk_level,
            "risk_score": assessment.risk_score,
            "confidence_score": assessment.confidence_score,
            "risk_category": assessment.risk_category,
            "risk_subcategory": assessment.risk_subcategory,
            "impact_score": assessment.impact_score,
            "likelihood_score": assessment.likelihood_score,
            "vulnerability_score": assessment.vulnerability_score,
            "threat_score": assessment.threat_score,
            "context_data": assessment.context_data,
            "analysis_data": assessment.analysis_data,
            "recommendations": assessment.recommendations,
            "llm_analysis": assessment.llm_analysis,
            "llm_confidence": assessment.llm_confidence,
            "llm_reasoning": assessment.llm_reasoning,
            "status": assessment.status,
            "created_at": assessment.created_at.isoformat(),
            "updated_at": assessment.updated_at.isoformat(),
            "completed_at": assessment.completed_at.isoformat() if assessment.completed_at else None,
            "created_by": assessment.created_by,
            "updated_by": assessment.updated_by,
            "reviewed_by": assessment.reviewed_by,
            "reviewed_at": assessment.reviewed_at.isoformat() if assessment.reviewed_at else None,
            "metadata": assessment.metadata,
            "tags": assessment.tags,
            "risk_factors": formatted_factors,
            "mitigations": formatted_mitigations
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting risk assessment {assessment_id}: {e}")
        metrics.risk_assessment_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/assessments")
@traced("risk_assessment_api_create_assessment")
async def create_risk_assessment(
    request: CreateAssessmentRequest,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db),
    engine: RiskAssessmentEngine = Depends(get_risk_assessment_engine)
):
    """Create a new risk assessment."""
    try:
        # Sanitize inputs
        requested_by = sanitize_input(request.requested_by, max_length=255)
        
        # Create assessment request
        assessment_request = AssessmentRequest(
            correlation_result_id=request.correlation_result_id,
            correlation_data=request.context.get("correlation_data", {}),
            assessment_type=request.assessment_type,
            priority=request.priority,
            requested_by=requested_by,
            context=request.context
        )
        
        # Queue assessment for processing
        background_tasks.add_task(engine.assess_risk, assessment_request)
        
        # Create pending assessment record
        from ..models.risk_assessment import create_risk_assessment
        assessment = create_risk_assessment(
            title=f"Risk Assessment for {request.correlation_result_id}",
            correlation_result_id=request.correlation_result_id,
            risk_level=RiskLevel.MEDIUM,  # Placeholder
            risk_score=0.0,  # Will be updated
            confidence_score=0.0,  # Will be updated
            risk_category=RiskCategory.SECURITY,  # Placeholder
            impact_score=0.0,  # Will be updated
            likelihood_score=0.0,  # Will be updated
            created_by=requested_by,
            status=RiskAssessmentStatus.PENDING
        )
        
        db.add(assessment)
        db.commit()
        db.refresh(assessment)
        
        logger.info(f"Risk assessment queued: {assessment.id}")
        metrics.risk_assessment_api_created.inc()
        
        return {
            "id": str(assessment.id),
            "correlation_result_id": str(assessment.correlation_result_id),
            "status": assessment.status,
            "assessment_type": request.assessment_type,
            "priority": request.priority,
            "created_at": assessment.created_at.isoformat(),
            "created_by": assessment.created_by,
            "message": "Risk assessment queued for processing"
        }
        
    except Exception as e:
        logger.error(f"Error creating risk assessment: {e}")
        metrics.risk_assessment_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/assessments/{assessment_id}")
@traced("risk_assessment_api_update_assessment")
async def update_risk_assessment(
    assessment_id: UUID,
    request: UpdateAssessmentRequest,
    db: Session = Depends(get_db)
):
    """Update a risk assessment."""
    try:
        assessment = db.query(RiskAssessment).filter(
            RiskAssessment.id == assessment_id
        ).first()
        
        if not assessment:
            raise HTTPException(status_code=404, detail="Risk assessment not found")
        
        # Sanitize inputs
        updated_by = sanitize_input(request.updated_by, max_length=255)
        
        # Update fields
        if request.status is not None:
            assessment.status = request.status
        
        if request.risk_level is not None:
            assessment.risk_level = request.risk_level
        
        if request.risk_score is not None:
            assessment.risk_score = request.risk_score
        
        if request.confidence_score is not None:
            assessment.confidence_score = request.confidence_score
        
        if request.description is not None:
            assessment.description = sanitize_input(request.description, max_length=1000)
        
        # Update metadata
        assessment.updated_by = updated_by
        assessment.updated_at = datetime.now()
        
        # Mark as reviewed if status is being set to reviewed
        if request.status == RiskAssessmentStatus.REVIEWED:
            assessment.reviewed_by = updated_by
            assessment.reviewed_at = datetime.now()
        
        db.commit()
        
        logger.info(f"Risk assessment updated: {assessment.id}")
        metrics.risk_assessment_api_updated.inc()
        
        return {
            "id": str(assessment.id),
            "status": assessment.status,
            "risk_level": assessment.risk_level,
            "risk_score": assessment.risk_score,
            "confidence_score": assessment.confidence_score,
            "updated_at": assessment.updated_at.isoformat(),
            "updated_by": assessment.updated_by,
            "reviewed_at": assessment.reviewed_at.isoformat() if assessment.reviewed_at else None,
            "reviewed_by": assessment.reviewed_by
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating risk assessment: {e}")
        metrics.risk_assessment_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/assessments/{assessment_id}/mitigations")
@traced("risk_assessment_api_create_mitigation")
async def create_risk_mitigation(
    assessment_id: UUID,
    request: CreateMitigationRequest,
    db: Session = Depends(get_db)
):
    """Create a risk mitigation for an assessment."""
    try:
        # Verify assessment exists
        assessment = db.query(RiskAssessment).filter(
            RiskAssessment.id == assessment_id
        ).first()
        
        if not assessment:
            raise HTTPException(status_code=404, detail="Risk assessment not found")
        
        # Sanitize inputs
        mitigation_name = sanitize_input(request.mitigation_name, max_length=255)
        description = sanitize_input(request.description, max_length=1000)
        assigned_to = sanitize_input(request.assigned_to, max_length=255) if request.assigned_to else None
        
        # Create mitigation
        mitigation = RiskMitigation(
            assessment_id=assessment_id,
            mitigation_name=mitigation_name,
            mitigation_type=request.mitigation_type,
            description=description,
            effectiveness_score=request.effectiveness_score,
            implementation_cost=request.implementation_cost,
            implementation_time=request.implementation_time,
            priority=request.priority,
            assigned_to=assigned_to,
            due_date=request.due_date,
            status="recommended"
        )
        
        db.add(mitigation)
        db.commit()
        db.refresh(mitigation)
        
        logger.info(f"Risk mitigation created for assessment {assessment_id}")
        metrics.risk_assessment_api_mitigations_created.inc()
        
        return {
            "id": str(mitigation.id),
            "assessment_id": str(mitigation.assessment_id),
            "mitigation_name": mitigation.mitigation_name,
            "mitigation_type": mitigation.mitigation_type,
            "description": mitigation.description,
            "effectiveness_score": mitigation.effectiveness_score,
            "implementation_cost": mitigation.implementation_cost,
            "implementation_time": mitigation.implementation_time,
            "priority": mitigation.priority,
            "status": mitigation.status,
            "assigned_to": mitigation.assigned_to,
            "due_date": mitigation.due_date.isoformat() if mitigation.due_date else None,
            "created_at": mitigation.created_at.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating risk mitigation: {e}")
        metrics.risk_assessment_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/profiles")
@traced("risk_assessment_api_get_profiles")
async def get_risk_profiles(
    entity_type: Optional[str] = None,
    risk_level: Optional[RiskLevel] = None,
    min_score: Optional[float] = Query(None, ge=0, le=100),
    max_score: Optional[float] = Query(None, ge=0, le=100),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Get risk profiles with filtering and pagination."""
    try:
        query = db.query(RiskProfile)
        
        # Apply filters
        if entity_type:
            query = query.filter(RiskProfile.entity_type == entity_type)
        
        if risk_level:
            query = query.filter(RiskProfile.risk_level == risk_level)
        
        if min_score is not None:
            query = query.filter(RiskProfile.overall_risk_score >= min_score)
        
        if max_score is not None:
            query = query.filter(RiskProfile.overall_risk_score <= max_score)
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering
        profiles = query.order_by(
            RiskProfile.overall_risk_score.desc(),
            RiskProfile.last_assessed_at.desc()
        ).offset(offset).limit(limit).all()
        
        # Format results
        formatted_profiles = []
        for profile in profiles:
            formatted_profiles.append({
                "id": str(profile.id),
                "entity_type": profile.entity_type,
                "entity_id": profile.entity_id,
                "entity_name": profile.entity_name,
                "overall_risk_score": profile.overall_risk_score,
                "risk_level": profile.risk_level,
                "risk_trend": profile.risk_trend,
                "security_score": profile.security_score,
                "compliance_score": profile.compliance_score,
                "operational_score": profile.operational_score,
                "incident_count": profile.incident_count,
                "last_incident_date": profile.last_incident_date.isoformat() if profile.last_incident_date else None,
                "last_assessed_at": profile.last_assessed_at.isoformat() if profile.last_assessed_at else None,
                "created_at": profile.created_at.isoformat(),
                "updated_at": profile.updated_at.isoformat()
            })
        
        return {
            "profiles": formatted_profiles,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        logger.error(f"Error getting risk profiles: {e}")
        metrics.risk_assessment_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/statistics")
@traced("risk_assessment_api_get_statistics")
async def get_risk_statistics(
    time_range: str = Query("24h", regex="^(1h|6h|24h|7d|30d)$"),
    db: Session = Depends(get_db)
):
    """Get risk assessment statistics."""
    try:
        # Parse time range
        time_delta_map = {
            "1h": timedelta(hours=1),
            "6h": timedelta(hours=6),
            "24h": timedelta(hours=24),
            "7d": timedelta(days=7),
            "30d": timedelta(days=30)
        }
        
        time_delta = time_delta_map.get(time_range, timedelta(hours=24))
        start_time = datetime.now() - time_delta
        
        # Get assessment statistics
        total_assessments = db.query(RiskAssessment).filter(
            RiskAssessment.created_at >= start_time
        ).count()
        
        # Get assessments by risk level
        risk_level_stats = {}
        for level in RiskLevel:
            count = db.query(RiskAssessment).filter(
                RiskAssessment.created_at >= start_time,
                RiskAssessment.risk_level == level
            ).count()
            risk_level_stats[level.value] = count
        
        # Get assessments by status
        status_stats = {}
        for status in RiskAssessmentStatus:
            count = db.query(RiskAssessment).filter(
                RiskAssessment.created_at >= start_time,
                RiskAssessment.status == status
            ).count()
            status_stats[status.value] = count
        
        # Get assessments by category
        category_stats = {}
        for category in RiskCategory:
            count = db.query(RiskAssessment).filter(
                RiskAssessment.created_at >= start_time,
                RiskAssessment.risk_category == category
            ).count()
            category_stats[category.value] = count
        
        # Get average risk score
        avg_risk_score = db.query(RiskAssessment).filter(
            RiskAssessment.created_at >= start_time
        ).with_entities(
            db.func.avg(RiskAssessment.risk_score).label('avg_score')
        ).scalar()
        
        # Get mitigation statistics
        total_mitigations = db.query(RiskMitigation).join(RiskAssessment).filter(
            RiskAssessment.created_at >= start_time
        ).count()
        
        return {
            "time_range": time_range,
            "start_time": start_time.isoformat(),
            "end_time": datetime.now().isoformat(),
            "total_assessments": total_assessments,
            "risk_level_breakdown": risk_level_stats,
            "status_breakdown": status_stats,
            "category_breakdown": category_stats,
            "average_risk_score": round(avg_risk_score, 2) if avg_risk_score else 0,
            "total_mitigations": total_mitigations
        }
        
    except Exception as e:
        logger.error(f"Error getting risk statistics: {e}")
        metrics.risk_assessment_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/assessments/{assessment_id}")
@traced("risk_assessment_api_delete_assessment")
async def delete_risk_assessment(
    assessment_id: UUID,
    user_id: str = Query(..., description="User ID performing the deletion"),
    db: Session = Depends(get_db)
):
    """Delete a risk assessment (admin only)."""
    try:
        # Sanitize input
        user_id = sanitize_input(user_id, max_length=255)
        
        assessment = db.query(RiskAssessment).filter(
            RiskAssessment.id == assessment_id
        ).first()
        
        if not assessment:
            raise HTTPException(status_code=404, detail="Risk assessment not found")
        
        # Log deletion for audit
        logger.info(f"Deleting risk assessment {assessment_id} by user {user_id}")
        
        # Delete assessment and related data
        db.query(RiskMitigation).filter(
            RiskMitigation.assessment_id == assessment_id
        ).delete()
        
        db.query(RiskFactor).filter(
            RiskFactor.assessment_id == assessment_id
        ).delete()
        
        db.delete(assessment)
        db.commit()
        
        metrics.risk_assessment_api_deletions.inc()
        
        return {
            "message": "Risk assessment deleted successfully",
            "assessment_id": str(assessment_id),
            "deleted_by": user_id,
            "deleted_at": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting risk assessment: {e}")
        metrics.risk_assessment_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")