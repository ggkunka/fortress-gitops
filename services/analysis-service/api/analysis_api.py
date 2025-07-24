"""
Analysis API - REST API for Analysis Service

This module provides REST API endpoints for managing analysis jobs,
retrieving results, and configuring analysis parameters.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, Path, Body
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from shared.auth.dependencies import get_current_user, require_permissions
from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.events.event_bus import get_event_bus

from ..models.analysis import (
    AnalysisJob, AnalysisResult, AnalysisType, AnalysisStatus, SeverityLevel,
    get_db
)
from ..services.analysis_engine import AnalysisEngine, AnalysisRequest

logger = get_logger(__name__)
metrics = get_metrics()

# Create router
router = APIRouter(prefix="/api/v1/analysis", tags=["analysis"])

# Pydantic models for API
class AnalysisJobCreate(BaseModel):
    """Request model for creating analysis job."""
    name: str = Field(..., description="Analysis job name")
    analysis_type: AnalysisType = Field(..., description="Type of analysis to perform")
    input_source: str = Field(..., description="Source of input data")
    input_data: Dict[str, Any] = Field(..., description="Input data for analysis")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Analysis parameters")
    priority: int = Field(default=5, ge=1, le=10, description="Job priority (1-10)")


class AnalysisJobResponse(BaseModel):
    """Response model for analysis job."""
    id: str
    name: str
    analysis_type: str
    status: str
    priority: int
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    execution_time: Optional[float]
    results_count: int
    findings_count: int
    error_message: Optional[str]
    created_by: str


class AnalysisResultResponse(BaseModel):
    """Response model for analysis result."""
    id: str
    job_id: str
    title: str
    analysis_type: str
    severity: str
    confidence_score: float
    risk_score: int
    finding_type: str
    description: str
    affected_entities: List[str]
    evidence: Dict[str, Any]
    recommendations: List[str]
    created_at: datetime


class AnalysisStatsResponse(BaseModel):
    """Response model for analysis statistics."""
    total_jobs: int
    active_jobs: int
    completed_jobs: int
    failed_jobs: int
    avg_processing_time: float
    jobs_by_type: Dict[str, int]
    jobs_by_status: Dict[str, int]


# Dependency to get analysis engine
async def get_analysis_engine() -> AnalysisEngine:
    """Get analysis engine instance."""
    event_bus = await get_event_bus()
    return AnalysisEngine(event_bus)


@router.post("/jobs", response_model=Dict[str, str])
@traced("analysis_api_create_job")
async def create_analysis_job(
    job_data: AnalysisJobCreate,
    current_user: Dict[str, Any] = Depends(get_current_user),
    analysis_engine: AnalysisEngine = Depends(get_analysis_engine)
):
    """Create a new analysis job."""
    try:
        # Check permissions
        await require_permissions(current_user, ["analysis:create"])
        
        # Create analysis request
        request = AnalysisRequest(
            analysis_type=job_data.analysis_type,
            input_source=job_data.input_source,
            input_data=job_data.input_data,
            parameters=job_data.parameters,
            priority=job_data.priority,
            requested_by=current_user.get("username", "unknown")
        )
        
        # Submit analysis job
        job_id = await analysis_engine.analyze(request)
        
        logger.info(f"Analysis job created: {job_id}")
        metrics.analysis_api_jobs_created.inc()
        
        return {"job_id": str(job_id)}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating analysis job: {e}")
        metrics.analysis_api_errors.inc()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/jobs", response_model=List[AnalysisJobResponse])
@traced("analysis_api_list_jobs")
async def list_analysis_jobs(
    skip: int = Query(0, ge=0, description="Number of jobs to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of jobs to return"),
    analysis_type: Optional[AnalysisType] = Query(None, description="Filter by analysis type"),
    status: Optional[AnalysisStatus] = Query(None, description="Filter by status"),
    created_by: Optional[str] = Query(None, description="Filter by creator"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List analysis jobs with optional filtering."""
    try:
        # Check permissions
        await require_permissions(current_user, ["analysis:read"])
        
        with get_db() as db:
            query = db.query(AnalysisJob)
            
            # Apply filters
            if analysis_type:
                query = query.filter(AnalysisJob.analysis_type == analysis_type.value)
            if status:
                query = query.filter(AnalysisJob.status == status.value)
            if created_by:
                query = query.filter(AnalysisJob.created_by == created_by)
            
            # Apply pagination
            jobs = query.offset(skip).limit(limit).all()
            
            # Convert to response models
            job_responses = []
            for job in jobs:
                job_responses.append(AnalysisJobResponse(
                    id=str(job.id),
                    name=job.name,
                    analysis_type=job.analysis_type,
                    status=job.status,
                    priority=job.priority,
                    created_at=job.created_at,
                    started_at=job.started_at,
                    completed_at=job.completed_at,
                    execution_time=job.execution_time,
                    results_count=job.results_count or 0,
                    findings_count=job.findings_count or 0,
                    error_message=job.error_message,
                    created_by=job.created_by
                ))
            
            logger.info(f"Listed {len(job_responses)} analysis jobs")
            metrics.analysis_api_jobs_listed.inc()
            
            return job_responses
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing analysis jobs: {e}")
        metrics.analysis_api_errors.inc()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/jobs/{job_id}", response_model=AnalysisJobResponse)
@traced("analysis_api_get_job")
async def get_analysis_job(
    job_id: UUID = Path(..., description="Analysis job ID"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get analysis job by ID."""
    try:
        # Check permissions
        await require_permissions(current_user, ["analysis:read"])
        
        with get_db() as db:
            job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
            
            if not job:
                raise HTTPException(status_code=404, detail="Analysis job not found")
            
            job_response = AnalysisJobResponse(
                id=str(job.id),
                name=job.name,
                analysis_type=job.analysis_type,
                status=job.status,
                priority=job.priority,
                created_at=job.created_at,
                started_at=job.started_at,
                completed_at=job.completed_at,
                execution_time=job.execution_time,
                results_count=job.results_count or 0,
                findings_count=job.findings_count or 0,
                error_message=job.error_message,
                created_by=job.created_by
            )
            
            logger.info(f"Retrieved analysis job: {job_id}")
            
            return job_response
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving analysis job: {e}")
        metrics.analysis_api_errors.inc()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/jobs/{job_id}/results", response_model=List[AnalysisResultResponse])
@traced("analysis_api_get_job_results")
async def get_job_results(
    job_id: UUID = Path(..., description="Analysis job ID"),
    skip: int = Query(0, ge=0, description="Number of results to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of results to return"),
    severity: Optional[SeverityLevel] = Query(None, description="Filter by severity"),
    finding_type: Optional[str] = Query(None, description="Filter by finding type"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get analysis results for a job."""
    try:
        # Check permissions
        await require_permissions(current_user, ["analysis:read"])
        
        with get_db() as db:
            # Verify job exists
            job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
            if not job:
                raise HTTPException(status_code=404, detail="Analysis job not found")
            
            # Query results
            query = db.query(AnalysisResult).filter(AnalysisResult.job_id == job_id)
            
            # Apply filters
            if severity:
                query = query.filter(AnalysisResult.severity == severity.value)
            if finding_type:
                query = query.filter(AnalysisResult.finding_type == finding_type)
            
            # Apply pagination
            results = query.offset(skip).limit(limit).all()
            
            # Convert to response models
            result_responses = []
            for result in results:
                result_responses.append(AnalysisResultResponse(
                    id=str(result.id),
                    job_id=str(result.job_id),
                    title=result.title,
                    analysis_type=result.analysis_type,
                    severity=result.severity,
                    confidence_score=result.confidence_score,
                    risk_score=result.risk_score,
                    finding_type=result.finding_type,
                    description=result.description,
                    affected_entities=result.affected_entities or [],
                    evidence=result.evidence or {},
                    recommendations=result.recommendations or [],
                    created_at=result.created_at
                ))
            
            logger.info(f"Retrieved {len(result_responses)} results for job {job_id}")
            
            return result_responses
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving job results: {e}")
        metrics.analysis_api_errors.inc()
        raise HTTPException(status_code=500, detail=str(e))


@router.delete("/jobs/{job_id}")
@traced("analysis_api_cancel_job")
async def cancel_analysis_job(
    job_id: UUID = Path(..., description="Analysis job ID"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Cancel an analysis job."""
    try:
        # Check permissions
        await require_permissions(current_user, ["analysis:delete"])
        
        with get_db() as db:
            job = db.query(AnalysisJob).filter(AnalysisJob.id == job_id).first()
            
            if not job:
                raise HTTPException(status_code=404, detail="Analysis job not found")
            
            if job.status in [AnalysisStatus.COMPLETED.value, AnalysisStatus.FAILED.value]:
                raise HTTPException(status_code=400, detail="Cannot cancel completed job")
            
            # Update job status
            job.status = AnalysisStatus.CANCELLED.value
            job.completed_at = datetime.now()
            db.commit()
            
            logger.info(f"Cancelled analysis job: {job_id}")
            metrics.analysis_api_jobs_cancelled.inc()
            
            return {"message": "Analysis job cancelled"}
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error cancelling analysis job: {e}")
        metrics.analysis_api_errors.inc()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/results", response_model=List[AnalysisResultResponse])
@traced("analysis_api_list_results")
async def list_analysis_results(
    skip: int = Query(0, ge=0, description="Number of results to skip"),
    limit: int = Query(100, ge=1, le=1000, description="Maximum number of results to return"),
    analysis_type: Optional[AnalysisType] = Query(None, description="Filter by analysis type"),
    severity: Optional[SeverityLevel] = Query(None, description="Filter by severity"),
    finding_type: Optional[str] = Query(None, description="Filter by finding type"),
    min_risk_score: Optional[int] = Query(None, ge=0, le=100, description="Minimum risk score"),
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """List analysis results with filtering."""
    try:
        # Check permissions
        await require_permissions(current_user, ["analysis:read"])
        
        with get_db() as db:
            query = db.query(AnalysisResult)
            
            # Apply filters
            if analysis_type:
                query = query.filter(AnalysisResult.analysis_type == analysis_type.value)
            if severity:
                query = query.filter(AnalysisResult.severity == severity.value)
            if finding_type:
                query = query.filter(AnalysisResult.finding_type == finding_type)
            if min_risk_score is not None:
                query = query.filter(AnalysisResult.risk_score >= min_risk_score)
            
            # Order by risk score descending
            query = query.order_by(AnalysisResult.risk_score.desc())
            
            # Apply pagination
            results = query.offset(skip).limit(limit).all()
            
            # Convert to response models
            result_responses = []
            for result in results:
                result_responses.append(AnalysisResultResponse(
                    id=str(result.id),
                    job_id=str(result.job_id),
                    title=result.title,
                    analysis_type=result.analysis_type,
                    severity=result.severity,
                    confidence_score=result.confidence_score,
                    risk_score=result.risk_score,
                    finding_type=result.finding_type,
                    description=result.description,
                    affected_entities=result.affected_entities or [],
                    evidence=result.evidence or {},
                    recommendations=result.recommendations or [],
                    created_at=result.created_at
                ))
            
            logger.info(f"Listed {len(result_responses)} analysis results")
            
            return result_responses
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error listing analysis results: {e}")
        metrics.analysis_api_errors.inc()
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/stats", response_model=AnalysisStatsResponse)
@traced("analysis_api_get_stats")
async def get_analysis_stats(
    current_user: Dict[str, Any] = Depends(get_current_user)
):
    """Get analysis service statistics."""
    try:
        # Check permissions
        await require_permissions(current_user, ["analysis:read"])
        
        with get_db() as db:
            # Get job counts
            total_jobs = db.query(AnalysisJob).count()
            active_jobs = db.query(AnalysisJob).filter(
                AnalysisJob.status == AnalysisStatus.RUNNING.value
            ).count()
            completed_jobs = db.query(AnalysisJob).filter(
                AnalysisJob.status == AnalysisStatus.COMPLETED.value
            ).count()
            failed_jobs = db.query(AnalysisJob).filter(
                AnalysisJob.status == AnalysisStatus.FAILED.value
            ).count()
            
            # Get average processing time
            completed_jobs_with_time = db.query(AnalysisJob).filter(
                AnalysisJob.status == AnalysisStatus.COMPLETED.value,
                AnalysisJob.execution_time.isnot(None)
            ).all()
            
            avg_processing_time = 0.0
            if completed_jobs_with_time:
                avg_processing_time = sum(
                    job.execution_time for job in completed_jobs_with_time
                ) / len(completed_jobs_with_time)
            
            # Get jobs by type
            jobs_by_type = {}
            for analysis_type in AnalysisType:
                count = db.query(AnalysisJob).filter(
                    AnalysisJob.analysis_type == analysis_type.value
                ).count()
                jobs_by_type[analysis_type.value] = count
            
            # Get jobs by status
            jobs_by_status = {}
            for status in AnalysisStatus:
                count = db.query(AnalysisJob).filter(
                    AnalysisJob.status == status.value
                ).count()
                jobs_by_status[status.value] = count
            
            stats = AnalysisStatsResponse(
                total_jobs=total_jobs,
                active_jobs=active_jobs,
                completed_jobs=completed_jobs,
                failed_jobs=failed_jobs,
                avg_processing_time=avg_processing_time,
                jobs_by_type=jobs_by_type,
                jobs_by_status=jobs_by_status
            )
            
            logger.info("Retrieved analysis statistics")
            
            return stats
            
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error retrieving analysis stats: {e}")
        metrics.analysis_api_errors.inc()
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/analyze/immediate")
@traced("analysis_api_immediate_analyze")
async def immediate_analyze(
    analysis_data: Dict[str, Any] = Body(..., description="Analysis data"),
    analysis_type: AnalysisType = Query(..., description="Type of analysis"),
    current_user: Dict[str, Any] = Depends(get_current_user),
    analysis_engine: AnalysisEngine = Depends(get_analysis_engine)
):
    """Perform immediate analysis without creating a job."""
    try:
        # Check permissions
        await require_permissions(current_user, ["analysis:execute"])
        
        # This would perform immediate analysis for small datasets
        # For now, we'll create a high-priority job
        request = AnalysisRequest(
            analysis_type=analysis_type,
            input_source="immediate_request",
            input_data=analysis_data,
            parameters={"immediate": True},
            priority=10,  # Highest priority
            requested_by=current_user.get("username", "unknown")
        )
        
        job_id = await analysis_engine.analyze(request)
        
        logger.info(f"Immediate analysis job created: {job_id}")
        metrics.analysis_api_immediate_analyses.inc()
        
        return {"job_id": str(job_id), "message": "Immediate analysis job created"}
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error performing immediate analysis: {e}")
        metrics.analysis_api_errors.inc()
        raise HTTPException(status_code=500, detail=str(e))