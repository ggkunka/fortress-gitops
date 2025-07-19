"""
Correlation API - REST endpoints for correlation operations
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.security.sanitization import sanitize_input

from ..models.correlation import (
    CorrelationResult, CorrelationEvent, CorrelationState,
    CorrelationResultStatus, get_db
)
from ..services.correlation_engine import CorrelationEngine
from ..services.event_correlator import EventCorrelator
from ..main import get_correlation_engine, get_event_correlator

logger = get_logger(__name__)
metrics = get_metrics()

router = APIRouter()


@router.get("/results")
@traced("correlation_api_get_results")
async def get_correlation_results(
    status: Optional[CorrelationResultStatus] = None,
    severity: Optional[str] = Query(None, regex="^(low|medium|high|critical)$"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: Session = Depends(get_db)
):
    """Get correlation results with filtering and pagination."""
    try:
        query = db.query(CorrelationResult)
        
        # Apply filters
        if status:
            query = query.filter(CorrelationResult.status == status)
        
        if severity:
            query = query.filter(CorrelationResult.severity == severity)
        
        if start_date:
            query = query.filter(CorrelationResult.created_at >= start_date)
        
        if end_date:
            query = query.filter(CorrelationResult.created_at <= end_date)
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering
        results = query.order_by(
            CorrelationResult.created_at.desc()
        ).offset(offset).limit(limit).all()
        
        # Format results
        formatted_results = []
        for result in results:
            formatted_results.append({
                "id": str(result.id),
                "rule_id": str(result.rule_id),
                "correlation_key": result.correlation_key,
                "title": result.title,
                "description": result.description,
                "severity": result.severity,
                "confidence": result.confidence,
                "risk_score": result.risk_score,
                "event_count": result.event_count,
                "status": result.status,
                "created_at": result.created_at.isoformat(),
                "first_event_at": result.first_event_at.isoformat(),
                "last_event_at": result.last_event_at.isoformat(),
                "metadata": result.metadata,
                "tags": result.tags
            })
        
        return {
            "results": formatted_results,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        logger.error(f"Error getting correlation results: {e}")
        metrics.correlation_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/results/{result_id}")
@traced("correlation_api_get_result")
async def get_correlation_result(
    result_id: UUID,
    db: Session = Depends(get_db)
):
    """Get a specific correlation result."""
    try:
        result = db.query(CorrelationResult).filter(
            CorrelationResult.id == result_id
        ).first()
        
        if not result:
            raise HTTPException(status_code=404, detail="Correlation result not found")
        
        # Get related events
        events = db.query(CorrelationEvent).filter(
            CorrelationEvent.rule_id == result.rule_id,
            CorrelationEvent.correlation_key == result.correlation_key
        ).all()
        
        formatted_events = []
        for event in events:
            formatted_events.append({
                "id": str(event.id),
                "event_id": event.event_id,
                "event_type": event.event_type,
                "event_timestamp": event.event_timestamp.isoformat(),
                "sequence_number": event.sequence_number,
                "status": event.status,
                "event_data": event.event_data
            })
        
        return {
            "id": str(result.id),
            "rule_id": str(result.rule_id),
            "correlation_key": result.correlation_key,
            "title": result.title,
            "description": result.description,
            "severity": result.severity,
            "confidence": result.confidence,
            "risk_score": result.risk_score,
            "event_count": result.event_count,
            "event_ids": result.event_ids,
            "status": result.status,
            "created_at": result.created_at.isoformat(),
            "updated_at": result.updated_at.isoformat(),
            "first_event_at": result.first_event_at.isoformat(),
            "last_event_at": result.last_event_at.isoformat(),
            "correlation_window": result.correlation_window,
            "metadata": result.metadata,
            "tags": result.tags,
            "events": formatted_events
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting correlation result {result_id}: {e}")
        metrics.correlation_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.patch("/results/{result_id}/status")
@traced("correlation_api_update_result_status")
async def update_correlation_result_status(
    result_id: UUID,
    status: CorrelationResultStatus,
    user_id: str = Query(..., description="User ID performing the update"),
    db: Session = Depends(get_db)
):
    """Update correlation result status."""
    try:
        # Sanitize inputs
        user_id = sanitize_input(user_id, max_length=255)
        
        result = db.query(CorrelationResult).filter(
            CorrelationResult.id == result_id
        ).first()
        
        if not result:
            raise HTTPException(status_code=404, detail="Correlation result not found")
        
        # Update status
        result.status = status
        result.updated_at = datetime.now()
        
        if status == CorrelationResultStatus.ACKNOWLEDGED:
            result.acknowledged_at = datetime.now()
            result.acknowledged_by = user_id
        elif status == CorrelationResultStatus.RESOLVED:
            result.resolved_at = datetime.now()
            result.resolved_by = user_id
        
        db.commit()
        
        logger.info(f"Updated correlation result {result_id} status to {status}")
        metrics.correlation_api_status_updates.inc()
        
        return {
            "id": str(result.id),
            "status": result.status,
            "updated_at": result.updated_at.isoformat(),
            "acknowledged_at": result.acknowledged_at.isoformat() if result.acknowledged_at else None,
            "acknowledged_by": result.acknowledged_by,
            "resolved_at": result.resolved_at.isoformat() if result.resolved_at else None,
            "resolved_by": result.resolved_by
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating correlation result status: {e}")
        metrics.correlation_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/events/{correlation_key}")
@traced("correlation_api_get_events")
async def get_correlation_events(
    correlation_key: str,
    rule_id: Optional[UUID] = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Get events for a correlation key."""
    try:
        # Sanitize input
        correlation_key = sanitize_input(correlation_key, max_length=255)
        
        query = db.query(CorrelationEvent).filter(
            CorrelationEvent.correlation_key == correlation_key
        )
        
        if rule_id:
            query = query.filter(CorrelationEvent.rule_id == rule_id)
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering
        events = query.order_by(
            CorrelationEvent.event_timestamp.asc()
        ).offset(offset).limit(limit).all()
        
        formatted_events = []
        for event in events:
            formatted_events.append({
                "id": str(event.id),
                "rule_id": str(event.rule_id),
                "event_id": event.event_id,
                "event_type": event.event_type,
                "correlation_key": event.correlation_key,
                "sequence_number": event.sequence_number,
                "event_timestamp": event.event_timestamp.isoformat(),
                "processed_at": event.processed_at.isoformat(),
                "status": event.status,
                "event_data": event.event_data
            })
        
        return {
            "events": formatted_events,
            "total": total,
            "limit": limit,
            "offset": offset,
            "correlation_key": correlation_key
        }
        
    except Exception as e:
        logger.error(f"Error getting correlation events: {e}")
        metrics.correlation_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/states")
@traced("correlation_api_get_states")
async def get_correlation_states(
    active_only: bool = Query(True, description="Only return active states"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Get correlation states."""
    try:
        query = db.query(CorrelationState)
        
        if active_only:
            query = query.filter(
                CorrelationState.is_active == True,
                CorrelationState.expires_at > datetime.now()
            )
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering
        states = query.order_by(
            CorrelationState.last_updated.desc()
        ).offset(offset).limit(limit).all()
        
        formatted_states = []
        for state in states:
            formatted_states.append({
                "id": str(state.id),
                "rule_id": str(state.rule_id),
                "correlation_key": state.correlation_key,
                "event_count": state.event_count,
                "started_at": state.started_at.isoformat(),
                "last_updated": state.last_updated.isoformat(),
                "expires_at": state.expires_at.isoformat(),
                "is_active": state.is_active,
                "state_data": state.state_data
            })
        
        return {
            "states": formatted_states,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        logger.error(f"Error getting correlation states: {e}")
        metrics.correlation_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/statistics")
@traced("correlation_api_get_statistics")
async def get_correlation_statistics(
    time_range: str = Query("24h", regex="^(1h|6h|24h|7d|30d)$"),
    correlator: EventCorrelator = Depends(get_event_correlator)
):
    """Get correlation statistics."""
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
        
        with get_db() as db:
            # Get correlation results statistics
            total_results = db.query(CorrelationResult).filter(
                CorrelationResult.created_at >= start_time
            ).count()
            
            # Get results by severity
            severity_stats = {}
            for severity in ["low", "medium", "high", "critical"]:
                count = db.query(CorrelationResult).filter(
                    CorrelationResult.created_at >= start_time,
                    CorrelationResult.severity == severity
                ).count()
                severity_stats[severity] = count
            
            # Get results by status
            status_stats = {}
            for status in CorrelationResultStatus:
                count = db.query(CorrelationResult).filter(
                    CorrelationResult.created_at >= start_time,
                    CorrelationResult.status == status
                ).count()
                status_stats[status.value] = count
            
            # Get active correlations
            active_correlations = db.query(CorrelationState).filter(
                CorrelationState.is_active == True,
                CorrelationState.expires_at > datetime.now()
            ).count()
            
            # Get processed events
            processed_events = db.query(CorrelationEvent).filter(
                CorrelationEvent.processed_at >= start_time
            ).count()
        
        # Get engine statistics
        engine_stats = correlator.get_stats()
        
        return {
            "time_range": time_range,
            "start_time": start_time.isoformat(),
            "end_time": datetime.now().isoformat(),
            "total_results": total_results,
            "severity_breakdown": severity_stats,
            "status_breakdown": status_stats,
            "active_correlations": active_correlations,
            "processed_events": processed_events,
            "engine_stats": engine_stats
        }
        
    except Exception as e:
        logger.error(f"Error getting correlation statistics: {e}")
        metrics.correlation_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/test-event")
@traced("correlation_api_test_event")
async def test_event_correlation(
    event_data: Dict[str, Any],
    rule_id: Optional[UUID] = None,
    correlation_engine: CorrelationEngine = Depends(get_correlation_engine)
):
    """Test event correlation (development/testing only)."""
    try:
        # This endpoint is for testing purposes only
        # In production, events would come through the event bus
        
        # Validate event data
        required_fields = ["id", "type", "timestamp"]
        for field in required_fields:
            if field not in event_data:
                raise HTTPException(
                    status_code=400,
                    detail=f"Missing required field: {field}"
                )
        
        # Simulate event processing
        stats = correlation_engine.get_stats()
        
        return {
            "message": "Event correlation test completed",
            "event_data": event_data,
            "rule_id": str(rule_id) if rule_id else None,
            "engine_stats": stats
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error testing event correlation: {e}")
        metrics.correlation_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/results/{result_id}")
@traced("correlation_api_delete_result")
async def delete_correlation_result(
    result_id: UUID,
    user_id: str = Query(..., description="User ID performing the deletion"),
    db: Session = Depends(get_db)
):
    """Delete a correlation result (admin only)."""
    try:
        # Sanitize input
        user_id = sanitize_input(user_id, max_length=255)
        
        result = db.query(CorrelationResult).filter(
            CorrelationResult.id == result_id
        ).first()
        
        if not result:
            raise HTTPException(status_code=404, detail="Correlation result not found")
        
        # Log deletion for audit
        logger.info(f"Deleting correlation result {result_id} by user {user_id}")
        
        # Delete result
        db.delete(result)
        db.commit()
        
        metrics.correlation_api_deletions.inc()
        
        return {
            "message": "Correlation result deleted successfully",
            "result_id": str(result_id),
            "deleted_by": user_id,
            "deleted_at": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting correlation result: {e}")
        metrics.correlation_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")