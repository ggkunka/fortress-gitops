"""
Rules API - REST endpoints for correlation rule management
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.security.sanitization import sanitize_input

from ..models.correlation import (
    CorrelationRule, CorrelationRuleStatus, CorrelationMetrics,
    create_correlation_rule, get_db
)
from ..services.rule_engine import RuleEngine
from ..main import get_rule_engine

logger = get_logger(__name__)
metrics = get_metrics()

router = APIRouter()


class CreateRuleRequest(BaseModel):
    """Request model for creating correlation rules."""
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    rule_dsl: str = Field(..., min_length=1, max_length=10000)
    rule_type: str = Field(..., regex="^(sequence|threshold|pattern|statistical|temporal)$")
    time_window: int = Field(..., ge=1, le=86400)  # 1 second to 24 hours
    max_events: Optional[int] = Field(1000, ge=1, le=100000)
    priority: Optional[int] = Field(5, ge=1, le=10)
    threshold_count: Optional[int] = Field(1, ge=1)
    threshold_timeframe: Optional[int] = Field(300, ge=1)
    configuration: Optional[Dict[str, Any]] = Field(default_factory=dict)
    created_by: str = Field(..., min_length=1, max_length=255)


class UpdateRuleRequest(BaseModel):
    """Request model for updating correlation rules."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=1000)
    rule_dsl: Optional[str] = Field(None, min_length=1, max_length=10000)
    rule_type: Optional[str] = Field(None, regex="^(sequence|threshold|pattern|statistical|temporal)$")
    time_window: Optional[int] = Field(None, ge=1, le=86400)
    max_events: Optional[int] = Field(None, ge=1, le=100000)
    priority: Optional[int] = Field(None, ge=1, le=10)
    threshold_count: Optional[int] = Field(None, ge=1)
    threshold_timeframe: Optional[int] = Field(None, ge=1)
    configuration: Optional[Dict[str, Any]] = None
    status: Optional[CorrelationRuleStatus] = None
    updated_by: str = Field(..., min_length=1, max_length=255)


class ValidateRuleRequest(BaseModel):
    """Request model for validating correlation rules."""
    rule_dsl: str = Field(..., min_length=1, max_length=10000)
    rule_type: str = Field(..., regex="^(sequence|threshold|pattern|statistical|temporal)$")


@router.get("/")
@traced("rules_api_get_rules")
async def get_correlation_rules(
    status: Optional[CorrelationRuleStatus] = None,
    rule_type: Optional[str] = Query(None, regex="^(sequence|threshold|pattern|statistical|temporal)$"),
    limit: int = Query(50, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db)
):
    """Get correlation rules with filtering and pagination."""
    try:
        query = db.query(CorrelationRule)
        
        # Apply filters
        if status:
            query = query.filter(CorrelationRule.status == status)
        
        if rule_type:
            query = query.filter(CorrelationRule.rule_type == rule_type)
        
        # Get total count
        total = query.count()
        
        # Apply pagination and ordering
        rules = query.order_by(
            CorrelationRule.priority.desc(),
            CorrelationRule.created_at.desc()
        ).offset(offset).limit(limit).all()
        
        # Format results
        formatted_rules = []
        for rule in rules:
            formatted_rules.append({
                "id": str(rule.id),
                "name": rule.name,
                "description": rule.description,
                "rule_type": rule.rule_type,
                "status": rule.status,
                "priority": rule.priority,
                "time_window": rule.time_window,
                "max_events": rule.max_events,
                "threshold_count": rule.threshold_count,
                "threshold_timeframe": rule.threshold_timeframe,
                "created_at": rule.created_at.isoformat(),
                "updated_at": rule.updated_at.isoformat(),
                "created_by": rule.created_by,
                "updated_by": rule.updated_by
            })
        
        return {
            "rules": formatted_rules,
            "total": total,
            "limit": limit,
            "offset": offset
        }
        
    except Exception as e:
        logger.error(f"Error getting correlation rules: {e}")
        metrics.rules_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{rule_id}")
@traced("rules_api_get_rule")
async def get_correlation_rule(
    rule_id: UUID,
    db: Session = Depends(get_db)
):
    """Get a specific correlation rule."""
    try:
        rule = db.query(CorrelationRule).filter(
            CorrelationRule.id == rule_id
        ).first()
        
        if not rule:
            raise HTTPException(status_code=404, detail="Correlation rule not found")
        
        # Get rule metrics
        metrics_data = db.query(CorrelationMetrics).filter(
            CorrelationMetrics.rule_id == rule_id
        ).order_by(CorrelationMetrics.created_at.desc()).first()
        
        rule_metrics = None
        if metrics_data:
            rule_metrics = {
                "events_processed": metrics_data.events_processed,
                "correlations_found": metrics_data.correlations_found,
                "false_positives": metrics_data.false_positives,
                "avg_processing_time": metrics_data.avg_processing_time,
                "max_processing_time": metrics_data.max_processing_time,
                "period_start": metrics_data.period_start.isoformat(),
                "period_end": metrics_data.period_end.isoformat()
            }
        
        return {
            "id": str(rule.id),
            "name": rule.name,
            "description": rule.description,
            "rule_dsl": rule.rule_dsl,
            "rule_type": rule.rule_type,
            "status": rule.status,
            "priority": rule.priority,
            "time_window": rule.time_window,
            "max_events": rule.max_events,
            "threshold_count": rule.threshold_count,
            "threshold_timeframe": rule.threshold_timeframe,
            "configuration": rule.configuration,
            "created_at": rule.created_at.isoformat(),
            "updated_at": rule.updated_at.isoformat(),
            "created_by": rule.created_by,
            "updated_by": rule.updated_by,
            "metrics": rule_metrics
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting correlation rule {rule_id}: {e}")
        metrics.rules_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/")
@traced("rules_api_create_rule")
async def create_correlation_rule_endpoint(
    request: CreateRuleRequest,
    db: Session = Depends(get_db),
    rule_engine: RuleEngine = Depends(get_rule_engine)
):
    """Create a new correlation rule."""
    try:
        # Sanitize inputs
        name = sanitize_input(request.name, max_length=255)
        description = sanitize_input(request.description, max_length=1000) if request.description else None
        rule_dsl = sanitize_input(request.rule_dsl, max_length=10000)
        created_by = sanitize_input(request.created_by, max_length=255)
        
        # Validate rule DSL
        validation_result = rule_engine.validate_rule(rule_dsl)
        if not validation_result['valid']:
            raise HTTPException(
                status_code=400,
                detail=f"Invalid rule DSL: {validation_result['error']}"
            )
        
        # Check if rule name already exists
        existing_rule = db.query(CorrelationRule).filter(
            CorrelationRule.name == name
        ).first()
        
        if existing_rule:
            raise HTTPException(
                status_code=400,
                detail="Rule with this name already exists"
            )
        
        # Create rule
        rule = create_correlation_rule(
            name=name,
            rule_dsl=rule_dsl,
            rule_type=request.rule_type,
            time_window=request.time_window,
            description=description,
            configuration=request.configuration,
            created_by=created_by
        )
        
        # Set additional properties
        rule.max_events = request.max_events
        rule.priority = request.priority
        rule.threshold_count = request.threshold_count
        rule.threshold_timeframe = request.threshold_timeframe
        
        # Save to database
        db.add(rule)
        db.commit()
        db.refresh(rule)
        
        logger.info(f"Created correlation rule: {rule.name}")
        metrics.rules_api_created.inc()
        
        return {
            "id": str(rule.id),
            "name": rule.name,
            "description": rule.description,
            "rule_type": rule.rule_type,
            "status": rule.status,
            "priority": rule.priority,
            "time_window": rule.time_window,
            "created_at": rule.created_at.isoformat(),
            "created_by": rule.created_by,
            "validation_result": validation_result
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating correlation rule: {e}")
        metrics.rules_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/{rule_id}")
@traced("rules_api_update_rule")
async def update_correlation_rule(
    rule_id: UUID,
    request: UpdateRuleRequest,
    db: Session = Depends(get_db),
    rule_engine: RuleEngine = Depends(get_rule_engine)
):
    """Update a correlation rule."""
    try:
        rule = db.query(CorrelationRule).filter(
            CorrelationRule.id == rule_id
        ).first()
        
        if not rule:
            raise HTTPException(status_code=404, detail="Correlation rule not found")
        
        # Sanitize inputs
        updated_by = sanitize_input(request.updated_by, max_length=255)
        
        # Update fields
        if request.name is not None:
            name = sanitize_input(request.name, max_length=255)
            # Check if new name conflicts with existing rule
            existing_rule = db.query(CorrelationRule).filter(
                CorrelationRule.name == name,
                CorrelationRule.id != rule_id
            ).first()
            
            if existing_rule:
                raise HTTPException(
                    status_code=400,
                    detail="Rule with this name already exists"
                )
            
            rule.name = name
        
        if request.description is not None:
            rule.description = sanitize_input(request.description, max_length=1000)
        
        if request.rule_dsl is not None:
            rule_dsl = sanitize_input(request.rule_dsl, max_length=10000)
            
            # Validate rule DSL
            validation_result = rule_engine.validate_rule(rule_dsl)
            if not validation_result['valid']:
                raise HTTPException(
                    status_code=400,
                    detail=f"Invalid rule DSL: {validation_result['error']}"
                )
            
            rule.rule_dsl = rule_dsl
            
            # Clear rule cache to force recompilation
            rule_engine.clear_cache()
        
        if request.rule_type is not None:
            rule.rule_type = request.rule_type
        
        if request.time_window is not None:
            rule.time_window = request.time_window
        
        if request.max_events is not None:
            rule.max_events = request.max_events
        
        if request.priority is not None:
            rule.priority = request.priority
        
        if request.threshold_count is not None:
            rule.threshold_count = request.threshold_count
        
        if request.threshold_timeframe is not None:
            rule.threshold_timeframe = request.threshold_timeframe
        
        if request.configuration is not None:
            rule.configuration = request.configuration
        
        if request.status is not None:
            rule.status = request.status
        
        # Update metadata
        rule.updated_by = updated_by
        rule.updated_at = datetime.now()
        
        # Save changes
        db.commit()
        
        logger.info(f"Updated correlation rule: {rule.name}")
        metrics.rules_api_updated.inc()
        
        return {
            "id": str(rule.id),
            "name": rule.name,
            "description": rule.description,
            "rule_type": rule.rule_type,
            "status": rule.status,
            "priority": rule.priority,
            "time_window": rule.time_window,
            "updated_at": rule.updated_at.isoformat(),
            "updated_by": rule.updated_by
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating correlation rule: {e}")
        metrics.rules_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/{rule_id}")
@traced("rules_api_delete_rule")
async def delete_correlation_rule(
    rule_id: UUID,
    user_id: str = Query(..., description="User ID performing the deletion"),
    db: Session = Depends(get_db)
):
    """Delete a correlation rule."""
    try:
        # Sanitize input
        user_id = sanitize_input(user_id, max_length=255)
        
        rule = db.query(CorrelationRule).filter(
            CorrelationRule.id == rule_id
        ).first()
        
        if not rule:
            raise HTTPException(status_code=404, detail="Correlation rule not found")
        
        # Check if rule has active correlations
        from ..models.correlation import CorrelationState
        active_correlations = db.query(CorrelationState).filter(
            CorrelationState.rule_id == rule_id,
            CorrelationState.is_active == True
        ).count()
        
        if active_correlations > 0:
            raise HTTPException(
                status_code=400,
                detail=f"Cannot delete rule with {active_correlations} active correlations"
            )
        
        # Log deletion for audit
        logger.info(f"Deleting correlation rule {rule.name} by user {user_id}")
        
        # Delete rule
        db.delete(rule)
        db.commit()
        
        metrics.rules_api_deleted.inc()
        
        return {
            "message": "Correlation rule deleted successfully",
            "rule_id": str(rule_id),
            "rule_name": rule.name,
            "deleted_by": user_id,
            "deleted_at": datetime.now().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting correlation rule: {e}")
        metrics.rules_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/validate")
@traced("rules_api_validate_rule")
async def validate_correlation_rule(
    request: ValidateRuleRequest,
    rule_engine: RuleEngine = Depends(get_rule_engine)
):
    """Validate a correlation rule DSL."""
    try:
        # Sanitize input
        rule_dsl = sanitize_input(request.rule_dsl, max_length=10000)
        
        # Validate rule
        validation_result = rule_engine.validate_rule(rule_dsl)
        
        return {
            "valid": validation_result['valid'],
            "rule_dsl": rule_dsl,
            "rule_type": request.rule_type,
            "parsed_rule": validation_result.get('parsed_rule'),
            "error": validation_result.get('error')
        }
        
    except Exception as e:
        logger.error(f"Error validating correlation rule: {e}")
        metrics.rules_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/{rule_id}/metrics")
@traced("rules_api_get_rule_metrics")
async def get_rule_metrics(
    rule_id: UUID,
    days: int = Query(30, ge=1, le=365),
    db: Session = Depends(get_db)
):
    """Get performance metrics for a correlation rule."""
    try:
        rule = db.query(CorrelationRule).filter(
            CorrelationRule.id == rule_id
        ).first()
        
        if not rule:
            raise HTTPException(status_code=404, detail="Correlation rule not found")
        
        # Get metrics for the specified time period
        start_date = datetime.now() - timedelta(days=days)
        
        metrics_data = db.query(CorrelationMetrics).filter(
            CorrelationMetrics.rule_id == rule_id,
            CorrelationMetrics.period_start >= start_date
        ).order_by(CorrelationMetrics.period_start.desc()).all()
        
        # Aggregate metrics
        total_events = sum(m.events_processed for m in metrics_data)
        total_correlations = sum(m.correlations_found for m in metrics_data)
        total_false_positives = sum(m.false_positives for m in metrics_data)
        
        avg_processing_time = 0
        if metrics_data:
            avg_processing_time = sum(m.avg_processing_time for m in metrics_data) / len(metrics_data)
        
        max_processing_time = max((m.max_processing_time for m in metrics_data), default=0)
        
        # Calculate accuracy
        accuracy = 0
        if total_correlations > 0:
            accuracy = (total_correlations - total_false_positives) / total_correlations
        
        return {
            "rule_id": str(rule_id),
            "rule_name": rule.name,
            "time_period_days": days,
            "metrics": {
                "total_events_processed": total_events,
                "total_correlations_found": total_correlations,
                "total_false_positives": total_false_positives,
                "accuracy": round(accuracy, 4),
                "avg_processing_time_ms": round(avg_processing_time, 2),
                "max_processing_time_ms": max_processing_time
            },
            "daily_metrics": [
                {
                    "date": m.period_start.strftime("%Y-%m-%d"),
                    "events_processed": m.events_processed,
                    "correlations_found": m.correlations_found,
                    "false_positives": m.false_positives,
                    "avg_processing_time_ms": m.avg_processing_time,
                    "max_processing_time_ms": m.max_processing_time
                }
                for m in metrics_data
            ]
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting rule metrics: {e}")
        metrics.rules_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/{rule_id}/test")
@traced("rules_api_test_rule")
async def test_correlation_rule(
    rule_id: UUID,
    test_events: List[Dict[str, Any]],
    db: Session = Depends(get_db),
    rule_engine: RuleEngine = Depends(get_rule_engine)
):
    """Test a correlation rule against sample events."""
    try:
        rule = db.query(CorrelationRule).filter(
            CorrelationRule.id == rule_id
        ).first()
        
        if not rule:
            raise HTTPException(status_code=404, detail="Correlation rule not found")
        
        # Parse the rule
        parsed_rule = rule_engine.parse_rule(rule)
        
        # Test rule against events
        test_results = []
        for event_data in test_events:
            # Create a test event
            from ..models.correlation import CorrelationEvent, CorrelationState
            
            test_event = CorrelationEvent(
                rule_id=rule.id,
                event_id=event_data.get('id', 'test-event'),
                event_type=event_data.get('type', 'test'),
                event_data=event_data,
                correlation_key='test-key',
                event_timestamp=datetime.now()
            )
            
            # Create a test state
            test_state = CorrelationState(
                rule_id=rule.id,
                correlation_key='test-key',
                state_data={},
                expires_at=datetime.now() + timedelta(seconds=rule.time_window)
            )
            
            # Evaluate conditions
            conditions_met = rule_engine.evaluate_conditions(
                parsed_rule, test_event, test_state
            )
            
            test_results.append({
                "event_data": event_data,
                "conditions_met": conditions_met
            })
        
        return {
            "rule_id": str(rule_id),
            "rule_name": rule.name,
            "test_results": test_results,
            "parsed_rule": {
                "rule_type": parsed_rule.rule_type.value,
                "conditions_count": len(parsed_rule.conditions),
                "actions_count": len(parsed_rule.actions)
            }
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error testing correlation rule: {e}")
        metrics.rules_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")