"""
Metrics API - Prometheus metrics endpoints for correlation engine
"""

from datetime import datetime, timedelta
from typing import Dict, Any

from fastapi import APIRouter, Depends, Response
from fastapi.responses import PlainTextResponse

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

from ..services.correlation_engine import CorrelationEngine
from ..services.rule_engine import RuleEngine
from ..services.pattern_matcher import PatternMatcher
from ..models.correlation import CorrelationResult, CorrelationEvent, CorrelationState, get_db
from ..main import get_correlation_engine, get_rule_engine, get_pattern_matcher

logger = get_logger(__name__)
metrics = get_metrics()

router = APIRouter()


@router.get("/")
@traced("metrics_api_prometheus")
async def get_prometheus_metrics():
    """Get Prometheus metrics."""
    try:
        # This would typically return Prometheus formatted metrics
        # For now, we'll return a simple response
        metrics_text = """
# HELP correlation_engine_status Correlation engine status (1=running, 0=stopped)
# TYPE correlation_engine_status gauge
correlation_engine_status 1

# HELP correlation_engine_events_processed_total Total number of events processed
# TYPE correlation_engine_events_processed_total counter
correlation_engine_events_processed_total 0

# HELP correlation_engine_correlations_found_total Total number of correlations found
# TYPE correlation_engine_correlations_found_total counter
correlation_engine_correlations_found_total 0

# HELP correlation_engine_active_correlations Current number of active correlations
# TYPE correlation_engine_active_correlations gauge
correlation_engine_active_correlations 0

# HELP correlation_engine_processing_time_seconds Time spent processing events
# TYPE correlation_engine_processing_time_seconds histogram
correlation_engine_processing_time_seconds_bucket{le="0.1"} 0
correlation_engine_processing_time_seconds_bucket{le="0.5"} 0
correlation_engine_processing_time_seconds_bucket{le="1.0"} 0
correlation_engine_processing_time_seconds_bucket{le="5.0"} 0
correlation_engine_processing_time_seconds_bucket{le="+Inf"} 0
correlation_engine_processing_time_seconds_sum 0
correlation_engine_processing_time_seconds_count 0
"""
        
        return PlainTextResponse(content=metrics_text.strip())
        
    except Exception as e:
        logger.error(f"Error getting Prometheus metrics: {e}")
        return PlainTextResponse(
            content="# Error retrieving metrics",
            status_code=500
        )


@router.get("/json")
@traced("metrics_api_json")
async def get_json_metrics(
    correlation_engine: CorrelationEngine = Depends(get_correlation_engine),
    rule_engine: RuleEngine = Depends(get_rule_engine),
    pattern_matcher: PatternMatcher = Depends(get_pattern_matcher)
):
    """Get metrics in JSON format."""
    try:
        # Get component stats
        engine_stats = correlation_engine.get_stats()
        rule_stats = {
            "compiled_rules": len(rule_engine.get_compiled_rules())
        }
        pattern_stats = {
            "patterns_count": len(pattern_matcher.get_patterns()),
            "history_keys": len(pattern_matcher.event_history)
        }
        
        # Get database stats
        db_stats = {}
        try:
            with get_db() as db:
                # Count results by status
                results_by_status = {}
                for status in ["active", "acknowledged", "resolved", "false_positive"]:
                    count = db.query(CorrelationResult).filter(
                        CorrelationResult.status == status
                    ).count()
                    results_by_status[status] = count
                
                # Count events by status
                events_by_status = {}
                for status in ["pending", "processing", "correlated", "timeout", "error"]:
                    count = db.query(CorrelationEvent).filter(
                        CorrelationEvent.status == status
                    ).count()
                    events_by_status[status] = count
                
                # Count active states
                active_states = db.query(CorrelationState).filter(
                    CorrelationState.is_active == True,
                    CorrelationState.expires_at > datetime.now()
                ).count()
                
                db_stats = {
                    "results_by_status": results_by_status,
                    "events_by_status": events_by_status,
                    "active_states": active_states
                }
                
        except Exception as e:
            logger.error(f"Error getting database stats: {e}")
            db_stats = {"error": str(e)}
        
        return {
            "timestamp": datetime.now().isoformat(),
            "service": "correlation-engine",
            "version": "1.0.0",
            "uptime": "unknown",
            "components": {
                "correlation_engine": engine_stats,
                "rule_engine": rule_stats,
                "pattern_matcher": pattern_stats,
                "database": db_stats
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting JSON metrics: {e}")
        return {
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }


@router.get("/performance")
@traced("metrics_api_performance")
async def get_performance_metrics(
    correlation_engine: CorrelationEngine = Depends(get_correlation_engine)
):
    """Get performance metrics."""
    try:
        stats = correlation_engine.get_stats()
        
        # Calculate some derived metrics
        events_processed = stats.get('events_processed', 0)
        correlations_found = stats.get('correlations_found', 0)
        processing_errors = stats.get('processing_errors', 0)
        avg_processing_time = stats.get('avg_processing_time', 0.0)
        
        # Calculate rates and ratios
        correlation_rate = 0.0
        if events_processed > 0:
            correlation_rate = correlations_found / events_processed
        
        error_rate = 0.0
        if events_processed > 0:
            error_rate = processing_errors / events_processed
        
        success_rate = 1.0 - error_rate
        
        return {
            "timestamp": datetime.now().isoformat(),
            "performance_metrics": {
                "events_processed": events_processed,
                "correlations_found": correlations_found,
                "processing_errors": processing_errors,
                "correlation_rate": round(correlation_rate, 4),
                "error_rate": round(error_rate, 4),
                "success_rate": round(success_rate, 4),
                "avg_processing_time_ms": round(avg_processing_time * 1000, 2),
                "active_processing_tasks": stats.get('active_processing_tasks', 0),
                "queue_size": stats.get('queue_size', 0)
            },
            "engine_status": {
                "is_running": stats.get('is_running', False),
                "active_correlations": stats.get('active_correlations', 0)
            }
        }
        
    except Exception as e:
        logger.error(f"Error getting performance metrics: {e}")
        return {
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }


@router.get("/summary")
@traced("metrics_api_summary")
async def get_metrics_summary():
    """Get a summary of key metrics."""
    try:
        with get_db() as db:
            # Get counts for last 24 hours
            last_24h = datetime.now() - timedelta(hours=24)
            
            recent_results = db.query(CorrelationResult).filter(
                CorrelationResult.created_at >= last_24h
            ).count()
            
            recent_events = db.query(CorrelationEvent).filter(
                CorrelationEvent.processed_at >= last_24h
            ).count()
            
            # Get severity breakdown for recent results
            severity_counts = {}
            for severity in ["low", "medium", "high", "critical"]:
                count = db.query(CorrelationResult).filter(
                    CorrelationResult.created_at >= last_24h,
                    CorrelationResult.severity == severity
                ).count()
                severity_counts[severity] = count
            
            # Get current active states
            active_states = db.query(CorrelationState).filter(
                CorrelationState.is_active == True,
                CorrelationState.expires_at > datetime.now()
            ).count()
            
            return {
                "timestamp": datetime.now().isoformat(),
                "time_window": "24h",
                "summary": {
                    "recent_correlation_results": recent_results,
                    "recent_events_processed": recent_events,
                    "active_correlation_states": active_states,
                    "severity_breakdown": severity_counts
                }
            }
            
    except Exception as e:
        logger.error(f"Error getting metrics summary: {e}")
        return {
            "timestamp": datetime.now().isoformat(),
            "error": str(e)
        }