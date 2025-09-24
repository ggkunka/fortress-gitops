"""
Health API - Health check endpoints for correlation engine
"""

from datetime import datetime
from typing import Dict, Any

from fastapi import APIRouter, Depends
from fastapi.responses import JSONResponse

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

from ..services.correlation_engine import CorrelationEngine
from ..services.rule_engine import RuleEngine
from ..services.pattern_matcher import PatternMatcher
from ..main import get_correlation_engine, get_rule_engine, get_pattern_matcher

logger = get_logger(__name__)
metrics = get_metrics()

router = APIRouter()


@router.get("/")
@traced("health_api_root")
async def health_check():
    """Basic health check."""
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "service": "correlation-engine",
        "version": "1.0.0"
    }


@router.get("/ready")
@traced("health_api_ready")
async def readiness_check(
    correlation_engine: CorrelationEngine = Depends(get_correlation_engine),
    rule_engine: RuleEngine = Depends(get_rule_engine),
    pattern_matcher: PatternMatcher = Depends(get_pattern_matcher)
):
    """Readiness check with component status."""
    try:
        # Check correlation engine status
        engine_stats = correlation_engine.get_stats()
        engine_ready = engine_stats.get('is_running', False)
        
        # Check rule engine status
        rule_stats = len(rule_engine.get_compiled_rules())
        
        # Check pattern matcher status
        pattern_stats = len(pattern_matcher.get_patterns())
        
        ready = engine_ready
        
        response = {
            "status": "ready" if ready else "not_ready",
            "timestamp": datetime.now().isoformat(),
            "components": {
                "correlation_engine": {
                    "status": "ready" if engine_ready else "not_ready",
                    "stats": engine_stats
                },
                "rule_engine": {
                    "status": "ready",
                    "compiled_rules": rule_stats
                },
                "pattern_matcher": {
                    "status": "ready",
                    "patterns_loaded": pattern_stats
                }
            }
        }
        
        status_code = 200 if ready else 503
        return JSONResponse(content=response, status_code=status_code)
        
    except Exception as e:
        logger.error(f"Error in readiness check: {e}")
        return JSONResponse(
            content={
                "status": "not_ready",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            },
            status_code=503
        )


@router.get("/live")
@traced("health_api_live")
async def liveness_check():
    """Liveness check - basic service availability."""
    return {
        "status": "alive",
        "timestamp": datetime.now().isoformat(),
        "uptime": "unknown"  # Could track actual uptime
    }


@router.get("/detailed")
@traced("health_api_detailed")
async def detailed_health_check(
    correlation_engine: CorrelationEngine = Depends(get_correlation_engine),
    rule_engine: RuleEngine = Depends(get_rule_engine),
    pattern_matcher: PatternMatcher = Depends(get_pattern_matcher)
):
    """Detailed health check with comprehensive status."""
    try:
        # Database health
        db_healthy = True
        try:
            from ..models.correlation import get_db
            with get_db() as db:
                # Simple query to test database connectivity
                db.execute("SELECT 1")
        except Exception as e:
            logger.error(f"Database health check failed: {e}")
            db_healthy = False
        
        # Component stats
        engine_stats = correlation_engine.get_stats()
        rule_stats = {
            "compiled_rules": len(rule_engine.get_compiled_rules())
        }
        pattern_stats = {
            "patterns_count": len(pattern_matcher.get_patterns()),
            "history_keys": len(pattern_matcher.event_history)
        }
        
        overall_healthy = (
            engine_stats.get('is_running', False) and
            db_healthy
        )
        
        response = {
            "status": "healthy" if overall_healthy else "unhealthy",
            "timestamp": datetime.now().isoformat(),
            "service": "correlation-engine",
            "version": "1.0.0",
            "components": {
                "database": {
                    "status": "healthy" if db_healthy else "unhealthy"
                },
                "correlation_engine": {
                    "status": "healthy" if engine_stats.get('is_running', False) else "unhealthy",
                    "stats": engine_stats
                },
                "rule_engine": {
                    "status": "healthy",
                    "stats": rule_stats
                },
                "pattern_matcher": {
                    "status": "healthy",
                    "stats": pattern_stats
                }
            }
        }
        
        status_code = 200 if overall_healthy else 503
        return JSONResponse(content=response, status_code=status_code)
        
    except Exception as e:
        logger.error(f"Error in detailed health check: {e}")
        return JSONResponse(
            content={
                "status": "error",
                "timestamp": datetime.now().isoformat(),
                "error": str(e)
            },
            status_code=500
        )