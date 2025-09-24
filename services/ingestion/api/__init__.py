"""API endpoints for the ingestion service."""

from .ingestion import router as ingestion_router
from .health import router as health_router
from .metrics import router as metrics_router

__all__ = [
    "ingestion_router",
    "health_router", 
    "metrics_router",
]