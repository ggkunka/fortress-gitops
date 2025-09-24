"""Event schemas for enrichment service."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from .enrichment import EnrichmentResponse, EnrichmentStatus, DataType
from .threat_intelligence import ThreatIntelligence
from .mitre_attack import MitreAttack


class EnrichmentEvent(BaseModel):
    """Base enrichment event schema."""
    
    event_id: str = Field(..., description="Unique event identifier")
    request_id: str = Field(..., description="Original enrichment request ID")
    event_type: str = Field(..., description="Type of enrichment event")
    data_type: DataType = Field(..., description="Type of data being enriched")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Event timestamp")
    source_service: str = Field(default="enrichment", description="Source service")
    correlation_id: Optional[str] = Field(None, description="Correlation ID for tracing")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "event_id": "event_123",
                "request_id": "enrich_123",
                "event_type": "enrichment.started",
                "data_type": "sbom",
                "timestamp": "2023-01-01T12:00:00Z",
                "source_service": "enrichment",
                "correlation_id": "trace_456",
                "metadata": {
                    "enrichment_types": ["threat_intelligence", "mitre_attack"]
                }
            }
        }


class EnrichmentStartedEvent(EnrichmentEvent):
    """Enrichment started event schema."""
    
    event_type: str = Field(default="enrichment.started", description="Event type")
    enrichment_types: List[str] = Field(
        default_factory=list,
        description="Types of enrichment being performed"
    )
    priority: int = Field(default=5, description="Processing priority")
    timeout_seconds: int = Field(default=300, description="Processing timeout")
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "event_id": "event_123",
                "request_id": "enrich_123",
                "event_type": "enrichment.started",
                "data_type": "sbom",
                "timestamp": "2023-01-01T12:00:00Z",
                "enrichment_types": ["threat_intelligence", "mitre_attack"],
                "priority": 7,
                "timeout_seconds": 300
            }
        }


class EnrichmentCompletedEvent(EnrichmentEvent):
    """Enrichment completed event schema."""
    
    event_type: str = Field(default="enrichment.completed", description="Event type")
    status: EnrichmentStatus = Field(default=EnrichmentStatus.COMPLETED, description="Final status")
    processing_time: float = Field(ge=0.0, description="Total processing time in seconds")
    enrichment_response: EnrichmentResponse = Field(..., description="Enrichment response")
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "event_id": "event_123",
                "request_id": "enrich_123",
                "event_type": "enrichment.completed",
                "data_type": "sbom",
                "timestamp": "2023-01-01T12:00:05Z",
                "status": "completed",
                "processing_time": 5.2,
                "enrichment_response": {
                    "request_id": "enrich_123",
                    "status": "completed",
                    "data_type": "sbom",
                    "original_data": {},
                    "enriched_data": {},
                    "results": [],
                    "total_processing_time": 5.2
                }
            }
        }


class EnrichmentFailedEvent(EnrichmentEvent):
    """Enrichment failed event schema."""
    
    event_type: str = Field(default="enrichment.failed", description="Event type")
    status: EnrichmentStatus = Field(default=EnrichmentStatus.FAILED, description="Final status")
    error_type: str = Field(..., description="Type of error")
    error_message: str = Field(..., description="Error message")
    processing_time: float = Field(ge=0.0, description="Processing time before failure")
    retry_count: int = Field(default=0, description="Number of retry attempts")
    is_retryable: bool = Field(default=False, description="Whether error is retryable")
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "event_id": "event_123",
                "request_id": "enrich_123",
                "event_type": "enrichment.failed",
                "data_type": "sbom",
                "timestamp": "2023-01-01T12:00:03Z",
                "status": "failed",
                "error_type": "timeout",
                "error_message": "Enrichment processing timeout",
                "processing_time": 3.0,
                "retry_count": 1,
                "is_retryable": True
            }
        }


class ThreatIntelligenceEvent(EnrichmentEvent):
    """Threat intelligence enrichment event schema."""
    
    event_type: str = Field(default="threat_intelligence.enriched", description="Event type")
    threat_intelligence: ThreatIntelligence = Field(..., description="Threat intelligence data")
    sources_used: List[str] = Field(default_factory=list, description="Intelligence sources used")
    processing_time: float = Field(ge=0.0, description="Processing time in seconds")
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "event_id": "event_123",
                "request_id": "enrich_123",
                "event_type": "threat_intelligence.enriched",
                "data_type": "sbom",
                "timestamp": "2023-01-01T12:00:03Z",
                "threat_intelligence": {
                    "intelligence_id": "ti_123",
                    "data_type": "sbom",
                    "threat_level": "high",
                    "confidence": 0.85,
                    "sources": ["misp", "virustotal"],
                    "indicators": [],
                    "threat_actors": [],
                    "malware": [],
                    "risk_score": 8.5
                },
                "sources_used": ["misp", "virustotal", "otx"],
                "processing_time": 2.5
            }
        }


class MitreAttackEvent(EnrichmentEvent):
    """MITRE ATT&CK mapping event schema."""
    
    event_type: str = Field(default="mitre_attack.mapped", description="Event type")
    mitre_attack: MitreAttack = Field(..., description="MITRE ATT&CK mapping data")
    techniques_mapped: List[str] = Field(
        default_factory=list,
        description="Mapped technique IDs"
    )
    tactics_mapped: List[str] = Field(
        default_factory=list,
        description="Mapped tactic IDs"
    )
    processing_time: float = Field(ge=0.0, description="Processing time in seconds")
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "event_id": "event_123",
                "request_id": "enrich_123",
                "event_type": "mitre_attack.mapped",
                "data_type": "cve",
                "timestamp": "2023-01-01T12:00:04Z",
                "mitre_attack": {
                    "mapping_id": "mitre_123",
                    "data_type": "cve",
                    "framework_version": "v13.1",
                    "confidence": 0.85,
                    "tactics": [],
                    "techniques": [],
                    "sub_techniques": [],
                    "mitigations": [],
                    "risk_score": 7.5
                },
                "techniques_mapped": ["T1566", "T1190"],
                "tactics_mapped": ["TA0001"],
                "processing_time": 1.8
            }
        }


class EnrichmentProgressEvent(EnrichmentEvent):
    """Enrichment progress event schema."""
    
    event_type: str = Field(default="enrichment.progress", description="Event type")
    current_step: str = Field(..., description="Current processing step")
    total_steps: int = Field(ge=1, description="Total number of steps")
    completed_steps: int = Field(ge=0, description="Number of completed steps")
    progress_percentage: float = Field(ge=0.0, le=100.0, description="Progress percentage")
    estimated_remaining_time: Optional[float] = Field(
        None,
        ge=0.0,
        description="Estimated remaining time in seconds"
    )
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "event_id": "event_123",
                "request_id": "enrich_123",
                "event_type": "enrichment.progress",
                "data_type": "sbom",
                "timestamp": "2023-01-01T12:00:02Z",
                "current_step": "threat_intelligence_lookup",
                "total_steps": 4,
                "completed_steps": 2,
                "progress_percentage": 50.0,
                "estimated_remaining_time": 2.5
            }
        }


class EnrichmentCancelledEvent(EnrichmentEvent):
    """Enrichment cancelled event schema."""
    
    event_type: str = Field(default="enrichment.cancelled", description="Event type")
    status: EnrichmentStatus = Field(default=EnrichmentStatus.CANCELLED, description="Final status")
    reason: str = Field(..., description="Cancellation reason")
    processing_time: float = Field(ge=0.0, description="Processing time before cancellation")
    partial_results: Optional[Dict[str, Any]] = Field(
        None,
        description="Partial results if any"
    )
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "event_id": "event_123",
                "request_id": "enrich_123",
                "event_type": "enrichment.cancelled",
                "data_type": "sbom",
                "timestamp": "2023-01-01T12:00:02Z",
                "status": "cancelled",
                "reason": "user_cancellation",
                "processing_time": 2.0,
                "partial_results": {
                    "threat_intelligence": {
                        "status": "completed"
                    },
                    "mitre_attack": {
                        "status": "cancelled"
                    }
                }
            }
        }


class EnrichmentTimeoutEvent(EnrichmentEvent):
    """Enrichment timeout event schema."""
    
    event_type: str = Field(default="enrichment.timeout", description="Event type")
    status: EnrichmentStatus = Field(default=EnrichmentStatus.FAILED, description="Final status")
    timeout_seconds: int = Field(ge=1, description="Configured timeout")
    processing_time: float = Field(ge=0.0, description="Actual processing time")
    partial_results: Optional[Dict[str, Any]] = Field(
        None,
        description="Partial results if any"
    )
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "event_id": "event_123",
                "request_id": "enrich_123",
                "event_type": "enrichment.timeout",
                "data_type": "sbom",
                "timestamp": "2023-01-01T12:05:00Z",
                "status": "failed",
                "timeout_seconds": 300,
                "processing_time": 300.0,
                "partial_results": {
                    "threat_intelligence": {
                        "status": "completed"
                    },
                    "mitre_attack": {
                        "status": "timeout"
                    }
                }
            }
        }


class EnrichmentRetryEvent(EnrichmentEvent):
    """Enrichment retry event schema."""
    
    event_type: str = Field(default="enrichment.retry", description="Event type")
    retry_count: int = Field(ge=1, description="Current retry attempt")
    max_retries: int = Field(ge=1, description="Maximum retry attempts")
    previous_error: str = Field(..., description="Previous error message")
    retry_delay: float = Field(ge=0.0, description="Retry delay in seconds")
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "event_id": "event_123",
                "request_id": "enrich_123",
                "event_type": "enrichment.retry",
                "data_type": "sbom",
                "timestamp": "2023-01-01T12:00:06Z",
                "retry_count": 2,
                "max_retries": 3,
                "previous_error": "Connection timeout to threat intelligence service",
                "retry_delay": 2.0
            }
        }