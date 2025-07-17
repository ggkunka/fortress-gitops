"""Enrichment data schemas."""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from enum import Enum
from uuid import UUID

from pydantic import BaseModel, Field, validator


class EnrichmentStatus(str, Enum):
    """Enrichment status enumeration."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class EnrichmentType(str, Enum):
    """Enrichment type enumeration."""
    THREAT_INTELLIGENCE = "threat_intelligence"
    MITRE_ATTACK = "mitre_attack"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    BEHAVIORAL_ANALYSIS = "behavioral_analysis"
    CONTEXTUAL_ANALYSIS = "contextual_analysis"
    RISK_ASSESSMENT = "risk_assessment"


class DataType(str, Enum):
    """Data type enumeration."""
    SBOM = "sbom"
    CVE = "cve"
    RUNTIME = "runtime"
    THREAT = "threat"
    INDICATOR = "indicator"


class EnrichmentRequest(BaseModel):
    """Enrichment request schema."""
    
    request_id: str = Field(..., description="Unique request identifier")
    data_type: DataType = Field(..., description="Type of data to enrich")
    data: Dict[str, Any] = Field(..., description="Data to be enriched")
    enrichment_types: List[EnrichmentType] = Field(
        default_factory=list,
        description="Types of enrichment to perform"
    )
    source_service: str = Field(..., description="Service that originated the request")
    correlation_id: Optional[str] = Field(None, description="Correlation ID for tracing")
    priority: int = Field(default=5, ge=1, le=10, description="Processing priority (1-10)")
    timeout_seconds: int = Field(default=300, ge=1, le=3600, description="Processing timeout")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    @validator('enrichment_types')
    def validate_enrichment_types(cls, v):
        """Validate enrichment types."""
        if not v:
            return [EnrichmentType.THREAT_INTELLIGENCE, EnrichmentType.MITRE_ATTACK]
        return v
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "request_id": "enrich_123",
                "data_type": "sbom",
                "data": {
                    "components": [
                        {
                            "name": "apache-log4j",
                            "version": "2.14.1",
                            "cpe": "cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*"
                        }
                    ]
                },
                "enrichment_types": ["threat_intelligence", "mitre_attack"],
                "source_service": "ingestion",
                "correlation_id": "trace_456",
                "priority": 7,
                "timeout_seconds": 300
            }
        }


class EnrichmentResult(BaseModel):
    """Single enrichment result."""
    
    enrichment_type: EnrichmentType = Field(..., description="Type of enrichment")
    status: EnrichmentStatus = Field(..., description="Result status")
    data: Dict[str, Any] = Field(default_factory=dict, description="Enriched data")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score")
    sources: List[str] = Field(default_factory=list, description="Data sources used")
    processing_time: float = Field(ge=0.0, description="Processing time in seconds")
    errors: List[str] = Field(default_factory=list, description="Any errors encountered")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "enrichment_type": "threat_intelligence",
                "status": "completed",
                "data": {
                    "threat_level": "high",
                    "indicators": ["malicious_domain.com"],
                    "malware_families": ["log4shell"]
                },
                "confidence": 0.95,
                "sources": ["misp", "virustotal", "otx"],
                "processing_time": 2.5,
                "errors": []
            }
        }


class EnrichmentResponse(BaseModel):
    """Enrichment response schema."""
    
    request_id: str = Field(..., description="Original request identifier")
    status: EnrichmentStatus = Field(..., description="Overall enrichment status")
    data_type: DataType = Field(..., description="Type of data enriched")
    original_data: Dict[str, Any] = Field(..., description="Original data")
    enriched_data: Dict[str, Any] = Field(..., description="Enriched data")
    results: List[EnrichmentResult] = Field(
        default_factory=list,
        description="Individual enrichment results"
    )
    total_processing_time: float = Field(ge=0.0, description="Total processing time")
    started_at: datetime = Field(..., description="Processing start time")
    completed_at: Optional[datetime] = Field(None, description="Processing completion time")
    correlation_id: Optional[str] = Field(None, description="Correlation ID for tracing")
    errors: List[str] = Field(default_factory=list, description="Any errors encountered")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    @validator('completed_at')
    def validate_completed_at(cls, v, values):
        """Validate completion time."""
        if v and 'started_at' in values and v < values['started_at']:
            raise ValueError('Completion time must be after start time')
        return v
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "request_id": "enrich_123",
                "status": "completed",
                "data_type": "sbom",
                "original_data": {
                    "components": [{"name": "apache-log4j", "version": "2.14.1"}]
                },
                "enriched_data": {
                    "components": [
                        {
                            "name": "apache-log4j",
                            "version": "2.14.1",
                            "threat_level": "high",
                            "vulnerabilities": ["CVE-2021-44228"],
                            "mitre_techniques": ["T1210", "T1190"]
                        }
                    ]
                },
                "results": [
                    {
                        "enrichment_type": "threat_intelligence",
                        "status": "completed",
                        "confidence": 0.95,
                        "processing_time": 2.5
                    }
                ],
                "total_processing_time": 5.2,
                "started_at": "2023-01-01T12:00:00Z",
                "completed_at": "2023-01-01T12:00:05Z"
            }
        }


class EnrichmentTask(BaseModel):
    """Enrichment task for processing queue."""
    
    task_id: str = Field(..., description="Unique task identifier")
    request: EnrichmentRequest = Field(..., description="Enrichment request")
    status: EnrichmentStatus = Field(default=EnrichmentStatus.PENDING, description="Task status")
    assigned_worker: Optional[str] = Field(None, description="Worker assigned to task")
    retry_count: int = Field(default=0, ge=0, description="Number of retry attempts")
    max_retries: int = Field(default=3, ge=0, description="Maximum retry attempts")
    created_at: datetime = Field(default_factory=datetime.utcnow, description="Task creation time")
    started_at: Optional[datetime] = Field(None, description="Task start time")
    completed_at: Optional[datetime] = Field(None, description="Task completion time")
    expires_at: Optional[datetime] = Field(None, description="Task expiration time")
    result: Optional[EnrichmentResponse] = Field(None, description="Task result")
    error: Optional[str] = Field(None, description="Error message if failed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    
    @validator('max_retries')
    def validate_max_retries(cls, v):
        """Validate max retries."""
        if v < 0:
            raise ValueError('Max retries must be non-negative')
        return v
    
    @validator('retry_count')
    def validate_retry_count(cls, v, values):
        """Validate retry count."""
        if v < 0:
            raise ValueError('Retry count must be non-negative')
        if 'max_retries' in values and v > values['max_retries']:
            raise ValueError('Retry count cannot exceed max retries')
        return v
    
    def can_retry(self) -> bool:
        """Check if task can be retried."""
        return self.retry_count < self.max_retries
    
    def is_expired(self) -> bool:
        """Check if task has expired."""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "task_id": "task_789",
                "request": {
                    "request_id": "enrich_123",
                    "data_type": "sbom",
                    "data": {"components": []},
                    "enrichment_types": ["threat_intelligence"],
                    "source_service": "ingestion"
                },
                "status": "pending",
                "retry_count": 0,
                "max_retries": 3,
                "created_at": "2023-01-01T12:00:00Z"
            }
        }


class EnrichmentStats(BaseModel):
    """Enrichment statistics schema."""
    
    total_requests: int = Field(ge=0, description="Total enrichment requests")
    completed_requests: int = Field(ge=0, description="Completed enrichment requests")
    failed_requests: int = Field(ge=0, description="Failed enrichment requests")
    pending_requests: int = Field(ge=0, description="Pending enrichment requests")
    processing_requests: int = Field(ge=0, description="Currently processing requests")
    average_processing_time: float = Field(ge=0.0, description="Average processing time")
    success_rate: float = Field(ge=0.0, le=1.0, description="Success rate")
    enrichment_type_stats: Dict[str, int] = Field(
        default_factory=dict,
        description="Statistics by enrichment type"
    )
    data_type_stats: Dict[str, int] = Field(
        default_factory=dict,
        description="Statistics by data type"
    )
    source_service_stats: Dict[str, int] = Field(
        default_factory=dict,
        description="Statistics by source service"
    )
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Statistics timestamp")
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "total_requests": 1000,
                "completed_requests": 850,
                "failed_requests": 50,
                "pending_requests": 75,
                "processing_requests": 25,
                "average_processing_time": 5.2,
                "success_rate": 0.85,
                "enrichment_type_stats": {
                    "threat_intelligence": 500,
                    "mitre_attack": 300
                },
                "data_type_stats": {
                    "sbom": 400,
                    "cve": 300,
                    "runtime": 200
                },
                "timestamp": "2023-01-01T12:00:00Z"
            }
        }


class EnrichmentConfig(BaseModel):
    """Enrichment configuration schema."""
    
    max_concurrent_tasks: int = Field(default=10, ge=1, description="Maximum concurrent tasks")
    default_timeout: int = Field(default=300, ge=1, description="Default timeout in seconds")
    max_retries: int = Field(default=3, ge=0, description="Maximum retry attempts")
    retry_delay: float = Field(default=1.0, ge=0.0, description="Retry delay in seconds")
    cleanup_interval: int = Field(default=3600, ge=1, description="Cleanup interval in seconds")
    threat_intelligence_sources: List[str] = Field(
        default_factory=list,
        description="Threat intelligence sources"
    )
    mitre_attack_sources: List[str] = Field(
        default_factory=list,
        description="MITRE ATT&CK sources"
    )
    cache_ttl: int = Field(default=3600, ge=0, description="Cache TTL in seconds")
    enable_caching: bool = Field(default=True, description="Enable caching")
    enable_metrics: bool = Field(default=True, description="Enable metrics collection")
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "max_concurrent_tasks": 10,
                "default_timeout": 300,
                "max_retries": 3,
                "retry_delay": 1.0,
                "cleanup_interval": 3600,
                "threat_intelligence_sources": ["misp", "virustotal", "otx"],
                "mitre_attack_sources": ["cti", "enterprise"],
                "cache_ttl": 3600,
                "enable_caching": True,
                "enable_metrics": True
            }
        }