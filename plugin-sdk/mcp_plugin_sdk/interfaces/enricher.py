"""
Enricher plugin interface for threat intelligence and data enrichment.
"""

from abc import abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from .base import BasePlugin, PluginMetadata, PluginType


class EnrichmentType(str, Enum):
    """Types of enrichment data."""
    THREAT_INTEL = "threat_intel"
    GEOLOCATION = "geolocation"
    REPUTATION = "reputation"
    MALWARE_ANALYSIS = "malware_analysis"
    DOMAIN_INFO = "domain_info"
    IP_INFO = "ip_info"
    FILE_ANALYSIS = "file_analysis"
    URL_ANALYSIS = "url_analysis"
    CVE_INFO = "cve_info"
    MITRE_MAPPING = "mitre_mapping"


class ConfidenceLevel(str, Enum):
    """Confidence levels for enrichment data."""
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


class EnrichmentResult(BaseModel):
    """Result of data enrichment."""
    
    # Source information
    source_type: str = Field(..., description="Type of source data")
    source_value: str = Field(..., description="Original value being enriched")
    
    # Enrichment data
    enrichment_type: EnrichmentType = Field(..., description="Type of enrichment")
    enriched_data: Dict[str, Any] = Field(..., description="Enriched data")
    
    # Metadata
    confidence: ConfidenceLevel = Field(..., description="Confidence in the enrichment")
    source_name: str = Field(..., description="Name of the enrichment source")
    source_url: Optional[str] = Field(None, description="URL of the enrichment source")
    
    # Timestamps
    data_timestamp: Optional[datetime] = Field(None, description="Timestamp of the enriched data")
    enrichment_timestamp: datetime = Field(default_factory=datetime.now)
    
    # Threat intelligence specific
    threat_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="Threat score")
    threat_categories: List[str] = Field(default_factory=list, description="Threat categories")
    iocs: List[str] = Field(default_factory=list, description="Indicators of compromise")
    
    # Additional context
    tags: List[str] = Field(default_factory=list, description="Enrichment tags")
    references: List[str] = Field(default_factory=list, description="Reference URLs")
    
    class Config:
        use_enum_values = True


class EnrichmentRequest(BaseModel):
    """Request for data enrichment."""
    
    request_id: str = Field(..., description="Unique request identifier")
    data_type: str = Field(..., description="Type of data to enrich (ip, domain, hash, etc.)")
    data_value: str = Field(..., description="Value to enrich")
    
    # Enrichment parameters
    enrichment_types: List[EnrichmentType] = Field(default_factory=list, description="Types of enrichment requested")
    include_historical: bool = Field(False, description="Include historical data")
    max_age_days: Optional[int] = Field(None, description="Maximum age of data in days")
    
    # Context
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context")
    timeout: int = Field(30, description="Enrichment timeout in seconds")
    
    # Metadata
    source: str = Field("", description="Source of the enrichment request")
    priority: int = Field(50, description="Request priority (0-100)")
    timestamp: datetime = Field(default_factory=datetime.now)


class EnrichmentResponse(BaseModel):
    """Response from data enrichment."""
    
    request_id: str = Field(..., description="Original request identifier")
    status: str = Field(..., description="Enrichment status: success, partial, error, timeout")
    
    # Results
    enrichments: List[EnrichmentResult] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict, description="Enrichment summary")
    
    # Performance metrics
    enrichment_duration: float = Field(..., description="Enrichment duration in seconds")
    sources_queried: int = Field(0, description="Number of sources queried")
    cache_hits: int = Field(0, description="Number of cache hits")
    
    # Error information
    error_message: Optional[str] = Field(None, description="Error message if status is error")
    warnings: List[str] = Field(default_factory=list, description="Enrichment warnings")
    
    # Metadata
    enricher_version: str = Field("", description="Enricher version")
    completion_timestamp: datetime = Field(default_factory=datetime.now)


class EnricherPlugin(BasePlugin):
    """
    Base class for enricher plugins.
    
    Enricher plugins add threat intelligence and contextual information
    to security events and indicators.
    """
    
    def get_metadata(self) -> PluginMetadata:
        """Get enricher plugin metadata."""
        metadata = super().get_metadata() if hasattr(super(), 'get_metadata') else PluginMetadata(
            name=self.__class__.__name__,
            version="1.0.0",
            plugin_type=PluginType.ENRICHER,
            entry_point=f"{self.__class__.__module__}:{self.__class__.__name__}"
        )
        metadata.plugin_type = PluginType.ENRICHER
        return metadata
    
    @abstractmethod
    async def enrich(self, request: EnrichmentRequest) -> EnrichmentResponse:
        """
        Perform data enrichment.
        
        Args:
            request: Enrichment request with data to enrich
            
        Returns:
            EnrichmentResponse: Enrichment results
            
        Raises:
            PluginError: If enrichment fails
        """
        pass
    
    @abstractmethod
    def get_supported_data_types(self) -> List[str]:
        """
        Get list of supported data types.
        
        Returns:
            List of supported data types (e.g., 'ip', 'domain', 'hash', 'email')
        """
        pass
    
    @abstractmethod
    def get_enrichment_types(self) -> List[EnrichmentType]:
        """
        Get list of supported enrichment types.
        
        Returns:
            List of supported enrichment types
        """
        pass
    
    async def validate_request(self, request: EnrichmentRequest) -> bool:
        """
        Validate an enrichment request.
        
        Args:
            request: Enrichment request to validate
            
        Returns:
            True if request is valid, False otherwise
        """
        if not request.data_type:
            return False
            
        if request.data_type not in self.get_supported_data_types():
            return False
            
        if not request.data_value:
            return False
            
        return True
    
    async def get_enrichment_stats(self) -> Dict[str, Any]:
        """
        Get enrichment statistics.
        
        Returns:
            Dictionary with enrichment statistics
        """
        return {
            "total_enrichments": 0,
            "cache_hit_rate": 0.0,
            "average_enrichment_time": 0.0,
            "success_rate": 1.0,
            "supported_data_types": self.get_supported_data_types(),
            "enrichment_types": [t.value for t in self.get_enrichment_types()],
        }