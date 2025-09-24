"""
Scanner plugin interface for security scanning operations.
"""

from abc import abstractmethod
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

from .base import BasePlugin, PluginMetadata, PluginType


class ScanType(str, Enum):
    """Types of security scans."""
    VULNERABILITY = "vulnerability"
    MALWARE = "malware"
    NETWORK = "network"
    WEB_APPLICATION = "web_application"
    CONTAINER = "container"
    INFRASTRUCTURE = "infrastructure"
    COMPLIANCE = "compliance"
    SECRETS = "secrets"
    DEPENDENCIES = "dependencies"
    STATIC_CODE = "static_code"


class ScanStatus(str, Enum):
    """Scan execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class ScanResult(BaseModel):
    """Result of a security scan."""
    
    # Identification
    scan_id: str = Field(..., description="Unique scan identifier")
    target: str = Field(..., description="Scan target")
    scan_type: ScanType = Field(..., description="Type of scan performed")
    
    # Status and timing
    status: ScanStatus = Field(..., description="Scan status")
    start_time: datetime = Field(..., description="Scan start time")
    end_time: Optional[datetime] = Field(None, description="Scan end time")
    duration: Optional[float] = Field(None, description="Scan duration in seconds")
    
    # Results
    findings: List[Dict[str, Any]] = Field(default_factory=list, description="Scan findings")
    summary: Dict[str, Any] = Field(default_factory=dict, description="Scan summary")
    statistics: Dict[str, Any] = Field(default_factory=dict, description="Scan statistics")
    
    # Risk assessment
    risk_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="Overall risk score")
    risk_level: Optional[str] = Field(None, description="Risk level (low, medium, high, critical)")
    
    # Metadata
    scanner_name: str = Field(..., description="Name of the scanner")
    scanner_version: str = Field("", description="Scanner version")
    scan_config: Dict[str, Any] = Field(default_factory=dict, description="Scan configuration used")
    
    # Error information
    error_message: Optional[str] = Field(None, description="Error message if scan failed")
    warnings: List[str] = Field(default_factory=list, description="Scan warnings")
    
    # Output files/artifacts
    artifacts: List[str] = Field(default_factory=list, description="Output artifacts (file paths, URLs)")
    
    class Config:
        use_enum_values = True


class ScanRequest(BaseModel):
    """Request for security scanning."""
    
    request_id: str = Field(..., description="Unique request identifier")
    scan_type: ScanType = Field(..., description="Type of scan to perform")
    target: str = Field(..., description="Scan target (URL, IP, file path, etc.)")
    
    # Scan parameters
    scan_profile: str = Field("default", description="Scan profile (quick, standard, deep)")
    options: Dict[str, Any] = Field(default_factory=dict, description="Scanner-specific options")
    
    # Scope and filters
    include_patterns: List[str] = Field(default_factory=list, description="Patterns to include")
    exclude_patterns: List[str] = Field(default_factory=list, description="Patterns to exclude")
    max_depth: Optional[int] = Field(None, description="Maximum scan depth")
    
    # Resource limits
    timeout: int = Field(3600, description="Scan timeout in seconds")
    max_memory_mb: Optional[int] = Field(None, description="Maximum memory usage in MB")
    max_cpu_percent: Optional[int] = Field(None, description="Maximum CPU usage percentage")
    
    # Authentication and credentials
    credentials: Dict[str, Any] = Field(default_factory=dict, description="Authentication credentials")
    headers: Dict[str, str] = Field(default_factory=dict, description="HTTP headers for web scans")
    
    # Output configuration
    output_format: str = Field("json", description="Output format")
    save_artifacts: bool = Field(False, description="Save scan artifacts")
    
    # Context
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context")
    priority: int = Field(50, description="Request priority (0-100)")
    
    # Metadata
    source: str = Field("", description="Source of the scan request")
    timestamp: datetime = Field(default_factory=datetime.now)


class ScanResponse(BaseModel):
    """Response from security scanning."""
    
    request_id: str = Field(..., description="Original request identifier")
    scan_id: str = Field(..., description="Unique scan identifier")
    
    # Status
    status: ScanStatus = Field(..., description="Scan status")
    progress: float = Field(0.0, ge=0.0, le=100.0, description="Scan progress percentage")
    
    # Results (may be partial for running scans)
    result: Optional[ScanResult] = Field(None, description="Scan result")
    
    # Real-time information
    current_activity: str = Field("", description="Current scan activity")
    estimated_completion: Optional[datetime] = Field(None, description="Estimated completion time")
    
    # Metadata
    response_timestamp: datetime = Field(default_factory=datetime.now)


class ScannerPlugin(BasePlugin):
    """
    Base class for scanner plugins.
    
    Scanner plugins perform various types of security scans including
    vulnerability scanning, malware detection, and compliance checking.
    """
    
    def get_metadata(self) -> PluginMetadata:
        """Get scanner plugin metadata."""
        metadata = super().get_metadata() if hasattr(super(), 'get_metadata') else PluginMetadata(
            name=self.__class__.__name__,
            version="1.0.0",
            plugin_type=PluginType.SCANNER,
            entry_point=f"{self.__class__.__module__}:{self.__class__.__name__}"
        )
        metadata.plugin_type = PluginType.SCANNER
        return metadata
    
    @abstractmethod
    async def start_scan(self, request: ScanRequest) -> ScanResponse:
        """
        Start a security scan.
        
        Args:
            request: Scan request with target and parameters
            
        Returns:
            ScanResponse: Initial scan response with scan ID
            
        Raises:
            PluginError: If scan startup fails
        """
        pass
    
    @abstractmethod
    async def get_scan_status(self, scan_id: str) -> ScanResponse:
        """
        Get the status of a running scan.
        
        Args:
            scan_id: Unique scan identifier
            
        Returns:
            ScanResponse: Current scan status and progress
            
        Raises:
            PluginError: If scan ID is not found
        """
        pass
    
    @abstractmethod
    async def cancel_scan(self, scan_id: str) -> bool:
        """
        Cancel a running scan.
        
        Args:
            scan_id: Unique scan identifier
            
        Returns:
            True if scan was cancelled successfully
            
        Raises:
            PluginError: If scan cancellation fails
        """
        pass
    
    @abstractmethod
    def get_supported_scan_types(self) -> List[ScanType]:
        """
        Get list of supported scan types.
        
        Returns:
            List of supported scan types
        """
        pass
    
    @abstractmethod
    def get_scan_profiles(self) -> Dict[str, Any]:
        """
        Get available scan profiles.
        
        Returns:
            Dictionary of scan profiles with their descriptions and parameters
        """
        pass
    
    async def validate_request(self, request: ScanRequest) -> bool:
        """
        Validate a scan request.
        
        Args:
            request: Scan request to validate
            
        Returns:
            True if request is valid, False otherwise
        """
        if not request.target:
            return False
            
        if request.scan_type not in self.get_supported_scan_types():
            return False
            
        if request.scan_profile not in self.get_scan_profiles():
            return False
            
        return True
    
    async def get_scanner_stats(self) -> Dict[str, Any]:
        """
        Get scanner statistics.
        
        Returns:
            Dictionary with scanner statistics
        """
        return {
            "total_scans": 0,
            "active_scans": 0,
            "completed_scans": 0,
            "failed_scans": 0,
            "average_scan_time": 0.0,
            "supported_scan_types": [t.value for t in self.get_supported_scan_types()],
            "scan_profiles": list(self.get_scan_profiles().keys()),
        }