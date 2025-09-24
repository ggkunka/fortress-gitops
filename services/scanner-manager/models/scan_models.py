"""
Scan Models

Data models for scanning operations and results.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union
from uuid import UUID

from pydantic import BaseModel, Field, validator


class ScanStatus(str, Enum):
    """Scan execution status."""
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class ScannerType(str, Enum):
    """Supported scanner types."""
    TRIVY = "trivy"
    GRYPE = "grype"
    SYFT = "syft"
    OSV = "osv"
    CLAIR = "clair"
    SNYK = "snyk"
    CUSTOM = "custom"


class TargetType(str, Enum):
    """Target types for scanning."""
    CONTAINER_IMAGE = "container_image"
    FILESYSTEM = "filesystem"
    REPOSITORY = "repository"
    ARTIFACT = "artifact"
    RUNTIME = "runtime"


class SeverityLevel(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"
    UNKNOWN = "unknown"


class PluginState(str, Enum):
    """Plugin state enumeration."""
    AVAILABLE = "available"
    ENABLED = "enabled"
    DISABLED = "disabled"
    ERROR = "error"
    LOADING = "loading"


class Priority(str, Enum):
    """Scan priority levels."""
    LOW = "low"
    NORMAL = "normal"
    HIGH = "high"
    URGENT = "urgent"


class ScanRequest(BaseModel):
    """Request model for creating a scan."""
    target: str = Field(..., description="Target to scan (image, path, etc.)")
    target_type: TargetType = Field(default=TargetType.CONTAINER_IMAGE, description="Type of target")
    scanners: List[ScannerType] = Field(default=[ScannerType.GRYPE], description="Scanners to use")
    priority: Priority = Field(default=Priority.NORMAL, description="Scan priority")
    timeout: int = Field(default=300, description="Timeout in seconds")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    options: Dict[str, Any] = Field(default_factory=dict, description="Scanner-specific options")
    tags: List[str] = Field(default_factory=list, description="Tags for categorization")
    
    @validator('timeout')
    def validate_timeout(cls, v):
        if v <= 0 or v > 3600:  # Max 1 hour
            raise ValueError('Timeout must be between 1 and 3600 seconds')
        return v
    
    @validator('scanners')
    def validate_scanners(cls, v):
        if not v:
            raise ValueError('At least one scanner must be specified')
        return v


class ScanResponse(BaseModel):
    """Response model for scan creation."""
    scan_id: str = Field(..., description="Unique scan identifier")
    status: ScanStatus = Field(..., description="Current scan status")
    message: str = Field(..., description="Status message")
    created_at: datetime = Field(..., description="Creation timestamp")
    estimated_duration: Optional[int] = Field(None, description="Estimated duration in seconds")


class VulnerabilityFinding(BaseModel):
    """Individual vulnerability finding."""
    id: str = Field(..., description="Vulnerability ID (CVE, etc.)")
    severity: SeverityLevel = Field(..., description="Vulnerability severity")
    title: str = Field(..., description="Vulnerability title")
    description: str = Field(..., description="Detailed description")
    package_name: str = Field(..., description="Affected package name")
    package_version: str = Field(..., description="Affected package version")
    fixed_version: Optional[str] = Field(None, description="Version with fix")
    cvss_score: Optional[float] = Field(None, description="CVSS score")
    cvss_vector: Optional[str] = Field(None, description="CVSS vector")
    references: List[str] = Field(default_factory=list, description="Reference URLs")
    scanner: ScannerType = Field(..., description="Scanner that found this vulnerability")
    confidence: Optional[float] = Field(None, description="Confidence score")


class ScannerResult(BaseModel):
    """Results from a single scanner."""
    scanner: ScannerType = Field(..., description="Scanner that generated this result")
    status: ScanStatus = Field(..., description="Scanner execution status")
    started_at: datetime = Field(..., description="Scanner start time")
    completed_at: Optional[datetime] = Field(None, description="Scanner completion time")
    duration: Optional[float] = Field(None, description="Duration in seconds")
    vulnerabilities: List[VulnerabilityFinding] = Field(default_factory=list, description="Found vulnerabilities")
    summary: Dict[str, Any] = Field(default_factory=dict, description="Scanner summary")
    raw_output: Optional[Dict[str, Any]] = Field(None, description="Raw scanner output")
    error_message: Optional[str] = Field(None, description="Error message if failed")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")


class ScanResult(BaseModel):
    """Complete scan result with all scanner outputs."""
    scan_id: str = Field(..., description="Unique scan identifier")
    target: str = Field(..., description="Scanned target")
    target_type: TargetType = Field(..., description="Type of target")
    status: ScanStatus = Field(..., description="Overall scan status")
    priority: Priority = Field(..., description="Scan priority")
    created_at: datetime = Field(..., description="Creation timestamp")
    started_at: Optional[datetime] = Field(None, description="Start timestamp")
    completed_at: Optional[datetime] = Field(None, description="Completion timestamp")
    duration: Optional[float] = Field(None, description="Total duration in seconds")
    
    # Scanner results
    scanner_results: List[ScannerResult] = Field(default_factory=list, description="Results from each scanner")
    
    # Aggregated data
    total_vulnerabilities: int = Field(default=0, description="Total vulnerabilities found")
    severity_counts: Dict[str, int] = Field(default_factory=dict, description="Count by severity")
    unique_vulnerabilities: List[VulnerabilityFinding] = Field(default_factory=list, description="Deduplicated vulnerabilities")
    
    # Metadata
    tags: List[str] = Field(default_factory=list, description="Tags")
    metadata: Dict[str, Any] = Field(default_factory=dict, description="Additional metadata")
    error_message: Optional[str] = Field(None, description="Error message if failed")


class ScheduledScan(BaseModel):
    """Scheduled scan configuration."""
    schedule_id: str = Field(..., description="Unique schedule identifier")
    name: str = Field(..., description="Schedule name")
    description: Optional[str] = Field(None, description="Schedule description")
    enabled: bool = Field(default=True, description="Whether schedule is enabled")
    
    # Scan configuration
    scan_request: ScanRequest = Field(..., description="Scan configuration")
    
    # Schedule configuration
    cron_expression: str = Field(..., description="Cron expression for scheduling")
    timezone: str = Field(default="UTC", description="Timezone for scheduling")
    
    # Metadata
    created_at: datetime = Field(..., description="Creation timestamp")
    updated_at: datetime = Field(..., description="Last update timestamp")
    last_run: Optional[datetime] = Field(None, description="Last execution time")
    next_run: Optional[datetime] = Field(None, description="Next scheduled execution")
    run_count: int = Field(default=0, description="Number of times executed")
    
    # Retention
    max_results: int = Field(default=10, description="Maximum results to keep")
    retention_days: int = Field(default=30, description="Result retention in days")


class PluginStatus(BaseModel):
    """Plugin status information."""
    name: str = Field(..., description="Plugin name")
    version: str = Field(..., description="Plugin version")
    state: PluginState = Field(..., description="Current plugin state")
    scanner_type: ScannerType = Field(..., description="Scanner type")
    description: str = Field(..., description="Plugin description")
    enabled: bool = Field(..., description="Whether plugin is enabled")
    available: bool = Field(..., description="Whether plugin is available")
    health_status: str = Field(..., description="Health check status")
    last_used: Optional[datetime] = Field(None, description="Last usage timestamp")
    usage_count: int = Field(default=0, description="Number of times used")
    error_message: Optional[str] = Field(None, description="Error message if any")
    capabilities: List[str] = Field(default_factory=list, description="Plugin capabilities")
    configuration: Dict[str, Any] = Field(default_factory=dict, description="Plugin configuration")


class ScanStatistics(BaseModel):
    """Scanning statistics and metrics."""
    total_scans: int = Field(..., description="Total number of scans")
    completed_scans: int = Field(..., description="Number of completed scans")
    failed_scans: int = Field(..., description="Number of failed scans")
    running_scans: int = Field(..., description="Number of currently running scans")
    queued_scans: int = Field(..., description="Number of queued scans")
    
    # Performance metrics
    average_duration: float = Field(..., description="Average scan duration in seconds")
    total_duration: float = Field(..., description="Total scanning time in seconds")
    throughput: float = Field(..., description="Scans per hour")
    
    # Vulnerability metrics
    total_vulnerabilities: int = Field(..., description="Total vulnerabilities found")
    critical_vulnerabilities: int = Field(..., description="Critical vulnerabilities")
    high_vulnerabilities: int = Field(..., description="High severity vulnerabilities")
    vulnerability_rate: float = Field(..., description="Vulnerabilities per scan")
    
    # Scanner usage
    scanner_usage: Dict[str, int] = Field(default_factory=dict, description="Usage by scanner type")
    scanner_performance: Dict[str, float] = Field(default_factory=dict, description="Average duration by scanner")
    
    # Time-based metrics
    scans_last_24h: int = Field(..., description="Scans in last 24 hours")
    scans_last_week: int = Field(..., description="Scans in last week")
    scans_last_month: int = Field(..., description="Scans in last month")
    
    # Resource usage
    cpu_usage: float = Field(..., description="Average CPU usage percentage")
    memory_usage: float = Field(..., description="Average memory usage percentage")
    storage_usage: float = Field(..., description="Storage usage in GB")
    
    # Error rates
    error_rate: float = Field(..., description="Error rate percentage")
    timeout_rate: float = Field(..., description="Timeout rate percentage")
    
    # Updated timestamp
    generated_at: datetime = Field(..., description="Statistics generation timestamp")


class ResourceUsage(BaseModel):
    """Resource usage information."""
    cpu_percent: float = Field(..., description="CPU usage percentage")
    memory_percent: float = Field(..., description="Memory usage percentage")
    disk_usage: float = Field(..., description="Disk usage in GB")
    network_io: Dict[str, float] = Field(default_factory=dict, description="Network I/O stats")
    active_connections: int = Field(..., description="Active connections")
    timestamp: datetime = Field(..., description="Measurement timestamp")


class ScanQueue(BaseModel):
    """Scan queue information."""
    queue_size: int = Field(..., description="Number of scans in queue")
    estimated_wait_time: float = Field(..., description="Estimated wait time in seconds")
    priority_distribution: Dict[str, int] = Field(default_factory=dict, description="Scans by priority")
    average_duration: float = Field(..., description="Average scan duration")
    max_concurrent: int = Field(..., description="Maximum concurrent scans")
    current_concurrent: int = Field(..., description="Current concurrent scans")


class ScanFilter(BaseModel):
    """Filter criteria for scan queries."""
    status: Optional[List[ScanStatus]] = Field(None, description="Filter by status")
    scanner: Optional[List[ScannerType]] = Field(None, description="Filter by scanner")
    target_type: Optional[List[TargetType]] = Field(None, description="Filter by target type")
    priority: Optional[List[Priority]] = Field(None, description="Filter by priority")
    tags: Optional[List[str]] = Field(None, description="Filter by tags")
    date_from: Optional[datetime] = Field(None, description="Start date filter")
    date_to: Optional[datetime] = Field(None, description="End date filter")
    has_vulnerabilities: Optional[bool] = Field(None, description="Filter scans with vulnerabilities")
    severity_threshold: Optional[SeverityLevel] = Field(None, description="Minimum severity level")


class BulkScanRequest(BaseModel):
    """Request for bulk scanning operations."""
    targets: List[str] = Field(..., description="List of targets to scan")
    common_config: ScanRequest = Field(..., description="Common scan configuration")
    target_specific_config: Dict[str, Dict[str, Any]] = Field(default_factory=dict, description="Target-specific overrides")
    batch_size: int = Field(default=5, description="Number of concurrent scans")
    priority: Priority = Field(default=Priority.NORMAL, description="Batch priority")
    
    @validator('targets')
    def validate_targets(cls, v):
        if not v:
            raise ValueError('At least one target must be specified')
        if len(v) > 100:  # Reasonable limit
            raise ValueError('Maximum 100 targets allowed per batch')
        return v


class BulkScanResponse(BaseModel):
    """Response for bulk scan operations."""
    batch_id: str = Field(..., description="Unique batch identifier")
    total_targets: int = Field(..., description="Total number of targets")
    scan_ids: List[str] = Field(..., description="Individual scan IDs")
    estimated_duration: float = Field(..., description="Estimated total duration")
    batch_status: str = Field(..., description="Overall batch status")
    created_at: datetime = Field(..., description="Creation timestamp")