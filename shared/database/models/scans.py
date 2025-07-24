"""
Scan Models

Database models for security scans, scan results, and scanner plugins.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List

from sqlalchemy import Column, String, Text, JSON, Enum as SQLEnum, ForeignKey, Float, Integer, Boolean
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import relationship
import uuid

from .base import BaseModel


class ScanStatus(str, Enum):
    """Scan execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


class ScanType(str, Enum):
    """Types of security scans."""
    VULNERABILITY = "vulnerability"
    CONTAINER = "container"
    SBOM = "sbom"
    LICENSE = "license"
    SECRET = "secret"
    COMPLIANCE = "compliance"
    MALWARE = "malware"
    DEPENDENCY = "dependency"


class ScannerType(str, Enum):
    """Supported scanner types."""
    GRYPE = "grype"
    TRIVY = "trivy"
    SYFT = "syft"
    OSV = "osv"
    CLAIR = "clair"
    ANCHORE = "anchore"
    SNYK = "snyk"
    TWISTLOCK = "twistlock"


class Priority(str, Enum):
    """Scan priority levels."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Scan(BaseModel):
    """Security scan entity."""
    
    __tablename__ = "scans"
    
    # Basic scan information
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    scan_type = Column(SQLEnum(ScanType), nullable=False)
    status = Column(SQLEnum(ScanStatus), default=ScanStatus.PENDING, nullable=False)
    priority = Column(SQLEnum(Priority), default=Priority.MEDIUM, nullable=False)
    
    # Target information
    target_type = Column(String(100), nullable=False)  # image, repository, file, etc.
    target_identifier = Column(String(500), nullable=False)  # image name, repo URL, file path
    target_metadata = Column(JSONB, default=dict, nullable=False)
    
    # Execution details
    scanner_configs = Column(JSONB, default=list, nullable=False)  # List of scanner configurations
    execution_config = Column(JSONB, default=dict, nullable=False)
    
    # Timing
    started_at = Column(JSON, nullable=True)
    completed_at = Column(JSON, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    
    # Results summary
    total_vulnerabilities = Column(Integer, default=0, nullable=False)
    critical_count = Column(Integer, default=0, nullable=False)
    high_count = Column(Integer, default=0, nullable=False)
    medium_count = Column(Integer, default=0, nullable=False)
    low_count = Column(Integer, default=0, nullable=False)
    info_count = Column(Integer, default=0, nullable=False)
    
    # Quality metrics
    scan_quality_score = Column(Float, nullable=True)
    coverage_percentage = Column(Float, nullable=True)
    false_positive_rate = Column(Float, nullable=True)
    
    # Scheduling
    scheduled = Column(Boolean, default=False, nullable=False)
    cron_expression = Column(String(100), nullable=True)
    last_scheduled_run = Column(JSON, nullable=True)
    next_scheduled_run = Column(JSON, nullable=True)
    
    # Organization context
    organization_id = Column(UUID(as_uuid=True), nullable=True)
    project_id = Column(UUID(as_uuid=True), nullable=True)
    team_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Relationships
    scan_results = relationship("ScanResult", back_populates="scan", cascade="all, delete-orphan")
    
    def _validate(self) -> List[str]:
        """Custom validation for scan model."""
        errors = []
        
        if not self.name or len(self.name.strip()) == 0:
            errors.append("Scan name cannot be empty")
        
        if not self.target_identifier or len(self.target_identifier.strip()) == 0:
            errors.append("Target identifier cannot be empty")
        
        if self.cron_expression and not self.scheduled:
            errors.append("Cron expression requires scheduled to be True")
            
        if self.duration_seconds and self.duration_seconds < 0:
            errors.append("Duration cannot be negative")
            
        return errors
    
    def update_counts(self, vulnerabilities: List[Dict[str, Any]]):
        """Update vulnerability counts from scan results."""
        self.total_vulnerabilities = len(vulnerabilities)
        self.critical_count = sum(1 for v in vulnerabilities if v.get('severity') == 'CRITICAL')
        self.high_count = sum(1 for v in vulnerabilities if v.get('severity') == 'HIGH')
        self.medium_count = sum(1 for v in vulnerabilities if v.get('severity') == 'MEDIUM')
        self.low_count = sum(1 for v in vulnerabilities if v.get('severity') == 'LOW')
        self.info_count = sum(1 for v in vulnerabilities if v.get('severity') == 'INFO')
    
    def get_risk_score(self) -> float:
        """Calculate overall risk score based on vulnerability counts."""
        weights = {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 1, "INFO": 0}
        total_score = (
            self.critical_count * weights["CRITICAL"] +
            self.high_count * weights["HIGH"] +
            self.medium_count * weights["MEDIUM"] +
            self.low_count * weights["LOW"] +
            self.info_count * weights["INFO"]
        )
        return min(total_score / 100.0, 10.0)  # Normalize to 0-10 scale


class ScanResult(BaseModel):
    """Individual scan result from a specific scanner."""
    
    __tablename__ = "scan_results"
    
    # Relationship to parent scan
    scan_id = Column(UUID(as_uuid=True), ForeignKey("scans.id"), nullable=False)
    
    # Scanner information
    scanner_id = Column(UUID(as_uuid=True), ForeignKey("scanner_plugins.id"), nullable=False)
    scanner_name = Column(String(100), nullable=False)
    scanner_version = Column(String(50), nullable=False)
    
    # Execution details
    status = Column(SQLEnum(ScanStatus), nullable=False)
    started_at = Column(JSON, nullable=True)
    completed_at = Column(JSON, nullable=True)
    duration_seconds = Column(Float, nullable=True)
    
    # Result data
    raw_output = Column(Text, nullable=True)  # Raw scanner output
    structured_results = Column(JSONB, default=list, nullable=False)  # Parsed results
    error_message = Column(Text, nullable=True)
    exit_code = Column(Integer, nullable=True)
    
    # Result summary
    findings_count = Column(Integer, default=0, nullable=False)
    vulnerabilities_found = Column(Integer, default=0, nullable=False)
    licenses_found = Column(Integer, default=0, nullable=False)
    secrets_found = Column(Integer, default=0, nullable=False)
    
    # Quality metrics
    confidence_score = Column(Float, nullable=True)
    data_quality_score = Column(Float, nullable=True)
    
    # Processing flags
    processed = Column(Boolean, default=False, nullable=False)
    enriched = Column(Boolean, default=False, nullable=False)
    analyzed = Column(Boolean, default=False, nullable=False)
    
    # Relationships
    scan = relationship("Scan", back_populates="scan_results")
    scanner_plugin = relationship("ScannerPlugin", back_populates="scan_results")
    
    def _validate(self) -> List[str]:
        """Custom validation for scan result model."""
        errors = []
        
        if not self.scanner_name or len(self.scanner_name.strip()) == 0:
            errors.append("Scanner name cannot be empty")
        
        if self.duration_seconds and self.duration_seconds < 0:
            errors.append("Duration cannot be negative")
            
        if self.confidence_score and (self.confidence_score < 0 or self.confidence_score > 1):
            errors.append("Confidence score must be between 0 and 1")
            
        return errors
    
    def mark_processed(self):
        """Mark result as processed."""
        self.processed = True
        self.set_metadata("processed_at", datetime.utcnow().isoformat())
    
    def add_finding(self, finding: Dict[str, Any]):
        """Add a finding to structured results."""
        if self.structured_results is None:
            self.structured_results = []
        self.structured_results.append(finding)
        self.findings_count = len(self.structured_results)


class ScannerPlugin(BaseModel):
    """Scanner plugin configuration and metadata."""
    
    __tablename__ = "scanner_plugins"
    
    # Plugin identification
    name = Column(String(100), unique=True, nullable=False)
    display_name = Column(String(200), nullable=False)
    description = Column(Text, nullable=True)
    scanner_type = Column(SQLEnum(ScannerType), nullable=False)
    version = Column(String(50), nullable=False)
    
    # Plugin configuration
    enabled = Column(Boolean, default=True, nullable=False)
    configuration = Column(JSONB, default=dict, nullable=False)
    default_settings = Column(JSONB, default=dict, nullable=False)
    
    # Capabilities
    supported_scan_types = Column(JSONB, default=list, nullable=False)  # List of ScanType values
    supported_targets = Column(JSONB, default=list, nullable=False)  # List of target types
    output_formats = Column(JSONB, default=list, nullable=False)  # Supported output formats
    
    # Runtime information
    executable_path = Column(String(500), nullable=True)
    docker_image = Column(String(300), nullable=True)
    environment_variables = Column(JSONB, default=dict, nullable=False)
    
    # Performance metrics
    average_scan_time = Column(Float, nullable=True)
    success_rate = Column(Float, nullable=True)
    reliability_score = Column(Float, nullable=True)
    
    # Health status
    health_status = Column(String(50), default="unknown", nullable=False)
    last_health_check = Column(JSON, nullable=True)
    health_check_interval = Column(Integer, default=300, nullable=False)  # seconds
    
    # Resource requirements
    cpu_limit = Column(Float, nullable=True)  # CPU cores
    memory_limit = Column(Integer, nullable=True)  # MB
    disk_space_limit = Column(Integer, nullable=True)  # MB
    timeout_seconds = Column(Integer, default=3600, nullable=False)
    
    # Usage statistics
    total_scans = Column(Integer, default=0, nullable=False)
    successful_scans = Column(Integer, default=0, nullable=False)
    failed_scans = Column(Integer, default=0, nullable=False)
    last_used = Column(JSON, nullable=True)
    
    # Relationships
    scan_results = relationship("ScanResult", back_populates="scanner_plugin")
    
    def _validate(self) -> List[str]:
        """Custom validation for scanner plugin model."""
        errors = []
        
        if not self.name or len(self.name.strip()) == 0:
            errors.append("Plugin name cannot be empty")
        
        if not self.display_name or len(self.display_name.strip()) == 0:
            errors.append("Display name cannot be empty")
        
        if not self.version or len(self.version.strip()) == 0:
            errors.append("Version cannot be empty")
            
        if self.cpu_limit and self.cpu_limit <= 0:
            errors.append("CPU limit must be positive")
            
        if self.memory_limit and self.memory_limit <= 0:
            errors.append("Memory limit must be positive")
            
        if self.timeout_seconds <= 0:
            errors.append("Timeout must be positive")
            
        return errors
    
    def update_success_rate(self):
        """Recalculate success rate based on scan statistics."""
        if self.total_scans > 0:
            self.success_rate = self.successful_scans / self.total_scans
        else:
            self.success_rate = 0.0
    
    def record_scan_result(self, success: bool, duration: Optional[float] = None):
        """Record the result of a scan execution."""
        self.total_scans += 1
        if success:
            self.successful_scans += 1
        else:
            self.failed_scans += 1
        
        self.update_success_rate()
        self.last_used = datetime.utcnow().isoformat()
        
        if duration and self.average_scan_time:
            # Update running average
            self.average_scan_time = (self.average_scan_time + duration) / 2
        elif duration:
            self.average_scan_time = duration
    
    def is_healthy(self) -> bool:
        """Check if plugin is in healthy state."""
        return self.health_status in ["healthy", "ok", "available"]
    
    def supports_scan_type(self, scan_type: ScanType) -> bool:
        """Check if plugin supports a specific scan type."""
        return scan_type.value in self.supported_scan_types
    
    def supports_target_type(self, target_type: str) -> bool:
        """Check if plugin supports a specific target type."""
        return target_type in self.supported_targets