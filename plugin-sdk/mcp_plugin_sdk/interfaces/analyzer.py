"""
Analyzer plugin interface for vulnerability analysis and threat detection.
"""

from abc import abstractmethod
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional, Union

from pydantic import BaseModel, Field

from .base import BasePlugin, PluginMetadata, PluginType


class Severity(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class VulnerabilityType(str, Enum):
    """Types of vulnerabilities."""
    CODE_INJECTION = "code_injection"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    AUTHENTICATION_BYPASS = "authentication_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    BUFFER_OVERFLOW = "buffer_overflow"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    MALWARE = "malware"
    MISCONFIGURATION = "misconfiguration"
    OUTDATED_COMPONENT = "outdated_component"
    WEAK_CRYPTOGRAPHY = "weak_cryptography"
    INSECURE_PROTOCOL = "insecure_protocol"
    OTHER = "other"


class MitreAttackTactic(str, Enum):
    """MITRE ATT&CK tactics."""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class VulnerabilityResult(BaseModel):
    """Result of vulnerability analysis."""
    
    # Identification
    vulnerability_id: str = Field(..., description="Unique vulnerability identifier")
    title: str = Field(..., description="Vulnerability title")
    description: str = Field("", description="Detailed description")
    
    # Classification
    vulnerability_type: VulnerabilityType = Field(..., description="Type of vulnerability")
    severity: Severity = Field(..., description="Severity level")
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="CVSS score")
    cve_ids: List[str] = Field(default_factory=list, description="Related CVE identifiers")
    cwe_ids: List[str] = Field(default_factory=list, description="Related CWE identifiers")
    
    # Context
    affected_component: str = Field("", description="Affected component or file")
    location: Dict[str, Any] = Field(default_factory=dict, description="Location information")
    evidence: List[str] = Field(default_factory=list, description="Evidence supporting the finding")
    
    # MITRE ATT&CK mapping
    mitre_tactics: List[MitreAttackTactic] = Field(default_factory=list)
    mitre_techniques: List[str] = Field(default_factory=list, description="MITRE technique IDs")
    
    # Remediation
    remediation: str = Field("", description="Remediation guidance")
    references: List[str] = Field(default_factory=list, description="External references")
    
    # Metadata
    confidence: float = Field(1.0, ge=0.0, le=1.0, description="Confidence in the finding")
    false_positive_risk: float = Field(0.0, ge=0.0, le=1.0, description="Risk of false positive")
    analyzer_name: str = Field("", description="Name of the analyzer that found this")
    analysis_timestamp: datetime = Field(default_factory=datetime.now)
    
    # Custom fields for plugin-specific data
    custom_fields: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        use_enum_values = True


class AnalysisRequest(BaseModel):
    """Request for vulnerability analysis."""
    
    request_id: str = Field(..., description="Unique request identifier")
    target_type: str = Field(..., description="Type of target (file, url, network, etc.)")
    target_data: Dict[str, Any] = Field(..., description="Target data to analyze")
    
    # Analysis parameters
    analysis_depth: str = Field("standard", description="Analysis depth: quick, standard, deep")
    include_patterns: List[str] = Field(default_factory=list, description="Patterns to include")
    exclude_patterns: List[str] = Field(default_factory=list, description="Patterns to exclude")
    
    # Context
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context")
    timeout: int = Field(300, description="Analysis timeout in seconds")
    
    # Metadata
    source: str = Field("", description="Source of the analysis request")
    priority: int = Field(50, description="Request priority (0-100)")
    timestamp: datetime = Field(default_factory=datetime.now)


class AnalysisResponse(BaseModel):
    """Response from vulnerability analysis."""
    
    request_id: str = Field(..., description="Original request identifier")
    status: str = Field(..., description="Analysis status: success, error, timeout")
    
    # Results
    vulnerabilities: List[VulnerabilityResult] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict, description="Analysis summary")
    
    # Performance metrics
    analysis_duration: float = Field(..., description="Analysis duration in seconds")
    files_analyzed: int = Field(0, description="Number of files analyzed")
    rules_executed: int = Field(0, description="Number of rules executed")
    
    # Error information
    error_message: Optional[str] = Field(None, description="Error message if status is error")
    warnings: List[str] = Field(default_factory=list, description="Analysis warnings")
    
    # Metadata
    analyzer_version: str = Field("", description="Analyzer version")
    completion_timestamp: datetime = Field(default_factory=datetime.now)


class AnalyzerPlugin(BasePlugin):
    """
    Base class for analyzer plugins.
    
    Analyzer plugins perform vulnerability analysis and threat detection
    on various types of security data including source code, network traffic,
    system logs, and configuration files.
    """
    
    def get_metadata(self) -> PluginMetadata:
        """Get analyzer plugin metadata."""
        metadata = super().get_metadata() if hasattr(super(), 'get_metadata') else PluginMetadata(
            name=self.__class__.__name__,
            version="1.0.0",
            plugin_type=PluginType.ANALYZER,
            entry_point=f"{self.__class__.__module__}:{self.__class__.__name__}"
        )
        metadata.plugin_type = PluginType.ANALYZER
        return metadata
    
    @abstractmethod
    async def analyze(self, request: AnalysisRequest) -> AnalysisResponse:
        """
        Perform vulnerability analysis.
        
        Args:
            request: Analysis request with target data and parameters
            
        Returns:
            AnalysisResponse: Analysis results with vulnerabilities found
            
        Raises:
            PluginError: If analysis fails
        """
        pass
    
    @abstractmethod
    def get_supported_types(self) -> List[str]:
        """
        Get list of supported target types.
        
        Returns:
            List of supported target types (e.g., 'source_code', 'network_pcap', 'log_file')
        """
        pass
    
    @abstractmethod
    def get_rules_info(self) -> Dict[str, Any]:
        """
        Get information about analysis rules.
        
        Returns:
            Dictionary with rules information including count, categories, etc.
        """
        pass
    
    async def validate_request(self, request: AnalysisRequest) -> bool:
        """
        Validate an analysis request.
        
        Args:
            request: Analysis request to validate
            
        Returns:
            True if request is valid, False otherwise
        """
        if not request.target_type:
            return False
            
        if request.target_type not in self.get_supported_types():
            return False
            
        if not request.target_data:
            return False
            
        return True
    
    async def get_analysis_stats(self) -> Dict[str, Any]:
        """
        Get analysis statistics.
        
        Returns:
            Dictionary with analysis statistics
        """
        return {
            "total_analyses": 0,
            "vulnerabilities_found": 0,
            "average_analysis_time": 0.0,
            "success_rate": 1.0,
            "supported_types": self.get_supported_types(),
            "rules_info": self.get_rules_info(),
        }