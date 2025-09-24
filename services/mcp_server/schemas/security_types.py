"""
Security Type Definitions

Pydantic models for security scan requests and results.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum

from pydantic import BaseModel, Field


class ScannerType(str, Enum):
    """Supported scanner types."""
    GRYPE = "grype"
    TRIVY = "trivy"
    SYFT = "syft"


class SeverityLevel(str, Enum):
    """Vulnerability severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"
    UNKNOWN = "unknown"


class ScanStatus(str, Enum):
    """Scan status values."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"


class SBOMFormat(str, Enum):
    """SBOM format types."""
    SPDX = "spdx"
    CYCLONEDX = "cyclonedx"
    SYFT = "syft"


class OutputFormat(str, Enum):
    """Output format types."""
    JSON = "json"
    XML = "xml"
    YAML = "yaml"
    TABLE = "table"
    SARIF = "sarif"


class ComplianceFramework(str, Enum):
    """Compliance framework types."""
    CIS = "cis"
    NIST = "nist"
    SOC2 = "soc2"
    PCI_DSS = "pci-dss"
    ISO27001 = "iso27001"


class ScanRequest(BaseModel):
    """Request model for vulnerability scans."""
    image: str = Field(..., description="Container image to scan")
    scanner: ScannerType = Field(default=ScannerType.GRYPE, description="Scanner to use")
    format: OutputFormat = Field(default=OutputFormat.JSON, description="Output format")


class SBOMRequest(BaseModel):
    """Request model for SBOM generation."""
    target: str = Field(..., description="Target to analyze")
    format: SBOMFormat = Field(default=SBOMFormat.SPDX, description="SBOM format")
    output: OutputFormat = Field(default=OutputFormat.JSON, description="Output format")


class RiskAssessmentRequest(BaseModel):
    """Request model for risk assessment."""
    vulnerabilities: List[Dict[str, Any]] = Field(..., description="Vulnerabilities to assess")
    context: Optional[str] = Field(None, description="Additional context")
    criteria: Optional[List[str]] = Field(None, description="Assessment criteria")


class ComplianceRequest(BaseModel):
    """Request model for compliance analysis."""
    target: str = Field(..., description="Target to analyze")
    framework: ComplianceFramework = Field(..., description="Compliance framework")
    profile: Optional[str] = Field(None, description="Specific profile or version")


class Vulnerability(BaseModel):
    """Vulnerability data model."""
    cve_id: str = Field(..., description="CVE identifier")
    severity: SeverityLevel = Field(..., description="Vulnerability severity")
    description: str = Field(..., description="Vulnerability description")
    package_name: str = Field(..., description="Affected package name")
    package_version: str = Field(..., description="Affected package version")
    package_type: Optional[str] = Field(None, description="Package type")
    fix_versions: List[str] = Field(default_factory=list, description="Available fix versions")
    urls: List[str] = Field(default_factory=list, description="Reference URLs")
    cvss_score: Optional[float] = Field(None, description="CVSS score")


class ScanSummary(BaseModel):
    """Scan summary statistics."""
    total_vulnerabilities: int = Field(..., description="Total vulnerability count")
    severity_counts: Dict[str, int] = Field(..., description="Count by severity")
    scanner: str = Field(..., description="Scanner used")


class ScanResult(BaseModel):
    """Complete scan result."""
    scan_id: str = Field(..., description="Unique scan identifier")
    image: str = Field(..., description="Scanned image")
    scanner: ScannerType = Field(..., description="Scanner used")
    format: OutputFormat = Field(..., description="Output format")
    scan_start: datetime = Field(..., description="Scan start time")
    scan_end: Optional[datetime] = Field(None, description="Scan end time")
    duration_seconds: float = Field(..., description="Scan duration")
    status: ScanStatus = Field(..., description="Scan status")
    summary: ScanSummary = Field(..., description="Scan summary")
    vulnerabilities: List[Vulnerability] = Field(..., description="Found vulnerabilities")
    raw_output: Optional[Dict[str, Any]] = Field(None, description="Raw scanner output")


class Component(BaseModel):
    """SBOM component data model."""
    name: str = Field(..., description="Component name")
    version: str = Field(..., description="Component version")
    type: str = Field(..., description="Component type")
    language: Optional[str] = Field(None, description="Programming language")
    locations: List[str] = Field(default_factory=list, description="File locations")
    licenses: List[str] = Field(default_factory=list, description="License information")
    cpes: List[str] = Field(default_factory=list, description="CPE identifiers")
    purl: Optional[str] = Field(None, description="Package URL")


class SBOMSummary(BaseModel):
    """SBOM summary statistics."""
    total_components: int = Field(..., description="Total component count")
    component_types: Dict[str, int] = Field(..., description="Count by component type")
    format: SBOMFormat = Field(..., description="SBOM format")


class SBOMResult(BaseModel):
    """Complete SBOM result."""
    sbom_id: str = Field(..., description="Unique SBOM identifier")
    target: str = Field(..., description="Analyzed target")
    format: SBOMFormat = Field(..., description="SBOM format")
    output_format: OutputFormat = Field(..., description="Output format")
    generation_start: datetime = Field(..., description="Generation start time")
    generation_end: Optional[datetime] = Field(None, description="Generation end time")
    duration_seconds: float = Field(..., description="Generation duration")
    status: ScanStatus = Field(..., description="Generation status")
    summary: SBOMSummary = Field(..., description="SBOM summary")
    components: List[Component] = Field(..., description="SBOM components")
    sbom_data: Optional[Dict[str, Any]] = Field(None, description="Raw SBOM data")


class RiskFactor(BaseModel):
    """Individual risk factor assessment."""
    severity_factor: float = Field(..., description="Severity-based risk factor")
    exploitability_factor: float = Field(..., description="Exploitability risk factor")
    exposure_factor: float = Field(..., description="Exposure risk factor")
    impact_factor: float = Field(..., description="Impact risk factor")
    mitigation_factor: float = Field(..., description="Mitigation availability factor")


class VulnerabilityRiskAnalysis(BaseModel):
    """Individual vulnerability risk analysis."""
    cve_id: str = Field(..., description="CVE identifier")
    package: str = Field(..., description="Affected package")
    severity: SeverityLevel = Field(..., description="Vulnerability severity")
    cvss_score: Optional[float] = Field(None, description="CVSS score")
    risk_factors: RiskFactor = Field(..., description="Risk factor breakdown")
    composite_risk_score: float = Field(..., description="Composite risk score")
    risk_level: str = Field(..., description="Calculated risk level")
    remediation_urgency: str = Field(..., description="Remediation urgency")
    contextual_factors: List[str] = Field(..., description="Contextual risk factors")


class RiskScores(BaseModel):
    """Overall risk scoring."""
    overall_risk_score: float = Field(..., description="Overall risk score")
    overall_risk_level: str = Field(..., description="Overall risk level")
    max_individual_risk: float = Field(..., description="Highest individual risk")
    average_risk_score: float = Field(..., description="Average risk score")
    risk_level_distribution: Dict[str, int] = Field(..., description="Risk level counts")
    total_vulnerabilities: int = Field(..., description="Total vulnerabilities assessed")
    high_risk_vulnerabilities: int = Field(..., description="High/critical risk count")


class Recommendation(BaseModel):
    """Risk remediation recommendation."""
    priority: str = Field(..., description="Recommendation priority")
    category: str = Field(..., description="Recommendation category")
    title: str = Field(..., description="Recommendation title")
    description: str = Field(..., description="Recommendation description")
    estimated_effort: str = Field(..., description="Estimated implementation effort")
    business_justification: str = Field(..., description="Business justification")


class RiskAssessmentResult(BaseModel):
    """Complete risk assessment result."""
    assessment_id: str = Field(..., description="Unique assessment identifier")
    assessment_start: datetime = Field(..., description="Assessment start time")
    assessment_end: Optional[datetime] = Field(None, description="Assessment end time")
    duration_seconds: float = Field(..., description="Assessment duration")
    status: ScanStatus = Field(..., description="Assessment status")
    risk_scores: RiskScores = Field(..., description="Overall risk scores")
    vulnerability_analyses: List[VulnerabilityRiskAnalysis] = Field(..., description="Individual vulnerability analyses")
    recommendations: List[Recommendation] = Field(..., description="Remediation recommendations")
    executive_summary: Dict[str, Any] = Field(..., description="Executive summary")


class ComplianceFinding(BaseModel):
    """Individual compliance finding."""
    control_id: str = Field(..., description="Control identifier")
    control_description: str = Field(..., description="Control description")
    status: str = Field(..., description="Compliance status")
    severity: str = Field(..., description="Finding severity")
    remediation: str = Field(..., description="Remediation guidance")
    section: str = Field(..., description="Framework section")


class ComplianceSummary(BaseModel):
    """Compliance assessment summary."""
    framework: ComplianceFramework = Field(..., description="Compliance framework")
    total_controls: int = Field(..., description="Total controls assessed")
    passed_controls: int = Field(..., description="Passed controls")
    failed_controls: int = Field(..., description="Failed controls")
    manual_controls: int = Field(..., description="Manual controls")
    compliance_score: float = Field(..., description="Compliance score percentage")
    risk_level: str = Field(..., description="Overall risk level")


class ComplianceResult(BaseModel):
    """Complete compliance assessment result."""
    analysis_id: str = Field(..., description="Unique analysis identifier")
    target: str = Field(..., description="Analyzed target")
    framework: ComplianceFramework = Field(..., description="Compliance framework")
    profile: Optional[str] = Field(None, description="Specific profile")
    analysis_start: datetime = Field(..., description="Analysis start time")
    analysis_end: Optional[datetime] = Field(None, description="Analysis end time")
    duration_seconds: float = Field(..., description="Analysis duration")
    status: ScanStatus = Field(..., description="Analysis status")
    summary: ComplianceSummary = Field(..., description="Compliance summary")
    findings: List[ComplianceFinding] = Field(..., description="Compliance findings")
    recommendations: List[Recommendation] = Field(..., description="Remediation recommendations")
    raw_results: Optional[Dict[str, Any]] = Field(None, description="Raw assessment results")