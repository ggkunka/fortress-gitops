"""
Vulnerability Models

Database models for vulnerabilities, CVEs, packages, and vulnerability matches.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List

from sqlalchemy import Column, String, Text, JSON, Enum as SQLEnum, ForeignKey, Float, Integer, Boolean, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import relationship
import uuid

from .base import BaseModel


class VulnerabilitySeverity(str, Enum):
    """CVSS severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium" 
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class VulnerabilityStatus(str, Enum):
    """Vulnerability remediation status."""
    OPEN = "open"
    FIXED = "fixed"
    MITIGATED = "mitigated"
    ACCEPTED = "accepted"
    FALSE_POSITIVE = "false_positive"
    WONT_FIX = "wont_fix"
    INVESTIGATING = "investigating"


class PackageType(str, Enum):
    """Types of software packages."""
    NPM = "npm"
    PYPI = "pypi"
    MAVEN = "maven"
    NUGET = "nuget"
    GEM = "gem"
    CARGO = "cargo"
    GO = "go"
    DEB = "deb"
    RPM = "rpm"
    APK = "apk"
    DOCKER = "docker"
    BINARY = "binary"
    UNKNOWN = "unknown"


class CVSSVersion(str, Enum):
    """CVSS scoring versions."""
    V2 = "2.0"
    V3 = "3.0"
    V3_1 = "3.1"
    V4 = "4.0"


class Vulnerability(BaseModel):
    """Core vulnerability entity."""
    
    __tablename__ = "vulnerabilities"
    
    # Primary identifiers
    vulnerability_id = Column(String(100), unique=True, nullable=False)  # CVE-ID, GHSA-ID, etc.
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    
    # Severity and scoring
    severity = Column(SQLEnum(VulnerabilitySeverity), nullable=False)
    cvss_version = Column(SQLEnum(CVSSVersion), nullable=True)
    cvss_vector = Column(String(200), nullable=True)
    cvss_score = Column(Float, nullable=True)
    
    # Detailed CVSS metrics
    attack_vector = Column(String(50), nullable=True)
    attack_complexity = Column(String(50), nullable=True)
    privileges_required = Column(String(50), nullable=True)
    user_interaction = Column(String(50), nullable=True)
    scope = Column(String(50), nullable=True)
    confidentiality_impact = Column(String(50), nullable=True)
    integrity_impact = Column(String(50), nullable=True)
    availability_impact = Column(String(50), nullable=True)
    
    # Vulnerability details
    cwe_ids = Column(ARRAY(String), default=list, nullable=False)  # Common Weakness Enumeration
    weakness_types = Column(JSONB, default=list, nullable=False)
    exploit_available = Column(Boolean, default=False, nullable=False)
    exploit_maturity = Column(String(50), nullable=True)
    
    # Timeline
    published_date = Column(JSON, nullable=True)
    last_modified_date = Column(JSON, nullable=True)
    disclosure_date = Column(JSON, nullable=True)
    
    # References and sources
    references = Column(JSONB, default=list, nullable=False)  # URLs, advisories
    source_db = Column(String(100), nullable=False)  # NVD, GHSA, OSV, etc.
    source_id = Column(String(200), nullable=False)
    aliases = Column(JSONB, default=list, nullable=False)  # Alternative IDs
    
    # Affected software
    affected_packages = Column(JSONB, default=list, nullable=False)
    vendor_advisories = Column(JSONB, default=list, nullable=False)
    
    # Fix information
    fixed_in_versions = Column(JSONB, default=list, nullable=False)
    patch_available = Column(Boolean, default=False, nullable=False)
    patch_urls = Column(JSONB, default=list, nullable=False)
    workarounds = Column(JSONB, default=list, nullable=False)
    
    # Threat intelligence
    epss_score = Column(Float, nullable=True)  # Exploit Prediction Scoring System
    epss_percentile = Column(Float, nullable=True)
    threat_intel_data = Column(JSONB, default=dict, nullable=False)
    mitre_attack_techniques = Column(JSONB, default=list, nullable=False)
    
    # Analysis flags
    analyzed = Column(Boolean, default=False, nullable=False)
    risk_assessed = Column(Boolean, default=False, nullable=False)
    enriched = Column(Boolean, default=False, nullable=False)
    
    # Relationships
    cve_records = relationship("CVE", back_populates="vulnerability")
    vulnerability_matches = relationship("VulnerabilityMatch", back_populates="vulnerability")
    
    def _validate(self) -> List[str]:
        """Custom validation for vulnerability model."""
        errors = []
        
        if not self.vulnerability_id or len(self.vulnerability_id.strip()) == 0:
            errors.append("Vulnerability ID cannot be empty")
        
        if not self.title or len(self.title.strip()) == 0:
            errors.append("Title cannot be empty")
        
        if self.cvss_score and (self.cvss_score < 0 or self.cvss_score > 10):
            errors.append("CVSS score must be between 0 and 10")
            
        if self.epss_score and (self.epss_score < 0 or self.epss_score > 1):
            errors.append("EPSS score must be between 0 and 1")
            
        return errors
    
    def get_risk_level(self) -> str:
        """Calculate risk level based on CVSS and EPSS scores."""
        cvss = self.cvss_score or 0
        epss = self.epss_score or 0
        
        if cvss >= 9.0 or epss >= 0.8:
            return "critical"
        elif cvss >= 7.0 or epss >= 0.5:
            return "high"
        elif cvss >= 4.0 or epss >= 0.2:
            return "medium"
        else:
            return "low"
    
    def is_exploitable(self) -> bool:
        """Check if vulnerability has known exploits."""
        return self.exploit_available or (self.epss_score and self.epss_score > 0.1)


class CVE(BaseModel):
    """CVE (Common Vulnerabilities and Exposures) specific data."""
    
    __tablename__ = "cves"
    
    # CVE identification
    cve_id = Column(String(20), unique=True, nullable=False)  # CVE-YYYY-NNNN
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerabilities.id"), nullable=False)
    
    # CVE specific fields
    assigner = Column(String(200), nullable=True)  # CNA (CVE Numbering Authority)
    assigner_org = Column(String(200), nullable=True)
    
    # NVD specific data
    nvd_published_date = Column(JSON, nullable=True)
    nvd_last_modified = Column(JSON, nullable=True)
    nvd_source = Column(String(100), nullable=True)
    
    # Configuration data
    configurations = Column(JSONB, default=list, nullable=False)  # CPE configurations
    cpe_matches = Column(JSONB, default=list, nullable=False)
    
    # Impact metrics
    impact_type = Column(String(50), nullable=True)
    base_severity = Column(String(50), nullable=True)
    exploitability_score = Column(Float, nullable=True)
    impact_score = Column(Float, nullable=True)
    
    # Status and review
    nvd_status = Column(String(50), nullable=True)
    review_status = Column(String(50), nullable=True)
    quality_score = Column(Float, nullable=True)
    
    # Relationship
    vulnerability = relationship("Vulnerability", back_populates="cve_records")
    
    def _validate(self) -> List[str]:
        """Custom validation for CVE model."""
        errors = []
        
        if not self.cve_id or not self.cve_id.startswith("CVE-"):
            errors.append("Invalid CVE ID format")
            
        return errors


class Package(BaseModel):
    """Software package information."""
    
    __tablename__ = "packages"
    
    # Package identification
    name = Column(String(200), nullable=False)
    namespace = Column(String(200), nullable=True)  # org, scope, group
    package_type = Column(SQLEnum(PackageType), nullable=False)
    version = Column(String(100), nullable=False)
    
    # Package metadata
    description = Column(Text, nullable=True)
    homepage = Column(String(500), nullable=True)
    repository_url = Column(String(500), nullable=True)
    license_name = Column(String(100), nullable=True)
    license_url = Column(String(500), nullable=True)
    
    # Package manager data
    package_url = Column(String(500), nullable=True)  # PURL format
    package_manager_url = Column(String(500), nullable=True)
    download_url = Column(String(500), nullable=True)
    
    # Checksums and integrity
    file_hashes = Column(JSONB, default=dict, nullable=False)  # sha1, sha256, md5
    size_bytes = Column(Integer, nullable=True)
    
    # Publishing information
    published_date = Column(JSON, nullable=True)
    author = Column(String(200), nullable=True)
    maintainer = Column(String(200), nullable=True)
    
    # Dependency information
    dependencies = Column(JSONB, default=list, nullable=False)
    dev_dependencies = Column(JSONB, default=list, nullable=False)
    peer_dependencies = Column(JSONB, default=list, nullable=False)
    
    # Security flags
    deprecated = Column(Boolean, default=False, nullable=False)
    malicious = Column(Boolean, default=False, nullable=False)
    security_advisory_count = Column(Integer, default=0, nullable=False)
    
    # Analysis metadata
    first_seen = Column(JSON, nullable=True)
    last_seen = Column(JSON, nullable=True)
    scan_count = Column(Integer, default=0, nullable=False)
    
    # Unique constraint
    __table_args__ = (
        UniqueConstraint('name', 'namespace', 'package_type', 'version', name='uq_package_version'),
    )
    
    # Relationships
    vulnerability_matches = relationship("VulnerabilityMatch", back_populates="package")
    
    def _validate(self) -> List[str]:
        """Custom validation for package model."""
        errors = []
        
        if not self.name or len(self.name.strip()) == 0:
            errors.append("Package name cannot be empty")
        
        if not self.version or len(self.version.strip()) == 0:
            errors.append("Package version cannot be empty")
            
        return errors
    
    def get_package_url(self) -> str:
        """Generate PURL (Package URL) for this package."""
        purl = f"pkg:{self.package_type.value}/{self.name}@{self.version}"
        if self.namespace:
            purl = f"pkg:{self.package_type.value}/{self.namespace}/{self.name}@{self.version}"
        return purl
    
    def is_security_risk(self) -> bool:
        """Check if package poses security risk."""
        return self.malicious or self.security_advisory_count > 0


class VulnerabilityMatch(BaseModel):
    """Match between a vulnerability and a package in a specific context."""
    
    __tablename__ = "vulnerability_matches"
    
    # Foreign keys
    vulnerability_id = Column(UUID(as_uuid=True), ForeignKey("vulnerabilities.id"), nullable=False)
    package_id = Column(UUID(as_uuid=True), ForeignKey("packages.id"), nullable=False)
    scan_id = Column(UUID(as_uuid=True), nullable=True)  # Optional scan context
    
    # Match details
    match_type = Column(String(50), nullable=False)  # exact, range, fuzzy
    confidence_score = Column(Float, nullable=False)
    matcher_name = Column(String(100), nullable=False)  # Which scanner found this
    
    # Version constraint information
    affected_version_range = Column(String(200), nullable=True)
    fixed_in_version = Column(String(100), nullable=True)
    introduced_in_version = Column(String(100), nullable=True)
    
    # Context information
    file_path = Column(String(1000), nullable=True)  # Where package was found
    layer_id = Column(String(100), nullable=True)  # Docker layer if applicable
    location_metadata = Column(JSONB, default=dict, nullable=False)
    
    # Remediation status
    status = Column(SQLEnum(VulnerabilityStatus), default=VulnerabilityStatus.OPEN, nullable=False)
    remediation_available = Column(Boolean, default=False, nullable=False)
    remediation_advice = Column(Text, nullable=True)
    
    # Risk assessment
    exploitable_in_context = Column(Boolean, nullable=True)
    business_impact = Column(String(50), nullable=True)
    risk_score = Column(Float, nullable=True)
    priority_score = Column(Float, nullable=True)
    
    # Analysis flags
    triaged = Column(Boolean, default=False, nullable=False)
    verified = Column(Boolean, default=False, nullable=False)
    suppressed = Column(Boolean, default=False, nullable=False)
    suppression_reason = Column(Text, nullable=True)
    
    # Timeline
    first_detected = Column(JSON, nullable=True)
    last_detected = Column(JSON, nullable=True)
    resolved_date = Column(JSON, nullable=True)
    
    # Unique constraint
    __table_args__ = (
        UniqueConstraint('vulnerability_id', 'package_id', 'file_path', 'scan_id', 
                        name='uq_vulnerability_package_match'),
    )
    
    # Relationships
    vulnerability = relationship("Vulnerability", back_populates="vulnerability_matches")
    package = relationship("Package", back_populates="vulnerability_matches")
    
    def _validate(self) -> List[str]:
        """Custom validation for vulnerability match model."""
        errors = []
        
        if self.confidence_score < 0 or self.confidence_score > 1:
            errors.append("Confidence score must be between 0 and 1")
        
        if not self.matcher_name or len(self.matcher_name.strip()) == 0:
            errors.append("Matcher name cannot be empty")
            
        if self.risk_score and (self.risk_score < 0 or self.risk_score > 10):
            errors.append("Risk score must be between 0 and 10")
            
        return errors
    
    def calculate_risk_score(self) -> float:
        """Calculate context-aware risk score."""
        base_score = 0
        
        # Base vulnerability score
        if hasattr(self.vulnerability, 'cvss_score') and self.vulnerability.cvss_score:
            base_score = self.vulnerability.cvss_score
        
        # Confidence adjustment
        confidence_factor = self.confidence_score or 0.5
        
        # Exploitability factor
        exploit_factor = 1.0
        if self.exploitable_in_context:
            exploit_factor = 1.5
        elif hasattr(self.vulnerability, 'exploit_available') and self.vulnerability.exploit_available:
            exploit_factor = 1.3
        
        # Business impact factor
        impact_factors = {
            "critical": 1.5,
            "high": 1.2,
            "medium": 1.0,
            "low": 0.8
        }
        impact_factor = impact_factors.get(self.business_impact or "medium", 1.0)
        
        # Calculate final score
        risk_score = base_score * confidence_factor * exploit_factor * impact_factor
        self.risk_score = min(risk_score, 10.0)  # Cap at 10
        
        return self.risk_score
    
    def is_actionable(self) -> bool:
        """Check if this match requires action."""
        return (
            self.status == VulnerabilityStatus.OPEN and
            not self.suppressed and
            self.confidence_score > 0.7 and
            (self.risk_score or 0) > 4.0
        )