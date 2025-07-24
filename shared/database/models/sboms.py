"""
SBOM Models

Database models for Software Bills of Materials, components, licenses, and dependencies.
"""

from datetime import datetime
from enum import Enum
from typing import Optional, Dict, Any, List

from sqlalchemy import Column, String, Text, JSON, Enum as SQLEnum, ForeignKey, Float, Integer, Boolean, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID, JSONB, ARRAY
from sqlalchemy.orm import relationship
import uuid

from .base import BaseModel


class SBOMFormat(str, Enum):
    """SBOM document formats."""
    SPDX_JSON = "spdx-json"
    SPDX_XML = "spdx-xml"
    SPDX_YAML = "spdx-yaml"
    CYCLONEDX_JSON = "cyclonedx-json"
    CYCLONEDX_XML = "cyclonedx-xml"
    SYFT_JSON = "syft-json"
    CUSTOM = "custom"


class ComponentType(str, Enum):
    """Types of software components."""
    LIBRARY = "library"
    FRAMEWORK = "framework"
    APPLICATION = "application"
    CONTAINER = "container"
    OPERATING_SYSTEM = "operating-system"
    DEVICE = "device"
    FIRMWARE = "firmware"
    FILE = "file"
    DATA = "data"
    DOCUMENTATION = "documentation"
    OTHER = "other"


class LicenseType(str, Enum):
    """License categories."""
    PERMISSIVE = "permissive"
    COPYLEFT = "copyleft"
    COPYLEFT_LIMITED = "copyleft-limited"
    PROPRIETARY = "proprietary"
    PUBLIC_DOMAIN = "public-domain"
    UNKNOWN = "unknown"
    NONE = "none"


class RelationshipType(str, Enum):
    """Component relationship types (SPDX)."""
    DESCRIBES = "describes"
    DESCRIBED_BY = "described_by"
    CONTAINS = "contains"
    CONTAINED_BY = "contained_by"
    DEPENDS_ON = "depends_on"
    DEPENDENCY_OF = "dependency_of"
    GENERATES = "generates"
    GENERATED_FROM = "generated_from"
    ANCESTOR_OF = "ancestor_of"
    DESCENDANT_OF = "descendant_of"
    VARIANT_OF = "variant_of"
    BUILD_TOOL_OF = "build_tool_of"
    DEV_TOOL_OF = "dev_tool_of"
    TEST_TOOL_OF = "test_tool_of"
    RUNTIME_DEPENDENCY_OF = "runtime_dependency_of"
    EXAMPLE_OF = "example_of"
    DOCUMENTATION_OF = "documentation_of"
    OPTIONAL_COMPONENT_OF = "optional_component_of"
    METAFILE_OF = "metafile_of"
    PACKAGE_OF = "package_of"
    AMENDS = "amends"
    PREREQUISITE_FOR = "prerequisite_for"
    HAS_PREREQUISITE = "has_prerequisite"
    OTHER = "other"


class SBOM(BaseModel):
    """Software Bill of Materials document."""
    
    __tablename__ = "sboms"
    
    # SBOM identification
    name = Column(String(255), nullable=False)
    document_id = Column(String(500), unique=True, nullable=False)  # SPDX ID or CycloneDX serial number
    version = Column(String(50), nullable=False)
    
    # Format and specification
    format = Column(SQLEnum(SBOMFormat), nullable=False)
    spec_version = Column(String(50), nullable=False)  # SPDX 2.3, CycloneDX 1.4, etc.
    
    # Document metadata
    creators = Column(JSONB, default=list, nullable=False)  # Tools, organizations, people
    created_timestamp = Column(JSON, nullable=False)
    document_namespace = Column(String(500), nullable=True)
    license_list_version = Column(String(50), nullable=True)
    
    # Target information
    target_name = Column(String(255), nullable=False)  # What the SBOM describes
    target_version = Column(String(100), nullable=True)
    target_type = Column(String(100), nullable=False)  # image, repository, application
    target_identifier = Column(String(500), nullable=False)  # Image name, repo URL, etc.
    
    # Raw document data
    raw_document = Column(JSONB, nullable=False)  # Complete SBOM document
    document_hash = Column(String(64), nullable=False)  # SHA256 of raw document
    
    # Analysis metadata
    total_components = Column(Integer, default=0, nullable=False)
    unique_licenses = Column(Integer, default=0, nullable=False)
    vulnerability_count = Column(Integer, default=0, nullable=False)
    risk_score = Column(Float, nullable=True)
    
    # Processing status
    processed = Column(Boolean, default=False, nullable=False)
    analyzed = Column(Boolean, default=False, nullable=False)
    validated = Column(Boolean, default=False, nullable=False)
    validation_errors = Column(JSONB, default=list, nullable=False)
    
    # Source information
    generated_by = Column(String(200), nullable=True)  # Tool that generated SBOM
    generator_version = Column(String(100), nullable=True)
    scan_id = Column(UUID(as_uuid=True), nullable=True)  # Associated scan
    
    # Organization context
    organization_id = Column(UUID(as_uuid=True), nullable=True)
    project_id = Column(UUID(as_uuid=True), nullable=True)
    
    # Relationships
    components = relationship("Component", back_populates="sbom", cascade="all, delete-orphan")
    dependencies = relationship("Dependency", back_populates="sbom", cascade="all, delete-orphan")
    
    def _validate(self) -> List[str]:
        """Custom validation for SBOM model."""
        errors = []
        
        if not self.name or len(self.name.strip()) == 0:
            errors.append("SBOM name cannot be empty")
        
        if not self.document_id or len(self.document_id.strip()) == 0:
            errors.append("Document ID cannot be empty")
        
        if not self.target_name or len(self.target_name.strip()) == 0:
            errors.append("Target name cannot be empty")
            
        if not self.document_hash or len(self.document_hash) != 64:
            errors.append("Invalid document hash")
            
        return errors
    
    def calculate_risk_score(self) -> float:
        """Calculate overall risk score based on components and vulnerabilities."""
        if self.total_components == 0:
            return 0.0
        
        # Base score from vulnerability ratio
        vuln_ratio = self.vulnerability_count / self.total_components
        base_score = min(vuln_ratio * 10, 10.0)
        
        # Adjust for license compliance risk
        license_risk = self.get_license_risk_factor()
        
        # Calculate final score
        final_score = (base_score * 0.7) + (license_risk * 0.3)
        self.risk_score = min(final_score, 10.0)
        
        return self.risk_score
    
    def get_license_risk_factor(self) -> float:
        """Calculate license compliance risk factor."""
        if not hasattr(self, 'components'):
            return 0.0
        
        risk_scores = {"proprietary": 3, "copyleft": 2, "copyleft-limited": 1.5, 
                      "unknown": 2.5, "permissive": 0.5, "public-domain": 0}
        
        total_risk = 0
        component_count = 0
        
        for component in self.components:
            if component.license:
                risk = risk_scores.get(component.license.license_type.value, 1)
                total_risk += risk
                component_count += 1
        
        return total_risk / max(component_count, 1)
    
    def get_summary(self) -> Dict[str, Any]:
        """Get SBOM summary statistics."""
        return {
            "name": self.name,
            "target": self.target_name,
            "version": self.target_version,
            "format": self.format.value,
            "total_components": self.total_components,
            "unique_licenses": self.unique_licenses,
            "vulnerability_count": self.vulnerability_count,
            "risk_score": self.risk_score,
            "created": self.created_timestamp
        }


class Component(BaseModel):
    """Individual software component in an SBOM."""
    
    __tablename__ = "components"
    
    # Relationship to SBOM
    sbom_id = Column(UUID(as_uuid=True), ForeignKey("sboms.id"), nullable=False)
    
    # Component identification
    name = Column(String(255), nullable=False)
    spdx_id = Column(String(200), nullable=True)  # SPDX element ID
    component_type = Column(SQLEnum(ComponentType), nullable=False)
    
    # Version information
    version = Column(String(100), nullable=True)
    version_range = Column(String(200), nullable=True)
    
    # Package information
    package_url = Column(String(500), nullable=True)  # PURL
    cpe = Column(String(500), nullable=True)  # Common Platform Enumeration
    supplier = Column(String(200), nullable=True)
    originator = Column(String(200), nullable=True)
    
    # File information
    file_name = Column(String(500), nullable=True)
    file_path = Column(String(1000), nullable=True)
    file_hashes = Column(JSONB, default=dict, nullable=False)
    file_size = Column(Integer, nullable=True)
    
    # License information
    license_id = Column(UUID(as_uuid=True), ForeignKey("licenses.id"), nullable=True)
    license_concluded = Column(String(200), nullable=True)
    license_declared = Column(String(200), nullable=True)
    copyright_text = Column(Text, nullable=True)
    
    # Description and metadata
    description = Column(Text, nullable=True)
    homepage = Column(String(500), nullable=True)
    download_location = Column(String(500), nullable=True)
    
    # Security information
    vulnerability_count = Column(Integer, default=0, nullable=False)
    risk_score = Column(Float, nullable=True)
    security_issues = Column(JSONB, default=list, nullable=False)
    
    # Analysis flags
    analyzed = Column(Boolean, default=False, nullable=False)
    external_reference = Column(Boolean, default=False, nullable=False)
    modified = Column(Boolean, default=False, nullable=False)
    
    # Layer information (for containers)
    layer_id = Column(String(100), nullable=True)
    layer_index = Column(Integer, nullable=True)
    
    # Additional metadata
    additional_metadata = Column(JSONB, default=dict, nullable=False)
    external_references = Column(JSONB, default=list, nullable=False)
    
    # Relationships
    sbom = relationship("SBOM", back_populates="components")
    license = relationship("License", back_populates="components")
    dependencies_as_source = relationship("Dependency", foreign_keys="Dependency.source_component_id", back_populates="source_component")
    dependencies_as_target = relationship("Dependency", foreign_keys="Dependency.target_component_id", back_populates="target_component")
    
    def _validate(self) -> List[str]:
        """Custom validation for component model."""
        errors = []
        
        if not self.name or len(self.name.strip()) == 0:
            errors.append("Component name cannot be empty")
            
        if self.file_size and self.file_size < 0:
            errors.append("File size cannot be negative")
            
        return errors
    
    def calculate_risk_score(self) -> float:
        """Calculate component risk score."""
        base_score = 0
        
        # Vulnerability impact
        if self.vulnerability_count > 0:
            base_score += min(self.vulnerability_count * 2, 8)
        
        # License risk
        if self.license:
            license_risks = {
                LicenseType.PROPRIETARY: 3,
                LicenseType.COPYLEFT: 2,
                LicenseType.UNKNOWN: 2.5,
                LicenseType.PERMISSIVE: 0.5
            }
            base_score += license_risks.get(self.license.license_type, 1)
        
        # External component risk
        if self.external_reference:
            base_score += 1
        
        self.risk_score = min(base_score, 10.0)
        return self.risk_score
    
    def get_package_coordinates(self) -> str:
        """Get package coordinates string."""
        if self.package_url:
            return self.package_url
        
        coords = f"{self.name}"
        if self.version:
            coords += f"@{self.version}"
        if self.supplier:
            coords = f"{self.supplier}/{coords}"
        
        return coords


class License(BaseModel):
    """Software license information."""
    
    __tablename__ = "licenses"
    
    # License identification
    license_id = Column(String(100), unique=True, nullable=False)  # SPDX license ID
    name = Column(String(200), nullable=False)
    license_type = Column(SQLEnum(LicenseType), nullable=False)
    
    # License details
    text = Column(Text, nullable=True)
    url = Column(String(500), nullable=True)
    osi_approved = Column(Boolean, default=False, nullable=False)
    fsf_approved = Column(Boolean, default=False, nullable=False)
    deprecated = Column(Boolean, default=False, nullable=False)
    
    # License characteristics
    commercial_use = Column(Boolean, nullable=True)
    distribution = Column(Boolean, nullable=True)
    modification = Column(Boolean, nullable=True)
    private_use = Column(Boolean, nullable=True)
    patent_use = Column(Boolean, nullable=True)
    
    # Obligations
    include_copyright = Column(Boolean, nullable=True)
    include_license = Column(Boolean, nullable=True)
    disclose_source = Column(Boolean, nullable=True)
    same_license = Column(Boolean, nullable=True)
    state_changes = Column(Boolean, nullable=True)
    
    # Risk assessment
    compliance_risk = Column(String(50), nullable=True)  # low, medium, high
    legal_review_required = Column(Boolean, default=False, nullable=False)
    business_use_allowed = Column(Boolean, nullable=True)
    
    # Metadata
    spdx_version = Column(String(50), nullable=True)
    reference_url = Column(String(500), nullable=True)
    exception_ids = Column(ARRAY(String), default=list, nullable=False)
    
    # Relationships
    components = relationship("Component", back_populates="license")
    
    def _validate(self) -> List[str]:
        """Custom validation for license model."""
        errors = []
        
        if not self.license_id or len(self.license_id.strip()) == 0:
            errors.append("License ID cannot be empty")
        
        if not self.name or len(self.name.strip()) == 0:
            errors.append("License name cannot be empty")
            
        return errors
    
    def get_risk_level(self) -> str:
        """Get license risk level for compliance."""
        if self.compliance_risk:
            return self.compliance_risk
        
        # Auto-calculate based on license type and characteristics
        if self.license_type == LicenseType.PROPRIETARY:
            return "high"
        elif self.license_type == LicenseType.COPYLEFT:
            return "medium"
        elif self.license_type == LicenseType.UNKNOWN:
            return "high"
        else:
            return "low"
    
    def requires_source_disclosure(self) -> bool:
        """Check if license requires source code disclosure."""
        return bool(self.disclose_source)
    
    def is_compatible_for_commercial_use(self) -> bool:
        """Check if license allows commercial use."""
        return bool(self.commercial_use and self.business_use_allowed)


class Dependency(BaseModel):
    """Dependency relationship between components."""
    
    __tablename__ = "dependencies"
    
    # Relationship to SBOM
    sbom_id = Column(UUID(as_uuid=True), ForeignKey("sboms.id"), nullable=False)
    
    # Component relationships
    source_component_id = Column(UUID(as_uuid=True), ForeignKey("components.id"), nullable=False)
    target_component_id = Column(UUID(as_uuid=True), ForeignKey("components.id"), nullable=False)
    
    # Relationship details
    relationship_type = Column(SQLEnum(RelationshipType), nullable=False)
    scope = Column(String(50), nullable=True)  # runtime, build, test, dev
    is_direct = Column(Boolean, default=True, nullable=False)
    is_optional = Column(Boolean, default=False, nullable=False)
    
    # Version constraints
    version_constraint = Column(String(200), nullable=True)
    resolved_version = Column(String(100), nullable=True)
    
    # Dependency metadata
    description = Column(Text, nullable=True)
    confidence_score = Column(Float, default=1.0, nullable=False)
    
    # Risk information
    introduces_vulnerabilities = Column(Boolean, default=False, nullable=False)
    vulnerability_count = Column(Integer, default=0, nullable=False)
    risk_impact = Column(String(50), nullable=True)  # low, medium, high, critical
    
    # Unique constraint to prevent duplicate relationships
    __table_args__ = (
        UniqueConstraint('sbom_id', 'source_component_id', 'target_component_id', 
                        'relationship_type', name='uq_dependency_relationship'),
    )
    
    # Relationships
    sbom = relationship("SBOM", back_populates="dependencies")
    source_component = relationship("Component", foreign_keys=[source_component_id], back_populates="dependencies_as_source")
    target_component = relationship("Component", foreign_keys=[target_component_id], back_populates="dependencies_as_target")
    
    def _validate(self) -> List[str]:
        """Custom validation for dependency model."""
        errors = []
        
        if self.source_component_id == self.target_component_id:
            errors.append("Component cannot depend on itself")
        
        if self.confidence_score < 0 or self.confidence_score > 1:
            errors.append("Confidence score must be between 0 and 1")
            
        return errors
    
    def calculate_risk_impact(self) -> str:
        """Calculate risk impact of this dependency."""
        if self.vulnerability_count == 0:
            return "low"
        elif self.vulnerability_count >= 10:
            return "critical"
        elif self.vulnerability_count >= 5:
            return "high"
        else:
            return "medium"
    
    def is_critical_path(self) -> bool:
        """Check if this is a critical dependency path."""
        return (
            self.is_direct and 
            self.relationship_type in [RelationshipType.DEPENDS_ON, RelationshipType.CONTAINS] and
            self.scope in ["runtime", None]
        )