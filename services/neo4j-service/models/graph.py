"""
Neo4j Graph Models for Dependency Analysis

This module defines the data models and structures for storing dependency graphs
in Neo4j for supply chain security analysis.
"""

from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Set
from enum import Enum
from dataclasses import dataclass, field
from pydantic import BaseModel, Field, validator
import uuid

from shared.observability.logging import get_logger
from shared.config.settings import get_settings

logger = get_logger(__name__)


class ComponentType(str, Enum):
    """Types of software components."""
    LIBRARY = "library"
    FRAMEWORK = "framework"
    APPLICATION = "application"
    CONTAINER = "container"
    OPERATING_SYSTEM = "operating_system"
    FIRMWARE = "firmware"
    HARDWARE = "hardware"
    FILE = "file"
    DEVICE = "device"
    SERVICE = "service"


class RelationshipType(str, Enum):
    """Types of dependency relationships."""
    DEPENDS_ON = "depends_on"
    CONTAINS = "contains"
    PREREQUISITE = "prerequisite"
    PROVIDES = "provides"
    PATCHES = "patches"
    REPLACES = "replaces"
    EXTENDS = "extends"
    IMPLEMENTS = "implements"
    BUNDLED_WITH = "bundled_with"
    RUNTIME_DEPENDENCY = "runtime_dependency"
    BUILD_DEPENDENCY = "build_dependency"
    TEST_DEPENDENCY = "test_dependency"
    OPTIONAL_DEPENDENCY = "optional_dependency"


class RiskLevel(str, Enum):
    """Risk severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class BaseGraphModel(BaseModel):
    """Base model for graph entities."""
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    
    @validator('created_at', 'updated_at')
    def validate_timestamps(cls, v):
        if v.tzinfo is None:
            v = v.replace(tzinfo=timezone.utc)
        return v
    
    class Config:
        use_enum_values = True


class ComponentNode(BaseGraphModel):
    """Component node in the dependency graph."""
    name: str = Field(...)
    version: str = Field(...)
    component_type: ComponentType = Field(...)
    
    # Package identification
    namespace: Optional[str] = None
    language: Optional[str] = None
    ecosystem: Optional[str] = None
    purl: Optional[str] = None  # Package URL
    cpe: Optional[str] = None   # Common Platform Enumeration
    
    # Supplier information
    supplier: Optional[str] = None
    author: Optional[str] = None
    homepage: Optional[str] = None
    repository_url: Optional[str] = None
    description: Optional[str] = None
    
    # License information
    license_declared: Optional[str] = None
    license_concluded: Optional[str] = None
    copyright: Optional[str] = None
    
    # File verification
    checksum_sha1: Optional[str] = None
    checksum_sha256: Optional[str] = None
    checksum_md5: Optional[str] = None
    download_url: Optional[str] = None
    files_analyzed: bool = Field(default=False)
    verification_code: Optional[str] = None
    
    # Risk assessment
    risk_score: float = Field(default=0.0, ge=0.0, le=10.0)
    confidence_score: float = Field(default=1.0, ge=0.0, le=1.0)
    popularity_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    maintenance_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    
    # Metadata
    properties: Dict[str, Any] = Field(default_factory=dict)
    labels: List[str] = Field(default_factory=list)


class DependencyRelationship(BaseGraphModel):
    """Dependency relationship between components."""
    from_component_id: str = Field(...)
    to_component_id: str = Field(...)
    relationship_type: RelationshipType = Field(...)
    
    # Dependency characteristics
    scope: Optional[str] = None  # runtime, compile, test, provided, etc.
    version_constraint: Optional[str] = None
    is_optional: bool = Field(default=False)
    is_direct: bool = Field(default=True)
    depth: int = Field(default=1, ge=1)
    introduced_by: Optional[str] = None
    
    # Verification
    confidence_score: float = Field(default=1.0, ge=0.0, le=1.0)
    last_verified: Optional[datetime] = None
    
    # Metadata
    properties: Dict[str, Any] = Field(default_factory=dict)


class VulnerabilityNode(BaseGraphModel):
    """Vulnerability node in the graph."""
    vulnerability_id: str = Field(...)
    cve_id: Optional[str] = None
    title: str = Field(...)
    description: Optional[str] = None
    
    # Severity information
    severity: RiskLevel = Field(...)
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None
    
    # Timeline
    published_date: datetime = Field(...)
    modified_date: Optional[datetime] = None
    
    # Source information
    source: str = Field(...)
    source_url: Optional[str] = None
    
    # Exploit information
    exploitability: Optional[str] = None
    impact: Optional[str] = None
    exploit_available: bool = Field(default=False)
    exploit_in_wild: bool = Field(default=False)
    
    # Patch information
    patch_available: bool = Field(default=False)
    patch_date: Optional[datetime] = None
    
    # Affected versions
    affected_versions: List[str] = Field(default_factory=list)
    fixed_versions: List[str] = Field(default_factory=list)
    
    # Metadata
    properties: Dict[str, Any] = Field(default_factory=dict)


class LicenseNode(BaseGraphModel):
    """License node in the graph."""
    license_id: str = Field(...)
    name: str = Field(...)
    full_name: Optional[str] = None
    
    # License characteristics
    is_osi_approved: bool = Field(default=False)
    is_fsf_approved: bool = Field(default=False)
    is_copyleft: bool = Field(default=False)
    is_permissive: bool = Field(default=False)
    
    # License text
    text: Optional[str] = None
    url: Optional[str] = None
    
    # Compatibility
    compatible_licenses: List[str] = Field(default_factory=list)
    incompatible_licenses: List[str] = Field(default_factory=list)
    
    # Risk assessment
    compliance_risk: RiskLevel = Field(default=RiskLevel.LOW)
    
    # Metadata
    properties: Dict[str, Any] = Field(default_factory=dict)


@dataclass
class GraphQuery:
    """Query model for graph operations."""
    query_type: str
    start_node_id: Optional[str] = None
    node_types: List[str] = field(default_factory=list)
    relationship_types: List[str] = field(default_factory=list)
    filters: Dict[str, Any] = field(default_factory=dict)
    max_depth: int = 5
    limit: int = 1000
    include_properties: bool = True


@dataclass
class GraphResult:
    """Result model for graph queries."""
    query: GraphQuery
    nodes: List[Dict[str, Any]]
    relationships: List[Dict[str, Any]]
    total_nodes: int
    total_relationships: int
    execution_time: float
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphPath:
    """Represents a path through the dependency graph."""
    nodes: List[Dict[str, Any]]
    relationships: List[Dict[str, Any]]
    depth: int
    risk_score: float = 0.0
    vulnerability_count: int = 0
    license_conflicts: List[str] = field(default_factory=list)
    maintenance_issues: Dict[str, Any] = field(default_factory=dict)


class SupplyChainRisk(BaseModel):
    """Supply chain risk analysis result."""
    component_id: str = Field(...)
    component_name: str = Field(...)
    component_version: str = Field(...)
    
    # Risk assessment
    overall_risk_score: float = Field(ge=0.0, le=10.0)
    risk_level: RiskLevel = Field(...)
    
    # Detailed analysis
    component_risk: Dict[str, Any] = Field(...)
    dependency_risks: List[Dict[str, Any]] = Field(default_factory=list)
    vulnerability_count: int = Field(default=0)
    high_risk_dependencies: List[Dict[str, Any]] = Field(default_factory=list)
    critical_paths: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Recommendations
    recommendations: List[str] = Field(default_factory=list)
    
    # Analysis metadata
    analysis_metadata: Dict[str, Any] = Field(default_factory=dict)
    
    class Config:
        use_enum_values = True


class LicenseCompliance(BaseModel):
    """License compliance analysis result."""
    component_id: str = Field(...)
    policy_name: str = Field(...)
    compliance_status: str = Field(...)  # compliant, non_compliant, review_required
    
    # Issues found
    issues: List[Dict[str, Any]] = Field(default_factory=list)
    license_distribution: Dict[str, int] = Field(default_factory=dict)
    
    # Recommendations
    recommendations: List[str] = Field(default_factory=list)
    
    # Analysis metadata
    analysis_metadata: Dict[str, Any] = Field(default_factory=dict)


class VulnerabilityImpact(BaseModel):
    """Vulnerability impact analysis result."""
    vulnerability_id: str = Field(...)
    
    # Impact assessment
    directly_affected_components: int = Field(default=0)
    total_affected_projects: int = Field(default=0)
    blast_radius: int = Field(default=0)
    
    # Detailed impact tree
    impact_tree: Dict[str, Any] = Field(default_factory=dict)
    critical_paths: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Risk assessment
    risk_assessment: Dict[str, Any] = Field(default_factory=dict)
    
    # Analysis metadata
    analysis_metadata: Dict[str, Any] = Field(default_factory=dict)


# Factory functions for creating graph models
def create_component_node(
    name: str,
    version: str,
    component_type: ComponentType,
    **kwargs
) -> ComponentNode:
    """Create a component node."""
    return ComponentNode(
        name=name,
        version=version,
        component_type=component_type,
        **kwargs
    )


def create_dependency_relationship(
    from_component_id: str,
    to_component_id: str,
    relationship_type: RelationshipType,
    **kwargs
) -> DependencyRelationship:
    """Create a dependency relationship."""
    return DependencyRelationship(
        from_component_id=from_component_id,
        to_component_id=to_component_id,
        relationship_type=relationship_type,
        **kwargs
    )


def create_vulnerability_node(
    vulnerability_id: str,
    title: str,
    severity: RiskLevel,
    published_date: datetime,
    source: str,
    **kwargs
) -> VulnerabilityNode:
    """Create a vulnerability node."""
    return VulnerabilityNode(
        vulnerability_id=vulnerability_id,
        title=title,
        severity=severity,
        published_date=published_date,
        source=source,
        **kwargs
    )


def create_license_node(
    license_id: str,
    name: str,
    **kwargs
) -> LicenseNode:
    """Create a license node."""
    return LicenseNode(
        license_id=license_id,
        name=name,
        **kwargs
    )