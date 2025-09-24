"""SBOM (Software Bill of Materials) schema definitions."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, validator


class SBOMComponent(BaseModel):
    """SBOM component model."""
    
    id: str = Field(..., description="Component unique identifier")
    type: str = Field(..., description="Component type (library, application, etc.)")
    name: str = Field(..., description="Component name")
    version: Optional[str] = Field(None, description="Component version")
    namespace: Optional[str] = Field(None, description="Component namespace")
    supplier: Optional[str] = Field(None, description="Component supplier")
    author: Optional[str] = Field(None, description="Component author")
    publisher: Optional[str] = Field(None, description="Component publisher")
    group: Optional[str] = Field(None, description="Component group")
    description: Optional[str] = Field(None, description="Component description")
    scope: Optional[str] = Field(None, description="Component scope")
    hashes: Optional[List[Dict[str, str]]] = Field(None, description="Component hashes")
    licenses: Optional[List[str]] = Field(None, description="Component licenses")
    copyright: Optional[str] = Field(None, description="Component copyright")
    cpe: Optional[str] = Field(None, description="Common Platform Enumeration")
    purl: Optional[str] = Field(None, description="Package URL")
    external_references: Optional[List[Dict[str, str]]] = Field(None, description="External references")
    dependencies: Optional[List[str]] = Field(None, description="Component dependencies")
    properties: Optional[Dict[str, Any]] = Field(None, description="Additional properties")
    
    @validator('type')
    def validate_type(cls, v):
        """Validate component type."""
        valid_types = [
            'application', 'framework', 'library', 'container', 'operating-system',
            'device', 'firmware', 'file', 'machine-learning-model', 'data'
        ]
        if v not in valid_types:
            raise ValueError(f'Invalid component type: {v}. Valid types: {valid_types}')
        return v
    
    @validator('hashes')
    def validate_hashes(cls, v):
        """Validate hash format."""
        if v:
            for hash_obj in v:
                if not isinstance(hash_obj, dict):
                    raise ValueError('Hash must be a dictionary')
                if 'alg' not in hash_obj or 'content' not in hash_obj:
                    raise ValueError('Hash must contain "alg" and "content" fields')
        return v


class SBOMVulnerability(BaseModel):
    """SBOM vulnerability model."""
    
    id: str = Field(..., description="Vulnerability ID (CVE, etc.)")
    source: str = Field(..., description="Vulnerability source")
    ratings: Optional[List[Dict[str, Any]]] = Field(None, description="Vulnerability ratings")
    cwes: Optional[List[int]] = Field(None, description="CWE identifiers")
    description: Optional[str] = Field(None, description="Vulnerability description")
    detail: Optional[str] = Field(None, description="Vulnerability details")
    recommendation: Optional[str] = Field(None, description="Remediation recommendation")
    advisories: Optional[List[Dict[str, str]]] = Field(None, description="Security advisories")
    created: Optional[datetime] = Field(None, description="Creation timestamp")
    published: Optional[datetime] = Field(None, description="Publication timestamp")
    updated: Optional[datetime] = Field(None, description="Last update timestamp")
    affects: Optional[List[str]] = Field(None, description="Affected components")
    properties: Optional[Dict[str, Any]] = Field(None, description="Additional properties")
    
    @validator('ratings')
    def validate_ratings(cls, v):
        """Validate ratings format."""
        if v:
            for rating in v:
                if not isinstance(rating, dict):
                    raise ValueError('Rating must be a dictionary')
                if 'score' not in rating or 'severity' not in rating:
                    raise ValueError('Rating must contain "score" and "severity" fields')
                
                # Validate score range
                score = rating.get('score')
                if isinstance(score, (int, float)) and not (0 <= score <= 10):
                    raise ValueError('Score must be between 0 and 10')
        return v


class SBOMMetadata(BaseModel):
    """SBOM metadata model."""
    
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="SBOM creation timestamp")
    tools: Optional[List[Dict[str, str]]] = Field(None, description="Tools used to create SBOM")
    authors: Optional[List[Dict[str, str]]] = Field(None, description="SBOM authors")
    supplier: Optional[Dict[str, str]] = Field(None, description="SBOM supplier")
    manufacturer: Optional[Dict[str, str]] = Field(None, description="SBOM manufacturer")
    licenses: Optional[List[str]] = Field(None, description="SBOM licenses")
    properties: Optional[Dict[str, Any]] = Field(None, description="Additional metadata properties")


class SBOMSchema(BaseModel):
    """Main SBOM schema."""
    
    # Required fields
    bom_format: str = Field(..., description="BOM format (CycloneDX, SPDX, etc.)")
    spec_version: str = Field(..., description="BOM specification version")
    serial_number: Optional[str] = Field(None, description="BOM serial number")
    version: int = Field(default=1, description="BOM version")
    
    # Metadata
    metadata: Optional[SBOMMetadata] = Field(None, description="SBOM metadata")
    
    # Components
    components: List[SBOMComponent] = Field(..., description="SBOM components")
    
    # Services (for service-oriented architectures)
    services: Optional[List[Dict[str, Any]]] = Field(None, description="SBOM services")
    
    # External references
    external_references: Optional[List[Dict[str, str]]] = Field(None, description="External references")
    
    # Dependencies
    dependencies: Optional[List[Dict[str, List[str]]]] = Field(None, description="Component dependencies")
    
    # Compositions
    compositions: Optional[List[Dict[str, Any]]] = Field(None, description="SBOM compositions")
    
    # Vulnerabilities
    vulnerabilities: Optional[List[SBOMVulnerability]] = Field(None, description="Known vulnerabilities")
    
    # Annotations
    annotations: Optional[List[Dict[str, str]]] = Field(None, description="SBOM annotations")
    
    # Formulation (build/deployment information)
    formulation: Optional[List[Dict[str, Any]]] = Field(None, description="Build formulation")
    
    # Properties
    properties: Optional[Dict[str, Any]] = Field(None, description="Additional properties")
    
    # Ingestion metadata
    ingestion_id: UUID = Field(default_factory=uuid4, description="Ingestion unique identifier")
    ingestion_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Ingestion timestamp")
    source_system: Optional[str] = Field(None, description="Source system identifier")
    source_environment: Optional[str] = Field(None, description="Source environment")
    
    @validator('bom_format')
    def validate_bom_format(cls, v):
        """Validate BOM format."""
        valid_formats = ['CycloneDX', 'SPDX', 'SWID']
        if v not in valid_formats:
            raise ValueError(f'Invalid BOM format: {v}. Valid formats: {valid_formats}')
        return v
    
    @validator('spec_version')
    def validate_spec_version(cls, v):
        """Validate specification version format."""
        import re
        if not re.match(r'^\d+\.\d+(\.\d+)?$', v):
            raise ValueError('Specification version must be in format X.Y or X.Y.Z')
        return v
    
    @validator('components')
    def validate_components_not_empty(cls, v):
        """Ensure components list is not empty."""
        if not v:
            raise ValueError('SBOM must contain at least one component')
        return v
    
    @validator('dependencies')
    def validate_dependencies(cls, v):
        """Validate dependencies format."""
        if v:
            for dep in v:
                if not isinstance(dep, dict):
                    raise ValueError('Dependency must be a dictionary')
                if 'ref' not in dep or 'dependsOn' not in dep:
                    raise ValueError('Dependency must contain "ref" and "dependsOn" fields')
        return v
    
    class Config:
        """Pydantic configuration."""
        
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: lambda v: str(v),
        }
        
        schema_extra = {
            "example": {
                "bom_format": "CycloneDX",
                "spec_version": "1.5",
                "serial_number": "urn:uuid:3e671687-395b-41f5-a30f-a58921a69b79",
                "version": 1,
                "metadata": {
                    "timestamp": "2023-01-01T00:00:00Z",
                    "tools": [
                        {
                            "vendor": "ACME Corp",
                            "name": "ACME SBOM Tool",
                            "version": "1.0.0"
                        }
                    ]
                },
                "components": [
                    {
                        "id": "pkg:npm/express@4.18.2",
                        "type": "library",
                        "name": "express",
                        "version": "4.18.2",
                        "purl": "pkg:npm/express@4.18.2",
                        "licenses": ["MIT"]
                    }
                ],
                "vulnerabilities": [
                    {
                        "id": "CVE-2023-1234",
                        "source": "NVD",
                        "ratings": [
                            {
                                "score": 7.5,
                                "severity": "high",
                                "method": "CVSSv3"
                            }
                        ],
                        "description": "Example vulnerability description"
                    }
                ]
            }
        }