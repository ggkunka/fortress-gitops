"""
MongoDB Models for SBOM Document Storage

This module defines the MongoDB schema for storing Software Bill of Materials (SBOM)
documents and related metadata.
"""

from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from uuid import uuid4
from enum import Enum
from bson import ObjectId
from pydantic import BaseModel, Field, validator
from pymongo import MongoClient
from motor.motor_asyncio import AsyncIOMotorClient

from shared.observability.logging import get_logger
from shared.config.settings import get_settings

logger = get_logger(__name__)


class SBOMFormat(str, Enum):
    """SBOM document formats."""
    SPDX_JSON = "spdx-json"
    CYCLONEDX_JSON = "cyclonedx-json"
    SPDX_XML = "spdx-xml"
    CYCLONEDX_XML = "cyclonedx-xml"
    SPDX_YAML = "spdx-yaml"
    CYCLONEDX_YAML = "cyclonedx-yaml"
    SPDX_TAG_VALUE = "spdx-tag-value"
    SYFT_JSON = "syft-json"


class SBOMStatus(str, Enum):
    """SBOM document processing status."""
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    ARCHIVED = "archived"


class ComponentType(str, Enum):
    """Component types in SBOM."""
    APPLICATION = "application"
    CONTAINER = "container"
    DEVICE = "device"
    FILE = "file"
    FIRMWARE = "firmware"
    FRAMEWORK = "framework"
    LIBRARY = "library"
    OPERATING_SYSTEM = "operating-system"
    PLATFORM = "platform"
    OTHER = "other"


class LicenseModel(BaseModel):
    """License information model."""
    id: Optional[str] = None
    name: Optional[str] = None
    text: Optional[str] = None
    url: Optional[str] = None
    is_osi_approved: Optional[bool] = None
    is_deprecated: Optional[bool] = None


class VulnerabilityModel(BaseModel):
    """Vulnerability information model."""
    id: str
    cve_id: Optional[str] = None
    severity: str
    score: Optional[float] = None
    vector: Optional[str] = None
    description: Optional[str] = None
    published_date: Optional[datetime] = None
    modified_date: Optional[datetime] = None
    references: Optional[List[str]] = Field(default_factory=list)
    affected_versions: Optional[List[str]] = Field(default_factory=list)
    fixed_versions: Optional[List[str]] = Field(default_factory=list)


class ComponentModel(BaseModel):
    """Component model for SBOM."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    name: str
    version: Optional[str] = None
    type: ComponentType
    supplier: Optional[str] = None
    publisher: Optional[str] = None
    description: Optional[str] = None
    copyright: Optional[str] = None
    homepage: Optional[str] = None
    download_location: Optional[str] = None
    file_name: Optional[str] = None
    package_url: Optional[str] = None  # PURL
    external_references: Optional[List[Dict[str, str]]] = Field(default_factory=list)
    hashes: Optional[Dict[str, str]] = Field(default_factory=dict)
    licenses: Optional[List[LicenseModel]] = Field(default_factory=list)
    vulnerabilities: Optional[List[VulnerabilityModel]] = Field(default_factory=list)
    dependencies: Optional[List[str]] = Field(default_factory=list)
    properties: Optional[Dict[str, Any]] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)


class SBOMMetadata(BaseModel):
    """SBOM metadata model."""
    timestamp: datetime = Field(default_factory=datetime.now)
    tools: Optional[List[Dict[str, str]]] = Field(default_factory=list)
    authors: Optional[List[str]] = Field(default_factory=list)
    supplier: Optional[str] = None
    manufacturer: Optional[str] = None
    lifecycle_phase: Optional[str] = None
    properties: Optional[Dict[str, Any]] = Field(default_factory=dict)


class SBOMDocument(BaseModel):
    """Main SBOM document model."""
    id: str = Field(default_factory=lambda: str(uuid4()))
    mongodb_id: Optional[str] = Field(None, alias="_id")
    
    # Core SBOM fields
    name: str
    version: str
    format: SBOMFormat
    spec_version: str
    data_license: Optional[str] = None
    spdx_id: Optional[str] = None
    document_namespace: Optional[str] = None
    creation_info: Optional[SBOMMetadata] = None
    
    # Document content
    raw_content: str  # Original SBOM content
    parsed_content: Optional[Dict[str, Any]] = None  # Parsed structured content
    components: List[ComponentModel] = Field(default_factory=list)
    
    # Processing metadata
    status: SBOMStatus = SBOMStatus.PENDING
    processing_started_at: Optional[datetime] = None
    processing_completed_at: Optional[datetime] = None
    processing_duration: Optional[int] = None  # seconds
    error_message: Optional[str] = None
    
    # File metadata
    file_size: Optional[int] = None
    file_hash: Optional[str] = None
    file_path: Optional[str] = None
    
    # Security analysis
    total_components: int = 0
    vulnerable_components: int = 0
    high_severity_vulnerabilities: int = 0
    medium_severity_vulnerabilities: int = 0
    low_severity_vulnerabilities: int = 0
    license_risks: Optional[List[str]] = Field(default_factory=list)
    
    # Tracking metadata
    created_at: datetime = Field(default_factory=datetime.now)
    updated_at: datetime = Field(default_factory=datetime.now)
    created_by: str
    updated_by: Optional[str] = None
    source: str  # Where the SBOM came from
    source_reference: Optional[str] = None  # Reference ID from source
    
    # Relationships
    parent_sbom_id: Optional[str] = None
    child_sbom_ids: Optional[List[str]] = Field(default_factory=list)
    related_artifacts: Optional[List[str]] = Field(default_factory=list)
    
    # Compliance and policies
    compliance_status: Optional[Dict[str, Any]] = Field(default_factory=dict)
    policy_violations: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    
    # Tags and categorization
    tags: Optional[List[str]] = Field(default_factory=list)
    category: Optional[str] = None
    environment: Optional[str] = None  # dev, staging, prod
    
    class Config:
        allow_population_by_field_name = True
        arbitrary_types_allowed = True
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            ObjectId: str
        }
    
    @validator('updated_at', pre=True, always=True)
    def set_updated_at(cls, v):
        return datetime.now()


class SBOMQuery(BaseModel):
    """Query model for SBOM searches."""
    name: Optional[str] = None
    version: Optional[str] = None
    format: Optional[SBOMFormat] = None
    status: Optional[SBOMStatus] = None
    created_by: Optional[str] = None
    source: Optional[str] = None
    has_vulnerabilities: Optional[bool] = None
    severity_threshold: Optional[str] = None
    license_pattern: Optional[str] = None
    component_name: Optional[str] = None
    tag: Optional[str] = None
    category: Optional[str] = None
    environment: Optional[str] = None
    date_from: Optional[datetime] = None
    date_to: Optional[datetime] = None
    limit: int = 100
    offset: int = 0
    sort_by: str = "created_at"
    sort_order: str = "desc"  # asc or desc


class SBOMStats(BaseModel):
    """SBOM statistics model."""
    total_sboms: int = 0
    sboms_by_status: Dict[str, int] = Field(default_factory=dict)
    sboms_by_format: Dict[str, int] = Field(default_factory=dict)
    sboms_by_environment: Dict[str, int] = Field(default_factory=dict)
    total_components: int = 0
    total_vulnerabilities: int = 0
    vulnerabilities_by_severity: Dict[str, int] = Field(default_factory=dict)
    top_vulnerable_components: List[Dict[str, Any]] = Field(default_factory=list)
    license_distribution: Dict[str, int] = Field(default_factory=dict)
    processing_stats: Dict[str, Any] = Field(default_factory=dict)


class ComponentQuery(BaseModel):
    """Query model for component searches."""
    name: Optional[str] = None
    version: Optional[str] = None
    type: Optional[ComponentType] = None
    supplier: Optional[str] = None
    has_vulnerabilities: Optional[bool] = None
    license_name: Optional[str] = None
    purl: Optional[str] = None
    limit: int = 100
    offset: int = 0
    sort_by: str = "name"
    sort_order: str = "asc"


# Database connection management
class MongoDBConnection:
    """MongoDB connection manager."""
    
    def __init__(self):
        self.client: Optional[AsyncIOMotorClient] = None
        self.db = None
        self.settings = get_settings()
        
    async def connect(self):
        """Connect to MongoDB."""
        try:
            self.client = AsyncIOMotorClient(self.settings.mongodb_url)
            self.db = self.client[self.settings.mongodb_database]
            
            # Test connection
            await self.client.admin.command('ping')
            logger.info("Connected to MongoDB successfully")
            
            # Create indexes
            await self._create_indexes()
            
        except Exception as e:
            logger.error(f"Failed to connect to MongoDB: {e}")
            raise
    
    async def disconnect(self):
        """Disconnect from MongoDB."""
        if self.client:
            self.client.close()
            logger.info("Disconnected from MongoDB")
    
    async def _create_indexes(self):
        """Create MongoDB indexes for performance."""
        try:
            # SBOM collection indexes
            sbom_collection = self.db.sbom_documents
            
            # Basic indexes
            await sbom_collection.create_index("id", unique=True)
            await sbom_collection.create_index("name")
            await sbom_collection.create_index("version")
            await sbom_collection.create_index("format")
            await sbom_collection.create_index("status")
            await sbom_collection.create_index("created_by")
            await sbom_collection.create_index("source")
            await sbom_collection.create_index("created_at")
            await sbom_collection.create_index("updated_at")
            
            # Compound indexes
            await sbom_collection.create_index([("name", 1), ("version", 1)])
            await sbom_collection.create_index([("status", 1), ("created_at", -1)])
            await sbom_collection.create_index([("source", 1), ("created_at", -1)])
            
            # Security-related indexes
            await sbom_collection.create_index("vulnerable_components")
            await sbom_collection.create_index("high_severity_vulnerabilities")
            await sbom_collection.create_index("tags")
            await sbom_collection.create_index("category")
            await sbom_collection.create_index("environment")
            
            # Component-related indexes
            await sbom_collection.create_index("components.name")
            await sbom_collection.create_index("components.version")
            await sbom_collection.create_index("components.type")
            await sbom_collection.create_index("components.package_url")
            
            # Text search index
            await sbom_collection.create_index([
                ("name", "text"),
                ("description", "text"),
                ("components.name", "text"),
                ("components.description", "text")
            ])
            
            logger.info("MongoDB indexes created successfully")
            
        except Exception as e:
            logger.error(f"Failed to create MongoDB indexes: {e}")
            raise


# Global connection instance
_mongo_connection = MongoDBConnection()


async def get_mongo_connection() -> MongoDBConnection:
    """Get MongoDB connection instance."""
    if not _mongo_connection.client:
        await _mongo_connection.connect()
    return _mongo_connection


async def get_mongo_db():
    """Get MongoDB database instance."""
    connection = await get_mongo_connection()
    return connection.db


def create_sbom_document(
    name: str,
    version: str,
    format: SBOMFormat,
    spec_version: str,
    raw_content: str,
    created_by: str,
    source: str,
    **kwargs
) -> SBOMDocument:
    """Create a new SBOM document."""
    return SBOMDocument(
        name=name,
        version=version,
        format=format,
        spec_version=spec_version,
        raw_content=raw_content,
        created_by=created_by,
        source=source,
        **kwargs
    )


def create_component(
    name: str,
    component_type: ComponentType,
    **kwargs
) -> ComponentModel:
    """Create a new component."""
    return ComponentModel(
        name=name,
        type=component_type,
        **kwargs
    )


def create_vulnerability(
    vuln_id: str,
    severity: str,
    **kwargs
) -> VulnerabilityModel:
    """Create a new vulnerability."""
    return VulnerabilityModel(
        id=vuln_id,
        severity=severity,
        **kwargs
    )


def create_license(
    **kwargs
) -> LicenseModel:
    """Create a new license."""
    return LicenseModel(**kwargs)