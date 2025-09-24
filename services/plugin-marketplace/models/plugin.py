"""
Plugin Marketplace Database Models - Plugin, Review, and Community Models

This module defines the database models for the plugin marketplace including
plugins, reviews, ratings, and community interaction tracking.
"""

import uuid
from datetime import datetime
from typing import Dict, List, Optional, Any
from enum import Enum

from sqlalchemy import Column, String, Text, Integer, Boolean, DateTime, Float, JSON, ForeignKey, Index
from sqlalchemy.dialects.postgresql import UUID, ARRAY
from sqlalchemy.orm import relationship
from sqlalchemy.ext.declarative import declarative_base
from pydantic import BaseModel, Field, validator

from shared.database.base import BaseModel as SharedBaseModel

Base = declarative_base()


class PluginStatus(str, Enum):
    """Plugin status enumeration."""
    DRAFT = "draft"
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    PUBLISHED = "published"
    DEPRECATED = "deprecated"
    SUSPENDED = "suspended"
    REJECTED = "rejected"


class PluginCategory(str, Enum):
    """Plugin category enumeration."""
    THREAT_DETECTION = "threat_detection"
    VULNERABILITY_SCANNER = "vulnerability_scanner"
    INCIDENT_RESPONSE = "incident_response"
    COMPLIANCE = "compliance"
    FORENSICS = "forensics"
    NETWORK_SECURITY = "network_security"
    ENDPOINT_SECURITY = "endpoint_security"
    CLOUD_SECURITY = "cloud_security"
    DATA_ANALYSIS = "data_analysis"
    REPORTING = "reporting"
    INTEGRATION = "integration"
    UTILITY = "utility"
    OTHER = "other"


class PluginType(str, Enum):
    """Plugin type enumeration."""
    ANALYZER = "analyzer"
    COLLECTOR = "collector"
    ENRICHER = "enricher"
    PROCESSOR = "processor"
    EXPORTER = "exporter"
    DASHBOARD = "dashboard"
    CONNECTOR = "connector"
    TOOL = "tool"


class Plugin(SharedBaseModel):
    """Plugin model for marketplace plugins."""
    
    __tablename__ = "plugins"
    
    # Basic information
    name = Column(String(255), nullable=False, index=True)
    slug = Column(String(255), unique=True, nullable=False, index=True)
    version = Column(String(50), nullable=False)
    description = Column(Text)
    long_description = Column(Text)
    
    # Classification
    category = Column(String(50), nullable=False, index=True)
    plugin_type = Column(String(50), nullable=False, index=True)
    tags = Column(ARRAY(String), default=[])
    
    # Author and ownership
    author_id = Column(String(255), nullable=False, index=True)
    author_name = Column(String(255), nullable=False)
    author_email = Column(String(255))
    organization = Column(String(255))
    
    # Status and visibility
    status = Column(String(50), default=PluginStatus.DRAFT, index=True)
    is_public = Column(Boolean, default=True, index=True)
    is_featured = Column(Boolean, default=False, index=True)
    is_verified = Column(Boolean, default=False, index=True)
    is_premium = Column(Boolean, default=False, index=True)
    
    # Technical details
    package_url = Column(String(500))  # URL to plugin package
    repository_url = Column(String(500))
    documentation_url = Column(String(500))
    homepage_url = Column(String(500))
    
    # Requirements and compatibility
    python_version = Column(String(50))
    mcp_version = Column(String(50))
    dependencies = Column(JSON, default={})
    system_requirements = Column(JSON, default={})
    
    # Configuration
    config_schema = Column(JSON, default={})  # JSON Schema for configuration
    default_config = Column(JSON, default={})
    capabilities = Column(ARRAY(String), default=[])
    
    # Metrics and ratings
    download_count = Column(Integer, default=0)
    install_count = Column(Integer, default=0)
    rating_average = Column(Float, default=0.0)
    rating_count = Column(Integer, default=0)
    review_count = Column(Integer, default=0)
    
    # Security and validation
    security_scan_status = Column(String(50))
    security_scan_date = Column(DateTime)
    validation_status = Column(String(50))
    validation_date = Column(DateTime)
    
    # Marketplace metadata
    submitted_at = Column(DateTime)
    published_at = Column(DateTime)
    last_updated = Column(DateTime)
    
    # File information
    file_size = Column(Integer)  # Size in bytes
    file_hash = Column(String(64))  # SHA-256 hash
    
    # Licensing
    license = Column(String(100))
    license_url = Column(String(500))
    
    # Support and maintenance
    support_email = Column(String(255))
    support_url = Column(String(500))
    maintenance_status = Column(String(50), default="active")
    
    # Relationships
    reviews = relationship("PluginReview", back_populates="plugin")
    installations = relationship("PluginInstallation", back_populates="plugin")
    
    # Indexes
    __table_args__ = (
        Index('idx_plugin_category_status', 'category', 'status'),
        Index('idx_plugin_author_status', 'author_id', 'status'),
        Index('idx_plugin_rating', 'rating_average', 'rating_count'),
        Index('idx_plugin_downloads', 'download_count'),
        Index('idx_plugin_published', 'published_at'),
    )


class PluginReview(SharedBaseModel):
    """Plugin review and rating model."""
    
    __tablename__ = "plugin_reviews"
    
    plugin_id = Column(UUID(as_uuid=True), ForeignKey("plugins.id"), nullable=False, index=True)
    reviewer_id = Column(String(255), nullable=False, index=True)
    reviewer_name = Column(String(255), nullable=False)
    
    # Review content
    rating = Column(Integer, nullable=False)  # 1-5 stars
    title = Column(String(255))
    content = Column(Text)
    
    # Review metadata
    is_verified = Column(Boolean, default=False)  # Verified purchase/installation
    is_featured = Column(Boolean, default=False)
    is_helpful_count = Column(Integer, default=0)
    is_reported = Column(Boolean, default=False)
    
    # Version reviewed
    plugin_version = Column(String(50))
    
    # Moderation
    moderation_status = Column(String(50), default="pending")
    moderated_by = Column(String(255))
    moderated_at = Column(DateTime)
    moderation_reason = Column(Text)
    
    # Relationships
    plugin = relationship("Plugin", back_populates="reviews")
    
    # Indexes
    __table_args__ = (
        Index('idx_review_plugin_rating', 'plugin_id', 'rating'),
        Index('idx_review_reviewer', 'reviewer_id'),
        Index('idx_review_moderation', 'moderation_status'),
    )


class PluginInstallation(SharedBaseModel):
    """Plugin installation tracking model."""
    
    __tablename__ = "plugin_installations"
    
    plugin_id = Column(UUID(as_uuid=True), ForeignKey("plugins.id"), nullable=False, index=True)
    user_id = Column(String(255), nullable=False, index=True)
    organization_id = Column(String(255), index=True)
    
    # Installation details
    version = Column(String(50), nullable=False)
    status = Column(String(50), default="active")  # active, inactive, uninstalled
    installation_method = Column(String(50))  # marketplace, manual, api
    
    # Configuration
    configuration = Column(JSON, default={})
    environment = Column(String(100))  # production, staging, development
    
    # Usage tracking
    last_used = Column(DateTime)
    usage_count = Column(Integer, default=0)
    
    # Health and performance
    health_status = Column(String(50), default="unknown")
    last_health_check = Column(DateTime)
    performance_metrics = Column(JSON, default={})
    
    # Installation metadata
    installed_at = Column(DateTime, default=datetime.utcnow)
    uninstalled_at = Column(DateTime)
    
    # Relationships
    plugin = relationship("Plugin", back_populates="installations")
    
    # Indexes
    __table_args__ = (
        Index('idx_installation_user_plugin', 'user_id', 'plugin_id'),
        Index('idx_installation_status', 'status'),
        Index('idx_installation_org', 'organization_id'),
    )


class PluginCategory(SharedBaseModel):
    """Plugin category model for organizing plugins."""
    
    __tablename__ = "plugin_categories"
    
    name = Column(String(255), unique=True, nullable=False, index=True)
    slug = Column(String(255), unique=True, nullable=False, index=True)
    description = Column(Text)
    icon = Column(String(255))  # Icon name or URL
    
    # Hierarchy
    parent_id = Column(UUID(as_uuid=True), ForeignKey("plugin_categories.id"))
    parent = relationship("PluginCategory", remote_side="PluginCategory.id", backref="children")
    
    # Display order and visibility
    display_order = Column(Integer, default=0)
    is_active = Column(Boolean, default=True)
    is_featured = Column(Boolean, default=False)
    
    # Statistics
    plugin_count = Column(Integer, default=0)
    
    # Indexes
    __table_args__ = (
        Index('idx_category_parent', 'parent_id'),
        Index('idx_category_active_order', 'is_active', 'display_order'),
    )


class PluginCollection(SharedBaseModel):
    """Plugin collection model for curated plugin lists."""
    
    __tablename__ = "plugin_collections"
    
    name = Column(String(255), nullable=False, index=True)
    slug = Column(String(255), unique=True, nullable=False, index=True)
    description = Column(Text)
    
    # Collection metadata
    curator_id = Column(String(255), nullable=False, index=True)
    curator_name = Column(String(255), nullable=False)
    
    # Visibility and status
    is_public = Column(Boolean, default=True, index=True)
    is_featured = Column(Boolean, default=False, index=True)
    is_official = Column(Boolean, default=False, index=True)
    
    # Collection image and branding
    cover_image_url = Column(String(500))
    icon_url = Column(String(500))
    
    # Statistics
    plugin_count = Column(Integer, default=0)
    subscriber_count = Column(Integer, default=0)
    
    # Indexes
    __table_args__ = (
        Index('idx_collection_curator', 'curator_id'),
        Index('idx_collection_public_featured', 'is_public', 'is_featured'),
    )


class PluginCollectionItem(SharedBaseModel):
    """Association table for plugins in collections."""
    
    __tablename__ = "plugin_collection_items"
    
    collection_id = Column(UUID(as_uuid=True), ForeignKey("plugin_collections.id"), nullable=False, index=True)
    plugin_id = Column(UUID(as_uuid=True), ForeignKey("plugins.id"), nullable=False, index=True)
    
    # Item metadata
    display_order = Column(Integer, default=0)
    added_by = Column(String(255), nullable=False)
    added_at = Column(DateTime, default=datetime.utcnow)
    description = Column(Text)  # Custom description for this collection
    
    # Relationships
    collection = relationship("PluginCollection")
    plugin = relationship("Plugin")
    
    # Indexes
    __table_args__ = (
        Index('idx_collection_item_order', 'collection_id', 'display_order'),
        Index('idx_collection_plugin', 'collection_id', 'plugin_id'),
    )


# Pydantic models for API

class PluginCreate(BaseModel):
    """Request model for creating a plugin."""
    name: str = Field(..., min_length=1, max_length=255)
    version: str = Field(..., min_length=1, max_length=50)
    description: str = Field(..., min_length=1, max_length=1000)
    long_description: Optional[str] = Field(None, max_length=10000)
    category: PluginCategory
    plugin_type: PluginType
    tags: List[str] = Field(default_factory=list)
    author_name: str = Field(..., min_length=1, max_length=255)
    author_email: Optional[str] = Field(None, max_length=255)
    organization: Optional[str] = Field(None, max_length=255)
    package_url: Optional[str] = Field(None, max_length=500)
    repository_url: Optional[str] = Field(None, max_length=500)
    documentation_url: Optional[str] = Field(None, max_length=500)
    homepage_url: Optional[str] = Field(None, max_length=500)
    python_version: Optional[str] = Field(None, max_length=50)
    mcp_version: Optional[str] = Field(None, max_length=50)
    dependencies: Dict[str, Any] = Field(default_factory=dict)
    system_requirements: Dict[str, Any] = Field(default_factory=dict)
    config_schema: Dict[str, Any] = Field(default_factory=dict)
    default_config: Dict[str, Any] = Field(default_factory=dict)
    capabilities: List[str] = Field(default_factory=list)
    license: Optional[str] = Field(None, max_length=100)
    license_url: Optional[str] = Field(None, max_length=500)
    support_email: Optional[str] = Field(None, max_length=255)
    support_url: Optional[str] = Field(None, max_length=500)
    is_public: bool = Field(default=True)
    is_premium: bool = Field(default=False)


class PluginUpdate(BaseModel):
    """Request model for updating a plugin."""
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    version: Optional[str] = Field(None, min_length=1, max_length=50)
    description: Optional[str] = Field(None, min_length=1, max_length=1000)
    long_description: Optional[str] = Field(None, max_length=10000)
    category: Optional[PluginCategory] = None
    plugin_type: Optional[PluginType] = None
    tags: Optional[List[str]] = None
    package_url: Optional[str] = Field(None, max_length=500)
    repository_url: Optional[str] = Field(None, max_length=500)
    documentation_url: Optional[str] = Field(None, max_length=500)
    homepage_url: Optional[str] = Field(None, max_length=500)
    dependencies: Optional[Dict[str, Any]] = None
    system_requirements: Optional[Dict[str, Any]] = None
    config_schema: Optional[Dict[str, Any]] = None
    default_config: Optional[Dict[str, Any]] = None
    capabilities: Optional[List[str]] = None
    license: Optional[str] = Field(None, max_length=100)
    support_email: Optional[str] = Field(None, max_length=255)
    support_url: Optional[str] = Field(None, max_length=500)
    is_public: Optional[bool] = None


class PluginResponse(BaseModel):
    """Response model for plugin data."""
    id: str
    name: str
    slug: str
    version: str
    description: str
    long_description: Optional[str]
    category: str
    plugin_type: str
    tags: List[str]
    author_id: str
    author_name: str
    author_email: Optional[str] 
    organization: Optional[str]
    status: str
    is_public: bool
    is_featured: bool
    is_verified: bool
    is_premium: bool
    package_url: Optional[str]
    repository_url: Optional[str]
    documentation_url: Optional[str]
    homepage_url: Optional[str]
    python_version: Optional[str]
    mcp_version: Optional[str]
    dependencies: Dict[str, Any]
    system_requirements: Dict[str, Any]
    config_schema: Dict[str, Any]
    default_config: Dict[str, Any]
    capabilities: List[str]
    download_count: int
    install_count: int
    rating_average: float
    rating_count: int
    review_count: int
    license: Optional[str]
    support_email: Optional[str]
    support_url: Optional[str]
    created_at: datetime
    updated_at: datetime
    published_at: Optional[datetime]
    
    class Config:
        from_attributes = True


class PluginReviewCreate(BaseModel):
    """Request model for creating a plugin review."""
    rating: int = Field(..., ge=1, le=5)
    title: Optional[str] = Field(None, max_length=255)
    content: Optional[str] = Field(None, max_length=5000)
    plugin_version: Optional[str] = Field(None, max_length=50)


class PluginReviewResponse(BaseModel):
    """Response model for plugin review data."""
    id: str
    plugin_id: str
    reviewer_id: str
    reviewer_name: str
    rating: int
    title: Optional[str]
    content: Optional[str]
    is_verified: bool
    is_featured: bool
    is_helpful_count: int
    plugin_version: Optional[str]
    created_at: datetime
    updated_at: datetime
    
    class Config:
        from_attributes = True


class PluginInstallationResponse(BaseModel):
    """Response model for plugin installation data."""
    id: str
    plugin_id: str
    user_id: str
    organization_id: Optional[str]
    version: str
    status: str
    installation_method: Optional[str]
    configuration: Dict[str, Any]
    environment: Optional[str]
    last_used: Optional[datetime]
    usage_count: int
    health_status: str
    last_health_check: Optional[datetime]
    performance_metrics: Dict[str, Any]
    installed_at: datetime
    uninstalled_at: Optional[datetime]
    
    class Config:
        from_attributes = True


# Factory functions

def create_plugin(
    name: str,
    version: str,
    description: str,
    category: PluginCategory,
    plugin_type: PluginType,
    author_id: str,
    author_name: str,
    **kwargs
) -> Plugin:
    """Create a new plugin instance."""
    # Generate slug from name
    slug = name.lower().replace(" ", "-").replace("_", "-")
    
    plugin = Plugin(
        id=uuid.uuid4(),
        name=name,
        slug=slug,
        version=version,
        description=description,
        category=category.value,
        plugin_type=plugin_type.value,
        author_id=author_id,
        author_name=author_name,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        **kwargs
    )
    
    return plugin


def create_plugin_review(
    plugin_id: uuid.UUID,
    reviewer_id: str,
    reviewer_name: str,
    rating: int,
    **kwargs
) -> PluginReview:
    """Create a new plugin review instance."""
    review = PluginReview(
        id=uuid.uuid4(),
        plugin_id=plugin_id,
        reviewer_id=reviewer_id,
        reviewer_name=reviewer_name,
        rating=rating,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        **kwargs
    )
    
    return review


def create_plugin_installation(
    plugin_id: uuid.UUID,
    user_id: str,
    version: str,
    **kwargs
) -> PluginInstallation:
    """Create a new plugin installation instance."""
    installation = PluginInstallation(
        id=uuid.uuid4(),
        plugin_id=plugin_id,
        user_id=user_id,
        version=version,
        created_at=datetime.utcnow(),
        updated_at=datetime.utcnow(),
        **kwargs
    )
    
    return installation