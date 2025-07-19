"""
MinIO Storage Models for Object Storage

This module defines the data models and structures for object storage
using MinIO, including buckets, objects, and policies.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from enum import Enum
from pydantic import BaseModel, Field, validator
import uuid

from shared.observability.logging import get_logger
from shared.config.settings import get_settings

logger = get_logger(__name__)


class ObjectType(str, Enum):
    """Types of stored objects."""
    DOCUMENT = "document"
    IMAGE = "image"
    VIDEO = "video"
    AUDIO = "audio"
    ARCHIVE = "archive"
    EXECUTABLE = "executable"
    SOURCE_CODE = "source_code"
    CONFIGURATION = "configuration"
    LOG = "log"
    BACKUP = "backup"
    REPORT = "report"
    SBOM = "sbom"
    VULNERABILITY_SCAN = "vulnerability_scan"
    COMPLIANCE_REPORT = "compliance_report"
    INCIDENT_EVIDENCE = "incident_evidence"
    THREAT_INTELLIGENCE = "threat_intelligence"
    MALWARE_SAMPLE = "malware_sample"
    FORENSIC_IMAGE = "forensic_image"
    FILE = "file"


class StorageClass(str, Enum):
    """Storage classes for objects."""
    STANDARD = "standard"
    REDUCED_REDUNDANCY = "reduced_redundancy"
    GLACIER = "glacier"
    DEEP_ARCHIVE = "deep_archive"
    INTELLIGENT_TIERING = "intelligent_tiering"


class AccessLevel(str, Enum):
    """Access levels for buckets."""
    PRIVATE = "private"
    PUBLIC_READ = "public_read"
    PUBLIC_WRITE = "public_write"
    AUTHENTICATED_READ = "authenticated_read"


class LifecycleAction(str, Enum):
    """Lifecycle rule actions."""
    EXPIRE = "expire"
    TRANSITION = "transition"
    DELETE_INCOMPLETE_MULTIPART = "delete_incomplete_multipart"
    ABORT_INCOMPLETE_MULTIPART = "abort_incomplete_multipart"


class BaseStorageModel(BaseModel):
    """Base model for storage entities."""
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


class StorageObject(BaseStorageModel):
    """Storage object model."""
    object_key: str = Field(...)
    bucket_name: str = Field(...)
    object_type: ObjectType = Field(...)
    
    # File information
    filename: str = Field(...)
    content_type: str = Field(...)
    size: int = Field(default=0, ge=0)
    
    # Storage configuration
    storage_class: StorageClass = Field(default=StorageClass.STANDARD)
    encryption_enabled: bool = Field(default=True)
    
    # Versioning
    version_id: Optional[str] = None
    etag: Optional[str] = None
    
    # Retention and lifecycle
    retention_days: Optional[int] = Field(None, ge=1, le=3650)
    retention_until: Optional[datetime] = None
    
    # Metadata
    description: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    
    # Checksums for integrity
    checksum_md5: Optional[str] = None
    checksum_sha256: Optional[str] = None
    
    # Access tracking
    last_accessed: Optional[datetime] = None
    access_count: int = Field(default=0, ge=0)
    download_count: int = Field(default=0, ge=0)
    
    # Security classification
    classification: Optional[str] = None
    sensitivity_level: Optional[str] = None
    
    @validator('retention_until', pre=True, always=True)
    def set_retention_until(cls, v, values):
        if v is None and 'retention_days' in values and values['retention_days']:
            created_at = values.get('created_at', datetime.now(timezone.utc))
            return created_at + timedelta(days=values['retention_days'])
        return v


class StorageBucket(BaseStorageModel):
    """Storage bucket model."""
    bucket_name: str = Field(...)
    description: Optional[str] = None
    
    # Storage configuration
    storage_class: StorageClass = Field(default=StorageClass.STANDARD)
    access_level: AccessLevel = Field(default=AccessLevel.PRIVATE)
    
    # Features
    versioning_enabled: bool = Field(default=False)
    encryption_enabled: bool = Field(default=True)
    public_access_blocked: bool = Field(default=True)
    
    # Lifecycle management
    lifecycle_rules: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Usage limits
    max_objects: Optional[int] = Field(None, ge=0)
    max_size_bytes: Optional[int] = Field(None, ge=0)
    
    # Metadata
    tags: Dict[str, str] = Field(default_factory=dict)
    
    # Statistics (calculated fields)
    object_count: int = Field(default=0, ge=0)
    total_size: int = Field(default=0, ge=0)
    last_modified: Optional[datetime] = None
    
    # Region and replication
    region: str = Field(default="us-east-1")
    replication_configuration: Optional[Dict[str, Any]] = None
    
    @validator('bucket_name')
    def validate_bucket_name(cls, v):
        if not v or len(v) < 3 or len(v) > 63:
            raise ValueError("Bucket name must be between 3 and 63 characters")
        
        import re
        if not re.match(r'^[a-z0-9][a-z0-9.-]*[a-z0-9]$', v):
            raise ValueError("Invalid bucket name format")
        
        return v.lower()


class StoragePolicy(BaseStorageModel):
    """Storage access policy model."""
    policy_name: str = Field(...)
    bucket_name: str = Field(...)
    
    # Policy configuration
    policy_document: Dict[str, Any] = Field(...)
    policy_type: str = Field(...)  # bucket, object, user
    
    # Scope
    resource_patterns: List[str] = Field(default_factory=list)
    principals: List[str] = Field(default_factory=list)
    actions: List[str] = Field(default_factory=list)
    
    # Conditions
    conditions: Dict[str, Any] = Field(default_factory=dict)
    
    # Status
    enabled: bool = Field(default=True)
    
    # Metadata
    description: Optional[str] = None
    tags: Dict[str, str] = Field(default_factory=dict)


class LifecycleRule(BaseStorageModel):
    """Lifecycle rule model."""
    rule_name: str = Field(...)
    bucket_name: str = Field(...)
    
    # Rule configuration
    enabled: bool = Field(default=True)
    filter_prefix: Optional[str] = None
    filter_tags: Dict[str, str] = Field(default_factory=dict)
    
    # Actions
    action: LifecycleAction = Field(...)
    days_after_creation: Optional[int] = Field(None, ge=0)
    days_after_modification: Optional[int] = Field(None, ge=0)
    
    # Transition configuration
    transition_storage_class: Optional[StorageClass] = None
    
    # Priority
    priority: int = Field(default=1, ge=1, le=1000)


class StorageMetadata(BaseModel):
    """Storage metadata for objects."""
    content_type: str = Field(...)
    content_encoding: Optional[str] = None
    content_language: Optional[str] = None
    content_disposition: Optional[str] = None
    cache_control: Optional[str] = None
    expires: Optional[datetime] = None
    
    # Custom metadata
    custom_metadata: Dict[str, str] = Field(default_factory=dict)
    
    # System metadata
    last_modified: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    etag: Optional[str] = None
    version_id: Optional[str] = None
    
    # Security metadata
    server_side_encryption: Optional[str] = None
    encryption_key_id: Optional[str] = None
    
    class Config:
        use_enum_values = True


class StorageUsageStats(BaseModel):
    """Storage usage statistics."""
    bucket_name: str = Field(...)
    
    # Object statistics
    total_objects: int = Field(default=0, ge=0)
    total_size: int = Field(default=0, ge=0)
    avg_object_size: float = Field(default=0.0, ge=0.0)
    
    # Size distribution
    size_distribution: Dict[str, int] = Field(default_factory=dict)
    
    # Type distribution
    object_type_distribution: Dict[str, int] = Field(default_factory=dict)
    
    # Storage class distribution
    storage_class_distribution: Dict[str, int] = Field(default_factory=dict)
    
    # Time-based statistics
    uploads_last_24h: int = Field(default=0, ge=0)
    downloads_last_24h: int = Field(default=0, ge=0)
    deletes_last_24h: int = Field(default=0, ge=0)
    
    # Growth statistics
    growth_rate_objects_per_day: float = Field(default=0.0)
    growth_rate_size_per_day: float = Field(default=0.0)
    
    # Oldest and newest objects
    oldest_object_date: Optional[datetime] = None
    newest_object_date: Optional[datetime] = None
    
    # Timestamps
    stats_generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    stats_period_start: Optional[datetime] = None
    stats_period_end: Optional[datetime] = None


class StorageQuota(BaseModel):
    """Storage quota configuration."""
    bucket_name: str = Field(...)
    
    # Quota limits
    max_objects: Optional[int] = Field(None, ge=0)
    max_size_bytes: Optional[int] = Field(None, ge=0)
    max_uploads_per_day: Optional[int] = Field(None, ge=0)
    max_downloads_per_day: Optional[int] = Field(None, ge=0)
    
    # Current usage
    current_objects: int = Field(default=0, ge=0)
    current_size_bytes: int = Field(default=0, ge=0)
    uploads_today: int = Field(default=0, ge=0)
    downloads_today: int = Field(default=0, ge=0)
    
    # Notifications
    notify_at_percentage: int = Field(default=80, ge=0, le=100)
    notification_enabled: bool = Field(default=True)
    
    # Status
    quota_exceeded: bool = Field(default=False)
    last_checked: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


# Factory functions for creating storage models
def create_storage_object(
    object_key: str,
    bucket_name: str,
    object_type: ObjectType,
    filename: str,
    content_type: str,
    size: int,
    **kwargs
) -> StorageObject:
    """Create a storage object."""
    return StorageObject(
        object_key=object_key,
        bucket_name=bucket_name,
        object_type=object_type,
        filename=filename,
        content_type=content_type,
        size=size,
        **kwargs
    )


def create_storage_bucket(
    bucket_name: str,
    **kwargs
) -> StorageBucket:
    """Create a storage bucket."""
    return StorageBucket(
        bucket_name=bucket_name,
        **kwargs
    )


def create_storage_policy(
    policy_name: str,
    bucket_name: str,
    policy_document: Dict[str, Any],
    policy_type: str,
    **kwargs
) -> StoragePolicy:
    """Create a storage policy."""
    return StoragePolicy(
        policy_name=policy_name,
        bucket_name=bucket_name,
        policy_document=policy_document,
        policy_type=policy_type,
        **kwargs
    )


def create_lifecycle_rule(
    rule_name: str,
    bucket_name: str,
    action: LifecycleAction,
    **kwargs
) -> LifecycleRule:
    """Create a lifecycle rule."""
    return LifecycleRule(
        rule_name=rule_name,
        bucket_name=bucket_name,
        action=action,
        **kwargs
    )