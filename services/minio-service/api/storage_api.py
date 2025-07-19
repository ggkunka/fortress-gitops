"""
Storage API - REST endpoints for object storage operations

This service provides comprehensive object storage capabilities using MinIO
for secure file storage, artifact management, and backup operations.
"""

import os
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, BinaryIO
from uuid import UUID
import mimetypes

from fastapi import APIRouter, Depends, HTTPException, Query, UploadFile, File, Form
from fastapi.responses import StreamingResponse, JSONResponse
from pydantic import BaseModel, Field

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.security.sanitization import sanitize_input

from ..models.storage import (
    StorageObject, StorageBucket, StorageMetadata, StoragePolicy,
    ObjectType, StorageClass, AccessLevel, LifecycleRule,
    create_storage_object, create_storage_bucket
)
from ..services.storage_repository import StorageRepository
from ..services.storage_manager import StorageManager

logger = get_logger(__name__)
metrics = get_metrics()

router = APIRouter()

# Global instances (would be injected in real implementation)
storage_repository = None
storage_manager = None


class CreateBucketRequest(BaseModel):
    """Request model for creating storage buckets."""
    bucket_name: str = Field(..., min_length=3, max_length=63)
    description: Optional[str] = Field(None, max_length=500)
    storage_class: StorageClass = Field(default=StorageClass.STANDARD)
    access_level: AccessLevel = Field(default=AccessLevel.PRIVATE)
    versioning_enabled: bool = Field(default=False)
    encryption_enabled: bool = Field(default=True)
    lifecycle_rules: Optional[List[Dict[str, Any]]] = Field(default_factory=list)
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)


class CreateObjectRequest(BaseModel):
    """Request model for creating storage objects."""
    object_key: str = Field(..., min_length=1, max_length=1024)
    bucket_name: str = Field(..., min_length=3, max_length=63)
    object_type: ObjectType = Field(...)
    content_type: Optional[str] = None
    description: Optional[str] = Field(None, max_length=500)
    storage_class: StorageClass = Field(default=StorageClass.STANDARD)
    encryption_enabled: bool = Field(default=True)
    retention_days: Optional[int] = Field(None, ge=1, le=3650)
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)


class UpdateObjectMetadataRequest(BaseModel):
    """Request model for updating object metadata."""
    description: Optional[str] = Field(None, max_length=500)
    tags: Optional[Dict[str, str]] = Field(default_factory=dict)
    metadata: Optional[Dict[str, Any]] = Field(default_factory=dict)
    retention_days: Optional[int] = Field(None, ge=1, le=3650)


class GeneratePresignedUrlRequest(BaseModel):
    """Request model for generating presigned URLs."""
    bucket_name: str = Field(..., min_length=3, max_length=63)
    object_key: str = Field(..., min_length=1, max_length=1024)
    operation: str = Field(..., regex="^(GET|PUT|DELETE)$")
    expiry_hours: int = Field(default=1, ge=1, le=168)  # Max 1 week


def get_storage_repository() -> StorageRepository:
    """Get storage repository instance."""
    global storage_repository
    if storage_repository is None:
        raise RuntimeError("Storage repository not initialized")
    return storage_repository


def get_storage_manager() -> StorageManager:
    """Get storage manager instance."""
    global storage_manager
    if storage_manager is None:
        raise RuntimeError("Storage manager not initialized")
    return storage_manager


@router.post("/buckets", response_model=Dict[str, Any])
@traced("storage_api_create_bucket")
async def create_bucket(
    request: CreateBucketRequest,
    repository: StorageRepository = Depends(get_storage_repository),
    manager: StorageManager = Depends(get_storage_manager)
):
    """Create a storage bucket."""
    try:
        # Sanitize inputs
        bucket_name = sanitize_input(request.bucket_name, max_length=63).lower()
        
        # Validate bucket name format
        if not manager.validate_bucket_name(bucket_name):
            raise HTTPException(
                status_code=400, 
                detail="Invalid bucket name format"
            )
        
        # Check if bucket already exists
        existing_bucket = await repository.get_bucket_by_name(bucket_name)
        if existing_bucket:
            raise HTTPException(
                status_code=409, 
                detail="Bucket already exists"
            )
        
        # Create bucket object
        bucket = create_storage_bucket(
            bucket_name=bucket_name,
            description=request.description,
            storage_class=request.storage_class,
            access_level=request.access_level,
            versioning_enabled=request.versioning_enabled,
            encryption_enabled=request.encryption_enabled,
            lifecycle_rules=request.lifecycle_rules or [],
            tags=request.tags or {}
        )
        
        # Create bucket in MinIO
        bucket_id = await manager.create_bucket(bucket)
        
        logger.info(f"Storage bucket created: {bucket_id}")
        metrics.storage_api_buckets_created.inc()
        
        return {
            "message": "Bucket created successfully",
            "bucket_id": bucket_id,
            "bucket_name": bucket_name,
            "storage_class": request.storage_class,
            "access_level": request.access_level,
            "timestamp": bucket.created_at.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error creating bucket: {e}")
        metrics.storage_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/objects/upload", response_model=Dict[str, Any])
@traced("storage_api_upload_object")
async def upload_object(
    file: UploadFile = File(...),
    bucket_name: str = Form(...),
    object_key: str = Form(...),
    object_type: ObjectType = Form(...),
    description: Optional[str] = Form(None),
    storage_class: StorageClass = Form(default=StorageClass.STANDARD),
    encryption_enabled: bool = Form(default=True),
    retention_days: Optional[int] = Form(None),
    tags: Optional[str] = Form(None),  # JSON string
    manager: StorageManager = Depends(get_storage_manager)
):
    """Upload an object to storage."""
    try:
        # Sanitize inputs
        bucket_name = sanitize_input(bucket_name, max_length=63).lower()
        object_key = sanitize_input(object_key, max_length=1024)
        
        # Parse tags if provided
        parsed_tags = {}
        if tags:
            import json
            try:
                parsed_tags = json.loads(tags)
            except json.JSONDecodeError:
                raise HTTPException(status_code=400, detail="Invalid tags format")
        
        # Validate file
        if not file.filename:
            raise HTTPException(status_code=400, detail="No filename provided")
        
        # Detect content type
        content_type = file.content_type
        if not content_type:
            content_type, _ = mimetypes.guess_type(file.filename)
            content_type = content_type or "application/octet-stream"
        
        # Create storage object
        storage_object = create_storage_object(
            object_key=object_key,
            bucket_name=bucket_name,
            object_type=object_type,
            filename=file.filename,
            content_type=content_type,
            size=0,  # Will be updated after upload
            description=description,
            storage_class=storage_class,
            encryption_enabled=encryption_enabled,
            retention_days=retention_days,
            tags=parsed_tags,
            metadata={}
        )
        
        # Upload file
        object_id = await manager.upload_object(storage_object, file.file)
        
        logger.info(f"Object uploaded: {object_id}")
        metrics.storage_api_objects_uploaded.inc()
        
        return {
            "message": "Object uploaded successfully",
            "object_id": object_id,
            "object_key": object_key,
            "bucket_name": bucket_name,
            "filename": file.filename,
            "size": storage_object.size,
            "content_type": content_type,
            "timestamp": storage_object.created_at.isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error uploading object: {e}")
        metrics.storage_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/objects/{bucket_name}/{object_key:path}")
@traced("storage_api_download_object")
async def download_object(
    bucket_name: str,
    object_key: str,
    version_id: Optional[str] = Query(None),
    manager: StorageManager = Depends(get_storage_manager)
):
    """Download an object from storage."""
    try:
        # Sanitize inputs
        bucket_name = sanitize_input(bucket_name, max_length=63).lower()
        object_key = sanitize_input(object_key, max_length=1024)
        
        # Get object metadata
        obj = await manager.get_object_metadata(bucket_name, object_key, version_id)
        if not obj:
            raise HTTPException(status_code=404, detail="Object not found")
        
        # Get object stream
        object_stream = await manager.download_object(bucket_name, object_key, version_id)
        
        logger.info(f"Object downloaded: {bucket_name}/{object_key}")
        metrics.storage_api_objects_downloaded.inc()
        
        # Return streaming response
        return StreamingResponse(
            object_stream,
            media_type=obj.content_type,
            headers={
                "Content-Disposition": f"attachment; filename={obj.filename}",
                "Content-Length": str(obj.size),
                "ETag": obj.etag or "",
                "Last-Modified": obj.updated_at.strftime("%a, %d %b %Y %H:%M:%S GMT")
            }
        )
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error downloading object: {e}")
        metrics.storage_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/objects/{bucket_name}/{object_key:path}/metadata", response_model=Dict[str, Any])
@traced("storage_api_get_object_metadata")
async def get_object_metadata(
    bucket_name: str,
    object_key: str,
    version_id: Optional[str] = Query(None),
    manager: StorageManager = Depends(get_storage_manager)
):
    """Get object metadata."""
    try:
        # Sanitize inputs
        bucket_name = sanitize_input(bucket_name, max_length=63).lower()
        object_key = sanitize_input(object_key, max_length=1024)
        
        # Get object metadata
        obj = await manager.get_object_metadata(bucket_name, object_key, version_id)
        if not obj:
            raise HTTPException(status_code=404, detail="Object not found")
        
        return obj.dict()
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting object metadata: {e}")
        metrics.storage_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.put("/objects/{bucket_name}/{object_key:path}/metadata", response_model=Dict[str, Any])
@traced("storage_api_update_object_metadata")
async def update_object_metadata(
    bucket_name: str,
    object_key: str,
    request: UpdateObjectMetadataRequest,
    manager: StorageManager = Depends(get_storage_manager)
):
    """Update object metadata."""
    try:
        # Sanitize inputs
        bucket_name = sanitize_input(bucket_name, max_length=63).lower()
        object_key = sanitize_input(object_key, max_length=1024)
        
        # Update metadata
        success = await manager.update_object_metadata(
            bucket_name=bucket_name,
            object_key=object_key,
            description=request.description,
            tags=request.tags,
            metadata=request.metadata,
            retention_days=request.retention_days
        )
        
        if not success:
            raise HTTPException(status_code=404, detail="Object not found")
        
        logger.info(f"Object metadata updated: {bucket_name}/{object_key}")
        
        return {
            "message": "Object metadata updated successfully",
            "bucket_name": bucket_name,
            "object_key": object_key,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error updating object metadata: {e}")
        metrics.storage_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/presigned-url", response_model=Dict[str, Any])
@traced("storage_api_generate_presigned_url")
async def generate_presigned_url(
    request: GeneratePresignedUrlRequest,
    manager: StorageManager = Depends(get_storage_manager)
):
    """Generate a presigned URL for object operations."""
    try:
        # Sanitize inputs
        bucket_name = sanitize_input(request.bucket_name, max_length=63).lower()
        object_key = sanitize_input(request.object_key, max_length=1024)
        
        # Generate presigned URL
        presigned_url = await manager.generate_presigned_url(
            bucket_name=bucket_name,
            object_key=object_key,
            operation=request.operation,
            expiry_hours=request.expiry_hours
        )
        
        expiry_time = datetime.utcnow() + timedelta(hours=request.expiry_hours)
        
        logger.info(f"Presigned URL generated: {bucket_name}/{object_key}")
        metrics.storage_api_presigned_urls_generated.inc()
        
        return {
            "presigned_url": presigned_url,
            "bucket_name": bucket_name,
            "object_key": object_key,
            "operation": request.operation,
            "expires_at": expiry_time.isoformat(),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error generating presigned URL: {e}")
        metrics.storage_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/buckets", response_model=Dict[str, Any])
@traced("storage_api_list_buckets")
async def list_buckets(
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    repository: StorageRepository = Depends(get_storage_repository)
):
    """List storage buckets."""
    try:
        buckets = await repository.list_buckets(limit=limit, offset=offset)
        total_count = await repository.count_buckets()
        
        return {
            "buckets": [bucket.dict() for bucket in buckets],
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error listing buckets: {e}")
        metrics.storage_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/buckets/{bucket_name}/objects", response_model=Dict[str, Any])
@traced("storage_api_list_objects")
async def list_objects(
    bucket_name: str,
    prefix: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    manager: StorageManager = Depends(get_storage_manager)
):
    """List objects in a bucket."""
    try:
        # Sanitize inputs
        bucket_name = sanitize_input(bucket_name, max_length=63).lower()
        prefix = sanitize_input(prefix, max_length=1024) if prefix else None
        
        objects = await manager.list_objects(
            bucket_name=bucket_name,
            prefix=prefix,
            limit=limit,
            offset=offset
        )
        
        total_count = await manager.count_objects(bucket_name, prefix)
        
        return {
            "bucket_name": bucket_name,
            "prefix": prefix,
            "objects": [obj.dict() for obj in objects],
            "total_count": total_count,
            "limit": limit,
            "offset": offset,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error listing objects: {e}")
        metrics.storage_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/buckets/{bucket_name}/usage", response_model=Dict[str, Any])
@traced("storage_api_get_bucket_usage")
async def get_bucket_usage(
    bucket_name: str,
    manager: StorageManager = Depends(get_storage_manager)
):
    """Get bucket usage statistics."""
    try:
        # Sanitize inputs
        bucket_name = sanitize_input(bucket_name, max_length=63).lower()
        
        usage_stats = await manager.get_bucket_usage(bucket_name)
        
        return {
            "bucket_name": bucket_name,
            "usage_statistics": usage_stats,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting bucket usage: {e}")
        metrics.storage_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/objects/{bucket_name}/{object_key:path}", response_model=Dict[str, Any])
@traced("storage_api_delete_object")
async def delete_object(
    bucket_name: str,
    object_key: str,
    version_id: Optional[str] = Query(None),
    manager: StorageManager = Depends(get_storage_manager)
):
    """Delete an object from storage."""
    try:
        # Sanitize inputs
        bucket_name = sanitize_input(bucket_name, max_length=63).lower()
        object_key = sanitize_input(object_key, max_length=1024)
        
        # Delete object
        success = await manager.delete_object(bucket_name, object_key, version_id)
        
        if not success:
            raise HTTPException(status_code=404, detail="Object not found")
        
        logger.info(f"Object deleted: {bucket_name}/{object_key}")
        metrics.storage_api_objects_deleted.inc()
        
        return {
            "message": "Object deleted successfully",
            "bucket_name": bucket_name,
            "object_key": object_key,
            "version_id": version_id,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting object: {e}")
        metrics.storage_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/buckets/{bucket_name}", response_model=Dict[str, Any])
@traced("storage_api_delete_bucket")
async def delete_bucket(
    bucket_name: str,
    force: bool = Query(False, description="Force delete bucket with objects"),
    manager: StorageManager = Depends(get_storage_manager)
):
    """Delete a storage bucket."""
    try:
        # Sanitize inputs
        bucket_name = sanitize_input(bucket_name, max_length=63).lower()
        
        # Delete bucket
        success = await manager.delete_bucket(bucket_name, force=force)
        
        if not success:
            raise HTTPException(status_code=404, detail="Bucket not found")
        
        logger.info(f"Bucket deleted: {bucket_name}")
        metrics.storage_api_buckets_deleted.inc()
        
        return {
            "message": "Bucket deleted successfully",
            "bucket_name": bucket_name,
            "force": force,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting bucket: {e}")
        metrics.storage_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/statistics", response_model=Dict[str, Any])
@traced("storage_api_get_statistics")
async def get_statistics(
    repository: StorageRepository = Depends(get_storage_repository),
    manager: StorageManager = Depends(get_storage_manager)
):
    """Get comprehensive storage statistics."""
    try:
        repository_stats = repository.get_stats()
        manager_stats = manager.get_stats()
        
        return {
            "service": "minio-service",
            "repository": repository_stats,
            "manager": manager_stats,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        metrics.storage_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")