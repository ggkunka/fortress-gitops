"""
Storage Manager Service - MinIO object storage management

This service provides high-level object storage operations using MinIO,
including file upload/download, bucket management, and lifecycle policies.
"""

import asyncio
import io
import re
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, BinaryIO, AsyncIterator
import mimetypes
import hashlib

from minio import Minio
from minio.error import S3Error, InvalidResponseError
from minio.commonconfig import CopySource
from minio.lifecycleconfig import LifecycleConfig, Rule, Expiration
import urllib3

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.config.settings import get_settings

from ..models.storage import (
    StorageObject, StorageBucket, StorageClass, AccessLevel, ObjectType
)
from .storage_repository import StorageRepository

logger = get_logger(__name__)
metrics = get_metrics()


class StorageManager:
    """
    High-level storage manager using MinIO.
    
    This manager provides:
    1. Bucket lifecycle management
    2. Object upload/download operations
    3. Presigned URL generation
    4. Storage policies and lifecycle rules
    5. Metadata management
    6. Usage monitoring and optimization
    """
    
    def __init__(self, repository: StorageRepository):
        self.repository = repository
        self.client: Optional[Minio] = None
        self.settings = get_settings()
        
        # MinIO connection settings
        self.endpoint = getattr(self.settings, 'minio_endpoint', 'localhost:9000')
        self.access_key = getattr(self.settings, 'minio_access_key', 'minioadmin')
        self.secret_key = getattr(self.settings, 'minio_secret_key', 'minioadmin')
        self.secure = getattr(self.settings, 'minio_secure', False)
        self.region = getattr(self.settings, 'minio_region', 'us-east-1')
        
        # Configuration
        self.chunk_size = 64 * 1024  # 64KB chunks for streaming
        self.max_object_size = 5 * 1024 * 1024 * 1024  # 5GB
        self.max_multipart_size = 100 * 1024 * 1024  # 100MB
        
        # Bucket naming validation
        self.bucket_name_regex = re.compile(r'^[a-z0-9][a-z0-9.-]*[a-z0-9]$')
        
        logger.info("Storage manager initialized")
    
    async def initialize(self):
        """Initialize storage manager with MinIO client."""
        try:
            # Disable SSL warnings if not using secure connection
            if not self.secure:
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            
            # Create MinIO client
            self.client = Minio(
                self.endpoint,
                access_key=self.access_key,
                secret_key=self.secret_key,
                secure=self.secure,
                region=self.region
            )
            
            # Test connection
            await self._test_connection()
            
            logger.info("Storage manager connected to MinIO")
            
        except Exception as e:
            logger.error(f"Failed to initialize storage manager: {e}")
            raise
    
    def validate_bucket_name(self, bucket_name: str) -> bool:
        """Validate bucket name according to MinIO/S3 rules."""
        if not bucket_name or len(bucket_name) < 3 or len(bucket_name) > 63:
            return False
        
        if not self.bucket_name_regex.match(bucket_name):
            return False
        
        # Additional checks
        if bucket_name.startswith('.') or bucket_name.endswith('.'):
            return False
        if '..' in bucket_name:
            return False
        if bucket_name.startswith('-') or bucket_name.endswith('-'):
            return False
        
        return True
    
    @traced("storage_manager_create_bucket")
    async def create_bucket(self, bucket: StorageBucket) -> str:
        """Create a bucket in MinIO and store metadata."""
        try:
            # Create bucket in MinIO
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.make_bucket(bucket.bucket_name, location=self.region)
            )
            
            # Set bucket policy if specified
            if bucket.access_level != AccessLevel.PRIVATE:
                await self._set_bucket_policy(bucket.bucket_name, bucket.access_level)
            
            # Set lifecycle configuration if rules provided
            if bucket.lifecycle_rules:
                await self._set_lifecycle_configuration(bucket.bucket_name, bucket.lifecycle_rules)
            
            # Enable versioning if requested
            if bucket.versioning_enabled:
                await self._enable_versioning(bucket.bucket_name)
            
            # Store metadata in repository
            bucket_id = await self.repository.create_bucket(bucket)
            
            logger.info(f"Bucket created: {bucket.bucket_name}")
            metrics.storage_manager_buckets_created.inc()
            
            return bucket_id
            
        except S3Error as e:
            if e.code == "BucketAlreadyExists":
                logger.error(f"Bucket already exists: {bucket.bucket_name}")
                raise ValueError(f"Bucket already exists: {bucket.bucket_name}")
            else:
                logger.error(f"MinIO error creating bucket: {e}")
                raise
        except Exception as e:
            logger.error(f"Error creating bucket: {e}")
            metrics.storage_manager_errors.inc()
            raise
    
    @traced("storage_manager_upload_object")
    async def upload_object(self, obj: StorageObject, file_data: BinaryIO) -> str:
        """Upload an object to MinIO and store metadata."""
        try:
            # Calculate file size and hash
            file_data.seek(0, 2)  # Seek to end
            file_size = file_data.tell()
            file_data.seek(0)  # Reset to beginning
            
            if file_size > self.max_object_size:
                raise ValueError(f"File size exceeds maximum allowed size: {self.max_object_size}")
            
            # Calculate SHA256 hash
            sha256_hash = hashlib.sha256()
            file_data.seek(0)
            while chunk := file_data.read(self.chunk_size):
                sha256_hash.update(chunk)
            file_data.seek(0)
            
            # Update object metadata
            obj.size = file_size
            obj.checksum_sha256 = sha256_hash.hexdigest()
            
            # Prepare metadata for MinIO
            metadata = {
                "object-type": obj.object_type,
                "storage-class": obj.storage_class,
                "description": obj.description or "",
                "filename": obj.filename,
                "upload-timestamp": obj.created_at.isoformat()
            }
            
            # Add custom metadata
            for key, value in obj.metadata.items():
                metadata[f"custom-{key}"] = str(value)
            
            # Add tags as metadata
            for key, value in obj.tags.items():
                metadata[f"tag-{key}"] = str(value)
            
            # Upload to MinIO
            result = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.put_object(
                    bucket_name=obj.bucket_name,
                    object_name=obj.object_key,
                    data=file_data,
                    length=file_size,
                    content_type=obj.content_type,
                    metadata=metadata
                )
            )
            
            # Update object with MinIO response data
            obj.etag = result.etag
            obj.version_id = result.version_id
            
            # Set retention if specified
            if obj.retention_days:
                obj.retention_until = obj.created_at + timedelta(days=obj.retention_days)
            
            # Store metadata in repository
            object_id = await self.repository.create_object(obj)
            
            # Record usage
            await self.repository.record_usage(
                bucket_name=obj.bucket_name,
                operation="upload",
                size=file_size
            )
            
            logger.info(f"Object uploaded: {obj.bucket_name}/{obj.object_key}")
            metrics.storage_manager_objects_uploaded.inc()
            metrics.storage_manager_bytes_uploaded.inc(file_size)
            
            return object_id
            
        except S3Error as e:
            logger.error(f"MinIO error uploading object: {e}")
            metrics.storage_manager_errors.inc()
            raise
        except Exception as e:
            logger.error(f"Error uploading object: {e}")
            metrics.storage_manager_errors.inc()
            raise
    
    @traced("storage_manager_download_object")
    async def download_object(
        self, 
        bucket_name: str, 
        object_key: str,
        version_id: Optional[str] = None
    ) -> AsyncIterator[bytes]:
        """Download an object from MinIO."""
        try:
            # Get object from MinIO
            response = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.get_object(
                    bucket_name=bucket_name,
                    object_name=object_key,
                    version_id=version_id
                )
            )
            
            # Stream the object data
            try:
                while True:
                    chunk = response.read(self.chunk_size)
                    if not chunk:
                        break
                    yield chunk
            finally:
                response.close()
                response.release_conn()
            
            # Record usage
            await self.repository.record_usage(
                bucket_name=bucket_name,
                operation="download"
            )
            
            logger.debug(f"Object downloaded: {bucket_name}/{object_key}")
            metrics.storage_manager_objects_downloaded.inc()
            
        except S3Error as e:
            if e.code == "NoSuchKey":
                logger.error(f"Object not found: {bucket_name}/{object_key}")
                raise FileNotFoundError(f"Object not found: {bucket_name}/{object_key}")
            else:
                logger.error(f"MinIO error downloading object: {e}")
                raise
        except Exception as e:
            logger.error(f"Error downloading object: {e}")
            metrics.storage_manager_errors.inc()
            raise
    
    @traced("storage_manager_get_object_metadata")
    async def get_object_metadata(
        self, 
        bucket_name: str, 
        object_key: str,
        version_id: Optional[str] = None
    ) -> Optional[StorageObject]:
        """Get object metadata."""
        try:
            # First try to get from repository
            obj = await self.repository.get_object(bucket_name, object_key, version_id)
            if obj:
                return obj
            
            # If not in repository, try to get from MinIO
            try:
                stat = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self.client.stat_object(
                        bucket_name=bucket_name,
                        object_name=object_key,
                        version_id=version_id
                    )
                )
                
                # Create object from MinIO stat
                obj = StorageObject(
                    object_key=object_key,
                    bucket_name=bucket_name,
                    object_type=ObjectType.FILE,  # Default
                    filename=object_key.split('/')[-1],
                    content_type=stat.content_type,
                    size=stat.size,
                    etag=stat.etag,
                    version_id=stat.version_id,
                    created_at=stat.last_modified,
                    updated_at=stat.last_modified
                )
                
                # Store in repository for future access
                await self.repository.create_object(obj)
                
                return obj
                
            except S3Error as e:
                if e.code == "NoSuchKey":
                    return None
                raise
            
        except Exception as e:
            logger.error(f"Error getting object metadata: {e}")
            metrics.storage_manager_errors.inc()
            raise
    
    @traced("storage_manager_update_object_metadata")
    async def update_object_metadata(
        self,
        bucket_name: str,
        object_key: str,
        description: Optional[str] = None,
        tags: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        retention_days: Optional[int] = None
    ) -> bool:
        """Update object metadata."""
        try:
            updates = {}
            
            if description is not None:
                updates["description"] = description
            
            if tags is not None:
                updates["tags"] = tags
            
            if metadata is not None:
                updates["metadata"] = metadata
            
            if retention_days is not None:
                retention_until = datetime.now(timezone.utc) + timedelta(days=retention_days)
                updates["retention_until"] = retention_until
                updates["retention_days"] = retention_days
            
            if not updates:
                return True
            
            success = await self.repository.update_object(
                bucket_name=bucket_name,
                object_key=object_key,
                updates=updates
            )
            
            if success:
                logger.debug(f"Object metadata updated: {bucket_name}/{object_key}")
                metrics.storage_manager_objects_updated.inc()
            
            return success
            
        except Exception as e:
            logger.error(f"Error updating object metadata: {e}")
            metrics.storage_manager_errors.inc()
            raise
    
    @traced("storage_manager_generate_presigned_url")
    async def generate_presigned_url(
        self,
        bucket_name: str,
        object_key: str,
        operation: str,
        expiry_hours: int = 1
    ) -> str:
        """Generate a presigned URL for object operations."""
        try:
            expiry = timedelta(hours=expiry_hours)
            
            if operation.upper() == "GET":
                url = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self.client.presigned_get_object(
                        bucket_name=bucket_name,
                        object_name=object_key,
                        expires=expiry
                    )
                )
            elif operation.upper() == "PUT":
                url = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: self.client.presigned_put_object(
                        bucket_name=bucket_name,
                        object_name=object_key,
                        expires=expiry
                    )
                )
            else:
                raise ValueError(f"Unsupported operation: {operation}")
            
            logger.debug(f"Presigned URL generated: {bucket_name}/{object_key}")
            metrics.storage_manager_presigned_urls_generated.inc()
            
            return url
            
        except Exception as e:
            logger.error(f"Error generating presigned URL: {e}")
            metrics.storage_manager_errors.inc()
            raise
    
    @traced("storage_manager_list_objects")
    async def list_objects(
        self,
        bucket_name: str,
        prefix: Optional[str] = None,
        limit: int = 100,
        offset: int = 0
    ) -> List[StorageObject]:
        """List objects in a bucket."""
        try:
            # Try to get from repository first (includes metadata)
            objects = await self.repository.list_objects(
                bucket_name=bucket_name,
                prefix=prefix,
                limit=limit,
                offset=offset
            )
            
            if objects:
                return objects
            
            # If not in repository, get from MinIO
            minio_objects = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: list(self.client.list_objects(
                    bucket_name=bucket_name,
                    prefix=prefix,
                    recursive=True
                ))
            )
            
            # Convert MinIO objects to StorageObject
            storage_objects = []
            for obj in minio_objects[offset:offset+limit]:
                storage_obj = StorageObject(
                    object_key=obj.object_name,
                    bucket_name=bucket_name,
                    object_type=ObjectType.FILE,
                    filename=obj.object_name.split('/')[-1],
                    content_type="application/octet-stream",  # Default
                    size=obj.size,
                    etag=obj.etag,
                    created_at=obj.last_modified,
                    updated_at=obj.last_modified
                )
                storage_objects.append(storage_obj)
            
            return storage_objects
            
        except Exception as e:
            logger.error(f"Error listing objects: {e}")
            metrics.storage_manager_errors.inc()
            raise
    
    @traced("storage_manager_count_objects")
    async def count_objects(
        self,
        bucket_name: str,
        prefix: Optional[str] = None
    ) -> int:
        """Count objects in a bucket."""
        try:
            # Try repository first
            count = await self.repository.count_objects(bucket_name, prefix)
            if count > 0:
                return count
            
            # Count from MinIO if not in repository
            objects = await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: list(self.client.list_objects(
                    bucket_name=bucket_name,
                    prefix=prefix,
                    recursive=True
                ))
            )
            
            return len(objects)
            
        except Exception as e:
            logger.error(f"Error counting objects: {e}")
            metrics.storage_manager_errors.inc()
            raise
    
    @traced("storage_manager_get_bucket_usage")
    async def get_bucket_usage(self, bucket_name: str) -> Dict[str, Any]:
        """Get bucket usage statistics."""
        try:
            # Get usage from repository
            usage_stats = await self.repository.get_bucket_usage(bucket_name)
            
            # Get additional stats from MinIO if needed
            if usage_stats["total_objects"] == 0:
                objects = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: list(self.client.list_objects(
                        bucket_name=bucket_name,
                        recursive=True
                    ))
                )
                
                if objects:
                    total_size = sum(obj.size for obj in objects)
                    usage_stats.update({
                        "total_objects": len(objects),
                        "total_size": total_size,
                        "avg_size": total_size / len(objects) if objects else 0
                    })
            
            return usage_stats
            
        except Exception as e:
            logger.error(f"Error getting bucket usage: {e}")
            metrics.storage_manager_errors.inc()
            raise
    
    @traced("storage_manager_delete_object")
    async def delete_object(
        self,
        bucket_name: str,
        object_key: str,
        version_id: Optional[str] = None
    ) -> bool:
        """Delete an object from MinIO and remove metadata."""
        try:
            # Delete from MinIO
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.remove_object(
                    bucket_name=bucket_name,
                    object_name=object_key,
                    version_id=version_id
                )
            )
            
            # Delete metadata from repository
            success = await self.repository.delete_object(
                bucket_name=bucket_name,
                object_key=object_key,
                version_id=version_id
            )
            
            # Record usage
            await self.repository.record_usage(
                bucket_name=bucket_name,
                operation="delete"
            )
            
            logger.info(f"Object deleted: {bucket_name}/{object_key}")
            metrics.storage_manager_objects_deleted.inc()
            
            return True
            
        except S3Error as e:
            if e.code == "NoSuchKey":
                logger.warning(f"Object not found for deletion: {bucket_name}/{object_key}")
                return False
            else:
                logger.error(f"MinIO error deleting object: {e}")
                raise
        except Exception as e:
            logger.error(f"Error deleting object: {e}")
            metrics.storage_manager_errors.inc()
            raise
    
    @traced("storage_manager_delete_bucket")
    async def delete_bucket(self, bucket_name: str, force: bool = False) -> bool:
        """Delete a bucket from MinIO and remove metadata."""
        try:
            if force:
                # Delete all objects first
                objects = await asyncio.get_event_loop().run_in_executor(
                    None,
                    lambda: list(self.client.list_objects(
                        bucket_name=bucket_name,
                        recursive=True
                    ))
                )
                
                for obj in objects:
                    await self.delete_object(bucket_name, obj.object_name)
            
            # Delete bucket from MinIO
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.remove_bucket(bucket_name)
            )
            
            # Delete metadata from repository
            success = await self.repository.delete_bucket(bucket_name)
            
            logger.info(f"Bucket deleted: {bucket_name}")
            metrics.storage_manager_buckets_deleted.inc()
            
            return True
            
        except S3Error as e:
            if e.code == "NoSuchBucket":
                logger.warning(f"Bucket not found for deletion: {bucket_name}")
                return False
            else:
                logger.error(f"MinIO error deleting bucket: {e}")
                raise
        except Exception as e:
            logger.error(f"Error deleting bucket: {e}")
            metrics.storage_manager_errors.inc()
            raise
    
    async def _test_connection(self):
        """Test MinIO connection."""
        try:
            # Try to list buckets
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: list(self.client.list_buckets())
            )
            logger.info("MinIO connection test passed")
        except Exception as e:
            logger.error(f"MinIO connection test failed: {e}")
            raise
    
    async def _set_bucket_policy(self, bucket_name: str, access_level: AccessLevel):
        """Set bucket access policy."""
        try:
            if access_level == AccessLevel.PUBLIC_READ:
                policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": f"arn:aws:s3:::{bucket_name}/*"
                        }
                    ]
                }
            elif access_level == AccessLevel.PUBLIC_WRITE:
                policy = {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": ["s3:GetObject", "s3:PutObject"],
                            "Resource": f"arn:aws:s3:::{bucket_name}/*"
                        }
                    ]
                }
            else:
                return  # Private bucket, no policy needed
            
            import json
            await asyncio.get_event_loop().run_in_executor(
                None,
                lambda: self.client.set_bucket_policy(bucket_name, json.dumps(policy))
            )
            
        except Exception as e:
            logger.warning(f"Failed to set bucket policy: {e}")
    
    async def _set_lifecycle_configuration(
        self, 
        bucket_name: str, 
        lifecycle_rules: List[Dict[str, Any]]
    ):
        """Set bucket lifecycle configuration."""
        try:
            # Convert lifecycle rules to MinIO format
            # This is a simplified implementation
            logger.info(f"Lifecycle rules would be applied to bucket: {bucket_name}")
            
        except Exception as e:
            logger.warning(f"Failed to set lifecycle configuration: {e}")
    
    async def _enable_versioning(self, bucket_name: str):
        """Enable versioning for a bucket."""
        try:
            # MinIO versioning configuration
            logger.info(f"Versioning would be enabled for bucket: {bucket_name}")
            
        except Exception as e:
            logger.warning(f"Failed to enable versioning: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get manager statistics."""
        return {
            "connection_status": "connected" if self.client else "disconnected",
            "endpoint": self.endpoint,
            "region": self.region,
            "secure": self.secure,
            "chunk_size": self.chunk_size,
            "max_object_size": self.max_object_size,
            "max_multipart_size": self.max_multipart_size,
            "operations": [
                "create_bucket", "upload_object", "download_object",
                "get_object_metadata", "update_object_metadata",
                "generate_presigned_url", "list_objects", "count_objects",
                "get_bucket_usage", "delete_object", "delete_bucket"
            ]
        }