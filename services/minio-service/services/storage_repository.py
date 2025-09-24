"""
Storage Repository Service - MongoDB-based storage metadata management

This service provides metadata storage and management for MinIO objects,
including bucket information, object metadata, and access policies.
"""

import asyncio
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any
from motor.motor_asyncio import AsyncIOMotorClient, AsyncIOMotorDatabase, AsyncIOMotorCollection
from pymongo import IndexModel, ASCENDING, DESCENDING
from pymongo.errors import DuplicateKeyError, PyMongoError

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.config.settings import get_settings

from ..models.storage import (
    StorageObject, StorageBucket, StorageMetadata, StoragePolicy,
    ObjectType, StorageClass, AccessLevel
)

logger = get_logger(__name__)
metrics = get_metrics()


class StorageRepository:
    """
    MongoDB-based repository for storage metadata.
    
    This repository provides:
    1. Bucket metadata management
    2. Object metadata storage
    3. Storage policy management
    4. Usage tracking and analytics
    5. Lifecycle management
    6. Access control metadata
    """
    
    def __init__(self):
        self.client: Optional[AsyncIOMotorClient] = None
        self.database: Optional[AsyncIOMotorDatabase] = None
        self.settings = get_settings()
        
        # MongoDB connection settings
        self.connection_string = getattr(
            self.settings, 'mongodb_connection_string', 
            'mongodb://localhost:27017'
        )
        self.database_name = getattr(
            self.settings, 'storage_metadata_database', 
            'mcp_storage_metadata'
        )
        
        # Collection names
        self.buckets_collection_name = "buckets"
        self.objects_collection_name = "objects"
        self.policies_collection_name = "policies"
        self.usage_collection_name = "usage_stats"
        
        # Collections
        self.buckets_collection: Optional[AsyncIOMotorCollection] = None
        self.objects_collection: Optional[AsyncIOMotorCollection] = None
        self.policies_collection: Optional[AsyncIOMotorCollection] = None
        self.usage_collection: Optional[AsyncIOMotorCollection] = None
        
        logger.info("Storage repository initialized")
    
    async def initialize(self):
        """Initialize repository with MongoDB connection."""
        try:
            # Create MongoDB client
            self.client = AsyncIOMotorClient(self.connection_string)
            self.database = self.client[self.database_name]
            
            # Get collections
            self.buckets_collection = self.database[self.buckets_collection_name]
            self.objects_collection = self.database[self.objects_collection_name]
            self.policies_collection = self.database[self.policies_collection_name]
            self.usage_collection = self.database[self.usage_collection_name]
            
            # Test connection
            await self._test_connection()
            
            # Create indexes
            await self._create_indexes()
            
            logger.info("Storage repository connected to MongoDB")
            
        except Exception as e:
            logger.error(f"Failed to initialize storage repository: {e}")
            raise
    
    async def close(self):
        """Close MongoDB connection."""
        if self.client:
            self.client.close()
            logger.info("Storage repository connection closed")
    
    @traced("storage_repository_create_bucket")
    async def create_bucket(self, bucket: StorageBucket) -> str:
        """Create a bucket metadata record."""
        try:
            bucket_data = bucket.dict()
            bucket_data["created_at"] = bucket.created_at
            bucket_data["updated_at"] = bucket.updated_at
            
            result = await self.buckets_collection.insert_one(bucket_data)
            bucket_id = str(result.inserted_id)
            
            # Update bucket with ID
            await self.buckets_collection.update_one(
                {"_id": result.inserted_id},
                {"$set": {"id": bucket_id}}
            )
            
            logger.debug(f"Bucket metadata created: {bucket_id}")
            metrics.storage_repository_buckets_created.inc()
            
            return bucket_id
            
        except DuplicateKeyError:
            logger.error(f"Bucket already exists: {bucket.bucket_name}")
            raise ValueError(f"Bucket already exists: {bucket.bucket_name}")
        except Exception as e:
            logger.error(f"Error creating bucket metadata: {e}")
            metrics.storage_repository_errors.inc()
            raise
    
    @traced("storage_repository_create_object")
    async def create_object(self, obj: StorageObject) -> str:
        """Create an object metadata record."""
        try:
            object_data = obj.dict()
            object_data["created_at"] = obj.created_at
            object_data["updated_at"] = obj.updated_at
            
            result = await self.objects_collection.insert_one(object_data)
            object_id = str(result.inserted_id)
            
            # Update object with ID
            await self.objects_collection.update_one(
                {"_id": result.inserted_id},
                {"$set": {"id": object_id}}
            )
            
            logger.debug(f"Object metadata created: {object_id}")
            metrics.storage_repository_objects_created.inc()
            
            return object_id
            
        except Exception as e:
            logger.error(f"Error creating object metadata: {e}")
            metrics.storage_repository_errors.inc()
            raise
    
    @traced("storage_repository_get_bucket_by_name")
    async def get_bucket_by_name(self, bucket_name: str) -> Optional[StorageBucket]:
        """Get bucket by name."""
        try:
            bucket_data = await self.buckets_collection.find_one(
                {"bucket_name": bucket_name}
            )
            
            if not bucket_data:
                return None
            
            return StorageBucket(**bucket_data)
            
        except Exception as e:
            logger.error(f"Error getting bucket by name: {e}")
            metrics.storage_repository_errors.inc()
            raise
    
    @traced("storage_repository_get_object")
    async def get_object(
        self, 
        bucket_name: str, 
        object_key: str, 
        version_id: Optional[str] = None
    ) -> Optional[StorageObject]:
        """Get object metadata."""
        try:
            query = {
                "bucket_name": bucket_name,
                "object_key": object_key
            }
            
            if version_id:
                query["version_id"] = version_id
            
            object_data = await self.objects_collection.find_one(query)
            
            if not object_data:
                return None
            
            return StorageObject(**object_data)
            
        except Exception as e:
            logger.error(f"Error getting object metadata: {e}")
            metrics.storage_repository_errors.inc()
            raise
    
    @traced("storage_repository_update_object")
    async def update_object(
        self, 
        bucket_name: str, 
        object_key: str,
        updates: Dict[str, Any]
    ) -> bool:
        """Update object metadata."""
        try:
            updates["updated_at"] = datetime.now(timezone.utc)
            
            result = await self.objects_collection.update_one(
                {
                    "bucket_name": bucket_name,
                    "object_key": object_key
                },
                {"$set": updates}
            )
            
            success = result.modified_count > 0
            
            if success:
                logger.debug(f"Object metadata updated: {bucket_name}/{object_key}")
                metrics.storage_repository_objects_updated.inc()
            
            return success
            
        except Exception as e:
            logger.error(f"Error updating object metadata: {e}")
            metrics.storage_repository_errors.inc()
            raise
    
    @traced("storage_repository_list_buckets")
    async def list_buckets(
        self, 
        limit: int = 100, 
        offset: int = 0
    ) -> List[StorageBucket]:
        """List buckets with pagination."""
        try:
            cursor = self.buckets_collection.find().skip(offset).limit(limit)
            buckets = []
            
            async for bucket_data in cursor:
                buckets.append(StorageBucket(**bucket_data))
            
            return buckets
            
        except Exception as e:
            logger.error(f"Error listing buckets: {e}")
            metrics.storage_repository_errors.inc()
            raise
    
    @traced("storage_repository_list_objects")
    async def list_objects(
        self, 
        bucket_name: str,
        prefix: Optional[str] = None,
        limit: int = 100, 
        offset: int = 0
    ) -> List[StorageObject]:
        """List objects in a bucket with pagination."""
        try:
            query = {"bucket_name": bucket_name}
            
            if prefix:
                query["object_key"] = {"$regex": f"^{prefix}"}
            
            cursor = self.objects_collection.find(query).skip(offset).limit(limit)
            objects = []
            
            async for object_data in cursor:
                objects.append(StorageObject(**object_data))
            
            return objects
            
        except Exception as e:
            logger.error(f"Error listing objects: {e}")
            metrics.storage_repository_errors.inc()
            raise
    
    @traced("storage_repository_count_buckets")
    async def count_buckets(self) -> int:
        """Count total number of buckets."""
        try:
            count = await self.buckets_collection.count_documents({})
            return count
            
        except Exception as e:
            logger.error(f"Error counting buckets: {e}")
            metrics.storage_repository_errors.inc()
            raise
    
    @traced("storage_repository_count_objects")
    async def count_objects(
        self, 
        bucket_name: str, 
        prefix: Optional[str] = None
    ) -> int:
        """Count objects in a bucket."""
        try:
            query = {"bucket_name": bucket_name}
            
            if prefix:
                query["object_key"] = {"$regex": f"^{prefix}"}
            
            count = await self.objects_collection.count_documents(query)
            return count
            
        except Exception as e:
            logger.error(f"Error counting objects: {e}")
            metrics.storage_repository_errors.inc()
            raise
    
    @traced("storage_repository_get_bucket_usage")
    async def get_bucket_usage(self, bucket_name: str) -> Dict[str, Any]:
        """Get bucket usage statistics."""
        try:
            # Aggregate object statistics for the bucket
            pipeline = [
                {"$match": {"bucket_name": bucket_name}},
                {
                    "$group": {
                        "_id": "$bucket_name",
                        "total_objects": {"$sum": 1},
                        "total_size": {"$sum": "$size"},
                        "avg_size": {"$avg": "$size"},
                        "object_types": {"$addToSet": "$object_type"},
                        "storage_classes": {"$addToSet": "$storage_class"},
                        "last_modified": {"$max": "$updated_at"}
                    }
                }
            ]
            
            cursor = self.objects_collection.aggregate(pipeline)
            result = await cursor.to_list(length=1)
            
            if not result:
                return {
                    "total_objects": 0,
                    "total_size": 0,
                    "avg_size": 0,
                    "object_types": [],
                    "storage_classes": [],
                    "last_modified": None
                }
            
            usage_stats = result[0]
            usage_stats.pop("_id", None)
            
            return usage_stats
            
        except Exception as e:
            logger.error(f"Error getting bucket usage: {e}")
            metrics.storage_repository_errors.inc()
            raise
    
    @traced("storage_repository_get_objects_by_type")
    async def get_objects_by_type(
        self, 
        object_type: ObjectType,
        limit: int = 100
    ) -> List[StorageObject]:
        """Get objects by type."""
        try:
            cursor = self.objects_collection.find(
                {"object_type": object_type}
            ).limit(limit)
            
            objects = []
            async for object_data in cursor:
                objects.append(StorageObject(**object_data))
            
            return objects
            
        except Exception as e:
            logger.error(f"Error getting objects by type: {e}")
            metrics.storage_repository_errors.inc()
            raise
    
    @traced("storage_repository_get_expired_objects")
    async def get_expired_objects(self) -> List[StorageObject]:
        """Get objects that have exceeded their retention period."""
        try:
            current_time = datetime.now(timezone.utc)
            
            # Find objects with retention policy that have expired
            cursor = self.objects_collection.find({
                "retention_until": {"$lt": current_time}
            })
            
            expired_objects = []
            async for object_data in cursor:
                expired_objects.append(StorageObject(**object_data))
            
            return expired_objects
            
        except Exception as e:
            logger.error(f"Error getting expired objects: {e}")
            metrics.storage_repository_errors.inc()
            raise
    
    @traced("storage_repository_delete_object")
    async def delete_object(
        self, 
        bucket_name: str, 
        object_key: str,
        version_id: Optional[str] = None
    ) -> bool:
        """Delete object metadata."""
        try:
            query = {
                "bucket_name": bucket_name,
                "object_key": object_key
            }
            
            if version_id:
                query["version_id"] = version_id
            
            result = await self.objects_collection.delete_one(query)
            success = result.deleted_count > 0
            
            if success:
                logger.debug(f"Object metadata deleted: {bucket_name}/{object_key}")
                metrics.storage_repository_objects_deleted.inc()
            
            return success
            
        except Exception as e:
            logger.error(f"Error deleting object metadata: {e}")
            metrics.storage_repository_errors.inc()
            raise
    
    @traced("storage_repository_delete_bucket")
    async def delete_bucket(self, bucket_name: str) -> bool:
        """Delete bucket metadata."""
        try:
            result = await self.buckets_collection.delete_one({
                "bucket_name": bucket_name
            })
            
            success = result.deleted_count > 0
            
            if success:
                logger.debug(f"Bucket metadata deleted: {bucket_name}")
                metrics.storage_repository_buckets_deleted.inc()
            
            return success
            
        except Exception as e:
            logger.error(f"Error deleting bucket metadata: {e}")
            metrics.storage_repository_errors.inc()
            raise
    
    @traced("storage_repository_create_policy")
    async def create_policy(self, policy: StoragePolicy) -> str:
        """Create a storage policy."""
        try:
            policy_data = policy.dict()
            policy_data["created_at"] = policy.created_at
            policy_data["updated_at"] = policy.updated_at
            
            result = await self.policies_collection.insert_one(policy_data)
            policy_id = str(result.inserted_id)
            
            # Update policy with ID
            await self.policies_collection.update_one(
                {"_id": result.inserted_id},
                {"$set": {"id": policy_id}}
            )
            
            logger.debug(f"Storage policy created: {policy_id}")
            metrics.storage_repository_policies_created.inc()
            
            return policy_id
            
        except Exception as e:
            logger.error(f"Error creating storage policy: {e}")
            metrics.storage_repository_errors.inc()
            raise
    
    @traced("storage_repository_record_usage")
    async def record_usage(
        self, 
        bucket_name: str, 
        operation: str, 
        size: int = 0
    ):
        """Record usage statistics."""
        try:
            usage_record = {
                "bucket_name": bucket_name,
                "operation": operation,
                "size": size,
                "timestamp": datetime.now(timezone.utc),
                "date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                "hour": datetime.now(timezone.utc).hour
            }
            
            await self.usage_collection.insert_one(usage_record)
            
            logger.debug(f"Usage recorded: {bucket_name} - {operation}")
            metrics.storage_repository_usage_recorded.inc()
            
        except Exception as e:
            logger.error(f"Error recording usage: {e}")
            metrics.storage_repository_errors.inc()
    
    async def _test_connection(self):
        """Test MongoDB connection."""
        try:
            await self.client.admin.command('ping')
            logger.info("MongoDB connection test passed")
        except Exception as e:
            logger.error(f"MongoDB connection test failed: {e}")
            raise
    
    async def _create_indexes(self):
        """Create database indexes."""
        try:
            # Bucket indexes
            bucket_indexes = [
                IndexModel([("bucket_name", ASCENDING)], unique=True),
                IndexModel([("created_at", DESCENDING)]),
                IndexModel([("storage_class", ASCENDING)]),
                IndexModel([("access_level", ASCENDING)])
            ]
            await self.buckets_collection.create_indexes(bucket_indexes)
            
            # Object indexes
            object_indexes = [
                IndexModel([("bucket_name", ASCENDING), ("object_key", ASCENDING)], unique=True),
                IndexModel([("bucket_name", ASCENDING)]),
                IndexModel([("object_type", ASCENDING)]),
                IndexModel([("storage_class", ASCENDING)]),
                IndexModel([("created_at", DESCENDING)]),
                IndexModel([("updated_at", DESCENDING)]),
                IndexModel([("retention_until", ASCENDING)]),
                IndexModel([("size", DESCENDING)]),
                IndexModel([("tags", ASCENDING)])
            ]
            await self.objects_collection.create_indexes(object_indexes)
            
            # Policy indexes
            policy_indexes = [
                IndexModel([("policy_name", ASCENDING)], unique=True),
                IndexModel([("bucket_name", ASCENDING)]),
                IndexModel([("created_at", DESCENDING)])
            ]
            await self.policies_collection.create_indexes(policy_indexes)
            
            # Usage indexes
            usage_indexes = [
                IndexModel([("bucket_name", ASCENDING), ("date", ASCENDING)]),
                IndexModel([("operation", ASCENDING)]),
                IndexModel([("timestamp", DESCENDING)])
            ]
            await self.usage_collection.create_indexes(usage_indexes)
            
            logger.info("Database indexes created")
            
        except Exception as e:
            logger.error(f"Error creating indexes: {e}")
    
    def get_stats(self) -> Dict[str, Any]:
        """Get repository statistics."""
        return {
            "connection_status": "connected" if self.client else "disconnected",
            "database": self.database_name,
            "collections": {
                "buckets": self.buckets_collection_name,
                "objects": self.objects_collection_name,
                "policies": self.policies_collection_name,
                "usage": self.usage_collection_name
            },
            "operations": [
                "create_bucket", "create_object", "get_bucket_by_name",
                "get_object", "update_object", "list_buckets", "list_objects",
                "count_buckets", "count_objects", "get_bucket_usage",
                "get_objects_by_type", "get_expired_objects", "delete_object",
                "delete_bucket", "create_policy", "record_usage"
            ]
        }