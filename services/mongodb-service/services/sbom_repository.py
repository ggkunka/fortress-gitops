"""
SBOM Repository Service - MongoDB-based SBOM document management

This service provides comprehensive SBOM document storage, retrieval, and management
capabilities using MongoDB as the backend.
"""

import json
import hashlib
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from uuid import uuid4
from bson import ObjectId
from pymongo import DESCENDING, ASCENDING
from motor.motor_asyncio import AsyncIOMotorCollection

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

from ..models.sbom import (
    SBOMDocument, ComponentModel, VulnerabilityModel, LicenseModel,
    SBOMFormat, SBOMStatus, ComponentType, SBOMQuery, SBOMStats,
    ComponentQuery, get_mongo_db, create_sbom_document
)

logger = get_logger(__name__)
metrics = get_metrics()


class SBOMRepository:
    """
    SBOM document repository for MongoDB operations.
    
    This repository provides:
    1. SBOM document CRUD operations
    2. Advanced search and filtering
    3. Vulnerability analysis
    4. License compliance checking
    5. Component relationship mapping
    6. Performance analytics
    """
    
    def __init__(self):
        self.db = None
        self.sbom_collection: Optional[AsyncIOMotorCollection] = None
        self.component_collection: Optional[AsyncIOMotorCollection] = None
        self.vulnerability_collection: Optional[AsyncIOMotorCollection] = None
        
        logger.info("SBOM repository initialized")
    
    async def initialize(self):
        """Initialize repository with database connection."""
        try:
            self.db = await get_mongo_db()
            self.sbom_collection = self.db.sbom_documents
            self.component_collection = self.db.components
            self.vulnerability_collection = self.db.vulnerabilities
            
            logger.info("SBOM repository connected to MongoDB")
            
        except Exception as e:
            logger.error(f"Failed to initialize SBOM repository: {e}")
            raise
    
    @traced("sbom_repository_create_sbom")
    async def create_sbom(self, sbom: SBOMDocument) -> SBOMDocument:
        """Create a new SBOM document."""
        try:
            # Calculate file hash
            if sbom.raw_content:
                sbom.file_hash = hashlib.sha256(sbom.raw_content.encode()).hexdigest()
                sbom.file_size = len(sbom.raw_content)
            
            # Set timestamps
            sbom.created_at = datetime.now()
            sbom.updated_at = datetime.now()
            
            # Convert to dict for MongoDB
            sbom_dict = sbom.dict(by_alias=True, exclude_none=True)
            
            # Insert into MongoDB
            result = await self.sbom_collection.insert_one(sbom_dict)
            sbom.mongodb_id = str(result.inserted_id)
            
            # Update component counts
            await self._update_component_counts(sbom)
            
            logger.info(f"SBOM document created: {sbom.id}")
            metrics.mongodb_sbom_documents_created.inc()
            
            return sbom
            
        except Exception as e:
            logger.error(f"Error creating SBOM document: {e}")
            metrics.mongodb_sbom_operations_failed.inc()
            raise
    
    @traced("sbom_repository_get_sbom")
    async def get_sbom(self, sbom_id: str) -> Optional[SBOMDocument]:
        """Get SBOM document by ID."""
        try:
            # Try to find by custom ID first
            doc = await self.sbom_collection.find_one({"id": sbom_id})
            
            # If not found, try MongoDB ObjectId
            if not doc:
                if ObjectId.is_valid(sbom_id):
                    doc = await self.sbom_collection.find_one({"_id": ObjectId(sbom_id)})
            
            if not doc:
                return None
            
            # Convert ObjectId to string
            if "_id" in doc:
                doc["_id"] = str(doc["_id"])
            
            # Create SBOM document
            sbom = SBOMDocument(**doc)
            
            logger.debug(f"Retrieved SBOM document: {sbom_id}")
            return sbom
            
        except Exception as e:
            logger.error(f"Error retrieving SBOM document {sbom_id}: {e}")
            metrics.mongodb_sbom_operations_failed.inc()
            raise
    
    @traced("sbom_repository_update_sbom")
    async def update_sbom(self, sbom_id: str, updates: Dict[str, Any]) -> Optional[SBOMDocument]:
        """Update SBOM document."""
        try:
            # Add updated timestamp
            updates["updated_at"] = datetime.now()
            
            # Update in MongoDB
            result = await self.sbom_collection.update_one(
                {"id": sbom_id},
                {"$set": updates}
            )
            
            if result.matched_count == 0:
                return None
            
            # Get updated document
            updated_sbom = await self.get_sbom(sbom_id)
            
            # Update component counts if components were modified
            if "components" in updates:
                await self._update_component_counts(updated_sbom)
            
            logger.info(f"SBOM document updated: {sbom_id}")
            metrics.mongodb_sbom_documents_updated.inc()
            
            return updated_sbom
            
        except Exception as e:
            logger.error(f"Error updating SBOM document {sbom_id}: {e}")
            metrics.mongodb_sbom_operations_failed.inc()
            raise
    
    @traced("sbom_repository_delete_sbom")
    async def delete_sbom(self, sbom_id: str) -> bool:
        """Delete SBOM document."""
        try:
            # Delete from MongoDB
            result = await self.sbom_collection.delete_one({"id": sbom_id})
            
            if result.deleted_count == 0:
                return False
            
            logger.info(f"SBOM document deleted: {sbom_id}")
            metrics.mongodb_sbom_documents_deleted.inc()
            
            return True
            
        except Exception as e:
            logger.error(f"Error deleting SBOM document {sbom_id}: {e}")
            metrics.mongodb_sbom_operations_failed.inc()
            raise
    
    @traced("sbom_repository_search_sboms")
    async def search_sboms(self, query: SBOMQuery) -> Tuple[List[SBOMDocument], int]:
        """Search SBOM documents with filtering and pagination."""
        try:
            # Build MongoDB query
            mongo_query = self._build_mongo_query(query)
            
            # Get total count
            total_count = await self.sbom_collection.count_documents(mongo_query)
            
            # Build sort criteria
            sort_order = DESCENDING if query.sort_order == "desc" else ASCENDING
            sort_criteria = [(query.sort_by, sort_order)]
            
            # Execute query with pagination
            cursor = self.sbom_collection.find(mongo_query).sort(sort_criteria).skip(query.offset).limit(query.limit)
            
            # Convert documents to SBOM objects
            sboms = []
            async for doc in cursor:
                if "_id" in doc:
                    doc["_id"] = str(doc["_id"])
                sboms.append(SBOMDocument(**doc))
            
            logger.debug(f"Found {len(sboms)} SBOM documents (total: {total_count})")
            
            return sboms, total_count
            
        except Exception as e:
            logger.error(f"Error searching SBOM documents: {e}")
            metrics.mongodb_sbom_operations_failed.inc()
            raise
    
    @traced("sbom_repository_get_components")
    async def get_components(self, sbom_id: str, query: ComponentQuery) -> Tuple[List[ComponentModel], int]:
        """Get components from SBOM with filtering."""
        try:
            # Get SBOM document
            sbom = await self.get_sbom(sbom_id)
            if not sbom:
                return [], 0
            
            # Filter components
            filtered_components = []
            for component in sbom.components:
                if self._matches_component_query(component, query):
                    filtered_components.append(component)
            
            # Sort components
            filtered_components.sort(key=lambda c: getattr(c, query.sort_by, ""))
            if query.sort_order == "desc":
                filtered_components.reverse()
            
            # Apply pagination
            total_count = len(filtered_components)
            start = query.offset
            end = start + query.limit
            paginated_components = filtered_components[start:end]
            
            logger.debug(f"Found {len(paginated_components)} components for SBOM {sbom_id}")
            
            return paginated_components, total_count
            
        except Exception as e:
            logger.error(f"Error getting components for SBOM {sbom_id}: {e}")
            metrics.mongodb_sbom_operations_failed.inc()
            raise
    
    @traced("sbom_repository_get_vulnerabilities")
    async def get_vulnerabilities(self, sbom_id: str, severity_filter: Optional[str] = None) -> List[VulnerabilityModel]:
        """Get all vulnerabilities from SBOM components."""
        try:
            # Get SBOM document
            sbom = await self.get_sbom(sbom_id)
            if not sbom:
                return []
            
            # Collect vulnerabilities from all components
            vulnerabilities = []
            for component in sbom.components:
                for vuln in component.vulnerabilities:
                    if not severity_filter or vuln.severity.lower() == severity_filter.lower():
                        vulnerabilities.append(vuln)
            
            logger.debug(f"Found {len(vulnerabilities)} vulnerabilities for SBOM {sbom_id}")
            
            return vulnerabilities
            
        except Exception as e:
            logger.error(f"Error getting vulnerabilities for SBOM {sbom_id}: {e}")
            metrics.mongodb_sbom_operations_failed.inc()
            raise
    
    @traced("sbom_repository_get_licenses")
    async def get_licenses(self, sbom_id: str) -> List[LicenseModel]:
        """Get all licenses from SBOM components."""
        try:
            # Get SBOM document
            sbom = await self.get_sbom(sbom_id)
            if not sbom:
                return []
            
            # Collect unique licenses
            licenses = []
            seen_licenses = set()
            
            for component in sbom.components:
                for license in component.licenses:
                    license_key = f"{license.id}:{license.name}"
                    if license_key not in seen_licenses:
                        licenses.append(license)
                        seen_licenses.add(license_key)
            
            logger.debug(f"Found {len(licenses)} unique licenses for SBOM {sbom_id}")
            
            return licenses
            
        except Exception as e:
            logger.error(f"Error getting licenses for SBOM {sbom_id}: {e}")
            metrics.mongodb_sbom_operations_failed.inc()
            raise
    
    @traced("sbom_repository_get_statistics")
    async def get_statistics(self, date_range: Optional[Tuple[datetime, datetime]] = None) -> SBOMStats:
        """Get comprehensive SBOM statistics."""
        try:
            # Build date filter
            date_filter = {}
            if date_range:
                start_date, end_date = date_range
                date_filter = {
                    "created_at": {
                        "$gte": start_date,
                        "$lte": end_date
                    }
                }
            
            # Get basic counts
            pipeline = [
                {"$match": date_filter},
                {"$group": {
                    "_id": None,
                    "total_sboms": {"$sum": 1},
                    "total_components": {"$sum": "$total_components"},
                    "total_vulnerabilities": {"$sum": "$vulnerable_components"},
                    "high_severity_vulns": {"$sum": "$high_severity_vulnerabilities"},
                    "medium_severity_vulns": {"$sum": "$medium_severity_vulnerabilities"},
                    "low_severity_vulns": {"$sum": "$low_severity_vulnerabilities"}
                }}
            ]
            
            basic_stats = await self.sbom_collection.aggregate(pipeline).to_list(1)
            
            # Get status distribution
            status_pipeline = [
                {"$match": date_filter},
                {"$group": {"_id": "$status", "count": {"$sum": 1}}}
            ]
            
            status_stats = await self.sbom_collection.aggregate(status_pipeline).to_list(None)
            
            # Get format distribution
            format_pipeline = [
                {"$match": date_filter},
                {"$group": {"_id": "$format", "count": {"$sum": 1}}}
            ]
            
            format_stats = await self.sbom_collection.aggregate(format_pipeline).to_list(None)
            
            # Get environment distribution
            env_pipeline = [
                {"$match": date_filter},
                {"$group": {"_id": "$environment", "count": {"$sum": 1}}}
            ]
            
            env_stats = await self.sbom_collection.aggregate(env_pipeline).to_list(None)
            
            # Get top vulnerable components
            vuln_pipeline = [
                {"$match": date_filter},
                {"$unwind": "$components"},
                {"$match": {"components.vulnerabilities": {"$exists": True, "$ne": []}}},
                {"$group": {
                    "_id": {
                        "name": "$components.name",
                        "version": "$components.version"
                    },
                    "vulnerability_count": {"$sum": {"$size": "$components.vulnerabilities"}},
                    "sbom_count": {"$sum": 1}
                }},
                {"$sort": {"vulnerability_count": -1}},
                {"$limit": 10}
            ]
            
            vuln_components = await self.sbom_collection.aggregate(vuln_pipeline).to_list(None)
            
            # Build statistics object
            stats = SBOMStats()
            
            if basic_stats:
                basic = basic_stats[0]
                stats.total_sboms = basic.get("total_sboms", 0)
                stats.total_components = basic.get("total_components", 0)
                stats.total_vulnerabilities = basic.get("total_vulnerabilities", 0)
                stats.vulnerabilities_by_severity = {
                    "high": basic.get("high_severity_vulns", 0),
                    "medium": basic.get("medium_severity_vulns", 0),
                    "low": basic.get("low_severity_vulns", 0)
                }
            
            # Process distributions
            stats.sboms_by_status = {item["_id"]: item["count"] for item in status_stats if item["_id"]}
            stats.sboms_by_format = {item["_id"]: item["count"] for item in format_stats if item["_id"]}
            stats.sboms_by_environment = {item["_id"]: item["count"] for item in env_stats if item["_id"]}
            
            # Process vulnerable components
            stats.top_vulnerable_components = [
                {
                    "name": item["_id"]["name"],
                    "version": item["_id"]["version"],
                    "vulnerability_count": item["vulnerability_count"],
                    "sbom_count": item["sbom_count"]
                }
                for item in vuln_components
            ]
            
            logger.debug("Generated SBOM statistics")
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting SBOM statistics: {e}")
            metrics.mongodb_sbom_operations_failed.inc()
            raise
    
    @traced("sbom_repository_update_processing_status")
    async def update_processing_status(self, sbom_id: str, status: SBOMStatus, error_message: Optional[str] = None):
        """Update SBOM processing status."""
        try:
            updates = {
                "status": status,
                "updated_at": datetime.now()
            }
            
            if status == SBOMStatus.PROCESSING:
                updates["processing_started_at"] = datetime.now()
            elif status in [SBOMStatus.COMPLETED, SBOMStatus.FAILED]:
                updates["processing_completed_at"] = datetime.now()
                
                # Calculate processing duration
                sbom = await self.get_sbom(sbom_id)
                if sbom and sbom.processing_started_at:
                    duration = (datetime.now() - sbom.processing_started_at).total_seconds()
                    updates["processing_duration"] = int(duration)
            
            if error_message:
                updates["error_message"] = error_message
            
            await self.update_sbom(sbom_id, updates)
            
            logger.info(f"Updated processing status for SBOM {sbom_id}: {status}")
            
        except Exception as e:
            logger.error(f"Error updating processing status for SBOM {sbom_id}: {e}")
            raise
    
    async def _update_component_counts(self, sbom: SBOMDocument):
        """Update component and vulnerability counts."""
        try:
            total_components = len(sbom.components)
            vulnerable_components = 0
            high_severity_vulns = 0
            medium_severity_vulns = 0
            low_severity_vulns = 0
            
            for component in sbom.components:
                if component.vulnerabilities:
                    vulnerable_components += 1
                    
                    for vuln in component.vulnerabilities:
                        severity = vuln.severity.lower()
                        if severity in ["high", "critical"]:
                            high_severity_vulns += 1
                        elif severity == "medium":
                            medium_severity_vulns += 1
                        elif severity == "low":
                            low_severity_vulns += 1
            
            # Update counts
            await self.update_sbom(sbom.id, {
                "total_components": total_components,
                "vulnerable_components": vulnerable_components,
                "high_severity_vulnerabilities": high_severity_vulns,
                "medium_severity_vulnerabilities": medium_severity_vulns,
                "low_severity_vulnerabilities": low_severity_vulns
            })
            
        except Exception as e:
            logger.error(f"Error updating component counts: {e}")
    
    def _build_mongo_query(self, query: SBOMQuery) -> Dict[str, Any]:
        """Build MongoDB query from search parameters."""
        mongo_query = {}
        
        if query.name:
            mongo_query["name"] = {"$regex": query.name, "$options": "i"}
        
        if query.version:
            mongo_query["version"] = {"$regex": query.version, "$options": "i"}
        
        if query.format:
            mongo_query["format"] = query.format
        
        if query.status:
            mongo_query["status"] = query.status
        
        if query.created_by:
            mongo_query["created_by"] = query.created_by
        
        if query.source:
            mongo_query["source"] = {"$regex": query.source, "$options": "i"}
        
        if query.has_vulnerabilities is not None:
            if query.has_vulnerabilities:
                mongo_query["vulnerable_components"] = {"$gt": 0}
            else:
                mongo_query["vulnerable_components"] = 0
        
        if query.component_name:
            mongo_query["components.name"] = {"$regex": query.component_name, "$options": "i"}
        
        if query.tag:
            mongo_query["tags"] = query.tag
        
        if query.category:
            mongo_query["category"] = query.category
        
        if query.environment:
            mongo_query["environment"] = query.environment
        
        # Date range filter
        if query.date_from or query.date_to:
            date_filter = {}
            if query.date_from:
                date_filter["$gte"] = query.date_from
            if query.date_to:
                date_filter["$lte"] = query.date_to
            mongo_query["created_at"] = date_filter
        
        return mongo_query
    
    def _matches_component_query(self, component: ComponentModel, query: ComponentQuery) -> bool:
        """Check if component matches query criteria."""
        if query.name and query.name.lower() not in component.name.lower():
            return False
        
        if query.version and component.version and query.version.lower() not in component.version.lower():
            return False
        
        if query.type and component.type != query.type:
            return False
        
        if query.supplier and component.supplier and query.supplier.lower() not in component.supplier.lower():
            return False
        
        if query.has_vulnerabilities is not None:
            has_vulns = len(component.vulnerabilities) > 0
            if query.has_vulnerabilities != has_vulns:
                return False
        
        if query.license_name:
            license_match = any(
                license.name and query.license_name.lower() in license.name.lower()
                for license in component.licenses
            )
            if not license_match:
                return False
        
        if query.purl and component.package_url and query.purl.lower() not in component.package_url.lower():
            return False
        
        return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Get repository statistics."""
        return {
            "collections": {
                "sbom_documents": "Primary SBOM storage",
                "components": "Component analysis cache",
                "vulnerabilities": "Vulnerability intelligence cache"
            },
            "operations": [
                "create_sbom", "get_sbom", "update_sbom", "delete_sbom",
                "search_sboms", "get_components", "get_vulnerabilities",
                "get_licenses", "get_statistics"
            ]
        }