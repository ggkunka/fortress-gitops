"""
Plugin Registry - Plugin metadata management and discovery service

This service manages plugin registration, metadata, versioning, and provides
plugin discovery capabilities for the marketplace.
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from uuid import UUID, uuid4
import hashlib
import re

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.database.connection import get_db

from ..models.plugin import (
    Plugin, PluginStatus, PluginCategory, PluginType,
    PluginCreate, PluginUpdate, PluginResponse,
    create_plugin
)

logger = get_logger(__name__)
metrics = get_metrics()


class PluginRegistry:
    """
    Plugin registry service for managing plugin metadata and discovery.
    
    This service handles:
    - Plugin registration and metadata management
    - Version management and compatibility checking
    - Plugin lifecycle management
    - Search and discovery operations
    - Metadata validation and normalization
    """
    
    def __init__(self):
        # Plugin metadata cache
        self.plugin_cache = {}
        self.cache_ttl = 3600  # 1 hour
        
        # Registry statistics
        self.stats = {
            "plugins_registered": 0,
            "plugins_updated": 0,
            "plugins_discovered": 0,
            "validation_errors": 0,
            "cache_hits": 0,
            "cache_misses": 0
        }
        
        # Validation patterns
        self.version_pattern = re.compile(r'^\d+\.\d+\.\d+(?:-[a-zA-Z0-9]+)?$')
        self.slug_pattern = re.compile(r'^[a-z0-9]+(?:-[a-z0-9]+)*$')
        
        logger.info("Plugin registry initialized")
    
    async def start(self):
        """Start the plugin registry service."""
        try:
            # Initialize registry data
            await self._initialize_registry()
            
            # Start background tasks
            asyncio.create_task(self._cache_cleanup_task())
            asyncio.create_task(self._metadata_validation_task())
            
            logger.info("Plugin registry service started successfully")
            
        except Exception as e:
            logger.error(f"Error starting plugin registry: {e}")
            raise
    
    async def stop(self):
        """Stop the plugin registry service."""
        try:
            # Clear caches
            self.plugin_cache.clear()
            
            logger.info("Plugin registry service stopped")
            
        except Exception as e:
            logger.error(f"Error stopping plugin registry: {e}")
    
    @traced("registry_register_plugin")
    async def register_plugin(
        self,
        plugin_data: PluginCreate,
        author_id: str,
        package_file: Optional[bytes] = None
    ) -> Dict[str, Any]:
        """Register a new plugin in the registry."""
        try:
            # Validate plugin data
            validation_result = await self._validate_plugin_data(plugin_data)
            if not validation_result["valid"]:
                return {
                    "success": False,
                    "error": "Plugin validation failed",
                    "validation_errors": validation_result["errors"]
                }
            
            # Check for duplicate names/slugs
            slug = self._generate_slug(plugin_data.name)
            existing_plugin = await self._get_plugin_by_slug(slug)
            if existing_plugin:
                return {
                    "success": False,
                    "error": f"Plugin with slug '{slug}' already exists"
                }
            
            # Create plugin record
            with get_db() as db:
                plugin = create_plugin(
                    name=plugin_data.name,
                    version=plugin_data.version,
                    description=plugin_data.description,
                    category=plugin_data.category,
                    plugin_type=plugin_data.plugin_type,
                    author_id=author_id,
                    author_name=plugin_data.author_name,
                    long_description=plugin_data.long_description,
                    tags=plugin_data.tags,
                    author_email=plugin_data.author_email,
                    organization=plugin_data.organization,
                    package_url=plugin_data.package_url,
                    repository_url=plugin_data.repository_url,
                    documentation_url=plugin_data.documentation_url,
                    homepage_url=plugin_data.homepage_url,
                    python_version=plugin_data.python_version,
                    mcp_version=plugin_data.mcp_version,
                    dependencies=plugin_data.dependencies,
                    system_requirements=plugin_data.system_requirements,
                    config_schema=plugin_data.config_schema,
                    default_config=plugin_data.default_config,
                    capabilities=plugin_data.capabilities,
                    license=plugin_data.license,
                    license_url=plugin_data.license_url,
                    support_email=plugin_data.support_email,
                    support_url=plugin_data.support_url,
                    is_public=plugin_data.is_public,
                    is_premium=plugin_data.is_premium,
                    status=PluginStatus.DRAFT,
                    slug=slug
                )
                
                db.add(plugin)
                db.commit()
                db.refresh(plugin)
                
                # Process package file if provided
                if package_file:
                    file_info = await self._process_package_file(plugin.id, package_file)
                    plugin.file_size = file_info["size"]
                    plugin.file_hash = file_info["hash"]
                    db.commit()
                
                # Update cache
                self._cache_plugin(plugin)
                
                # Update statistics
                self.stats["plugins_registered"] += 1
                metrics.registry_plugins_registered.inc()
                
                logger.info(f"Plugin registered successfully: {plugin.name} (ID: {plugin.id})")
                
                return {
                    "success": True,
                    "plugin": PluginResponse.from_orm(plugin).dict(),
                    "message": "Plugin registered successfully"
                }
                
        except Exception as e:
            logger.error(f"Error registering plugin: {e}")
            metrics.registry_registration_errors.inc()
            raise
    
    @traced("registry_update_plugin")
    async def update_plugin(
        self,
        plugin_id: UUID,
        update_data: PluginUpdate,
        author_id: str
    ) -> Dict[str, Any]:
        """Update an existing plugin in the registry."""
        try:
            with get_db() as db:
                # Get existing plugin
                plugin = db.query(Plugin).filter(Plugin.id == plugin_id).first()
                if not plugin:
                    return {
                        "success": False,
                        "error": "Plugin not found"
                    }
                
                # Check ownership
                if plugin.author_id != author_id:
                    return {
                        "success": False,
                        "error": "Not authorized to update this plugin"
                    }
                
                # Update fields
                update_fields = update_data.dict(exclude_unset=True)
                for field, value in update_fields.items():
                    if hasattr(plugin, field):
                        setattr(plugin, field, value)
                
                # Update slug if name changed
                if "name" in update_fields:
                    new_slug = self._generate_slug(update_data.name)
                    if new_slug != plugin.slug:
                        # Check if new slug is available
                        existing = db.query(Plugin).filter(
                            Plugin.slug == new_slug,
                            Plugin.id != plugin_id
                        ).first()
                        if existing:
                            return {
                                "success": False,
                                "error": f"Plugin with slug '{new_slug}' already exists"
                            }
                        plugin.slug = new_slug
                
                plugin.updated_at = datetime.utcnow()
                db.commit()
                
                # Update cache
                self._cache_plugin(plugin)
                
                # Update statistics
                self.stats["plugins_updated"] += 1
                metrics.registry_plugins_updated.inc()
                
                logger.info(f"Plugin updated successfully: {plugin.name} (ID: {plugin.id})")
                
                return {
                    "success": True,
                    "plugin": PluginResponse.from_orm(plugin).dict(),
                    "message": "Plugin updated successfully"
                }
                
        except Exception as e:
            logger.error(f"Error updating plugin: {e}")
            metrics.registry_update_errors.inc()
            raise
    
    @traced("registry_get_plugin")
    async def get_plugin(
        self,
        plugin_id: Optional[UUID] = None,
        slug: Optional[str] = None,
        include_metrics: bool = True
    ) -> Optional[Dict[str, Any]]:
        """Get a plugin by ID or slug."""
        try:
            if not plugin_id and not slug:
                return None
            
            # Check cache first
            cache_key = f"plugin_{plugin_id or slug}"
            cached_plugin = self._get_cached_plugin(cache_key)
            if cached_plugin:
                self.stats["cache_hits"] += 1
                return cached_plugin
            
            self.stats["cache_misses"] += 1
            
            with get_db() as db:
                query = db.query(Plugin)
                
                if plugin_id:
                    query = query.filter(Plugin.id == plugin_id)
                else:
                    query = query.filter(Plugin.slug == slug)
                
                plugin = query.first()
                
                if not plugin:
                    return None
                
                plugin_data = PluginResponse.from_orm(plugin).dict()
                
                if include_metrics:
                    # Add additional metrics
                    plugin_data["metrics"] = await self._get_plugin_metrics(plugin.id, db)
                
                # Cache the result
                self._cache_plugin_data(cache_key, plugin_data)
                
                return plugin_data
                
        except Exception as e:
            logger.error(f"Error getting plugin: {e}")
            raise
    
    @traced("registry_list_plugins")
    async def list_plugins(
        self,
        author_id: Optional[str] = None,
        category: Optional[PluginCategory] = None,
        plugin_type: Optional[PluginType] = None,
        status: Optional[PluginStatus] = None,
        is_public: Optional[bool] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """List plugins with filtering options."""
        try:
            with get_db() as db:
                query = db.query(Plugin)
                
                # Apply filters
                if author_id:
                    query = query.filter(Plugin.author_id == author_id)
                
                if category:
                    query = query.filter(Plugin.category == category.value)
                
                if plugin_type:
                    query = query.filter(Plugin.plugin_type == plugin_type.value)
                
                if status:
                    query = query.filter(Plugin.status == status.value)
                
                if is_public is not None:
                    query = query.filter(Plugin.is_public == is_public)
                
                # Get total count
                total_count = query.count()
                
                # Apply ordering and pagination
                plugins = query.order_by(
                    Plugin.created_at.desc()
                ).offset(offset).limit(limit).all()
                
                # Convert to response format
                plugin_list = [
                    PluginResponse.from_orm(plugin).dict()
                    for plugin in plugins
                ]
                
                # Update statistics
                self.stats["plugins_discovered"] += len(plugin_list)
                
                return {
                    "plugins": plugin_list,
                    "total": total_count,
                    "limit": limit,
                    "offset": offset,
                    "has_more": offset + limit < total_count
                }
                
        except Exception as e:
            logger.error(f"Error listing plugins: {e}")
            raise
    
    @traced("registry_change_plugin_status")
    async def change_plugin_status(
        self,
        plugin_id: UUID,
        new_status: PluginStatus,
        changed_by: str,
        reason: Optional[str] = None
    ) -> Dict[str, Any]:
        """Change the status of a plugin."""
        try:
            with get_db() as db:
                plugin = db.query(Plugin).filter(Plugin.id == plugin_id).first()
                if not plugin:
                    return {
                        "success": False,
                        "error": "Plugin not found"
                    }
                
                old_status = plugin.status
                plugin.status = new_status.value
                plugin.updated_at = datetime.utcnow()
                
                # Set published date if moving to published status
                if new_status == PluginStatus.PUBLISHED and old_status != PluginStatus.PUBLISHED.value:
                    plugin.published_at = datetime.utcnow()
                
                db.commit()
                
                # Clear cache
                self._clear_plugin_cache(plugin_id)
                
                logger.info(f"Plugin status changed: {plugin.name} from {old_status} to {new_status.value}")
                
                return {
                    "success": True,
                    "old_status": old_status,
                    "new_status": new_status.value,
                    "message": f"Plugin status changed to {new_status.value}"
                }
                
        except Exception as e:
            logger.error(f"Error changing plugin status: {e}")
            raise
    
    @traced("registry_get_plugin_versions")
    async def get_plugin_versions(
        self,
        plugin_id: UUID
    ) -> List[Dict[str, Any]]:
        """Get version history for a plugin."""
        try:
            with get_db() as db:
                # For now, we'll return current version
                # In a full implementation, this would query a plugin_versions table
                plugin = db.query(Plugin).filter(Plugin.id == plugin_id).first()
                if not plugin:
                    return []
                
                return [{
                    "version": plugin.version,
                    "published_at": plugin.published_at.isoformat() if plugin.published_at else None,
                    "updated_at": plugin.updated_at.isoformat(),
                    "is_current": True
                }]
                
        except Exception as e:
            logger.error(f"Error getting plugin versions: {e}")
            raise
    
    @traced("registry_validate_compatibility")
    async def validate_compatibility(
        self,
        plugin_id: UUID,
        target_mcp_version: str,
        python_version: str
    ) -> Dict[str, Any]:
        """Validate plugin compatibility with target versions."""
        try:
            plugin_data = await self.get_plugin(plugin_id=plugin_id)
            if not plugin_data:
                return {
                    "compatible": False,
                    "error": "Plugin not found"
                }
            
            compatibility_issues = []
            
            # Check MCP version compatibility
            if plugin_data.get("mcp_version"):
                if not self._is_version_compatible(
                    plugin_data["mcp_version"],
                    target_mcp_version
                ):
                    compatibility_issues.append(
                        f"MCP version mismatch: plugin requires {plugin_data['mcp_version']}, target is {target_mcp_version}"
                    )
            
            # Check Python version compatibility
            if plugin_data.get("python_version"):
                if not self._is_version_compatible(
                    plugin_data["python_version"],
                    python_version
                ):
                    compatibility_issues.append(
                        f"Python version mismatch: plugin requires {plugin_data['python_version']}, target is {python_version}"
                    )
            
            # Check system requirements
            system_requirements = plugin_data.get("system_requirements", {})
            if system_requirements:
                # This would check against actual system capabilities
                # For now, we'll just note that requirements exist
                if "memory" in system_requirements:
                    # Would check available memory
                    pass
                if "disk_space" in system_requirements:
                    # Would check available disk space
                    pass
            
            return {
                "compatible": len(compatibility_issues) == 0,
                "issues": compatibility_issues,
                "plugin_requirements": {
                    "mcp_version": plugin_data.get("mcp_version"),
                    "python_version": plugin_data.get("python_version"),
                    "system_requirements": system_requirements,
                    "dependencies": plugin_data.get("dependencies", {})
                }
            }
            
        except Exception as e:
            logger.error(f"Error validating compatibility: {e}")
            raise
    
    def get_stats(self) -> Dict[str, Any]:
        """Get registry statistics."""
        return {
            "service": "plugin_registry",
            "statistics": self.stats.copy(),
            "cache_stats": {
                "cache_size": len(self.plugin_cache),
                "cache_ttl": self.cache_ttl
            },
            "status": "active"
        }
    
    # Private helper methods
    
    async def _initialize_registry(self):
        """Initialize registry data and statistics."""
        try:
            with get_db() as db:
                # Get current statistics
                total_plugins = db.query(Plugin).count()
                published_plugins = db.query(Plugin).filter(
                    Plugin.status == PluginStatus.PUBLISHED
                ).count()
                
                logger.info(f"Registry initialized with {total_plugins} total plugins, {published_plugins} published")
                
        except Exception as e:
            logger.error(f"Error initializing registry: {e}")
    
    async def _validate_plugin_data(self, plugin_data: PluginCreate) -> Dict[str, Any]:
        """Validate plugin data before registration."""
        errors = []
        
        # Validate required fields
        if not plugin_data.name or len(plugin_data.name.strip()) == 0:
            errors.append("Plugin name is required")
        
        if not plugin_data.version or not self.version_pattern.match(plugin_data.version):
            errors.append("Valid semantic version is required (e.g., 1.0.0)")
        
        if not plugin_data.description or len(plugin_data.description.strip()) < 10:
            errors.append("Description must be at least 10 characters long")
        
        # Validate URLs if provided
        url_fields = ["package_url", "repository_url", "documentation_url", "homepage_url", "license_url", "support_url"]
        for field in url_fields:
            value = getattr(plugin_data, field, None)
            if value and not self._is_valid_url(value):
                errors.append(f"Invalid URL format for {field}")
        
        # Validate email if provided
        if plugin_data.author_email and not self._is_valid_email(plugin_data.author_email):
            errors.append("Invalid email format for author_email")
        
        if plugin_data.support_email and not self._is_valid_email(plugin_data.support_email):
            errors.append("Invalid email format for support_email")
        
        # Validate JSON schemas
        if plugin_data.config_schema:
            try:
                json.dumps(plugin_data.config_schema)
            except (TypeError, ValueError):
                errors.append("Invalid JSON format for config_schema")
        
        # Update validation statistics
        if errors:
            self.stats["validation_errors"] += 1
        
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }
    
    def _generate_slug(self, name: str) -> str:
        """Generate a URL-friendly slug from plugin name."""
        slug = name.lower()
        slug = re.sub(r'[^a-z0-9\s-]', '', slug)
        slug = re.sub(r'[\s-]+', '-', slug)
        slug = slug.strip('-')
        return slug
    
    async def _get_plugin_by_slug(self, slug: str) -> Optional[Plugin]:
        """Get plugin by slug."""
        with get_db() as db:
            return db.query(Plugin).filter(Plugin.slug == slug).first()
    
    async def _process_package_file(self, plugin_id: UUID, package_file: bytes) -> Dict[str, Any]:
        """Process uploaded package file."""
        # Calculate file hash
        file_hash = hashlib.sha256(package_file).hexdigest()
        file_size = len(package_file)
        
        # In a real implementation, this would:
        # 1. Store the file in object storage (S3, etc.)
        # 2. Scan the file for security issues
        # 3. Extract metadata from the package
        # 4. Validate the package structure
        
        return {
            "hash": file_hash,
            "size": file_size
        }
    
    async def _get_plugin_metrics(self, plugin_id: UUID, db: Session) -> Dict[str, Any]:
        """Get additional metrics for a plugin."""
        # This would calculate various metrics
        # For now, return empty metrics
        return {
            "recent_downloads": 0,
            "active_installations": 0,
            "recent_reviews": 0
        }
    
    def _is_version_compatible(self, required_version: str, target_version: str) -> bool:
        """Check if versions are compatible using semantic versioning."""
        # Simple compatibility check - in reality, this would be more sophisticated
        try:
            required_parts = [int(x) for x in required_version.split('.')]
            target_parts = [int(x) for x in target_version.split('.')]
            
            # Major version must match, minor/patch can be higher
            if required_parts[0] != target_parts[0]:
                return False
            
            if len(required_parts) > 1 and len(target_parts) > 1:
                if required_parts[1] > target_parts[1]:
                    return False
            
            return True
            
        except (ValueError, IndexError):
            return False
    
    def _is_valid_url(self, url: str) -> bool:
        """Validate URL format."""
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        return url_pattern.match(url) is not None
    
    def _is_valid_email(self, email: str) -> bool:
        """Validate email format."""
        email_pattern = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
        return email_pattern.match(email) is not None
    
    # Cache management
    
    def _cache_plugin(self, plugin: Plugin):
        """Cache plugin data."""
        plugin_data = PluginResponse.from_orm(plugin).dict()
        cache_key = f"plugin_{plugin.id}"
        self.plugin_cache[cache_key] = (datetime.utcnow(), plugin_data)
        
        # Also cache by slug
        slug_cache_key = f"plugin_{plugin.slug}"
        self.plugin_cache[slug_cache_key] = (datetime.utcnow(), plugin_data)
    
    def _cache_plugin_data(self, cache_key: str, plugin_data: Dict[str, Any]):
        """Cache plugin data with key."""
        self.plugin_cache[cache_key] = (datetime.utcnow(), plugin_data)
    
    def _get_cached_plugin(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached plugin data."""
        cached_entry = self.plugin_cache.get(cache_key)
        if cached_entry:
            cached_time, cached_data = cached_entry
            if (datetime.utcnow() - cached_time).total_seconds() < self.cache_ttl:
                return cached_data
            else:
                self.plugin_cache.pop(cache_key, None)
        return None
    
    def _clear_plugin_cache(self, plugin_id: UUID):
        """Clear cached data for a specific plugin."""
        keys_to_remove = [
            key for key in self.plugin_cache.keys()
            if str(plugin_id) in key
        ]
        for key in keys_to_remove:
            self.plugin_cache.pop(key, None)
    
    # Background tasks
    
    async def _cache_cleanup_task(self):
        """Background task to clean up expired cache entries."""
        while True:
            try:
                await asyncio.sleep(600)  # Run every 10 minutes
                
                current_time = datetime.utcnow()
                expired_keys = [
                    key for key, (cached_time, _) in self.plugin_cache.items()
                    if (current_time - cached_time).total_seconds() > self.cache_ttl
                ]
                
                for key in expired_keys:
                    self.plugin_cache.pop(key, None)
                
                logger.debug(f"Cache cleanup: removed {len(expired_keys)} expired entries")
                
            except Exception as e:
                logger.error(f"Error in cache cleanup task: {e}")
    
    async def _metadata_validation_task(self):
        """Background task to validate plugin metadata."""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                # This would validate metadata for plugins that need it
                # For example, checking for broken URLs, validating schemas, etc.
                
                logger.debug("Metadata validation task completed")
                
            except Exception as e:
                logger.error(f"Error in metadata validation task: {e}")