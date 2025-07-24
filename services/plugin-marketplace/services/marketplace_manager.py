"""
Marketplace Manager - Central coordinator for plugin marketplace operations

This service manages the overall plugin marketplace functionality including
plugin discovery, search, recommendations, and marketplace analytics.
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from uuid import UUID
from collections import defaultdict

from sqlalchemy.orm import Session
from sqlalchemy import and_, or_, desc, func, text

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.events.event_bus import EventBus
from shared.database.connection import get_db

from ..models.plugin import (
    Plugin, PluginReview, PluginInstallation, PluginCollection,
    PluginStatus, PluginCategory, PluginType,
    PluginResponse
)

logger = get_logger(__name__)
metrics = get_metrics()


class MarketplaceManager:
    """
    Central marketplace manager for plugin discovery, search, and recommendations.
    
    This service coordinates plugin marketplace operations including:
    - Plugin search and discovery
    - Recommendation engine
    - Marketplace analytics
    - Featured content management
    - Trend analysis
    """
    
    def __init__(
        self,
        registry,
        installer,
        validator,
        executor,
        community,
        event_bus: EventBus
    ):
        self.registry = registry
        self.installer = installer
        self.validator = validator
        self.executor = executor
        self.community = community
        self.event_bus = event_bus
        
        # Search and recommendation caches
        self.search_cache = {}
        self.recommendation_cache = {}
        self.trending_cache = {}
        self.cache_ttl = 900  # 15 minutes
        
        # Analytics tracking
        self.analytics = {
            "searches_performed": 0,
            "plugins_viewed": 0,
            "recommendations_generated": 0,
            "featured_content_views": 0
        }
        
        logger.info("Marketplace manager initialized")
    
    async def start(self):
        """Start the marketplace manager."""
        try:
            # Set up event listeners
            await self._setup_event_handlers()
            
            # Initialize analytics
            await self._initialize_analytics()
            
            # Start background tasks
            asyncio.create_task(self._cache_cleanup_task())
            asyncio.create_task(self._trending_analysis_task())
            asyncio.create_task(self._recommendation_update_task())
            
            logger.info("Marketplace manager started successfully")
            
        except Exception as e:
            logger.error(f"Error starting marketplace manager: {e}")
            raise
    
    async def stop(self):
        """Stop the marketplace manager."""
        try:
            # Clear caches
            self.search_cache.clear()
            self.recommendation_cache.clear()
            self.trending_cache.clear()
            
            logger.info("Marketplace manager stopped")
            
        except Exception as e:
            logger.error(f"Error stopping marketplace manager: {e}")
    
    @traced("marketplace_search_plugins")
    async def search_plugins(
        self,
        query: Optional[str] = None,
        category: Optional[PluginCategory] = None,
        plugin_type: Optional[PluginType] = None,
        tags: Optional[List[str]] = None,
        author: Optional[str] = None,
        min_rating: Optional[float] = None,
        max_price: Optional[float] = None,
        is_featured: Optional[bool] = None,
        is_verified: Optional[bool] = None,
        sort_by: str = "relevance",
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """Search for plugins with advanced filtering and sorting."""
        try:
            # Create cache key
            cache_key = self._create_search_cache_key(
                query, category, plugin_type, tags, author, min_rating,
                max_price, is_featured, is_verified, sort_by, limit, offset
            )
            
            # Check cache
            cached_result = self._get_cached_search(cache_key)
            if cached_result:
                logger.debug(f"Returning cached search results for: {query}")
                return cached_result
            
            # Perform database search
            with get_db() as db:
                query_builder = db.query(Plugin).filter(
                    Plugin.status == PluginStatus.PUBLISHED,
                    Plugin.is_public == True
                )
                
                # Apply filters
                if query:
                    search_terms = query.lower().split()
                    search_conditions = []
                    for term in search_terms:
                        search_conditions.append(
                            or_(
                                Plugin.name.ilike(f"%{term}%"),
                                Plugin.description.ilike(f"%{term}%"),
                                Plugin.long_description.ilike(f"%{term}%"),
                                Plugin.tags.any(term)
                            )
                        )
                    query_builder = query_builder.filter(and_(*search_conditions))
                
                if category:
                    query_builder = query_builder.filter(Plugin.category == category.value)
                
                if plugin_type:
                    query_builder = query_builder.filter(Plugin.plugin_type == plugin_type.value)
                
                if tags:
                    for tag in tags:
                        query_builder = query_builder.filter(Plugin.tags.any(tag))
                
                if author:
                    query_builder = query_builder.filter(
                        or_(
                            Plugin.author_name.ilike(f"%{author}%"),
                            Plugin.organization.ilike(f"%{author}%")
                        )
                    )
                
                if min_rating:
                    query_builder = query_builder.filter(Plugin.rating_average >= min_rating)
                
                if is_featured is not None:
                    query_builder = query_builder.filter(Plugin.is_featured == is_featured)
                
                if is_verified is not None:
                    query_builder = query_builder.filter(Plugin.is_verified == is_verified)
                
                # Apply sorting
                if sort_by == "relevance" and query:
                    # Simple relevance scoring based on name matches
                    query_builder = query_builder.order_by(
                        Plugin.name.ilike(f"%{query}%").desc(),
                        Plugin.rating_average.desc(),
                        Plugin.download_count.desc()
                    )
                elif sort_by == "popular":
                    query_builder = query_builder.order_by(Plugin.download_count.desc())
                elif sort_by == "rating":
                    query_builder = query_builder.order_by(
                        Plugin.rating_average.desc(),
                        Plugin.rating_count.desc()
                    )
                elif sort_by == "newest":
                    query_builder = query_builder.order_by(Plugin.published_at.desc())
                elif sort_by == "updated":
                    query_builder = query_builder.order_by(Plugin.updated_at.desc())
                elif sort_by == "name":
                    query_builder = query_builder.order_by(Plugin.name.asc())
                else:
                    # Default to relevance/popularity
                    query_builder = query_builder.order_by(
                        Plugin.rating_average.desc(),
                        Plugin.download_count.desc()
                    )
                
                # Get total count
                total_count = query_builder.count()
                
                # Apply pagination
                plugins = query_builder.offset(offset).limit(limit).all()
                
                # Convert to response format
                plugin_responses = []
                for plugin in plugins:
                    plugin_data = PluginResponse.from_orm(plugin)
                    plugin_responses.append(plugin_data.dict())
                
                result = {
                    "plugins": plugin_responses,
                    "total": total_count,
                    "limit": limit,
                    "offset": offset,
                    "has_more": offset + limit < total_count,
                    "search_metadata": {
                        "query": query,
                        "filters_applied": {
                            "category": category.value if category else None,
                            "plugin_type": plugin_type.value if plugin_type else None,
                            "tags": tags,
                            "author": author,
                            "min_rating": min_rating,
                            "is_featured": is_featured,
                            "is_verified": is_verified
                        },
                        "sort_by": sort_by
                    }
                }
                
                # Cache the result
                self._cache_search_result(cache_key, result)
                
                # Update analytics
                self.analytics["searches_performed"] += 1
                metrics.marketplace_searches_performed.inc()
                
                logger.info(f"Search completed: {total_count} plugins found for query '{query}'")
                return result
                
        except Exception as e:
            logger.error(f"Error searching plugins: {e}")
            metrics.marketplace_search_errors.inc()
            raise
    
    @traced("marketplace_get_recommendations")
    async def get_recommendations(
        self,
        user_id: str,
        plugin_id: Optional[UUID] = None,
        recommendation_type: str = "personalized",
        limit: int = 10
    ) -> Dict[str, Any]:
        """Get plugin recommendations for a user."""
        try:
            cache_key = f"recommendations_{user_id}_{plugin_id}_{recommendation_type}_{limit}"
            
            # Check cache
            cached_recommendations = self._get_cached_recommendations(cache_key)
            if cached_recommendations:
                logger.debug(f"Returning cached recommendations for user: {user_id}")
                return cached_recommendations
            
            recommendations = []
            
            with get_db() as db:
                if recommendation_type == "personalized":
                    recommendations = await self._get_personalized_recommendations(
                        db, user_id, limit
                    )
                elif recommendation_type == "similar" and plugin_id:
                    recommendations = await self._get_similar_plugins(
                        db, plugin_id, limit
                    )
                elif recommendation_type == "trending":
                    recommendations = await self._get_trending_plugins(db, limit)
                elif recommendation_type == "popular":
                    recommendations = await self._get_popular_plugins(db, limit)
                elif recommendation_type == "new":
                    recommendations = await self._get_new_plugins(db, limit)
                else:
                    # Default to popular plugins
                    recommendations = await self._get_popular_plugins(db, limit)
                
                result = {
                    "recommendations": recommendations,
                    "recommendation_type": recommendation_type,
                    "user_id": user_id,
                    "plugin_id": str(plugin_id) if plugin_id else None,
                    "count": len(recommendations),
                    "generated_at": datetime.utcnow().isoformat()
                }
                
                # Cache the result
                self._cache_recommendations(cache_key, result)
                
                # Update analytics
                self.analytics["recommendations_generated"] += 1
                metrics.marketplace_recommendations_generated.inc()
                
                logger.info(f"Generated {len(recommendations)} {recommendation_type} recommendations for user {user_id}")
                return result
                
        except Exception as e:
            logger.error(f"Error getting recommendations: {e}")
            metrics.marketplace_recommendation_errors.inc()
            raise
    
    @traced("marketplace_get_featured_content")
    async def get_featured_content(
        self,
        content_type: str = "all",
        limit: int = 20
    ) -> Dict[str, Any]:
        """Get featured marketplace content."""
        try:
            cache_key = f"featured_{content_type}_{limit}"
            
            # Check cache
            cached_content = self._get_cached_featured_content(cache_key)
            if cached_content:
                return cached_content
            
            featured_content = {}
            
            with get_db() as db:
                if content_type in ["all", "plugins"]:
                    # Get featured plugins
                    featured_plugins = db.query(Plugin).filter(
                        Plugin.is_featured == True,
                        Plugin.status == PluginStatus.PUBLISHED,
                        Plugin.is_public == True
                    ).order_by(
                        Plugin.rating_average.desc(),
                        Plugin.download_count.desc()
                    ).limit(limit).all()
                    
                    featured_content["plugins"] = [
                        PluginResponse.from_orm(plugin).dict()
                        for plugin in featured_plugins
                    ]
                
                if content_type in ["all", "collections"]:
                    # Get featured collections
                    featured_collections = db.query(PluginCollection).filter(
                        PluginCollection.is_featured == True,
                        PluginCollection.is_public == True
                    ).order_by(
                        PluginCollection.plugin_count.desc(),
                        PluginCollection.subscriber_count.desc()
                    ).limit(limit).all()
                    
                    featured_content["collections"] = [
                        {
                            "id": str(collection.id),
                            "name": collection.name,
                            "slug": collection.slug,
                            "description": collection.description,
                            "curator_name": collection.curator_name,
                            "plugin_count": collection.plugin_count,
                            "subscriber_count": collection.subscriber_count,
                            "cover_image_url": collection.cover_image_url,
                            "is_official": collection.is_official,
                            "created_at": collection.created_at.isoformat(),
                            "updated_at": collection.updated_at.isoformat()
                        }
                        for collection in featured_collections
                    ]
                
                result = {
                    "featured_content": featured_content,
                    "content_type": content_type,
                    "generated_at": datetime.utcnow().isoformat()
                }
                
                # Cache the result
                self._cache_featured_content(cache_key, result)
                
                # Update analytics
                self.analytics["featured_content_views"] += 1
                metrics.marketplace_featured_views.inc()
                
                return result
                
        except Exception as e:
            logger.error(f"Error getting featured content: {e}")
            raise
    
    @traced("marketplace_get_analytics")
    async def get_marketplace_analytics(
        self,
        time_range: str = "7d",
        include_trends: bool = True
    ) -> Dict[str, Any]:
        """Get marketplace analytics and trends."""
        try:
            with get_db() as db:
                # Parse time range
                if time_range == "1d":
                    start_time = datetime.utcnow() - timedelta(days=1)
                elif time_range == "7d":
                    start_time = datetime.utcnow() - timedelta(days=7)
                elif time_range == "30d":
                    start_time = datetime.utcnow() - timedelta(days=30)
                elif time_range == "90d":
                    start_time = datetime.utcnow() - timedelta(days=90)
                else:
                    start_time = datetime.utcnow() - timedelta(days=7)
                
                # Basic statistics
                total_plugins = db.query(Plugin).filter(
                    Plugin.status == PluginStatus.PUBLISHED
                ).count()
                
                active_installations = db.query(PluginInstallation).filter(
                    PluginInstallation.status == "active",
                    PluginInstallation.updated_at >= start_time
                ).count()
                
                total_downloads = db.query(func.sum(Plugin.download_count)).scalar() or 0
                total_reviews = db.query(PluginReview).count()
                
                # Category breakdown
                category_stats = db.query(
                    Plugin.category,
                    func.count(Plugin.id).label("count")
                ).filter(
                    Plugin.status == PluginStatus.PUBLISHED
                ).group_by(Plugin.category).all()
                
                # Top plugins by downloads
                top_plugins = db.query(Plugin).filter(
                    Plugin.status == PluginStatus.PUBLISHED
                ).order_by(Plugin.download_count.desc()).limit(10).all()
                
                analytics_data = {
                    "time_range": time_range,
                    "start_time": start_time.isoformat(),
                    "end_time": datetime.utcnow().isoformat(),
                    "totals": {
                        "plugins": total_plugins,
                        "active_installations": active_installations,
                        "downloads": total_downloads,
                        "reviews": total_reviews
                    },
                    "category_breakdown": {
                        stat.category: stat.count for stat in category_stats
                    },
                    "top_plugins": [
                        {
                            "name": plugin.name,
                            "downloads": plugin.download_count,
                            "rating": plugin.rating_average,
                            "category": plugin.category
                        }
                        for plugin in top_plugins
                    ],
                    "service_analytics": self.analytics.copy()
                }
                
                if include_trends:
                    trends = await self._get_trending_analysis(db, start_time)
                    analytics_data["trends"] = trends
                
                logger.info(f"Generated marketplace analytics for {time_range}")
                return analytics_data
                
        except Exception as e:
            logger.error(f"Error getting marketplace analytics: {e}")
            raise
    
    def get_stats(self) -> Dict[str, Any]:
        """Get marketplace manager statistics."""
        return {
            "service": "marketplace_manager",
            "analytics": self.analytics.copy(),
            "cache_stats": {
                "search_cache_size": len(self.search_cache),
                "recommendation_cache_size": len(self.recommendation_cache),
                "trending_cache_size": len(self.trending_cache)
            },
            "status": "active"
        }
    
    # Private helper methods
    
    async def _setup_event_handlers(self):
        """Set up event handlers for marketplace events."""
        await self.event_bus.subscribe("plugin.installed", self._handle_plugin_installed)
        await self.event_bus.subscribe("plugin.reviewed", self._handle_plugin_reviewed)
        await self.event_bus.subscribe("plugin.downloaded", self._handle_plugin_downloaded)
    
    async def _initialize_analytics(self):
        """Initialize analytics tracking."""
        # Reset analytics counters
        self.analytics = {
            "searches_performed": 0,
            "plugins_viewed": 0,
            "recommendations_generated": 0,
            "featured_content_views": 0
        }
    
    async def _get_personalized_recommendations(
        self,
        db: Session,
        user_id: str,
        limit: int
    ) -> List[Dict[str, Any]]:
        """Get personalized plugin recommendations for a user."""
        # Get user's installation history
        user_installations = db.query(PluginInstallation).filter(
            PluginInstallation.user_id == user_id,
            PluginInstallation.status == "active"
        ).all()
        
        if not user_installations:
            # No installation history, return popular plugins
            return await self._get_popular_plugins(db, limit)
        
        # Get categories and types from user's installed plugins
        installed_plugin_ids = [inst.plugin_id for inst in user_installations]
        installed_plugins = db.query(Plugin).filter(
            Plugin.id.in_(installed_plugin_ids)
        ).all()
        
        user_categories = [plugin.category for plugin in installed_plugins]
        user_types = [plugin.plugin_type for plugin in installed_plugins]
        
        # Find similar plugins in same categories/types
        recommendations = db.query(Plugin).filter(
            Plugin.status == PluginStatus.PUBLISHED,
            Plugin.is_public == True,
            Plugin.id.notin_(installed_plugin_ids),
            or_(
                Plugin.category.in_(user_categories),
                Plugin.plugin_type.in_(user_types)
            )
        ).order_by(
            Plugin.rating_average.desc(),
            Plugin.download_count.desc()
        ).limit(limit).all()
        
        return [PluginResponse.from_orm(plugin).dict() for plugin in recommendations]
    
    async def _get_similar_plugins(
        self,
        db: Session,
        plugin_id: UUID,
        limit: int
    ) -> List[Dict[str, Any]]:
        """Get plugins similar to a specific plugin."""
        target_plugin = db.query(Plugin).filter(Plugin.id == plugin_id).first()
        if not target_plugin:
            return []
        
        # Find similar plugins by category, type, and tags
        similar_plugins = db.query(Plugin).filter(
            Plugin.status == PluginStatus.PUBLISHED,
            Plugin.is_public == True,
            Plugin.id != plugin_id,
            or_(
                Plugin.category == target_plugin.category,
                Plugin.plugin_type == target_plugin.plugin_type,
                Plugin.tags.overlap(target_plugin.tags)
            )
        ).order_by(
            Plugin.rating_average.desc(),
            Plugin.download_count.desc()
        ).limit(limit).all()
        
        return [PluginResponse.from_orm(plugin).dict() for plugin in similar_plugins]
    
    async def _get_trending_plugins(
        self,
        db: Session,
        limit: int
    ) -> List[Dict[str, Any]]:
        """Get currently trending plugins."""
        # Calculate trending based on recent downloads and installations
        seven_days_ago = datetime.utcnow() - timedelta(days=7)
        
        # Get plugins with recent activity
        trending_plugins = db.query(Plugin).join(PluginInstallation).filter(
            Plugin.status == PluginStatus.PUBLISHED,
            Plugin.is_public == True,
            PluginInstallation.installed_at >= seven_days_ago
        ).group_by(Plugin.id).order_by(
            func.count(PluginInstallation.id).desc(),
            Plugin.rating_average.desc()
        ).limit(limit).all()
        
        return [PluginResponse.from_orm(plugin).dict() for plugin in trending_plugins]
    
    async def _get_popular_plugins(
        self,
        db: Session,
        limit: int
    ) -> List[Dict[str, Any]]:
        """Get most popular plugins by downloads."""
        popular_plugins = db.query(Plugin).filter(
            Plugin.status == PluginStatus.PUBLISHED,
            Plugin.is_public == True
        ).order_by(
            Plugin.download_count.desc(),
            Plugin.rating_average.desc()
        ).limit(limit).all()
        
        return [PluginResponse.from_orm(plugin).dict() for plugin in popular_plugins]
    
    async def _get_new_plugins(
        self,
        db: Session,
        limit: int
    ) -> List[Dict[str, Any]]:
        """Get recently published plugins."""
        new_plugins = db.query(Plugin).filter(
            Plugin.status == PluginStatus.PUBLISHED,
            Plugin.is_public == True
        ).order_by(
            Plugin.published_at.desc()
        ).limit(limit).all()
        
        return [PluginResponse.from_orm(plugin).dict() for plugin in new_plugins]
    
    async def _get_trending_analysis(
        self,
        db: Session,
        start_time: datetime
    ) -> Dict[str, Any]:
        """Get trending analysis for the marketplace."""
        # Trending categories
        trending_categories = db.query(
            Plugin.category,
            func.count(PluginInstallation.id).label("installations")
        ).join(PluginInstallation).filter(
            PluginInstallation.installed_at >= start_time
        ).group_by(Plugin.category).order_by(
            func.count(PluginInstallation.id).desc()
        ).limit(10).all()
        
        # Growth trends
        growth_plugins = db.query(Plugin).join(PluginInstallation).filter(
            PluginInstallation.installed_at >= start_time
        ).group_by(Plugin.id).having(
            func.count(PluginInstallation.id) > 5
        ).order_by(
            func.count(PluginInstallation.id).desc()
        ).limit(10).all()
        
        return {
            "trending_categories": [
                {"category": cat.category, "installations": cat.installations}
                for cat in trending_categories
            ],
            "growth_plugins": [
                PluginResponse.from_orm(plugin).dict()
                for plugin in growth_plugins
            ]
        }
    
    # Cache management methods
    
    def _create_search_cache_key(self, *args) -> str:
        """Create a cache key for search results."""
        return f"search_{hash(str(args))}"
    
    def _get_cached_search(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached search results."""
        cached_entry = self.search_cache.get(cache_key)
        if cached_entry:
            cached_time, cached_data = cached_entry
            if (datetime.utcnow() - cached_time).total_seconds() < self.cache_ttl:
                return cached_data
            else:
                self.search_cache.pop(cache_key, None)
        return None
    
    def _cache_search_result(self, cache_key: str, result: Dict[str, Any]):
        """Cache search results."""
        self.search_cache[cache_key] = (datetime.utcnow(), result)
    
    def _get_cached_recommendations(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached recommendations."""
        cached_entry = self.recommendation_cache.get(cache_key)
        if cached_entry:
            cached_time, cached_data = cached_entry
            if (datetime.utcnow() - cached_time).total_seconds() < self.cache_ttl:
                return cached_data
            else:
                self.recommendation_cache.pop(cache_key, None)
        return None
    
    def _cache_recommendations(self, cache_key: str, result: Dict[str, Any]):
        """Cache recommendations."""
        self.recommendation_cache[cache_key] = (datetime.utcnow(), result)
    
    def _get_cached_featured_content(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached featured content."""
        cached_entry = self.trending_cache.get(cache_key)
        if cached_entry:
            cached_time, cached_data = cached_entry
            if (datetime.utcnow() - cached_time).total_seconds() < self.cache_ttl:
                return cached_data
            else:
                self.trending_cache.pop(cache_key, None)
        return None
    
    def _cache_featured_content(self, cache_key: str, result: Dict[str, Any]):
        """Cache featured content."""
        self.trending_cache[cache_key] = (datetime.utcnow(), result)
    
    # Background tasks
    
    async def _cache_cleanup_task(self):
        """Background task to clean up expired cache entries."""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                
                current_time = datetime.utcnow()
                
                # Clean search cache
                expired_keys = [
                    key for key, (cached_time, _) in self.search_cache.items()
                    if (current_time - cached_time).total_seconds() > self.cache_ttl
                ]
                for key in expired_keys:
                    self.search_cache.pop(key, None)
                
                # Clean recommendation cache
                expired_keys = [
                    key for key, (cached_time, _) in self.recommendation_cache.items()
                    if (current_time - cached_time).total_seconds() > self.cache_ttl
                ]
                for key in expired_keys:
                    self.recommendation_cache.pop(key, None)
                
                # Clean trending cache
                expired_keys = [
                    key for key, (cached_time, _) in self.trending_cache.items()
                    if (current_time - cached_time).total_seconds() > self.cache_ttl
                ]
                for key in expired_keys:
                    self.trending_cache.pop(key, None)
                
                logger.debug("Cache cleanup completed")
                
            except Exception as e:
                logger.error(f"Error in cache cleanup task: {e}")
    
    async def _trending_analysis_task(self):
        """Background task to update trending analysis."""
        while True:
            try:
                await asyncio.sleep(3600)  # Run every hour
                
                # Update trending analysis
                # This would typically update the trending cache
                logger.debug("Trending analysis update completed")
                
            except Exception as e:
                logger.error(f"Error in trending analysis task: {e}")
    
    async def _recommendation_update_task(self):
        """Background task to update recommendation models."""
        while True:
            try:
                await asyncio.sleep(7200)  # Run every 2 hours
                
                # Update recommendation models
                # This would typically update ML models for recommendations
                logger.debug("Recommendation model update completed")
                
            except Exception as e:
                logger.error(f"Error in recommendation update task: {e}")
    
    # Event handlers
    
    async def _handle_plugin_installed(self, event_data: Dict[str, Any]):
        """Handle plugin installation events."""
        try:
            plugin_id = event_data.get("plugin_id")
            user_id = event_data.get("user_id")
            
            # Clear relevant caches
            cache_keys_to_clear = [
                key for key in self.recommendation_cache.keys()
                if user_id in key
            ]
            for key in cache_keys_to_clear:
                self.recommendation_cache.pop(key, None)
            
            logger.debug(f"Handled plugin installation event: {plugin_id}")
            
        except Exception as e:
            logger.error(f"Error handling plugin installation event: {e}")
    
    async def _handle_plugin_reviewed(self, event_data: Dict[str, Any]):
        """Handle plugin review events."""
        try:
            plugin_id = event_data.get("plugin_id")
            
            # Clear search caches that might be affected by rating changes
            self.search_cache.clear()
            
            logger.debug(f"Handled plugin review event: {plugin_id}")
            
        except Exception as e:
            logger.error(f"Error handling plugin review event: {e}")
    
    async def _handle_plugin_downloaded(self, event_data: Dict[str, Any]):
        """Handle plugin download events."""
        try:
            plugin_id = event_data.get("plugin_id")
            
            # Update analytics
            self.analytics["plugins_viewed"] += 1
            
            logger.debug(f"Handled plugin download event: {plugin_id}")
            
        except Exception as e:
            logger.error(f"Error handling plugin download event: {e}")