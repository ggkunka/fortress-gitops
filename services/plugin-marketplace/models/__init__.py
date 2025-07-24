"""
Plugin Marketplace Models - Database models and schemas for the plugin marketplace

This module exports all the database models, enums, and factory functions
used in the plugin marketplace service.
"""

from .plugin import (
    # Models
    Plugin,
    PluginReview,
    PluginInstallation,
    PluginCategory as PluginCategoryModel,
    PluginCollection,
    PluginCollectionItem,
    
    # Enums
    PluginStatus,
    PluginCategory,
    PluginType,
    
    # Pydantic models
    PluginCreate,
    PluginUpdate,
    PluginResponse,
    PluginReviewCreate,
    PluginReviewResponse,
    PluginInstallationResponse,
    
    # Factory functions
    create_plugin,
    create_plugin_review,
    create_plugin_installation,
)

# Database connection helper
from shared.database.connection import get_db

__all__ = [
    # Models
    "Plugin",
    "PluginReview", 
    "PluginInstallation",
    "PluginCategoryModel",
    "PluginCollection",
    "PluginCollectionItem",
    
    # Enums
    "PluginStatus",
    "PluginCategory",
    "PluginType",
    
    # Pydantic models
    "PluginCreate",
    "PluginUpdate", 
    "PluginResponse",
    "PluginReviewCreate",
    "PluginReviewResponse",
    "PluginInstallationResponse",
    
    # Factory functions
    "create_plugin",
    "create_plugin_review",
    "create_plugin_installation",
    
    # Database
    "get_db",
]