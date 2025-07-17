"""
MCP Security Platform Plugin SDK

This package provides the core interfaces and utilities for developing
plugins for the MCP Security Platform.
"""

__version__ = "1.0.0"
__author__ = "MCP Security Platform Team"
__email__ = "platform@mcp-security.com"

# Core plugin interfaces
from .interfaces.base import BasePlugin, PluginMetadata, PluginCapabilities
from .interfaces.analyzer import AnalyzerPlugin, VulnerabilityResult
from .interfaces.enricher import EnricherPlugin, EnrichmentResult
from .interfaces.scanner import ScannerPlugin, ScanResult
from .interfaces.notifier import NotifierPlugin, NotificationResult

# Event system
from .events.bus import EventBus, EventSubscription
from .events.types import EventType, SecurityEvent, PluginEvent

# Configuration management
from .config.manager import ConfigManager, PluginConfig
from .config.schema import ConfigSchema, ValidationError

# Lifecycle management
from .lifecycle.manager import LifecycleManager
from .lifecycle.hooks import LifecycleHook

# Utilities
from .utils.logger import get_logger
from .utils.decorators import plugin_method, async_plugin_method
from .utils.exceptions import PluginError, ConfigurationError, EventError

__all__ = [
    # Core interfaces
    "BasePlugin",
    "PluginMetadata", 
    "PluginCapabilities",
    "AnalyzerPlugin",
    "VulnerabilityResult",
    "EnricherPlugin",
    "EnrichmentResult",
    "ScannerPlugin", 
    "ScanResult",
    "NotifierPlugin",
    "NotificationResult",
    
    # Event system
    "EventBus",
    "EventSubscription",
    "EventType",
    "SecurityEvent",
    "PluginEvent",
    
    # Configuration
    "ConfigManager",
    "PluginConfig",
    "ConfigSchema",
    "ValidationError",
    
    # Lifecycle
    "LifecycleManager",
    "LifecycleHook",
    
    # Utilities
    "get_logger",
    "plugin_method",
    "async_plugin_method",
    "PluginError",
    "ConfigurationError", 
    "EventError",
]