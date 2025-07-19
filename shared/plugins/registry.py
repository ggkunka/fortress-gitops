"""
Plugin Registry - Dynamic plugin discovery and management

This module provides centralized plugin registration, discovery, and lifecycle management
for all plugin types in the MCP Security Platform.
"""

import asyncio
import importlib
import inspect
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Any, Type, Union, Callable
from enum import Enum
import yaml

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from .base import BasePlugin, BaseScannerPlugin, BaseIntegrationPlugin, BaseAlertPlugin, BaseCompliancePlugin

logger = get_logger(__name__)
metrics = get_metrics()


class PluginType(str, Enum):
    """Plugin types supported by the registry."""
    SCANNER = "scanner"
    INTEGRATION = "integration"
    ALERT = "alert"
    COMPLIANCE = "compliance"
    CUSTOM = "custom"


class PluginStatus(str, Enum):
    """Plugin status states."""
    REGISTERED = "registered"
    INITIALIZING = "initializing"
    ACTIVE = "active"
    ERROR = "error"
    DISABLED = "disabled"
    UNLOADING = "unloading"


class PluginInfo:
    """Plugin information and metadata."""
    
    def __init__(
        self,
        name: str,
        plugin_type: PluginType,
        plugin_class: Type[BasePlugin],
        version: str,
        description: str = "",
        author: str = "",
        dependencies: List[str] = None,
        config_schema: Dict[str, Any] = None,
        capabilities: List[str] = None,
        tags: List[str] = None
    ):
        self.name = name
        self.plugin_type = plugin_type
        self.plugin_class = plugin_class
        self.version = version
        self.description = description
        self.author = author
        self.dependencies = dependencies or []
        self.config_schema = config_schema or {}
        self.capabilities = capabilities or []
        self.tags = tags or []
        self.registered_at = datetime.now(timezone.utc)
        self.status = PluginStatus.REGISTERED
        self.instance: Optional[BasePlugin] = None
        self.last_error: Optional[str] = None
        self.load_count = 0
        self.health_checks = 0
        self.last_health_check = None


class PluginRegistry:
    """
    Centralized plugin registry for dynamic plugin discovery and management.
    
    Features:
    - Automatic plugin discovery from configured directories
    - Plugin lifecycle management (load, initialize, cleanup, unload)
    - Dependency resolution and validation
    - Health monitoring and status tracking
    - Configuration management
    - Plugin metadata and documentation
    - Event-driven plugin lifecycle notifications
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.plugins: Dict[str, PluginInfo] = {}
        self.plugin_paths: List[Path] = []
        self.plugin_configs: Dict[str, Dict[str, Any]] = {}
        self.lifecycle_hooks: Dict[str, List[Callable]] = {
            "before_load": [],
            "after_load": [],
            "before_initialize": [],
            "after_initialize": [],
            "before_cleanup": [],
            "after_cleanup": [],
            "before_unload": [],
            "after_unload": [],
            "on_error": []
        }
        
        # Plugin type mappings
        self.plugin_base_classes = {
            PluginType.SCANNER: BaseScannerPlugin,
            PluginType.INTEGRATION: BaseIntegrationPlugin,
            PluginType.ALERT: BaseAlertPlugin,
            PluginType.COMPLIANCE: BaseCompliancePlugin,
            PluginType.CUSTOM: BasePlugin
        }
        
        # Default plugin search paths
        self.plugin_paths = [
            Path(__file__).parent.parent.parent / "plugins",
            Path.cwd() / "plugins",
            Path.home() / ".mcp-security-platform" / "plugins"
        ]
        
        # Add configured paths
        for path in self.config.get("plugin_paths", []):
            self.plugin_paths.append(Path(path))
        
        logger.info("Plugin registry initialized")
    
    async def initialize(self) -> bool:
        """Initialize the plugin registry."""
        try:
            # Load plugin configurations
            await self._load_plugin_configurations()
            
            # Discover available plugins
            await self.discover_plugins()
            
            # Auto-load enabled plugins
            if self.config.get("auto_load_enabled", True):
                await self._auto_load_plugins()
            
            logger.info(f"Plugin registry initialized with {len(self.plugins)} plugins")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize plugin registry: {e}")
            return False
    
    async def cleanup(self) -> bool:
        """Cleanup the plugin registry."""
        try:
            # Cleanup all active plugins
            for plugin_info in self.plugins.values():
                if plugin_info.instance and plugin_info.status == PluginStatus.ACTIVE:
                    await self.unload_plugin(plugin_info.name)
            
            logger.info("Plugin registry cleaned up successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup plugin registry: {e}")
            return False
    
    @traced("plugin_registry_discover")
    async def discover_plugins(self) -> int:
        """Discover plugins from configured paths."""
        discovered_count = 0
        
        for plugin_path in self.plugin_paths:
            if not plugin_path.exists():
                continue
                
            logger.debug(f"Scanning for plugins in: {plugin_path}")
            
            # Scan for plugin modules
            for plugin_dir in plugin_path.iterdir():
                if not plugin_dir.is_dir() or plugin_dir.name.startswith('.'):
                    continue
                
                try:
                    discovered = await self._discover_plugins_in_directory(plugin_dir)
                    discovered_count += discovered
                except Exception as e:
                    logger.warning(f"Failed to discover plugins in {plugin_dir}: {e}")
        
        logger.info(f"Discovered {discovered_count} plugins")
        metrics.plugins_discovered.inc(discovered_count)
        return discovered_count
    
    async def register_plugin(
        self,
        name: str,
        plugin_class: Type[BasePlugin],
        plugin_type: PluginType,
        metadata: Dict[str, Any] = None
    ) -> bool:
        """Register a plugin manually."""
        try:
            metadata = metadata or {}
            
            # Validate plugin class
            base_class = self.plugin_base_classes.get(plugin_type, BasePlugin)
            if not issubclass(plugin_class, base_class):
                raise ValueError(f"Plugin {name} must inherit from {base_class.__name__}")
            
            # Create plugin info
            plugin_info = PluginInfo(
                name=name,
                plugin_type=plugin_type,
                plugin_class=plugin_class,
                version=metadata.get("version", "1.0.0"),
                description=metadata.get("description", ""),
                author=metadata.get("author", ""),
                dependencies=metadata.get("dependencies", []),
                config_schema=metadata.get("config_schema", {}),
                capabilities=metadata.get("capabilities", []),
                tags=metadata.get("tags", [])
            )
            
            # Check for conflicts
            if name in self.plugins:
                existing = self.plugins[name]
                logger.warning(f"Plugin {name} already registered (version: {existing.version})")
                return False
            
            # Register plugin
            self.plugins[name] = plugin_info
            logger.info(f"Registered plugin: {name} (type: {plugin_type.value}, version: {plugin_info.version})")
            
            # Call lifecycle hooks
            await self._call_lifecycle_hooks("after_register", plugin_info)
            
            metrics.plugins_registered.inc()
            return True
            
        except Exception as e:
            logger.error(f"Failed to register plugin {name}: {e}")
            return False
    
    @traced("plugin_registry_load")
    async def load_plugin(self, name: str, config: Dict[str, Any] = None) -> bool:
        """Load and initialize a plugin."""
        try:
            plugin_info = self.plugins.get(name)
            if not plugin_info:
                raise ValueError(f"Plugin {name} not found in registry")
            
            if plugin_info.status == PluginStatus.ACTIVE:
                logger.warning(f"Plugin {name} is already active")
                return True
            
            # Call before load hooks
            await self._call_lifecycle_hooks("before_load", plugin_info)
            
            plugin_info.status = PluginStatus.INITIALIZING
            
            # Resolve dependencies
            await self._resolve_dependencies(plugin_info)
            
            # Get plugin configuration
            plugin_config = config or self.plugin_configs.get(name, {})
            
            # Create plugin instance
            try:
                plugin_info.instance = plugin_info.plugin_class(plugin_config)
            except Exception as e:
                raise RuntimeError(f"Failed to create plugin instance: {e}")
            
            # Call before initialize hooks
            await self._call_lifecycle_hooks("before_initialize", plugin_info)
            
            # Initialize plugin
            if hasattr(plugin_info.instance, 'initialize'):
                success = await plugin_info.instance.initialize()
                if not success:
                    raise RuntimeError("Plugin initialization failed")
            
            plugin_info.status = PluginStatus.ACTIVE
            plugin_info.load_count += 1
            plugin_info.last_error = None
            
            # Call after hooks
            await self._call_lifecycle_hooks("after_initialize", plugin_info)
            await self._call_lifecycle_hooks("after_load", plugin_info)
            
            logger.info(f"Plugin {name} loaded successfully")
            metrics.plugins_loaded.inc()
            return True
            
        except Exception as e:
            error_msg = f"Failed to load plugin {name}: {e}"
            logger.error(error_msg)
            
            if name in self.plugins:
                self.plugins[name].status = PluginStatus.ERROR
                self.plugins[name].last_error = str(e)
            
            await self._call_lifecycle_hooks("on_error", plugin_info, error=e)
            metrics.plugin_load_errors.inc()
            return False
    
    @traced("plugin_registry_unload")
    async def unload_plugin(self, name: str) -> bool:
        """Unload and cleanup a plugin."""
        try:
            plugin_info = self.plugins.get(name)
            if not plugin_info:
                raise ValueError(f"Plugin {name} not found in registry")
            
            if plugin_info.status != PluginStatus.ACTIVE or not plugin_info.instance:
                logger.warning(f"Plugin {name} is not active")
                return True
            
            # Call before hooks
            await self._call_lifecycle_hooks("before_cleanup", plugin_info)
            await self._call_lifecycle_hooks("before_unload", plugin_info)
            
            plugin_info.status = PluginStatus.UNLOADING
            
            # Cleanup plugin
            if hasattr(plugin_info.instance, 'cleanup'):
                try:
                    await plugin_info.instance.cleanup()
                except Exception as e:
                    logger.warning(f"Plugin {name} cleanup failed: {e}")
            
            plugin_info.instance = None
            plugin_info.status = PluginStatus.REGISTERED
            
            # Call after hooks
            await self._call_lifecycle_hooks("after_cleanup", plugin_info)
            await self._call_lifecycle_hooks("after_unload", plugin_info)
            
            logger.info(f"Plugin {name} unloaded successfully")
            metrics.plugins_unloaded.inc()
            return True
            
        except Exception as e:
            logger.error(f"Failed to unload plugin {name}: {e}")
            return False
    
    def get_plugin(self, name: str) -> Optional[BasePlugin]:
        """Get active plugin instance."""
        plugin_info = self.plugins.get(name)
        if plugin_info and plugin_info.status == PluginStatus.ACTIVE:
            return plugin_info.instance
        return None
    
    def get_plugins_by_type(self, plugin_type: PluginType) -> List[BasePlugin]:
        """Get all active plugins of a specific type."""
        plugins = []
        for plugin_info in self.plugins.values():
            if (plugin_info.plugin_type == plugin_type and 
                plugin_info.status == PluginStatus.ACTIVE and 
                plugin_info.instance):
                plugins.append(plugin_info.instance)
        return plugins
    
    def get_plugin_info(self, name: str) -> Optional[PluginInfo]:
        """Get plugin information."""
        return self.plugins.get(name)
    
    def list_plugins(
        self,
        plugin_type: Optional[PluginType] = None,
        status: Optional[PluginStatus] = None,
        tags: Optional[List[str]] = None
    ) -> List[PluginInfo]:
        """List plugins with optional filtering."""
        plugins = list(self.plugins.values())
        
        if plugin_type:
            plugins = [p for p in plugins if p.plugin_type == plugin_type]
        
        if status:
            plugins = [p for p in plugins if p.status == status]
        
        if tags:
            plugins = [p for p in plugins if any(tag in p.tags for tag in tags)]
        
        return plugins
    
    async def health_check(self, name: Optional[str] = None) -> Dict[str, Any]:
        """Perform health check on plugins."""
        if name:
            # Check specific plugin
            plugin_info = self.plugins.get(name)
            if not plugin_info:
                return {"error": f"Plugin {name} not found"}
            
            return await self._check_plugin_health(plugin_info)
        else:
            # Check all plugins
            health_status = {}
            for plugin_name, plugin_info in self.plugins.items():
                health_status[plugin_name] = await self._check_plugin_health(plugin_info)
            
            return health_status
    
    def add_lifecycle_hook(self, event: str, callback: Callable):
        """Add lifecycle hook callback."""
        if event in self.lifecycle_hooks:
            self.lifecycle_hooks[event].append(callback)
        else:
            logger.warning(f"Unknown lifecycle event: {event}")
    
    def remove_lifecycle_hook(self, event: str, callback: Callable):
        """Remove lifecycle hook callback."""
        if event in self.lifecycle_hooks and callback in self.lifecycle_hooks[event]:
            self.lifecycle_hooks[event].remove(callback)
    
    async def reload_plugin(self, name: str, config: Dict[str, Any] = None) -> bool:
        """Reload a plugin."""
        await self.unload_plugin(name)
        return await self.load_plugin(name, config)
    
    def get_registry_stats(self) -> Dict[str, Any]:
        """Get registry statistics."""
        stats = {
            "total_plugins": len(self.plugins),
            "by_type": {},
            "by_status": {},
            "load_attempts": sum(p.load_count for p in self.plugins.values()),
            "health_checks": sum(p.health_checks for p in self.plugins.values())
        }
        
        # Count by type
        for plugin_type in PluginType:
            count = len([p for p in self.plugins.values() if p.plugin_type == plugin_type])
            stats["by_type"][plugin_type.value] = count
        
        # Count by status
        for status in PluginStatus:
            count = len([p for p in self.plugins.values() if p.status == status])
            stats["by_status"][status.value] = count
        
        return stats
    
    async def _discover_plugins_in_directory(self, plugin_dir: Path) -> int:
        """Discover plugins in a specific directory."""
        discovered_count = 0
        
        # Look for plugin metadata file
        metadata_file = plugin_dir / "plugin.yaml"
        if not metadata_file.exists():
            metadata_file = plugin_dir / "plugin.json"
        
        if metadata_file.exists():
            # Load plugin metadata
            try:
                if metadata_file.suffix == ".yaml":
                    with open(metadata_file) as f:
                        metadata = yaml.safe_load(f)
                else:
                    with open(metadata_file) as f:
                        metadata = json.load(f)
                
                # Register plugin from metadata
                plugin_name = metadata.get("name", plugin_dir.name)
                module_path = metadata.get("module", f"{plugin_dir.name}_plugin")
                plugin_class_name = metadata.get("class", f"{plugin_name.title()}Plugin")
                
                # Import plugin module
                module_name = f"plugins.{plugin_dir.parent.name}.{plugin_dir.name}.{module_path}"
                try:
                    module = importlib.import_module(module_name)
                    plugin_class = getattr(module, plugin_class_name)
                    
                    plugin_type = PluginType(metadata.get("type", "custom"))
                    
                    await self.register_plugin(
                        name=plugin_name,
                        plugin_class=plugin_class,
                        plugin_type=plugin_type,
                        metadata=metadata
                    )
                    
                    discovered_count += 1
                    
                except (ImportError, AttributeError) as e:
                    logger.warning(f"Failed to import plugin {plugin_name}: {e}")
                    
            except Exception as e:
                logger.warning(f"Failed to load plugin metadata from {metadata_file}: {e}")
        
        return discovered_count
    
    async def _load_plugin_configurations(self):
        """Load plugin configurations from files."""
        config_paths = [
            Path.cwd() / "config" / "plugins",
            Path.home() / ".mcp-security-platform" / "config" / "plugins"
        ]
        
        for config_path in config_paths:
            if not config_path.exists():
                continue
            
            for config_file in config_path.glob("*.yaml"):
                try:
                    with open(config_file) as f:
                        config_data = yaml.safe_load(f)
                    
                    plugin_name = config_file.stem
                    self.plugin_configs[plugin_name] = config_data
                    
                except Exception as e:
                    logger.warning(f"Failed to load plugin config {config_file}: {e}")
    
    async def _auto_load_plugins(self):
        """Auto-load enabled plugins."""
        for plugin_name, plugin_info in self.plugins.items():
            config = self.plugin_configs.get(plugin_name, {})
            if config.get("enabled", False):
                await self.load_plugin(plugin_name, config)
    
    async def _resolve_dependencies(self, plugin_info: PluginInfo):
        """Resolve plugin dependencies."""
        for dependency in plugin_info.dependencies:
            dep_plugin = self.plugins.get(dependency)
            if not dep_plugin:
                raise RuntimeError(f"Dependency {dependency} not found")
            
            if dep_plugin.status != PluginStatus.ACTIVE:
                # Try to load dependency
                success = await self.load_plugin(dependency)
                if not success:
                    raise RuntimeError(f"Failed to load dependency {dependency}")
    
    async def _check_plugin_health(self, plugin_info: PluginInfo) -> Dict[str, Any]:
        """Check health of a specific plugin."""
        health_info = {
            "name": plugin_info.name,
            "status": plugin_info.status.value,
            "version": plugin_info.version,
            "load_count": plugin_info.load_count,
            "last_error": plugin_info.last_error,
            "healthy": False
        }
        
        try:
            if plugin_info.instance and hasattr(plugin_info.instance, 'get_health'):
                plugin_health = plugin_info.instance.get_health()
                health_info.update(plugin_health)
                health_info["healthy"] = plugin_health.get("healthy", False)
            elif plugin_info.status == PluginStatus.ACTIVE:
                health_info["healthy"] = True
            
            plugin_info.health_checks += 1
            plugin_info.last_health_check = datetime.now(timezone.utc)
            
        except Exception as e:
            health_info["error"] = str(e)
            logger.warning(f"Health check failed for plugin {plugin_info.name}: {e}")
        
        return health_info
    
    async def _call_lifecycle_hooks(self, event: str, plugin_info: PluginInfo, **kwargs):
        """Call lifecycle hooks for an event."""
        for callback in self.lifecycle_hooks.get(event, []):
            try:
                if inspect.iscoroutinefunction(callback):
                    await callback(plugin_info, **kwargs)
                else:
                    callback(plugin_info, **kwargs)
            except Exception as e:
                logger.warning(f"Lifecycle hook {event} failed: {e}")


# Global plugin registry instance
_registry: Optional[PluginRegistry] = None


def get_plugin_registry(config: Dict[str, Any] = None) -> PluginRegistry:
    """Get the global plugin registry instance."""
    global _registry
    if _registry is None:
        _registry = PluginRegistry(config)
    return _registry


async def initialize_plugin_registry(config: Dict[str, Any] = None) -> bool:
    """Initialize the global plugin registry."""
    registry = get_plugin_registry(config)
    return await registry.initialize()


async def cleanup_plugin_registry() -> bool:
    """Cleanup the global plugin registry."""
    global _registry
    if _registry:
        success = await _registry.cleanup()
        _registry = None
        return success
    return True