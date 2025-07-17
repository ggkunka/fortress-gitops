"""
Plugin Registry Service

Manages plugin discovery, loading, lifecycle, and API access.
"""

import asyncio
import importlib
import inspect
import os
import sys
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Type
import json
import logging
import traceback
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
import structlog

# Plugin SDK imports
from mcp_plugin_sdk import (
    BasePlugin, PluginMetadata, PluginContext, PluginType, PluginStatus,
    EventBus, ConfigManager, get_logger
)
from mcp_plugin_sdk.utils.exceptions import PluginError, ConfigurationError


class PluginInstance:
    """Represents a loaded plugin instance."""
    
    def __init__(
        self,
        plugin_id: str,
        plugin: BasePlugin,
        metadata: PluginMetadata,
        context: PluginContext
    ):
        self.plugin_id = plugin_id
        self.plugin = plugin
        self.metadata = metadata
        self.context = context
        self.status = PluginStatus.LOADED
        self.load_time = datetime.now()
        self.error_count = 0
        self.last_error: Optional[str] = None
        self.last_activity = datetime.now()


class PluginRegistryConfig(BaseModel):
    """Configuration for the plugin registry."""
    
    # Registry settings
    registry_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    plugin_directories: List[str] = Field(default_factory=list)
    auto_discovery: bool = True
    auto_load: bool = False
    
    # Security settings
    sandbox_plugins: bool = True
    allowed_permissions: Set[str] = Field(default_factory=set)
    max_plugin_memory_mb: int = 512
    max_plugin_cpu_percent: int = 50
    
    # Lifecycle settings
    startup_timeout: int = 30
    shutdown_timeout: int = 15
    health_check_interval: int = 60
    
    # API settings
    api_host: str = "0.0.0.0"
    api_port: int = 8090
    api_prefix: str = "/api/v1"
    cors_origins: List[str] = Field(default_factory=lambda: ["*"])
    
    # Storage settings
    metadata_storage: str = "file"  # file, redis, database
    state_file: str = "registry_state.json"
    
    # Logging
    log_level: str = "INFO"
    log_format: str = "json"


class PluginRegistry:
    """
    Central plugin registry for discovering, loading, and managing plugins.
    """
    
    def __init__(self, config: PluginRegistryConfig):
        self.config = config
        self.logger = get_logger("plugin_registry")
        
        # State
        self._plugins: Dict[str, PluginInstance] = {}
        self._metadata_cache: Dict[str, PluginMetadata] = {}
        self._running = False
        
        # Components
        self.event_bus: Optional[EventBus] = None
        self.config_manager: Optional[ConfigManager] = None
        
        # Background tasks
        self._health_check_task: Optional[asyncio.Task] = None
        self._discovery_task: Optional[asyncio.Task] = None
        
        # API app
        self.app = self._create_api_app()
    
    async def start(self) -> None:
        """Start the plugin registry."""
        if self._running:
            return
        
        self.logger.info("Starting plugin registry")
        
        # Initialize components
        self.event_bus = EventBus()
        await self.event_bus.start()
        
        self.config_manager = ConfigManager()
        
        # Load saved state
        await self._load_state()
        
        # Start background tasks
        if self.config.auto_discovery:
            self._discovery_task = asyncio.create_task(self._discovery_loop())
        
        self._health_check_task = asyncio.create_task(self._health_check_loop())
        
        # Auto-load plugins if configured
        if self.config.auto_load:
            await self.discover_plugins()
            for plugin_id in self._metadata_cache:
                try:
                    await self.load_plugin(plugin_id)
                except Exception as e:
                    self.logger.warning(f"Failed to auto-load plugin {plugin_id}: {e}")
        
        self._running = True
        self.logger.info(f"Plugin registry started with {len(self._plugins)} plugins")
    
    async def stop(self) -> None:
        """Stop the plugin registry."""
        if not self._running:
            return
        
        self.logger.info("Stopping plugin registry")
        self._running = False
        
        # Stop background tasks
        if self._discovery_task:
            self._discovery_task.cancel()
        
        if self._health_check_task:
            self._health_check_task.cancel()
        
        # Unload all plugins
        plugin_ids = list(self._plugins.keys())
        for plugin_id in plugin_ids:
            try:
                await self.unload_plugin(plugin_id)
            except Exception as e:
                self.logger.error(f"Failed to unload plugin {plugin_id}: {e}")
        
        # Save state
        await self._save_state()
        
        # Stop components
        if self.event_bus:
            await self.event_bus.stop()
        
        self.logger.info("Plugin registry stopped")
    
    async def discover_plugins(self, directories: Optional[List[str]] = None) -> List[str]:
        """
        Discover plugins in specified directories.
        
        Args:
            directories: Directories to search (uses config if None)
            
        Returns:
            List of discovered plugin IDs
        """
        search_dirs = directories or self.config.plugin_directories
        discovered = []
        
        for directory in search_dirs:
            try:
                dir_path = Path(directory)
                if not dir_path.exists():
                    continue
                
                self.logger.info(f"Discovering plugins in {directory}")
                
                # Look for plugin manifest files
                for manifest_file in dir_path.rglob("plugin.json"):
                    try:
                        plugin_id = await self._load_plugin_metadata(manifest_file)
                        if plugin_id:
                            discovered.append(plugin_id)
                    except Exception as e:
                        self.logger.warning(f"Failed to load plugin from {manifest_file}: {e}")
                
                # Look for Python files with plugin classes
                for py_file in dir_path.rglob("*.py"):
                    try:
                        plugin_ids = await self._discover_python_plugins(py_file)
                        discovered.extend(plugin_ids)
                    except Exception as e:
                        self.logger.debug(f"No plugins found in {py_file}: {e}")
                        
            except Exception as e:
                self.logger.error(f"Failed to discover plugins in {directory}: {e}")
        
        self.logger.info(f"Discovered {len(discovered)} plugins")
        return discovered
    
    async def load_plugin(self, plugin_id: str, config_override: Optional[Dict[str, Any]] = None) -> bool:
        """
        Load and initialize a plugin.
        
        Args:
            plugin_id: Plugin identifier
            config_override: Configuration override
            
        Returns:
            True if plugin was loaded successfully
        """
        if plugin_id in self._plugins:
            self.logger.warning(f"Plugin {plugin_id} is already loaded")
            return False
        
        metadata = self._metadata_cache.get(plugin_id)
        if not metadata:
            raise PluginError(f"Plugin {plugin_id} not found in metadata cache")
        
        try:
            self.logger.info(f"Loading plugin {plugin_id}")
            
            # Create plugin context
            context = await self._create_plugin_context(plugin_id, metadata, config_override)
            
            # Load plugin class
            plugin_class = await self._load_plugin_class(metadata)
            
            # Create plugin instance
            plugin = plugin_class(context)
            
            # Validate compatibility
            await self._validate_plugin_compatibility(plugin, metadata)
            
            # Create plugin instance wrapper
            instance = PluginInstance(plugin_id, plugin, metadata, context)
            
            # Initialize plugin
            instance.status = PluginStatus.INITIALIZING
            try:
                await asyncio.wait_for(
                    plugin.initialize(),
                    timeout=self.config.startup_timeout
                )
                instance.status = PluginStatus.READY
            except asyncio.TimeoutError:
                instance.status = PluginStatus.ERROR
                raise PluginError(f"Plugin {plugin_id} initialization timed out")
            except Exception as e:
                instance.status = PluginStatus.ERROR
                raise PluginError(f"Plugin {plugin_id} initialization failed: {e}")
            
            # Register plugin
            self._plugins[plugin_id] = instance
            
            # Publish plugin loaded event
            if self.event_bus:
                await self.event_bus.publish_plugin_event({
                    'event_type': 'plugin.loaded',
                    'plugin_id': plugin_id,
                    'timestamp': datetime.now(),
                    'data': {'metadata': metadata.dict()}
                })
            
            self.logger.info(f"Plugin {plugin_id} loaded successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load plugin {plugin_id}: {e}")
            if plugin_id in self._plugins:
                del self._plugins[plugin_id]
            raise
    
    async def unload_plugin(self, plugin_id: str) -> bool:
        """
        Unload a plugin.
        
        Args:
            plugin_id: Plugin identifier
            
        Returns:
            True if plugin was unloaded successfully
        """
        instance = self._plugins.get(plugin_id)
        if not instance:
            return False
        
        try:
            self.logger.info(f"Unloading plugin {plugin_id}")
            
            instance.status = PluginStatus.STOPPING
            
            # Shutdown plugin
            try:
                await asyncio.wait_for(
                    instance.plugin.shutdown(),
                    timeout=self.config.shutdown_timeout
                )
            except asyncio.TimeoutError:
                self.logger.warning(f"Plugin {plugin_id} shutdown timed out")
            except Exception as e:
                self.logger.warning(f"Plugin {plugin_id} shutdown error: {e}")
            
            instance.status = PluginStatus.STOPPED
            
            # Remove from registry
            del self._plugins[plugin_id]
            
            # Publish plugin unloaded event
            if self.event_bus:
                await self.event_bus.publish_plugin_event({
                    'event_type': 'plugin.unloaded',
                    'plugin_id': plugin_id,
                    'timestamp': datetime.now(),
                    'data': {}
                })
            
            self.logger.info(f"Plugin {plugin_id} unloaded successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to unload plugin {plugin_id}: {e}")
            return False
    
    async def reload_plugin(self, plugin_id: str, config_override: Optional[Dict[str, Any]] = None) -> bool:
        """
        Reload a plugin.
        
        Args:
            plugin_id: Plugin identifier
            config_override: Configuration override
            
        Returns:
            True if plugin was reloaded successfully
        """
        if plugin_id in self._plugins:
            await self.unload_plugin(plugin_id)
        
        return await self.load_plugin(plugin_id, config_override)
    
    def get_plugin(self, plugin_id: str) -> Optional[BasePlugin]:
        """Get a loaded plugin instance."""
        instance = self._plugins.get(plugin_id)
        return instance.plugin if instance else None
    
    def get_plugin_metadata(self, plugin_id: str) -> Optional[PluginMetadata]:
        """Get plugin metadata."""
        return self._metadata_cache.get(plugin_id)
    
    def list_plugins(self, plugin_type: Optional[PluginType] = None, status: Optional[PluginStatus] = None) -> List[Dict[str, Any]]:
        """
        List plugins with optional filtering.
        
        Args:
            plugin_type: Filter by plugin type
            status: Filter by plugin status
            
        Returns:
            List of plugin information
        """
        plugins = []
        
        for plugin_id, instance in self._plugins.items():
            if plugin_type and instance.metadata.plugin_type != plugin_type:
                continue
            
            if status and instance.status != status:
                continue
            
            plugins.append({
                'plugin_id': plugin_id,
                'name': instance.metadata.name,
                'version': instance.metadata.version,
                'type': instance.metadata.plugin_type,
                'status': instance.status,
                'load_time': instance.load_time,
                'error_count': instance.error_count,
                'last_error': instance.last_error,
                'last_activity': instance.last_activity
            })
        
        return plugins
    
    def get_plugin_stats(self) -> Dict[str, Any]:
        """Get plugin registry statistics."""
        total_plugins = len(self._metadata_cache)
        loaded_plugins = len(self._plugins)
        
        status_counts = {}
        type_counts = {}
        
        for instance in self._plugins.values():
            status_counts[instance.status.value] = status_counts.get(instance.status.value, 0) + 1
            type_counts[instance.metadata.plugin_type.value] = type_counts.get(instance.metadata.plugin_type.value, 0) + 1
        
        return {
            'total_plugins': total_plugins,
            'loaded_plugins': loaded_plugins,
            'running': self._running,
            'status_counts': status_counts,
            'type_counts': type_counts,
            'directories': self.config.plugin_directories,
            'auto_discovery': self.config.auto_discovery,
            'auto_load': self.config.auto_load
        }
    
    # Private methods
    
    async def _load_plugin_metadata(self, manifest_file: Path) -> Optional[str]:
        """Load plugin metadata from manifest file."""
        try:
            with open(manifest_file, 'r') as f:
                manifest_data = json.load(f)
            
            metadata = PluginMetadata(**manifest_data)
            plugin_id = f"{metadata.name}:{metadata.version}"
            
            self._metadata_cache[plugin_id] = metadata
            self.logger.debug(f"Loaded metadata for plugin {plugin_id}")
            
            return plugin_id
            
        except Exception as e:
            self.logger.warning(f"Failed to load plugin metadata from {manifest_file}: {e}")
            return None
    
    async def _discover_python_plugins(self, py_file: Path) -> List[str]:
        """Discover plugins in a Python file."""
        discovered = []
        
        try:
            # Load module
            spec = importlib.util.spec_from_file_location("plugin_module", py_file)
            if not spec or not spec.loader:
                return discovered
            
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Find plugin classes
            for name, obj in inspect.getmembers(module):
                if (inspect.isclass(obj) and 
                    issubclass(obj, BasePlugin) and 
                    obj != BasePlugin):
                    
                    try:
                        # Create temporary instance to get metadata
                        temp_context = PluginContext(
                            plugin_id="temp",
                            instance_id="temp",
                            config={},
                            logger=self.logger,
                            event_bus=None,
                            config_manager=None,
                            startup_time=datetime.now(),
                            working_directory=str(py_file.parent),
                            temp_directory="/tmp",
                            platform_version="1.0.0",
                            api_version="1.0.0"
                        )
                        
                        temp_plugin = obj(temp_context)
                        metadata = temp_plugin.get_metadata()
                        
                        plugin_id = f"{metadata.name}:{metadata.version}"
                        metadata.entry_point = f"{module.__name__}:{name}"
                        
                        self._metadata_cache[plugin_id] = metadata
                        discovered.append(plugin_id)
                        
                        self.logger.debug(f"Discovered plugin {plugin_id} in {py_file}")
                        
                    except Exception as e:
                        self.logger.debug(f"Failed to get metadata from {name}: {e}")
            
        except Exception as e:
            self.logger.debug(f"Failed to analyze {py_file}: {e}")
        
        return discovered
    
    async def _create_plugin_context(
        self,
        plugin_id: str,
        metadata: PluginMetadata,
        config_override: Optional[Dict[str, Any]] = None
    ) -> PluginContext:
        """Create plugin context."""
        # Load plugin configuration
        plugin_config = metadata.default_config.copy()
        
        if self.config_manager:
            stored_config = await self.config_manager.get_plugin_config(plugin_id)
            if stored_config:
                plugin_config.update(stored_config)
        
        if config_override:
            plugin_config.update(config_override)
        
        # Create working directory
        working_dir = Path(f"./plugins/{plugin_id}")
        working_dir.mkdir(parents=True, exist_ok=True)
        
        temp_dir = Path(f"./tmp/{plugin_id}")
        temp_dir.mkdir(parents=True, exist_ok=True)
        
        return PluginContext(
            plugin_id=plugin_id,
            instance_id=str(uuid.uuid4()),
            config=plugin_config,
            logger=get_logger(f"plugin.{plugin_id}"),
            event_bus=self.event_bus,
            config_manager=self.config_manager,
            startup_time=datetime.now(),
            working_directory=str(working_dir),
            temp_directory=str(temp_dir),
            platform_version="1.0.0",
            api_version="1.0.0"
        )
    
    async def _load_plugin_class(self, metadata: PluginMetadata) -> Type[BasePlugin]:
        """Load plugin class from entry point."""
        try:
            module_name, class_name = metadata.entry_point.split(':')
            module = importlib.import_module(module_name)
            plugin_class = getattr(module, class_name)
            
            if not issubclass(plugin_class, BasePlugin):
                raise PluginError(f"Plugin class {class_name} does not inherit from BasePlugin")
            
            return plugin_class
            
        except Exception as e:
            raise PluginError(f"Failed to load plugin class from {metadata.entry_point}: {e}")
    
    async def _validate_plugin_compatibility(self, plugin: BasePlugin, metadata: PluginMetadata) -> None:
        """Validate plugin compatibility and security requirements."""
        # Check required permissions
        for permission in metadata.capabilities.required_permissions:
            if permission not in self.config.allowed_permissions and self.config.allowed_permissions:
                raise PluginError(f"Plugin requires unauthorized permission: {permission}")
        
        # Validate configuration schema
        if metadata.config_schema and self.config_manager:
            await self.config_manager.validate_config(plugin.config, metadata.config_schema)
    
    async def _health_check_loop(self) -> None:
        """Background loop for plugin health checks."""
        while self._running:
            try:
                await asyncio.sleep(self.config.health_check_interval)
                
                for plugin_id, instance in list(self._plugins.items()):
                    try:
                        health = await instance.plugin.health_check()
                        if health.get('status') != 'healthy':
                            self.logger.warning(f"Plugin {plugin_id} health check failed: {health}")
                            instance.error_count += 1
                        else:
                            instance.last_activity = datetime.now()
                            
                    except Exception as e:
                        self.logger.error(f"Health check failed for plugin {plugin_id}: {e}")
                        instance.error_count += 1
                        instance.last_error = str(e)
                        
                        if instance.error_count > 3:
                            self.logger.error(f"Unloading unhealthy plugin {plugin_id}")
                            await self.unload_plugin(plugin_id)
                
            except Exception as e:
                self.logger.error(f"Error in health check loop: {e}")
    
    async def _discovery_loop(self) -> None:
        """Background loop for plugin discovery."""
        while self._running:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes
                await self.discover_plugins()
                
            except Exception as e:
                self.logger.error(f"Error in discovery loop: {e}")
    
    async def _load_state(self) -> None:
        """Load registry state from storage."""
        try:
            if os.path.exists(self.config.state_file):
                with open(self.config.state_file, 'r') as f:
                    state = json.load(f)
                
                # Load metadata cache
                for plugin_id, metadata_dict in state.get('metadata_cache', {}).items():
                    self._metadata_cache[plugin_id] = PluginMetadata(**metadata_dict)
                
                self.logger.info(f"Loaded state with {len(self._metadata_cache)} plugins")
                
        except Exception as e:
            self.logger.warning(f"Failed to load registry state: {e}")
    
    async def _save_state(self) -> None:
        """Save registry state to storage."""
        try:
            state = {
                'metadata_cache': {
                    plugin_id: metadata.dict()
                    for plugin_id, metadata in self._metadata_cache.items()
                },
                'timestamp': datetime.now().isoformat()
            }
            
            with open(self.config.state_file, 'w') as f:
                json.dump(state, f, indent=2)
            
            self.logger.debug("Saved registry state")
            
        except Exception as e:
            self.logger.error(f"Failed to save registry state: {e}")
    
    def _create_api_app(self) -> FastAPI:
        """Create FastAPI application for plugin registry API."""
        
        @asynccontextmanager
        async def lifespan(app: FastAPI):
            # Startup
            await self.start()
            yield
            # Shutdown
            await self.stop()
        
        app = FastAPI(
            title="MCP Plugin Registry",
            description="Plugin management and API service",
            version="1.0.0",
            lifespan=lifespan
        )
        
        # Add CORS middleware
        app.add_middleware(
            CORSMiddleware,
            allow_origins=self.config.cors_origins,
            allow_credentials=True,
            allow_methods=["*"],
            allow_headers=["*"],
        )
        
        # API Routes
        @app.get(f"{self.config.api_prefix}/plugins")
        async def list_plugins_api(
            type: Optional[str] = None,
            status: Optional[str] = None
        ):
            plugin_type = PluginType(type) if type else None
            plugin_status = PluginStatus(status) if status else None
            return self.list_plugins(plugin_type, plugin_status)
        
        @app.get(f"{self.config.api_prefix}/plugins/{{plugin_id}}")
        async def get_plugin_api(plugin_id: str):
            metadata = self.get_plugin_metadata(plugin_id)
            if not metadata:
                raise HTTPException(status_code=404, detail="Plugin not found")
            
            instance = self._plugins.get(plugin_id)
            return {
                'metadata': metadata.dict(),
                'status': instance.status.value if instance else 'unloaded',
                'load_time': instance.load_time if instance else None,
                'error_count': instance.error_count if instance else 0
            }
        
        @app.post(f"{self.config.api_prefix}/plugins/{{plugin_id}}/load")
        async def load_plugin_api(plugin_id: str, config: Optional[Dict[str, Any]] = None):
            try:
                result = await self.load_plugin(plugin_id, config)
                return {'success': result}
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))
        
        @app.post(f"{self.config.api_prefix}/plugins/{{plugin_id}}/unload")
        async def unload_plugin_api(plugin_id: str):
            result = await self.unload_plugin(plugin_id)
            return {'success': result}
        
        @app.post(f"{self.config.api_prefix}/plugins/{{plugin_id}}/reload")
        async def reload_plugin_api(plugin_id: str, config: Optional[Dict[str, Any]] = None):
            try:
                result = await self.reload_plugin(plugin_id, config)
                return {'success': result}
            except Exception as e:
                raise HTTPException(status_code=400, detail=str(e))
        
        @app.get(f"{self.config.api_prefix}/plugins/{{plugin_id}}/health")
        async def plugin_health_api(plugin_id: str):
            instance = self._plugins.get(plugin_id)
            if not instance:
                raise HTTPException(status_code=404, detail="Plugin not loaded")
            
            try:
                health = await instance.plugin.health_check()
                return health
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @app.post(f"{self.config.api_prefix}/discovery")
        async def discover_plugins_api(directories: Optional[List[str]] = None):
            discovered = await self.discover_plugins(directories)
            return {'discovered': discovered, 'count': len(discovered)}
        
        @app.get(f"{self.config.api_prefix}/stats")
        async def get_stats_api():
            return self.get_plugin_stats()
        
        return app


# Main function for running the registry service
async def main():
    """Run the plugin registry service."""
    import uvicorn
    
    config = PluginRegistryConfig(
        plugin_directories=["./plugins", "/opt/mcp/plugins"],
        auto_discovery=True,
        auto_load=True
    )
    
    registry = PluginRegistry(config)
    
    # Run the API server
    uvicorn_config = uvicorn.Config(
        registry.app,
        host=config.api_host,
        port=config.api_port,
        log_level=config.log_level.lower()
    )
    
    server = uvicorn.Server(uvicorn_config)
    await server.serve()


if __name__ == "__main__":
    asyncio.run(main())