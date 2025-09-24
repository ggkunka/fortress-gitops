"""
Base plugin interface and metadata definitions.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Union
from datetime import datetime
import asyncio

from pydantic import BaseModel, Field


class PluginType(str, Enum):
    """Plugin type enumeration."""
    ANALYZER = "analyzer"
    ENRICHER = "enricher"
    SCANNER = "scanner"
    NOTIFIER = "notifier"
    PROCESSOR = "processor"
    CONNECTOR = "connector"


class PluginStatus(str, Enum):
    """Plugin lifecycle status."""
    UNLOADED = "unloaded"
    LOADING = "loading"
    LOADED = "loaded"
    INITIALIZING = "initializing"
    READY = "ready"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"


@dataclass
class PluginCapabilities:
    """Plugin capability declarations."""
    event_types: Set[str] = field(default_factory=set)
    supported_formats: Set[str] = field(default_factory=set)
    required_permissions: Set[str] = field(default_factory=set)
    cpu_intensive: bool = False
    memory_intensive: bool = False
    network_access: bool = False
    file_system_access: bool = False
    database_access: bool = False


class PluginMetadata(BaseModel):
    """Plugin metadata and configuration."""
    
    # Basic information
    name: str = Field(..., description="Plugin name")
    version: str = Field(..., description="Plugin version")
    description: str = Field("", description="Plugin description")
    author: str = Field("", description="Plugin author")
    email: str = Field("", description="Author email")
    license: str = Field("MIT", description="Plugin license")
    
    # Plugin characteristics
    plugin_type: PluginType = Field(..., description="Plugin type")
    capabilities: PluginCapabilities = Field(default_factory=PluginCapabilities)
    
    # Dependencies and compatibility
    sdk_version: str = Field(">=1.0.0", description="Required SDK version")
    python_version: str = Field(">=3.9", description="Required Python version")
    dependencies: List[str] = Field(default_factory=list, description="Python package dependencies")
    
    # Configuration schema
    config_schema: Optional[Dict[str, Any]] = Field(None, description="JSON schema for plugin configuration")
    default_config: Dict[str, Any] = Field(default_factory=dict, description="Default configuration values")
    
    # Runtime information
    entry_point: str = Field(..., description="Plugin entry point class")
    priority: int = Field(50, description="Plugin priority (0-100)")
    enabled: bool = Field(True, description="Plugin enabled by default")
    
    # Metadata
    tags: List[str] = Field(default_factory=list, description="Plugin tags")
    documentation_url: Optional[str] = Field(None, description="Documentation URL")
    source_url: Optional[str] = Field(None, description="Source code URL")
    
    class Config:
        use_enum_values = True


class PluginContext(BaseModel):
    """Runtime context provided to plugins."""
    
    plugin_id: str
    instance_id: str
    config: Dict[str, Any]
    logger: Any = Field(exclude=True)
    event_bus: Any = Field(exclude=True)
    config_manager: Any = Field(exclude=True)
    
    # Runtime information
    startup_time: datetime
    working_directory: str
    temp_directory: str
    
    # Platform information
    platform_version: str
    api_version: str
    environment: str = "production"
    
    class Config:
        arbitrary_types_allowed = True


class BasePlugin(ABC):
    """
    Base class for all MCP Security Platform plugins.
    
    This abstract base class defines the core interface that all plugins
    must implement. It provides lifecycle management, configuration handling,
    and integration with the platform's event system.
    """
    
    def __init__(self, context: PluginContext):
        """
        Initialize the plugin with the provided context.
        
        Args:
            context: Runtime context with configuration and platform services
        """
        self.context = context
        self.metadata: Optional[PluginMetadata] = None
        self.status = PluginStatus.UNLOADED
        self._shutdown_event = asyncio.Event()
        
    @property
    def plugin_id(self) -> str:
        """Get the plugin ID."""
        return self.context.plugin_id
        
    @property
    def config(self) -> Dict[str, Any]:
        """Get the plugin configuration."""
        return self.context.config
        
    @property
    def logger(self):
        """Get the plugin logger."""
        return self.context.logger
        
    @property
    def event_bus(self):
        """Get the event bus."""
        return self.context.event_bus
    
    @abstractmethod
    async def initialize(self) -> None:
        """
        Initialize the plugin.
        
        This method is called when the plugin is loaded and should perform
        any necessary setup operations. The plugin should be ready to receive
        events after this method completes successfully.
        
        Raises:
            PluginError: If initialization fails
        """
        pass
    
    @abstractmethod
    async def shutdown(self) -> None:
        """
        Shutdown the plugin gracefully.
        
        This method is called when the plugin is being unloaded and should
        perform cleanup operations such as closing connections, saving state,
        and releasing resources.
        """
        pass
    
    @abstractmethod
    def get_metadata(self) -> PluginMetadata:
        """
        Get plugin metadata.
        
        Returns:
            PluginMetadata: Plugin metadata and configuration
        """
        pass
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform a health check.
        
        Returns:
            Dict containing health status information
        """
        return {
            "status": "healthy",
            "plugin_id": self.plugin_id,
            "uptime": (datetime.now() - self.context.startup_time).total_seconds(),
            "memory_usage": None,  # Could be implemented with psutil
        }
    
    async def get_metrics(self) -> Dict[str, Any]:
        """
        Get plugin metrics.
        
        Returns:
            Dict containing plugin metrics
        """
        return {
            "plugin_id": self.plugin_id,
            "status": self.status.value,
            "events_processed": 0,  # Should be implemented by concrete plugins
            "errors": 0,
            "last_activity": datetime.now().isoformat(),
        }
    
    async def reload_config(self, new_config: Dict[str, Any]) -> None:
        """
        Reload plugin configuration.
        
        Args:
            new_config: New configuration dictionary
        """
        self.context.config.update(new_config)
        await self._on_config_changed(new_config)
    
    async def _on_config_changed(self, new_config: Dict[str, Any]) -> None:
        """
        Handle configuration changes.
        
        Override this method to handle configuration updates.
        
        Args:
            new_config: New configuration dictionary
        """
        pass
    
    def __repr__(self) -> str:
        """String representation of the plugin."""
        return f"<{self.__class__.__name__} id={self.plugin_id} status={self.status.value}>"