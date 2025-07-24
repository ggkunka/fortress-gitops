"""
Plugin Manager Service

Manages scanner plugins including discovery, lifecycle, and health monitoring.
"""

import asyncio
import importlib
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

import structlog
from shared.event_bus import EventBus

from ..models.scan_models import PluginStatus, PluginState, ScannerType

logger = structlog.get_logger(__name__)


class PluginManager:
    """
    Manages scanner plugins including discovery, loading, and lifecycle management.
    """
    
    def __init__(self, event_bus: EventBus):
        """Initialize the plugin manager."""
        self.event_bus = event_bus
        
        # Plugin storage
        self.plugins: Dict[str, any] = {}  # Plugin instances
        self.plugin_statuses: Dict[str, PluginStatus] = {}
        self.plugin_configs: Dict[str, dict] = {}
        
        # Plugin discovery paths
        self.plugin_paths = [
            Path("plugins/scanners"),
            Path("/usr/local/lib/mcp-plugins"),
            Path.home() / ".mcp-plugins"
        ]
        
        # Health status
        self.healthy = True
        
        # Background tasks
        self.health_check_task: Optional[asyncio.Task] = None
    
    async def initialize(self):
        """Initialize the plugin manager."""
        try:
            # Start health monitoring
            self.health_check_task = asyncio.create_task(self._health_check_loop())
            
            logger.info("Plugin manager initialized", plugin_paths=str(self.plugin_paths))
            
        except Exception as e:
            logger.error("Failed to initialize plugin manager", error=str(e))
            self.healthy = False
            raise
    
    async def cleanup(self):
        """Cleanup plugin manager resources."""
        try:
            # Cancel health check task
            if self.health_check_task:
                self.health_check_task.cancel()
            
            # Cleanup all plugins
            for plugin_name in list(self.plugins.keys()):
                await self.disable_plugin(plugin_name)
            
            logger.info("Plugin manager cleaned up")
            
        except Exception as e:
            logger.error("Error during plugin manager cleanup", error=str(e))
    
    def is_healthy(self) -> bool:
        """Check if plugin manager is healthy."""
        return self.healthy
    
    async def discover_plugins(self):
        """Discover available scanner plugins."""
        discovered_count = 0
        
        try:
            # Check for built-in scanner plugins
            builtin_plugins = {
                "grype": {
                    "name": "grype",
                    "version": "0.65.0",
                    "scanner_type": ScannerType.GRYPE,
                    "description": "Anchore Grype vulnerability scanner",
                    "executable": "grype",
                    "capabilities": ["vulnerability_scan", "container_scan", "filesystem_scan"]
                },
                "trivy": {
                    "name": "trivy",
                    "version": "0.45.0",
                    "scanner_type": ScannerType.TRIVY,
                    "description": "Aqua Security Trivy scanner",
                    "executable": "trivy",
                    "capabilities": ["vulnerability_scan", "secret_scan", "misconfiguration_scan"]
                },
                "syft": {
                    "name": "syft",
                    "version": "0.90.0",
                    "scanner_type": ScannerType.SYFT,
                    "description": "Anchore Syft SBOM generator",
                    "executable": "syft",
                    "capabilities": ["sbom_generation", "package_analysis"]
                },
                "osv": {
                    "name": "osv",
                    "version": "1.0.0",
                    "scanner_type": ScannerType.OSV,
                    "description": "OSV vulnerability scanner",
                    "executable": "osv-scanner",
                    "capabilities": ["vulnerability_scan", "oss_scan"]
                }
            }
            
            # Register built-in plugins
            for plugin_name, config in builtin_plugins.items():
                await self._register_plugin(plugin_name, config)
                discovered_count += 1
            
            # Discover custom plugins from filesystem
            for plugin_path in self.plugin_paths:
                if plugin_path.exists():
                    discovered_count += await self._discover_plugins_in_path(plugin_path)
            
            logger.info("Plugin discovery completed", discovered_count=discovered_count)
            
        except Exception as e:
            logger.error("Plugin discovery failed", error=str(e))
            raise
    
    async def _discover_plugins_in_path(self, path: Path) -> int:
        """Discover plugins in a specific path."""
        discovered = 0
        
        try:
            for plugin_dir in path.iterdir():
                if plugin_dir.is_dir() and not plugin_dir.name.startswith('.'):
                    plugin_file = plugin_dir / "plugin.py"
                    config_file = plugin_dir / "config.yaml"
                    
                    if plugin_file.exists():
                        try:
                            config = await self._load_plugin_config(config_file)
                            await self._register_plugin(plugin_dir.name, config)
                            discovered += 1
                            
                        except Exception as e:
                            logger.warning("Failed to load plugin", 
                                         plugin=plugin_dir.name, error=str(e))
            
        except Exception as e:
            logger.error("Failed to discover plugins in path", path=str(path), error=str(e))
        
        return discovered
    
    async def _register_plugin(self, plugin_name: str, config: dict):
        """Register a plugin with the manager."""
        try:
            # Check if plugin executable is available
            available = await self._check_plugin_availability(config)
            
            # Create plugin status
            status = PluginStatus(
                name=plugin_name,
                version=config.get("version", "unknown"),
                state=PluginState.AVAILABLE if available else PluginState.ERROR,
                scanner_type=config.get("scanner_type", ScannerType.CUSTOM),
                description=config.get("description", ""),
                enabled=False,
                available=available,
                health_status="healthy" if available else "unavailable",
                capabilities=config.get("capabilities", []),
                configuration=config
            )
            
            self.plugin_statuses[plugin_name] = status
            self.plugin_configs[plugin_name] = config
            
            # Auto-enable available plugins
            if available:
                await self.enable_plugin(plugin_name)
            
            logger.info("Plugin registered", 
                       plugin=plugin_name, 
                       available=available,
                       scanner_type=config.get("scanner_type"))
            
        except Exception as e:
            logger.error("Failed to register plugin", plugin=plugin_name, error=str(e))
            raise
    
    async def _check_plugin_availability(self, config: dict) -> bool:
        """Check if a plugin's executable is available."""
        executable = config.get("executable")
        if not executable:
            return True  # Assume available if no executable specified
        
        try:
            # Check if executable exists in PATH
            process = await asyncio.create_subprocess_exec(
                "which", executable,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            returncode = await process.wait()
            return returncode == 0
            
        except Exception:
            return False
    
    async def _load_plugin_config(self, config_file: Path) -> dict:
        """Load plugin configuration from file."""
        # For now, return default config
        # In production, would parse YAML/JSON config file
        return {
            "name": config_file.parent.name,
            "version": "1.0.0",
            "scanner_type": ScannerType.CUSTOM,
            "description": f"Custom plugin: {config_file.parent.name}",
            "executable": config_file.parent.name,
            "capabilities": ["vulnerability_scan"]
        }
    
    async def enable_plugin(self, plugin_name: str) -> bool:
        """Enable a plugin."""
        if plugin_name not in self.plugin_statuses:
            logger.warning("Plugin not found", plugin=plugin_name)
            return False
        
        status = self.plugin_statuses[plugin_name]
        
        if not status.available:
            logger.warning("Plugin not available", plugin=plugin_name)
            return False
        
        if status.enabled:
            logger.info("Plugin already enabled", plugin=plugin_name)
            return True
        
        try:
            # Load plugin instance (simulated)
            plugin_instance = await self._load_plugin_instance(plugin_name)
            self.plugins[plugin_name] = plugin_instance
            
            # Update status
            status.enabled = True
            status.state = PluginState.ENABLED
            status.health_status = "healthy"
            
            # Emit event
            await self.event_bus.publish(
                "plugin.enabled",
                {
                    "plugin_name": plugin_name,
                    "scanner_type": status.scanner_type.value,
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
            
            logger.info("Plugin enabled", plugin=plugin_name)
            return True
            
        except Exception as e:
            status.state = PluginState.ERROR
            status.health_status = "error"
            status.error_message = str(e)
            
            logger.error("Failed to enable plugin", plugin=plugin_name, error=str(e))
            return False
    
    async def disable_plugin(self, plugin_name: str) -> bool:
        """Disable a plugin."""
        if plugin_name not in self.plugin_statuses:
            logger.warning("Plugin not found", plugin=plugin_name)
            return False
        
        status = self.plugin_statuses[plugin_name]
        
        if not status.enabled:
            logger.info("Plugin already disabled", plugin=plugin_name)
            return True
        
        try:
            # Unload plugin instance
            if plugin_name in self.plugins:
                await self._unload_plugin_instance(plugin_name)
                del self.plugins[plugin_name]
            
            # Update status
            status.enabled = False
            status.state = PluginState.DISABLED
            status.health_status = "disabled"
            
            # Emit event
            await self.event_bus.publish(
                "plugin.disabled",
                {
                    "plugin_name": plugin_name,
                    "scanner_type": status.scanner_type.value,
                    "timestamp": datetime.utcnow().isoformat()
                }
            )
            
            logger.info("Plugin disabled", plugin=plugin_name)
            return True
            
        except Exception as e:
            status.state = PluginState.ERROR
            status.error_message = str(e)
            
            logger.error("Failed to disable plugin", plugin=plugin_name, error=str(e))
            return False
    
    async def _load_plugin_instance(self, plugin_name: str):
        """Load a plugin instance."""
        # Simulated plugin loading
        # In production, would dynamically import and instantiate plugin class
        config = self.plugin_configs[plugin_name]
        
        class MockPlugin:
            def __init__(self, name, config):
                self.name = name
                self.config = config
                self.enabled = True
                
            async def scan(self, target: str) -> dict:
                # Simulate scan execution
                await asyncio.sleep(1)
                return {"vulnerabilities": [], "status": "completed"}
                
            async def health_check(self) -> bool:
                return True
        
        return MockPlugin(plugin_name, config)
    
    async def _unload_plugin_instance(self, plugin_name: str):
        """Unload a plugin instance."""
        # Cleanup plugin resources
        plugin = self.plugins.get(plugin_name)
        if plugin and hasattr(plugin, 'cleanup'):
            await plugin.cleanup()
    
    def get_available_plugins(self) -> List[str]:
        """Get list of available plugin names."""
        return [
            name for name, status in self.plugin_statuses.items()
            if status.available
        ]
    
    def get_active_plugins(self) -> List[str]:
        """Get list of enabled plugin names."""
        return [
            name for name, status in self.plugin_statuses.items()
            if status.enabled
        ]
    
    def get_failed_plugins(self) -> List[str]:
        """Get list of failed plugin names."""
        return [
            name for name, status in self.plugin_statuses.items()
            if status.state == PluginState.ERROR
        ]
    
    def get_plugin_statuses(self) -> List[PluginStatus]:
        """Get status of all plugins."""
        return list(self.plugin_statuses.values())
    
    def get_plugin_instance(self, plugin_name: str):
        """Get a plugin instance by name."""
        return self.plugins.get(plugin_name)
    
    async def _health_check_loop(self):
        """Background task for plugin health monitoring."""
        while True:
            try:
                for plugin_name, status in self.plugin_statuses.items():
                    if status.enabled and plugin_name in self.plugins:
                        try:
                            plugin = self.plugins[plugin_name]
                            healthy = await plugin.health_check()
                            
                            if healthy:
                                status.health_status = "healthy"
                                if status.state == PluginState.ERROR:
                                    status.state = PluginState.ENABLED
                                    status.error_message = None
                            else:
                                status.health_status = "unhealthy"
                                status.state = PluginState.ERROR
                                status.error_message = "Health check failed"
                                
                        except Exception as e:
                            status.health_status = "error"
                            status.state = PluginState.ERROR
                            status.error_message = str(e)
                            
                            logger.warning("Plugin health check failed", 
                                         plugin=plugin_name, error=str(e))
                
                # Wait 30 seconds before next health check
                await asyncio.sleep(30)
                
            except Exception as e:
                logger.error("Error in plugin health check loop", error=str(e))
                await asyncio.sleep(60)