"""
Configuration management for plugins.
"""

import json
import os
from typing import Any, Dict, Optional
import asyncio
from pathlib import Path

import yaml
from jsonschema import validate, ValidationError as JsonSchemaValidationError
from pydantic import BaseModel, Field

from ..utils.exceptions import ConfigurationError
from ..utils.logger import get_logger


class PluginConfig(BaseModel):
    """Plugin configuration wrapper."""
    
    plugin_id: str
    config_data: Dict[str, Any] = Field(default_factory=dict)
    schema: Optional[Dict[str, Any]] = None
    version: str = "1.0"
    created_at: str = ""
    updated_at: str = ""


class ConfigManager:
    """
    Configuration manager for plugins.
    
    Handles loading, saving, validation, and hot-reloading of plugin configurations.
    """
    
    def __init__(
        self,
        config_dir: str = "./config/plugins",
        storage_format: str = "yaml",  # yaml, json
        auto_reload: bool = True
    ):
        self.config_dir = Path(config_dir)
        self.storage_format = storage_format
        self.auto_reload = auto_reload
        
        self.logger = get_logger("config_manager")
        
        # In-memory cache
        self._config_cache: Dict[str, PluginConfig] = {}
        self._file_watchers: Dict[str, asyncio.Task] = {}
        
        # Ensure config directory exists
        self.config_dir.mkdir(parents=True, exist_ok=True)
    
    async def get_plugin_config(self, plugin_id: str) -> Optional[Dict[str, Any]]:
        """
        Get configuration for a plugin.
        
        Args:
            plugin_id: Plugin identifier
            
        Returns:
            Plugin configuration dict or None if not found
        """
        # Check cache first
        if plugin_id in self._config_cache:
            return self._config_cache[plugin_id].config_data
        
        # Load from file
        config_file = self._get_config_file_path(plugin_id)
        if config_file.exists():
            try:
                config = await self._load_config_file(config_file)
                self._config_cache[plugin_id] = config
                
                # Start file watcher if auto-reload is enabled
                if self.auto_reload:
                    await self._start_file_watcher(plugin_id, config_file)
                
                return config.config_data
                
            except Exception as e:
                self.logger.error(f"Failed to load config for {plugin_id}: {e}")
                return None
        
        return None
    
    async def set_plugin_config(
        self,
        plugin_id: str,
        config_data: Dict[str, Any],
        schema: Optional[Dict[str, Any]] = None
    ) -> bool:
        """
        Set configuration for a plugin.
        
        Args:
            plugin_id: Plugin identifier
            config_data: Configuration data
            schema: JSON schema for validation
            
        Returns:
            True if configuration was saved successfully
        """
        try:
            # Validate against schema if provided
            if schema:
                await self.validate_config(config_data, schema)
            
            # Create plugin config object
            config = PluginConfig(
                plugin_id=plugin_id,
                config_data=config_data,
                schema=schema,
                updated_at=str(asyncio.get_event_loop().time())
            )
            
            # Save to file
            config_file = self._get_config_file_path(plugin_id)
            await self._save_config_file(config_file, config)
            
            # Update cache
            self._config_cache[plugin_id] = config
            
            # Start file watcher if not already running
            if self.auto_reload and plugin_id not in self._file_watchers:
                await self._start_file_watcher(plugin_id, config_file)
            
            self.logger.info(f"Saved configuration for plugin {plugin_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save config for {plugin_id}: {e}")
            return False
    
    async def validate_config(self, config_data: Dict[str, Any], schema: Dict[str, Any]) -> None:
        """
        Validate configuration against JSON schema.
        
        Args:
            config_data: Configuration to validate
            schema: JSON schema
            
        Raises:
            ConfigurationError: If validation fails
        """
        try:
            validate(instance=config_data, schema=schema)
        except JsonSchemaValidationError as e:
            raise ConfigurationError(f"Configuration validation failed: {e.message}")
    
    async def delete_plugin_config(self, plugin_id: str) -> bool:
        """
        Delete configuration for a plugin.
        
        Args:
            plugin_id: Plugin identifier
            
        Returns:
            True if configuration was deleted successfully
        """
        try:
            # Remove from cache
            self._config_cache.pop(plugin_id, None)
            
            # Stop file watcher
            if plugin_id in self._file_watchers:
                self._file_watchers[plugin_id].cancel()
                del self._file_watchers[plugin_id]
            
            # Delete file
            config_file = self._get_config_file_path(plugin_id)
            if config_file.exists():
                config_file.unlink()
            
            self.logger.info(f"Deleted configuration for plugin {plugin_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to delete config for {plugin_id}: {e}")
            return False
    
    async def list_plugin_configs(self) -> Dict[str, Dict[str, Any]]:
        """
        List all plugin configurations.
        
        Returns:
            Dictionary mapping plugin IDs to their configurations
        """
        configs = {}
        
        # Load from files
        for config_file in self.config_dir.glob(f"*.{self.storage_format}"):
            plugin_id = config_file.stem
            try:
                config_data = await self.get_plugin_config(plugin_id)
                if config_data:
                    configs[plugin_id] = config_data
            except Exception as e:
                self.logger.error(f"Failed to load config for {plugin_id}: {e}")
        
        return configs
    
    async def reload_plugin_config(self, plugin_id: str) -> Optional[Dict[str, Any]]:
        """
        Reload configuration for a plugin from file.
        
        Args:
            plugin_id: Plugin identifier
            
        Returns:
            Reloaded configuration or None if not found
        """
        # Remove from cache to force reload
        self._config_cache.pop(plugin_id, None)
        
        return await self.get_plugin_config(plugin_id)
    
    def _get_config_file_path(self, plugin_id: str) -> Path:
        """Get configuration file path for a plugin."""
        filename = f"{plugin_id}.{self.storage_format}"
        return self.config_dir / filename
    
    async def _load_config_file(self, config_file: Path) -> PluginConfig:
        """Load configuration from file."""
        try:
            with open(config_file, 'r') as f:
                if self.storage_format == "yaml":
                    data = yaml.safe_load(f)
                else:  # json
                    data = json.load(f)
            
            return PluginConfig(**data)
            
        except Exception as e:
            raise ConfigurationError(f"Failed to load config file {config_file}: {e}")
    
    async def _save_config_file(self, config_file: Path, config: PluginConfig) -> None:
        """Save configuration to file."""
        try:
            with open(config_file, 'w') as f:
                data = config.dict()
                if self.storage_format == "yaml":
                    yaml.safe_dump(data, f, default_flow_style=False)
                else:  # json
                    json.dump(data, f, indent=2)
                    
        except Exception as e:
            raise ConfigurationError(f"Failed to save config file {config_file}: {e}")
    
    async def _start_file_watcher(self, plugin_id: str, config_file: Path) -> None:
        """Start watching a configuration file for changes."""
        if plugin_id in self._file_watchers:
            return
        
        async def watch_file():
            """Watch file for modifications."""
            last_mtime = 0
            
            while True:
                try:
                    if config_file.exists():
                        mtime = config_file.stat().st_mtime
                        if mtime > last_mtime and last_mtime > 0:
                            self.logger.info(f"Configuration file changed for {plugin_id}")
                            
                            # Reload configuration
                            try:
                                new_config = await self._load_config_file(config_file)
                                self._config_cache[plugin_id] = new_config
                                self.logger.info(f"Reloaded configuration for {plugin_id}")
                            except Exception as e:
                                self.logger.error(f"Failed to reload config for {plugin_id}: {e}")
                        
                        last_mtime = mtime
                    
                    await asyncio.sleep(1)
                    
                except asyncio.CancelledError:
                    break
                except Exception as e:
                    self.logger.error(f"Error watching config file for {plugin_id}: {e}")
                    await asyncio.sleep(5)
        
        task = asyncio.create_task(watch_file())
        self._file_watchers[plugin_id] = task
    
    async def stop(self) -> None:
        """Stop the configuration manager."""
        # Cancel all file watchers
        for task in self._file_watchers.values():
            task.cancel()
        
        if self._file_watchers:
            await asyncio.gather(*self._file_watchers.values(), return_exceptions=True)
        
        self._file_watchers.clear()
        self.logger.info("Configuration manager stopped")