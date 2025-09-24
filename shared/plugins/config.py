"""
Plugin Configuration Management - Configuration validation, schema management, and dynamic updates

This module provides comprehensive configuration management for plugins including
schema validation, encryption, environment variable substitution, and hot reloading.
"""

import os
import json
import yaml
from pathlib import Path
from typing import Dict, List, Optional, Any, Union, Type
from datetime import datetime, timezone
from enum import Enum
import jsonschema
from cryptography.fernet import Fernet
import base64
import re

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

logger = get_logger(__name__)
metrics = get_metrics()


class ConfigFormat(str, Enum):
    """Configuration file formats."""
    JSON = "json"
    YAML = "yaml"
    ENV = "env"


class ConfigSource(str, Enum):
    """Configuration sources."""
    FILE = "file"
    ENVIRONMENT = "environment"
    DATABASE = "database"
    VAULT = "vault"
    RUNTIME = "runtime"


class ConfigValidationError(Exception):
    """Configuration validation error."""
    pass


class ConfigEncryptionError(Exception):
    """Configuration encryption error."""
    pass


class PluginConfigManager:
    """
    Plugin configuration manager with advanced features.
    
    Features:
    - Schema-based configuration validation
    - Sensitive data encryption/decryption
    - Environment variable substitution
    - Multi-source configuration merging
    - Hot reloading and change notifications
    - Configuration templates and inheritance
    - Audit logging and change tracking
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.config_cache: Dict[str, Dict[str, Any]] = {}
        self.schemas: Dict[str, Dict[str, Any]] = {}
        self.watchers: Dict[str, List[callable]] = {}
        self.encryption_key: Optional[bytes] = None
        self.last_modified: Dict[str, datetime] = {}
        
        # Configuration paths
        self.config_paths = [
            Path.cwd() / "config" / "plugins",
            Path.home() / ".mcp-security-platform" / "config" / "plugins",
            Path("/etc/mcp-security-platform/plugins")
        ]
        
        # Add configured paths
        for path in self.config.get("config_paths", []):
            self.config_paths.append(Path(path))
        
        # Initialize encryption
        self._initialize_encryption()
        
        logger.info("Plugin configuration manager initialized")
    
    def _initialize_encryption(self):
        """Initialize encryption for sensitive configuration data."""
        try:
            # Try to load existing key
            key_file = Path.home() / ".mcp-security-platform" / "config.key"
            if key_file.exists():
                with open(key_file, 'rb') as f:
                    self.encryption_key = f.read()
            else:
                # Generate new key
                self.encryption_key = Fernet.generate_key()
                key_file.parent.mkdir(parents=True, exist_ok=True)
                with open(key_file, 'wb') as f:
                    f.write(self.encryption_key)
                os.chmod(key_file, 0o600)  # Restrict permissions
                
        except Exception as e:
            logger.warning(f"Failed to initialize configuration encryption: {e}")
            self.encryption_key = None
    
    @traced("config_manager_load")
    async def load_config(
        self,
        plugin_name: str,
        schema: Optional[Dict[str, Any]] = None,
        defaults: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Load and validate plugin configuration."""
        try:
            # Register schema if provided
            if schema:
                self.register_schema(plugin_name, schema)
            
            # Load configuration from all sources
            config_data = await self._load_from_sources(plugin_name)
            
            # Apply defaults
            if defaults:
                config_data = self._merge_configs(defaults, config_data)
            
            # Substitute environment variables
            config_data = self._substitute_env_vars(config_data)
            
            # Decrypt sensitive fields
            config_data = self._decrypt_sensitive_data(config_data)
            
            # Validate against schema
            if plugin_name in self.schemas:
                self._validate_config(plugin_name, config_data)
            
            # Cache configuration
            self.config_cache[plugin_name] = config_data
            self.last_modified[plugin_name] = datetime.now(timezone.utc)
            
            logger.debug(f"Loaded configuration for plugin: {plugin_name}")
            metrics.plugin_configs_loaded.inc()
            
            return config_data
            
        except Exception as e:
            logger.error(f"Failed to load configuration for {plugin_name}: {e}")
            metrics.plugin_config_errors.inc()
            raise ConfigValidationError(f"Configuration load failed: {e}")
    
    @traced("config_manager_save")
    async def save_config(
        self,
        plugin_name: str,
        config_data: Dict[str, Any],
        encrypt_sensitive: bool = True
    ) -> bool:
        """Save plugin configuration."""
        try:
            # Validate against schema
            if plugin_name in self.schemas:
                self._validate_config(plugin_name, config_data)
            
            # Encrypt sensitive fields
            if encrypt_sensitive:
                config_data = self._encrypt_sensitive_data(config_data)
            
            # Save to primary config file
            config_file = self.config_paths[0] / f"{plugin_name}.yaml"
            config_file.parent.mkdir(parents=True, exist_ok=True)
            
            with open(config_file, 'w') as f:
                yaml.dump(config_data, f, default_flow_style=False)
            
            # Update cache
            self.config_cache[plugin_name] = config_data
            self.last_modified[plugin_name] = datetime.now(timezone.utc)
            
            # Notify watchers
            await self._notify_watchers(plugin_name, config_data)
            
            logger.info(f"Saved configuration for plugin: {plugin_name}")
            metrics.plugin_configs_saved.inc()
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to save configuration for {plugin_name}: {e}")
            return False
    
    def register_schema(self, plugin_name: str, schema: Dict[str, Any]):
        """Register configuration schema for validation."""
        try:
            # Validate schema itself
            jsonschema.Draft7Validator.check_schema(schema)
            
            self.schemas[plugin_name] = schema
            logger.debug(f"Registered schema for plugin: {plugin_name}")
            
        except jsonschema.SchemaError as e:
            raise ConfigValidationError(f"Invalid schema for {plugin_name}: {e}")
    
    def get_schema(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Get configuration schema for a plugin."""
        return self.schemas.get(plugin_name)
    
    def validate_config(self, plugin_name: str, config_data: Dict[str, Any]) -> bool:
        """Validate configuration against registered schema."""
        try:
            self._validate_config(plugin_name, config_data)
            return True
        except ConfigValidationError:
            return False
    
    def add_watcher(self, plugin_name: str, callback: callable):
        """Add configuration change watcher."""
        if plugin_name not in self.watchers:
            self.watchers[plugin_name] = []
        self.watchers[plugin_name].append(callback)
    
    def remove_watcher(self, plugin_name: str, callback: callable):
        """Remove configuration change watcher."""
        if plugin_name in self.watchers and callback in self.watchers[plugin_name]:
            self.watchers[plugin_name].remove(callback)
    
    async def reload_config(self, plugin_name: str) -> Optional[Dict[str, Any]]:
        """Reload configuration for a plugin."""
        try:
            # Check if config files have changed
            current_config = self.config_cache.get(plugin_name, {})
            new_config = await self.load_config(plugin_name)
            
            if new_config != current_config:
                # Notify watchers of changes
                await self._notify_watchers(plugin_name, new_config)
                logger.info(f"Reloaded configuration for plugin: {plugin_name}")
                return new_config
            
            return current_config
            
        except Exception as e:
            logger.error(f"Failed to reload configuration for {plugin_name}: {e}")
            return None
    
    async def reload_all_configs(self) -> Dict[str, bool]:
        """Reload all cached configurations."""
        results = {}
        for plugin_name in self.config_cache.keys():
            try:
                await self.reload_config(plugin_name)
                results[plugin_name] = True
            except Exception as e:
                logger.error(f"Failed to reload config for {plugin_name}: {e}")
                results[plugin_name] = False
        return results
    
    def encrypt_value(self, value: str) -> str:
        """Encrypt a configuration value."""
        if not self.encryption_key:
            raise ConfigEncryptionError("Encryption not available")
        
        try:
            fernet = Fernet(self.encryption_key)
            encrypted = fernet.encrypt(value.encode())
            return f"encrypted:{base64.b64encode(encrypted).decode()}"
        except Exception as e:
            raise ConfigEncryptionError(f"Encryption failed: {e}")
    
    def decrypt_value(self, encrypted_value: str) -> str:
        """Decrypt a configuration value."""
        if not encrypted_value.startswith("encrypted:"):
            return encrypted_value
        
        if not self.encryption_key:
            raise ConfigEncryptionError("Encryption key not available")
        
        try:
            encrypted_data = base64.b64decode(encrypted_value[10:])  # Remove "encrypted:" prefix
            fernet = Fernet(self.encryption_key)
            decrypted = fernet.decrypt(encrypted_data)
            return decrypted.decode()
        except Exception as e:
            raise ConfigEncryptionError(f"Decryption failed: {e}")
    
    def get_config_template(self, plugin_type: str) -> Dict[str, Any]:
        """Get configuration template for a plugin type."""
        templates = {
            "scanner": {
                "enabled": True,
                "timeout_seconds": 300,
                "retry_count": 3,
                "output_format": "json",
                "scan_targets": [],
                "exclude_patterns": [],
                "severity_threshold": "medium"
            },
            "integration": {
                "enabled": True,
                "api_endpoint": "",
                "api_key": "encrypted:placeholder",
                "timeout_seconds": 30,
                "retry_count": 3,
                "rate_limit_per_minute": 60,
                "sync_interval_minutes": 15
            },
            "alert": {
                "enabled": True,
                "priority_mapping": {
                    "critical": "high",
                    "high": "medium",
                    "medium": "low",
                    "low": "info"
                },
                "retry_count": 3,
                "timeout_seconds": 30,
                "rate_limit_per_minute": 100
            },
            "compliance": {
                "enabled": True,
                "framework_version": "latest",
                "assessment_scope": [],
                "evidence_collection": True,
                "automated_reporting": True,
                "compliance_threshold": 0.8
            }
        }
        
        return templates.get(plugin_type, {})
    
    def export_config(self, plugin_name: str, format: ConfigFormat = ConfigFormat.YAML) -> str:
        """Export plugin configuration in specified format."""
        config_data = self.config_cache.get(plugin_name, {})
        
        if format == ConfigFormat.JSON:
            return json.dumps(config_data, indent=2)
        elif format == ConfigFormat.YAML:
            return yaml.dump(config_data, default_flow_style=False)
        elif format == ConfigFormat.ENV:
            return self._export_as_env_vars(plugin_name, config_data)
        else:
            raise ValueError(f"Unsupported export format: {format}")
    
    def import_config(
        self,
        plugin_name: str,
        config_content: str,
        format: ConfigFormat
    ) -> Dict[str, Any]:
        """Import plugin configuration from content."""
        try:
            if format == ConfigFormat.JSON:
                config_data = json.loads(config_content)
            elif format == ConfigFormat.YAML:
                config_data = yaml.safe_load(config_content)
            elif format == ConfigFormat.ENV:
                config_data = self._import_from_env_vars(config_content)
            else:
                raise ValueError(f"Unsupported import format: {format}")
            
            # Validate imported configuration
            if plugin_name in self.schemas:
                self._validate_config(plugin_name, config_data)
            
            return config_data
            
        except Exception as e:
            raise ConfigValidationError(f"Import failed: {e}")
    
    async def _load_from_sources(self, plugin_name: str) -> Dict[str, Any]:
        """Load configuration from all available sources."""
        config_data = {}
        
        # Load from files (in order of precedence)
        for config_path in reversed(self.config_paths):
            for ext in ['.yaml', '.yml', '.json']:
                config_file = config_path / f"{plugin_name}{ext}"
                if config_file.exists():
                    try:
                        with open(config_file) as f:
                            if ext in ['.yaml', '.yml']:
                                file_config = yaml.safe_load(f)
                            else:
                                file_config = json.load(f)
                        
                        config_data = self._merge_configs(config_data, file_config or {})
                        
                    except Exception as e:
                        logger.warning(f"Failed to load config file {config_file}: {e}")
        
        # Load from environment variables
        env_config = self._load_from_environment(plugin_name)
        config_data = self._merge_configs(config_data, env_config)
        
        return config_data
    
    def _load_from_environment(self, plugin_name: str) -> Dict[str, Any]:
        """Load configuration from environment variables."""
        config_data = {}
        prefix = f"MCP_{plugin_name.upper()}_"
        
        for key, value in os.environ.items():
            if key.startswith(prefix):
                config_key = key[len(prefix):].lower()
                
                # Convert nested keys (SECTION__SUBSECTION -> section.subsection)
                config_path = config_key.split('__')
                
                # Try to parse value as JSON, otherwise keep as string
                try:
                    parsed_value = json.loads(value)
                except (json.JSONDecodeError, ValueError):
                    parsed_value = value
                
                # Set nested configuration
                current = config_data
                for path_part in config_path[:-1]:
                    if path_part not in current:
                        current[path_part] = {}
                    current = current[path_part]
                current[config_path[-1]] = parsed_value
        
        return config_data
    
    def _merge_configs(self, base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
        """Merge two configuration dictionaries."""
        result = base.copy()
        
        for key, value in override.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_configs(result[key], value)
            else:
                result[key] = value
        
        return result
    
    def _substitute_env_vars(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Substitute environment variables in configuration."""
        def substitute_value(value):
            if isinstance(value, str):
                # Pattern: ${VAR_NAME} or ${VAR_NAME:default_value}
                pattern = r'\$\{([^}]+)\}'
                
                def replace_var(match):
                    var_expr = match.group(1)
                    if ':' in var_expr:
                        var_name, default_value = var_expr.split(':', 1)
                    else:
                        var_name, default_value = var_expr, ''
                    
                    return os.environ.get(var_name, default_value)
                
                return re.sub(pattern, replace_var, value)
            elif isinstance(value, dict):
                return {k: substitute_value(v) for k, v in value.items()}
            elif isinstance(value, list):
                return [substitute_value(item) for item in value]
            else:
                return value
        
        return substitute_value(config_data)
    
    def _encrypt_sensitive_data(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Encrypt sensitive configuration fields."""
        sensitive_keys = ['password', 'secret', 'key', 'token', 'credential']
        
        def encrypt_recursive(data):
            if isinstance(data, dict):
                result = {}
                for key, value in data.items():
                    if any(sensitive_key in key.lower() for sensitive_key in sensitive_keys):
                        if isinstance(value, str) and not value.startswith('encrypted:'):
                            try:
                                result[key] = self.encrypt_value(value)
                            except ConfigEncryptionError:
                                result[key] = value
                        else:
                            result[key] = value
                    else:
                        result[key] = encrypt_recursive(value)
                return result
            elif isinstance(data, list):
                return [encrypt_recursive(item) for item in data]
            else:
                return data
        
        return encrypt_recursive(config_data)
    
    def _decrypt_sensitive_data(self, config_data: Dict[str, Any]) -> Dict[str, Any]:
        """Decrypt sensitive configuration fields."""
        def decrypt_recursive(data):
            if isinstance(data, dict):
                result = {}
                for key, value in data.items():
                    if isinstance(value, str) and value.startswith('encrypted:'):
                        try:
                            result[key] = self.decrypt_value(value)
                        except ConfigEncryptionError as e:
                            logger.warning(f"Failed to decrypt {key}: {e}")
                            result[key] = value
                    else:
                        result[key] = decrypt_recursive(value)
                return result
            elif isinstance(data, list):
                return [decrypt_recursive(item) for item in data]
            else:
                return data
        
        return decrypt_recursive(config_data)
    
    def _validate_config(self, plugin_name: str, config_data: Dict[str, Any]):
        """Validate configuration against schema."""
        schema = self.schemas.get(plugin_name)
        if not schema:
            return  # No schema to validate against
        
        try:
            jsonschema.validate(config_data, schema)
        except jsonschema.ValidationError as e:
            raise ConfigValidationError(f"Configuration validation failed for {plugin_name}: {e.message}")
    
    async def _notify_watchers(self, plugin_name: str, config_data: Dict[str, Any]):
        """Notify configuration change watchers."""
        for callback in self.watchers.get(plugin_name, []):
            try:
                if hasattr(callback, '__call__'):
                    if asyncio.iscoroutinefunction(callback):
                        await callback(plugin_name, config_data)
                    else:
                        callback(plugin_name, config_data)
            except Exception as e:
                logger.warning(f"Configuration watcher failed for {plugin_name}: {e}")
    
    def _export_as_env_vars(self, plugin_name: str, config_data: Dict[str, Any]) -> str:
        """Export configuration as environment variables."""
        lines = []
        prefix = f"MCP_{plugin_name.upper()}_"
        
        def flatten_config(data, prefix_parts=None):
            prefix_parts = prefix_parts or []
            
            for key, value in data.items():
                current_parts = prefix_parts + [key.upper()]
                
                if isinstance(value, dict):
                    flatten_config(value, current_parts)
                else:
                    env_var = prefix + '__'.join(current_parts)
                    env_value = json.dumps(value) if not isinstance(value, str) else value
                    lines.append(f"{env_var}={env_value}")
        
        flatten_config(config_data)
        return '\n'.join(lines)
    
    def _import_from_env_vars(self, content: str) -> Dict[str, Any]:
        """Import configuration from environment variable format."""
        config_data = {}
        
        for line in content.strip().split('\n'):
            if '=' in line:
                key, value = line.split('=', 1)
                
                # Parse nested keys
                if '__' in key:
                    parts = key.split('__')
                    current = config_data
                    for part in parts[:-1]:
                        if part not in current:
                            current[part] = {}
                        current = current[part]
                    
                    # Try to parse as JSON
                    try:
                        current[parts[-1]] = json.loads(value)
                    except (json.JSONDecodeError, ValueError):
                        current[parts[-1]] = value
                else:
                    try:
                        config_data[key] = json.loads(value)
                    except (json.JSONDecodeError, ValueError):
                        config_data[key] = value
        
        return config_data


# Global configuration manager instance
_config_manager: Optional[PluginConfigManager] = None


def get_config_manager(config: Dict[str, Any] = None) -> PluginConfigManager:
    """Get the global plugin configuration manager instance."""
    global _config_manager
    if _config_manager is None:
        _config_manager = PluginConfigManager(config)
    return _config_manager