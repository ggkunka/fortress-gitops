"""
Plugin Installer - Plugin installation and lifecycle management service

This service handles plugin installation, uninstallation, updates, and
lifecycle management including dependency resolution and configuration.
"""

import asyncio
import json
import subprocess
import tempfile
import shutil
import os
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from uuid import UUID, uuid4
from pathlib import Path
import venv
import sys

from sqlalchemy.orm import Session

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.database.connection import get_db

from ..models.plugin import (
    Plugin, PluginInstallation, PluginStatus,
    create_plugin_installation
)

logger = get_logger(__name__)
metrics = get_metrics()


class PluginInstaller:
    """
    Plugin installer service for managing plugin installations and lifecycle.
    
    This service provides:
    - Plugin installation and uninstallation
    - Dependency resolution and management
    - Virtual environment management
    - Plugin configuration management
    - Installation health monitoring
    - Bulk operations support
    """
    
    def __init__(self, registry, validator):
        self.registry = registry
        self.validator = validator
        
        # Installation configuration
        self.base_install_path = Path("/opt/mcp-security-platform/plugins")
        self.venv_path = Path("/opt/mcp-security-platform/venvs")
        self.config_path = Path("/etc/mcp-security-platform/plugins")
        
        # Installation tracking
        self.active_installations = {}
        self.installation_queue = asyncio.Queue()
        
        # Statistics
        self.stats = {
            "installations_completed": 0,
            "installations_failed": 0,
            "uninstallations_completed": 0,
            "updates_completed": 0,
            "dependency_resolutions": 0,
            "health_checks_performed": 0
        }
        
        logger.info("Plugin installer initialized")
    
    async def start(self):
        """Start the plugin installer service."""
        try:
            # Create directories
            await self._create_directories()
            
            # Start installation worker
            asyncio.create_task(self._installation_worker())
            asyncio.create_task(self._health_monitor_task())
            
            logger.info("Plugin installer service started successfully")
            
        except Exception as e:
            logger.error(f"Error starting plugin installer: {e}")
            raise
    
    async def stop(self):
        """Stop the plugin installer service."""
        try:
            # Cancel active installations
            for installation_id in self.active_installations:
                self.active_installations[installation_id]["cancelled"] = True
            
            logger.info("Plugin installer service stopped")
            
        except Exception as e:
            logger.error(f"Error stopping plugin installer: {e}")
    
    @traced("installer_install_plugin")
    async def install_plugin(
        self,
        plugin_id: UUID,
        user_id: str,
        organization_id: Optional[str] = None,
        configuration: Optional[Dict[str, Any]] = None,
        environment: str = "production",
        force_reinstall: bool = False
    ) -> Dict[str, Any]:
        """Install a plugin for a user/organization."""
        try:
            # Check if already installed
            existing = await self._get_existing_installation(plugin_id, user_id, organization_id)
            if existing and not force_reinstall:
                return {
                    "success": False,
                    "error": "Plugin already installed",
                    "installation_id": str(existing.id)
                }
            
            # Get plugin information
            plugin_data = await self.registry.get_plugin(plugin_id=plugin_id)
            if not plugin_data:
                return {
                    "success": False,
                    "error": "Plugin not found"
                }
            
            if plugin_data["status"] != PluginStatus.PUBLISHED.value:
                return {
                    "success": False,
                    "error": "Plugin is not published"
                }
            
            # Validate plugin
            validation_result = await self.validator.validate_plugin(plugin_id)
            if not validation_result["valid"]:
                return {
                    "success": False,
                    "error": "Plugin validation failed",
                    "validation_issues": validation_result["issues"]
                }
            
            # Create installation record
            installation_id = uuid4()
            with get_db() as db:
                installation = create_plugin_installation(
                    plugin_id=plugin_id,
                    user_id=user_id,
                    version=plugin_data["version"],
                    organization_id=organization_id,
                    configuration=configuration or {},
                    environment=environment,
                    installation_method="marketplace",
                    status="installing"
                )
                installation.id = installation_id
                
                db.add(installation)
                db.commit()
            
            # Queue for installation
            await self.installation_queue.put({
                "action": "install",
                "installation_id": installation_id,
                "plugin_id": plugin_id,
                "user_id": user_id,
                "organization_id": organization_id,
                "plugin_data": plugin_data,
                "configuration": configuration or {},
                "environment": environment,
                "force_reinstall": force_reinstall
            })
            
            logger.info(f"Plugin installation queued: {plugin_data['name']} for user {user_id}")
            
            return {
                "success": True,
                "installation_id": str(installation_id),
                "status": "queued",
                "message": "Plugin installation queued"
            }
            
        except Exception as e:
            logger.error(f"Error installing plugin: {e}")
            metrics.installer_install_errors.inc()
            raise
    
    @traced("installer_uninstall_plugin")
    async def uninstall_plugin(
        self,
        installation_id: UUID,
        user_id: str,
        cleanup_data: bool = False
    ) -> Dict[str, Any]:
        """Uninstall a plugin installation."""
        try:
            with get_db() as db:
                installation = db.query(PluginInstallation).filter(
                    PluginInstallation.id == installation_id,
                    PluginInstallation.user_id == user_id
                ).first()
                
                if not installation:
                    return {
                        "success": False,
                        "error": "Installation not found"
                    }
                
                if installation.status == "uninstalling":
                    return {
                        "success": False,
                        "error": "Already uninstalling"
                    }
                
                # Update status
                installation.status = "uninstalling"
                db.commit()
            
            # Queue for uninstallation
            await self.installation_queue.put({
                "action": "uninstall",
                "installation_id": installation_id,
                "user_id": user_id,
                "cleanup_data": cleanup_data
            })
            
            logger.info(f"Plugin uninstallation queued: {installation_id}")
            
            return {
                "success": True,
                "installation_id": str(installation_id),
                "status": "queued",
                "message": "Plugin uninstallation queued"
            }
            
        except Exception as e:
            logger.error(f"Error uninstalling plugin: {e}")
            raise
    
    @traced("installer_update_plugin")
    async def update_plugin(
        self,
        installation_id: UUID,
        target_version: Optional[str] = None,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """Update a plugin installation to a newer version."""
        try:
            with get_db() as db:
                installation = db.query(PluginInstallation).filter(
                    PluginInstallation.id == installation_id
                ).first()
                
                if not installation:
                    return {
                        "success": False,
                        "error": "Installation not found"
                    }
                
                if user_id and installation.user_id != user_id:
                    return {
                        "success": False,
                        "error": "Not authorized"
                    }
                
                # Get current plugin data
                plugin_data = await self.registry.get_plugin(plugin_id=installation.plugin_id)
                if not plugin_data:
                    return {
                        "success": False,
                        "error": "Plugin not found"
                    }
                
                # Determine target version
                if not target_version:
                    target_version = plugin_data["version"]
                
                # Check if update is needed
                if installation.version == target_version:
                    return {
                        "success": False,
                        "error": "Already on target version"
                    }
                
                # Update status
                installation.status = "updating"
                db.commit()
            
            # Queue for update
            await self.installation_queue.put({
                "action": "update",
                "installation_id": installation_id,
                "current_version": installation.version,
                "target_version": target_version,
                "plugin_data": plugin_data
            })
            
            logger.info(f"Plugin update queued: {installation_id} to version {target_version}")
            
            return {
                "success": True,
                "installation_id": str(installation_id),
                "current_version": installation.version,
                "target_version": target_version,
                "status": "queued",
                "message": "Plugin update queued"
            }
            
        except Exception as e:
            logger.error(f"Error updating plugin: {e}")
            raise
    
    @traced("installer_configure_plugin")
    async def configure_plugin(
        self,
        installation_id: UUID,
        configuration: Dict[str, Any],
        user_id: str
    ) -> Dict[str, Any]:
        """Update plugin configuration."""
        try:
            with get_db() as db:
                installation = db.query(PluginInstallation).filter(
                    PluginInstallation.id == installation_id,
                    PluginInstallation.user_id == user_id
                ).first()
                
                if not installation:
                    return {
                        "success": False,
                        "error": "Installation not found"
                    }
                
                # Validate configuration against schema
                plugin_data = await self.registry.get_plugin(plugin_id=installation.plugin_id)
                if plugin_data and plugin_data.get("config_schema"):
                    validation_result = await self._validate_configuration(
                        configuration,
                        plugin_data["config_schema"]
                    )
                    if not validation_result["valid"]:
                        return {
                            "success": False,
                            "error": "Configuration validation failed",
                            "validation_errors": validation_result["errors"]
                        }
                
                # Update configuration
                installation.configuration = configuration
                installation.updated_at = datetime.utcnow()
                db.commit()
                
                # Apply configuration
                await self._apply_plugin_configuration(installation_id, configuration)
                
                logger.info(f"Plugin configuration updated: {installation_id}")
                
                return {
                    "success": True,
                    "installation_id": str(installation_id),
                    "message": "Configuration updated successfully"
                }
                
        except Exception as e:
            logger.error(f"Error configuring plugin: {e}")
            raise
    
    @traced("installer_get_installation_status")
    async def get_installation_status(
        self,
        installation_id: UUID
    ) -> Dict[str, Any]:
        """Get the status of a plugin installation."""
        try:
            with get_db() as db:
                installation = db.query(PluginInstallation).filter(
                    PluginInstallation.id == installation_id
                ).first()
                
                if not installation:
                    return {
                        "success": False,
                        "error": "Installation not found"
                    }
                
                # Get plugin information
                plugin_data = await self.registry.get_plugin(plugin_id=installation.plugin_id)
                
                status_data = {
                    "installation_id": str(installation.id),
                    "plugin_id": str(installation.plugin_id),
                    "plugin_name": plugin_data["name"] if plugin_data else "Unknown",
                    "version": installation.version,
                    "status": installation.status,
                    "environment": installation.environment,
                    "installed_at": installation.installed_at.isoformat() if installation.installed_at else None,
                    "updated_at": installation.updated_at.isoformat(),
                    "last_used": installation.last_used.isoformat() if installation.last_used else None,
                    "usage_count": installation.usage_count,
                    "health_status": installation.health_status,
                    "last_health_check": installation.last_health_check.isoformat() if installation.last_health_check else None,
                    "performance_metrics": installation.performance_metrics,
                    "configuration": installation.configuration
                }
                
                # Add active installation progress if applicable
                if str(installation_id) in self.active_installations:
                    active_info = self.active_installations[str(installation_id)]
                    status_data["progress"] = active_info.get("progress", 0)
                    status_data["current_step"] = active_info.get("current_step", "")
                
                return {
                    "success": True,
                    "installation": status_data
                }
                
        except Exception as e:
            logger.error(f"Error getting installation status: {e}")
            raise
    
    @traced("installer_list_installations")
    async def list_installations(
        self,
        user_id: str,
        organization_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0
    ) -> Dict[str, Any]:
        """List plugin installations for a user/organization."""
        try:
            with get_db() as db:
                query = db.query(PluginInstallation).filter(
                    PluginInstallation.user_id == user_id
                )
                
                if organization_id:
                    query = query.filter(PluginInstallation.organization_id == organization_id)
                
                if status:
                    query = query.filter(PluginInstallation.status == status)
                
                # Get total count
                total_count = query.count()
                
                # Apply ordering and pagination
                installations = query.order_by(
                    PluginInstallation.installed_at.desc()
                ).offset(offset).limit(limit).all()
                
                # Format results
                installation_list = []
                for installation in installations:
                    plugin_data = await self.registry.get_plugin(plugin_id=installation.plugin_id)
                    
                    installation_list.append({
                        "installation_id": str(installation.id),
                        "plugin_id": str(installation.plugin_id),
                        "plugin_name": plugin_data["name"] if plugin_data else "Unknown",
                        "version": installation.version,
                        "status": installation.status,
                        "environment": installation.environment,
                        "installed_at": installation.installed_at.isoformat() if installation.installed_at else None,
                        "last_used": installation.last_used.isoformat() if installation.last_used else None,
                        "health_status": installation.health_status
                    })
                
                return {
                    "installations": installation_list,
                    "total": total_count,
                    "limit": limit,
                    "offset": offset,
                    "has_more": offset + limit < total_count
                }
                
        except Exception as e:
            logger.error(f"Error listing installations: {e}")
            raise
    
    def get_stats(self) -> Dict[str, Any]:
        """Get installer statistics."""
        return {
            "service": "plugin_installer",
            "statistics": self.stats.copy(),
            "queue_size": self.installation_queue.qsize(),
            "active_installations": len(self.active_installations),
            "paths": {
                "install_path": str(self.base_install_path),
                "venv_path": str(self.venv_path),
                "config_path": str(self.config_path)
            },
            "status": "active"
        }
    
    # Private helper methods
    
    async def _create_directories(self):
        """Create necessary directories for plugin installation."""
        directories = [
            self.base_install_path,
            self.venv_path,
            self.config_path
        ]
        
        for directory in directories:
            directory.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Created directory: {directory}")
    
    async def _get_existing_installation(
        self,
        plugin_id: UUID,
        user_id: str,
        organization_id: Optional[str] = None
    ) -> Optional[PluginInstallation]:
        """Check if plugin is already installed."""
        with get_db() as db:
            query = db.query(PluginInstallation).filter(
                PluginInstallation.plugin_id == plugin_id,
                PluginInstallation.user_id == user_id,
                PluginInstallation.status.in_(["active", "installing", "updating"])
            )
            
            if organization_id:
                query = query.filter(PluginInstallation.organization_id == organization_id)
            
            return query.first()
    
    async def _validate_configuration(
        self,
        configuration: Dict[str, Any],
        config_schema: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Validate plugin configuration against schema."""
        # Simple validation - in reality, this would use JSON Schema validation
        errors = []
        
        try:
            # Basic validation logic
            required_fields = config_schema.get("required", [])
            for field in required_fields:
                if field not in configuration:
                    errors.append(f"Required field '{field}' is missing")
            
            # Type validation for properties
            properties = config_schema.get("properties", {})
            for field, value in configuration.items():
                if field in properties:
                    expected_type = properties[field].get("type")
                    if expected_type == "string" and not isinstance(value, str):
                        errors.append(f"Field '{field}' should be a string")
                    elif expected_type == "integer" and not isinstance(value, int):
                        errors.append(f"Field '{field}' should be an integer")
                    elif expected_type == "boolean" and not isinstance(value, bool):
                        errors.append(f"Field '{field}' should be a boolean")
            
        except Exception as e:
            errors.append(f"Configuration validation error: {str(e)}")
        
        return {
            "valid": len(errors) == 0,
            "errors": errors
        }
    
    async def _apply_plugin_configuration(
        self,
        installation_id: UUID,
        configuration: Dict[str, Any]
    ):
        """Apply configuration to a plugin installation."""
        try:
            # Write configuration file
            config_file = self.config_path / f"{installation_id}.json"
            with open(config_file, 'w') as f:
                json.dump(configuration, f, indent=2)
            
            # Restart plugin if it's running
            # This would interact with the plugin executor
            
            logger.debug(f"Configuration applied for installation: {installation_id}")
            
        except Exception as e:
            logger.error(f"Error applying configuration: {e}")
            raise
    
    # Installation worker
    
    async def _installation_worker(self):
        """Background worker to process installation queue."""
        while True:
            try:
                # Get next installation task
                task = await self.installation_queue.get()
                
                if task["action"] == "install":
                    await self._perform_installation(task)
                elif task["action"] == "uninstall":
                    await self._perform_uninstallation(task)
                elif task["action"] == "update":
                    await self._perform_update(task)
                
                self.installation_queue.task_done()
                
            except Exception as e:
                logger.error(f"Error in installation worker: {e}")
    
    async def _perform_installation(self, task: Dict[str, Any]):
        """Perform actual plugin installation."""
        installation_id = task["installation_id"]
        plugin_data = task["plugin_data"]
        
        try:
            # Track active installation
            self.active_installations[str(installation_id)] = {
                "progress": 0,
                "current_step": "Starting installation",
                "cancelled": False
            }
            
            logger.info(f"Starting installation: {plugin_data['name']}")
            
            # Step 1: Create virtual environment
            await self._update_installation_progress(installation_id, 10, "Creating virtual environment")
            venv_dir = await self._create_virtual_environment(installation_id)
            
            # Step 2: Download and validate package
            await self._update_installation_progress(installation_id, 30, "Downloading package")
            package_path = await self._download_plugin_package(plugin_data)
            
            # Step 3: Install dependencies
            await self._update_installation_progress(installation_id, 50, "Installing dependencies")
            await self._install_dependencies(venv_dir, plugin_data.get("dependencies", {}))
            
            # Step 4: Install plugin
            await self._update_installation_progress(installation_id, 70, "Installing plugin")
            await self._install_plugin_package(venv_dir, package_path)
            
            # Step 5: Configure plugin
            await self._update_installation_progress(installation_id, 85, "Configuring plugin")
            await self._configure_installed_plugin(installation_id, task["configuration"])
            
            # Step 6: Validate installation
            await self._update_installation_progress(installation_id, 95, "Validating installation")
            validation_result = await self._validate_installation(installation_id, venv_dir)
            
            if not validation_result["valid"]:
                raise Exception(f"Installation validation failed: {validation_result['errors']}")
            
            # Complete installation
            await self._update_installation_progress(installation_id, 100, "Installation complete")
            await self._complete_installation(installation_id, "active")
            
            self.stats["installations_completed"] += 1
            metrics.installer_installations_completed.inc()
            
            logger.info(f"Installation completed successfully: {plugin_data['name']}")
            
        except Exception as e:
            logger.error(f"Installation failed: {e}")
            await self._complete_installation(installation_id, "failed", str(e))
            self.stats["installations_failed"] += 1
            metrics.installer_installations_failed.inc()
        
        finally:
            # Clean up
            self.active_installations.pop(str(installation_id), None)
    
    async def _perform_uninstallation(self, task: Dict[str, Any]):
        """Perform actual plugin uninstallation."""
        installation_id = task["installation_id"]
        
        try:
            logger.info(f"Starting uninstallation: {installation_id}")
            
            # Stop plugin if running
            await self._stop_plugin(installation_id)
            
            # Remove virtual environment
            venv_dir = self.venv_path / str(installation_id)
            if venv_dir.exists():
                shutil.rmtree(venv_dir)
            
            # Remove configuration
            config_file = self.config_path / f"{installation_id}.json"
            if config_file.exists():
                config_file.unlink()
            
            # Clean up data if requested
            if task.get("cleanup_data", False):
                data_dir = self.base_install_path / str(installation_id)
                if data_dir.exists():
                    shutil.rmtree(data_dir)
            
            # Update database
            with get_db() as db:
                installation = db.query(PluginInstallation).filter(
                    PluginInstallation.id == installation_id
                ).first()
                
                if installation:
                    installation.status = "uninstalled"
                    installation.uninstalled_at = datetime.utcnow()
                    db.commit()
            
            self.stats["uninstallations_completed"] += 1
            metrics.installer_uninstallations_completed.inc()
            
            logger.info(f"Uninstallation completed: {installation_id}")
            
        except Exception as e:
            logger.error(f"Uninstallation failed: {e}")
            
            # Update status to failed
            with get_db() as db:
                installation = db.query(PluginInstallation).filter(
                    PluginInstallation.id == installation_id
                ).first()
                
                if installation:
                    installation.status = "uninstall_failed"
                    db.commit()
    
    async def _perform_update(self, task: Dict[str, Any]):
        """Perform plugin update."""
        installation_id = task["installation_id"]
        
        try:
            logger.info(f"Starting update: {installation_id} to {task['target_version']}")
            
            # This would perform a similar process to installation
            # but preserve user data and configuration
            
            # Update database
            with get_db() as db:
                installation = db.query(PluginInstallation).filter(
                    PluginInstallation.id == installation_id
                ).first()
                
                if installation:
                    installation.version = task["target_version"]
                    installation.status = "active"
                    installation.updated_at = datetime.utcnow()
                    db.commit()
            
            self.stats["updates_completed"] += 1
            metrics.installer_updates_completed.inc()
            
            logger.info(f"Update completed: {installation_id}")
            
        except Exception as e:
            logger.error(f"Update failed: {e}")
            
            # Revert status
            with get_db() as db:
                installation = db.query(PluginInstallation).filter(
                    PluginInstallation.id == installation_id
                ).first()
                
                if installation:
                    installation.status = "update_failed"
                    db.commit()
    
    async def _create_virtual_environment(self, installation_id: UUID) -> Path:
        """Create a virtual environment for the plugin."""
        venv_dir = self.venv_path / str(installation_id)
        
        if venv_dir.exists():
            shutil.rmtree(venv_dir)
        
        # Create virtual environment
        venv.create(venv_dir, with_pip=True)
        
        return venv_dir
    
    async def _download_plugin_package(self, plugin_data: Dict[str, Any]) -> Path:
        """Download plugin package."""
        # In a real implementation, this would download from the package URL
        # For now, we'll simulate this
        
        temp_dir = Path(tempfile.mkdtemp())
        package_path = temp_dir / f"{plugin_data['name']}-{plugin_data['version']}.tar.gz"
        
        # Simulate package download
        package_path.touch()
        
        return package_path
    
    async def _install_dependencies(self, venv_dir: Path, dependencies: Dict[str, Any]):
        """Install plugin dependencies."""
        pip_executable = venv_dir / "bin" / "pip"
        
        for dep_name, dep_version in dependencies.items():
            cmd = [str(pip_executable), "install", f"{dep_name}=={dep_version}"]
            
            # Run in background (simulated)
            await asyncio.sleep(0.1)  # Simulate installation time
    
    async def _install_plugin_package(self, venv_dir: Path, package_path: Path):
        """Install the plugin package."""
        pip_executable = venv_dir / "bin" / "pip"
        
        cmd = [str(pip_executable), "install", str(package_path)]
        
        # Run installation (simulated)
        await asyncio.sleep(0.1)
    
    async def _configure_installed_plugin(
        self,
        installation_id: UUID,
        configuration: Dict[str, Any]
    ):
        """Configure the installed plugin."""
        if configuration:
            await self._apply_plugin_configuration(installation_id, configuration)
    
    async def _validate_installation(
        self,
        installation_id: UUID,
        venv_dir: Path
    ) -> Dict[str, Any]:
        """Validate that the plugin was installed correctly."""
        try:
            # Check virtual environment
            if not venv_dir.exists():
                return {"valid": False, "errors": ["Virtual environment not found"]}
            
            # Check plugin executable/module
            # This would vary based on plugin type
            
            return {"valid": True, "errors": []}
            
        except Exception as e:
            return {"valid": False, "errors": [str(e)]}
    
    async def _stop_plugin(self, installation_id: UUID):
        """Stop a running plugin."""
        # This would interact with the plugin executor to stop the plugin
        pass
    
    async def _update_installation_progress(
        self,
        installation_id: UUID,
        progress: int,
        current_step: str
    ):
        """Update installation progress."""
        if str(installation_id) in self.active_installations:
            self.active_installations[str(installation_id)].update({
                "progress": progress,
                "current_step": current_step
            })
    
    async def _complete_installation(
        self,
        installation_id: UUID,
        status: str,
        error_message: Optional[str] = None
    ):
        """Complete the installation process."""
        with get_db() as db:
            installation = db.query(PluginInstallation).filter(
                PluginInstallation.id == installation_id
            ).first()
            
            if installation:
                installation.status = status
                installation.updated_at = datetime.utcnow()
                
                if status == "active":
                    installation.installed_at = datetime.utcnow()
                
                db.commit()
    
    # Health monitoring
    
    async def _health_monitor_task(self):
        """Background task to monitor plugin health."""
        while True:
            try:
                await asyncio.sleep(300)  # Run every 5 minutes
                
                # Check health of active installations
                with get_db() as db:
                    active_installations = db.query(PluginInstallation).filter(
                        PluginInstallation.status == "active"
                    ).all()
                    
                    for installation in active_installations:
                        await self._check_plugin_health(installation)
                
                logger.debug("Plugin health monitoring completed")
                
            except Exception as e:
                logger.error(f"Error in health monitor task: {e}")
    
    async def _check_plugin_health(self, installation: PluginInstallation):
        """Check the health of a plugin installation."""
        try:
            # Perform health checks
            health_status = "healthy"  # This would be determined by actual checks
            
            # Update database
            with get_db() as db:
                installation.health_status = health_status
                installation.last_health_check = datetime.utcnow()
                db.commit()
            
            self.stats["health_checks_performed"] += 1
            
        except Exception as e:
            logger.error(f"Error checking plugin health: {e}")
            
            # Mark as unhealthy
            with get_db() as db:
                installation.health_status = "unhealthy"
                installation.last_health_check = datetime.utcnow()
                db.commit()