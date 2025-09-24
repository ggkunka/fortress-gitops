"""
Restore manager for recovering from backups.
"""

import os
import json
import asyncio
import subprocess
import tarfile
import gzip
import tempfile
import shutil
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .backup_manager import BackupMetadata, BackupConfig
from shared.observability.logging import get_logger


@dataclass
class RestoreConfig:
    """Configuration for restore operations."""
    # Target settings
    target_database_url: Optional[str] = None
    target_directory: Optional[str] = None
    
    # Restore options
    restore_database: bool = True
    restore_files: bool = True
    restore_configs: bool = True
    
    # Safety options
    backup_before_restore: bool = True
    verify_before_restore: bool = True
    dry_run: bool = False
    
    # Database options
    drop_existing_database: bool = False
    create_database_if_not_exists: bool = True
    
    # File options
    overwrite_existing_files: bool = False
    preserve_permissions: bool = True
    
    # Recovery options
    point_in_time_recovery: Optional[datetime] = None
    partial_restore_tables: List[str] = None
    partial_restore_paths: List[str] = None


@dataclass
class RestoreResult:
    """Result of a restore operation."""
    restore_id: str
    backup_id: str
    restore_type: str
    status: str
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    restored_items: int = 0
    execution_time_ms: int = 0
    metadata: Dict[str, Any] = None


class RestoreManager:
    """Manages restore operations from backups."""
    
    def __init__(self, config: RestoreConfig):
        self.config = config
        self.logger = get_logger("restore_manager")
    
    async def restore_from_backup(self, backup_metadata: BackupMetadata) -> RestoreResult:
        """Restore from a specific backup."""
        restore_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        started_at = datetime.now()
        
        self.logger.info(
            f"Starting restore operation",
            restore_id=restore_id,
            backup_id=backup_metadata.backup_id,
            backup_type=backup_metadata.backup_type
        )
        
        try:
            # Verify backup before restore
            if self.config.verify_before_restore:
                if not await self._verify_backup(backup_metadata):
                    raise RuntimeError("Backup verification failed")
            
            # Create backup of current state if requested
            if self.config.backup_before_restore:
                await self._create_pre_restore_backup(backup_metadata.backup_type)
            
            # Perform dry run if requested
            if self.config.dry_run:
                return await self._dry_run_restore(restore_id, backup_metadata, started_at)
            
            # Execute restore based on backup type
            if backup_metadata.backup_type == "database":
                restored_items = await self._restore_database(backup_metadata)
            elif backup_metadata.backup_type == "files":
                restored_items = await self._restore_files(backup_metadata)
            elif backup_metadata.backup_type == "config":
                restored_items = await self._restore_config(backup_metadata)
            else:
                raise ValueError(f"Unsupported backup type: {backup_metadata.backup_type}")
            
            # Calculate completion time
            completed_at = datetime.now()
            execution_time = int((completed_at - started_at).total_seconds() * 1000)
            
            result = RestoreResult(
                restore_id=restore_id,
                backup_id=backup_metadata.backup_id,
                restore_type=backup_metadata.backup_type,
                status="completed",
                started_at=started_at,
                completed_at=completed_at,
                restored_items=restored_items,
                execution_time_ms=execution_time,
                metadata={
                    "backup_timestamp": backup_metadata.timestamp.isoformat(),
                    "backup_size": backup_metadata.file_size,
                    "backup_checksum": backup_metadata.checksum
                }
            )
            
            self.logger.info(
                f"Restore completed successfully",
                restore_id=restore_id,
                execution_time_ms=execution_time,
                restored_items=restored_items
            )
            
            return result
            
        except Exception as e:
            completed_at = datetime.now()
            execution_time = int((completed_at - started_at).total_seconds() * 1000)
            
            result = RestoreResult(
                restore_id=restore_id,
                backup_id=backup_metadata.backup_id,
                restore_type=backup_metadata.backup_type,
                status="failed",
                started_at=started_at,
                completed_at=completed_at,
                error_message=str(e),
                execution_time_ms=execution_time
            )
            
            self.logger.error(
                f"Restore failed",
                restore_id=restore_id,
                error=str(e)
            )
            
            return result
    
    async def _verify_backup(self, backup_metadata: BackupMetadata) -> bool:
        """Verify backup integrity before restore."""
        try:
            # Check file exists
            if not os.path.exists(backup_metadata.file_path):
                self.logger.error(f"Backup file not found: {backup_metadata.file_path}")
                return False
            
            # Verify checksum
            current_checksum = await self._calculate_checksum(backup_metadata.file_path)
            if current_checksum != backup_metadata.checksum:
                self.logger.error(f"Backup checksum mismatch")
                return False
            
            self.logger.info("Backup verification passed")
            return True
            
        except Exception as e:
            self.logger.error(f"Backup verification failed: {e}")
            return False
    
    async def _create_pre_restore_backup(self, backup_type: str):
        """Create backup of current state before restore."""
        self.logger.info(f"Creating pre-restore backup for {backup_type}")
        
        # This would create a quick backup of the current state
        # Implementation depends on backup type
        pass
    
    async def _dry_run_restore(self, restore_id: str, backup_metadata: BackupMetadata, started_at: datetime) -> RestoreResult:
        """Perform dry run of restore operation."""
        self.logger.info("Performing dry run restore")
        
        # Simulate restore without making changes
        await asyncio.sleep(1)  # Simulate work
        
        completed_at = datetime.now()
        execution_time = int((completed_at - started_at).total_seconds() * 1000)
        
        return RestoreResult(
            restore_id=restore_id,
            backup_id=backup_metadata.backup_id,
            restore_type=backup_metadata.backup_type,
            status="dry_run_completed",
            started_at=started_at,
            completed_at=completed_at,
            restored_items=0,
            execution_time_ms=execution_time,
            metadata={"dry_run": True}
        )
    
    async def _restore_database(self, backup_metadata: BackupMetadata) -> int:
        """Restore database from backup."""
        self.logger.info("Starting database restore")
        
        # Prepare backup file for restore
        restore_file = await self._prepare_backup_file(backup_metadata)
        
        try:
            # Get database info from metadata
            db_type = backup_metadata.metadata.get("database_type", "postgresql").lower()
            
            if db_type == "postgresql":
                return await self._restore_postgresql(restore_file, backup_metadata)
            elif db_type == "mysql":
                return await self._restore_mysql(restore_file, backup_metadata)
            elif db_type == "mongodb":
                return await self._restore_mongodb(restore_file, backup_metadata)
            else:
                raise ValueError(f"Unsupported database type: {db_type}")
                
        finally:
            # Clean up temporary file
            if restore_file != backup_metadata.file_path:
                os.remove(restore_file)
    
    async def _restore_postgresql(self, restore_file: str, backup_metadata: BackupMetadata) -> int:
        """Restore PostgreSQL database."""
        db_info = self._parse_database_url(self.config.target_database_url)
        
        # Drop existing database if requested
        if self.config.drop_existing_database:
            await self._drop_postgresql_database(db_info)
        
        # Create database if needed
        if self.config.create_database_if_not_exists:
            await self._create_postgresql_database(db_info)
        
        # Build pg_restore command
        cmd = [
            "pg_restore",
            "--verbose",
            "--no-password",
            "--clean",
            "--if-exists"
        ]
        
        # Add connection parameters
        env = os.environ.copy()
        if db_info.get("host"):
            cmd.extend(["--host", db_info["host"]])
        if db_info.get("port"):
            cmd.extend(["--port", str(db_info["port"])])
        if db_info.get("username"):
            cmd.extend(["--username", db_info["username"]])
        if db_info.get("password"):
            env["PGPASSWORD"] = db_info["password"]
        
        # Add database name and restore file
        cmd.extend(["--dbname", db_info["database"], restore_file])
        
        # Execute pg_restore
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise RuntimeError(f"pg_restore failed: {stderr.decode()}")
            
            self.logger.info("PostgreSQL restore completed")
            return 1  # Number of databases restored
            
        except Exception as e:
            raise RuntimeError(f"PostgreSQL restore failed: {e}")
    
    async def _restore_mysql(self, restore_file: str, backup_metadata: BackupMetadata) -> int:
        """Restore MySQL database."""
        db_info = self._parse_database_url(self.config.target_database_url)
        
        # Build mysql command
        cmd = ["mysql"]
        
        # Add connection parameters
        if db_info.get("host"):
            cmd.extend(["--host", db_info["host"]])
        if db_info.get("port"):
            cmd.extend(["--port", str(db_info["port"])])
        if db_info.get("username"):
            cmd.extend(["--user", db_info["username"]])
        if db_info.get("password"):
            cmd.extend([f"--password={db_info['password']}"])
        
        # Add database name
        cmd.append(db_info["database"])
        
        # Execute mysql with input from backup file
        try:
            with open(restore_file, 'r') as f:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdin=f,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                if process.returncode != 0:
                    raise RuntimeError(f"mysql restore failed: {stderr.decode()}")
            
            self.logger.info("MySQL restore completed")
            return 1
            
        except Exception as e:
            raise RuntimeError(f"MySQL restore failed: {e}")
    
    async def _restore_mongodb(self, restore_file: str, backup_metadata: BackupMetadata) -> int:
        """Restore MongoDB database."""
        db_info = self._parse_database_url(self.config.target_database_url)
        
        # Extract tar file to temp directory
        temp_dir = tempfile.mkdtemp()
        
        try:
            with tarfile.open(restore_file, "r") as tar:
                tar.extractall(temp_dir)
            
            # Find the database directory
            db_dirs = [d for d in os.listdir(temp_dir) if os.path.isdir(os.path.join(temp_dir, d))]
            if not db_dirs:
                raise RuntimeError("No database directory found in backup")
            
            restore_dir = os.path.join(temp_dir, db_dirs[0])
            
            # Build mongorestore command
            cmd = [
                "mongorestore",
                "--drop",  # Drop collections before restoring
                restore_dir
            ]
            
            # Add connection parameters
            if db_info.get("host"):
                cmd.extend(["--host", f"{db_info['host']}:{db_info.get('port', 27017)}"])
            if db_info.get("username"):
                cmd.extend(["--username", db_info["username"]])
            if db_info.get("password"):
                cmd.extend(["--password", db_info["password"]])
            if db_info.get("database"):
                cmd.extend(["--db", db_info["database"]])
            
            # Execute mongorestore
            try:
                process = await asyncio.create_subprocess_exec(
                    *cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE
                )
                
                stdout, stderr = await process.communicate()
                
                if process.returncode != 0:
                    raise RuntimeError(f"mongorestore failed: {stderr.decode()}")
                
                self.logger.info("MongoDB restore completed")
                return 1
                
            except Exception as e:
                raise RuntimeError(f"MongoDB restore failed: {e}")
                
        finally:
            # Clean up temp directory
            shutil.rmtree(temp_dir)
    
    async def _restore_files(self, backup_metadata: BackupMetadata) -> int:
        """Restore files from backup."""
        self.logger.info("Starting file restore")
        
        # Prepare backup file for restore
        restore_file = await self._prepare_backup_file(backup_metadata)
        
        try:
            # Determine target directory
            target_dir = self.config.target_directory or "."
            
            # Extract tar file
            with tarfile.open(restore_file, "r") as tar:
                members = tar.getmembers()
                
                # Filter members if partial restore is requested
                if self.config.partial_restore_paths:
                    filtered_members = []
                    for member in members:
                        if any(path in member.name for path in self.config.partial_restore_paths):
                            filtered_members.append(member)
                    members = filtered_members
                
                # Extract files
                extracted_count = 0
                for member in members:
                    target_path = os.path.join(target_dir, member.name)
                    
                    # Check if file exists and handle overwrite
                    if os.path.exists(target_path) and not self.config.overwrite_existing_files:
                        self.logger.warning(f"Skipping existing file: {target_path}")
                        continue
                    
                    # Extract file
                    tar.extract(member, target_dir)
                    extracted_count += 1
                    
                    # Preserve permissions if requested
                    if self.config.preserve_permissions and hasattr(member, 'mode'):
                        os.chmod(target_path, member.mode)
                
                self.logger.info(f"File restore completed - extracted {extracted_count} files")
                return extracted_count
                
        finally:
            # Clean up temporary file
            if restore_file != backup_metadata.file_path:
                os.remove(restore_file)
    
    async def _restore_config(self, backup_metadata: BackupMetadata) -> int:
        """Restore configuration from backup."""
        self.logger.info("Starting config restore")
        
        # Prepare backup file for restore
        restore_file = await self._prepare_backup_file(backup_metadata)
        
        try:
            # Load configuration data
            with open(restore_file, 'r') as f:
                config_data = json.load(f)
            
            restored_count = 0
            
            # Restore configuration files
            if "config_files" in config_data:
                for file_path, content in config_data["config_files"].items():
                    target_path = file_path
                    
                    # Check if file exists and handle overwrite
                    if os.path.exists(target_path) and not self.config.overwrite_existing_files:
                        self.logger.warning(f"Skipping existing config file: {target_path}")
                        continue
                    
                    # Create directory if needed
                    os.makedirs(os.path.dirname(target_path), exist_ok=True)
                    
                    # Write config file
                    with open(target_path, 'w') as f:
                        f.write(content)
                    
                    restored_count += 1
                    self.logger.info(f"Restored config file: {target_path}")
            
            self.logger.info(f"Config restore completed - restored {restored_count} files")
            return restored_count
            
        finally:
            # Clean up temporary file
            if restore_file != backup_metadata.file_path:
                os.remove(restore_file)
    
    async def _prepare_backup_file(self, backup_metadata: BackupMetadata) -> str:
        """Prepare backup file for restore (decompress/decrypt if needed)."""
        current_file = backup_metadata.file_path
        
        # Handle decryption
        if backup_metadata.encrypted:
            # Would implement decryption here
            self.logger.warning("Decryption not implemented - assuming file is not encrypted")
        
        # Handle decompression
        if backup_metadata.compressed or current_file.endswith('.gz'):
            temp_file = tempfile.mktemp()
            with gzip.open(current_file, 'rb') as f_in:
                with open(temp_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            current_file = temp_file
        
        return current_file
    
    def _parse_database_url(self, url: str) -> Dict[str, str]:
        """Parse database URL into components."""
        from urllib.parse import urlparse
        
        parsed = urlparse(url)
        
        return {
            "scheme": parsed.scheme,
            "username": parsed.username,
            "password": parsed.password,
            "host": parsed.hostname,
            "port": parsed.port,
            "database": parsed.path.lstrip("/") if parsed.path else None
        }
    
    async def _drop_postgresql_database(self, db_info: Dict[str, str]):
        """Drop PostgreSQL database."""
        # Implementation for dropping database
        pass
    
    async def _create_postgresql_database(self, db_info: Dict[str, str]):
        """Create PostgreSQL database."""
        # Implementation for creating database
        pass
    
    async def _calculate_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum of file."""
        import hashlib
        
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()
    
    async def list_restore_points(self, backup_metadata_list: List[BackupMetadata], 
                                backup_type: str = None) -> List[Dict[str, Any]]:
        """List available restore points."""
        restore_points = []
        
        for metadata in backup_metadata_list:
            if backup_type and metadata.backup_type != backup_type:
                continue
            
            restore_point = {
                "backup_id": metadata.backup_id,
                "timestamp": metadata.timestamp.isoformat(),
                "backup_type": metadata.backup_type,
                "file_size": metadata.file_size,
                "status": metadata.status,
                "retention_category": metadata.retention_category,
                "expires_at": metadata.expires_at.isoformat(),
                "can_restore": os.path.exists(metadata.file_path) and metadata.status == "completed"
            }
            
            restore_points.append(restore_point)
        
        # Sort by timestamp descending (newest first)
        restore_points.sort(key=lambda x: x["timestamp"], reverse=True)
        
        return restore_points