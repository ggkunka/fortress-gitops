"""
Backup strategies for different types of data.
"""

import os
import subprocess
import tarfile
import gzip
import hashlib
import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from pathlib import Path
import tempfile
import shutil

from .backup_manager import BackupStrategy, BackupConfig, BackupMetadata
from shared.observability.logging import get_logger


class DatabaseBackupStrategy(BackupStrategy):
    """Strategy for backing up databases."""
    
    def __init__(self):
        self.logger = get_logger("backup.database")
    
    def get_backup_type(self) -> str:
        return "database"
    
    async def create_backup(self, config: BackupConfig, backup_id: str) -> BackupMetadata:
        """Create database backup."""
        self.logger.info(f"Starting database backup: {backup_id}")
        
        # Parse database URL
        db_info = self._parse_database_url(config.database_url)
        
        # Create backup based on database type
        if config.database_type.lower() == "postgresql":
            backup_file = await self._backup_postgresql(config, backup_id, db_info)
        elif config.database_type.lower() == "mysql":
            backup_file = await self._backup_mysql(config, backup_id, db_info)
        elif config.database_type.lower() == "mongodb":
            backup_file = await self._backup_mongodb(config, backup_id, db_info)
        else:
            raise ValueError(f"Unsupported database type: {config.database_type}")
        
        # Compress if enabled
        if config.enable_compression:
            backup_file = await self._compress_file(backup_file, config.compression_level)
        
        # Encrypt if enabled
        if config.enable_encryption and config.encryption_key:
            backup_file = await self._encrypt_file(backup_file, config.encryption_key)
        
        # Calculate file info
        file_size = os.path.getsize(backup_file)
        checksum = await self._calculate_checksum(backup_file)
        
        # Determine retention
        timestamp = datetime.now()
        retention_category, expires_at = self._calculate_retention(timestamp, config)
        
        metadata = BackupMetadata(
            backup_id=backup_id,
            timestamp=timestamp,
            backup_type=self.get_backup_type(),
            status="created",
            file_path=backup_file,
            file_size=file_size,
            checksum=checksum,
            encrypted=config.enable_encryption,
            compressed=config.enable_compression,
            retention_category=retention_category,
            expires_at=expires_at,
            metadata={
                "database_type": config.database_type,
                "database_name": db_info.get("database"),
                "host": db_info.get("host"),
                "port": db_info.get("port")
            }
        )
        
        self.logger.info(
            f"Database backup created",
            backup_id=backup_id,
            file_size=file_size,
            checksum=checksum
        )
        
        return metadata
    
    async def _backup_postgresql(self, config: BackupConfig, backup_id: str, db_info: Dict[str, str]) -> str:
        """Create PostgreSQL backup using pg_dump."""
        backup_file = os.path.join(config.backup_dir, f"{backup_id}_postgresql.sql")
        
        # Build pg_dump command
        cmd = [
            "pg_dump",
            "--verbose",
            "--no-password",
            "--format=custom",
            "--compress=0",  # We'll compress ourselves if needed
            "--file", backup_file
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
        
        # Add database name
        cmd.append(db_info["database"])
        
        # Execute pg_dump
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise RuntimeError(f"pg_dump failed: {stderr.decode()}")
            
            self.logger.info("PostgreSQL backup completed")
            return backup_file
            
        except Exception as e:
            if os.path.exists(backup_file):
                os.remove(backup_file)
            raise RuntimeError(f"PostgreSQL backup failed: {e}")
    
    async def _backup_mysql(self, config: BackupConfig, backup_id: str, db_info: Dict[str, str]) -> str:
        """Create MySQL backup using mysqldump."""
        backup_file = os.path.join(config.backup_dir, f"{backup_id}_mysql.sql")
        
        # Build mysqldump command
        cmd = [
            "mysqldump",
            "--single-transaction",
            "--routines",
            "--triggers",
            "--events",
            "--result-file", backup_file
        ]
        
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
        
        # Execute mysqldump
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise RuntimeError(f"mysqldump failed: {stderr.decode()}")
            
            self.logger.info("MySQL backup completed")
            return backup_file
            
        except Exception as e:
            if os.path.exists(backup_file):
                os.remove(backup_file)
            raise RuntimeError(f"MySQL backup failed: {e}")
    
    async def _backup_mongodb(self, config: BackupConfig, backup_id: str, db_info: Dict[str, str]) -> str:
        """Create MongoDB backup using mongodump."""
        backup_dir = os.path.join(config.backup_dir, f"{backup_id}_mongodb")
        backup_file = f"{backup_dir}.tar"
        
        # Build mongodump command
        cmd = [
            "mongodump",
            "--out", backup_dir
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
        
        # Execute mongodump
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                raise RuntimeError(f"mongodump failed: {stderr.decode()}")
            
            # Create tar archive
            with tarfile.open(backup_file, "w") as tar:
                tar.add(backup_dir, arcname=os.path.basename(backup_dir))
            
            # Remove temp directory
            shutil.rmtree(backup_dir)
            
            self.logger.info("MongoDB backup completed")
            return backup_file
            
        except Exception as e:
            if os.path.exists(backup_dir):
                shutil.rmtree(backup_dir)
            if os.path.exists(backup_file):
                os.remove(backup_file)
            raise RuntimeError(f"MongoDB backup failed: {e}")
    
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
    
    async def verify_backup(self, metadata: BackupMetadata) -> bool:
        """Verify database backup integrity."""
        try:
            # Check file exists
            if not os.path.exists(metadata.file_path):
                self.logger.error(f"Backup file not found: {metadata.file_path}")
                return False
            
            # Verify checksum
            current_checksum = await self._calculate_checksum(metadata.file_path)
            if current_checksum != metadata.checksum:
                self.logger.error(f"Checksum mismatch for {metadata.file_path}")
                return False
            
            # Additional database-specific verification
            db_type = metadata.metadata.get("database_type", "").lower()
            
            if db_type == "postgresql":
                return await self._verify_postgresql_backup(metadata.file_path)
            elif db_type == "mysql":
                return await self._verify_mysql_backup(metadata.file_path)
            elif db_type == "mongodb":
                return await self._verify_mongodb_backup(metadata.file_path)
            
            return True
            
        except Exception as e:
            self.logger.error(f"Backup verification failed: {e}")
            return False
    
    async def _verify_postgresql_backup(self, file_path: str) -> bool:
        """Verify PostgreSQL backup using pg_restore --list."""
        try:
            # Decompress/decrypt if needed
            temp_file = await self._prepare_file_for_verification(file_path)
            
            cmd = ["pg_restore", "--list", temp_file]
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate()
            
            # Clean up temp file
            if temp_file != file_path:
                os.remove(temp_file)
            
            return process.returncode == 0
            
        except Exception as e:
            self.logger.error(f"PostgreSQL backup verification failed: {e}")
            return False
    
    async def _verify_mysql_backup(self, file_path: str) -> bool:
        """Verify MySQL backup by checking SQL syntax."""
        try:
            # Decompress/decrypt if needed
            temp_file = await self._prepare_file_for_verification(file_path)
            
            # Check if file contains valid SQL
            with open(temp_file, 'r') as f:
                content = f.read(1000)  # Read first 1KB
                
                # Look for MySQL dump markers
                if "-- MySQL dump" not in content and "CREATE TABLE" not in content:
                    return False
            
            # Clean up temp file
            if temp_file != file_path:
                os.remove(temp_file)
            
            return True
            
        except Exception as e:
            self.logger.error(f"MySQL backup verification failed: {e}")
            return False
    
    async def _verify_mongodb_backup(self, file_path: str) -> bool:
        """Verify MongoDB backup by checking tar contents."""
        try:
            # Decompress/decrypt if needed
            temp_file = await self._prepare_file_for_verification(file_path)
            
            # Check tar file contents
            with tarfile.open(temp_file, "r") as tar:
                members = tar.getnames()
                
                # Should contain BSON files
                bson_files = [m for m in members if m.endswith('.bson')]
                if not bson_files:
                    return False
            
            # Clean up temp file
            if temp_file != file_path:
                os.remove(temp_file)
            
            return True
            
        except Exception as e:
            self.logger.error(f"MongoDB backup verification failed: {e}")
            return False
    
    async def _prepare_file_for_verification(self, file_path: str) -> str:
        """Prepare backup file for verification (decompress/decrypt if needed)."""
        current_file = file_path
        
        # Handle decryption
        if file_path.endswith('.enc'):
            # Would implement decryption here
            pass
        
        # Handle decompression
        if file_path.endswith('.gz'):
            temp_file = tempfile.mktemp()
            with gzip.open(current_file, 'rb') as f_in:
                with open(temp_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            current_file = temp_file
        
        return current_file
    
    async def _compress_file(self, file_path: str, compression_level: int) -> str:
        """Compress backup file."""
        compressed_file = f"{file_path}.gz"
        
        with open(file_path, 'rb') as f_in:
            with gzip.open(compressed_file, 'wb', compresslevel=compression_level) as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        # Remove original file
        os.remove(file_path)
        
        return compressed_file
    
    async def _encrypt_file(self, file_path: str, encryption_key: str) -> str:
        """Encrypt backup file."""
        encrypted_file = f"{file_path}.enc"
        
        # This is a placeholder - would implement actual encryption
        # using libraries like cryptography
        self.logger.warning("File encryption not implemented - file not encrypted")
        return file_path
    
    async def _calculate_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum of file."""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()
    
    def _calculate_retention(self, timestamp: datetime, config: BackupConfig) -> tuple[str, datetime]:
        """Calculate retention category and expiration date."""
        now = datetime.now()
        age = now - timestamp
        
        if age < timedelta(days=1):
            expires_at = timestamp + timedelta(days=config.retain_daily)
            return "daily", expires_at
        elif age < timedelta(weeks=1):
            expires_at = timestamp + timedelta(weeks=config.retain_weekly)
            return "weekly", expires_at
        elif age < timedelta(days=30):
            expires_at = timestamp + timedelta(days=30 * config.retain_monthly)
            return "monthly", expires_at
        else:
            expires_at = timestamp + timedelta(days=365 * config.retain_yearly)
            return "yearly", expires_at


class FileBackupStrategy(BackupStrategy):
    """Strategy for backing up files and directories."""
    
    def __init__(self):
        self.logger = get_logger("backup.files")
    
    def get_backup_type(self) -> str:
        return "files"
    
    async def create_backup(self, config: BackupConfig, backup_id: str) -> BackupMetadata:
        """Create file backup."""
        self.logger.info(f"Starting file backup: {backup_id}")
        
        backup_file = os.path.join(config.backup_dir, f"{backup_id}_files.tar")
        
        # Create tar archive
        with tarfile.open(backup_file, "w") as tar:
            for path in config.file_paths:
                if os.path.exists(path):
                    self._add_to_archive(tar, path, config.exclude_patterns)
                else:
                    self.logger.warning(f"Path not found: {path}")
        
        # Compress if enabled
        if config.enable_compression:
            backup_file = await self._compress_file(backup_file, config.compression_level)
        
        # Encrypt if enabled
        if config.enable_encryption and config.encryption_key:
            backup_file = await self._encrypt_file(backup_file, config.encryption_key)
        
        # Calculate file info
        file_size = os.path.getsize(backup_file)
        checksum = await self._calculate_checksum(backup_file)
        
        # Determine retention
        timestamp = datetime.now()
        retention_category, expires_at = self._calculate_retention(timestamp, config)
        
        metadata = BackupMetadata(
            backup_id=backup_id,
            timestamp=timestamp,
            backup_type=self.get_backup_type(),
            status="created",
            file_path=backup_file,
            file_size=file_size,
            checksum=checksum,
            encrypted=config.enable_encryption,
            compressed=config.enable_compression,
            retention_category=retention_category,
            expires_at=expires_at,
            metadata={
                "paths_backed_up": config.file_paths,
                "exclude_patterns": config.exclude_patterns
            }
        )
        
        self.logger.info(
            f"File backup created",
            backup_id=backup_id,
            file_size=file_size,
            paths_count=len(config.file_paths)
        )
        
        return metadata
    
    def _add_to_archive(self, tar: tarfile.TarFile, path: str, exclude_patterns: List[str]):
        """Add path to tar archive with exclusion patterns."""
        import fnmatch
        
        def exclude_filter(tarinfo):
            # Check against exclude patterns
            for pattern in exclude_patterns:
                if fnmatch.fnmatch(tarinfo.name, pattern):
                    return None
                if fnmatch.fnmatch(os.path.basename(tarinfo.name), pattern):
                    return None
            return tarinfo
        
        tar.add(path, filter=exclude_filter)
    
    async def verify_backup(self, metadata: BackupMetadata) -> bool:
        """Verify file backup integrity."""
        try:
            # Check file exists
            if not os.path.exists(metadata.file_path):
                return False
            
            # Verify checksum
            current_checksum = await self._calculate_checksum(metadata.file_path)
            if current_checksum != metadata.checksum:
                return False
            
            # Verify tar file integrity
            temp_file = await self._prepare_file_for_verification(metadata.file_path)
            
            try:
                with tarfile.open(temp_file, "r") as tar:
                    # Try to list contents
                    members = tar.getmembers()
                    if not members:
                        return False
                
                # Clean up temp file
                if temp_file != metadata.file_path:
                    os.remove(temp_file)
                
                return True
                
            except tarfile.TarError:
                return False
            
        except Exception as e:
            self.logger.error(f"File backup verification failed: {e}")
            return False
    
    async def _compress_file(self, file_path: str, compression_level: int) -> str:
        """Compress backup file."""
        compressed_file = f"{file_path}.gz"
        
        with open(file_path, 'rb') as f_in:
            with gzip.open(compressed_file, 'wb', compresslevel=compression_level) as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        os.remove(file_path)
        return compressed_file
    
    async def _encrypt_file(self, file_path: str, encryption_key: str) -> str:
        """Encrypt backup file."""
        # Placeholder for encryption
        return file_path
    
    async def _calculate_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum of file."""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()
    
    async def _prepare_file_for_verification(self, file_path: str) -> str:
        """Prepare backup file for verification."""
        current_file = file_path
        
        if file_path.endswith('.gz'):
            temp_file = tempfile.mktemp()
            with gzip.open(current_file, 'rb') as f_in:
                with open(temp_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            current_file = temp_file
        
        return current_file
    
    def _calculate_retention(self, timestamp: datetime, config: BackupConfig) -> tuple[str, datetime]:
        """Calculate retention category and expiration date."""
        now = datetime.now()
        age = now - timestamp
        
        if age < timedelta(days=1):
            expires_at = timestamp + timedelta(days=config.retain_daily)
            return "daily", expires_at
        elif age < timedelta(weeks=1):
            expires_at = timestamp + timedelta(weeks=config.retain_weekly)
            return "weekly", expires_at
        elif age < timedelta(days=30):
            expires_at = timestamp + timedelta(days=30 * config.retain_monthly)
            return "monthly", expires_at
        else:
            expires_at = timestamp + timedelta(days=365 * config.retain_yearly)
            return "yearly", expires_at


class ConfigBackupStrategy(BackupStrategy):
    """Strategy for backing up configuration files and settings."""
    
    def __init__(self):
        self.logger = get_logger("backup.config")
    
    def get_backup_type(self) -> str:
        return "config"
    
    async def create_backup(self, config: BackupConfig, backup_id: str) -> BackupMetadata:
        """Create configuration backup."""
        self.logger.info(f"Starting config backup: {backup_id}")
        
        # Collect configuration data
        config_data = await self._collect_config_data()
        
        # Save to JSON file
        backup_file = os.path.join(config.backup_dir, f"{backup_id}_config.json")
        
        with open(backup_file, 'w') as f:
            json.dump(config_data, f, indent=2, default=str)
        
        # Compress if enabled
        if config.enable_compression:
            backup_file = await self._compress_file(backup_file, config.compression_level)
        
        # Calculate file info
        file_size = os.path.getsize(backup_file)
        checksum = await self._calculate_checksum(backup_file)
        
        # Determine retention
        timestamp = datetime.now()
        retention_category, expires_at = self._calculate_retention(timestamp, config)
        
        metadata = BackupMetadata(
            backup_id=backup_id,
            timestamp=timestamp,
            backup_type=self.get_backup_type(),
            status="created",
            file_path=backup_file,
            file_size=file_size,
            checksum=checksum,
            encrypted=config.enable_encryption,
            compressed=config.enable_compression,
            retention_category=retention_category,
            expires_at=expires_at,
            metadata={
                "config_sections": list(config_data.keys())
            }
        )
        
        self.logger.info(
            f"Config backup created",
            backup_id=backup_id,
            file_size=file_size,
            sections=len(config_data)
        )
        
        return metadata
    
    async def _collect_config_data(self) -> Dict[str, Any]:
        """Collect configuration data from various sources."""
        config_data = {
            "timestamp": datetime.now().isoformat(),
            "platform_info": {
                "version": "1.0.0",
                "environment": os.environ.get("ENVIRONMENT", "unknown")
            }
        }
        
        # Collect environment variables (non-sensitive)
        safe_env_vars = {}
        for key, value in os.environ.items():
            # Skip sensitive variables
            if any(sensitive in key.upper() for sensitive in ['PASSWORD', 'SECRET', 'KEY', 'TOKEN']):
                continue
            safe_env_vars[key] = value
        
        config_data["environment_variables"] = safe_env_vars
        
        # Collect configuration files
        config_files = {}
        config_paths = [
            "docker-compose.yml",
            "monitoring/prometheus/prometheus.yml",
            "monitoring/grafana/provisioning/datasources.yaml",
            "operations/migrations/alembic.ini"
        ]
        
        for path in config_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r') as f:
                        config_files[path] = f.read()
                except Exception as e:
                    self.logger.warning(f"Could not read config file {path}: {e}")
        
        config_data["config_files"] = config_files
        
        return config_data
    
    async def verify_backup(self, metadata: BackupMetadata) -> bool:
        """Verify configuration backup integrity."""
        try:
            # Check file exists
            if not os.path.exists(metadata.file_path):
                return False
            
            # Verify checksum
            current_checksum = await self._calculate_checksum(metadata.file_path)
            if current_checksum != metadata.checksum:
                return False
            
            # Verify JSON structure
            temp_file = await self._prepare_file_for_verification(metadata.file_path)
            
            try:
                with open(temp_file, 'r') as f:
                    data = json.load(f)
                
                # Check required fields
                if "timestamp" not in data or "platform_info" not in data:
                    return False
                
                # Clean up temp file
                if temp_file != metadata.file_path:
                    os.remove(temp_file)
                
                return True
                
            except json.JSONDecodeError:
                return False
            
        except Exception as e:
            self.logger.error(f"Config backup verification failed: {e}")
            return False
    
    async def _compress_file(self, file_path: str, compression_level: int) -> str:
        """Compress backup file."""
        compressed_file = f"{file_path}.gz"
        
        with open(file_path, 'rb') as f_in:
            with gzip.open(compressed_file, 'wb', compresslevel=compression_level) as f_out:
                shutil.copyfileobj(f_in, f_out)
        
        os.remove(file_path)
        return compressed_file
    
    async def _calculate_checksum(self, file_path: str) -> str:
        """Calculate SHA256 checksum of file."""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()
    
    async def _prepare_file_for_verification(self, file_path: str) -> str:
        """Prepare backup file for verification."""
        current_file = file_path
        
        if file_path.endswith('.gz'):
            temp_file = tempfile.mktemp()
            with gzip.open(current_file, 'rb') as f_in:
                with open(temp_file, 'wb') as f_out:
                    shutil.copyfileobj(f_in, f_out)
            current_file = temp_file
        
        return current_file
    
    def _calculate_retention(self, timestamp: datetime, config: BackupConfig) -> tuple[str, datetime]:
        """Calculate retention category and expiration date."""
        now = datetime.now()
        age = now - timestamp
        
        if age < timedelta(days=1):
            expires_at = timestamp + timedelta(days=config.retain_daily)
            return "daily", expires_at
        elif age < timedelta(weeks=1):
            expires_at = timestamp + timedelta(weeks=config.retain_weekly)
            return "weekly", expires_at
        elif age < timedelta(days=30):
            expires_at = timestamp + timedelta(days=30 * config.retain_monthly)
            return "monthly", expires_at
        else:
            expires_at = timestamp + timedelta(days=365 * config.retain_yearly)
            return "yearly", expires_at