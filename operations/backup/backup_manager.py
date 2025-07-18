"""
Backup manager for automated backup operations.
"""

import os
import json
import asyncio
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
import gzip
import hashlib
from abc import ABC, abstractmethod

from shared.observability.logging import get_logger


@dataclass
class BackupConfig:
    """Configuration for backup operations."""
    # Storage settings
    backup_dir: str = "operations/backups"
    s3_bucket: Optional[str] = None
    s3_prefix: str = "mcp-backups"
    
    # Database settings
    database_url: str = ""
    database_type: str = "postgresql"  # postgresql, mysql, mongodb
    
    # Retention policy
    retain_daily: int = 7
    retain_weekly: int = 4
    retain_monthly: int = 12
    retain_yearly: int = 3
    
    # Compression
    enable_compression: bool = True
    compression_level: int = 6
    
    # Encryption
    enable_encryption: bool = True
    encryption_key: Optional[str] = None
    
    # Backup types
    backup_database: bool = True
    backup_files: bool = True
    backup_configs: bool = True
    backup_logs: bool = False
    
    # File paths to backup
    file_paths: List[str] = field(default_factory=lambda: [
        "shared/",
        "operations/",
        "monitoring/",
        "configs/"
    ])
    
    # Exclusion patterns
    exclude_patterns: List[str] = field(default_factory=lambda: [
        "*.log",
        "*.tmp",
        "__pycache__",
        "*.pyc",
        ".git",
        "node_modules"
    ])
    
    # Scheduling
    schedule_enabled: bool = True
    daily_time: str = "02:00"  # 2 AM
    timezone: str = "UTC"
    
    # Notification
    notify_on_success: bool = False
    notify_on_failure: bool = True
    notification_webhook: Optional[str] = None
    
    # Performance
    parallel_backups: bool = True
    max_workers: int = 4
    chunk_size: int = 1024 * 1024  # 1MB


@dataclass
class BackupMetadata:
    """Metadata for a backup operation."""
    backup_id: str
    timestamp: datetime
    backup_type: str
    status: str
    file_path: str
    file_size: int
    checksum: str
    encrypted: bool
    compressed: bool
    retention_category: str
    expires_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)


class BackupStrategy(ABC):
    """Abstract base class for backup strategies."""
    
    @abstractmethod
    async def create_backup(self, config: BackupConfig, backup_id: str) -> BackupMetadata:
        """Create a backup using this strategy."""
        pass
    
    @abstractmethod
    async def verify_backup(self, metadata: BackupMetadata) -> bool:
        """Verify backup integrity."""
        pass
    
    @abstractmethod
    def get_backup_type(self) -> str:
        """Get the backup type identifier."""
        pass


class BackupManager:
    """Manages backup operations and scheduling."""
    
    def __init__(self, config: BackupConfig):
        self.config = config
        self.logger = get_logger("backup_manager")
        self.strategies: Dict[str, BackupStrategy] = {}
        self._backup_metadata: List[BackupMetadata] = []
        self._scheduler_task: Optional[asyncio.Task] = None
    
    async def initialize(self):
        """Initialize backup manager."""
        try:
            # Create backup directory
            os.makedirs(self.config.backup_dir, exist_ok=True)
            
            # Register backup strategies
            await self._register_strategies()
            
            # Load existing backup metadata
            await self._load_backup_metadata()
            
            # Start scheduler if enabled
            if self.config.schedule_enabled:
                await self._start_scheduler()
            
            self.logger.info(
                "Backup manager initialized",
                backup_dir=self.config.backup_dir,
                strategies=list(self.strategies.keys()),
                existing_backups=len(self._backup_metadata)
            )
            
        except Exception as e:
            self.logger.error(f"Failed to initialize backup manager: {e}")
            raise
    
    async def _register_strategies(self):
        """Register available backup strategies."""
        from .backup_strategies import DatabaseBackupStrategy, FileBackupStrategy, ConfigBackupStrategy
        
        if self.config.backup_database:
            strategy = DatabaseBackupStrategy()
            self.strategies[strategy.get_backup_type()] = strategy
        
        if self.config.backup_files:
            strategy = FileBackupStrategy()
            self.strategies[strategy.get_backup_type()] = strategy
        
        if self.config.backup_configs:
            strategy = ConfigBackupStrategy()
            self.strategies[strategy.get_backup_type()] = strategy
        
        self.logger.info(f"Registered {len(self.strategies)} backup strategies")
    
    async def create_backup(self, backup_types: List[str] = None) -> List[BackupMetadata]:
        """Create backups using specified strategies."""
        if not backup_types:
            backup_types = list(self.strategies.keys())
        
        backup_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        results = []
        
        self.logger.info(f"Starting backup operation: {backup_id}")
        
        if self.config.parallel_backups:
            # Run backups in parallel
            tasks = []
            for backup_type in backup_types:
                if backup_type in self.strategies:
                    strategy = self.strategies[backup_type]
                    task = asyncio.create_task(
                        self._create_single_backup(strategy, backup_id, backup_type)
                    )
                    tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
        else:
            # Run backups sequentially
            for backup_type in backup_types:
                if backup_type in self.strategies:
                    strategy = self.strategies[backup_type]
                    result = await self._create_single_backup(strategy, backup_id, backup_type)
                    results.append(result)
        
        # Filter successful results
        successful_backups = [r for r in results if isinstance(r, BackupMetadata)]
        failed_backups = [r for r in results if isinstance(r, Exception)]
        
        # Save metadata
        for backup in successful_backups:
            self._backup_metadata.append(backup)
        
        await self._save_backup_metadata()
        
        # Cleanup old backups
        await self._cleanup_old_backups()
        
        # Send notifications
        await self._send_notifications(successful_backups, failed_backups)
        
        self.logger.info(
            f"Backup operation completed",
            backup_id=backup_id,
            successful=len(successful_backups),
            failed=len(failed_backups)
        )
        
        return successful_backups
    
    async def _create_single_backup(self, strategy: BackupStrategy, backup_id: str, backup_type: str) -> BackupMetadata:
        """Create a single backup using the specified strategy."""
        try:
            self.logger.info(f"Creating {backup_type} backup")
            
            metadata = await strategy.create_backup(self.config, f"{backup_id}_{backup_type}")
            
            # Verify backup
            if await strategy.verify_backup(metadata):
                metadata.status = "completed"
                self.logger.info(
                    f"{backup_type} backup completed",
                    file_size=metadata.file_size,
                    checksum=metadata.checksum
                )
            else:
                metadata.status = "verification_failed"
                self.logger.error(f"{backup_type} backup verification failed")
            
            return metadata
            
        except Exception as e:
            self.logger.error(f"{backup_type} backup failed: {e}")
            raise
    
    async def _load_backup_metadata(self):
        """Load backup metadata from disk."""
        metadata_file = os.path.join(self.config.backup_dir, "metadata.json")
        
        if os.path.exists(metadata_file):
            try:
                with open(metadata_file, 'r') as f:
                    data = json.load(f)
                
                self._backup_metadata = []
                for item in data.get("backups", []):
                    metadata = BackupMetadata(
                        backup_id=item["backup_id"],
                        timestamp=datetime.fromisoformat(item["timestamp"]),
                        backup_type=item["backup_type"],
                        status=item["status"],
                        file_path=item["file_path"],
                        file_size=item["file_size"],
                        checksum=item["checksum"],
                        encrypted=item["encrypted"],
                        compressed=item["compressed"],
                        retention_category=item["retention_category"],
                        expires_at=datetime.fromisoformat(item["expires_at"]),
                        metadata=item.get("metadata", {})
                    )
                    self._backup_metadata.append(metadata)
                
                self.logger.info(f"Loaded {len(self._backup_metadata)} backup records")
                
            except Exception as e:
                self.logger.error(f"Failed to load backup metadata: {e}")
                self._backup_metadata = []
    
    async def _save_backup_metadata(self):
        """Save backup metadata to disk."""
        metadata_file = os.path.join(self.config.backup_dir, "metadata.json")
        
        try:
            data = {
                "last_updated": datetime.now().isoformat(),
                "backups": [
                    {
                        "backup_id": m.backup_id,
                        "timestamp": m.timestamp.isoformat(),
                        "backup_type": m.backup_type,
                        "status": m.status,
                        "file_path": m.file_path,
                        "file_size": m.file_size,
                        "checksum": m.checksum,
                        "encrypted": m.encrypted,
                        "compressed": m.compressed,
                        "retention_category": m.retention_category,
                        "expires_at": m.expires_at.isoformat(),
                        "metadata": m.metadata
                    }
                    for m in self._backup_metadata
                ]
            }
            
            with open(metadata_file, 'w') as f:
                json.dump(data, f, indent=2)
            
        except Exception as e:
            self.logger.error(f"Failed to save backup metadata: {e}")
    
    async def _cleanup_old_backups(self):
        """Clean up old backups based on retention policy."""
        now = datetime.now()
        to_remove = []
        
        for metadata in self._backup_metadata:
            if metadata.expires_at <= now:
                to_remove.append(metadata)
                
                # Remove backup file
                try:
                    if os.path.exists(metadata.file_path):
                        os.remove(metadata.file_path)
                        self.logger.info(f"Removed expired backup: {metadata.backup_id}")
                except Exception as e:
                    self.logger.error(f"Failed to remove backup file {metadata.file_path}: {e}")
        
        # Remove from metadata
        for metadata in to_remove:
            self._backup_metadata.remove(metadata)
        
        if to_remove:
            await self._save_backup_metadata()
            self.logger.info(f"Cleaned up {len(to_remove)} expired backups")
    
    def _calculate_retention_category(self, timestamp: datetime) -> tuple[str, datetime]:
        """Calculate retention category and expiration date."""
        now = datetime.now()
        age = now - timestamp
        
        if age < timedelta(days=1):
            # Keep daily backups
            expires_at = timestamp + timedelta(days=self.config.retain_daily)
            return "daily", expires_at
        elif age < timedelta(weeks=1):
            # Keep weekly backups
            expires_at = timestamp + timedelta(weeks=self.config.retain_weekly)
            return "weekly", expires_at
        elif age < timedelta(days=30):
            # Keep monthly backups
            expires_at = timestamp + timedelta(days=30 * self.config.retain_monthly)
            return "monthly", expires_at
        else:
            # Keep yearly backups
            expires_at = timestamp + timedelta(days=365 * self.config.retain_yearly)
            return "yearly", expires_at
    
    async def _start_scheduler(self):
        """Start backup scheduler."""
        self._scheduler_task = asyncio.create_task(self._scheduler_loop())
        self.logger.info(f"Backup scheduler started (daily at {self.config.daily_time})")
    
    async def _scheduler_loop(self):
        """Main scheduler loop."""
        while True:
            try:
                # Calculate next backup time
                now = datetime.now()
                next_backup = self._calculate_next_backup_time(now)
                sleep_seconds = (next_backup - now).total_seconds()
                
                self.logger.info(f"Next scheduled backup: {next_backup}")
                
                # Wait until next backup time
                await asyncio.sleep(sleep_seconds)
                
                # Run backup
                await self.create_backup()
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                self.logger.error(f"Scheduler error: {e}")
                # Wait 1 hour before retrying
                await asyncio.sleep(3600)
    
    def _calculate_next_backup_time(self, now: datetime) -> datetime:
        """Calculate next scheduled backup time."""
        # Parse daily time
        hour, minute = map(int, self.config.daily_time.split(':'))
        
        # Calculate next occurrence
        next_backup = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        
        # If time has passed today, schedule for tomorrow
        if next_backup <= now:
            next_backup += timedelta(days=1)
        
        return next_backup
    
    async def _send_notifications(self, successful: List[BackupMetadata], failed: List[Exception]):
        """Send backup notifications."""
        if not self.config.notification_webhook:
            return
        
        if failed and self.config.notify_on_failure:
            await self._send_notification("failure", successful, failed)
        elif successful and self.config.notify_on_success:
            await self._send_notification("success", successful, failed)
    
    async def _send_notification(self, status: str, successful: List[BackupMetadata], failed: List[Exception]):
        """Send notification webhook."""
        try:
            import httpx
            
            payload = {
                "status": status,
                "timestamp": datetime.now().isoformat(),
                "successful_backups": len(successful),
                "failed_backups": len(failed),
                "backups": [
                    {
                        "backup_id": b.backup_id,
                        "type": b.backup_type,
                        "size": b.file_size,
                        "status": b.status
                    }
                    for b in successful
                ],
                "errors": [str(e) for e in failed]
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.config.notification_webhook,
                    json=payload,
                    timeout=30
                )
                response.raise_for_status()
            
            self.logger.info("Backup notification sent")
            
        except Exception as e:
            self.logger.error(f"Failed to send notification: {e}")
    
    async def list_backups(self, backup_type: str = None) -> List[BackupMetadata]:
        """List available backups."""
        if backup_type:
            return [b for b in self._backup_metadata if b.backup_type == backup_type]
        return self._backup_metadata.copy()
    
    async def get_backup_status(self) -> Dict[str, Any]:
        """Get backup system status."""
        total_backups = len(self._backup_metadata)
        total_size = sum(b.file_size for b in self._backup_metadata)
        
        by_type = {}
        for backup in self._backup_metadata:
            if backup.backup_type not in by_type:
                by_type[backup.backup_type] = {"count": 0, "size": 0}
            by_type[backup.backup_type]["count"] += 1
            by_type[backup.backup_type]["size"] += backup.file_size
        
        latest_backup = max(self._backup_metadata, key=lambda b: b.timestamp) if self._backup_metadata else None
        
        return {
            "total_backups": total_backups,
            "total_size_bytes": total_size,
            "total_size_gb": total_size / (1024**3),
            "by_type": by_type,
            "latest_backup": {
                "backup_id": latest_backup.backup_id,
                "timestamp": latest_backup.timestamp.isoformat(),
                "type": latest_backup.backup_type,
                "status": latest_backup.status
            } if latest_backup else None,
            "scheduler_running": self._scheduler_task is not None and not self._scheduler_task.done(),
            "config": {
                "schedule_enabled": self.config.schedule_enabled,
                "daily_time": self.config.daily_time,
                "backup_dir": self.config.backup_dir,
                "retention_daily": self.config.retain_daily,
                "retention_weekly": self.config.retain_weekly,
                "retention_monthly": self.config.retain_monthly
            }
        }
    
    async def cleanup(self):
        """Cleanup backup manager resources."""
        if self._scheduler_task:
            self._scheduler_task.cancel()
            try:
                await self._scheduler_task
            except asyncio.CancelledError:
                pass
        
        self.logger.info("Backup manager cleanup completed")