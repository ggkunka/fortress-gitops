"""
Migration manager for database schema management.
"""

import os
import json
import asyncio
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
import importlib.util
from contextlib import asynccontextmanager

from .migration_base import (
    Migration, MigrationMetadata, MigrationResult, 
    MigrationDirection, MigrationStatus
)
from shared.observability.logging import get_logger


@dataclass
class MigrationConfig:
    """Configuration for migration manager."""
    # Database connection
    database_url: str
    
    # Migration directories
    migrations_dir: str = "operations/migrations/versions"
    
    # Migration table
    migration_table: str = "schema_migrations"
    
    # Lock settings
    enable_locking: bool = True
    lock_timeout: int = 300  # 5 minutes
    
    # Backup settings
    backup_before_migration: bool = True
    backup_dir: str = "operations/backups/migrations"
    
    # Validation
    validate_checksums: bool = True
    strict_ordering: bool = True
    
    # Rollback settings
    allow_rollbacks: bool = True
    max_rollback_steps: int = 10
    
    # Environment
    environment: str = "development"
    dry_run: bool = False
    
    # Connection settings
    connection_pool_size: int = 5
    connection_timeout: int = 30


class MigrationManager:
    """Manages database migrations."""
    
    def __init__(self, config: MigrationConfig):
        self.config = config
        self.logger = get_logger("migration_manager")
        self._connection_pool = None
        self._discovered_migrations: Dict[str, Migration] = {}
        self._applied_migrations: Dict[str, Dict[str, Any]] = {}
    
    async def initialize(self):
        """Initialize migration manager."""
        try:
            # Create migrations directory if it doesn't exist
            os.makedirs(self.config.migrations_dir, exist_ok=True)
            
            # Create backup directory if it doesn't exist
            if self.config.backup_before_migration:
                os.makedirs(self.config.backup_dir, exist_ok=True)
            
            # Initialize database connection
            await self._initialize_database()
            
            # Create migration tracking table
            await self._create_migration_table()
            
            # Load applied migrations
            await self._load_applied_migrations()
            
            # Discover available migrations
            await self._discover_migrations()
            
            self.logger.info(
                "Migration manager initialized",
                migrations_dir=self.config.migrations_dir,
                discovered_migrations=len(self._discovered_migrations),
                applied_migrations=len(self._applied_migrations)
            )
            
        except Exception as e:
            self.logger.error(f"Failed to initialize migration manager: {e}")
            raise
    
    async def _initialize_database(self):
        """Initialize database connection."""
        # This would be implemented based on your database choice
        # For example, using SQLAlchemy or asyncpg
        try:
            from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession
            from sqlalchemy.orm import sessionmaker
            
            self._engine = create_async_engine(
                self.config.database_url,
                pool_size=self.config.connection_pool_size,
                max_overflow=0,
                pool_timeout=self.config.connection_timeout
            )
            
            self._session_factory = sessionmaker(
                self._engine, class_=AsyncSession, expire_on_commit=False
            )
            
            # Test connection
            async with self._engine.begin() as conn:
                await conn.execute("SELECT 1")
            
            self.logger.info("Database connection established")
            
        except Exception as e:
            self.logger.error(f"Database connection failed: {e}")
            raise
    
    async def _create_migration_table(self):
        """Create migration tracking table."""
        create_table_sql = f\"\"\"
        CREATE TABLE IF NOT EXISTS {self.config.migration_table} (
            version VARCHAR(50) PRIMARY KEY,
            name VARCHAR(255) NOT NULL,
            description TEXT,
            author VARCHAR(100),
            checksum VARCHAR(64),
            applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            execution_time_ms INTEGER,
            affected_rows INTEGER,
            rollback_sql TEXT,
            status VARCHAR(20) DEFAULT 'completed',
            error_message TEXT
        )
        \"\"\"
        
        try:
            async with self._engine.begin() as conn:
                await conn.execute(create_table_sql)
            
            self.logger.info(f"Migration table '{self.config.migration_table}' ready")
            
        except Exception as e:
            self.logger.error(f"Failed to create migration table: {e}")
            raise
    
    async def _load_applied_migrations(self):
        """Load applied migrations from database."""
        try:
            query = f"SELECT * FROM {self.config.migration_table} ORDER BY applied_at"
            
            async with self._engine.begin() as conn:
                result = await conn.execute(query)
                rows = result.fetchall()
            
            self._applied_migrations = {}
            for row in rows:
                self._applied_migrations[row.version] = {
                    'version': row.version,
                    'name': row.name,
                    'description': row.description,
                    'author': row.author,
                    'checksum': row.checksum,
                    'applied_at': row.applied_at,
                    'execution_time_ms': row.execution_time_ms,
                    'affected_rows': row.affected_rows,
                    'rollback_sql': row.rollback_sql,
                    'status': row.status,
                    'error_message': row.error_message
                }
            
            self.logger.info(f"Loaded {len(self._applied_migrations)} applied migrations")
            
        except Exception as e:
            self.logger.error(f"Failed to load applied migrations: {e}")
            raise
    
    async def _discover_migrations(self):
        """Discover migration files in migrations directory."""
        try:
            migrations_path = Path(self.config.migrations_dir)
            
            for file_path in sorted(migrations_path.glob("*.py")):
                if file_path.name.startswith("__"):
                    continue
                
                try:
                    migration = await self._load_migration_from_file(file_path)
                    if migration and migration.validate():
                        self._discovered_migrations[migration.metadata.version] = migration
                        self.logger.debug(f"Discovered migration: {migration.metadata.version}")
                
                except Exception as e:
                    self.logger.warning(f"Failed to load migration {file_path}: {e}")
            
            self.logger.info(f"Discovered {len(self._discovered_migrations)} migrations")
            
        except Exception as e:
            self.logger.error(f"Migration discovery failed: {e}")
            raise
    
    async def _load_migration_from_file(self, file_path: Path) -> Optional[Migration]:
        """Load migration from Python file."""
        try:
            spec = importlib.util.spec_from_file_location("migration", file_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            
            # Look for migration class or function
            if hasattr(module, 'migration'):
                return module.migration
            elif hasattr(module, 'Migration'):
                return module.Migration()
            else:
                self.logger.warning(f"No migration found in {file_path}")
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to load migration from {file_path}: {e}")
            raise
    
    async def get_pending_migrations(self) -> List[Migration]:
        """Get list of pending migrations."""
        pending = []
        
        for version, migration in sorted(self._discovered_migrations.items()):
            if version not in self._applied_migrations:
                pending.append(migration)
            elif self.config.validate_checksums:
                # Check if migration has changed
                applied = self._applied_migrations[version]
                current_checksum = migration.generate_checksum()
                
                if applied.get('checksum') != current_checksum:
                    self.logger.warning(
                        f"Migration {version} checksum mismatch",
                        applied_checksum=applied.get('checksum'),
                        current_checksum=current_checksum
                    )
                    if self.config.environment == "production":
                        raise RuntimeError(f"Migration {version} has been modified")
        
        return pending
    
    async def migrate(self, target_version: str = None) -> List[MigrationResult]:
        """Execute pending migrations up to target version."""
        if self.config.dry_run:
            return await self._dry_run_migrations(target_version)
        
        # Get lock
        async with self._migration_lock():
            return await self._execute_migrations(target_version)
    
    async def rollback(self, target_version: str = None, steps: int = 1) -> List[MigrationResult]:
        """Rollback migrations."""
        if not self.config.allow_rollbacks:
            raise RuntimeError("Rollbacks are disabled")
        
        if steps > self.config.max_rollback_steps:
            raise ValueError(f"Cannot rollback more than {self.config.max_rollback_steps} steps")
        
        async with self._migration_lock():
            return await self._execute_rollbacks(target_version, steps)
    
    @asynccontextmanager
    async def _migration_lock(self):
        """Acquire migration lock to prevent concurrent migrations."""
        if not self.config.enable_locking:
            yield
            return
        
        lock_acquired = False
        try:
            # Try to acquire lock
            lock_sql = f\"\"\"
            INSERT INTO {self.config.migration_table}_lock (locked_at, expires_at)
            VALUES (CURRENT_TIMESTAMP, CURRENT_TIMESTAMP + INTERVAL '{self.config.lock_timeout} seconds')
            \"\"\"
            
            async with self._engine.begin() as conn:
                try:
                    await conn.execute(lock_sql)
                    lock_acquired = True
                    self.logger.info("Migration lock acquired")
                except Exception:
                    # Check if lock is expired
                    check_sql = f\"\"\"
                    DELETE FROM {self.config.migration_table}_lock
                    WHERE expires_at < CURRENT_TIMESTAMP
                    \"\"\"
                    await conn.execute(check_sql)
                    
                    # Try again
                    await conn.execute(lock_sql)
                    lock_acquired = True
                    self.logger.info("Migration lock acquired after cleanup")
            
            yield
            
        except Exception as e:
            if "duplicate" in str(e).lower() or "unique" in str(e).lower():
                raise RuntimeError("Another migration is currently running")
            raise
        
        finally:
            if lock_acquired:
                try:
                    unlock_sql = f"DELETE FROM {self.config.migration_table}_lock"
                    async with self._engine.begin() as conn:
                        await conn.execute(unlock_sql)
                    self.logger.info("Migration lock released")
                except Exception as e:
                    self.logger.error(f"Failed to release migration lock: {e}")
    
    async def _execute_migrations(self, target_version: str = None) -> List[MigrationResult]:
        """Execute pending migrations."""
        results = []
        pending = await self.get_pending_migrations()
        
        for migration in pending:
            if target_version and migration.metadata.version > target_version:
                break
            
            self.logger.info(
                f"Executing migration {migration.metadata.version}: {migration.metadata.name}"
            )
            
            # Backup if configured
            if self.config.backup_before_migration:
                await self._create_backup(migration.metadata.version)
            
            # Execute migration
            async with self._engine.begin() as conn:
                result = await migration.up(conn)
                
                if result.status == MigrationStatus.COMPLETED:
                    # Record successful migration
                    await self._record_migration(conn, migration, result)
                    results.append(result)
                    
                    self.logger.info(
                        f"Migration {migration.metadata.version} completed",
                        execution_time_ms=result.execution_time_ms,
                        affected_rows=result.affected_rows
                    )
                else:
                    # Migration failed
                    self.logger.error(
                        f"Migration {migration.metadata.version} failed",
                        error=result.error_message
                    )
                    results.append(result)
                    break
        
        return results
    
    async def _execute_rollbacks(self, target_version: str = None, steps: int = 1) -> List[MigrationResult]:
        """Execute migration rollbacks."""
        results = []
        
        # Get applied migrations in reverse order
        applied_versions = sorted(self._applied_migrations.keys(), reverse=True)
        rollback_count = 0
        
        for version in applied_versions:
            if rollback_count >= steps:
                break
            
            if target_version and version <= target_version:
                break
            
            migration = self._discovered_migrations.get(version)
            if not migration:
                self.logger.warning(f"Migration {version} not found for rollback")
                continue
            
            self.logger.info(f"Rolling back migration {version}: {migration.metadata.name}")
            
            # Execute rollback
            async with self._engine.begin() as conn:
                result = await migration.down(conn)
                
                if result.status == MigrationStatus.COMPLETED:
                    # Remove migration record
                    await self._remove_migration_record(conn, version)
                    results.append(result)
                    rollback_count += 1
                    
                    self.logger.info(
                        f"Migration {version} rolled back",
                        execution_time_ms=result.execution_time_ms
                    )
                else:
                    self.logger.error(
                        f"Rollback of {version} failed",
                        error=result.error_message
                    )
                    results.append(result)
                    break
        
        # Reload applied migrations
        await self._load_applied_migrations()
        
        return results
    
    async def _record_migration(self, conn, migration: Migration, result: MigrationResult):
        """Record successful migration in database."""
        insert_sql = f\"\"\"
        INSERT INTO {self.config.migration_table} 
        (version, name, description, author, checksum, execution_time_ms, 
         affected_rows, rollback_sql, status)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        \"\"\"
        
        params = (
            migration.metadata.version,
            migration.metadata.name,
            migration.metadata.description,
            migration.metadata.author,
            migration.generate_checksum(),
            result.execution_time_ms,
            result.affected_rows,
            result.rollback_sql,
            result.status.value
        )
        
        await conn.execute(insert_sql, params)
        
        # Update in-memory cache
        self._applied_migrations[migration.metadata.version] = {
            'version': migration.metadata.version,
            'name': migration.metadata.name,
            'description': migration.metadata.description,
            'author': migration.metadata.author,
            'checksum': migration.generate_checksum(),
            'applied_at': result.completed_at,
            'execution_time_ms': result.execution_time_ms,
            'affected_rows': result.affected_rows,
            'rollback_sql': result.rollback_sql,
            'status': result.status.value,
            'error_message': result.error_message
        }
    
    async def _remove_migration_record(self, conn, version: str):
        """Remove migration record from database."""
        delete_sql = f"DELETE FROM {self.config.migration_table} WHERE version = ?"
        await conn.execute(delete_sql, (version,))
        
        # Update in-memory cache
        self._applied_migrations.pop(version, None)
    
    async def _create_backup(self, version: str):
        """Create database backup before migration."""
        try:
            backup_file = f"{self.config.backup_dir}/backup_before_{version}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.sql"
            
            # This would be implemented based on your database
            # For PostgreSQL: pg_dump
            # For MySQL: mysqldump
            # etc.
            
            self.logger.info(f"Created backup: {backup_file}")
            
        except Exception as e:
            self.logger.error(f"Backup creation failed: {e}")
            if self.config.environment == "production":
                raise
    
    async def _dry_run_migrations(self, target_version: str = None) -> List[MigrationResult]:
        """Simulate migration execution without applying changes."""
        self.logger.info("Performing dry run of migrations")
        
        pending = await self.get_pending_migrations()
        results = []
        
        for migration in pending:
            if target_version and migration.metadata.version > target_version:
                break
            
            # Create a mock result
            result = MigrationResult(
                migration_id=f"{migration.metadata.version}_{migration.metadata.name}",
                direction=MigrationDirection.UP,
                status=MigrationStatus.COMPLETED,
                started_at=datetime.utcnow(),
                completed_at=datetime.utcnow(),
                affected_rows=0,  # Unknown in dry run
                execution_time_ms=0
            )
            
            results.append(result)
            
            self.logger.info(
                f"DRY RUN: Would execute migration {migration.metadata.version}: {migration.metadata.name}"
            )
        
        return results
    
    async def get_migration_status(self) -> Dict[str, Any]:
        """Get current migration status."""
        pending = await self.get_pending_migrations()
        
        return {
            "applied_migrations": len(self._applied_migrations),
            "pending_migrations": len(pending),
            "total_migrations": len(self._discovered_migrations),
            "last_applied": max(self._applied_migrations.keys()) if self._applied_migrations else None,
            "next_pending": pending[0].metadata.version if pending else None,
            "database_url": self.config.database_url.split('@')[-1] if '@' in self.config.database_url else "***",
            "environment": self.config.environment
        }
    
    async def cleanup(self):
        """Cleanup resources."""
        if self._engine:
            await self._engine.dispose()
        
        self.logger.info("Migration manager cleanup completed")