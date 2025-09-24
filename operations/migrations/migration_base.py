"""
Base classes for database migrations.
"""

from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from datetime import datetime
import hashlib


class MigrationDirection(Enum):
    """Migration direction."""
    UP = "up"
    DOWN = "down"


class MigrationStatus(Enum):
    """Migration execution status."""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


@dataclass
class MigrationMetadata:
    """Metadata for a migration."""
    version: str
    name: str
    description: str
    author: str
    created_at: datetime
    checksum: str
    dependencies: List[str] = None
    tags: List[str] = None
    
    def __post_init__(self):
        if self.dependencies is None:
            self.dependencies = []
        if self.tags is None:
            self.tags = []


@dataclass
class MigrationResult:
    """Result of a migration execution."""
    migration_id: str
    direction: MigrationDirection
    status: MigrationStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    rollback_sql: Optional[str] = None
    affected_rows: int = 0
    execution_time_ms: int = 0


class Migration(ABC):
    """Base class for database migrations."""
    
    def __init__(self):
        self._metadata: Optional[MigrationMetadata] = None
        self._connection = None
    
    @property
    @abstractmethod
    def metadata(self) -> MigrationMetadata:
        """Return migration metadata."""
        pass
    
    @abstractmethod
    async def up(self, connection) -> MigrationResult:
        """Execute the migration (upgrade)."""
        pass
    
    @abstractmethod
    async def down(self, connection) -> MigrationResult:
        """Rollback the migration (downgrade)."""
        pass
    
    def validate(self) -> bool:
        """Validate migration before execution."""
        try:
            metadata = self.metadata
            
            # Check required fields
            if not metadata.version:
                raise ValueError("Migration version is required")
            
            if not metadata.name:
                raise ValueError("Migration name is required")
            
            if not metadata.author:
                raise ValueError("Migration author is required")
            
            # Validate version format (semantic versioning)
            import re
            version_pattern = r'^\d+\.\d+\.\d+$'
            if not re.match(version_pattern, metadata.version):
                raise ValueError(f"Invalid version format: {metadata.version}")
            
            return True
            
        except Exception as e:
            print(f"Migration validation failed: {e}")
            return False
    
    def generate_checksum(self) -> str:
        """Generate checksum for migration integrity."""
        content = f"{self.metadata.version}{self.metadata.name}{self.metadata.description}"
        
        # Include source code if available
        try:
            import inspect
            source = inspect.getsource(self.up) + inspect.getsource(self.down)
            content += source
        except Exception:
            pass
        
        return hashlib.sha256(content.encode()).hexdigest()
    
    async def execute_sql(self, connection, sql: str, params: Dict[str, Any] = None) -> int:
        """Execute SQL statement and return affected rows."""
        if not sql.strip():
            return 0
        
        try:
            if hasattr(connection, 'execute'):
                # SQLAlchemy-style connection
                result = await connection.execute(sql, params or {})
                return result.rowcount if hasattr(result, 'rowcount') else 0
            else:
                # Raw database connection
                cursor = await connection.cursor()
                await cursor.execute(sql, params or {})
                affected = cursor.rowcount
                await cursor.close()
                return affected
                
        except Exception as e:
            raise RuntimeError(f"SQL execution failed: {e}")
    
    async def execute_sql_file(self, connection, file_path: str) -> int:
        """Execute SQL from file."""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                sql = f.read()
            
            # Split by semicolon for multiple statements
            statements = [stmt.strip() for stmt in sql.split(';') if stmt.strip()]
            total_affected = 0
            
            for stmt in statements:
                affected = await self.execute_sql(connection, stmt)
                total_affected += affected
            
            return total_affected
            
        except FileNotFoundError:
            raise RuntimeError(f"SQL file not found: {file_path}")
        except Exception as e:
            raise RuntimeError(f"Failed to execute SQL file {file_path}: {e}")


class SQLMigration(Migration):
    """Migration that executes SQL statements."""
    
    def __init__(self, metadata: MigrationMetadata, up_sql: str, down_sql: str):
        super().__init__()
        self._metadata = metadata
        self.up_sql = up_sql
        self.down_sql = down_sql
    
    @property
    def metadata(self) -> MigrationMetadata:
        return self._metadata
    
    async def up(self, connection) -> MigrationResult:
        """Execute upgrade SQL."""
        started_at = datetime.utcnow()
        migration_id = f"{self.metadata.version}_{self.metadata.name}"
        
        try:
            affected_rows = await self.execute_sql(connection, self.up_sql)
            completed_at = datetime.utcnow()
            execution_time = int((completed_at - started_at).total_seconds() * 1000)
            
            return MigrationResult(
                migration_id=migration_id,
                direction=MigrationDirection.UP,
                status=MigrationStatus.COMPLETED,
                started_at=started_at,
                completed_at=completed_at,
                affected_rows=affected_rows,
                execution_time_ms=execution_time,
                rollback_sql=self.down_sql
            )
            
        except Exception as e:
            completed_at = datetime.utcnow()
            execution_time = int((completed_at - started_at).total_seconds() * 1000)
            
            return MigrationResult(
                migration_id=migration_id,
                direction=MigrationDirection.UP,
                status=MigrationStatus.FAILED,
                started_at=started_at,
                completed_at=completed_at,
                error_message=str(e),
                execution_time_ms=execution_time
            )
    
    async def down(self, connection) -> MigrationResult:
        """Execute downgrade SQL."""
        started_at = datetime.utcnow()
        migration_id = f"{self.metadata.version}_{self.metadata.name}"
        
        try:
            affected_rows = await self.execute_sql(connection, self.down_sql)
            completed_at = datetime.utcnow()
            execution_time = int((completed_at - started_at).total_seconds() * 1000)
            
            return MigrationResult(
                migration_id=migration_id,
                direction=MigrationDirection.DOWN,
                status=MigrationStatus.COMPLETED,
                started_at=started_at,
                completed_at=completed_at,
                affected_rows=affected_rows,
                execution_time_ms=execution_time
            )
            
        except Exception as e:
            completed_at = datetime.utcnow()
            execution_time = int((completed_at - started_at).total_seconds() * 1000)
            
            return MigrationResult(
                migration_id=migration_id,
                direction=MigrationDirection.DOWN,
                status=MigrationStatus.FAILED,
                started_at=started_at,
                completed_at=completed_at,
                error_message=str(e),
                execution_time_ms=execution_time
            )


class FileMigration(Migration):
    """Migration that executes SQL from files."""
    
    def __init__(self, metadata: MigrationMetadata, up_file: str, down_file: str):
        super().__init__()
        self._metadata = metadata
        self.up_file = up_file
        self.down_file = down_file
    
    @property
    def metadata(self) -> MigrationMetadata:
        return self._metadata
    
    async def up(self, connection) -> MigrationResult:
        """Execute upgrade SQL from file."""
        started_at = datetime.utcnow()
        migration_id = f"{self.metadata.version}_{self.metadata.name}"
        
        try:
            affected_rows = await self.execute_sql_file(connection, self.up_file)
            completed_at = datetime.utcnow()
            execution_time = int((completed_at - started_at).total_seconds() * 1000)
            
            return MigrationResult(
                migration_id=migration_id,
                direction=MigrationDirection.UP,
                status=MigrationStatus.COMPLETED,
                started_at=started_at,
                completed_at=completed_at,
                affected_rows=affected_rows,
                execution_time_ms=execution_time
            )
            
        except Exception as e:
            completed_at = datetime.utcnow()
            execution_time = int((completed_at - started_at).total_seconds() * 1000)
            
            return MigrationResult(
                migration_id=migration_id,
                direction=MigrationDirection.UP,
                status=MigrationStatus.FAILED,
                started_at=started_at,
                completed_at=completed_at,
                error_message=str(e),
                execution_time_ms=execution_time
            )
    
    async def down(self, connection) -> MigrationResult:
        """Execute downgrade SQL from file."""
        started_at = datetime.utcnow()
        migration_id = f"{self.metadata.version}_{self.metadata.name}"
        
        try:
            affected_rows = await self.execute_sql_file(connection, self.down_file)
            completed_at = datetime.utcnow()
            execution_time = int((completed_at - started_at).total_seconds() * 1000)
            
            return MigrationResult(
                migration_id=migration_id,
                direction=MigrationDirection.DOWN,
                status=MigrationStatus.COMPLETED,
                started_at=started_at,
                completed_at=completed_at,
                affected_rows=affected_rows,
                execution_time_ms=execution_time
            )
            
        except Exception as e:
            completed_at = datetime.utcnow()
            execution_time = int((completed_at - started_at).total_seconds() * 1000)
            
            return MigrationResult(
                migration_id=migration_id,
                direction=MigrationDirection.DOWN,
                status=MigrationStatus.FAILED,
                started_at=started_at,
                completed_at=completed_at,
                error_message=str(e),
                execution_time_ms=execution_time
            )


class PythonMigration(Migration):
    """Migration that executes Python code."""
    
    def __init__(self, metadata: MigrationMetadata):
        super().__init__()
        self._metadata = metadata
    
    @property
    def metadata(self) -> MigrationMetadata:
        return self._metadata
    
    @abstractmethod
    async def upgrade(self, connection) -> int:
        """Override this method to implement upgrade logic."""
        pass
    
    @abstractmethod
    async def downgrade(self, connection) -> int:
        """Override this method to implement downgrade logic."""
        pass
    
    async def up(self, connection) -> MigrationResult:
        """Execute upgrade logic."""
        started_at = datetime.utcnow()
        migration_id = f"{self.metadata.version}_{self.metadata.name}"
        
        try:
            affected_rows = await self.upgrade(connection)
            completed_at = datetime.utcnow()
            execution_time = int((completed_at - started_at).total_seconds() * 1000)
            
            return MigrationResult(
                migration_id=migration_id,
                direction=MigrationDirection.UP,
                status=MigrationStatus.COMPLETED,
                started_at=started_at,
                completed_at=completed_at,
                affected_rows=affected_rows,
                execution_time_ms=execution_time
            )
            
        except Exception as e:
            completed_at = datetime.utcnow()
            execution_time = int((completed_at - started_at).total_seconds() * 1000)
            
            return MigrationResult(
                migration_id=migration_id,
                direction=MigrationDirection.UP,
                status=MigrationStatus.FAILED,
                started_at=started_at,
                completed_at=completed_at,
                error_message=str(e),
                execution_time_ms=execution_time
            )
    
    async def down(self, connection) -> MigrationResult:
        """Execute downgrade logic."""
        started_at = datetime.utcnow()
        migration_id = f"{self.metadata.version}_{self.metadata.name}"
        
        try:
            affected_rows = await self.downgrade(connection)
            completed_at = datetime.utcnow()
            execution_time = int((completed_at - started_at).total_seconds() * 1000)
            
            return MigrationResult(
                migration_id=migration_id,
                direction=MigrationDirection.DOWN,
                status=MigrationStatus.COMPLETED,
                started_at=started_at,
                completed_at=completed_at,
                affected_rows=affected_rows,
                execution_time_ms=execution_time
            )
            
        except Exception as e:
            completed_at = datetime.utcnow()
            execution_time = int((completed_at - started_at).total_seconds() * 1000)
            
            return MigrationResult(
                migration_id=migration_id,
                direction=MigrationDirection.DOWN,
                status=MigrationStatus.FAILED,
                started_at=started_at,
                completed_at=completed_at,
                error_message=str(e),
                execution_time_ms=execution_time
            )