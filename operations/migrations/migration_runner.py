"""
Migration runner CLI and programmatic interface.
"""

import asyncio
import argparse
import sys
from typing import List, Optional, Dict, Any
from datetime import datetime
import json

from .migration_manager import MigrationManager, MigrationConfig
from .migration_base import MigrationResult, MigrationStatus
from shared.observability.logging import get_logger


class MigrationRunner:
    """Command-line and programmatic interface for running migrations."""
    
    def __init__(self, config: MigrationConfig):
        self.config = config
        self.logger = get_logger("migration_runner")
        self.manager = MigrationManager(config)
    
    async def initialize(self):
        """Initialize the migration runner."""
        await self.manager.initialize()
    
    async def run_command(self, command: str, **kwargs) -> Dict[str, Any]:
        """Run a migration command programmatically."""
        try:
            await self.initialize()
            
            if command == "status":
                return await self._status()
            elif command == "migrate":
                return await self._migrate(kwargs.get('target_version'))
            elif command == "rollback":
                return await self._rollback(
                    kwargs.get('target_version'),
                    kwargs.get('steps', 1)
                )
            elif command == "create":
                return await self._create_migration(
                    kwargs.get('name'),
                    kwargs.get('description', ''),
                    kwargs.get('author', 'unknown')
                )
            elif command == "validate":
                return await self._validate()
            elif command == "history":
                return await self._history()
            else:
                raise ValueError(f"Unknown command: {command}")
                
        except Exception as e:
            self.logger.error(f"Command '{command}' failed: {e}")
            return {
                "success": False,
                "error": str(e),
                "command": command
            }
        finally:
            await self.manager.cleanup()
    
    async def _status(self) -> Dict[str, Any]:
        """Get migration status."""
        status = await self.manager.get_migration_status()
        pending = await self.manager.get_pending_migrations()
        
        result = {
            "success": True,
            "status": status,
            "pending_migrations": [
                {
                    "version": m.metadata.version,
                    "name": m.metadata.name,
                    "description": m.metadata.description,
                    "author": m.metadata.author
                }
                for m in pending
            ]
        }
        
        self.logger.info(
            "Migration status",
            applied=status["applied_migrations"],
            pending=status["pending_migrations"],
            total=status["total_migrations"]
        )
        
        return result
    
    async def _migrate(self, target_version: str = None) -> Dict[str, Any]:
        """Execute migrations."""
        self.logger.info(f"Starting migration to version: {target_version or 'latest'}")
        
        results = await self.manager.migrate(target_version)
        
        success = all(r.status == MigrationStatus.COMPLETED for r in results)
        
        result = {
            "success": success,
            "migrations_executed": len(results),
            "results": [
                {
                    "migration_id": r.migration_id,
                    "status": r.status.value,
                    "execution_time_ms": r.execution_time_ms,
                    "affected_rows": r.affected_rows,
                    "error_message": r.error_message
                }
                for r in results
            ]
        }
        
        if success:
            self.logger.info(f"Migration completed successfully. {len(results)} migrations executed.")
        else:
            failed_count = sum(1 for r in results if r.status == MigrationStatus.FAILED)
            self.logger.error(f"Migration failed. {failed_count} migrations failed.")
        
        return result
    
    async def _rollback(self, target_version: str = None, steps: int = 1) -> Dict[str, Any]:
        """Execute rollbacks."""
        self.logger.info(f"Starting rollback - steps: {steps}, target: {target_version or 'auto'}")
        
        results = await self.manager.rollback(target_version, steps)
        
        success = all(r.status == MigrationStatus.COMPLETED for r in results)
        
        result = {
            "success": success,
            "rollbacks_executed": len(results),
            "results": [
                {
                    "migration_id": r.migration_id,
                    "status": r.status.value,
                    "execution_time_ms": r.execution_time_ms,
                    "error_message": r.error_message
                }
                for r in results
            ]
        }
        
        if success:
            self.logger.info(f"Rollback completed successfully. {len(results)} migrations rolled back.")
        else:
            failed_count = sum(1 for r in results if r.status == MigrationStatus.FAILED)
            self.logger.error(f"Rollback failed. {failed_count} rollbacks failed.")
        
        return result
    
    async def _create_migration(self, name: str, description: str, author: str) -> Dict[str, Any]:
        """Create a new migration file."""
        if not name:
            raise ValueError("Migration name is required")
        
        # Generate version based on current time
        version = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create migration file content
        migration_content = self._generate_migration_template(version, name, description, author)
        
        # Write to file
        import os
        filename = f"{version}_{name.lower().replace(' ', '_')}.py"
        filepath = os.path.join(self.config.migrations_dir, filename)
        
        with open(filepath, 'w') as f:
            f.write(migration_content)
        
        result = {
            "success": True,
            "migration_file": filepath,
            "version": version,
            "name": name
        }
        
        self.logger.info(f"Created migration file: {filepath}")
        
        return result
    
    def _generate_migration_template(self, version: str, name: str, description: str, author: str) -> str:
        """Generate migration file template."""
        template = f'''"""
Migration: {name}
Version: {version}
Description: {description}
Author: {author}
Created: {datetime.now().isoformat()}
"""

from datetime import datetime
from operations.migrations.migration_base import SQLMigration, MigrationMetadata


# Define the migration
migration = SQLMigration(
    metadata=MigrationMetadata(
        version="{version}",
        name="{name}",
        description="{description}",
        author="{author}",
        created_at=datetime.now()
    ),
    up_sql="""
        -- Add your upgrade SQL here
        -- Example:
        -- CREATE TABLE example_table (
        --     id SERIAL PRIMARY KEY,
        --     name VARCHAR(255) NOT NULL,
        --     created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        -- );
    """,
    down_sql="""
        -- Add your downgrade SQL here
        -- Example:
        -- DROP TABLE IF EXISTS example_table;
    """
)
'''
        return template
    
    async def _validate(self) -> Dict[str, Any]:
        """Validate all migrations."""
        validation_errors = []
        
        for version, migration in self.manager._discovered_migrations.items():
            if not migration.validate():
                validation_errors.append({
                    "version": version,
                    "name": migration.metadata.name,
                    "error": "Validation failed"
                })
        
        # Check for duplicate versions
        versions = list(self.manager._discovered_migrations.keys())
        duplicates = [v for v in versions if versions.count(v) > 1]
        
        for dup in duplicates:
            validation_errors.append({
                "version": dup,
                "error": "Duplicate version found"
            })
        
        # Check dependency order
        if self.config.strict_ordering:
            sorted_versions = sorted(versions)
            if versions != sorted_versions:
                validation_errors.append({
                    "error": "Migrations are not in chronological order"
                })
        
        success = len(validation_errors) == 0
        
        result = {
            "success": success,
            "total_migrations": len(self.manager._discovered_migrations),
            "validation_errors": validation_errors
        }
        
        if success:
            self.logger.info("All migrations validated successfully")
        else:
            self.logger.error(f"Validation failed with {len(validation_errors)} errors")
        
        return result
    
    async def _history(self) -> Dict[str, Any]:
        """Get migration history."""
        applied = self.manager._applied_migrations
        
        history = []
        for version in sorted(applied.keys()):
            migration_info = applied[version]
            history.append({
                "version": version,
                "name": migration_info["name"],
                "description": migration_info["description"],
                "author": migration_info["author"],
                "applied_at": migration_info["applied_at"].isoformat() if migration_info["applied_at"] else None,
                "execution_time_ms": migration_info["execution_time_ms"],
                "affected_rows": migration_info["affected_rows"],
                "status": migration_info["status"]
            })
        
        result = {
            "success": True,
            "history": history,
            "total_applied": len(history)
        }
        
        self.logger.info(f"Retrieved migration history: {len(history)} applied migrations")
        
        return result


def create_cli_parser() -> argparse.ArgumentParser:
    """Create command-line argument parser."""
    parser = argparse.ArgumentParser(description="Database Migration Runner")
    
    # Global options
    parser.add_argument("--database-url", required=True, help="Database connection URL")
    parser.add_argument("--migrations-dir", default="operations/migrations/versions", help="Migrations directory")
    parser.add_argument("--dry-run", action="store_true", help="Simulate migrations without applying")
    parser.add_argument("--environment", default="development", help="Environment name")
    parser.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    
    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    
    # Status command
    subparsers.add_parser("status", help="Show migration status")
    
    # Migrate command
    migrate_parser = subparsers.add_parser("migrate", help="Run pending migrations")
    migrate_parser.add_argument("--target", help="Target version to migrate to")
    
    # Rollback command
    rollback_parser = subparsers.add_parser("rollback", help="Rollback migrations")
    rollback_parser.add_argument("--target", help="Target version to rollback to")
    rollback_parser.add_argument("--steps", type=int, default=1, help="Number of steps to rollback")
    
    # Create command
    create_parser = subparsers.add_parser("create", help="Create new migration")
    create_parser.add_argument("name", help="Migration name")
    create_parser.add_argument("--description", default="", help="Migration description")
    create_parser.add_argument("--author", default="unknown", help="Migration author")
    
    # Validate command
    subparsers.add_parser("validate", help="Validate all migrations")
    
    # History command
    subparsers.add_parser("history", help="Show migration history")
    
    return parser


async def main():
    """Main CLI entry point."""
    parser = create_cli_parser()
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Configure logging
    import logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(level=level, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    
    # Create configuration
    config = MigrationConfig(
        database_url=args.database_url,
        migrations_dir=args.migrations_dir,
        dry_run=args.dry_run,
        environment=args.environment
    )
    
    # Create runner
    runner = MigrationRunner(config)
    
    # Build kwargs for command
    kwargs = {}
    if hasattr(args, 'target') and args.target:
        kwargs['target_version'] = args.target
    if hasattr(args, 'steps'):
        kwargs['steps'] = args.steps
    if hasattr(args, 'name'):
        kwargs['name'] = args.name
    if hasattr(args, 'description'):
        kwargs['description'] = args.description
    if hasattr(args, 'author'):
        kwargs['author'] = args.author
    
    # Run command
    try:
        result = await runner.run_command(args.command, **kwargs)
        
        # Print result
        print(json.dumps(result, indent=2, default=str))
        
        # Exit with appropriate code
        sys.exit(0 if result.get("success", False) else 1)
        
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())