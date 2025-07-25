"""
Database initialization script for the MCP Security Platform

This script creates all database tables, initial data, and sets up
the database schema for the security platform.
"""

import asyncio
import sys
from pathlib import Path
from typing import Optional

import asyncpg
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from alembic.config import Config
from alembic import command

# Add project root to path
project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(project_root))

from shared.config.settings import get_settings
from shared.observability.logging import setup_logging, get_logger
from shared.database.connection import get_database_url, create_database_engine

# Import all models to ensure they're registered
from shared.database.models.base import Base
from shared.database.models import *

logger = get_logger(__name__)


class DatabaseInitializer:
    """Database initialization manager."""
    
    def __init__(self):
        self.settings = get_settings()
        self.engine = None
        self.Session = None
        
    async def initialize_database(self, create_db: bool = True, run_migrations: bool = True):
        """Initialize the complete database setup."""
        try:
            logger.info("Starting database initialization...")
            
            if create_db:
                await self._create_database_if_not_exists()
            
            self._setup_engine()
            
            if run_migrations:
                await self._run_migrations()
            else:
                await self._create_tables()
            
            await self._create_initial_data()
            await self._verify_database_setup()
            
            logger.info("Database initialization completed successfully")
            
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
            raise
    
    async def _create_database_if_not_exists(self):
        """Create the database if it doesn't exist."""
        try:
            # Parse database URL to get connection details
            db_url = get_database_url()
            
            # Extract database name and connection details
            if "postgresql" in db_url:
                await self._create_postgresql_database()
            
            logger.info("Database creation check completed")
            
        except Exception as e:
            logger.error(f"Error checking/creating database: {e}")
            raise
    
    async def _create_postgresql_database(self):
        """Create PostgreSQL database if it doesn't exist."""
        try:
            # Connection details
            host = self.settings.database_host
            port = self.settings.database_port
            user = self.settings.database_user
            password = self.settings.database_password
            database = self.settings.database_name
            
            # Connect to postgres database to create our database
            conn = await asyncpg.connect(
                host=host,
                port=port,
                user=user,
                password=password,
                database="postgres"
            )
            
            try:
                # Check if database exists
                db_exists = await conn.fetchval(
                    "SELECT 1 FROM pg_database WHERE datname = $1",
                    database
                )
                
                if not db_exists:
                    # Create database
                    await conn.execute(f'CREATE DATABASE "{database}"')
                    logger.info(f"Created database: {database}")
                else:
                    logger.info(f"Database already exists: {database}")
                
            finally:
                await conn.close()
                
        except Exception as e:
            logger.error(f"Error creating PostgreSQL database: {e}")
            raise
    
    def _setup_engine(self):
        """Setup SQLAlchemy engine and session."""
        try:
            self.engine = create_database_engine()
            self.Session = sessionmaker(bind=self.engine)
            
            logger.info("Database engine setup completed")
            
        except Exception as e:
            logger.error(f"Error setting up database engine: {e}")
            raise
    
    async def _run_migrations(self):
        """Run Alembic migrations."""
        try:
            # Setup Alembic configuration
            alembic_cfg = Config(str(Path(__file__).parent / "alembic.ini"))
            alembic_cfg.set_main_option("script_location", str(Path(__file__).parent / "migrations"))
            alembic_cfg.set_main_option("sqlalchemy.url", get_database_url())
            
            # Run migrations
            command.upgrade(alembic_cfg, "head")
            
            logger.info("Database migrations completed")
            
        except Exception as e:
            logger.error(f"Error running migrations: {e}")
            # Fall back to direct table creation
            await self._create_tables()
    
    async def _create_tables(self):
        """Create all tables directly (fallback if migrations fail)."""
        try:
            # Create all tables
            Base.metadata.create_all(self.engine)
            
            logger.info("Database tables created directly")
            
        except Exception as e:
            logger.error(f"Error creating tables: {e}")
            raise
    
    async def _create_initial_data(self):
        """Create initial data for the platform."""
        try:
            with self.Session() as session:
                # Create default organization
                await self._create_default_organization(session)
                
                # Create default roles and permissions
                await self._create_default_roles(session)
                
                # Create default plugin categories
                await self._create_default_plugin_categories(session)
                
                # Create default notification templates
                await self._create_default_notification_templates(session)
                
                # Create default scan policies
                await self._create_default_scan_policies(session)
                
                session.commit()
            
            logger.info("Initial data creation completed")
            
        except Exception as e:
            logger.error(f"Error creating initial data: {e}")
            raise
    
    async def _create_default_organization(self, session):
        """Create default organization."""
        from shared.database.models.organizations import Organization, create_organization
        
        # Check if default org exists
        existing_org = session.query(Organization).filter(
            Organization.name == "Default Organization"
        ).first()
        
        if not existing_org:
            default_org = create_organization(
                name="Default Organization",
                description="Default organization for the MCP Security Platform",
                organization_type="enterprise",
                settings={
                    "default_scan_schedule": "0 2 * * *",  # Daily at 2 AM
                    "retention_days": 90,
                    "max_concurrent_scans": 5
                },
                created_by="system"
            )
            session.add(default_org)
            logger.info("Created default organization")
    
    async def _create_default_roles(self, session):
        """Create default roles and permissions."""
        from shared.database.models.users import Role, Permission
        
        # Default permissions
        permissions = [
            ("scans:read", "Read scan results and reports"),
            ("scans:write", "Create and manage scans"),
            ("scans:delete", "Delete scans and results"),
            ("vulnerabilities:read", "Read vulnerability data"),
            ("vulnerabilities:write", "Manage vulnerability data"),
            ("reports:read", "Read reports"),
            ("reports:write", "Create and manage reports"),
            ("integrations:read", "Read integration configurations"),
            ("integrations:write", "Manage integrations"),
            ("plugins:read", "Read plugin information"),
            ("plugins:write", "Install and manage plugins"),
            ("users:read", "Read user information"),
            ("users:write", "Manage users"),
            ("admin:read", "Read system administration data"),
            ("admin:write", "Full system administration access")
        ]
        
        # Create permissions
        permission_objects = {}
        for perm_name, perm_desc in permissions:
            existing_perm = session.query(Permission).filter(
                Permission.name == perm_name
            ).first()
            
            if not existing_perm:
                perm = Permission(
                    name=perm_name,
                    description=perm_desc
                )
                session.add(perm)
                permission_objects[perm_name] = perm
            else:
                permission_objects[perm_name] = existing_perm
        
        session.flush()  # Ensure permissions are created
        
        # Default roles
        roles_config = [
            {
                "name": "Administrator",
                "description": "Full system access",
                "permissions": [p for p in permissions]
            },
            {
                "name": "Security Analyst",
                "description": "Security analysis and reporting",
                "permissions": [
                    ("scans:read", "scans:write"),
                    ("vulnerabilities:read", "vulnerabilities:write"),
                    ("reports:read", "reports:write"),
                    ("integrations:read",),
                    ("plugins:read",)
                ]
            },
            {
                "name": "Viewer",
                "description": "Read-only access to security data",
                "permissions": [
                    ("scans:read",),
                    ("vulnerabilities:read",),
                    ("reports:read",),
                    ("integrations:read",),
                    ("plugins:read",)
                ]
            }
        ]
        
        # Create roles
        for role_config in roles_config:
            existing_role = session.query(Role).filter(
                Role.name == role_config["name"]
            ).first()
            
            if not existing_role:
                role = Role(
                    name=role_config["name"],
                    description=role_config["description"]
                )
                session.add(role)
                session.flush()
                
                # Add permissions to role
                for perm_tuple in role_config["permissions"]:
                    for perm_name in perm_tuple:
                        if perm_name in permission_objects:
                            role.permissions.append(permission_objects[perm_name])
                
                logger.info(f"Created role: {role_config['name']}")
    
    async def _create_default_plugin_categories(self, session):
        """Create default plugin categories."""
        from shared.database.models.plugin import PluginCategoryModel
        
        categories = [
            ("Security Scanners", "Vulnerability and security scanning tools", "shield"),
            ("Threat Intelligence", "Threat intelligence and analysis tools", "eye"),
            ("Compliance", "Compliance checking and reporting tools", "check-circle"),
            ("SIEM Integration", "SIEM and log management integrations", "database"),
            ("Cloud Security", "Cloud platform security tools", "cloud"),
            ("Network Security", "Network security and monitoring tools", "network"),
            ("Incident Response", "Incident response and forensics tools", "alert-triangle"),
            ("Reporting", "Reporting and visualization tools", "bar-chart"),
            ("Utilities", "General purpose utilities", "tool")
        ]
        
        for name, description, icon in categories:
            existing_cat = session.query(PluginCategoryModel).filter(
                PluginCategoryModel.name == name
            ).first()
            
            if not existing_cat:
                category = PluginCategoryModel(
                    name=name,
                    slug=name.lower().replace(" ", "-"),
                    description=description,
                    icon=icon,
                    is_active=True
                )
                session.add(category)
                logger.info(f"Created plugin category: {name}")
    
    async def _create_default_notification_templates(self, session):
        """Create default notification templates."""
        # This would create default notification templates
        # Implementation depends on notification models
        pass
    
    async def _create_default_scan_policies(self, session):
        """Create default scan policies."""
        from shared.database.models.policies import Policy, create_policy
        
        policies = [
            {
                "name": "Default Container Scan Policy",
                "description": "Default policy for container vulnerability scanning",
                "policy_type": "scan",
                "target_type": "container",
                "rules": {
                    "severity_threshold": "medium",
                    "fail_on_critical": True,
                    "max_scan_time": 1800,
                    "scanners": ["grype", "trivy"]
                },
                "is_active": True
            },
            {
                "name": "Critical Vulnerability Policy",
                "description": "Policy for handling critical vulnerabilities",
                "policy_type": "vulnerability",
                "target_type": "all",
                "rules": {
                    "auto_create_tickets": True,
                    "notification_channels": ["email", "slack"],
                    "escalation_time": 4  # hours
                },
                "is_active": True
            }
        ]
        
        for policy_config in policies:
            existing_policy = session.query(Policy).filter(
                Policy.name == policy_config["name"]
            ).first()
            
            if not existing_policy:
                policy = create_policy(
                    name=policy_config["name"],
                    description=policy_config["description"],
                    policy_type=policy_config["policy_type"],
                    target_type=policy_config["target_type"],
                    rules=policy_config["rules"],
                    created_by="system",
                    is_active=policy_config["is_active"]
                )
                session.add(policy)
                logger.info(f"Created policy: {policy_config['name']}")
    
    async def _verify_database_setup(self):
        """Verify that the database setup was successful."""
        try:
            with self.Session() as session:
                # Test basic queries
                from shared.database.models.organizations import Organization
                from shared.database.models.users import Role
                
                org_count = session.query(Organization).count()
                role_count = session.query(Role).count()
                
                logger.info(f"Database verification: {org_count} organizations, {role_count} roles")
                
                if org_count == 0:
                    logger.warning("No organizations found in database")
                
                if role_count == 0:
                    logger.warning("No roles found in database")
                
            logger.info("Database verification completed")
            
        except Exception as e:
            logger.error(f"Database verification failed: {e}")
            raise
    
    def cleanup(self):
        """Cleanup database connections."""
        if self.engine:
            self.engine.dispose()


async def main():
    """Main initialization function."""
    setup_logging(service_name="database-init")
    
    initializer = DatabaseInitializer()
    
    try:
        await initializer.initialize_database(
            create_db=True,
            run_migrations=True
        )
        logger.info("Database initialization completed successfully")
        
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        return 1
    
    finally:
        initializer.cleanup()
    
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(asyncio.run(main()))