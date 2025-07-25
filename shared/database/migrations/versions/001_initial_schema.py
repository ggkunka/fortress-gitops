"""Initial schema creation

Revision ID: 001
Revises: 
Create Date: 2025-07-24 12:00:00.000000

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers
revision = '001'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    """Create initial schema tables."""
    
    # Organizations table
    op.create_table('organizations',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('slug', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('organization_type', sa.String(length=50), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('settings', sa.JSON(), nullable=True),
        sa.Column('subscription_plan', sa.String(length=50), nullable=False),
        sa.Column('created_by', sa.String(length=255), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('slug')
    )
    op.create_index('idx_organization_name', 'organizations', ['name'])
    op.create_index('idx_organization_type_status', 'organizations', ['organization_type', 'status'])
    
    # Users table
    op.create_table('users',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('username', sa.String(length=255), nullable=False),
        sa.Column('email', sa.String(length=255), nullable=False),
        sa.Column('password_hash', sa.String(length=255), nullable=False),
        sa.Column('first_name', sa.String(length=100), nullable=True),
        sa.Column('last_name', sa.String(length=100), nullable=True),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('is_superuser', sa.Boolean(), nullable=False),
        sa.Column('is_verified', sa.Boolean(), nullable=False),
        sa.Column('last_login', sa.DateTime(), nullable=True),
        sa.Column('settings', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('email'),
        sa.UniqueConstraint('username')
    )
    op.create_index('idx_user_email', 'users', ['email'])
    op.create_index('idx_user_organization', 'users', ['organization_id'])
    op.create_index('idx_user_active', 'users', ['is_active'])
    
    # Roles table
    op.create_table('roles',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('is_system', sa.Boolean(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )
    
    # Permissions table
    op.create_table('permissions',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=100), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('resource', sa.String(length=100), nullable=False),
        sa.Column('action', sa.String(length=50), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('name')
    )
    
    # User roles association table
    op.create_table('user_roles',
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('role_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('assigned_at', sa.DateTime(), nullable=False),
        sa.Column('assigned_by', sa.String(length=255), nullable=False),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('user_id', 'role_id')
    )
    
    # Role permissions association table
    op.create_table('role_permissions',
        sa.Column('role_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('permission_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.ForeignKeyConstraint(['permission_id'], ['permissions.id'], ),
        sa.ForeignKeyConstraint(['role_id'], ['roles.id'], ),
        sa.PrimaryKeyConstraint('role_id', 'permission_id')
    )
    
    # Scans table
    op.create_table('scans',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('scan_type', sa.String(length=50), nullable=False),
        sa.Column('target_type', sa.String(length=50), nullable=False),
        sa.Column('target_identifier', sa.String(length=500), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('priority', sa.String(length=20), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_by', sa.String(length=255), nullable=False),
        sa.Column('configuration', sa.JSON(), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('scheduled_at', sa.DateTime(), nullable=True),
        sa.Column('started_at', sa.DateTime(), nullable=True),
        sa.Column('completed_at', sa.DateTime(), nullable=True),
        sa.Column('duration', sa.Integer(), nullable=True),
        sa.Column('progress', sa.Integer(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_scan_status', 'scans', ['status'])
    op.create_index('idx_scan_type_target', 'scans', ['scan_type', 'target_type'])
    op.create_index('idx_scan_organization', 'scans', ['organization_id'])
    op.create_index('idx_scan_created_by', 'scans', ['created_by'])
    
    # Vulnerabilities table
    op.create_table('vulnerabilities',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('cve_id', sa.String(length=50), nullable=True),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('cvss_score', sa.Float(), nullable=True),
        sa.Column('cvss_vector', sa.String(length=200), nullable=True),
        sa.Column('cwe_id', sa.String(length=20), nullable=True),
        sa.Column('package_name', sa.String(length=255), nullable=True),
        sa.Column('package_version', sa.String(length=100), nullable=True),
        sa.Column('fixed_version', sa.String(length=100), nullable=True),
        sa.Column('scan_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('source', sa.String(length=100), nullable=False),
        sa.Column('confidence', sa.String(length=20), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('first_seen', sa.DateTime(), nullable=False),
        sa.Column('last_seen', sa.DateTime(), nullable=False),
        sa.Column('references', sa.JSON(), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['scan_id'], ['scans.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_vulnerability_cve', 'vulnerabilities', ['cve_id'])
    op.create_index('idx_vulnerability_severity', 'vulnerabilities', ['severity'])
    op.create_index('idx_vulnerability_package', 'vulnerabilities', ['package_name'])
    op.create_index('idx_vulnerability_scan', 'vulnerabilities', ['scan_id'])
    op.create_index('idx_vulnerability_status', 'vulnerabilities', ['status'])
    
    # Events table
    op.create_table('events',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('event_type', sa.String(length=100), nullable=False),
        sa.Column('source', sa.String(length=100), nullable=False),
        sa.Column('severity', sa.String(length=20), nullable=False),
        sa.Column('title', sa.String(length=500), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('data', sa.JSON(), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('user_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('correlation_id', sa.String(length=100), nullable=True),
        sa.Column('tags', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('processed', sa.Boolean(), nullable=False),
        sa.Column('acknowledged', sa.Boolean(), nullable=False),
        sa.Column('occurred_at', sa.DateTime(), nullable=False),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
        sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_event_type_severity', 'events', ['event_type', 'severity'])
    op.create_index('idx_event_organization', 'events', ['organization_id'])
    op.create_index('idx_event_occurred_at', 'events', ['occurred_at'])
    op.create_index('idx_event_processed', 'events', ['processed'])
    
    # Integrations table
    op.create_table('integrations',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('integration_type', sa.String(length=50), nullable=False),
        sa.Column('provider', sa.String(length=100), nullable=False),
        sa.Column('config', sa.JSON(), nullable=False),
        sa.Column('credentials', sa.JSON(), nullable=False),
        sa.Column('version', sa.String(length=50), nullable=True),
        sa.Column('capabilities', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('is_enabled', sa.Boolean(), nullable=False),
        sa.Column('is_bidirectional', sa.Boolean(), nullable=False),
        sa.Column('endpoint_url', sa.String(length=500), nullable=True),
        sa.Column('authentication_method', sa.String(length=50), nullable=True),
        sa.Column('timeout', sa.Integer(), nullable=True),
        sa.Column('retry_attempts', sa.Integer(), nullable=True),
        sa.Column('priority', sa.Integer(), nullable=True),
        sa.Column('health_check_interval', sa.Integer(), nullable=True),
        sa.Column('sync_interval', sa.Integer(), nullable=True),
        sa.Column('settings', sa.JSON(), nullable=True),
        sa.Column('tags', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('created_by', sa.String(length=255), nullable=False),
        sa.Column('updated_by', sa.String(length=255), nullable=True),
        sa.Column('connection_count', sa.Integer(), nullable=True),
        sa.Column('last_sync_at', sa.DateTime(), nullable=True),
        sa.Column('total_data_transferred', sa.Integer(), nullable=True),
        sa.Column('error_count', sa.Integer(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_integration_name', 'integrations', ['name'])
    op.create_index('idx_integration_type_provider', 'integrations', ['integration_type', 'provider'])
    op.create_index('idx_integration_status_enabled', 'integrations', ['status', 'is_enabled'])
    
    # Plugins table
    op.create_table('plugins',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('slug', sa.String(length=255), nullable=False),
        sa.Column('version', sa.String(length=50), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('long_description', sa.Text(), nullable=True),
        sa.Column('category', sa.String(length=50), nullable=False),
        sa.Column('plugin_type', sa.String(length=50), nullable=False),
        sa.Column('tags', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('author_id', sa.String(length=255), nullable=False),
        sa.Column('author_name', sa.String(length=255), nullable=False),
        sa.Column('author_email', sa.String(length=255), nullable=True),
        sa.Column('organization', sa.String(length=255), nullable=True),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('is_public', sa.Boolean(), nullable=False),
        sa.Column('is_featured', sa.Boolean(), nullable=False),
        sa.Column('is_verified', sa.Boolean(), nullable=False),
        sa.Column('is_premium', sa.Boolean(), nullable=False),
        sa.Column('package_url', sa.String(length=500), nullable=True),
        sa.Column('repository_url', sa.String(length=500), nullable=True),
        sa.Column('documentation_url', sa.String(length=500), nullable=True),
        sa.Column('homepage_url', sa.String(length=500), nullable=True),
        sa.Column('python_version', sa.String(length=50), nullable=True),
        sa.Column('mcp_version', sa.String(length=50), nullable=True),
        sa.Column('dependencies', sa.JSON(), nullable=True),
        sa.Column('system_requirements', sa.JSON(), nullable=True),
        sa.Column('config_schema', sa.JSON(), nullable=True),
        sa.Column('default_config', sa.JSON(), nullable=True),
        sa.Column('capabilities', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('download_count', sa.Integer(), nullable=True),
        sa.Column('install_count', sa.Integer(), nullable=True),
        sa.Column('rating_average', sa.Float(), nullable=True),
        sa.Column('rating_count', sa.Integer(), nullable=True),
        sa.Column('review_count', sa.Integer(), nullable=True),
        sa.Column('license', sa.String(length=100), nullable=True),
        sa.Column('support_email', sa.String(length=255), nullable=True),
        sa.Column('support_url', sa.String(length=500), nullable=True),
        sa.Column('submitted_at', sa.DateTime(), nullable=True),
        sa.Column('published_at', sa.DateTime(), nullable=True),
        sa.Column('last_updated', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('slug')
    )
    op.create_index('idx_plugin_name', 'plugins', ['name'])
    op.create_index('idx_plugin_category_status', 'plugins', ['category', 'status'])
    op.create_index('idx_plugin_author_status', 'plugins', ['author_id', 'status'])
    
    # Reports table
    op.create_table('reports',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('report_type', sa.String(length=50), nullable=False),
        sa.Column('format', sa.String(length=20), nullable=False),
        sa.Column('status', sa.String(length=50), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_by', sa.String(length=255), nullable=False),
        sa.Column('parameters', sa.JSON(), nullable=True),
        sa.Column('filters', sa.JSON(), nullable=True),
        sa.Column('template_id', postgresql.UUID(as_uuid=True), nullable=True),
        sa.Column('file_path', sa.String(length=500), nullable=True),
        sa.Column('file_size', sa.Integer(), nullable=True),
        sa.Column('generated_at', sa.DateTime(), nullable=True),
        sa.Column('expires_at', sa.DateTime(), nullable=True),
        sa.Column('is_scheduled', sa.Boolean(), nullable=False),
        sa.Column('schedule_config', sa.JSON(), nullable=True),
        sa.Column('distribution_list', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_report_type_status', 'reports', ['report_type', 'status'])
    op.create_index('idx_report_organization', 'reports', ['organization_id'])
    op.create_index('idx_report_created_by', 'reports', ['created_by'])
    
    # Policies table
    op.create_table('policies',
        sa.Column('id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('description', sa.Text(), nullable=True),
        sa.Column('policy_type', sa.String(length=50), nullable=False),
        sa.Column('target_type', sa.String(length=50), nullable=False),
        sa.Column('rules', sa.JSON(), nullable=False),
        sa.Column('organization_id', postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column('created_by', sa.String(length=255), nullable=False),
        sa.Column('is_active', sa.Boolean(), nullable=False),
        sa.Column('is_system', sa.Boolean(), nullable=False),
        sa.Column('priority', sa.Integer(), nullable=False),
        sa.Column('enforcement_mode', sa.String(length=20), nullable=False),
        sa.Column('tags', postgresql.ARRAY(sa.String()), nullable=True),
        sa.Column('metadata', sa.JSON(), nullable=True),
        sa.Column('last_applied', sa.DateTime(), nullable=True),
        sa.Column('created_at', sa.DateTime(), nullable=False),
        sa.Column('updated_at', sa.DateTime(), nullable=False),
        sa.ForeignKeyConstraint(['organization_id'], ['organizations.id'], ),
        sa.PrimaryKeyConstraint('id')
    )
    op.create_index('idx_policy_type_active', 'policies', ['policy_type', 'is_active'])
    op.create_index('idx_policy_organization', 'policies', ['organization_id'])


def downgrade():
    """Drop all tables."""
    op.drop_table('policies')
    op.drop_table('reports')
    op.drop_table('plugins')
    op.drop_table('integrations')
    op.drop_table('events')
    op.drop_table('vulnerabilities')
    op.drop_table('scans')
    op.drop_table('role_permissions')
    op.drop_table('user_roles')
    op.drop_table('permissions')
    op.drop_table('roles')
    op.drop_table('users')
    op.drop_table('organizations')