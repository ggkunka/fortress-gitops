"""
Test configuration and fixtures for MCP Security Platform.
"""
import asyncio
import os
import pytest
import pytest_asyncio
from typing import AsyncGenerator, Generator
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker
from fastapi.testclient import TestClient
from httpx import AsyncClient

from core.config import Settings
from shared.database.models.base import BaseModel
from shared.database.session import get_db_session
from api.main import app


# Test database configuration
TEST_DATABASE_URL = "postgresql+asyncpg://test:test@localhost/mcp_security_test"

@pytest.fixture(scope="session")
def event_loop() -> Generator[asyncio.AbstractEventLoop, None, None]:
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture(scope="session")
def test_settings() -> Settings:
    """Test settings configuration."""
    return Settings(
        database_url=TEST_DATABASE_URL,
        secret_key="test-secret-key-for-testing-only",
        algorithm="HS256",
        access_token_expire_minutes=30,
        refresh_token_expire_days=7,
        environment="test",
        debug=True,
        testing=True,
    )


@pytest_asyncio.fixture(scope="session")
async def test_engine(test_settings: Settings):
    """Create test database engine."""
    engine = create_async_engine(
        test_settings.database_url,
        echo=False,
        future=True,
    )
    
    # Create all tables
    async with engine.begin() as conn:
        await conn.run_sync(BaseModel.metadata.create_all)
    
    yield engine
    
    # Drop all tables after tests
    async with engine.begin() as conn:
        await conn.run_sync(BaseModel.metadata.drop_all)
    
    await engine.dispose()


@pytest_asyncio.fixture
async def db_session(test_engine) -> AsyncGenerator[AsyncSession, None]:
    """Create a test database session."""
    async_session_maker = sessionmaker(
        test_engine, class_=AsyncSession, expire_on_commit=False
    )
    
    async with async_session_maker() as session:
        yield session
        await session.rollback()


@pytest.fixture
def override_get_db(db_session: AsyncSession):
    """Override the database dependency for testing."""
    async def _override_get_db():
        yield db_session
    
    app.dependency_overrides[get_db_session] = _override_get_db
    yield
    app.dependency_overrides.clear()


@pytest.fixture
def client(override_get_db) -> TestClient:
    """Create a test client."""
    return TestClient(app)


@pytest_asyncio.fixture
async def async_client(override_get_db) -> AsyncGenerator[AsyncClient, None]:
    """Create an async test client."""
    async with AsyncClient(app=app, base_url="http://testserver") as client:
        yield client


@pytest_asyncio.fixture
async def test_user(db_session: AsyncSession):
    """Create a test user."""
    from shared.database.models.users import User
    from shared.database.models.organizations import Organization
    from core.security import get_password_hash
    
    # Create test organization
    org = Organization(
        name="Test Organization",
        domain="test.com",
        subscription_tier="enterprise",
        is_active=True
    )
    db_session.add(org)
    await db_session.flush()
    
    # Create test user
    user = User(
        username="testuser",
        email="test@test.com",
        hashed_password=get_password_hash("testpass123"),
        first_name="Test",
        last_name="User",
        organization_id=org.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    
    return user


@pytest_asyncio.fixture
async def test_admin_user(db_session: AsyncSession):
    """Create a test admin user."""
    from shared.database.models.users import User
    from shared.database.models.organizations import Organization
    from shared.database.models.roles import Role, UserRole
    from core.security import get_password_hash
    
    # Create test organization
    org = Organization(
        name="Admin Test Organization",
        domain="admin.test.com",
        subscription_tier="enterprise",
        is_active=True
    )
    db_session.add(org)
    await db_session.flush()
    
    # Create admin role
    admin_role = Role(
        name="admin",
        description="Administrator role",
        organization_id=org.id,
        permissions=[
            "scan:create", "scan:read", "scan:update", "scan:delete",
            "vulnerability:create", "vulnerability:read", "vulnerability:update", "vulnerability:delete",
            "report:create", "report:read", "report:update", "report:delete",
            "integration:create", "integration:read", "integration:update", "integration:delete",
            "user:create", "user:read", "user:update", "user:delete",
            "admin:all"
        ]
    )
    db_session.add(admin_role)
    await db_session.flush()
    
    # Create admin user
    admin_user = User(
        username="admin",
        email="admin@test.com",
        hashed_password=get_password_hash("admin123"),
        first_name="Admin",
        last_name="User",
        organization_id=org.id,
        is_active=True,
        is_verified=True,
    )
    db_session.add(admin_user)
    await db_session.flush()
    
    # Assign admin role
    user_role = UserRole(
        user_id=admin_user.id,
        role_id=admin_role.id
    )
    db_session.add(user_role)
    
    await db_session.commit()
    await db_session.refresh(admin_user)
    
    return admin_user


@pytest_asyncio.fixture
async def auth_headers(test_user) -> dict:
    """Create authentication headers for test user."""
    from core.security import create_access_token
    
    access_token = create_access_token(data={"sub": test_user.username})
    return {"Authorization": f"Bearer {access_token}"}


@pytest_asyncio.fixture
async def admin_auth_headers(test_admin_user) -> dict:
    """Create authentication headers for admin user."""
    from core.security import create_access_token
    
    access_token = create_access_token(data={"sub": test_admin_user.username})
    return {"Authorization": f"Bearer {access_token}"}


@pytest_asyncio.fixture
async def test_scan(db_session: AsyncSession, test_user):
    """Create a test scan."""
    from shared.database.models.scans import Scan
    
    scan = Scan(
        name="Test Network Scan",
        type="network",
        target="192.168.1.0/24",
        status="completed",
        progress=100,
        created_by=test_user.id,
        organization_id=test_user.organization_id,
        scan_config={
            "ports": "1-1000",
            "timing_template": "normal",
            "scan_techniques": ["tcp_syn"]
        },
        results_summary={
            "hosts_discovered": 10,
            "services_detected": 25,
            "vulnerabilities_found": 5,
            "compliance_issues": 0
        }
    )
    db_session.add(scan)
    await db_session.commit()
    await db_session.refresh(scan)
    
    return scan


@pytest_asyncio.fixture
async def test_vulnerability(db_session: AsyncSession, test_user, test_scan):
    """Create a test vulnerability."""
    from shared.database.models.vulnerabilities import Vulnerability
    
    vulnerability = Vulnerability(
        title="Test SQL Injection",
        description="SQL injection vulnerability in test application",
        severity="high",
        cvss_score=8.5,
        cve_id="CVE-2024-TEST",
        asset="test.example.com",
        port=443,
        service="HTTPS",
        status="open",
        scan_id=test_scan.id,
        organization_id=test_user.organization_id,
        created_by=test_user.id,
        remediation="Use parameterized queries",
        references=["https://owasp.org/test"],
        tags=["sql-injection", "web-app"],
        risk_score=85
    )
    db_session.add(vulnerability)
    await db_session.commit()
    await db_session.refresh(vulnerability)
    
    return vulnerability


@pytest_asyncio.fixture
async def test_integration(db_session: AsyncSession, test_user):
    """Create a test integration."""
    from shared.database.models.integrations import Integration
    
    integration = Integration(
        name="Test Splunk Integration",
        type="siem",
        provider="splunk",
        status="connected",
        enabled=True,
        sync_frequency=15,
        organization_id=test_user.organization_id,
        created_by=test_user.id,
        config={
            "endpoint": "https://test-splunk.com:8089",
            "username": "test_user"
        },
        health={
            "status": "healthy",
            "last_check": "2024-01-15T10:00:00Z"
        },
        metrics={
            "events_ingested": 1000,
            "data_exported": 0,
            "sync_errors": 0,
            "uptime_percentage": 99.9
        }
    )
    db_session.add(integration)
    await db_session.commit()
    await db_session.refresh(integration)
    
    return integration


# Test data fixtures
@pytest.fixture
def sample_scan_data():
    """Sample scan data for testing."""
    return {
        "name": "Test API Scan",
        "type": "web",
        "target": "https://api.example.com",
        "description": "Test web application scan",
        "scan_config": {
            "ports": "80,443",
            "timing_template": "fast",
            "scan_techniques": ["tcp_syn", "tcp_connect"]
        }
    }


@pytest.fixture
def sample_vulnerability_data():
    """Sample vulnerability data for testing."""
    return {
        "title": "Test XSS Vulnerability",
        "description": "Cross-site scripting vulnerability",
        "severity": "medium",
        "cvss_score": 6.1,
        "asset": "web.example.com",
        "port": 443,
        "service": "HTTPS",
        "remediation": "Sanitize user input",
        "references": ["https://owasp.org/xss"],
        "tags": ["xss", "web-security"]
    }


@pytest.fixture
def sample_integration_data():
    """Sample integration data for testing."""
    return {
        "name": "Test AWS Integration",
        "type": "cloud_security",
        "provider": "aws",
        "config": {
            "region": "us-east-1",
            "account_id": "123456789012"
        },
        "sync_frequency": 30,
        "enabled": True
    }


# Mock external services
@pytest.fixture
def mock_scan_engine():
    """Mock scan engine for testing."""
    class MockScanEngine:
        async def start_scan(self, scan_config):
            return {"scan_id": "mock-scan-123", "status": "started"}
        
        async def get_scan_status(self, scan_id):
            return {"status": "running", "progress": 50}
        
        async def get_scan_results(self, scan_id):
            return {
                "vulnerabilities": [
                    {
                        "title": "Mock Vulnerability",
                        "severity": "medium",
                        "cvss_score": 5.0
                    }
                ]
            }
    
    return MockScanEngine()


@pytest.fixture
def mock_notification_service():
    """Mock notification service for testing."""
    class MockNotificationService:
        def __init__(self):
            self.sent_notifications = []
        
        async def send_notification(self, notification_data):
            self.sent_notifications.append(notification_data)
            return {"status": "sent", "id": "mock-notification-123"}
    
    return MockNotificationService()


# Environment setup
@pytest.fixture(autouse=True)
def setup_test_environment():
    """Setup test environment variables."""
    original_env = os.environ.copy()
    
    # Set test environment variables
    os.environ.update({
        "TESTING": "true",
        "DATABASE_URL": TEST_DATABASE_URL,
        "SECRET_KEY": "test-secret-key",
        "REDIS_URL": "redis://localhost:6379/1",
    })
    
    yield
    
    # Restore original environment
    os.environ.clear()
    os.environ.update(original_env)