"""
Tests for authentication and authorization functionality.
"""
import pytest
from httpx import AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession

from core.security import verify_password, get_password_hash, create_access_token


class TestAuthentication:
    """Test authentication endpoints."""

    async def test_login_success(self, async_client: AsyncClient, test_user):
        """Test successful login."""
        response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "username": "testuser",
                "password": "testpass123"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"
        assert data["user"]["username"] == "testuser"
        assert data["user"]["email"] == "test@test.com"

    async def test_login_invalid_credentials(self, async_client: AsyncClient, test_user):
        """Test login with invalid credentials."""
        response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "username": "testuser",
                "password": "wrongpassword"
            }
        )
        
        assert response.status_code == 401
        assert "Invalid credentials" in response.json()["detail"]

    async def test_login_nonexistent_user(self, async_client: AsyncClient):
        """Test login with non-existent user."""
        response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "username": "nonexistent",
                "password": "password123"
            }
        )
        
        assert response.status_code == 401

    async def test_login_inactive_user(self, async_client: AsyncClient, db_session: AsyncSession):
        """Test login with inactive user."""
        from shared.database.models.users import User
        from shared.database.models.organizations import Organization
        from core.security import get_password_hash
        
        # Create inactive user
        org = Organization(
            name="Test Org",
            domain="test.com",
            subscription_tier="basic",
            is_active=True
        )
        db_session.add(org)
        await db_session.flush()
        
        inactive_user = User(
            username="inactive",
            email="inactive@test.com",
            hashed_password=get_password_hash("password123"),
            first_name="Inactive",
            last_name="User",
            organization_id=org.id,
            is_active=False,
            is_verified=True,
        )
        db_session.add(inactive_user)
        await db_session.commit()
        
        response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "username": "inactive",
                "password": "password123"
            }
        )
        
        assert response.status_code == 401
        assert "inactive" in response.json()["detail"].lower()

    async def test_get_current_user(self, async_client: AsyncClient, auth_headers):
        """Test getting current user information."""
        response = await async_client.get(
            "/api/v1/auth/me",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["username"] == "testuser"
        assert data["email"] == "test@test.com"
        assert "organization" in data

    async def test_get_current_user_unauthorized(self, async_client: AsyncClient):
        """Test getting current user without authentication."""
        response = await async_client.get("/api/v1/auth/me")
        
        assert response.status_code == 401

    async def test_get_current_user_invalid_token(self, async_client: AsyncClient):
        """Test getting current user with invalid token."""
        response = await async_client.get(
            "/api/v1/auth/me",
            headers={"Authorization": "Bearer invalid-token"}
        )
        
        assert response.status_code == 401

    async def test_refresh_token(self, async_client: AsyncClient, test_user):
        """Test token refresh functionality."""
        # First login to get tokens
        login_response = await async_client.post(
            "/api/v1/auth/login",
            json={
                "username": "testuser",
                "password": "testpass123"
            }
        )
        
        tokens = login_response.json()
        refresh_token = tokens["refresh_token"]
        
        # Use refresh token to get new access token
        response = await async_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": refresh_token}
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert "refresh_token" in data
        assert data["token_type"] == "bearer"

    async def test_refresh_token_invalid(self, async_client: AsyncClient):
        """Test refresh with invalid token."""
        response = await async_client.post(
            "/api/v1/auth/refresh",
            json={"refresh_token": "invalid-refresh-token"}
        )
        
        assert response.status_code == 401

    async def test_logout(self, async_client: AsyncClient, auth_headers):
        """Test user logout."""
        response = await async_client.post(
            "/api/v1/auth/logout",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        assert response.json()["message"] == "Successfully logged out"

    async def test_change_password(self, async_client: AsyncClient, auth_headers):
        """Test password change."""
        response = await async_client.post(
            "/api/v1/auth/change-password",
            headers=auth_headers,
            json={
                "current_password": "testpass123",
                "new_password": "newtestpass123"
            }
        )
        
        assert response.status_code == 200
        assert response.json()["message"] == "Password changed successfully"

    async def test_change_password_wrong_current(self, async_client: AsyncClient, auth_headers):
        """Test password change with wrong current password."""
        response = await async_client.post(
            "/api/v1/auth/change-password",
            headers=auth_headers,
            json={
                "current_password": "wrongpassword",
                "new_password": "newtestpass123"
            }
        )
        
        assert response.status_code == 400
        assert "current password" in response.json()["detail"].lower()


class TestAuthorization:
    """Test authorization and permissions."""

    async def test_admin_access_required(self, async_client: AsyncClient, auth_headers):
        """Test that admin endpoints require admin permissions."""
        response = await async_client.get(
            "/api/v1/admin/users",
            headers=auth_headers
        )
        
        assert response.status_code == 403
        assert "insufficient permissions" in response.json()["detail"].lower()

    async def test_admin_access_with_admin_user(self, async_client: AsyncClient, admin_auth_headers):
        """Test admin access with admin user."""
        response = await async_client.get(
            "/api/v1/admin/users",
            headers=admin_auth_headers
        )
        
        assert response.status_code == 200

    async def test_organization_isolation(self, async_client: AsyncClient, auth_headers, db_session: AsyncSession):
        """Test that users can only access their organization's data."""
        from shared.database.models.scans import Scan
        from shared.database.models.organizations import Organization
        from shared.database.models.users import User
        from core.security import get_password_hash
        
        # Create another organization and user
        other_org = Organization(
            name="Other Organization",
            domain="other.com",
            subscription_tier="basic",
            is_active=True
        )
        db_session.add(other_org)
        await db_session.flush()
        
        other_user = User(
            username="otheruser",
            email="other@other.com",
            hashed_password=get_password_hash("password123"),
            first_name="Other",
            last_name="User",
            organization_id=other_org.id,
            is_active=True,
            is_verified=True,
        )
        db_session.add(other_user)
        await db_session.flush()
        
        # Create scan for other organization
        other_scan = Scan(
            name="Other Organization Scan",
            type="network",
            target="10.0.0.0/24",
            status="completed",
            created_by=other_user.id,
            organization_id=other_org.id
        )
        db_session.add(other_scan)
        await db_session.commit()
        
        # Try to access other organization's scan
        response = await async_client.get(
            f"/api/v1/scans/{other_scan.id}",
            headers=auth_headers
        )
        
        assert response.status_code == 404  # Should not find the scan


class TestPasswordSecurity:
    """Test password security functions."""

    def test_password_hashing(self):
        """Test password hashing and verification."""
        password = "testpassword123"
        hashed = get_password_hash(password)
        
        assert hashed != password
        assert verify_password(password, hashed)
        assert not verify_password("wrongpassword", hashed)

    def test_password_hash_uniqueness(self):
        """Test that password hashes are unique."""
        password = "testpassword123"
        hash1 = get_password_hash(password)
        hash2 = get_password_hash(password)
        
        assert hash1 != hash2  # Should be different due to salt
        assert verify_password(password, hash1)
        assert verify_password(password, hash2)


class TestTokenSecurity:
    """Test JWT token security."""

    def test_token_creation_and_validation(self, test_user):
        """Test JWT token creation and validation."""
        from core.security import create_access_token, decode_access_token
        
        token_data = {"sub": test_user.username}
        token = create_access_token(data=token_data)
        
        assert token is not None
        assert isinstance(token, str)
        
        decoded_data = decode_access_token(token)
        assert decoded_data["sub"] == test_user.username

    def test_token_expiration(self):
        """Test token expiration."""
        from core.security import create_access_token, decode_access_token
        from datetime import timedelta
        
        # Create token with very short expiration
        token = create_access_token(
            data={"sub": "testuser"},
            expires_delta=timedelta(seconds=-1)  # Already expired
        )
        
        # Should raise exception when decoding expired token
        with pytest.raises(Exception):
            decode_access_token(token)

    def test_invalid_token(self):
        """Test invalid token handling."""
        from core.security import decode_access_token
        
        with pytest.raises(Exception):
            decode_access_token("invalid.token.here")


class TestUserPermissions:
    """Test user permission system."""

    async def test_user_permissions_check(self, async_client: AsyncClient, auth_headers):
        """Test user permissions endpoint."""
        response = await async_client.get(
            "/api/v1/auth/permissions",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "permissions" in data
        assert isinstance(data["permissions"], list)

    async def test_specific_permission_check(self, async_client: AsyncClient, auth_headers):
        """Test checking for specific permission."""
        response = await async_client.get(
            "/api/v1/auth/permissions/scan:read",
            headers=auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "has_permission" in data
        assert isinstance(data["has_permission"], bool)

    async def test_admin_permissions(self, async_client: AsyncClient, admin_auth_headers):
        """Test admin user permissions."""
        response = await async_client.get(
            "/api/v1/auth/permissions/admin:all",
            headers=admin_auth_headers
        )
        
        assert response.status_code == 200
        data = response.json()
        assert data["has_permission"] is True