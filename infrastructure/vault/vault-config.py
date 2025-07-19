"""
HashiCorp Vault Integration Service

This service provides comprehensive secret management integration with HashiCorp Vault
for the MCP Security Platform, including dynamic secrets, encryption, and PKI.
"""

import asyncio
import json
import base64
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union
import aiohttp
import hvac
from hvac.adapters import JSONAdapter
from pathlib import Path
import ssl
import certifi

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

logger = get_logger(__name__)
metrics = get_metrics()


class VaultAuthMethod:
    """Vault authentication methods."""
    TOKEN = "token"
    KUBERNETES = "kubernetes"
    LDAP = "ldap"
    USERPASS = "userpass"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    JWT = "jwt"
    OIDC = "oidc"


class VaultSecretEngine:
    """Vault secret engines."""
    KV_V1 = "kv"
    KV_V2 = "kv-v2"
    DATABASE = "database"
    PKI = "pki"
    TRANSIT = "transit"
    SSH = "ssh"
    AWS = "aws"
    AZURE = "azure"
    GCP = "gcp"
    KUBERNETES = "kubernetes"


class VaultClient:
    """
    Enhanced Vault client with advanced features for the MCP Security Platform.
    
    Features:
    - Multiple authentication methods
    - Secret management (static and dynamic)
    - Encryption as a Service (Transit)
    - PKI certificate management
    - Database credential rotation
    - Kubernetes service account tokens
    - Policy management
    - Audit logging integration
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Vault configuration
        self.vault_url = self.config.get("vault_url", "https://vault.mcp-platform.local:8200")
        self.vault_namespace = self.config.get("vault_namespace", "mcp")
        self.auth_method = self.config.get("auth_method", VaultAuthMethod.KUBERNETES)
        self.mount_point = self.config.get("mount_point", "mcp-secrets")
        
        # Authentication configuration
        self.auth_config = self.config.get("auth_config", {})
        self.token_file = self.config.get("token_file", "/var/run/secrets/kubernetes.io/serviceaccount/token")
        self.role = self.config.get("role", "mcp-security-platform")
        
        # Vault client
        self.client: Optional[hvac.Client] = None
        self.token_renewal_task: Optional[asyncio.Task] = None
        
        # SSL configuration
        self.verify_ssl = self.config.get("verify_ssl", True)
        self.ca_cert_path = self.config.get("ca_cert_path")
        self.client_cert_path = self.config.get("client_cert_path")
        self.client_key_path = self.config.get("client_key_path")
        
        # Caching
        self.secret_cache: Dict[str, Dict[str, Any]] = {}
        self.cache_ttl = self.config.get("cache_ttl", 300)  # 5 minutes
        
        logger.info("Vault client initialized")
    
    async def initialize(self) -> bool:
        """Initialize Vault client and authenticate."""
        try:
            # Create SSL context
            ssl_context = self._create_ssl_context()
            
            # Initialize Vault client
            self.client = hvac.Client(
                url=self.vault_url,
                namespace=self.vault_namespace,
                verify=ssl_context if self.verify_ssl else False
            )
            
            # Authenticate
            auth_success = await self._authenticate()
            if not auth_success:
                raise RuntimeError("Vault authentication failed")
            
            # Start token renewal task
            if self.auth_method in [VaultAuthMethod.KUBERNETES, VaultAuthMethod.JWT]:
                self.token_renewal_task = asyncio.create_task(self._token_renewal_loop())
            
            # Initialize secret engines
            await self._initialize_secret_engines()
            
            logger.info("Vault client initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Vault client: {e}")
            return False
    
    async def cleanup(self) -> bool:
        """Cleanup Vault client."""
        try:
            # Cancel token renewal task
            if self.token_renewal_task:
                self.token_renewal_task.cancel()
                try:
                    await self.token_renewal_task
                except asyncio.CancelledError:
                    pass
            
            # Revoke token if needed
            if self.client and self.client.token:
                try:
                    self.client.auth.token.revoke_self()
                except Exception as e:
                    logger.warning(f"Failed to revoke token: {e}")
            
            logger.info("Vault client cleaned up successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup Vault client: {e}")
            return False
    
    @traced("vault_get_secret")
    async def get_secret(self, path: str, version: Optional[int] = None) -> Optional[Dict[str, Any]]:
        """Get secret from Vault."""
        try:
            # Check cache first
            cache_key = f"{path}:{version or 'latest'}"
            if cache_key in self.secret_cache:
                cached_secret = self.secret_cache[cache_key]
                if self._is_cache_valid(cached_secret):
                    logger.debug(f"Retrieved secret from cache: {path}")
                    return cached_secret["data"]
            
            # Read from Vault
            if self.mount_point.endswith("kv-v2") or version is not None:
                # KV v2 engine
                response = self.client.secrets.kv.v2.read_secret_version(
                    path=path,
                    version=version,
                    mount_point=self.mount_point
                )
                secret_data = response["data"]["data"]
            else:
                # KV v1 engine
                response = self.client.secrets.kv.v1.read_secret(
                    path=path,
                    mount_point=self.mount_point
                )
                secret_data = response["data"]
            
            # Cache the secret
            self.secret_cache[cache_key] = {
                "data": secret_data,
                "timestamp": datetime.now(timezone.utc),
                "ttl": self.cache_ttl
            }
            
            logger.debug(f"Retrieved secret from Vault: {path}")
            metrics.vault_secrets_retrieved.inc()
            return secret_data
            
        except Exception as e:
            logger.error(f"Failed to get secret {path}: {e}")
            metrics.vault_errors.inc()
            return None
    
    @traced("vault_put_secret")
    async def put_secret(self, path: str, secret: Dict[str, Any]) -> bool:
        """Put secret to Vault."""
        try:
            if self.mount_point.endswith("kv-v2"):
                # KV v2 engine
                self.client.secrets.kv.v2.create_or_update_secret(
                    path=path,
                    secret=secret,
                    mount_point=self.mount_point
                )
            else:
                # KV v1 engine
                self.client.secrets.kv.v1.create_or_update_secret(
                    path=path,
                    secret=secret,
                    mount_point=self.mount_point
                )
            
            # Invalidate cache
            cache_keys_to_remove = [k for k in self.secret_cache.keys() if k.startswith(f"{path}:")]
            for cache_key in cache_keys_to_remove:
                del self.secret_cache[cache_key]
            
            logger.debug(f"Put secret to Vault: {path}")
            metrics.vault_secrets_stored.inc()
            return True
            
        except Exception as e:
            logger.error(f"Failed to put secret {path}: {e}")
            metrics.vault_errors.inc()
            return False
    
    @traced("vault_delete_secret")
    async def delete_secret(self, path: str, versions: Optional[List[int]] = None) -> bool:
        """Delete secret from Vault."""
        try:
            if self.mount_point.endswith("kv-v2"):
                if versions:
                    # Delete specific versions
                    self.client.secrets.kv.v2.delete_secret_versions(
                        path=path,
                        versions=versions,
                        mount_point=self.mount_point
                    )
                else:
                    # Delete latest version
                    self.client.secrets.kv.v2.delete_latest_version_of_secret(
                        path=path,
                        mount_point=self.mount_point
                    )
            else:
                # KV v1 engine
                self.client.secrets.kv.v1.delete_secret(
                    path=path,
                    mount_point=self.mount_point
                )
            
            # Invalidate cache
            cache_keys_to_remove = [k for k in self.secret_cache.keys() if k.startswith(f"{path}:")]
            for cache_key in cache_keys_to_remove:
                del self.secret_cache[cache_key]
            
            logger.debug(f"Deleted secret from Vault: {path}")
            metrics.vault_secrets_deleted.inc()
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete secret {path}: {e}")
            metrics.vault_errors.inc()
            return False
    
    @traced("vault_encrypt_data")
    async def encrypt_data(self, plaintext: str, key_name: str = "mcp-encryption-key") -> Optional[str]:
        """Encrypt data using Vault Transit engine."""
        try:
            # Encode plaintext to base64
            plaintext_b64 = base64.b64encode(plaintext.encode()).decode()
            
            # Encrypt using Transit engine
            response = self.client.secrets.transit.encrypt_data(
                name=key_name,
                plaintext=plaintext_b64,
                mount_point="transit"
            )
            
            ciphertext = response["data"]["ciphertext"]
            
            logger.debug("Encrypted data using Vault Transit")
            metrics.vault_encryptions.inc()
            return ciphertext
            
        except Exception as e:
            logger.error(f"Failed to encrypt data: {e}")
            metrics.vault_errors.inc()
            return None
    
    @traced("vault_decrypt_data")
    async def decrypt_data(self, ciphertext: str, key_name: str = "mcp-encryption-key") -> Optional[str]:
        """Decrypt data using Vault Transit engine."""
        try:
            # Decrypt using Transit engine
            response = self.client.secrets.transit.decrypt_data(
                name=key_name,
                ciphertext=ciphertext,
                mount_point="transit"
            )
            
            # Decode from base64
            plaintext_b64 = response["data"]["plaintext"]
            plaintext = base64.b64decode(plaintext_b64).decode()
            
            logger.debug("Decrypted data using Vault Transit")
            metrics.vault_decryptions.inc()
            return plaintext
            
        except Exception as e:
            logger.error(f"Failed to decrypt data: {e}")
            metrics.vault_errors.inc()
            return None
    
    @traced("vault_generate_certificate")
    async def generate_certificate(
        self,
        common_name: str,
        role_name: str = "mcp-server",
        ttl: str = "8760h",  # 1 year
        alt_names: Optional[List[str]] = None,
        ip_sans: Optional[List[str]] = None
    ) -> Optional[Dict[str, str]]:
        """Generate certificate using Vault PKI engine."""
        try:
            # Generate certificate
            response = self.client.secrets.pki.generate_certificate(
                name=role_name,
                common_name=common_name,
                alt_names=alt_names,
                ip_sans=ip_sans,
                ttl=ttl,
                mount_point="pki"
            )
            
            certificate_data = response["data"]
            
            logger.info(f"Generated certificate for {common_name}")
            metrics.vault_certificates_generated.inc()
            return {
                "certificate": certificate_data["certificate"],
                "private_key": certificate_data["private_key"],
                "ca_chain": certificate_data.get("ca_chain", []),
                "serial_number": certificate_data["serial_number"]
            }
            
        except Exception as e:
            logger.error(f"Failed to generate certificate for {common_name}: {e}")
            metrics.vault_errors.inc()
            return None
    
    @traced("vault_revoke_certificate")
    async def revoke_certificate(self, serial_number: str) -> bool:
        """Revoke certificate using Vault PKI engine."""
        try:
            self.client.secrets.pki.revoke_certificate(
                serial_number=serial_number,
                mount_point="pki"
            )
            
            logger.info(f"Revoked certificate {serial_number}")
            metrics.vault_certificates_revoked.inc()
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke certificate {serial_number}: {e}")
            metrics.vault_errors.inc()
            return False
    
    @traced("vault_get_database_credentials")
    async def get_database_credentials(self, role_name: str) -> Optional[Dict[str, str]]:
        """Get dynamic database credentials."""
        try:
            response = self.client.secrets.database.generate_credentials(
                name=role_name,
                mount_point="database"
            )
            
            credentials = response["data"]
            
            logger.info(f"Generated database credentials for role {role_name}")
            metrics.vault_db_credentials_generated.inc()
            return {
                "username": credentials["username"],
                "password": credentials["password"],
                "lease_id": response["lease_id"],
                "lease_duration": response["lease_duration"]
            }
            
        except Exception as e:
            logger.error(f"Failed to get database credentials for {role_name}: {e}")
            metrics.vault_errors.inc()
            return None
    
    @traced("vault_renew_lease")
    async def renew_lease(self, lease_id: str, increment: Optional[int] = None) -> bool:
        """Renew a Vault lease."""
        try:
            self.client.sys.renew_lease(
                lease_id=lease_id,
                increment=increment
            )
            
            logger.debug(f"Renewed lease {lease_id}")
            metrics.vault_leases_renewed.inc()
            return True
            
        except Exception as e:
            logger.error(f"Failed to renew lease {lease_id}: {e}")
            metrics.vault_errors.inc()
            return False
    
    @traced("vault_revoke_lease")
    async def revoke_lease(self, lease_id: str) -> bool:
        """Revoke a Vault lease."""
        try:
            self.client.sys.revoke_lease(lease_id=lease_id)
            
            logger.debug(f"Revoked lease {lease_id}")
            metrics.vault_leases_revoked.inc()
            return True
            
        except Exception as e:
            logger.error(f"Failed to revoke lease {lease_id}: {e}")
            metrics.vault_errors.inc()
            return False
    
    async def create_policy(self, name: str, policy: str) -> bool:
        """Create or update Vault policy."""
        try:
            self.client.sys.create_or_update_policy(
                name=name,
                policy=policy
            )
            
            logger.info(f"Created/updated policy {name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create policy {name}: {e}")
            return False
    
    async def delete_policy(self, name: str) -> bool:
        """Delete Vault policy."""
        try:
            self.client.sys.delete_policy(name=name)
            
            logger.info(f"Deleted policy {name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete policy {name}: {e}")
            return False
    
    async def get_audit_logs(self, path: str = "file") -> Optional[Dict[str, Any]]:
        """Get audit log configuration."""
        try:
            response = self.client.sys.list_enabled_audit_devices()
            return response.get(f"{path}/")
            
        except Exception as e:
            logger.error(f"Failed to get audit logs: {e}")
            return None
    
    async def _authenticate(self) -> bool:
        """Authenticate with Vault using configured method."""
        try:
            if self.auth_method == VaultAuthMethod.TOKEN:
                token = self.auth_config.get("token")
                if not token:
                    raise ValueError("Token not provided for token authentication")
                self.client.token = token
                
            elif self.auth_method == VaultAuthMethod.KUBERNETES:
                # Read service account token
                if Path(self.token_file).exists():
                    with open(self.token_file, 'r') as f:
                        jwt_token = f.read().strip()
                else:
                    jwt_token = self.auth_config.get("jwt_token")
                
                if not jwt_token:
                    raise ValueError("Kubernetes service account token not found")
                
                # Authenticate with Kubernetes auth method
                response = self.client.auth.kubernetes.login(
                    role=self.role,
                    jwt=jwt_token,
                    mount_point=self.auth_config.get("mount_point", "kubernetes")
                )
                self.client.token = response["auth"]["client_token"]
                
            elif self.auth_method == VaultAuthMethod.USERPASS:
                username = self.auth_config.get("username")
                password = self.auth_config.get("password")
                
                if not username or not password:
                    raise ValueError("Username and password required for userpass authentication")
                
                response = self.client.auth.userpass.login(
                    username=username,
                    password=password,
                    mount_point=self.auth_config.get("mount_point", "userpass")
                )
                self.client.token = response["auth"]["client_token"]
                
            elif self.auth_method == VaultAuthMethod.JWT:
                jwt_token = self.auth_config.get("jwt_token")
                
                if not jwt_token:
                    raise ValueError("JWT token required for JWT authentication")
                
                response = self.client.auth.jwt.login(
                    role=self.role,
                    jwt=jwt_token,
                    mount_point=self.auth_config.get("mount_point", "jwt")
                )
                self.client.token = response["auth"]["client_token"]
                
            else:
                raise ValueError(f"Unsupported authentication method: {self.auth_method}")
            
            # Verify authentication
            if not self.client.is_authenticated():
                raise RuntimeError("Vault authentication verification failed")
            
            logger.info(f"Successfully authenticated with Vault using {self.auth_method}")
            return True
            
        except Exception as e:
            logger.error(f"Vault authentication failed: {e}")
            return False
    
    async def _token_renewal_loop(self):
        """Background task for token renewal."""
        while True:
            try:
                # Check token info
                token_info = self.client.auth.token.lookup_self()
                ttl = token_info["data"]["ttl"]
                
                # Renew when 1/3 of TTL remaining
                sleep_time = max(ttl // 3, 60)  # At least 60 seconds
                
                await asyncio.sleep(sleep_time)
                
                # Renew token
                self.client.auth.token.renew_self()
                logger.debug("Renewed Vault token")
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Token renewal failed: {e}")
                await asyncio.sleep(60)  # Retry in 1 minute
    
    async def _initialize_secret_engines(self):
        """Initialize required secret engines."""
        try:
            # Enable KV v2 secrets engine
            try:
                self.client.sys.enable_secrets_engine(
                    backend_type="kv-v2",
                    path=self.mount_point
                )
            except Exception:
                # Engine might already be enabled
                pass
            
            # Enable Transit engine for encryption
            try:
                self.client.sys.enable_secrets_engine(
                    backend_type="transit",
                    path="transit"
                )
                
                # Create encryption key
                self.client.secrets.transit.create_key(
                    name="mcp-encryption-key",
                    mount_point="transit"
                )
            except Exception:
                # Engine/key might already exist
                pass
            
            # Enable PKI engine
            try:
                self.client.sys.enable_secrets_engine(
                    backend_type="pki",
                    path="pki"
                )
                
                # Configure PKI
                self.client.secrets.pki.set_urls(
                    issuing_certificates=f"{self.vault_url}/v1/pki/ca",
                    crl_distribution_points=f"{self.vault_url}/v1/pki/crl",
                    mount_point="pki"
                )
            except Exception:
                # Engine might already be enabled
                pass
            
            logger.debug("Initialized Vault secret engines")
            
        except Exception as e:
            logger.warning(f"Failed to initialize some secret engines: {e}")
    
    def _create_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Create SSL context for Vault connection."""
        if not self.verify_ssl:
            return None
        
        try:
            context = ssl.create_default_context(cafile=certifi.where())
            
            if self.ca_cert_path:
                context.load_verify_locations(self.ca_cert_path)
            
            if self.client_cert_path and self.client_key_path:
                context.load_cert_chain(self.client_cert_path, self.client_key_path)
            
            return context
            
        except Exception as e:
            logger.warning(f"Failed to create SSL context: {e}")
            return ssl.create_default_context()
    
    def _is_cache_valid(self, cached_item: Dict[str, Any]) -> bool:
        """Check if cached item is still valid."""
        timestamp = cached_item["timestamp"]
        ttl = cached_item["ttl"]
        
        return (datetime.now(timezone.utc) - timestamp).total_seconds() < ttl


class VaultSecretManager:
    """
    High-level secret manager for MCP Security Platform.
    
    Provides simplified interface for common secret operations.
    """
    
    def __init__(self, vault_client: VaultClient):
        self.vault = vault_client
        
        # Secret paths
        self.database_secrets_path = "database"
        self.api_keys_path = "api-keys"
        self.certificates_path = "certificates"
        self.encryption_keys_path = "encryption"
        
    async def get_database_connection_string(self, database_name: str) -> Optional[str]:
        """Get database connection string."""
        secret = await self.vault.get_secret(f"{self.database_secrets_path}/{database_name}")
        if secret:
            return secret.get("connection_string")
        return None
    
    async def get_api_key(self, service_name: str) -> Optional[str]:
        """Get API key for external service."""
        secret = await self.vault.get_secret(f"{self.api_keys_path}/{service_name}")
        if secret:
            return secret.get("api_key")
        return None
    
    async def store_api_key(self, service_name: str, api_key: str) -> bool:
        """Store API key for external service."""
        return await self.vault.put_secret(
            f"{self.api_keys_path}/{service_name}",
            {"api_key": api_key}
        )
    
    async def get_certificate(self, service_name: str) -> Optional[Dict[str, str]]:
        """Get TLS certificate for service."""
        secret = await self.vault.get_secret(f"{self.certificates_path}/{service_name}")
        if secret:
            return {
                "certificate": secret.get("certificate"),
                "private_key": secret.get("private_key"),
                "ca_chain": secret.get("ca_chain")
            }
        return None
    
    async def generate_service_certificate(self, service_name: str, common_name: str) -> Optional[Dict[str, str]]:
        """Generate and store certificate for service."""
        cert_data = await self.vault.generate_certificate(
            common_name=common_name,
            role_name="mcp-server",
            alt_names=[f"{service_name}.mcp-security-platform.local"]
        )
        
        if cert_data:
            # Store certificate in KV store
            await self.vault.put_secret(
                f"{self.certificates_path}/{service_name}",
                cert_data
            )
        
        return cert_data
    
    async def encrypt_sensitive_data(self, data: str) -> Optional[str]:
        """Encrypt sensitive data."""
        return await self.vault.encrypt_data(data)
    
    async def decrypt_sensitive_data(self, encrypted_data: str) -> Optional[str]:
        """Decrypt sensitive data."""
        return await self.vault.decrypt_data(encrypted_data)


# Vault policies for MCP Security Platform
VAULT_POLICIES = {
    "mcp-scan-service": """
        # Scan service policy
        path "mcp-secrets/data/scanners/*" {
          capabilities = ["read"]
        }
        
        path "mcp-secrets/data/api-keys/vulnerability-feeds" {
          capabilities = ["read"]
        }
        
        path "transit/encrypt/mcp-encryption-key" {
          capabilities = ["update"]
        }
        
        path "transit/decrypt/mcp-encryption-key" {
          capabilities = ["update"]
        }
    """,
    
    "mcp-compliance-service": """
        # Compliance service policy
        path "mcp-secrets/data/compliance/*" {
          capabilities = ["read", "create", "update"]
        }
        
        path "mcp-secrets/data/certificates/compliance-*" {
          capabilities = ["read"]
        }
        
        path "pki/issue/mcp-server" {
          capabilities = ["update"]
        }
    """,
    
    "mcp-admin": """
        # Admin policy for MCP platform
        path "mcp-secrets/*" {
          capabilities = ["create", "read", "update", "delete", "list"]
        }
        
        path "transit/*" {
          capabilities = ["create", "read", "update", "delete", "list"]
        }
        
        path "pki/*" {
          capabilities = ["create", "read", "update", "delete", "list"]
        }
        
        path "database/*" {
          capabilities = ["create", "read", "update", "delete", "list"]
        }
        
        path "sys/policies/acl/*" {
          capabilities = ["create", "read", "update", "delete", "list"]
        }
    """
}