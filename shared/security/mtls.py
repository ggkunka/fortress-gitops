"""
Mutual TLS (mTLS) implementation for secure service-to-service communication.
"""

import ssl
import os
import logging
from typing import Dict, Optional, List, Tuple
from dataclasses import dataclass
from pathlib import Path
import socket
import time
from datetime import datetime, timedelta

import httpx
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

from ..observability.logging import get_logger


@dataclass
class MTLSConfig:
    """Configuration for mTLS."""
    # Certificate paths
    ca_cert_path: str
    server_cert_path: str
    server_key_path: str
    client_cert_path: Optional[str] = None
    client_key_path: Optional[str] = None
    
    # Certificate validation
    verify_mode: ssl.VerifyMode = ssl.CERT_REQUIRED
    check_hostname: bool = True
    verify_client_cert: bool = True
    
    # TLS configuration
    protocol: ssl.Protocol = ssl.PROTOCOL_TLS
    ciphers: str = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20:!aNULL:!MD5:!DSS"
    
    # Certificate rotation
    cert_refresh_interval: int = 3600  # 1 hour
    cert_check_interval: int = 300     # 5 minutes
    
    # Service identification
    service_name: str = "mcp-service"
    allowed_services: List[str] = None


class CertificateManager:
    """Manages X.509 certificates for mTLS."""
    
    def __init__(self, config: MTLSConfig):
        self.config = config
        self.logger = get_logger("mtls.cert_manager")
    
    def generate_ca_certificate(self, 
                               common_name: str = "MCP Security Platform CA",
                               validity_days: int = 365) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Generate a Certificate Authority (CA) certificate."""
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=4096,
            backend=default_backend()
        )
        
        # Create certificate subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MCP Security Platform"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Security"),
            x509.NameAttribute(NameOID.COMMON_NAME, common_name),
        ])
        
        # Create certificate
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            subject  # Self-signed
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=True,
                crl_sign=True,
                digital_signature=False,
                key_encipherment=False,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).sign(private_key, hashes.SHA256(), default_backend())
        
        return cert, private_key
    
    def generate_service_certificate(self,
                                   service_name: str,
                                   ca_cert: x509.Certificate,
                                   ca_private_key: rsa.RSAPrivateKey,
                                   san_list: List[str] = None,
                                   validity_days: int = 90) -> Tuple[x509.Certificate, rsa.RSAPrivateKey]:
        """Generate a service certificate signed by the CA."""
        
        # Generate private key
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        
        # Create certificate subject
        subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
            x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
            x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "MCP Security Platform"),
            x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, "Services"),
            x509.NameAttribute(NameOID.COMMON_NAME, service_name),
        ])
        
        # Subject Alternative Names
        san_names = [x509.DNSName(service_name)]
        if san_list:
            san_names.extend([x509.DNSName(name) for name in san_list])
        
        # Add localhost and service variations
        san_names.extend([
            x509.DNSName("localhost"),
            x509.DNSName(f"{service_name}.default.svc.cluster.local"),
            x509.DNSName(f"{service_name}.mcp.svc.cluster.local"),
            x509.IPAddress(socket.inet_aton("127.0.0.1")),
        ])
        
        # Create certificate
        cert = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_cert.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=validity_days)
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                key_cert_sign=False,
                crl_sign=False,
                digital_signature=True,
                key_encipherment=True,
                key_agreement=False,
                content_commitment=False,
                data_encipherment=False,
                encipher_only=False,
                decipher_only=False
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([
                x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH,
                x509.oid.ExtendedKeyUsageOID.SERVER_AUTH,
            ]),
            critical=True,
        ).add_extension(
            x509.SubjectAlternativeName(san_names),
            critical=False,
        ).sign(ca_private_key, hashes.SHA256(), default_backend())
        
        return cert, private_key
    
    def save_certificate(self, cert: x509.Certificate, path: str):
        """Save certificate to PEM file."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        with open(path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
        
        # Set restrictive permissions
        os.chmod(path, 0o644)
        
        self.logger.info(f"Certificate saved to {path}")
    
    def save_private_key(self, private_key: rsa.RSAPrivateKey, path: str, password: bytes = None):
        """Save private key to PEM file."""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        encryption_algorithm = serialization.NoEncryption()
        if password:
            encryption_algorithm = serialization.BestAvailableEncryption(password)
        
        with open(path, 'wb') as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=encryption_algorithm
            ))
        
        # Set restrictive permissions
        os.chmod(path, 0o600)
        
        self.logger.info(f"Private key saved to {path}")
    
    def load_certificate(self, path: str) -> x509.Certificate:
        """Load certificate from PEM file."""
        with open(path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read(), default_backend())
        
        return cert
    
    def load_private_key(self, path: str, password: bytes = None) -> rsa.RSAPrivateKey:
        """Load private key from PEM file."""
        with open(path, 'rb') as f:
            key = serialization.load_pem_private_key(
                f.read(), 
                password=password, 
                backend=default_backend()
            )
        
        return key
    
    def verify_certificate_chain(self, cert: x509.Certificate, ca_cert: x509.Certificate) -> bool:
        """Verify certificate is signed by CA."""
        try:
            ca_public_key = ca_cert.public_key()
            ca_public_key.verify(
                cert.signature,
                cert.tbs_certificate_bytes,
                cert.signature_algorithm_oid._name
            )
            return True
        except Exception as e:
            self.logger.error(f"Certificate verification failed: {e}")
            return False
    
    def check_certificate_expiry(self, cert: x509.Certificate, warning_days: int = 30) -> bool:
        """Check if certificate is expiring soon."""
        expiry = cert.not_valid_after
        warning_time = datetime.utcnow() + timedelta(days=warning_days)
        
        if expiry <= warning_time:
            days_left = (expiry - datetime.utcnow()).days
            self.logger.warning(f"Certificate expires in {days_left} days: {cert.subject}")
            return True
        
        return False


class MTLSManager:
    """Manages mTLS configuration and contexts."""
    
    def __init__(self, config: MTLSConfig):
        self.config = config
        self.logger = get_logger("mtls.manager")
        self.cert_manager = CertificateManager(config)
        self._server_context = None
        self._client_context = None
        self._last_cert_check = 0
    
    def create_server_context(self) -> ssl.SSLContext:
        """Create SSL context for server (accepting connections)."""
        context = ssl.SSLContext(self.config.protocol)
        
        # Load server certificate and key
        context.load_cert_chain(
            self.config.server_cert_path,
            self.config.server_key_path
        )
        
        # Load CA certificate for client verification
        context.load_verify_locations(self.config.ca_cert_path)
        
        # Configure verification
        context.verify_mode = self.config.verify_mode
        context.check_hostname = False  # We'll verify manually for services
        
        if self.config.verify_client_cert:
            context.verify_mode = ssl.CERT_REQUIRED
        
        # Set cipher suite
        context.set_ciphers(self.config.ciphers)
        
        # Set protocols
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        
        self.logger.info("Server SSL context created")
        return context
    
    def create_client_context(self) -> ssl.SSLContext:
        """Create SSL context for client (making connections)."""
        context = ssl.SSLContext(self.config.protocol)
        
        # Load client certificate and key if provided
        if self.config.client_cert_path and self.config.client_key_path:
            context.load_cert_chain(
                self.config.client_cert_path,
                self.config.client_key_path
            )
        
        # Load CA certificate for server verification
        context.load_verify_locations(self.config.ca_cert_path)
        
        # Configure verification
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = self.config.check_hostname
        
        # Set cipher suite
        context.set_ciphers(self.config.ciphers)
        
        # Set protocols
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        
        self.logger.info("Client SSL context created")
        return context
    
    def get_server_context(self) -> ssl.SSLContext:
        """Get cached server context, refresh if needed."""
        current_time = time.time()
        
        if (self._server_context is None or 
            current_time - self._last_cert_check > self.config.cert_check_interval):
            
            self._check_certificate_renewal()
            self._server_context = self.create_server_context()
            self._last_cert_check = current_time
        
        return self._server_context
    
    def get_client_context(self) -> ssl.SSLContext:
        """Get cached client context, refresh if needed."""
        current_time = time.time()
        
        if (self._client_context is None or 
            current_time - self._last_cert_check > self.config.cert_check_interval):
            
            self._check_certificate_renewal()
            self._client_context = self.create_client_context()
            self._last_cert_check = current_time
        
        return self._client_context
    
    def _check_certificate_renewal(self):
        """Check if certificates need renewal."""
        try:
            # Check server certificate
            if os.path.exists(self.config.server_cert_path):
                cert = self.cert_manager.load_certificate(self.config.server_cert_path)
                self.cert_manager.check_certificate_expiry(cert)
            
            # Check client certificate
            if (self.config.client_cert_path and 
                os.path.exists(self.config.client_cert_path)):
                cert = self.cert_manager.load_certificate(self.config.client_cert_path)
                self.cert_manager.check_certificate_expiry(cert)
        
        except Exception as e:
            self.logger.error(f"Certificate check failed: {e}")
    
    def verify_peer_certificate(self, peer_cert: x509.Certificate) -> bool:
        """Verify peer certificate against allowed services."""
        try:
            # Load CA certificate
            ca_cert = self.cert_manager.load_certificate(self.config.ca_cert_path)
            
            # Verify certificate chain
            if not self.cert_manager.verify_certificate_chain(peer_cert, ca_cert):
                self.logger.warning("Peer certificate chain verification failed")
                return False
            
            # Check expiry
            if peer_cert.not_valid_after <= datetime.utcnow():
                self.logger.warning("Peer certificate has expired")
                return False
            
            # Extract service name from certificate
            common_name = None
            for attribute in peer_cert.subject:
                if attribute.oid == NameOID.COMMON_NAME:
                    common_name = attribute.value
                    break
            
            # Check if service is allowed
            if self.config.allowed_services and common_name:
                if common_name not in self.config.allowed_services:
                    self.logger.warning(f"Service {common_name} not in allowed list")
                    return False
            
            self.logger.info(f"Peer certificate verified for service: {common_name}")
            return True
            
        except Exception as e:
            self.logger.error(f"Peer certificate verification failed: {e}")
            return False


class MTLSHTTPXClient:
    """HTTPX client with mTLS support."""
    
    def __init__(self, mtls_manager: MTLSManager, base_url: str = None):
        self.mtls_manager = mtls_manager
        self.base_url = base_url
        self.logger = get_logger("mtls.httpx_client")
    
    def create_client(self, **kwargs) -> httpx.AsyncClient:
        """Create HTTPX client with mTLS configuration."""
        
        # Get client SSL context
        ssl_context = self.mtls_manager.get_client_context()
        
        # Create client with mTLS
        client_kwargs = {
            'verify': ssl_context,
            'timeout': httpx.Timeout(30.0),
            **kwargs
        }
        
        if self.base_url:
            client_kwargs['base_url'] = self.base_url
        
        return httpx.AsyncClient(**client_kwargs)
    
    async def request(self, method: str, url: str, **kwargs) -> httpx.Response:
        """Make HTTP request with mTLS."""
        async with self.create_client() as client:
            response = await client.request(method, url, **kwargs)
            
            # Log certificate information
            if hasattr(response, 'stream') and hasattr(response.stream, '_transport'):
                transport = response.stream._transport
                if hasattr(transport, 'get_extra_info'):
                    ssl_object = transport.get_extra_info('ssl_object')
                    if ssl_object:
                        peer_cert = ssl_object.getpeercert(binary_form=True)
                        if peer_cert:
                            cert = x509.load_der_x509_certificate(peer_cert, default_backend())
                            self.logger.debug(f"Connected to service: {cert.subject}")
            
            return response
    
    async def get(self, url: str, **kwargs) -> httpx.Response:
        """Make GET request with mTLS."""
        return await self.request("GET", url, **kwargs)
    
    async def post(self, url: str, **kwargs) -> httpx.Response:
        """Make POST request with mTLS."""
        return await self.request("POST", url, **kwargs)
    
    async def put(self, url: str, **kwargs) -> httpx.Response:
        """Make PUT request with mTLS."""
        return await self.request("PUT", url, **kwargs)
    
    async def delete(self, url: str, **kwargs) -> httpx.Response:
        """Make DELETE request with mTLS."""
        return await self.request("DELETE", url, **kwargs)


def create_mtls_context(config: MTLSConfig) -> MTLSManager:
    """Create mTLS manager with given configuration."""
    return MTLSManager(config)


def setup_service_certificates(service_name: str, 
                             cert_dir: str = "/etc/ssl/mcp",
                             ca_common_name: str = "MCP Security Platform CA"):
    """Setup certificates for a service."""
    
    # Create certificate directory
    os.makedirs(cert_dir, exist_ok=True)
    
    # Certificate paths
    ca_cert_path = os.path.join(cert_dir, "ca.crt")
    ca_key_path = os.path.join(cert_dir, "ca.key")
    service_cert_path = os.path.join(cert_dir, f"{service_name}.crt")
    service_key_path = os.path.join(cert_dir, f"{service_name}.key")
    
    # Create certificate manager
    config = MTLSConfig(
        ca_cert_path=ca_cert_path,
        server_cert_path=service_cert_path,
        server_key_path=service_key_path,
        client_cert_path=service_cert_path,
        client_key_path=service_key_path,
        service_name=service_name
    )
    
    cert_manager = CertificateManager(config)
    logger = get_logger("mtls.setup")
    
    # Generate or load CA certificate
    if not os.path.exists(ca_cert_path):
        logger.info("Generating CA certificate")
        ca_cert, ca_key = cert_manager.generate_ca_certificate(ca_common_name)
        cert_manager.save_certificate(ca_cert, ca_cert_path)
        cert_manager.save_private_key(ca_key, ca_key_path)
    else:
        logger.info("Loading existing CA certificate")
        ca_cert = cert_manager.load_certificate(ca_cert_path)
        ca_key = cert_manager.load_private_key(ca_key_path)
    
    # Generate service certificate
    logger.info(f"Generating certificate for service: {service_name}")
    service_cert, service_key = cert_manager.generate_service_certificate(
        service_name, ca_cert, ca_key
    )
    
    cert_manager.save_certificate(service_cert, service_cert_path)
    cert_manager.save_private_key(service_key, service_key_path)
    
    logger.info(f"Certificates generated for {service_name}")
    return config


def verify_mtls_connection(client_config: MTLSConfig, server_url: str) -> bool:
    """Verify mTLS connection to a server."""
    try:
        mtls_manager = MTLSManager(client_config)
        client = MTLSHTTPXClient(mtls_manager)
        
        # Test connection
        import asyncio
        
        async def test_connection():
            try:
                response = await client.get(f"{server_url}/health")
                return response.status_code == 200
            except Exception as e:
                logger = get_logger("mtls.verify")
                logger.error(f"mTLS connection test failed: {e}")
                return False
        
        return asyncio.run(test_connection())
        
    except Exception as e:
        logger = get_logger("mtls.verify")
        logger.error(f"mTLS verification failed: {e}")
        return False