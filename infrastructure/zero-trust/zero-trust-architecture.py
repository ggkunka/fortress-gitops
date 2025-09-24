"""
Zero Trust Security Architecture Implementation

This module implements comprehensive Zero Trust security principles for the MCP Security Platform,
including identity verification, device compliance, network microsegmentation, and continuous monitoring.
"""

import asyncio
import json
import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from enum import Enum
from dataclasses import dataclass, field
import hashlib
import ipaddress
import ssl
import jwt
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

logger = get_logger(__name__)
metrics = get_metrics()


class TrustLevel(str, Enum):
    """Trust levels for Zero Trust assessment."""
    UNTRUSTED = "untrusted"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    VERIFIED = "verified"


class AccessDecision(str, Enum):
    """Access control decisions."""
    ALLOW = "allow"
    DENY = "deny"
    CHALLENGE = "challenge"
    MONITOR = "monitor"


class RiskScore(str, Enum):
    """Risk score levels."""
    MINIMAL = "minimal"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DeviceCompliance(str, Enum):
    """Device compliance status."""
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    UNKNOWN = "unknown"
    QUARANTINED = "quarantined"


@dataclass
class Identity:
    """User or service identity."""
    id: str
    type: str  # user, service, device
    attributes: Dict[str, Any]
    roles: List[str]
    groups: List[str]
    trust_level: TrustLevel
    verification_methods: List[str]
    last_verified: datetime
    risk_factors: List[str] = field(default_factory=list)
    compliance_status: str = "unknown"


@dataclass
class Device:
    """Device information and compliance status."""
    id: str
    fingerprint: str
    type: str
    os_type: str
    os_version: str
    patch_level: str
    compliance_status: DeviceCompliance
    security_features: Dict[str, bool]
    last_scan: datetime
    certificates: List[str] = field(default_factory=list)
    risk_indicators: List[str] = field(default_factory=list)
    location: Optional[str] = None
    network_segment: Optional[str] = None


@dataclass
class NetworkSegment:
    """Network microsegment definition."""
    id: str
    name: str
    cidr: str
    trust_zone: str
    allowed_protocols: List[str]
    allowed_ports: List[int]
    ingress_rules: List[Dict[str, Any]]
    egress_rules: List[Dict[str, Any]]
    monitoring_level: str
    encryption_required: bool = True


@dataclass
class AccessRequest:
    """Access request for Zero Trust evaluation."""
    request_id: str
    identity: Identity
    device: Device
    resource: str
    action: str
    context: Dict[str, Any]
    timestamp: datetime
    source_ip: str
    user_agent: Optional[str] = None
    session_id: Optional[str] = None


@dataclass
class AccessEvaluation:
    """Result of Zero Trust access evaluation."""
    request_id: str
    decision: AccessDecision
    trust_score: float
    risk_score: RiskScore
    reasons: List[str]
    conditions: List[str] = field(default_factory=list)
    monitoring_requirements: List[str] = field(default_factory=list)
    valid_until: Optional[datetime] = None


class IdentityVerificationEngine:
    """
    Identity verification and continuous authentication engine.
    
    Features:
    - Multi-factor authentication
    - Behavioral analysis
    - Risk-based authentication
    - Continuous verification
    - Identity posture assessment
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.identity_store: Dict[str, Identity] = {}
        self.verification_cache: Dict[str, Dict[str, Any]] = {}
        self.behavioral_profiles: Dict[str, Dict[str, Any]] = {}
        
        # Verification thresholds
        self.verification_interval = self.config.get("verification_interval", 3600)  # 1 hour
        self.risk_threshold = self.config.get("risk_threshold", 0.7)
        self.trust_decay_rate = self.config.get("trust_decay_rate", 0.1)
        
    async def verify_identity(self, identity_id: str, verification_data: Dict[str, Any]) -> TrustLevel:
        """Verify identity and return trust level."""
        try:
            identity = self.identity_store.get(identity_id)
            if not identity:
                logger.warning(f"Unknown identity: {identity_id}")
                return TrustLevel.UNTRUSTED
            
            # Check verification methods
            trust_factors = []
            
            # Primary authentication
            if "credentials" in verification_data:
                if await self._verify_credentials(identity, verification_data["credentials"]):
                    trust_factors.append("valid_credentials")
                else:
                    return TrustLevel.UNTRUSTED
            
            # Multi-factor authentication
            if "mfa_token" in verification_data:
                if await self._verify_mfa(identity, verification_data["mfa_token"]):
                    trust_factors.append("mfa_verified")
            
            # Certificate-based authentication
            if "client_certificate" in verification_data:
                if await self._verify_certificate(identity, verification_data["client_certificate"]):
                    trust_factors.append("certificate_valid")
            
            # Behavioral analysis
            behavioral_score = await self._analyze_behavior(identity, verification_data)
            if behavioral_score > 0.8:
                trust_factors.append("behavior_normal")
            elif behavioral_score < 0.3:
                trust_factors.append("behavior_anomalous")
            
            # Calculate trust level
            trust_level = self._calculate_trust_level(trust_factors, behavioral_score)
            
            # Update identity
            identity.trust_level = trust_level
            identity.last_verified = datetime.now(timezone.utc)
            
            logger.info(f"Verified identity {identity_id} with trust level {trust_level}")
            metrics.identity_verifications.inc()
            
            return trust_level
            
        except Exception as e:
            logger.error(f"Identity verification failed for {identity_id}: {e}")
            return TrustLevel.UNTRUSTED
    
    async def _verify_credentials(self, identity: Identity, credentials: Dict[str, str]) -> bool:
        """Verify user credentials."""
        # Implementation would integrate with identity provider
        username = credentials.get("username")
        password = credentials.get("password")
        
        # Simulate credential verification
        return username == identity.attributes.get("username") and len(password or "") >= 8
    
    async def _verify_mfa(self, identity: Identity, mfa_token: str) -> bool:
        """Verify multi-factor authentication token."""
        # Implementation would integrate with MFA provider (TOTP, SMS, etc.)
        return len(mfa_token) == 6 and mfa_token.isdigit()
    
    async def _verify_certificate(self, identity: Identity, certificate_pem: str) -> bool:
        """Verify client certificate."""
        try:
            cert = x509.load_pem_x509_certificate(certificate_pem.encode())
            
            # Check certificate validity
            now = datetime.now(timezone.utc)
            if now < cert.not_valid_before or now > cert.not_valid_after:
                return False
            
            # Check subject matches identity
            subject = cert.subject
            cert_cn = None
            for attribute in subject:
                if attribute.oid._name == "commonName":
                    cert_cn = attribute.value
                    break
            
            return cert_cn == identity.attributes.get("common_name")
            
        except Exception as e:
            logger.error(f"Certificate verification failed: {e}")
            return False
    
    async def _analyze_behavior(self, identity: Identity, context: Dict[str, Any]) -> float:
        """Analyze user behavior for anomalies."""
        try:
            profile = self.behavioral_profiles.get(identity.id, {})
            
            # Analyze various behavioral factors
            factors = {}
            
            # Time-based analysis
            current_hour = datetime.now().hour
            typical_hours = profile.get("typical_hours", set(range(8, 18)))
            factors["time_normal"] = 1.0 if current_hour in typical_hours else 0.3
            
            # Location analysis
            source_ip = context.get("source_ip")
            if source_ip:
                typical_networks = profile.get("typical_networks", set())
                factors["location_normal"] = 1.0 if any(
                    ipaddress.ip_address(source_ip) in ipaddress.ip_network(net, strict=False)
                    for net in typical_networks
                ) else 0.5
            
            # Device analysis
            user_agent = context.get("user_agent", "")
            typical_agents = profile.get("typical_user_agents", set())
            factors["device_normal"] = 1.0 if user_agent in typical_agents else 0.7
            
            # Calculate overall behavioral score
            if factors:
                behavioral_score = sum(factors.values()) / len(factors)
            else:
                behavioral_score = 0.5  # Neutral score for new users
            
            # Update behavioral profile
            self._update_behavioral_profile(identity.id, context)
            
            return behavioral_score
            
        except Exception as e:
            logger.error(f"Behavioral analysis failed: {e}")
            return 0.5
    
    def _calculate_trust_level(self, trust_factors: List[str], behavioral_score: float) -> TrustLevel:
        """Calculate overall trust level."""
        score = 0.0
        
        # Factor scores
        factor_scores = {
            "valid_credentials": 0.3,
            "mfa_verified": 0.3,
            "certificate_valid": 0.2,
            "behavior_normal": 0.2,
            "behavior_anomalous": -0.3
        }
        
        for factor in trust_factors:
            score += factor_scores.get(factor, 0.0)
        
        # Add behavioral component
        score += (behavioral_score - 0.5) * 0.2
        
        # Map score to trust level
        if score >= 0.9:
            return TrustLevel.VERIFIED
        elif score >= 0.7:
            return TrustLevel.HIGH
        elif score >= 0.5:
            return TrustLevel.MEDIUM
        elif score >= 0.3:
            return TrustLevel.LOW
        else:
            return TrustLevel.UNTRUSTED
    
    def _update_behavioral_profile(self, identity_id: str, context: Dict[str, Any]):
        """Update behavioral profile with new context."""
        if identity_id not in self.behavioral_profiles:
            self.behavioral_profiles[identity_id] = {
                "typical_hours": set(),
                "typical_networks": set(),
                "typical_user_agents": set()
            }
        
        profile = self.behavioral_profiles[identity_id]
        
        # Update typical hours
        current_hour = datetime.now().hour
        profile["typical_hours"].add(current_hour)
        
        # Update typical networks (simplified to /24)
        source_ip = context.get("source_ip")
        if source_ip:
            try:
                network = ipaddress.ip_network(f"{source_ip}/24", strict=False)
                profile["typical_networks"].add(str(network))
            except ValueError:
                pass
        
        # Update typical user agents
        user_agent = context.get("user_agent")
        if user_agent:
            profile["typical_user_agents"].add(user_agent)


class DeviceComplianceEngine:
    """
    Device compliance and trust assessment engine.
    
    Features:
    - Device fingerprinting
    - Compliance assessment
    - Security posture evaluation
    - Certificate management
    - Risk scoring
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.device_store: Dict[str, Device] = {}
        self.compliance_policies: Dict[str, Dict[str, Any]] = {}
        
        # Load default compliance policies
        self._load_default_policies()
    
    async def assess_device_compliance(self, device_id: str, device_info: Dict[str, Any]) -> DeviceCompliance:
        """Assess device compliance against security policies."""
        try:
            device = self.device_store.get(device_id)
            if not device:
                # Create new device record
                device = Device(
                    id=device_id,
                    fingerprint=self._generate_device_fingerprint(device_info),
                    type=device_info.get("type", "unknown"),
                    os_type=device_info.get("os_type", "unknown"),
                    os_version=device_info.get("os_version", "unknown"),
                    patch_level=device_info.get("patch_level", "unknown"),
                    compliance_status=DeviceCompliance.UNKNOWN,
                    security_features={},
                    last_scan=datetime.now(timezone.utc)
                )
                self.device_store[device_id] = device
            
            # Update device information
            device.os_version = device_info.get("os_version", device.os_version)
            device.patch_level = device_info.get("patch_level", device.patch_level)
            device.last_scan = datetime.now(timezone.utc)
            
            # Assess compliance
            compliance_score = await self._calculate_compliance_score(device, device_info)
            
            # Determine compliance status
            if compliance_score >= 0.9:
                device.compliance_status = DeviceCompliance.COMPLIANT
            elif compliance_score >= 0.7:
                device.compliance_status = DeviceCompliance.NON_COMPLIANT
            else:
                device.compliance_status = DeviceCompliance.QUARANTINED
            
            logger.info(f"Device {device_id} compliance: {device.compliance_status}")
            metrics.device_compliance_assessments.inc()
            
            return device.compliance_status
            
        except Exception as e:
            logger.error(f"Device compliance assessment failed for {device_id}: {e}")
            return DeviceCompliance.UNKNOWN
    
    async def _calculate_compliance_score(self, device: Device, device_info: Dict[str, Any]) -> float:
        """Calculate device compliance score."""
        score = 0.0
        total_checks = 0
        
        policy = self.compliance_policies.get(device.type, self.compliance_policies["default"])
        
        # OS version compliance
        if "min_os_version" in policy:
            total_checks += 1
            if self._compare_versions(device.os_version, policy["min_os_version"]) >= 0:
                score += 1.0
        
        # Security features
        required_features = policy.get("required_security_features", [])
        if required_features:
            total_checks += len(required_features)
            for feature in required_features:
                if device_info.get("security_features", {}).get(feature, False):
                    score += 1.0
        
        # Certificate presence
        if policy.get("require_certificate", False):
            total_checks += 1
            if device.certificates:
                score += 1.0
        
        # Encryption requirements
        if policy.get("require_encryption", False):
            total_checks += 1
            if device_info.get("encryption_enabled", False):
                score += 1.0
        
        # Patch level
        if "max_patch_age_days" in policy:
            total_checks += 1
            patch_age = self._calculate_patch_age(device.patch_level)
            if patch_age <= policy["max_patch_age_days"]:
                score += 1.0
        
        return score / total_checks if total_checks > 0 else 0.0
    
    def _generate_device_fingerprint(self, device_info: Dict[str, Any]) -> str:
        """Generate unique device fingerprint."""
        fingerprint_data = f"{device_info.get('os_type', '')}" \
                          f"{device_info.get('hardware_id', '')}" \
                          f"{device_info.get('mac_addresses', [])}" \
                          f"{device_info.get('cpu_info', '')}"
        
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    def _compare_versions(self, version1: str, version2: str) -> int:
        """Compare version strings. Returns 1 if v1 > v2, -1 if v1 < v2, 0 if equal."""
        try:
            v1_parts = [int(x) for x in version1.split('.')]
            v2_parts = [int(x) for x in version2.split('.')]
            
            # Pad with zeros to make same length
            max_len = max(len(v1_parts), len(v2_parts))
            v1_parts.extend([0] * (max_len - len(v1_parts)))
            v2_parts.extend([0] * (max_len - len(v2_parts)))
            
            for i in range(max_len):
                if v1_parts[i] > v2_parts[i]:
                    return 1
                elif v1_parts[i] < v2_parts[i]:
                    return -1
            
            return 0
        except ValueError:
            return 0
    
    def _calculate_patch_age(self, patch_level: str) -> int:
        """Calculate age of patch level in days."""
        try:
            # This is simplified - real implementation would parse patch dates
            if "2024" in patch_level:
                return 30  # Recent patches
            elif "2023" in patch_level:
                return 180  # Older patches
            else:
                return 365  # Very old patches
        except Exception:
            return 999  # Unknown age
    
    def _load_default_policies(self):
        """Load default device compliance policies."""
        self.compliance_policies = {
            "default": {
                "min_os_version": "10.0.0",
                "required_security_features": ["antivirus", "firewall", "auto_update"],
                "require_certificate": True,
                "require_encryption": True,
                "max_patch_age_days": 90
            },
            "mobile": {
                "min_os_version": "14.0.0",
                "required_security_features": ["pin_lock", "biometrics", "remote_wipe"],
                "require_certificate": True,
                "require_encryption": True,
                "max_patch_age_days": 60
            },
            "server": {
                "min_os_version": "20.04",
                "required_security_features": ["intrusion_detection", "log_monitoring", "hardening"],
                "require_certificate": True,
                "require_encryption": True,
                "max_patch_age_days": 30
            }
        }


class NetworkMicrosegmentation:
    """
    Network microsegmentation for Zero Trust networking.
    
    Features:
    - Dynamic segment creation
    - Traffic policy enforcement
    - East-west traffic inspection
    - Network policy automation
    - Breach containment
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.segments: Dict[str, NetworkSegment] = {}
        self.traffic_policies: Dict[str, Dict[str, Any]] = {}
        
        # Initialize default segments
        self._create_default_segments()
    
    async def create_segment(self, segment_config: Dict[str, Any]) -> str:
        """Create new network microsegment."""
        try:
            segment_id = str(uuid.uuid4())
            
            segment = NetworkSegment(
                id=segment_id,
                name=segment_config["name"],
                cidr=segment_config["cidr"],
                trust_zone=segment_config.get("trust_zone", "restricted"),
                allowed_protocols=segment_config.get("allowed_protocols", ["TCP", "UDP"]),
                allowed_ports=segment_config.get("allowed_ports", []),
                ingress_rules=segment_config.get("ingress_rules", []),
                egress_rules=segment_config.get("egress_rules", []),
                monitoring_level=segment_config.get("monitoring_level", "high"),
                encryption_required=segment_config.get("encryption_required", True)
            )
            
            self.segments[segment_id] = segment
            
            # Generate network policies
            await self._generate_network_policies(segment)
            
            logger.info(f"Created network segment {segment.name} ({segment_id})")
            metrics.network_segments_created.inc()
            
            return segment_id
            
        except Exception as e:
            logger.error(f"Failed to create network segment: {e}")
            raise
    
    async def evaluate_traffic(self, source_ip: str, dest_ip: str, port: int, protocol: str) -> AccessDecision:
        """Evaluate network traffic against microsegmentation policies."""
        try:
            # Find source and destination segments
            source_segment = self._find_segment_for_ip(source_ip)
            dest_segment = self._find_segment_for_ip(dest_ip)
            
            if not source_segment or not dest_segment:
                logger.warning(f"Unknown segment for traffic {source_ip} -> {dest_ip}:{port}")
                return AccessDecision.DENY
            
            # Check if traffic is allowed between segments
            if not self._is_traffic_allowed(source_segment, dest_segment, port, protocol):
                logger.info(f"Traffic denied by policy: {source_ip} -> {dest_ip}:{port}")
                return AccessDecision.DENY
            
            # Check for monitoring requirements
            if source_segment.monitoring_level == "high" or dest_segment.monitoring_level == "high":
                return AccessDecision.MONITOR
            
            return AccessDecision.ALLOW
            
        except Exception as e:
            logger.error(f"Traffic evaluation failed: {e}")
            return AccessDecision.DENY
    
    def _find_segment_for_ip(self, ip_address: str) -> Optional[NetworkSegment]:
        """Find network segment containing IP address."""
        try:
            ip = ipaddress.ip_address(ip_address)
            for segment in self.segments.values():
                if ip in ipaddress.ip_network(segment.cidr):
                    return segment
            return None
        except ValueError:
            return None
    
    def _is_traffic_allowed(self, source: NetworkSegment, dest: NetworkSegment, port: int, protocol: str) -> bool:
        """Check if traffic is allowed between segments."""
        # Check protocol
        if protocol not in dest.allowed_protocols:
            return False
        
        # Check port
        if dest.allowed_ports and port not in dest.allowed_ports:
            return False
        
        # Check trust zones
        trust_zone_matrix = {
            ("public", "private"): False,
            ("public", "restricted"): False,
            ("private", "restricted"): True,
            ("restricted", "private"): True,
            ("private", "private"): True,
            ("restricted", "restricted"): True
        }
        
        zone_key = (source.trust_zone, dest.trust_zone)
        return trust_zone_matrix.get(zone_key, False)
    
    def _create_default_segments(self):
        """Create default network segments."""
        default_segments = [
            {
                "name": "dmz",
                "cidr": "10.0.1.0/24",
                "trust_zone": "public",
                "allowed_protocols": ["TCP", "UDP"],
                "allowed_ports": [80, 443, 22],
                "monitoring_level": "high"
            },
            {
                "name": "internal",
                "cidr": "10.0.2.0/24", 
                "trust_zone": "private",
                "allowed_protocols": ["TCP", "UDP", "ICMP"],
                "allowed_ports": [],
                "monitoring_level": "medium"
            },
            {
                "name": "restricted",
                "cidr": "10.0.3.0/24",
                "trust_zone": "restricted",
                "allowed_protocols": ["TCP"],
                "allowed_ports": [443, 8080],
                "monitoring_level": "high"
            }
        ]
        
        for segment_config in default_segments:
            asyncio.create_task(self.create_segment(segment_config))
    
    async def _generate_network_policies(self, segment: NetworkSegment):
        """Generate Kubernetes NetworkPolicies for segment."""
        # This would generate actual Kubernetes NetworkPolicy resources
        policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": f"segment-{segment.name}",
                "namespace": "mcp-security-platform"
            },
            "spec": {
                "podSelector": {
                    "matchLabels": {
                        "network-segment": segment.name
                    }
                },
                "policyTypes": ["Ingress", "Egress"],
                "ingress": segment.ingress_rules,
                "egress": segment.egress_rules
            }
        }
        
        # Store policy for application
        self.traffic_policies[segment.id] = policy


class ZeroTrustAccessEngine:
    """
    Central Zero Trust access decision engine.
    
    Combines identity, device, network, and behavioral factors to make access decisions.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Component engines
        self.identity_engine = IdentityVerificationEngine(config.get("identity", {}))
        self.device_engine = DeviceComplianceEngine(config.get("device", {}))
        self.network_engine = NetworkMicrosegmentation(config.get("network", {}))
        
        # Access policies
        self.access_policies: Dict[str, Dict[str, Any]] = {}
        self.resource_requirements: Dict[str, Dict[str, Any]] = {}
        
        # Decision cache
        self.decision_cache: Dict[str, AccessEvaluation] = {}
        
        # Load default policies
        self._load_default_policies()
    
    @traced("zero_trust_evaluate_access")
    async def evaluate_access(self, request: AccessRequest) -> AccessEvaluation:
        """Evaluate access request using Zero Trust principles."""
        try:
            # Check cache for recent decision
            cache_key = self._generate_cache_key(request)
            if cache_key in self.decision_cache:
                cached_decision = self.decision_cache[cache_key]
                if cached_decision.valid_until and datetime.now(timezone.utc) < cached_decision.valid_until:
                    logger.debug(f"Returning cached decision for {request.request_id}")
                    return cached_decision
            
            # Collect all factors for decision
            factors = await self._collect_decision_factors(request)
            
            # Calculate trust and risk scores
            trust_score = self._calculate_trust_score(factors)
            risk_score = self._calculate_risk_score(factors)
            
            # Make access decision
            decision = self._make_access_decision(request, trust_score, risk_score, factors)
            
            # Create evaluation result
            evaluation = AccessEvaluation(
                request_id=request.request_id,
                decision=decision,
                trust_score=trust_score,
                risk_score=risk_score,
                reasons=factors.get("decision_reasons", []),
                conditions=factors.get("conditions", []),
                monitoring_requirements=factors.get("monitoring", []),
                valid_until=datetime.now(timezone.utc) + timedelta(minutes=15)
            )
            
            # Cache decision
            self.decision_cache[cache_key] = evaluation
            
            logger.info(f"Access evaluation completed: {request.request_id} -> {decision}")
            metrics.zero_trust_evaluations.inc()
            
            return evaluation
            
        except Exception as e:
            logger.error(f"Access evaluation failed for {request.request_id}: {e}")
            return AccessEvaluation(
                request_id=request.request_id,
                decision=AccessDecision.DENY,
                trust_score=0.0,
                risk_score=RiskScore.CRITICAL,
                reasons=[f"Evaluation error: {str(e)}"]
            )
    
    async def _collect_decision_factors(self, request: AccessRequest) -> Dict[str, Any]:
        """Collect all factors needed for access decision."""
        factors = {
            "identity_trust": request.identity.trust_level,
            "device_compliance": request.device.compliance_status,
            "decision_reasons": [],
            "conditions": [],
            "monitoring": []
        }
        
        # Network context
        network_decision = await self.network_engine.evaluate_traffic(
            request.source_ip, 
            "internal", 
            443, 
            "TCP"
        )
        factors["network_decision"] = network_decision
        
        # Time-based factors
        current_hour = datetime.now().hour
        factors["business_hours"] = 8 <= current_hour <= 18
        
        # Resource sensitivity
        resource_requirements = self.resource_requirements.get(request.resource, {})
        factors["resource_sensitivity"] = resource_requirements.get("sensitivity", "medium")
        factors["required_trust"] = resource_requirements.get("min_trust_level", "medium")
        
        # Action risk
        high_risk_actions = ["delete", "admin", "export", "modify"]
        factors["action_risk"] = "high" if request.action in high_risk_actions else "low"
        
        # Session context
        factors["session_age"] = self._calculate_session_age(request.session_id)
        
        return factors
    
    def _calculate_trust_score(self, factors: Dict[str, Any]) -> float:
        """Calculate overall trust score."""
        score = 0.0
        
        # Identity trust (40% weight)
        trust_scores = {
            TrustLevel.VERIFIED: 1.0,
            TrustLevel.HIGH: 0.8,
            TrustLevel.MEDIUM: 0.6,
            TrustLevel.LOW: 0.4,
            TrustLevel.UNTRUSTED: 0.0
        }
        score += trust_scores.get(factors["identity_trust"], 0.0) * 0.4
        
        # Device compliance (30% weight)
        compliance_scores = {
            DeviceCompliance.COMPLIANT: 1.0,
            DeviceCompliance.NON_COMPLIANT: 0.5,
            DeviceCompliance.QUARANTINED: 0.0,
            DeviceCompliance.UNKNOWN: 0.3
        }
        score += compliance_scores.get(factors["device_compliance"], 0.0) * 0.3
        
        # Network context (20% weight)
        if factors["network_decision"] == AccessDecision.ALLOW:
            score += 0.2
        elif factors["network_decision"] == AccessDecision.MONITOR:
            score += 0.15
        
        # Business hours (10% weight)
        if factors["business_hours"]:
            score += 0.1
        
        return min(score, 1.0)
    
    def _calculate_risk_score(self, factors: Dict[str, Any]) -> RiskScore:
        """Calculate overall risk score."""
        risk_points = 0
        
        # High-risk actions
        if factors["action_risk"] == "high":
            risk_points += 3
        
        # Sensitive resources
        if factors["resource_sensitivity"] == "high":
            risk_points += 2
        elif factors["resource_sensitivity"] == "critical":
            risk_points += 4
        
        # Non-compliant device
        if factors["device_compliance"] == DeviceCompliance.NON_COMPLIANT:
            risk_points += 2
        elif factors["device_compliance"] == DeviceCompliance.QUARANTINED:
            risk_points += 4
        
        # Untrusted identity
        if factors["identity_trust"] == TrustLevel.UNTRUSTED:
            risk_points += 3
        elif factors["identity_trust"] == TrustLevel.LOW:
            risk_points += 1
        
        # Off-hours access
        if not factors["business_hours"]:
            risk_points += 1
        
        # Map risk points to risk score
        if risk_points >= 8:
            return RiskScore.CRITICAL
        elif risk_points >= 6:
            return RiskScore.HIGH
        elif risk_points >= 4:
            return RiskScore.MEDIUM
        elif risk_points >= 2:
            return RiskScore.LOW
        else:
            return RiskScore.MINIMAL
    
    def _make_access_decision(
        self,
        request: AccessRequest,
        trust_score: float,
        risk_score: RiskScore,
        factors: Dict[str, Any]
    ) -> AccessDecision:
        """Make final access decision."""
        # Get resource requirements
        resource_requirements = self.resource_requirements.get(request.resource, {})
        min_trust = resource_requirements.get("min_trust_score", 0.6)
        max_risk = resource_requirements.get("max_risk_level", RiskScore.MEDIUM)
        
        # Critical resources require high trust
        if factors["resource_sensitivity"] == "critical" and trust_score < 0.8:
            factors["decision_reasons"].append("Insufficient trust for critical resource")
            return AccessDecision.DENY
        
        # High-risk actions require verification
        if risk_score in [RiskScore.HIGH, RiskScore.CRITICAL]:
            if trust_score < 0.8:
                factors["decision_reasons"].append("High risk requires additional verification")
                return AccessDecision.CHALLENGE
            factors["monitoring"].append("high_risk_action")
        
        # Check minimum trust threshold
        if trust_score < min_trust:
            factors["decision_reasons"].append(f"Trust score {trust_score} below minimum {min_trust}")
            return AccessDecision.DENY
        
        # Check maximum risk threshold
        risk_levels = {
            RiskScore.MINIMAL: 1,
            RiskScore.LOW: 2,
            RiskScore.MEDIUM: 3,
            RiskScore.HIGH: 4,
            RiskScore.CRITICAL: 5
        }
        
        if risk_levels.get(risk_score, 5) > risk_levels.get(max_risk, 3):
            factors["decision_reasons"].append(f"Risk level {risk_score} exceeds maximum {max_risk}")
            return AccessDecision.DENY
        
        # Add monitoring for sensitive operations
        if factors["resource_sensitivity"] in ["high", "critical"]:
            factors["monitoring"].append("sensitive_resource_access")
        
        factors["decision_reasons"].append(f"Trust: {trust_score:.2f}, Risk: {risk_score}")
        return AccessDecision.ALLOW
    
    def _generate_cache_key(self, request: AccessRequest) -> str:
        """Generate cache key for access request."""
        key_data = f"{request.identity.id}:{request.device.id}:{request.resource}:{request.action}"
        return hashlib.sha256(key_data.encode()).hexdigest()
    
    def _calculate_session_age(self, session_id: Optional[str]) -> int:
        """Calculate session age in minutes."""
        # This would look up actual session data
        return 30  # Placeholder
    
    def _load_default_policies(self):
        """Load default access policies and resource requirements."""
        self.resource_requirements = {
            "/admin/*": {
                "sensitivity": "critical",
                "min_trust_score": 0.9,
                "max_risk_level": RiskScore.LOW,
                "require_mfa": True
            },
            "/api/scan/*": {
                "sensitivity": "medium",
                "min_trust_score": 0.6,
                "max_risk_level": RiskScore.MEDIUM
            },
            "/api/reports/*": {
                "sensitivity": "high",
                "min_trust_score": 0.7,
                "max_risk_level": RiskScore.MEDIUM
            },
            "/database/*": {
                "sensitivity": "critical",
                "min_trust_score": 0.8,
                "max_risk_level": RiskScore.LOW
            }
        }