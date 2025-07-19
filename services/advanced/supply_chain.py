"""
Supply Chain Security Analysis Service

This service provides comprehensive supply chain security analysis including
dependency analysis, SBOM generation, vulnerability tracking, and risk assessment.
"""

import asyncio
import json
import hashlib
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union, Set, Tuple
from enum import Enum
from dataclasses import dataclass, field
from pathlib import Path
import re
import semver
from urllib.parse import urlparse

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.data.mongodb import MongoDBService
from shared.data.neo4j import Neo4jService

logger = get_logger(__name__)
metrics = get_metrics()


class ComponentType(str, Enum):
    """Software component types."""
    LIBRARY = "library"
    FRAMEWORK = "framework"
    APPLICATION = "application"
    CONTAINER = "container"
    OPERATING_SYSTEM = "operating_system"
    FIRMWARE = "firmware"
    HARDWARE = "hardware"


class LicenseType(str, Enum):
    """License types for compliance analysis."""
    PERMISSIVE = "permissive"
    COPYLEFT = "copyleft"
    PROPRIETARY = "proprietary"
    UNKNOWN = "unknown"


class RiskLevel(str, Enum):
    """Risk assessment levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NEGLIGIBLE = "negligible"


@dataclass
class SoftwareComponent:
    """Software component in the supply chain."""
    id: str
    name: str
    version: str
    component_type: ComponentType
    supplier: Optional[str] = None
    description: Optional[str] = None
    homepage: Optional[str] = None
    download_location: Optional[str] = None
    files_analyzed: List[str] = field(default_factory=list)
    verification_code: Optional[str] = None
    license_declared: Optional[str] = None
    license_concluded: Optional[str] = None
    license_type: LicenseType = LicenseType.UNKNOWN
    copyright_text: Optional[str] = None
    package_manager: Optional[str] = None
    scope: Optional[str] = None
    hashes: Dict[str, str] = field(default_factory=dict)
    external_refs: List[Dict[str, str]] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    risk_level: RiskLevel = RiskLevel.NEGLIGIBLE
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SBOM:
    """Software Bill of Materials."""
    sbom_id: str
    name: str
    version: str
    description: Optional[str] = None
    creation_info: Dict[str, Any] = field(default_factory=dict)
    document_namespace: Optional[str] = None
    components: List[SoftwareComponent] = field(default_factory=list)
    relationships: List[Dict[str, str]] = field(default_factory=list)
    annotations: List[Dict[str, str]] = field(default_factory=list)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    updated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class SupplyChainRisk:
    """Supply chain risk assessment."""
    risk_id: str
    component_id: str
    component_name: str
    risk_type: str
    risk_level: RiskLevel
    title: str
    description: str
    impact: str
    likelihood: str
    mitigation: Optional[str] = None
    remediation_effort: str = "medium"
    business_impact: str = "medium"
    technical_impact: str = "medium"
    cvss_score: Optional[float] = None
    cve_ids: List[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    resolved: bool = False
    resolved_at: Optional[datetime] = None


@dataclass
class SupplyChainPolicy:
    """Supply chain security policy."""
    policy_id: str
    name: str
    description: str
    rules: List[Dict[str, Any]] = field(default_factory=list)
    allowed_licenses: List[str] = field(default_factory=list)
    blocked_licenses: List[str] = field(default_factory=list)
    max_risk_score: float = 7.0
    require_sbom: bool = True
    require_signatures: bool = False
    allowed_suppliers: List[str] = field(default_factory=list)
    blocked_suppliers: List[str] = field(default_factory=list)
    vulnerability_tolerance: Dict[str, int] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    enabled: bool = True


class SupplyChainSecurityService:
    """
    Supply Chain Security Analysis Service.
    
    Features:
    - SBOM generation and management
    - Dependency analysis and tracking
    - Vulnerability assessment
    - License compliance analysis
    - Risk assessment and scoring
    - Policy enforcement
    - Supplier risk analysis
    - Component authenticity verification
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        
        # Database connections
        self.mongodb: Optional[MongoDBService] = None
        self.neo4j: Optional[Neo4jService] = None
        
        # Component cache
        self.component_cache: Dict[str, SoftwareComponent] = {}
        self.sbom_cache: Dict[str, SBOM] = {}
        
        # Policies
        self.policies: Dict[str, SupplyChainPolicy] = {}
        
        # Risk assessment models
        self.risk_models: Dict[str, Any] = {}
        
        # License mappings
        self.license_mappings = self._initialize_license_mappings()
        
        # Known malicious components
        self.malicious_components: Set[str] = set()
        
        logger.info("Supply Chain Security Service initialized")
    
    async def initialize(self) -> bool:
        """Initialize the supply chain security service."""
        try:
            # Initialize database connections
            self.mongodb = MongoDBService(self.config.get("mongodb", {}))
            await self.mongodb.initialize()
            
            self.neo4j = Neo4jService(self.config.get("neo4j", {}))
            await self.neo4j.initialize()
            
            # Load policies
            await self._load_policies()
            
            # Load risk models
            await self._load_risk_models()
            
            # Load malicious component database
            await self._load_malicious_components()
            
            logger.info("Supply Chain Security Service initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Supply Chain Security Service: {e}")
            return False
    
    async def cleanup(self) -> bool:
        """Cleanup supply chain security service."""
        try:
            if self.mongodb:
                await self.mongodb.cleanup()
            
            if self.neo4j:
                await self.neo4j.cleanup()
            
            logger.info("Supply Chain Security Service cleaned up successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup Supply Chain Security Service: {e}")
            return False
    
    @traced("supply_chain_generate_sbom")
    async def generate_sbom(
        self,
        project_path: str,
        sbom_name: str,
        include_dev_dependencies: bool = False,
        scan_depth: int = 5
    ) -> SBOM:
        """Generate Software Bill of Materials for a project."""
        try:
            project_path = Path(project_path)
            if not project_path.exists():
                raise ValueError(f"Project path does not exist: {project_path}")
            
            # Create SBOM
            sbom_id = f"sbom_{sbom_name}_{int(datetime.now(timezone.utc).timestamp())}"
            sbom = SBOM(
                sbom_id=sbom_id,
                name=sbom_name,
                version="1.0.0",
                description=f"SBOM for {sbom_name}",
                creation_info={
                    "created": datetime.now(timezone.utc).isoformat(),
                    "creators": ["MCP Security Platform"],
                    "license_list_version": "3.17"
                },
                document_namespace=f"https://mcp-security-platform.local/sboms/{sbom_id}"
            )
            
            # Discover components based on package managers
            components = await self._discover_components(
                project_path, 
                include_dev_dependencies, 
                scan_depth
            )
            
            # Add components to SBOM
            sbom.components = components
            
            # Build dependency relationships
            relationships = await self._build_relationships(components)
            sbom.relationships = relationships
            
            # Perform security analysis
            await self._analyze_sbom_security(sbom)
            
            # Store SBOM
            await self._store_sbom(sbom)
            
            # Store dependency graph in Neo4j
            await self._store_dependency_graph(sbom)
            
            logger.info(f"Generated SBOM {sbom_id} with {len(components)} components")
            metrics.sboms_generated.inc()
            
            return sbom
            
        except Exception as e:
            logger.error(f"Failed to generate SBOM: {e}")
            raise
    
    @traced("supply_chain_analyze_component")
    async def analyze_component(self, component: SoftwareComponent) -> SupplyChainRisk:
        """Analyze a software component for security risks."""
        try:
            risks = []
            
            # Check for known vulnerabilities
            vulnerability_risks = await self._check_vulnerabilities(component)
            risks.extend(vulnerability_risks)
            
            # License compliance analysis
            license_risks = await self._analyze_license_compliance(component)
            risks.extend(license_risks)
            
            # Supplier risk analysis
            supplier_risks = await self._analyze_supplier_risk(component)
            risks.extend(supplier_risks)
            
            # Malicious component check
            malicious_risks = await self._check_malicious_components(component)
            risks.extend(malicious_risks)
            
            # Age and maintenance analysis
            maintenance_risks = await self._analyze_maintenance_status(component)
            risks.extend(maintenance_risks)
            
            # Calculate overall risk score
            component.risk_score = self._calculate_risk_score(risks)
            component.risk_level = self._determine_risk_level(component.risk_score)
            
            # Return highest priority risk
            if risks:
                highest_risk = max(risks, key=lambda r: self._risk_level_score(r.risk_level))
                return highest_risk
            
            # Create low-risk assessment if no issues found
            return SupplyChainRisk(
                risk_id=f"risk_{component.id}_safe",
                component_id=component.id,
                component_name=component.name,
                risk_type="assessment",
                risk_level=RiskLevel.LOW,
                title="Component appears secure",
                description="No significant security issues detected",
                impact="Low",
                likelihood="Low"
            )
            
        except Exception as e:
            logger.error(f"Failed to analyze component {component.name}: {e}")
            raise
    
    @traced("supply_chain_check_policy_compliance")
    async def check_policy_compliance(
        self, 
        sbom: SBOM, 
        policy_id: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Check SBOM compliance against supply chain policies."""
        try:
            violations = []
            
            # Use default policy if none specified
            if policy_id:
                policy = self.policies.get(policy_id)
                if not policy:
                    raise ValueError(f"Policy {policy_id} not found")
                policies_to_check = [policy]
            else:
                policies_to_check = [p for p in self.policies.values() if p.enabled]
            
            for policy in policies_to_check:
                policy_violations = await self._check_policy_violations(sbom, policy)
                violations.extend(policy_violations)
            
            logger.info(f"Policy compliance check completed, found {len(violations)} violations")
            return violations
            
        except Exception as e:
            logger.error(f"Failed to check policy compliance: {e}")
            return []
    
    async def get_sbom(self, sbom_id: str) -> Optional[SBOM]:
        """Get SBOM by ID."""
        try:
            # Check cache first
            if sbom_id in self.sbom_cache:
                return self.sbom_cache[sbom_id]
            
            # Query from database
            result = await self.mongodb.find_one("sboms", {"sbom_id": sbom_id})
            if result:
                sbom = self._deserialize_sbom(result)
                self.sbom_cache[sbom_id] = sbom
                return sbom
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to get SBOM {sbom_id}: {e}")
            return None
    
    async def update_component_vulnerabilities(self, component_id: str, vulnerabilities: List[str]) -> bool:
        """Update component vulnerability information."""
        try:
            # Update in cache
            if component_id in self.component_cache:
                self.component_cache[component_id].vulnerabilities = vulnerabilities
                self.component_cache[component_id].updated_at = datetime.now(timezone.utc)
            
            # Update in database
            await self.mongodb.update_one(
                "components",
                {"id": component_id},
                {
                    "$set": {
                        "vulnerabilities": vulnerabilities,
                        "updated_at": datetime.now(timezone.utc)
                    }
                }
            )
            
            logger.info(f"Updated vulnerabilities for component {component_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update component vulnerabilities: {e}")
            return False
    
    async def get_dependency_graph(self, sbom_id: str) -> Dict[str, Any]:
        """Get dependency graph for SBOM."""
        try:
            query = """
            MATCH (s:SBOM {sbom_id: $sbom_id})-[:CONTAINS]->(c:Component)
            OPTIONAL MATCH (c)-[r:DEPENDS_ON]->(d:Component)
            RETURN s, collect(c) as components, collect({source: c, target: d, type: type(r)}) as relationships
            """
            
            result = await self.neo4j.run_query(query, {"sbom_id": sbom_id})
            
            if result:
                return {
                    "sbom": result[0]["s"],
                    "components": result[0]["components"],
                    "relationships": result[0]["relationships"]
                }
            
            return {}
            
        except Exception as e:
            logger.error(f"Failed to get dependency graph for {sbom_id}: {e}")
            return {}
    
    async def find_vulnerable_paths(self, sbom_id: str, vulnerability_id: str) -> List[List[str]]:
        """Find all dependency paths to vulnerable components."""
        try:
            query = """
            MATCH (s:SBOM {sbom_id: $sbom_id})-[:CONTAINS]->(root:Component)
            WHERE NOT (root)<-[:DEPENDS_ON]-()
            MATCH (vulnerable:Component)
            WHERE $vulnerability_id IN vulnerable.vulnerabilities
            MATCH path = (root)-[:DEPENDS_ON*]->(vulnerable)
            RETURN [node IN nodes(path) | node.name] as path
            ORDER BY length(path)
            """
            
            results = await self.neo4j.run_query(query, {
                "sbom_id": sbom_id,
                "vulnerability_id": vulnerability_id
            })
            
            paths = [record["path"] for record in results] if results else []
            
            logger.info(f"Found {len(paths)} vulnerable paths for {vulnerability_id}")
            return paths
            
        except Exception as e:
            logger.error(f"Failed to find vulnerable paths: {e}")
            return []
    
    async def _discover_components(
        self, 
        project_path: Path, 
        include_dev: bool, 
        scan_depth: int
    ) -> List[SoftwareComponent]:
        """Discover components in project using various package managers."""
        components = []
        
        # Scan for different package manager files
        package_files = {
            "package.json": self._scan_npm_components,
            "requirements.txt": self._scan_python_components,
            "Pipfile": self._scan_pipenv_components,
            "poetry.lock": self._scan_poetry_components,
            "pom.xml": self._scan_maven_components,
            "build.gradle": self._scan_gradle_components,
            "Cargo.toml": self._scan_cargo_components,
            "go.mod": self._scan_go_components,
            "composer.json": self._scan_composer_components,
            "Gemfile": self._scan_bundler_components
        }
        
        for file_name, scanner_func in package_files.items():
            package_file = project_path / file_name
            if package_file.exists():
                try:
                    found_components = await scanner_func(package_file, include_dev, scan_depth)
                    components.extend(found_components)
                    logger.debug(f"Found {len(found_components)} components from {file_name}")
                except Exception as e:
                    logger.warning(f"Failed to scan {file_name}: {e}")
        
        return components
    
    async def _scan_npm_components(
        self, 
        package_file: Path, 
        include_dev: bool, 
        scan_depth: int
    ) -> List[SoftwareComponent]:
        """Scan NPM package.json for components."""
        components = []
        
        try:
            with open(package_file) as f:
                package_data = json.load(f)
            
            dependencies = package_data.get("dependencies", {})
            if include_dev:
                dependencies.update(package_data.get("devDependencies", {}))
            
            for name, version in dependencies.items():
                component = SoftwareComponent(
                    id=f"npm_{name}_{version}",
                    name=name,
                    version=version.lstrip("^~>=<"),
                    component_type=ComponentType.LIBRARY,
                    package_manager="npm",
                    scope="runtime" if name in package_data.get("dependencies", {}) else "development"
                )
                
                # Add package-specific metadata
                component.external_refs = [
                    {"type": "package-manager", "locator": f"npm:{name}@{version}"}
                ]
                
                components.append(component)
        
        except Exception as e:
            logger.error(f"Failed to scan NPM components: {e}")
        
        return components
    
    async def _scan_python_components(
        self, 
        requirements_file: Path, 
        include_dev: bool, 
        scan_depth: int
    ) -> List[SoftwareComponent]:
        """Scan Python requirements.txt for components."""
        components = []
        
        try:
            with open(requirements_file) as f:
                lines = f.readlines()
            
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#"):
                    # Parse requirement line
                    match = re.match(r"([a-zA-Z0-9_-]+)([>=<~!]+)?(.+)?", line)
                    if match:
                        name = match.group(1)
                        version = match.group(3) if match.group(3) else "latest"
                        
                        component = SoftwareComponent(
                            id=f"python_{name}_{version}",
                            name=name,
                            version=version,
                            component_type=ComponentType.LIBRARY,
                            package_manager="pip",
                            scope="runtime"
                        )
                        
                        component.external_refs = [
                            {"type": "package-manager", "locator": f"pypi:{name}@{version}"}
                        ]
                        
                        components.append(component)
        
        except Exception as e:
            logger.error(f"Failed to scan Python components: {e}")
        
        return components
    
    # Placeholder implementations for other package managers
    async def _scan_pipenv_components(self, *args) -> List[SoftwareComponent]:
        return []
    
    async def _scan_poetry_components(self, *args) -> List[SoftwareComponent]:
        return []
    
    async def _scan_maven_components(self, *args) -> List[SoftwareComponent]:
        return []
    
    async def _scan_gradle_components(self, *args) -> List[SoftwareComponent]:
        return []
    
    async def _scan_cargo_components(self, *args) -> List[SoftwareComponent]:
        return []
    
    async def _scan_go_components(self, *args) -> List[SoftwareComponent]:
        return []
    
    async def _scan_composer_components(self, *args) -> List[SoftwareComponent]:
        return []
    
    async def _scan_bundler_components(self, *args) -> List[SoftwareComponent]:
        return []
    
    async def _build_relationships(self, components: List[SoftwareComponent]) -> List[Dict[str, str]]:
        """Build dependency relationships between components."""
        relationships = []
        
        # This would typically involve parsing lock files or dependency trees
        # For now, create basic relationships
        for component in components:
            for dep in component.dependencies:
                relationships.append({
                    "type": "dependsOn",
                    "source": component.id,
                    "target": dep
                })
        
        return relationships
    
    async def _analyze_sbom_security(self, sbom: SBOM):
        """Perform security analysis on SBOM components."""
        for component in sbom.components:
            try:
                await self.analyze_component(component)
            except Exception as e:
                logger.warning(f"Failed to analyze component {component.name}: {e}")
    
    async def _check_vulnerabilities(self, component: SoftwareComponent) -> List[SupplyChainRisk]:
        """Check component for known vulnerabilities."""
        risks = []
        
        # This would integrate with vulnerability databases
        # For now, simulate vulnerability checks
        if component.name in ["vulnerable-lib", "insecure-package"]:
            risk = SupplyChainRisk(
                risk_id=f"vuln_{component.id}",
                component_id=component.id,
                component_name=component.name,
                risk_type="vulnerability",
                risk_level=RiskLevel.HIGH,
                title=f"Known vulnerability in {component.name}",
                description="Component has known security vulnerabilities",
                impact="High",
                likelihood="High",
                cve_ids=["CVE-2023-1234"]
            )
            risks.append(risk)
        
        return risks
    
    async def _analyze_license_compliance(self, component: SoftwareComponent) -> List[SupplyChainRisk]:
        """Analyze license compliance for component."""
        risks = []
        
        # Check license compatibility
        if component.license_declared:
            license_type = self._classify_license(component.license_declared)
            component.license_type = license_type
            
            # Check against blocked licenses
            for policy in self.policies.values():
                if component.license_declared in policy.blocked_licenses:
                    risk = SupplyChainRisk(
                        risk_id=f"license_{component.id}",
                        component_id=component.id,
                        component_name=component.name,
                        risk_type="license_compliance",
                        risk_level=RiskLevel.MEDIUM,
                        title=f"Blocked license: {component.license_declared}",
                        description="Component uses a license that is blocked by policy",
                        impact="Medium",
                        likelihood="High"
                    )
                    risks.append(risk)
        
        return risks
    
    async def _analyze_supplier_risk(self, component: SoftwareComponent) -> List[SupplyChainRisk]:
        """Analyze supplier risk for component."""
        risks = []
        
        if component.supplier:
            # Check against blocked suppliers
            for policy in self.policies.values():
                if component.supplier in policy.blocked_suppliers:
                    risk = SupplyChainRisk(
                        risk_id=f"supplier_{component.id}",
                        component_id=component.id,
                        component_name=component.name,
                        risk_type="supplier_risk",
                        risk_level=RiskLevel.HIGH,
                        title=f"Blocked supplier: {component.supplier}",
                        description="Component from a supplier that is blocked by policy",
                        impact="High",
                        likelihood="High"
                    )
                    risks.append(risk)
        
        return risks
    
    async def _check_malicious_components(self, component: SoftwareComponent) -> List[SupplyChainRisk]:
        """Check for known malicious components."""
        risks = []
        
        component_signature = f"{component.name}:{component.version}"
        if component_signature in self.malicious_components:
            risk = SupplyChainRisk(
                risk_id=f"malicious_{component.id}",
                component_id=component.id,
                component_name=component.name,
                risk_type="malicious_component",
                risk_level=RiskLevel.CRITICAL,
                title=f"Known malicious component: {component.name}",
                description="Component is known to be malicious or compromised",
                impact="Critical",
                likelihood="High"
            )
            risks.append(risk)
        
        return risks
    
    async def _analyze_maintenance_status(self, component: SoftwareComponent) -> List[SupplyChainRisk]:
        """Analyze component maintenance and age status."""
        risks = []
        
        # Check component age (simulate)
        age_days = (datetime.now(timezone.utc) - component.created_at).days
        if age_days > 730:  # 2 years
            risk = SupplyChainRisk(
                risk_id=f"age_{component.id}",
                component_id=component.id,
                component_name=component.name,
                risk_type="maintenance_risk",
                risk_level=RiskLevel.MEDIUM,
                title=f"Outdated component: {component.name}",
                description="Component is old and may not receive security updates",
                impact="Medium",
                likelihood="Medium"
            )
            risks.append(risk)
        
        return risks
    
    def _calculate_risk_score(self, risks: List[SupplyChainRisk]) -> float:
        """Calculate overall risk score for component."""
        if not risks:
            return 0.0
        
        risk_scores = {
            RiskLevel.CRITICAL: 10.0,
            RiskLevel.HIGH: 7.0,
            RiskLevel.MEDIUM: 5.0,
            RiskLevel.LOW: 3.0,
            RiskLevel.NEGLIGIBLE: 1.0
        }
        
        total_score = sum(risk_scores.get(risk.risk_level, 0.0) for risk in risks)
        return min(total_score, 10.0)  # Cap at 10.0
    
    def _determine_risk_level(self, risk_score: float) -> RiskLevel:
        """Determine risk level from score."""
        if risk_score >= 9.0:
            return RiskLevel.CRITICAL
        elif risk_score >= 7.0:
            return RiskLevel.HIGH
        elif risk_score >= 5.0:
            return RiskLevel.MEDIUM
        elif risk_score >= 3.0:
            return RiskLevel.LOW
        else:
            return RiskLevel.NEGLIGIBLE
    
    def _risk_level_score(self, risk_level: RiskLevel) -> int:
        """Convert risk level to numeric score for comparison."""
        scores = {
            RiskLevel.CRITICAL: 5,
            RiskLevel.HIGH: 4,
            RiskLevel.MEDIUM: 3,
            RiskLevel.LOW: 2,
            RiskLevel.NEGLIGIBLE: 1
        }
        return scores.get(risk_level, 0)
    
    def _classify_license(self, license_name: str) -> LicenseType:
        """Classify license type."""
        license_lower = license_name.lower()
        
        if any(permissive in license_lower for permissive in ["mit", "apache", "bsd", "isc"]):
            return LicenseType.PERMISSIVE
        elif any(copyleft in license_lower for copyleft in ["gpl", "lgpl", "agpl", "copyleft"]):
            return LicenseType.COPYLEFT
        elif "proprietary" in license_lower:
            return LicenseType.PROPRIETARY
        else:
            return LicenseType.UNKNOWN
    
    def _initialize_license_mappings(self) -> Dict[str, LicenseType]:
        """Initialize license type mappings."""
        return {
            "MIT": LicenseType.PERMISSIVE,
            "Apache-2.0": LicenseType.PERMISSIVE,
            "BSD-3-Clause": LicenseType.PERMISSIVE,
            "GPL-3.0": LicenseType.COPYLEFT,
            "LGPL-3.0": LicenseType.COPYLEFT,
            "AGPL-3.0": LicenseType.COPYLEFT
        }
    
    async def _store_sbom(self, sbom: SBOM):
        """Store SBOM in database."""
        sbom_data = self._serialize_sbom(sbom)
        await self.mongodb.insert_one("sboms", sbom_data)
        
        # Store components
        for component in sbom.components:
            component_data = self._serialize_component(component)
            await self.mongodb.upsert("components", {"id": component.id}, component_data)
    
    async def _store_dependency_graph(self, sbom: SBOM):
        """Store dependency graph in Neo4j."""
        # Create SBOM node
        await self.neo4j.run_query(
            "MERGE (s:SBOM {sbom_id: $sbom_id, name: $name, version: $version})",
            {"sbom_id": sbom.sbom_id, "name": sbom.name, "version": sbom.version}
        )
        
        # Create component nodes
        for component in sbom.components:
            await self.neo4j.run_query(
                """
                MERGE (c:Component {id: $id, name: $name, version: $version, type: $type})
                WITH c
                MATCH (s:SBOM {sbom_id: $sbom_id})
                MERGE (s)-[:CONTAINS]->(c)
                """,
                {
                    "id": component.id,
                    "name": component.name,
                    "version": component.version,
                    "type": component.component_type.value,
                    "sbom_id": sbom.sbom_id
                }
            )
        
        # Create relationships
        for relationship in sbom.relationships:
            await self.neo4j.run_query(
                """
                MATCH (source:Component {id: $source_id})
                MATCH (target:Component {id: $target_id})
                MERGE (source)-[:DEPENDS_ON]->(target)
                """,
                {
                    "source_id": relationship["source"],
                    "target_id": relationship["target"]
                }
            )
    
    async def _check_policy_violations(self, sbom: SBOM, policy: SupplyChainPolicy) -> List[Dict[str, Any]]:
        """Check SBOM against specific policy."""
        violations = []
        
        for component in sbom.components:
            # Check license violations
            if component.license_declared in policy.blocked_licenses:
                violations.append({
                    "type": "blocked_license",
                    "component": component.name,
                    "license": component.license_declared,
                    "severity": "high"
                })
            
            # Check supplier violations
            if component.supplier in policy.blocked_suppliers:
                violations.append({
                    "type": "blocked_supplier",
                    "component": component.name,
                    "supplier": component.supplier,
                    "severity": "high"
                })
            
            # Check risk score violations
            if component.risk_score > policy.max_risk_score:
                violations.append({
                    "type": "high_risk_component",
                    "component": component.name,
                    "risk_score": component.risk_score,
                    "max_allowed": policy.max_risk_score,
                    "severity": "medium"
                })
        
        return violations
    
    async def _load_policies(self):
        """Load supply chain policies."""
        # Load default policy
        default_policy = SupplyChainPolicy(
            policy_id="default",
            name="Default Supply Chain Policy",
            description="Default security policy for supply chain components",
            blocked_licenses=["GPL-3.0", "AGPL-3.0"],
            max_risk_score=7.0,
            require_sbom=True
        )
        self.policies[default_policy.policy_id] = default_policy
    
    async def _load_risk_models(self):
        """Load risk assessment models."""
        # Placeholder for ML models
        pass
    
    async def _load_malicious_components(self):
        """Load known malicious components database."""
        # This would load from threat intelligence feeds
        self.malicious_components = {
            "malicious-package:1.0.0",
            "backdoor-lib:2.1.0"
        }
    
    def _serialize_sbom(self, sbom: SBOM) -> Dict[str, Any]:
        """Serialize SBOM for storage."""
        return {
            "sbom_id": sbom.sbom_id,
            "name": sbom.name,
            "version": sbom.version,
            "description": sbom.description,
            "creation_info": sbom.creation_info,
            "document_namespace": sbom.document_namespace,
            "components": [self._serialize_component(c) for c in sbom.components],
            "relationships": sbom.relationships,
            "annotations": sbom.annotations,
            "created_at": sbom.created_at,
            "updated_at": sbom.updated_at
        }
    
    def _serialize_component(self, component: SoftwareComponent) -> Dict[str, Any]:
        """Serialize component for storage."""
        return {
            "id": component.id,
            "name": component.name,
            "version": component.version,
            "component_type": component.component_type.value,
            "supplier": component.supplier,
            "description": component.description,
            "homepage": component.homepage,
            "download_location": component.download_location,
            "license_declared": component.license_declared,
            "license_concluded": component.license_concluded,
            "license_type": component.license_type.value,
            "package_manager": component.package_manager,
            "scope": component.scope,
            "dependencies": component.dependencies,
            "vulnerabilities": component.vulnerabilities,
            "risk_score": component.risk_score,
            "risk_level": component.risk_level.value,
            "created_at": component.created_at,
            "updated_at": component.updated_at
        }
    
    def _deserialize_sbom(self, data: Dict[str, Any]) -> SBOM:
        """Deserialize SBOM from storage."""
        components = [self._deserialize_component(c) for c in data.get("components", [])]
        
        return SBOM(
            sbom_id=data["sbom_id"],
            name=data["name"],
            version=data["version"],
            description=data.get("description"),
            creation_info=data.get("creation_info", {}),
            document_namespace=data.get("document_namespace"),
            components=components,
            relationships=data.get("relationships", []),
            annotations=data.get("annotations", []),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at")
        )
    
    def _deserialize_component(self, data: Dict[str, Any]) -> SoftwareComponent:
        """Deserialize component from storage."""
        return SoftwareComponent(
            id=data["id"],
            name=data["name"],
            version=data["version"],
            component_type=ComponentType(data["component_type"]),
            supplier=data.get("supplier"),
            description=data.get("description"),
            homepage=data.get("homepage"),
            download_location=data.get("download_location"),
            license_declared=data.get("license_declared"),
            license_concluded=data.get("license_concluded"),
            license_type=LicenseType(data.get("license_type", "unknown")),
            package_manager=data.get("package_manager"),
            scope=data.get("scope"),
            dependencies=data.get("dependencies", []),
            vulnerabilities=data.get("vulnerabilities", []),
            risk_score=data.get("risk_score", 0.0),
            risk_level=RiskLevel(data.get("risk_level", "negligible")),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at")
        )