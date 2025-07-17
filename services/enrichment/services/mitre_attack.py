"""MITRE ATT&CK mapping service for enriching data with MITRE ATT&CK techniques."""

import json
import re
from typing import Dict, Any, List, Optional, Set
from datetime import datetime
from pathlib import Path

import httpx
import structlog
from shared.config import get_settings

from ..schemas.mitre_attack import (
    MitreAttack, Technique, SubTechnique, Tactic, Mitigation, DataSource,
    AttackPattern, TacticType, PlatformType, DetectionLevel, MitigationLevel
)
from ..schemas.enrichment import DataType
from .caching import CachingService

settings = get_settings()
logger = structlog.get_logger()


class MitreAttackService:
    """Service for enriching data with MITRE ATT&CK mappings."""
    
    def __init__(self):
        self.logger = logger.bind(service="enrichment", component="mitre_attack")
        self.caching_service = CachingService()
        self.is_running = False
        
        # MITRE ATT&CK data
        self.techniques: Dict[str, Technique] = {}
        self.sub_techniques: Dict[str, SubTechnique] = {}
        self.tactics: Dict[str, Tactic] = {}
        self.mitigations: Dict[str, Mitigation] = {}
        self.data_sources: Dict[str, DataSource] = {}
        
        # Mapping rules for different data types
        self.mapping_rules = {
            DataType.SBOM: self._get_sbom_mapping_rules(),
            DataType.CVE: self._get_cve_mapping_rules(),
            DataType.RUNTIME: self._get_runtime_mapping_rules(),
        }
        
        # HTTP client for downloading MITRE data
        self.http_client = httpx.AsyncClient(timeout=30.0)
        
        # MITRE ATT&CK data URLs
        self.mitre_urls = {
            "enterprise": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
            "mobile": "https://raw.githubusercontent.com/mitre/cti/master/mobile-attack/mobile-attack.json",
            "ics": "https://raw.githubusercontent.com/mitre/cti/master/ics-attack/ics-attack.json",
        }
    
    async def start(self) -> None:
        """Start the MITRE ATT&CK service."""
        try:
            await self.caching_service.start()
            await self._load_mitre_data()
            self.is_running = True
            self.logger.info("MITRE ATT&CK service started")
        except Exception as e:
            self.logger.error("Failed to start MITRE ATT&CK service", error=str(e))
            raise
    
    async def stop(self) -> None:
        """Stop the MITRE ATT&CK service."""
        try:
            await self.http_client.aclose()
            await self.caching_service.stop()
            self.is_running = False
            self.logger.info("MITRE ATT&CK service stopped")
        except Exception as e:
            self.logger.error("Error stopping MITRE ATT&CK service", error=str(e))
            raise
    
    async def enrich(self, data: Dict[str, Any], data_type: DataType) -> Dict[str, Any]:
        """Enrich data with MITRE ATT&CK mappings."""
        try:
            self.logger.info(
                "Starting MITRE ATT&CK enrichment",
                data_type=data_type
            )
            
            start_time = datetime.utcnow()
            
            # Map data to MITRE ATT&CK techniques
            mitre_attack = await self._map_to_mitre_attack(data, data_type)
            
            # Calculate processing time
            processing_time = (datetime.utcnow() - start_time).total_seconds()
            
            # Apply enrichment to original data
            enriched_data = await self._apply_enrichment(data, mitre_attack)
            
            # Determine confidence and sources
            confidence = self._calculate_confidence(mitre_attack)
            sources = ["mitre_attack_framework"]
            
            return {
                "data": mitre_attack.model_dump(),
                "enriched_data": enriched_data,
                "confidence": confidence,
                "sources": sources,
                "metadata": {
                    "framework_version": mitre_attack.framework_version,
                    "techniques_mapped": len(mitre_attack.techniques),
                    "tactics_mapped": len(mitre_attack.tactics),
                    "processing_time": processing_time,
                    "risk_score": mitre_attack.risk_score,
                }
            }
            
        except Exception as e:
            self.logger.error("Error in MITRE ATT&CK enrichment", error=str(e))
            raise
    
    async def _load_mitre_data(self) -> None:
        """Load MITRE ATT&CK data from various sources."""
        try:
            # Check cache first
            cached_data = await self.caching_service.get_mitre_data()
            if cached_data:
                self._parse_mitre_data(cached_data)
                self.logger.info("Loaded MITRE ATT&CK data from cache")
                return
            
            # Download from GitHub
            for framework, url in self.mitre_urls.items():
                try:
                    response = await self.http_client.get(url)
                    response.raise_for_status()
                    
                    mitre_data = response.json()
                    self._parse_mitre_data(mitre_data)
                    
                    # Cache the data
                    await self.caching_service.cache_mitre_data(mitre_data)
                    
                    self.logger.info(
                        "Downloaded MITRE ATT&CK data",
                        framework=framework,
                        objects=len(mitre_data.get("objects", []))
                    )
                    
                except Exception as e:
                    self.logger.error(
                        "Failed to download MITRE data",
                        framework=framework,
                        error=str(e)
                    )
            
            # Load default data if download fails
            if not self.techniques:
                self._load_default_mitre_data()
            
        except Exception as e:
            self.logger.error("Error loading MITRE ATT&CK data", error=str(e))
            # Load minimal default data
            self._load_default_mitre_data()
    
    def _parse_mitre_data(self, mitre_data: Dict[str, Any]) -> None:
        """Parse MITRE ATT&CK data and populate internal structures."""
        objects = mitre_data.get("objects", [])
        
        for obj in objects:
            obj_type = obj.get("type")
            
            if obj_type == "attack-pattern":
                self._parse_technique(obj)
            elif obj_type == "x-mitre-tactic":
                self._parse_tactic(obj)
            elif obj_type == "course-of-action":
                self._parse_mitigation(obj)
            elif obj_type == "x-mitre-data-source":
                self._parse_data_source(obj)
    
    def _parse_technique(self, obj: Dict[str, Any]) -> None:
        """Parse a MITRE ATT&CK technique object."""
        try:
            # Extract technique ID
            external_refs = obj.get("external_references", [])
            technique_id = None
            
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break
            
            if not technique_id:
                return
            
            # Determine if it's a sub-technique
            is_sub_technique = "." in technique_id
            
            # Extract kill chain phases (tactics)
            tactics = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    phase_name = phase.get("phase_name", "").replace("-", "_")
                    try:
                        tactic = TacticType(phase_name)
                        tactics.append(tactic)
                    except ValueError:
                        pass
            
            # Extract platforms
            platforms = []
            for platform in obj.get("x_mitre_platforms", []):
                try:
                    platform_type = PlatformType(platform.lower().replace(" ", "_"))
                    platforms.append(platform_type)
                except ValueError:
                    pass
            
            # Extract data sources
            data_sources = []
            for data_source in obj.get("x_mitre_data_sources", []):
                data_sources.append(data_source)
            
            if is_sub_technique:
                # Create sub-technique
                parent_id = technique_id.split(".")[0]
                sub_technique = SubTechnique(
                    sub_technique_id=technique_id,
                    parent_technique_id=parent_id,
                    name=obj.get("name", ""),
                    description=obj.get("description", ""),
                    platforms=platforms,
                    data_sources=data_sources,
                    external_references=[
                        ref.get("url", "") for ref in external_refs
                        if ref.get("url")
                    ],
                )
                
                self.sub_techniques[technique_id] = sub_technique
            else:
                # Create technique
                technique = Technique(
                    technique_id=technique_id,
                    name=obj.get("name", ""),
                    description=obj.get("description", ""),
                    tactics=tactics,
                    platforms=platforms,
                    data_sources=data_sources,
                    external_references=[
                        ref.get("url", "") for ref in external_refs
                        if ref.get("url")
                    ],
                )
                
                self.techniques[technique_id] = technique
        
        except Exception as e:
            self.logger.error("Error parsing technique", error=str(e))
    
    def _parse_tactic(self, obj: Dict[str, Any]) -> None:
        """Parse a MITRE ATT&CK tactic object."""
        try:
            # Extract tactic ID
            external_refs = obj.get("external_references", [])
            tactic_id = None
            
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    tactic_id = ref.get("external_id")
                    break
            
            if not tactic_id:
                return
            
            tactic = Tactic(
                tactic_id=tactic_id,
                name=obj.get("name", ""),
                description=obj.get("description", ""),
                short_name=obj.get("x_mitre_shortname", ""),
                external_references=[
                    ref.get("url", "") for ref in external_refs
                    if ref.get("url")
                ],
            )
            
            self.tactics[tactic_id] = tactic
        
        except Exception as e:
            self.logger.error("Error parsing tactic", error=str(e))
    
    def _parse_mitigation(self, obj: Dict[str, Any]) -> None:
        """Parse a MITRE ATT&CK mitigation object."""
        try:
            # Extract mitigation ID
            external_refs = obj.get("external_references", [])
            mitigation_id = None
            
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    mitigation_id = ref.get("external_id")
                    break
            
            if not mitigation_id:
                return
            
            mitigation = Mitigation(
                mitigation_id=mitigation_id,
                name=obj.get("name", ""),
                description=obj.get("description", ""),
                external_references=[
                    ref.get("url", "") for ref in external_refs
                    if ref.get("url")
                ],
            )
            
            self.mitigations[mitigation_id] = mitigation
        
        except Exception as e:
            self.logger.error("Error parsing mitigation", error=str(e))
    
    def _parse_data_source(self, obj: Dict[str, Any]) -> None:
        """Parse a MITRE ATT&CK data source object."""
        try:
            # Extract data source ID
            external_refs = obj.get("external_references", [])
            data_source_id = None
            
            for ref in external_refs:
                if ref.get("source_name") == "mitre-attack":
                    data_source_id = ref.get("external_id")
                    break
            
            if not data_source_id:
                return
            
            # Extract platforms
            platforms = []
            for platform in obj.get("x_mitre_platforms", []):
                try:
                    platform_type = PlatformType(platform.lower().replace(" ", "_"))
                    platforms.append(platform_type)
                except ValueError:
                    pass
            
            data_source = DataSource(
                data_source_id=data_source_id,
                name=obj.get("name", ""),
                description=obj.get("description", ""),
                platforms=platforms,
                data_components=obj.get("x_mitre_data_components", []),
                external_references=[
                    ref.get("url", "") for ref in external_refs
                    if ref.get("url")
                ],
            )
            
            self.data_sources[data_source_id] = data_source
        
        except Exception as e:
            self.logger.error("Error parsing data source", error=str(e))
    
    def _load_default_mitre_data(self) -> None:
        """Load minimal default MITRE ATT&CK data."""
        # Default techniques for common attack patterns
        default_techniques = [
            {
                "technique_id": "T1566",
                "name": "Phishing",
                "description": "Adversaries may send phishing messages to gain access to victim systems.",
                "tactics": [TacticType.INITIAL_ACCESS],
                "platforms": [PlatformType.WINDOWS, PlatformType.LINUX, PlatformType.MACOS],
            },
            {
                "technique_id": "T1190",
                "name": "Exploit Public-Facing Application",
                "description": "Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program.",
                "tactics": [TacticType.INITIAL_ACCESS],
                "platforms": [PlatformType.WINDOWS, PlatformType.LINUX, PlatformType.MACOS],
            },
            {
                "technique_id": "T1210",
                "name": "Exploitation of Remote Services",
                "description": "Adversaries may exploit remote services to gain unauthorized access to internal systems.",
                "tactics": [TacticType.LATERAL_MOVEMENT],
                "platforms": [PlatformType.WINDOWS, PlatformType.LINUX, PlatformType.MACOS],
            },
        ]
        
        for tech_data in default_techniques:
            technique = Technique(**tech_data)
            self.techniques[technique.technique_id] = technique
        
        self.logger.info("Loaded default MITRE ATT&CK data")
    
    async def _map_to_mitre_attack(self, data: Dict[str, Any], data_type: DataType) -> MitreAttack:
        """Map data to MITRE ATT&CK techniques based on data type."""
        mitre_attack = MitreAttack(
            mapping_id=f"mitre_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}",
            data_type=data_type.value,
            confidence=0.0,
            risk_score=0.0,
        )
        
        # Get mapping rules for data type
        mapping_rules = self.mapping_rules.get(data_type, [])
        
        # Apply mapping rules
        for rule in mapping_rules:
            try:
                if self._rule_matches(data, rule):
                    techniques = rule.get("techniques", [])
                    confidence = rule.get("confidence", 0.5)
                    
                    for technique_id in techniques:
                        technique = self.techniques.get(technique_id)
                        if technique:
                            mitre_attack.techniques.append(technique)
                            
                            # Add associated tactics
                            for tactic_type in technique.tactics:
                                tactic_id = self._get_tactic_id(tactic_type)
                                if tactic_id:
                                    tactic = self.tactics.get(tactic_id)
                                    if tactic and tactic not in mitre_attack.tactics:
                                        mitre_attack.tactics.append(tactic)
                            
                            # Add platforms
                            mitre_attack.platforms.extend(technique.platforms)
                            
                            # Add data sources
                            for ds_name in technique.data_sources:
                                data_source = self._find_data_source(ds_name)
                                if data_source and data_source not in mitre_attack.data_sources:
                                    mitre_attack.data_sources.append(data_source)
                    
                    # Update confidence
                    mitre_attack.confidence = max(mitre_attack.confidence, confidence)
            
            except Exception as e:
                self.logger.error("Error applying mapping rule", error=str(e))
        
        # Remove duplicates
        mitre_attack.platforms = list(set(mitre_attack.platforms))
        
        # Calculate risk score
        mitre_attack.risk_score = self._calculate_risk_score(mitre_attack)
        
        # Generate recommendations
        mitre_attack.detection_recommendations = self._generate_detection_recommendations(mitre_attack)
        mitre_attack.mitigation_recommendations = self._generate_mitigation_recommendations(mitre_attack)
        
        return mitre_attack
    
    def _get_sbom_mapping_rules(self) -> List[Dict[str, Any]]:
        """Get MITRE ATT&CK mapping rules for SBOM data."""
        return [
            {
                "name": "Vulnerable Components",
                "condition": {
                    "type": "has_vulnerabilities",
                    "severity": ["high", "critical"]
                },
                "techniques": ["T1190", "T1210"],
                "confidence": 0.8,
                "description": "Components with high/critical vulnerabilities may be exploited"
            },
            {
                "name": "Suspicious Download Sources",
                "condition": {
                    "type": "suspicious_download_location",
                    "patterns": ["suspicious", "unknown", "compromised"]
                },
                "techniques": ["T1195"],
                "confidence": 0.7,
                "description": "Components from suspicious sources may be supply chain compromised"
            },
            {
                "name": "Outdated Components",
                "condition": {
                    "type": "outdated_components",
                    "age_threshold": 365
                },
                "techniques": ["T1190"],
                "confidence": 0.6,
                "description": "Outdated components may have known vulnerabilities"
            },
        ]
    
    def _get_cve_mapping_rules(self) -> List[Dict[str, Any]]:
        """Get MITRE ATT&CK mapping rules for CVE data."""
        return [
            {
                "name": "Remote Code Execution",
                "condition": {
                    "type": "cve_type",
                    "patterns": ["remote code execution", "rce", "code execution"]
                },
                "techniques": ["T1190", "T1210"],
                "confidence": 0.9,
                "description": "RCE vulnerabilities enable initial access and lateral movement"
            },
            {
                "name": "Privilege Escalation",
                "condition": {
                    "type": "cve_type",
                    "patterns": ["privilege escalation", "escalation", "elevation"]
                },
                "techniques": ["T1068"],
                "confidence": 0.9,
                "description": "Privilege escalation vulnerabilities enable elevation of privileges"
            },
            {
                "name": "Information Disclosure",
                "condition": {
                    "type": "cve_type",
                    "patterns": ["information disclosure", "data leak", "exposure"]
                },
                "techniques": ["T1083", "T1005"],
                "confidence": 0.7,
                "description": "Information disclosure vulnerabilities enable data collection"
            },
            {
                "name": "Authentication Bypass",
                "condition": {
                    "type": "cve_type",
                    "patterns": ["authentication bypass", "auth bypass", "bypass"]
                },
                "techniques": ["T1078"],
                "confidence": 0.8,
                "description": "Authentication bypass vulnerabilities enable unauthorized access"
            },
        ]
    
    def _get_runtime_mapping_rules(self) -> List[Dict[str, Any]]:
        """Get MITRE ATT&CK mapping rules for runtime behavior data."""
        return [
            {
                "name": "Network Connections",
                "condition": {
                    "type": "network_connections",
                    "suspicious": True
                },
                "techniques": ["T1071", "T1043"],
                "confidence": 0.7,
                "description": "Suspicious network connections may indicate C2 communication"
            },
            {
                "name": "Process Creation",
                "condition": {
                    "type": "process_creation",
                    "suspicious": True
                },
                "techniques": ["T1059", "T1106"],
                "confidence": 0.8,
                "description": "Suspicious process creation may indicate malicious execution"
            },
            {
                "name": "File System Access",
                "condition": {
                    "type": "file_access",
                    "sensitive": True
                },
                "techniques": ["T1083", "T1005"],
                "confidence": 0.6,
                "description": "Access to sensitive files may indicate data collection"
            },
            {
                "name": "Registry Modifications",
                "condition": {
                    "type": "registry_access",
                    "suspicious": True
                },
                "techniques": ["T1112"],
                "confidence": 0.7,
                "description": "Registry modifications may indicate persistence mechanisms"
            },
        ]
    
    def _rule_matches(self, data: Dict[str, Any], rule: Dict[str, Any]) -> bool:
        """Check if a mapping rule matches the given data."""
        condition = rule.get("condition", {})
        condition_type = condition.get("type")
        
        if condition_type == "has_vulnerabilities":
            return self._check_vulnerabilities(data, condition)
        elif condition_type == "suspicious_download_location":
            return self._check_download_locations(data, condition)
        elif condition_type == "outdated_components":
            return self._check_outdated_components(data, condition)
        elif condition_type == "cve_type":
            return self._check_cve_type(data, condition)
        elif condition_type == "network_connections":
            return self._check_network_connections(data, condition)
        elif condition_type == "process_creation":
            return self._check_process_creation(data, condition)
        elif condition_type == "file_access":
            return self._check_file_access(data, condition)
        elif condition_type == "registry_access":
            return self._check_registry_access(data, condition)
        
        return False
    
    def _check_vulnerabilities(self, data: Dict[str, Any], condition: Dict[str, Any]) -> bool:
        """Check if data has vulnerabilities matching the condition."""
        severity_filter = condition.get("severity", [])
        
        for vuln in data.get("vulnerabilities", []):
            vuln_severity = vuln.get("severity", "").lower()
            if vuln_severity in severity_filter:
                return True
        
        return False
    
    def _check_download_locations(self, data: Dict[str, Any], condition: Dict[str, Any]) -> bool:
        """Check if data has suspicious download locations."""
        patterns = condition.get("patterns", [])
        
        for component in data.get("components", []):
            download_location = component.get("download_location", "").lower()
            for pattern in patterns:
                if pattern in download_location:
                    return True
        
        return False
    
    def _check_outdated_components(self, data: Dict[str, Any], condition: Dict[str, Any]) -> bool:
        """Check if data has outdated components."""
        age_threshold = condition.get("age_threshold", 365)
        current_date = datetime.utcnow()
        
        for component in data.get("components", []):
            # This is a simplified check - in reality, you'd need component age data
            # For now, we'll use a heuristic based on version patterns
            version = component.get("version", "")
            if self._is_old_version(version):
                return True
        
        return False
    
    def _check_cve_type(self, data: Dict[str, Any], condition: Dict[str, Any]) -> bool:
        """Check if CVE matches the type condition."""
        patterns = condition.get("patterns", [])
        description = data.get("description", "").lower()
        
        for pattern in patterns:
            if pattern in description:
                return True
        
        return False
    
    def _check_network_connections(self, data: Dict[str, Any], condition: Dict[str, Any]) -> bool:
        """Check if runtime data has suspicious network connections."""
        for event in data.get("events", []):
            if event.get("event_type") == "network_connection":
                # Check for suspicious indicators
                event_data = event.get("data", {})
                dest_ip = event_data.get("destination_ip", "")
                dest_port = event_data.get("destination_port", 0)
                
                # Heuristic for suspicious connections
                if self._is_suspicious_network_connection(dest_ip, dest_port):
                    return True
        
        return False
    
    def _check_process_creation(self, data: Dict[str, Any], condition: Dict[str, Any]) -> bool:
        """Check if runtime data has suspicious process creation."""
        for event in data.get("events", []):
            if event.get("event_type") == "process_start":
                event_data = event.get("data", {})
                process_name = event_data.get("process_name", "")
                command_line = event_data.get("command_line", "")
                
                # Heuristic for suspicious processes
                if self._is_suspicious_process(process_name, command_line):
                    return True
        
        return False
    
    def _check_file_access(self, data: Dict[str, Any], condition: Dict[str, Any]) -> bool:
        """Check if runtime data has sensitive file access."""
        for event in data.get("events", []):
            if event.get("event_type") == "file_access":
                event_data = event.get("data", {})
                file_path = event_data.get("file_path", "")
                
                # Check for sensitive file paths
                if self._is_sensitive_file_path(file_path):
                    return True
        
        return False
    
    def _check_registry_access(self, data: Dict[str, Any], condition: Dict[str, Any]) -> bool:
        """Check if runtime data has suspicious registry access."""
        for event in data.get("events", []):
            if event.get("event_type") == "registry_access":
                event_data = event.get("data", {})
                registry_key = event_data.get("registry_key", "")
                
                # Check for suspicious registry keys
                if self._is_suspicious_registry_key(registry_key):
                    return True
        
        return False
    
    def _is_old_version(self, version: str) -> bool:
        """Heuristic to determine if a version is old."""
        # Simple heuristic - look for version patterns that suggest old versions
        old_patterns = [
            r"^[0-1]\.",  # Version 0.x or 1.x
            r"^2\.[0-5]\.",  # Version 2.0-2.5
            r"2019|2020|2021",  # Year in version
        ]
        
        for pattern in old_patterns:
            if re.search(pattern, version):
                return True
        
        return False
    
    def _is_suspicious_network_connection(self, dest_ip: str, dest_port: int) -> bool:
        """Heuristic to determine if a network connection is suspicious."""
        # Common suspicious ports
        suspicious_ports = [4444, 5555, 6666, 7777, 8888, 9999]
        
        # Check for suspicious ports
        if dest_port in suspicious_ports:
            return True
        
        # Check for private IP ranges connecting to external services
        if dest_ip.startswith(("192.168.", "10.", "172.")):
            return False
        
        return False
    
    def _is_suspicious_process(self, process_name: str, command_line: str) -> bool:
        """Heuristic to determine if a process is suspicious."""
        suspicious_processes = [
            "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
            "mshta.exe", "rundll32.exe", "regsvr32.exe"
        ]
        
        suspicious_commands = [
            "invoke-expression", "downloadstring", "base64", "encoded",
            "bypass", "unrestricted", "hidden", "windowstyle"
        ]
        
        # Check process name
        if process_name.lower() in suspicious_processes:
            return True
        
        # Check command line
        command_lower = command_line.lower()
        for cmd in suspicious_commands:
            if cmd in command_lower:
                return True
        
        return False
    
    def _is_sensitive_file_path(self, file_path: str) -> bool:
        """Heuristic to determine if a file path is sensitive."""
        sensitive_paths = [
            "system32", "syswow64", "windows", "program files",
            "users", "documents", "desktop", "downloads", "appdata"
        ]
        
        file_lower = file_path.lower()
        for path in sensitive_paths:
            if path in file_lower:
                return True
        
        return False
    
    def _is_suspicious_registry_key(self, registry_key: str) -> bool:
        """Heuristic to determine if a registry key is suspicious."""
        suspicious_keys = [
            "run", "runonce", "currentversion", "winlogon",
            "services", "drivers", "policies", "security"
        ]
        
        key_lower = registry_key.lower()
        for key in suspicious_keys:
            if key in key_lower:
                return True
        
        return False
    
    def _get_tactic_id(self, tactic_type: TacticType) -> Optional[str]:
        """Get tactic ID from tactic type."""
        tactic_mapping = {
            TacticType.INITIAL_ACCESS: "TA0001",
            TacticType.EXECUTION: "TA0002",
            TacticType.PERSISTENCE: "TA0003",
            TacticType.PRIVILEGE_ESCALATION: "TA0004",
            TacticType.DEFENSE_EVASION: "TA0005",
            TacticType.CREDENTIAL_ACCESS: "TA0006",
            TacticType.DISCOVERY: "TA0007",
            TacticType.LATERAL_MOVEMENT: "TA0008",
            TacticType.COLLECTION: "TA0009",
            TacticType.COMMAND_AND_CONTROL: "TA0011",
            TacticType.EXFILTRATION: "TA0010",
            TacticType.IMPACT: "TA0040",
        }
        
        return tactic_mapping.get(tactic_type)
    
    def _find_data_source(self, name: str) -> Optional[DataSource]:
        """Find data source by name."""
        for ds in self.data_sources.values():
            if ds.name.lower() == name.lower():
                return ds
        return None
    
    def _calculate_confidence(self, mitre_attack: MitreAttack) -> float:
        """Calculate confidence score for MITRE ATT&CK mapping."""
        if not mitre_attack.techniques:
            return 0.0
        
        # Base confidence on number of techniques mapped
        technique_confidence = min(len(mitre_attack.techniques) * 0.2, 1.0)
        
        # Adjust based on data quality
        data_quality_factor = 0.8  # Assume good data quality
        
        return technique_confidence * data_quality_factor
    
    def _calculate_risk_score(self, mitre_attack: MitreAttack) -> float:
        """Calculate risk score based on MITRE ATT&CK mapping."""
        if not mitre_attack.techniques:
            return 0.0
        
        # Base score on number of techniques and tactics
        technique_score = len(mitre_attack.techniques) * 1.0
        tactic_score = len(mitre_attack.tactics) * 0.5
        
        # Adjust for high-impact techniques
        high_impact_techniques = ["T1190", "T1210", "T1068", "T1071"]
        impact_bonus = 0.0
        
        for technique in mitre_attack.techniques:
            if technique.technique_id in high_impact_techniques:
                impact_bonus += 1.0
        
        risk_score = technique_score + tactic_score + impact_bonus
        
        return min(risk_score, 10.0)
    
    def _generate_detection_recommendations(self, mitre_attack: MitreAttack) -> List[str]:
        """Generate detection recommendations based on mapped techniques."""
        recommendations = []
        
        # Generate recommendations based on data sources
        data_sources = set()
        for technique in mitre_attack.techniques:
            data_sources.update(technique.data_sources)
        
        for ds in data_sources:
            recommendations.append(f"Monitor {ds} for suspicious activity")
        
        # Add technique-specific recommendations
        technique_recommendations = {
            "T1190": "Implement web application firewalls and regular vulnerability scanning",
            "T1566": "Deploy email security solutions and conduct phishing awareness training",
            "T1210": "Implement network segmentation and monitor lateral movement",
            "T1071": "Monitor network traffic for C2 communications",
            "T1059": "Monitor process creation and command-line arguments",
        }
        
        for technique in mitre_attack.techniques:
            if technique.technique_id in technique_recommendations:
                recommendations.append(technique_recommendations[technique.technique_id])
        
        return list(set(recommendations))  # Remove duplicates
    
    def _generate_mitigation_recommendations(self, mitre_attack: MitreAttack) -> List[str]:
        """Generate mitigation recommendations based on mapped techniques."""
        recommendations = []
        
        # Get mitigations for mapped techniques
        mitigation_ids = set()
        for technique in mitre_attack.techniques:
            mitigation_ids.update(technique.mitigations)
        
        for mitigation_id in mitigation_ids:
            mitigation = self.mitigations.get(mitigation_id)
            if mitigation:
                recommendations.append(mitigation.description)
        
        # Add general recommendations
        general_recommendations = [
            "Keep systems and applications updated",
            "Implement defense in depth security controls",
            "Conduct regular security awareness training",
            "Monitor and log security events",
            "Implement incident response procedures",
        ]
        
        recommendations.extend(general_recommendations)
        
        return list(set(recommendations))  # Remove duplicates
    
    async def _apply_enrichment(
        self,
        original_data: Dict[str, Any],
        mitre_attack: MitreAttack
    ) -> Dict[str, Any]:
        """Apply MITRE ATT&CK enrichment to original data."""
        enriched_data = original_data.copy()
        
        # Add MITRE ATT&CK summary
        enriched_data["mitre_attack"] = {
            "framework_version": mitre_attack.framework_version,
            "confidence": mitre_attack.confidence,
            "risk_score": mitre_attack.risk_score,
            "techniques_count": len(mitre_attack.techniques),
            "tactics_count": len(mitre_attack.tactics),
            "mitigations_count": len(mitre_attack.mitigations),
            "platforms": [p.value for p in mitre_attack.platforms],
            "detection_recommendations": mitre_attack.detection_recommendations,
            "mitigation_recommendations": mitre_attack.mitigation_recommendations,
        }
        
        # Add techniques summary
        if mitre_attack.techniques:
            enriched_data["mitre_techniques"] = [
                {
                    "technique_id": technique.technique_id,
                    "name": technique.name,
                    "tactics": [t.value for t in technique.tactics],
                    "platforms": [p.value for p in technique.platforms],
                    "detection_level": technique.detection_level.value,
                    "mitigation_level": technique.mitigation_level.value,
                }
                for technique in mitre_attack.techniques
            ]
        
        # Add tactics summary
        if mitre_attack.tactics:
            enriched_data["mitre_tactics"] = [
                {
                    "tactic_id": tactic.tactic_id,
                    "name": tactic.name,
                    "description": tactic.description,
                }
                for tactic in mitre_attack.tactics
            ]
        
        return enriched_data
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform health check on the MITRE ATT&CK service."""
        health_status = {
            "service": "mitre_attack",
            "status": "healthy" if self.is_running else "stopped",
            "data_loaded": {
                "techniques": len(self.techniques),
                "sub_techniques": len(self.sub_techniques),
                "tactics": len(self.tactics),
                "mitigations": len(self.mitigations),
                "data_sources": len(self.data_sources),
            },
            "timestamp": datetime.utcnow().isoformat(),
        }
        
        # Check caching service
        try:
            cache_health = await self.caching_service.health_check()
            health_status["caching"] = cache_health
        except Exception as e:
            health_status["caching"] = {"status": "unhealthy", "error": str(e)}
        
        return health_status
    
    def get_stats(self) -> Dict[str, Any]:
        """Get MITRE ATT&CK service statistics."""
        return {
            "service": "mitre_attack",
            "is_running": self.is_running,
            "techniques_loaded": len(self.techniques),
            "sub_techniques_loaded": len(self.sub_techniques),
            "tactics_loaded": len(self.tactics),
            "mitigations_loaded": len(self.mitigations),
            "data_sources_loaded": len(self.data_sources),
            "mapping_rules": sum(len(rules) for rules in self.mapping_rules.values()),
            "timestamp": datetime.utcnow().isoformat(),
        }