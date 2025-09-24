"""
Threat Analyzer - Advanced Threat Detection and Analysis

This service analyzes security events and patterns to identify potential threats,
classify threat types, and assess threat levels using multiple detection methods.
"""

import re
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from collections import defaultdict, Counter
from dataclasses import dataclass
from enum import Enum

import numpy as np
from scipy import stats

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

logger = get_logger(__name__)
metrics = get_metrics()


class ThreatCategory(str, Enum):
    """Threat categories based on MITRE ATT&CK framework."""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"


class ThreatLevel(str, Enum):
    """Threat severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


@dataclass
class ThreatSignature:
    """Threat signature definition."""
    name: str
    category: ThreatCategory
    description: str
    indicators: List[str]
    confidence_threshold: float
    severity: ThreatLevel
    mitre_techniques: List[str]
    false_positive_indicators: List[str]
    context_requirements: Dict[str, Any]


class ThreatAnalyzer:
    """
    Advanced threat analyzer for security event analysis.
    
    Analyzes:
    - Known threat patterns and signatures
    - APT tactics, techniques, and procedures (TTPs)
    - Malware behaviors and indicators
    - Attack chain reconstruction
    - Threat attribution and classification
    """
    
    def __init__(self):
        # Threat signature database
        self.threat_signatures = self._initialize_threat_signatures()
        self.apt_patterns = self._initialize_apt_patterns()
        self.malware_signatures = self._initialize_malware_signatures()
        
        # Analysis configuration
        self.confidence_threshold = 0.6
        self.correlation_window = 3600  # 1 hour
        self.min_indicators_required = 2
        
        # Threat intelligence cache
        self.threat_intel_cache = {}
        self.cache_ttl = 1800  # 30 minutes
        
        logger.info("Threat analyzer initialized")
    
    def _initialize_threat_signatures(self) -> Dict[str, ThreatSignature]:
        """Initialize threat signature database."""
        return {
            'apt_lateral_movement': ThreatSignature(
                name="APT Lateral Movement",
                category=ThreatCategory.LATERAL_MOVEMENT,
                description="Advanced persistent threat lateral movement patterns",
                indicators=[
                    "process_creation:psexec",
                    "network_connection:445",
                    "authentication:ntlm",
                    "file_creation:admin_share"
                ],
                confidence_threshold=0.8,
                severity=ThreatLevel.HIGH,
                mitre_techniques=["T1021.002", "T1021.001"],
                false_positive_indicators=[
                    "process_parent:sccm",
                    "user_context:admin_scheduled"
                ],
                context_requirements={
                    "time_correlation": True,
                    "source_correlation": True,
                    "min_events": 3
                }
            ),
            
            'ransomware_behavior': ThreatSignature(
                name="Ransomware Activity",
                category=ThreatCategory.IMPACT,
                description="Ransomware encryption and extortion behavior",
                indicators=[
                    "file_modification:mass_encryption",
                    "file_creation:ransom_note",
                    "process_creation:crypto_binary",
                    "network_connection:tor_exit"
                ],
                confidence_threshold=0.9,
                severity=ThreatLevel.CRITICAL,
                mitre_techniques=["T1486", "T1083", "T1490"],
                false_positive_indicators=[
                    "process_parent:backup_software",
                    "user_context:legitimate_encryption"
                ],
                context_requirements={
                    "file_extension_changes": True,
                    "volume_threshold": 100
                }
            ),
            
            'credential_harvesting': ThreatSignature(
                name="Credential Harvesting",
                category=ThreatCategory.CREDENTIAL_ACCESS,
                description="Credential dumping and harvesting activities",
                indicators=[
                    "process_creation:mimikatz",
                    "file_access:sam_database",
                    "registry_access:security_hive",
                    "memory_access:lsass_process"
                ],
                confidence_threshold=0.85,
                severity=ThreatLevel.CRITICAL,
                mitre_techniques=["T1003.001", "T1003.002", "T1003.003"],
                false_positive_indicators=[
                    "process_parent:system_process",
                    "user_context:security_software"
                ],
                context_requirements={
                    "privilege_level": "high",
                    "suspicious_tools": True
                }
            ),
            
            'data_exfiltration': ThreatSignature(
                name="Data Exfiltration",
                category=ThreatCategory.EXFILTRATION,
                description="Suspicious data collection and exfiltration patterns",
                indicators=[
                    "file_access:sensitive_documents",
                    "network_transfer:large_volume",
                    "process_creation:compression_tool",
                    "network_connection:external_cloud"
                ],
                confidence_threshold=0.75,
                severity=ThreatLevel.HIGH,
                mitre_techniques=["T1041", "T1567", "T1074"],
                false_positive_indicators=[
                    "process_parent:backup_agent",
                    "destination:approved_cloud"
                ],
                context_requirements={
                    "data_volume_threshold": 1073741824,  # 1GB
                    "time_correlation": True
                }
            ),
            
            'c2_communication': ThreatSignature(
                name="Command and Control Communication",
                category=ThreatCategory.COMMAND_AND_CONTROL, 
                description="Suspicious command and control communication patterns",
                indicators=[
                    "network_connection:suspicious_domain",
                    "dns_query:dga_pattern",
                    "network_traffic:beaconing",
                    "process_creation:tunneling_tool"
                ],
                confidence_threshold=0.7,
                severity=ThreatLevel.HIGH,
                mitre_techniques=["T1071", "T1568", "T1573"],
                false_positive_indicators=[
                    "destination:whitelist_domain",
                    "process_parent:legitimate_software"
                ],
                context_requirements={
                    "frequency_analysis": True,
                    "protocol_analysis": True
                }
            ),
            
            'persistence_mechanism': ThreatSignature(
                name="Persistence Mechanism",
                category=ThreatCategory.PERSISTENCE,
                description="Malicious persistence establishment",
                indicators=[
                    "registry_modification:run_key",
                    "file_creation:startup_folder",
                    "service_creation:suspicious_service",
                    "scheduled_task:persistence_task"
                ],
                confidence_threshold=0.75,
                severity=ThreatLevel.MEDIUM,
                mitre_techniques=["T1547", "T1053", "T1543"],
                false_positive_indicators=[
                    "process_parent:installer",
                    "digital_signature:valid"
                ],
                context_requirements={
                    "persistence_location": True,
                    "execution_context": True
                }
            )
        }
    
    def _initialize_apt_patterns(self) -> Dict[str, Dict[str, Any]]:
        """Initialize APT group patterns."""
        return {
            'apt28_fancy_bear': {
                'aliases': ['Fancy Bear', 'Pawn Storm', 'Sofacy'],
                'techniques': ['T1566.001', 'T1059.003', 'T1083', 'T1105'],
                'indicators': [
                    'process_creation:x-agent',
                    'network_connection:gameplayit.*',
                    'file_creation:.*\\.scr$',
                    'registry_modification:.*CurrentVersion.*'
                ],
                'confidence_factors': {
                    'tool_overlap': 0.3,
                    'technique_overlap': 0.4,
                    'infrastructure_overlap': 0.3
                }
            },
            
            'apt29_cozy_bear': {
                'aliases': ['Cozy Bear', 'The Dukes', 'CozyDuke'],
                'techniques': ['T1566.002', 'T1059.001', 'T1055', 'T1027'],
                'indicators': [
                    'process_creation:powershell.*-enc',
                    'file_creation:.*\\.lnk$',
                    'network_connection:.*cloudfront.*',
                    'registry_modification:.*Software\\\\Classes.*'
                ],
                'confidence_factors': {
                    'powershell_usage': 0.4,
                    'steganography': 0.3,
                    'cloud_infrastructure': 0.3
                }
            },
            
            'lazarus_group': {
                'aliases': ['Lazarus', 'Hidden Cobra', 'Guardians of Peace'],
                'techniques': ['T1566.001', 'T1204.002', 'T1057', 'T1041'],
                'indicators': [
                    'file_hash:.*lazarus_hash.*',
                    'network_connection:.*bit\\.ly.*',
                    'process_creation:.*wiper.*',
                    'file_creation:.*\\.hwp$'
                ],
                'confidence_factors': {
                    'wiper_malware': 0.5,
                    'cryptocurrency_targeting': 0.3,
                    'destructive_capability': 0.2
                }
            }
        }
    
    def _initialize_malware_signatures(self) -> Dict[str, Dict[str, Any]]:
        """Initialize malware family signatures."""
        return {
            'emotet': {
                'family': 'Banking Trojan',
                'techniques': ['T1566.001', 'T1059.003', 'T1055'],
                'indicators': [
                    'process_injection:explorer.exe',
                    'network_connection:.*emotet_c2.*',
                    'file_creation:.*\\.doc$',
                    'registry_modification:.*Run.*'
                ],
                'behavioral_patterns': [
                    'macro_execution',
                    'process_hollowing',
                    'credential_theft'
                ]
            },
            
            'trickbot': {
                'family': 'Banking Trojan',
                'techniques': ['T1055', 'T1083', 'T1082'],
                'indicators': [
                    'process_creation:.*svchost.*',
                    'file_creation:.*config\\.conf$',
                    'network_connection:.*trickbot_domain.*',
                    'registry_enumeration:installed_software'
                ],
                'behavioral_patterns': [
                    'system_reconnaissance',
                    'lateral_movement',
                    'data_collection'
                ]
            },
            
            'ryuk_ransomware': {
                'family': 'Ransomware',
                'techniques': ['T1486', 'T1490', 'T1083'],
                'indicators': [
                    'file_encryption:mass_encrypt',
                    'file_creation:.*RyukReadMe.*',
                    'process_termination:backup_services',
                    'shadow_copy_deletion:vssadmin'
                ],
                'behavioral_patterns': [
                    'service_termination',
                    'backup_destruction',
                    'file_encryption'
                ]
            }
        }
    
    @traced("threat_analyzer_analyze_threats")
    async def analyze_threats(
        self,
        data: Dict[str, Any],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze data for threat indicators and patterns."""
        try:
            threats = []
            
            # Get analysis configuration
            analysis_types = config.get('analysis_types', [
                'signature_matching', 'apt_attribution', 'malware_detection',
                'attack_chain_analysis', 'threat_hunting'
            ])
            
            entity_id = data.get('entity_id', 'unknown')
            
            # Extract events and indicators
            events = self._extract_events(data)
            indicators = self._extract_indicators(events)
            
            # Run different threat analyses
            for analysis_type in analysis_types:
                if analysis_type == 'signature_matching':
                    signature_threats = await self._analyze_threat_signatures(
                        events, indicators, config
                    )
                    threats.extend(signature_threats)
                
                elif analysis_type == 'apt_attribution':
                    apt_threats = await self._analyze_apt_patterns(
                        events, indicators, config
                    )
                    threats.extend(apt_threats)
                
                elif analysis_type == 'malware_detection':
                    malware_threats = await self._analyze_malware_signatures(
                        events, indicators, config
                    )
                    threats.extend(malware_threats)
                
                elif analysis_type == 'attack_chain_analysis':
                    chain_threats = await self._analyze_attack_chains(
                        events, indicators, config
                    )
                    threats.extend(chain_threats)
                
                elif analysis_type == 'threat_hunting':
                    hunting_threats = await self._hunt_threats(
                        events, indicators, config
                    )
                    threats.extend(hunting_threats)
            
            # Filter and rank threats
            filtered_threats = self._filter_and_rank_threats(threats, config)
            
            logger.info(f"Threat analysis found {len(filtered_threats)} threats for {entity_id}")
            metrics.threat_analyzer_threats_detected.inc(len(filtered_threats))
            
            return filtered_threats
            
        except Exception as e:
            logger.error(f"Error analyzing threats: {e}")
            metrics.threat_analyzer_errors.inc()
            raise
    
    def _extract_events(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract and normalize events from input data."""
        events = []
        
        if 'events' in data and isinstance(data['events'], list):
            events = data['events']
        elif 'correlation_data' in data:
            correlation_data = data['correlation_data']
            if 'events' in correlation_data:
                events = correlation_data['events']
        
        # Normalize events
        normalized_events = []
        for event in events:
            normalized_event = {
                'timestamp': event.get('timestamp', datetime.now().isoformat()),
                'event_type': event.get('type', 'unknown'),
                'source': event.get('source', 'unknown'),
                'data': event,
                'indicators': self._extract_event_indicators(event)
            }
            normalized_events.append(normalized_event)
        
        # Sort by timestamp
        normalized_events.sort(key=lambda x: x.get('timestamp', ''))
        
        return normalized_events
    
    def _extract_event_indicators(self, event: Dict[str, Any]) -> List[str]:
        """Extract threat indicators from a single event."""
        indicators = []
        
        event_type = event.get('type', '')
        
        # Process creation indicators
        if 'process' in event_type:
            if 'process_name' in event:
                indicators.append(f"process_creation:{event['process_name']}")
            if 'command_line' in event:
                indicators.append(f"command_line:{event['command_line']}")
            if 'parent_process' in event:
                indicators.append(f"process_parent:{event['parent_process']}")
        
        # Network indicators
        elif 'network' in event_type:
            if 'destination' in event:
                indicators.append(f"network_connection:{event['destination']}")
            if 'protocol' in event:
                indicators.append(f"network_protocol:{event['protocol']}")
            if 'bytes_transferred' in event:
                indicators.append(f"data_transfer:{event['bytes_transferred']}")
        
        # File system indicators
        elif 'file' in event_type:
            if 'file_path' in event:
                indicators.append(f"file_access:{event['file_path']}")
            if 'file_hash' in event:
                indicators.append(f"file_hash:{event['file_hash']}")
            if 'file_size' in event:
                indicators.append(f"file_size:{event['file_size']}")
        
        # Registry indicators
        elif 'registry' in event_type:
            if 'registry_key' in event:
                indicators.append(f"registry_access:{event['registry_key']}")
            if 'registry_value' in event:
                indicators.append(f"registry_modification:{event['registry_value']}")
        
        return indicators
    
    def _extract_indicators(self, events: List[Dict[str, Any]]) -> Dict[str, List[str]]:
        """Extract and categorize indicators from events."""
        indicators = defaultdict(list)
        
        for event in events:
            event_indicators = event.get('indicators', [])
            for indicator in event_indicators:
                # Categorize indicators
                if indicator.startswith('process_'):
                    indicators['process'].append(indicator)
                elif indicator.startswith('network_'):
                    indicators['network'].append(indicator)
                elif indicator.startswith('file_'):
                    indicators['file'].append(indicator)
                elif indicator.startswith('registry_'):
                    indicators['registry'].append(indicator)
                else:
                    indicators['other'].append(indicator)
        
        return dict(indicators)
    
    async def _analyze_threat_signatures(
        self,
        events: List[Dict[str, Any]],
        indicators: Dict[str, List[str]],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze events against threat signatures."""
        threats = []
        
        for signature_name, signature in self.threat_signatures.items():
            # Check if signature indicators are present
            matched_indicators = []
            total_indicators = len(signature.indicators)
            
            for sig_indicator in signature.indicators:
                # Check for pattern matches in all indicator types
                for category, category_indicators in indicators.items():
                    for indicator in category_indicators:
                        if self._indicator_matches(indicator, sig_indicator):
                            matched_indicators.append({
                                'signature_indicator': sig_indicator,
                                'matched_indicator': indicator,
                                'category': category
                            })
                            break
            
            # Calculate confidence based on matched indicators
            match_ratio = len(matched_indicators) / max(1, total_indicators)
            
            # Check context requirements
            context_satisfied = self._check_context_requirements(
                signature.context_requirements, events, matched_indicators
            )
            
            # Check for false positive indicators
            false_positive_score = self._check_false_positives(
                signature.false_positive_indicators, indicators
            )
            
            # Calculate final confidence
            confidence = match_ratio * context_satisfied * (1 - false_positive_score)
            
            if confidence >= signature.confidence_threshold:
                threat = {
                    'threat_type': signature_name,
                    'threat_category': signature.category.value,
                    'confidence': confidence,
                    'severity': signature.severity.value,
                    'risk_score': self._calculate_threat_risk_score(confidence, signature.severity),
                    'description': signature.description,
                    'mitre_techniques': signature.mitre_techniques,
                    'matched_indicators': matched_indicators,
                    'evidence': {
                        'signature_name': signature_name,
                        'total_indicators': total_indicators,
                        'matched_indicators': len(matched_indicators),
                        'match_ratio': match_ratio,
                        'context_satisfied': context_satisfied,
                        'false_positive_score': false_positive_score
                    },
                    'recommendations': [
                        f"Investigate {signature_name} activity immediately",
                        f"Review MITRE ATT&CK techniques: {', '.join(signature.mitre_techniques)}",
                        "Isolate affected systems if confirmed malicious",
                        "Collect additional forensic evidence"
                    ],
                    'affected_entities': list(set(event.get('source', 'unknown') for event in events))
                }
                
                threats.append(threat)
        
        return threats
    
    async def _analyze_apt_patterns(
        self,
        events: List[Dict[str, Any]],
        indicators: Dict[str, List[str]],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze events for APT group patterns."""
        threats = []
        
        for apt_name, apt_pattern in self.apt_patterns.items():
            # Check for APT-specific indicators
            matched_indicators = []
            confidence_factors = apt_pattern['confidence_factors']
            
            for pattern_indicator in apt_pattern['indicators']:
                for category, category_indicators in indicators.items():
                    for indicator in category_indicators:
                        if re.search(pattern_indicator, indicator, re.IGNORECASE):
                            matched_indicators.append({
                                'apt_indicator': pattern_indicator,
                                'matched_indicator': indicator,
                                'category': category
                            })
            
            if matched_indicators:
                # Calculate APT attribution confidence
                confidence = self._calculate_apt_confidence(
                    matched_indicators, confidence_factors, apt_pattern
                )
                
                if confidence >= 0.6:  # APT attribution threshold
                    threat = {
                        'threat_type': f"APT Attribution: {apt_name}",
                        'threat_category': 'apt_activity',
                        'confidence': confidence,
                        'severity': 'high',
                        'risk_score': min(95, int(confidence * 100)),
                        'description': f"Activity consistent with {apt_name} group patterns",
                        'apt_group': apt_name,
                        'apt_aliases': apt_pattern['aliases'],
                        'mitre_techniques': apt_pattern['techniques'],
                        'matched_indicators': matched_indicators,
                        'evidence': {
                            'apt_group': apt_name,
                            'confidence_breakdown': confidence_factors,
                            'total_matches': len(matched_indicators)
                        },
                        'recommendations': [
                            f"Investigate potential {apt_name} group activity",
                            "Correlate with threat intelligence feeds",
                            "Implement enhanced monitoring for APT TTPs",
                            "Consider threat hunting across environment"
                        ],
                        'affected_entities': list(set(event.get('source', 'unknown') for event in events))
                    }
                    
                    threats.append(threat)
        
        return threats
    
    async def _analyze_malware_signatures(
        self,
        events: List[Dict[str, Any]],
        indicators: Dict[str, List[str]],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze events for malware family signatures."""
        threats = []
        
        for malware_name, malware_sig in self.malware_signatures.items():
            # Check for malware-specific indicators
            matched_indicators = []
            matched_behaviors = []
            
            # Check indicators
            for mal_indicator in malware_sig['indicators']:
                for category, category_indicators in indicators.items():
                    for indicator in category_indicators:
                        if re.search(mal_indicator, indicator, re.IGNORECASE):
                            matched_indicators.append({
                                'malware_indicator': mal_indicator,
                                'matched_indicator': indicator,
                                'category': category
                            })
            
            # Check behavioral patterns
            for behavior in malware_sig['behavioral_patterns']:
                if self._check_behavioral_pattern(behavior, events):
                    matched_behaviors.append(behavior)
            
            # Calculate malware detection confidence
            indicator_score = len(matched_indicators) / max(1, len(malware_sig['indicators']))
            behavior_score = len(matched_behaviors) / max(1, len(malware_sig['behavioral_patterns']))
            confidence = (indicator_score + behavior_score) / 2
            
            if confidence >= 0.7:  # Malware detection threshold
                threat = {
                    'threat_type': f"Malware Detection: {malware_name}",
                    'threat_category': 'malware_activity',
                    'confidence': confidence,
                    'severity': 'high',
                    'risk_score': min(90, int(confidence * 100)),
                    'description': f"Activity consistent with {malware_name} malware family",
                    'malware_family': malware_sig['family'],
                    'mitre_techniques': malware_sig['techniques'],
                    'matched_indicators': matched_indicators,
                    'matched_behaviors': matched_behaviors,
                    'evidence': {
                        'malware_name': malware_name,
                        'indicator_matches': len(matched_indicators),
                        'behavior_matches': len(matched_behaviors),
                        'confidence_breakdown': {
                            'indicator_score': indicator_score,
                            'behavior_score': behavior_score
                        }
                    },
                    'recommendations': [
                        f"Quarantine systems infected with {malware_name}",
                        "Run full antivirus scan on affected systems",
                        "Check for lateral movement to other systems",
                        "Review network traffic for C2 communication"
                    ],
                    'affected_entities': list(set(event.get('source', 'unknown') for event in events))
                }
                
                threats.append(threat)
        
        return threats
    
    async def _analyze_attack_chains(
        self,
        events: List[Dict[str, Any]],
        indicators: Dict[str, List[str]],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze events for attack chain patterns."""
        threats = []
        
        # Define common attack chain patterns
        attack_chains = {
            'kill_chain_full': [
                'reconnaissance', 'weaponization', 'delivery',
                'exploitation', 'installation', 'command_and_control', 'actions'
            ],
            'apt_chain': [
                'initial_access', 'execution', 'persistence',
                'privilege_escalation', 'credential_access', 'lateral_movement'
            ],
            'ransomware_chain': [
                'initial_access', 'execution', 'discovery',
                'collection', 'defense_evasion', 'impact'
            ]
        }
        
        for chain_name, chain_phases in attack_chains.items():
            detected_phases = []
            phase_evidence = {}
            
            # Check for each phase in the attack chain
            for phase in chain_phases:
                phase_indicators = self._get_phase_indicators(phase, events)
                if phase_indicators:
                    detected_phases.append(phase)
                    phase_evidence[phase] = phase_indicators
            
            # Calculate chain completion percentage
            completion_ratio = len(detected_phases) / len(chain_phases)
            
            if completion_ratio >= 0.4:  # At least 40% of chain detected
                confidence = min(1.0, completion_ratio * 1.5)
                
                threat = {
                    'threat_type': f"Attack Chain: {chain_name}",
                    'threat_category': 'attack_chain',
                    'confidence': confidence,
                    'severity': 'high' if completion_ratio > 0.6 else 'medium',
                    'risk_score': min(90, int(completion_ratio * 100)),
                    'description': f"Multi-stage attack chain detected: {chain_name}",
                    'attack_chain': chain_name,
                    'detected_phases': detected_phases,
                    'completion_ratio': completion_ratio,
                    'evidence': {
                        'chain_name': chain_name,
                        'total_phases': len(chain_phases),
                        'detected_phases': len(detected_phases),
                        'phase_evidence': phase_evidence
                    },
                    'recommendations': [
                        f"Investigate multi-stage attack: {chain_name}",
                        "Map attack progression against kill chain",
                        "Identify and block remaining attack phases",
                        "Implement detection for missing phases"
                    ],
                    'affected_entities': list(set(event.get('source', 'unknown') for event in events))
                }
                
                threats.append(threat)
        
        return threats
    
    async def _hunt_threats(
        self,
        events: List[Dict[str, Any]],
        indicators: Dict[str, List[str]],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Hunt for threats using behavioral analysis."""
        threats = []
        
        # Hunt for suspicious patterns
        hunting_patterns = {
            'living_off_the_land': {
                'description': 'Abuse of legitimate tools for malicious purposes',
                'indicators': ['powershell', 'wmic', 'certutil', 'bitsadmin'],
                'threshold': 3
            },
            'defense_evasion': {
                'description': 'Attempts to avoid detection',
                'indicators': ['process_hollowing', 'dll_injection', 'masquerading'],
                'threshold': 2
            },
            'privilege_abuse': {
                'description': 'Abuse of elevated privileges',
                'indicators': ['token_impersonation', 'uac_bypass', 'service_abuse'],
                'threshold': 2
            }
        }
        
        for pattern_name, pattern in hunting_patterns.items():
            matches = 0
            matched_indicators = []
            
            for hunt_indicator in pattern['indicators']:
                for category, category_indicators in indicators.items():
                    for indicator in category_indicators:
                        if hunt_indicator.lower() in indicator.lower():
                            matches += 1
                            matched_indicators.append(indicator)
            
            if matches >= pattern['threshold']:
                confidence = min(1.0, matches / len(pattern['indicators']))
                
                threat = {
                    'threat_type': f"Threat Hunt: {pattern_name}",
                    'threat_category': 'suspicious_activity',
                    'confidence': confidence,
                    'severity': 'medium',
                    'risk_score': min(75, int(confidence * 80)),
                    'description': pattern['description'],
                    'hunting_pattern': pattern_name,
                    'matched_indicators': matched_indicators,
                    'evidence': {
                        'pattern_name': pattern_name,
                        'matches': matches,
                        'threshold': pattern['threshold'],
                        'match_ratio': matches / len(pattern['indicators'])
                    },
                    'recommendations': [
                        f"Investigate {pattern_name} activity",
                        "Correlate with additional data sources",
                        "Validate findings with subject matter experts",
                        "Consider creating custom detection rules"
                    ],
                    'affected_entities': list(set(event.get('source', 'unknown') for event in events))
                }
                
                threats.append(threat)
        
        return threats
    
    def _indicator_matches(self, indicator: str, pattern: str) -> bool:
        """Check if indicator matches pattern."""
        try:
            return bool(re.search(pattern, indicator, re.IGNORECASE))
        except re.error:
            return pattern.lower() in indicator.lower()
    
    def _check_context_requirements(
        self,
        requirements: Dict[str, Any],
        events: List[Dict[str, Any]],
        matched_indicators: List[Dict[str, Any]]
    ) -> float:
        """Check if context requirements are satisfied."""
        if not requirements:
            return 1.0
        
        satisfaction_score = 1.0
        
        # Check minimum events requirement
        if 'min_events' in requirements:
            min_events = requirements['min_events']
            if len(events) < min_events:
                satisfaction_score *= len(events) / min_events
        
        # Check time correlation requirement
        if requirements.get('time_correlation', False):
            if len(events) >= 2:
                time_span = self._calculate_event_time_span(events)
                if time_span > self.correlation_window:
                    satisfaction_score *= 0.7  # Reduce confidence for scattered events
        
        # Check source correlation requirement
        if requirements.get('source_correlation', False):
            sources = set(event.get('source', 'unknown') for event in events)
            if len(sources) > len(events) * 0.8:  # Too many different sources
                satisfaction_score *= 0.8
        
        return satisfaction_score
    
    def _check_false_positives(
        self,
        fp_indicators: List[str],
        indicators: Dict[str, List[str]]
    ) -> float:
        """Check for false positive indicators."""
        if not fp_indicators:
            return 0.0
        
        fp_matches = 0
        total_indicators = sum(len(category_indicators) for category_indicators in indicators.values())
        
        for fp_indicator in fp_indicators:
            for category, category_indicators in indicators.items():
                for indicator in category_indicators:
                    if self._indicator_matches(indicator, fp_indicator):
                        fp_matches += 1
        
        return fp_matches / max(1, total_indicators)
    
    def _calculate_threat_risk_score(self, confidence: float, severity: ThreatLevel) -> int:
        """Calculate threat risk score."""
        severity_scores = {
            ThreatLevel.CRITICAL: 95,
            ThreatLevel.HIGH: 80,
            ThreatLevel.MEDIUM: 60,
            ThreatLevel.LOW: 40,
            ThreatLevel.INFORMATIONAL: 20
        }
        
        base_score = severity_scores.get(severity, 50)
        return int(base_score * confidence)
    
    def _calculate_apt_confidence(
        self,
        matched_indicators: List[Dict[str, Any]],
        confidence_factors: Dict[str, float],
        apt_pattern: Dict[str, Any]
    ) -> float:
        """Calculate APT attribution confidence."""
        base_confidence = len(matched_indicators) / max(1, len(apt_pattern['indicators']))
        
        # Apply confidence factors (simplified)
        factor_boost = sum(confidence_factors.values()) / len(confidence_factors)
        
        return min(1.0, base_confidence * factor_boost)
    
    def _check_behavioral_pattern(self, pattern: str, events: List[Dict[str, Any]]) -> bool:
        """Check if behavioral pattern is present in events."""
        pattern_checks = {
            'macro_execution': lambda e: any('macro' in str(event).lower() for event in e),
            'process_hollowing': lambda e: any('hollowing' in str(event).lower() for event in e),
            'credential_theft': lambda e: any('credential' in str(event).lower() for event in e),
            'system_reconnaissance': lambda e: any('enum' in str(event).lower() for event in e),
            'lateral_movement': lambda e: any('psexec' in str(event).lower() for event in e),
            'data_collection': lambda e: any('collection' in str(event).lower() for event in e),
            'service_termination': lambda e: any('terminate' in str(event).lower() for event in e),
            'backup_destruction': lambda e: any('backup' in str(event).lower() for event in e),
            'file_encryption': lambda e: any('encrypt' in str(event).lower() for event in e)
        }
        
        check_func = pattern_checks.get(pattern)
        return check_func(events) if check_func else False
    
    def _get_phase_indicators(self, phase: str, events: List[Dict[str, Any]]) -> List[str]:
        """Get indicators for a specific attack phase."""
        phase_patterns = {
            'reconnaissance': ['nmap', 'scan', 'enum'],
            'initial_access': ['exploit', 'phishing', 'rdp'],
            'execution': ['powershell', 'cmd', 'wscript'],
            'persistence': ['startup', 'service', 'registry'],
            'privilege_escalation': ['uac', 'token', 'sudo'],
            'credential_access': ['mimikatz', 'sam', 'lsass'],
            'lateral_movement': ['psexec', 'wmi', 'ssh'],
            'collection': ['keylog', 'screen', 'audio'],
            'command_and_control': ['beacon', 'c2', 'tunnel'],
            'exfiltration': ['upload', 'ftp', 'dns'],
            'impact': ['encrypt', 'delete', 'wipe']
        }
        
        patterns = phase_patterns.get(phase, [])
        indicators = []
        
        for event in events:
            event_str = str(event).lower()
            for pattern in patterns:
                if pattern in event_str:
                    indicators.append(f"{phase}:{pattern}")
        
        return indicators
    
    def _calculate_event_time_span(self, events: List[Dict[str, Any]]) -> float:
        """Calculate time span of events in seconds."""
        if len(events) < 2:
            return 0
        
        try:
            timestamps = [
                datetime.fromisoformat(event.get('timestamp', ''))
                for event in events
                if event.get('timestamp')
            ]
            
            if len(timestamps) < 2:
                return 0
            
            return (max(timestamps) - min(timestamps)).total_seconds()
        except:
            return 0
    
    def _filter_and_rank_threats(
        self,
        threats: List[Dict[str, Any]],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Filter and rank threats by risk score."""
        # Filter by confidence threshold
        confidence_threshold = config.get('confidence_threshold', self.confidence_threshold)
        filtered_threats = [
            threat for threat in threats
            if threat.get('confidence', 0) >= confidence_threshold
        ]
        
        # Sort by risk score descending
        filtered_threats.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
        
        # Limit results if specified
        max_results = config.get('max_results', 100)
        return filtered_threats[:max_results]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get threat analyzer statistics."""
        return {
            'threat_signatures': len(self.threat_signatures),
            'apt_patterns': len(self.apt_patterns),
            'malware_signatures': len(self.malware_signatures),
            'confidence_threshold': self.confidence_threshold,
            'correlation_window': self.correlation_window,
            'threat_intel_cache_size': len(self.threat_intel_cache)
        }