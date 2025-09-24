"""
Pattern Analyzer - Advanced Security Pattern Detection

This service implements sophisticated pattern matching algorithms for detecting
known attack patterns, threat signatures, and security-relevant sequences.
"""

import re
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Pattern, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

logger = get_logger(__name__)
metrics = get_metrics()


class PatternCategory(str, Enum):
    """Pattern categories."""
    ATTACK_SEQUENCE = "attack_sequence"
    THREAT_SIGNATURE = "threat_signature"
    COMPLIANCE_VIOLATION = "compliance_violation"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ABUSE = "privilege_abuse"
    RECONNAISSANCE = "reconnaissance"
    LATERAL_MOVEMENT = "lateral_movement"


@dataclass 
class SecurityPattern:
    """Security pattern definition."""
    name: str
    category: PatternCategory
    pattern_type: str  # regex, sequence, statistical
    signature: str
    severity: str
    confidence_threshold: float
    description: str
    recommendations: List[str]
    metadata: Dict[str, Any]


class PatternAnalyzer:
    """
    Advanced pattern analyzer for security event analysis.
    
    Detects:
    - Known attack patterns (MITRE ATT&CK)
    - Threat signatures
    - Compliance violations
    - Custom security patterns
    - Multi-stage attack sequences
    """
    
    def __init__(self):
        # Pattern libraries
        self.attack_patterns = self._initialize_attack_patterns()
        self.threat_signatures = self._initialize_threat_signatures()
        self.compliance_patterns = self._initialize_compliance_patterns()
        
        # Pattern matching state
        self.sequence_cache = defaultdict(lambda: deque(maxlen=1000))
        self.pattern_cache = {}
        
        # Configuration
        self.max_sequence_length = 50
        self.sequence_timeout = 3600  # 1 hour
        
        logger.info("Pattern analyzer initialized")
    
    def _initialize_attack_patterns(self) -> Dict[str, SecurityPattern]:
        """Initialize MITRE ATT&CK-based patterns."""
        return {
            'credential_dumping': SecurityPattern(
                name="Credential Dumping",
                category=PatternCategory.ATTACK_SEQUENCE,
                pattern_type="sequence",
                signature="process_creation:mimikatz|process_creation:procdump->file_access:SAM|file_access:SYSTEM",
                severity="critical",
                confidence_threshold=0.8,
                description="Potential credential dumping activity detected",
                recommendations=[
                    "Immediately investigate credential dumping activity",
                    "Check for compromised credentials",
                    "Review privileged account usage",
                    "Consider password reset for affected accounts"
                ],
                metadata={
                    "mitre_technique": "T1003",
                    "kill_chain_phase": "credential_access",
                    "data_sources": ["process_monitoring", "file_monitoring"]
                }
            ),
            
            'lateral_movement_psexec': SecurityPattern(
                name="PsExec Lateral Movement",
                category=PatternCategory.LATERAL_MOVEMENT,
                pattern_type="sequence", 
                signature="network_connection:445->process_creation:psexec->process_creation:cmd.exe",
                severity="high",
                confidence_threshold=0.7,
                description="PsExec-based lateral movement detected",
                recommendations=[
                    "Investigate lateral movement activity",
                    "Check source and destination systems",
                    "Review network segmentation",
                    "Validate legitimate administrative activity"
                ],
                metadata={
                    "mitre_technique": "T1021.002",
                    "kill_chain_phase": "lateral_movement",
                    "tools": ["psexec", "sysmon"]
                }
            ),
            
            'powershell_empire': SecurityPattern(
                name="PowerShell Empire Activity",
                category=PatternCategory.ATTACK_SEQUENCE,
                pattern_type="regex",
                signature=r"powershell.*-enc\s+[A-Za-z0-9+/]+=*",
                severity="high",
                confidence_threshold=0.8,
                description="Suspicious encoded PowerShell command detected",
                recommendations=[
                    "Decode and analyze PowerShell command",
                    "Check for Empire or Cobalt Strike signatures",
                    "Investigate process ancestry",
                    "Consider PowerShell logging enhancement"
                ],
                metadata={
                    "mitre_technique": "T1059.001",
                    "kill_chain_phase": "execution",
                    "indicators": ["base64_encoding", "powershell_obfuscation"]
                }
            ),
            
            'privilege_escalation_uac': SecurityPattern(
                name="UAC Bypass Attempt",
                category=PatternCategory.PRIVILEGE_ABUSE,
                pattern_type="sequence",
                signature="registry_modification:HKCU\\Software\\Classes\\ms-settings->process_creation:fodhelper.exe",
                severity="high",
                confidence_threshold=0.75,
                description="UAC bypass attempt using fodhelper technique",
                recommendations=[
                    "Investigate UAC bypass attempt",
                    "Check for privilege escalation",
                    "Review system integrity",
                    "Consider enhanced UAC settings"
                ],
                metadata={
                    "mitre_technique": "T1548.002",
                    "kill_chain_phase": "privilege_escalation", 
                    "bypass_method": "fodhelper"
                }
            ),
            
            'data_staging': SecurityPattern(
                name="Data Staging for Exfiltration",
                category=PatternCategory.DATA_EXFILTRATION,
                pattern_type="sequence",
                signature="file_access:*.doc|*.pdf|*.xls->file_creation:temp_archive->network_connection:external",
                severity="critical",
                confidence_threshold=0.8,
                description="Data staging and potential exfiltration detected",
                recommendations=[
                    "Immediately investigate data exfiltration",
                    "Identify sensitive data accessed",
                    "Block suspicious network connections", 
                    "Review data loss prevention controls"
                ],
                metadata={
                    "mitre_technique": "T1074",
                    "kill_chain_phase": "collection",
                    "data_types": ["documents", "archives"]
                }
            ),
            
            'reconnaissance_netscan': SecurityPattern(
                name="Network Reconnaissance",
                category=PatternCategory.RECONNAISSANCE,
                pattern_type="statistical",
                signature="network_connections:multiple_ports>20&unique_hosts>10",
                severity="medium",
                confidence_threshold=0.6,
                description="Network reconnaissance activity detected",
                recommendations=[
                    "Investigate network scanning activity",
                    "Check for authorized penetration testing",
                    "Review network access controls",
                    "Monitor for follow-on attacks"
                ],
                metadata={
                    "mitre_technique": "T1046",
                    "kill_chain_phase": "discovery",
                    "scan_types": ["port_scan", "host_discovery"]
                }
            )
        }
    
    def _initialize_threat_signatures(self) -> Dict[str, SecurityPattern]:
        """Initialize threat signature patterns."""
        return {
            'ransomware_file_extension': SecurityPattern(
                name="Ransomware File Extension Change",
                category=PatternCategory.THREAT_SIGNATURE,
                pattern_type="regex",
                signature=r"file_rename:.*\.(locked|encrypted|crypto|vault|zepto|locky|cerber)",
                severity="critical",
                confidence_threshold=0.9,
                description="Ransomware file extension pattern detected",
                recommendations=[
                    "IMMEDIATE: Isolate affected systems",
                    "Activate incident response procedures",
                    "Check backup integrity",
                    "Do not pay ransom - contact authorities"
                ],
                metadata={
                    "threat_family": "ransomware",
                    "indicators": ["file_encryption", "extension_change"]
                }
            ),
            
            'webshell_upload': SecurityPattern(
                name="Web Shell Upload",
                category=PatternCategory.THREAT_SIGNATURE,
                pattern_type="regex",
                signature=r"file_upload:.*\.(php|asp|aspx|jsp).*eval\(|exec\(|system\(",
                severity="critical",
                confidence_threshold=0.85,
                description="Potential web shell upload detected",
                recommendations=[
                    "Immediately investigate web shell upload",
                    "Remove malicious files",
                    "Check web application security",
                    "Review file upload controls"
                ],
                metadata={
                    "threat_family": "webshell",
                    "file_types": ["php", "asp", "jsp"],
                    "techniques": ["code_injection", "backdoor"]
                }
            ),
            
            'cryptocurrency_mining': SecurityPattern(
                name="Cryptocurrency Mining",
                category=PatternCategory.THREAT_SIGNATURE,
                pattern_type="regex",
                signature=r"process_creation:.*(xmrig|cpuminer|cgminer)|network_connection:.*:8333|:4444",
                severity="medium",
                confidence_threshold=0.7,
                description="Cryptocurrency mining activity detected",
                recommendations=[
                    "Investigate unauthorized mining activity",
                    "Check system performance impact",
                    "Remove mining software",
                    "Review endpoint security controls"
                ],
                metadata={
                    "threat_family": "cryptomining",
                    "mining_pools": ["common_ports", "mining_software"]
                }
            )
        }
    
    def _initialize_compliance_patterns(self) -> Dict[str, SecurityPattern]:
        """Initialize compliance violation patterns."""
        return {
            'pci_dss_violation': SecurityPattern(
                name="PCI DSS Data Access Violation",
                category=PatternCategory.COMPLIANCE_VIOLATION,
                pattern_type="regex",
                signature=r"file_access:.*credit_card|.*payment.*\.db",
                severity="high",
                confidence_threshold=0.8,
                description="Potential PCI DSS compliance violation - unauthorized cardholder data access",
                recommendations=[
                    "Investigate cardholder data access",
                    "Verify business justification",
                    "Review PCI DSS compliance requirements",
                    "Check data encryption status"
                ],
                metadata={
                    "compliance_framework": "PCI_DSS",
                    "requirement": "3.4",
                    "data_classification": "cardholder_data"
                }
            ),
            
            'hipaa_violation': SecurityPattern(
                name="HIPAA PHI Access Violation",
                category=PatternCategory.COMPLIANCE_VIOLATION,
                pattern_type="regex",
                signature=r"file_access:.*patient.*\.db|.*medical_records|.*phi_",
                severity="high", 
                confidence_threshold=0.8,
                description="Potential HIPAA violation - unauthorized PHI access",
                recommendations=[
                    "Investigate PHI access immediately",
                    "Verify authorized access",
                    "Document potential breach",
                    "Consider breach notification requirements"
                ],
                metadata={
                    "compliance_framework": "HIPAA",
                    "data_classification": "PHI",
                    "breach_notification": "required"
                }
            )
        }
    
    @traced("pattern_analyzer_analyze_patterns")
    async def analyze_patterns(
        self,
        data: Dict[str, Any],
        config: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """Analyze data for security patterns."""
        try:
            patterns_found = []
            
            # Get analysis configuration
            pattern_types = config.get('pattern_types', [
                'attack_patterns', 'threat_signatures', 'compliance_patterns'
            ])
            entity_id = data.get('entity_id', 'unknown')
            
            # Extract events and sequences
            events = self._extract_events(data)
            sequences = self._build_event_sequences(events, entity_id)
            
            # Analyze each pattern type
            if 'attack_patterns' in pattern_types:
                attack_matches = await self._match_attack_patterns(sequences, events)
                patterns_found.extend(attack_matches)
            
            if 'threat_signatures' in pattern_types:
                threat_matches = await self._match_threat_signatures(sequences, events)
                patterns_found.extend(threat_matches)
            
            if 'compliance_patterns' in pattern_types:
                compliance_matches = await self._match_compliance_patterns(sequences, events)
                patterns_found.extend(compliance_matches)
            
            # Apply custom patterns if provided
            custom_patterns = config.get('custom_patterns', [])
            if custom_patterns:
                custom_matches = await self._match_custom_patterns(
                    sequences, events, custom_patterns
                )
                patterns_found.extend(custom_matches)
            
            # Filter by confidence threshold
            confidence_threshold = config.get('confidence_threshold', 0.5)
            filtered_patterns = [
                pattern for pattern in patterns_found
                if pattern.get('confidence', 0) >= confidence_threshold
            ]
            
            # Sort by risk score descending
            filtered_patterns.sort(key=lambda x: x.get('risk_score', 0), reverse=True)
            
            logger.info(f"Pattern analysis found {len(filtered_patterns)} matches for {entity_id}")
            metrics.pattern_analyzer_patterns_found.inc(len(filtered_patterns))
            
            return filtered_patterns
            
        except Exception as e:
            logger.error(f"Error analyzing patterns: {e}")
            metrics.pattern_analyzer_errors.inc()
            raise
    
    def _extract_events(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Extract and normalize events from input data."""
        events = []
        
        if 'events' in data and isinstance(data['events'], list):
            for event in data['events']:
                normalized_event = {
                    'timestamp': event.get('timestamp', datetime.now().isoformat()),
                    'event_type': event.get('type', 'unknown'),
                    'source': event.get('source', 'unknown'),
                    'data': event
                }
                events.append(normalized_event)
        
        elif 'correlation_data' in data:
            # Handle correlation result data
            correlation_data = data['correlation_data']
            if 'events' in correlation_data:
                events = correlation_data['events']
        
        # Sort events by timestamp
        events.sort(key=lambda x: x.get('timestamp', ''))
        
        return events
    
    def _build_event_sequences(
        self,
        events: List[Dict[str, Any]],
        entity_id: str
    ) -> List[List[Dict[str, Any]]]:
        """Build event sequences for pattern matching."""
        # Add events to sequence cache
        sequence_key = f"entity_{entity_id}"
        
        for event in events:
            self.sequence_cache[sequence_key].append(event)
        
        # Build sliding windows of different sizes
        sequences = []
        event_list = list(self.sequence_cache[sequence_key])
        
        # Create sequences of different lengths
        for window_size in [3, 5, 10, 20]:
            if len(event_list) >= window_size:
                for i in range(len(event_list) - window_size + 1):
                    sequence = event_list[i:i + window_size]
                    sequences.append(sequence)
        
        return sequences
    
    async def _match_attack_patterns(
        self,
        sequences: List[List[Dict[str, Any]]],
        events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Match against attack patterns."""
        matches = []
        
        for pattern_name, pattern in self.attack_patterns.items():
            pattern_matches = await self._apply_pattern(
                pattern, sequences, events
            )
            matches.extend(pattern_matches)
        
        return matches
    
    async def _match_threat_signatures(
        self,
        sequences: List[List[Dict[str, Any]]],
        events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Match against threat signatures."""
        matches = []
        
        for pattern_name, pattern in self.threat_signatures.items():
            pattern_matches = await self._apply_pattern(
                pattern, sequences, events
            )
            matches.extend(pattern_matches)
        
        return matches
    
    async def _match_compliance_patterns(
        self,
        sequences: List[List[Dict[str, Any]]],
        events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Match against compliance patterns."""
        matches = []
        
        for pattern_name, pattern in self.compliance_patterns.items():
            pattern_matches = await self._apply_pattern(
                pattern, sequences, events
            )
            matches.extend(pattern_matches)
        
        return matches
    
    async def _match_custom_patterns(
        self,
        sequences: List[List[Dict[str, Any]]],
        events: List[Dict[str, Any]],
        custom_patterns: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Match against custom patterns."""
        matches = []
        
        for custom_pattern_config in custom_patterns:
            # Convert custom pattern config to SecurityPattern
            pattern = SecurityPattern(
                name=custom_pattern_config.get('name', 'Custom Pattern'),
                category=PatternCategory(custom_pattern_config.get('category', 'attack_sequence')),
                pattern_type=custom_pattern_config.get('pattern_type', 'regex'),
                signature=custom_pattern_config.get('signature', ''),
                severity=custom_pattern_config.get('severity', 'medium'),
                confidence_threshold=custom_pattern_config.get('confidence_threshold', 0.7),
                description=custom_pattern_config.get('description', 'Custom security pattern'),
                recommendations=custom_pattern_config.get('recommendations', []),
                metadata=custom_pattern_config.get('metadata', {})
            )
            
            pattern_matches = await self._apply_pattern(
                pattern, sequences, events
            )
            matches.extend(pattern_matches)
        
        return matches
    
    async def _apply_pattern(
        self,
        pattern: SecurityPattern,
        sequences: List[List[Dict[str, Any]]],
        events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Apply a security pattern to events/sequences."""
        matches = []
        
        try:
            if pattern.pattern_type == "regex":
                matches = self._apply_regex_pattern(pattern, events)
            elif pattern.pattern_type == "sequence":
                matches = self._apply_sequence_pattern(pattern, sequences)
            elif pattern.pattern_type == "statistical":
                matches = self._apply_statistical_pattern(pattern, events)
            
            # Add pattern metadata to matches
            for match in matches:
                match['pattern_name'] = pattern.name
                match['pattern_category'] = pattern.category.value
                match['pattern_metadata'] = pattern.metadata
                
                # Calculate confidence if not already set
                if 'confidence' not in match:
                    match['confidence'] = pattern.confidence_threshold
                
                # Set severity and risk score
                match['severity'] = pattern.severity
                if 'risk_score' not in match:
                    severity_scores = {
                        'critical': 90,
                        'high': 75,
                        'medium': 50,
                        'low': 25,
                        'informational': 10
                    }
                    match['risk_score'] = severity_scores.get(pattern.severity, 50)
                
                # Add recommendations
                match['recommendations'] = pattern.recommendations
                match['description'] = pattern.description
        
        except Exception as e:
            logger.error(f"Error applying pattern {pattern.name}: {e}")
        
        return matches
    
    def _apply_regex_pattern(
        self,
        pattern: SecurityPattern,
        events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Apply regex pattern matching."""
        matches = []
        
        try:
            regex = re.compile(pattern.signature, re.IGNORECASE)
            
            for event in events:
                # Convert event to searchable string
                event_str = self._event_to_string(event)
                
                regex_match = regex.search(event_str)
                if regex_match:
                    confidence = 1.0  # Regex matches are binary
                    
                    match = {
                        'type': 'regex_match',
                        'confidence': confidence,
                        'matched_text': regex_match.group(),
                        'event_timestamp': event.get('timestamp'),
                        'event_type': event.get('event_type'),
                        'evidence': {
                            'regex_pattern': pattern.signature,
                            'matched_groups': regex_match.groups(),
                            'match_position': regex_match.span(),
                            'full_event': event
                        },
                        'affected_entities': [event.get('source', 'unknown')]
                    }
                    
                    matches.append(match)
        
        except re.error as e:
            logger.error(f"Invalid regex pattern {pattern.signature}: {e}")
        
        return matches
    
    def _apply_sequence_pattern(
        self,
        pattern: SecurityPattern,
        sequences: List[List[Dict[str, Any]]]
    ) -> List[Dict[str, Any]]:
        """Apply sequence pattern matching."""
        matches = []
        
        # Parse sequence pattern (simplified)
        # Format: "event_type1:detail->event_type2:detail->event_type3:detail"
        pattern_steps = pattern.signature.split('->')
        pattern_steps = [step.strip() for step in pattern_steps]
        
        for sequence in sequences:
            if len(sequence) < len(pattern_steps):
                continue
            
            # Try to match pattern at each position in sequence
            for start_idx in range(len(sequence) - len(pattern_steps) + 1):
                sequence_match = True
                matched_events = []
                
                for i, pattern_step in enumerate(pattern_steps):
                    event = sequence[start_idx + i]
                    
                    if not self._event_matches_step(event, pattern_step):
                        sequence_match = False
                        break
                    
                    matched_events.append(event)
                
                if sequence_match:
                    # Calculate confidence based on time gaps
                    confidence = self._calculate_sequence_confidence(matched_events)
                    
                    match = {
                        'type': 'sequence_match',
                        'confidence': confidence,
                        'matched_events': len(matched_events),
                        'sequence_length': len(pattern_steps),
                        'first_event_timestamp': matched_events[0].get('timestamp'),
                        'last_event_timestamp': matched_events[-1].get('timestamp'),
                        'evidence': {
                            'sequence_pattern': pattern.signature,
                            'matched_events': matched_events,
                            'time_span': self._calculate_time_span(matched_events)
                        },
                        'affected_entities': list(set(
                            event.get('source', 'unknown') for event in matched_events
                        ))
                    }
                    
                    matches.append(match)
                    break  # Don't match overlapping sequences
        
        return matches
    
    def _apply_statistical_pattern(
        self,
        pattern: SecurityPattern,
        events: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Apply statistical pattern matching."""
        matches = []
        
        # Parse statistical pattern
        # Format: "field:threshold_condition"
        # Example: "network_connections:count>20&unique_hosts>10"
        
        try:
            # Simple statistical analysis
            event_counts = defaultdict(int)
            unique_values = defaultdict(set)
            
            for event in events:
                event_type = event.get('event_type', '')
                source = event.get('source', '')
                
                event_counts[event_type] += 1
                unique_values['sources'].add(source)
                
                # Extract numeric fields
                event_data = event.get('data', {})
                for key, value in event_data.items():
                    if isinstance(value, (int, float)):
                        unique_values[key].add(value)
            
            # Check statistical conditions (simplified)
            if 'network_connections' in pattern.signature:
                connection_count = event_counts.get('network_connection', 0)
                unique_hosts = len(unique_values.get('destination', set()))
                
                if connection_count > 20 and unique_hosts > 10:
                    confidence = min(1.0, (connection_count / 20) * (unique_hosts / 10) * 0.5)
                    
                    match = {
                        'type': 'statistical_match',
                        'confidence': confidence,
                        'connection_count': connection_count,
                        'unique_hosts': unique_hosts,
                        'evidence': {
                            'statistical_pattern': pattern.signature,
                            'event_counts': dict(event_counts),
                            'unique_counts': {k: len(v) for k, v in unique_values.items()}
                        },
                        'affected_entities': list(unique_values.get('sources', set()))
                    }
                    
                    matches.append(match)
        
        except Exception as e:
            logger.error(f"Error in statistical pattern matching: {e}")
        
        return matches
    
    def _event_to_string(self, event: Dict[str, Any]) -> str:
        """Convert event to searchable string."""
        parts = []
        
        parts.append(f"{event.get('event_type', '')}")
        
        if 'data' in event:
            for key, value in event['data'].items():
                parts.append(f"{key}:{value}")
        
        return " ".join(parts)
    
    def _event_matches_step(self, event: Dict[str, Any], pattern_step: str) -> bool:
        """Check if event matches a pattern step."""
        # Parse pattern step: "event_type:detail"
        if ':' in pattern_step:
            expected_type, expected_detail = pattern_step.split(':', 1)
        else:
            expected_type = pattern_step
            expected_detail = None
        
        event_type = event.get('event_type', '')
        
        # Check event type match
        if expected_type not in event_type:
            return False
        
        # Check detail match if specified
        if expected_detail:
            event_str = self._event_to_string(event)
            if expected_detail not in event_str:
                return False
        
        return True
    
    def _calculate_sequence_confidence(self, events: List[Dict[str, Any]]) -> float:
        """Calculate confidence for sequence match."""
        if len(events) < 2:
            return 1.0
        
        # Calculate time gaps between events
        time_gaps = []
        for i in range(1, len(events)):
            try:
                prev_time = datetime.fromisoformat(events[i-1].get('timestamp', ''))
                curr_time = datetime.fromisoformat(events[i].get('timestamp', ''))
                gap = (curr_time - prev_time).total_seconds()
                time_gaps.append(gap)
            except:
                time_gaps.append(0)
        
        # Confidence decreases with larger time gaps
        avg_gap = sum(time_gaps) / len(time_gaps) if time_gaps else 0
        
        if avg_gap < 60:  # < 1 minute
            return 1.0
        elif avg_gap < 300:  # < 5 minutes
            return 0.9
        elif avg_gap < 1800:  # < 30 minutes
            return 0.7
        elif avg_gap < 3600:  # < 1 hour
            return 0.5
        else:
            return 0.3
    
    def _calculate_time_span(self, events: List[Dict[str, Any]]) -> float:
        """Calculate time span of events in seconds."""
        if len(events) < 2:
            return 0
        
        try:
            first_time = datetime.fromisoformat(events[0].get('timestamp', ''))
            last_time = datetime.fromisoformat(events[-1].get('timestamp', ''))
            return (last_time - first_time).total_seconds()
        except:
            return 0
    
    def get_stats(self) -> Dict[str, Any]:
        """Get pattern analyzer statistics."""
        return {
            'attack_patterns': len(self.attack_patterns),
            'threat_signatures': len(self.threat_signatures),
            'compliance_patterns': len(self.compliance_patterns),
            'sequence_cache_size': len(self.sequence_cache),
            'max_sequence_length': self.max_sequence_length,
            'sequence_timeout': self.sequence_timeout
        }