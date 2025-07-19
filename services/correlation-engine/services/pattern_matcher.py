"""
Pattern Matcher - Advanced Pattern Detection

This service implements sophisticated pattern matching algorithms
for detecting complex event patterns and anomalies.
"""

import re
import math
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import defaultdict, deque
from dataclasses import dataclass
from enum import Enum

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

from ..models.correlation import CorrelationEvent, CorrelationState

logger = get_logger(__name__)
metrics = get_metrics()


class PatternType(str, Enum):
    """Pattern types."""
    SEQUENCE = "sequence"
    FREQUENCY = "frequency"
    ANOMALY = "anomaly"
    BEHAVIORAL = "behavioral"
    TEMPORAL = "temporal"
    STATISTICAL = "statistical"


@dataclass
class PatternSignature:
    """Pattern signature for matching."""
    pattern_type: PatternType
    name: str
    signature: str
    weight: float
    confidence_threshold: float
    metadata: Dict[str, Any]


@dataclass
class PatternMatch:
    """Pattern match result."""
    pattern_name: str
    pattern_type: PatternType
    confidence: float
    events: List[CorrelationEvent]
    metadata: Dict[str, Any]
    timestamp: datetime


class PatternMatcher:
    """
    Advanced pattern matcher for security events.
    
    Implements various pattern detection algorithms including:
    - Sequence pattern matching
    - Frequency analysis
    - Anomaly detection
    - Behavioral pattern analysis
    - Temporal pattern analysis
    - Statistical pattern analysis
    """
    
    def __init__(self):
        self.patterns: Dict[str, PatternSignature] = {}
        self.event_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=10000))
        self.baseline_stats: Dict[str, Dict[str, float]] = {}
        
        # Initialize built-in patterns
        self._initialize_builtin_patterns()
        
        logger.info("Pattern matcher initialized")
    
    def _initialize_builtin_patterns(self):
        """Initialize built-in security patterns."""
        # Brute force attack pattern
        self.patterns["brute_force_login"] = PatternSignature(
            pattern_type=PatternType.FREQUENCY,
            name="Brute Force Login Attack",
            signature="login_failed",
            weight=0.8,
            confidence_threshold=0.7,
            metadata={
                "threshold": 5,
                "time_window": 300,
                "field": "user_id",
                "description": "Multiple failed login attempts"
            }
        )
        
        # Port scan pattern
        self.patterns["port_scan"] = PatternSignature(
            pattern_type=PatternType.FREQUENCY,
            name="Port Scan Attack",
            signature="network_connection",
            weight=0.7,
            confidence_threshold=0.6,
            metadata={
                "threshold": 20,
                "time_window": 60,
                "field": "destination_port",
                "description": "Multiple connections to different ports"
            }
        )
        
        # Privilege escalation sequence
        self.patterns["privilege_escalation"] = PatternSignature(
            pattern_type=PatternType.SEQUENCE,
            name="Privilege Escalation",
            signature="login_success->sudo_command->admin_access",
            weight=0.9,
            confidence_threshold=0.8,
            metadata={
                "sequence": ["login_success", "sudo_command", "admin_access"],
                "max_time_gap": 1800,
                "description": "Suspicious privilege escalation sequence"
            }
        )
        
        # Data exfiltration pattern
        self.patterns["data_exfiltration"] = PatternSignature(
            pattern_type=PatternType.ANOMALY,
            name="Data Exfiltration",
            signature="file_access",
            weight=0.8,
            confidence_threshold=0.7,
            metadata={
                "anomaly_type": "volume",
                "threshold_multiplier": 3.0,
                "time_window": 3600,
                "description": "Unusual data access volume"
            }
        )
        
        # Lateral movement pattern
        self.patterns["lateral_movement"] = PatternSignature(
            pattern_type=PatternType.BEHAVIORAL,
            name="Lateral Movement",
            signature="network_connection",
            weight=0.7,
            confidence_threshold=0.6,
            metadata={
                "behavior_type": "network_spread",
                "unique_hosts_threshold": 5,
                "time_window": 1800,
                "description": "Suspicious network lateral movement"
            }
        )
    
    @traced("pattern_matcher_detect_patterns")
    def detect_patterns(
        self, 
        events: List[CorrelationEvent],
        correlation_key: str
    ) -> List[PatternMatch]:
        """Detect patterns in a list of events."""
        matches = []
        
        try:
            # Update event history
            self._update_event_history(events, correlation_key)
            
            # Apply each pattern matcher
            for pattern_name, pattern in self.patterns.items():
                pattern_matches = self._apply_pattern(pattern, events, correlation_key)
                matches.extend(pattern_matches)
            
            # Sort matches by confidence
            matches.sort(key=lambda x: x.confidence, reverse=True)
            
            logger.debug(f"Found {len(matches)} pattern matches for key {correlation_key}")
            metrics.pattern_matcher_matches.inc(len(matches))
            
            return matches
            
        except Exception as e:
            logger.error(f"Error detecting patterns: {e}")
            metrics.pattern_matcher_errors.inc()
            return []
    
    def _update_event_history(self, events: List[CorrelationEvent], correlation_key: str):
        """Update event history for pattern analysis."""
        for event in events:
            self.event_history[correlation_key].append(event)
    
    @traced("pattern_matcher_apply_pattern")
    def _apply_pattern(
        self, 
        pattern: PatternSignature, 
        events: List[CorrelationEvent],
        correlation_key: str
    ) -> List[PatternMatch]:
        """Apply a specific pattern to events."""
        matches = []
        
        try:
            if pattern.pattern_type == PatternType.SEQUENCE:
                matches = self._detect_sequence_pattern(pattern, events, correlation_key)
            
            elif pattern.pattern_type == PatternType.FREQUENCY:
                matches = self._detect_frequency_pattern(pattern, events, correlation_key)
            
            elif pattern.pattern_type == PatternType.ANOMALY:
                matches = self._detect_anomaly_pattern(pattern, events, correlation_key)
            
            elif pattern.pattern_type == PatternType.BEHAVIORAL:
                matches = self._detect_behavioral_pattern(pattern, events, correlation_key)
            
            elif pattern.pattern_type == PatternType.TEMPORAL:
                matches = self._detect_temporal_pattern(pattern, events, correlation_key)
            
            elif pattern.pattern_type == PatternType.STATISTICAL:
                matches = self._detect_statistical_pattern(pattern, events, correlation_key)
            
            # Filter matches by confidence threshold
            filtered_matches = [
                match for match in matches 
                if match.confidence >= pattern.confidence_threshold
            ]
            
            return filtered_matches
            
        except Exception as e:
            logger.error(f"Error applying pattern {pattern.name}: {e}")
            return []
    
    def _detect_sequence_pattern(
        self, 
        pattern: PatternSignature, 
        events: List[CorrelationEvent],
        correlation_key: str
    ) -> List[PatternMatch]:
        """Detect sequence patterns."""
        matches = []
        
        sequence = pattern.metadata.get("sequence", [])
        max_time_gap = pattern.metadata.get("max_time_gap", 3600)
        
        if not sequence:
            return matches
        
        # Get all events for this correlation key
        all_events = list(self.event_history[correlation_key])
        
        # Find sequences
        for i in range(len(all_events) - len(sequence) + 1):
            sequence_events = []
            sequence_match = True
            
            for j, expected_type in enumerate(sequence):
                event = all_events[i + j]
                
                # Check if event type matches
                if event.event_type != expected_type:
                    sequence_match = False
                    break
                
                # Check time gap
                if j > 0:
                    time_diff = (event.event_timestamp - sequence_events[-1].event_timestamp).total_seconds()
                    if time_diff > max_time_gap:
                        sequence_match = False
                        break
                
                sequence_events.append(event)
            
            if sequence_match:
                confidence = self._calculate_sequence_confidence(sequence_events, pattern)
                
                match = PatternMatch(
                    pattern_name=pattern.name,
                    pattern_type=pattern.pattern_type,
                    confidence=confidence,
                    events=sequence_events,
                    metadata={
                        "sequence_length": len(sequence_events),
                        "time_span": (sequence_events[-1].event_timestamp - sequence_events[0].event_timestamp).total_seconds()
                    },
                    timestamp=datetime.now()
                )
                matches.append(match)
        
        return matches
    
    def _detect_frequency_pattern(
        self, 
        pattern: PatternSignature, 
        events: List[CorrelationEvent],
        correlation_key: str
    ) -> List[PatternMatch]:
        """Detect frequency-based patterns."""
        matches = []
        
        threshold = pattern.metadata.get("threshold", 5)
        time_window = pattern.metadata.get("time_window", 300)
        field = pattern.metadata.get("field", "event_type")
        
        # Get events within time window
        now = datetime.now()
        cutoff_time = now - timedelta(seconds=time_window)
        
        recent_events = [
            event for event in self.event_history[correlation_key]
            if event.event_timestamp >= cutoff_time
        ]
        
        # Count events by field
        field_counts = defaultdict(int)
        for event in recent_events:
            field_value = self._get_event_field_value(event, field)
            if field_value:
                field_counts[field_value] += 1
        
        # Check for threshold violations
        for field_value, count in field_counts.items():
            if count >= threshold:
                related_events = [
                    event for event in recent_events
                    if self._get_event_field_value(event, field) == field_value
                ]
                
                confidence = self._calculate_frequency_confidence(count, threshold, pattern)
                
                match = PatternMatch(
                    pattern_name=pattern.name,
                    pattern_type=pattern.pattern_type,
                    confidence=confidence,
                    events=related_events,
                    metadata={
                        "field": field,
                        "field_value": field_value,
                        "count": count,
                        "threshold": threshold,
                        "time_window": time_window
                    },
                    timestamp=datetime.now()
                )
                matches.append(match)
        
        return matches
    
    def _detect_anomaly_pattern(
        self, 
        pattern: PatternSignature, 
        events: List[CorrelationEvent],
        correlation_key: str
    ) -> List[PatternMatch]:
        """Detect anomaly patterns."""
        matches = []
        
        anomaly_type = pattern.metadata.get("anomaly_type", "volume")
        threshold_multiplier = pattern.metadata.get("threshold_multiplier", 3.0)
        time_window = pattern.metadata.get("time_window", 3600)
        
        # Get baseline statistics
        baseline_key = f"{correlation_key}_{pattern.name}"
        baseline = self.baseline_stats.get(baseline_key, {})
        
        if not baseline:
            # Initialize baseline
            self._update_baseline_stats(baseline_key, events)
            return matches
        
        # Check for anomalies
        if anomaly_type == "volume":
            current_volume = len(events)
            expected_volume = baseline.get("avg_volume", 0)
            std_dev = baseline.get("std_dev", 0)
            
            if current_volume > expected_volume + (threshold_multiplier * std_dev):
                confidence = self._calculate_anomaly_confidence(
                    current_volume, expected_volume, std_dev, threshold_multiplier
                )
                
                match = PatternMatch(
                    pattern_name=pattern.name,
                    pattern_type=pattern.pattern_type,
                    confidence=confidence,
                    events=events,
                    metadata={
                        "anomaly_type": anomaly_type,
                        "current_volume": current_volume,
                        "expected_volume": expected_volume,
                        "deviation": current_volume - expected_volume
                    },
                    timestamp=datetime.now()
                )
                matches.append(match)
        
        # Update baseline
        self._update_baseline_stats(baseline_key, events)
        
        return matches
    
    def _detect_behavioral_pattern(
        self, 
        pattern: PatternSignature, 
        events: List[CorrelationEvent],
        correlation_key: str
    ) -> List[PatternMatch]:
        """Detect behavioral patterns."""
        matches = []
        
        behavior_type = pattern.metadata.get("behavior_type", "network_spread")
        time_window = pattern.metadata.get("time_window", 1800)
        
        if behavior_type == "network_spread":
            unique_hosts_threshold = pattern.metadata.get("unique_hosts_threshold", 5)
            
            # Get unique destination hosts
            unique_hosts = set()
            for event in events:
                dest_host = self._get_event_field_value(event, "destination_host")
                if dest_host:
                    unique_hosts.add(dest_host)
            
            if len(unique_hosts) >= unique_hosts_threshold:
                confidence = min(1.0, len(unique_hosts) / (unique_hosts_threshold * 2))
                
                match = PatternMatch(
                    pattern_name=pattern.name,
                    pattern_type=pattern.pattern_type,
                    confidence=confidence,
                    events=events,
                    metadata={
                        "behavior_type": behavior_type,
                        "unique_hosts": len(unique_hosts),
                        "threshold": unique_hosts_threshold,
                        "hosts": list(unique_hosts)
                    },
                    timestamp=datetime.now()
                )
                matches.append(match)
        
        return matches
    
    def _detect_temporal_pattern(
        self, 
        pattern: PatternSignature, 
        events: List[CorrelationEvent],
        correlation_key: str
    ) -> List[PatternMatch]:
        """Detect temporal patterns."""
        matches = []
        
        # Look for time-based patterns like regular intervals
        if len(events) < 3:
            return matches
        
        # Calculate intervals between events
        intervals = []
        for i in range(1, len(events)):
            interval = (events[i].event_timestamp - events[i-1].event_timestamp).total_seconds()
            intervals.append(interval)
        
        # Check for regular intervals (potential scheduled attacks)
        if len(intervals) >= 3:
            avg_interval = sum(intervals) / len(intervals)
            variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
            std_dev = math.sqrt(variance)
            
            # If intervals are very regular (low variance), it might be suspicious
            if std_dev < avg_interval * 0.1 and avg_interval > 0:  # Less than 10% variance
                confidence = min(1.0, 1.0 - (std_dev / avg_interval))
                
                match = PatternMatch(
                    pattern_name=f"{pattern.name}_regular_interval",
                    pattern_type=pattern.pattern_type,
                    confidence=confidence,
                    events=events,
                    metadata={
                        "avg_interval": avg_interval,
                        "std_dev": std_dev,
                        "regularity": 1.0 - (std_dev / avg_interval)
                    },
                    timestamp=datetime.now()
                )
                matches.append(match)
        
        return matches
    
    def _detect_statistical_pattern(
        self, 
        pattern: PatternSignature, 
        events: List[CorrelationEvent],
        correlation_key: str
    ) -> List[PatternMatch]:
        """Detect statistical patterns."""
        matches = []
        
        # Implement statistical analysis like Z-score, chi-square, etc.
        # This is a simplified example
        
        if len(events) < 10:
            return matches
        
        # Calculate Z-score for event frequency
        event_counts = defaultdict(int)
        for event in events:
            event_counts[event.event_type] += 1
        
        counts = list(event_counts.values())
        if len(counts) > 1:
            mean_count = sum(counts) / len(counts)
            std_dev = math.sqrt(sum((x - mean_count) ** 2 for x in counts) / len(counts))
            
            for event_type, count in event_counts.items():
                if std_dev > 0:
                    z_score = (count - mean_count) / std_dev
                    
                    if abs(z_score) > 2.0:  # Significant deviation
                        confidence = min(1.0, abs(z_score) / 4.0)
                        
                        related_events = [e for e in events if e.event_type == event_type]
                        
                        match = PatternMatch(
                            pattern_name=f"{pattern.name}_statistical_outlier",
                            pattern_type=pattern.pattern_type,
                            confidence=confidence,
                            events=related_events,
                            metadata={
                                "event_type": event_type,
                                "count": count,
                                "mean_count": mean_count,
                                "z_score": z_score
                            },
                            timestamp=datetime.now()
                        )
                        matches.append(match)
        
        return matches
    
    def _calculate_sequence_confidence(
        self, 
        events: List[CorrelationEvent], 
        pattern: PatternSignature
    ) -> float:
        """Calculate confidence for sequence patterns."""
        # Base confidence from pattern weight
        confidence = pattern.weight
        
        # Adjust based on time gaps
        if len(events) > 1:
            time_gaps = []
            for i in range(1, len(events)):
                gap = (events[i].event_timestamp - events[i-1].event_timestamp).total_seconds()
                time_gaps.append(gap)
            
            # Penalize very long gaps
            max_gap = max(time_gaps)
            if max_gap > 3600:  # 1 hour
                confidence *= 0.8
            elif max_gap > 1800:  # 30 minutes
                confidence *= 0.9
        
        return min(1.0, confidence)
    
    def _calculate_frequency_confidence(
        self, 
        count: int, 
        threshold: int, 
        pattern: PatternSignature
    ) -> float:
        """Calculate confidence for frequency patterns."""
        # Base confidence from pattern weight
        base_confidence = pattern.weight
        
        # Increase confidence based on how much the count exceeds threshold
        multiplier = min(2.0, count / threshold)
        confidence = base_confidence * multiplier
        
        return min(1.0, confidence)
    
    def _calculate_anomaly_confidence(
        self, 
        current_value: float, 
        expected_value: float, 
        std_dev: float,
        threshold_multiplier: float
    ) -> float:
        """Calculate confidence for anomaly patterns."""
        if std_dev == 0:
            return 1.0 if current_value > expected_value else 0.0
        
        # Calculate Z-score
        z_score = (current_value - expected_value) / std_dev
        
        # Convert Z-score to confidence (0-1)
        confidence = min(1.0, abs(z_score) / (threshold_multiplier * 2))
        
        return confidence
    
    def _get_event_field_value(self, event: CorrelationEvent, field: str) -> Any:
        """Get field value from event."""
        if field in event.event_data:
            return event.event_data[field]
        
        if hasattr(event, field):
            return getattr(event, field)
        
        # Handle nested fields
        if '.' in field:
            parts = field.split('.')
            value = event.event_data
            
            for part in parts:
                if isinstance(value, dict) and part in value:
                    value = value[part]
                else:
                    return None
            
            return value
        
        return None
    
    def _update_baseline_stats(self, baseline_key: str, events: List[CorrelationEvent]):
        """Update baseline statistics for anomaly detection."""
        if baseline_key not in self.baseline_stats:
            self.baseline_stats[baseline_key] = {}
        
        baseline = self.baseline_stats[baseline_key]
        
        # Update volume statistics
        current_volume = len(events)
        
        if "volume_history" not in baseline:
            baseline["volume_history"] = deque(maxlen=100)
        
        baseline["volume_history"].append(current_volume)
        
        # Calculate statistics
        volumes = list(baseline["volume_history"])
        baseline["avg_volume"] = sum(volumes) / len(volumes)
        
        if len(volumes) > 1:
            variance = sum((x - baseline["avg_volume"]) ** 2 for x in volumes) / len(volumes)
            baseline["std_dev"] = math.sqrt(variance)
        else:
            baseline["std_dev"] = 0
    
    def add_custom_pattern(self, pattern: PatternSignature):
        """Add a custom pattern."""
        self.patterns[pattern.name] = pattern
        logger.info(f"Added custom pattern: {pattern.name}")
    
    def remove_pattern(self, pattern_name: str):
        """Remove a pattern."""
        if pattern_name in self.patterns:
            del self.patterns[pattern_name]
            logger.info(f"Removed pattern: {pattern_name}")
    
    def get_patterns(self) -> Dict[str, PatternSignature]:
        """Get all patterns."""
        return self.patterns.copy()
    
    def clear_history(self, correlation_key: str = None):
        """Clear event history."""
        if correlation_key:
            if correlation_key in self.event_history:
                del self.event_history[correlation_key]
        else:
            self.event_history.clear()
            self.baseline_stats.clear()
        
        logger.info(f"Cleared pattern matcher history for {correlation_key or 'all keys'}")