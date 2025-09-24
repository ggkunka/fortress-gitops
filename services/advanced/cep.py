"""
Complex Event Processing (CEP) Service

This service provides real-time complex event processing capabilities for security events,
enabling pattern detection, correlation, and automated response to complex event sequences.
"""

import asyncio
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Union, Callable, AsyncGenerator
from enum import Enum
from dataclasses import dataclass, field
import re
from collections import defaultdict, deque
import numpy as np

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.events.event_bus import EventBus
from shared.data.models import SecurityEvent

logger = get_logger(__name__)
metrics = get_metrics()


class RuleOperator(str, Enum):
    """CEP rule operators."""
    AND = "and"
    OR = "or"
    NOT = "not"
    SEQUENCE = "sequence"
    WITHIN = "within"
    FOLLOWED_BY = "followed_by"
    COUNT = "count"
    AVG = "avg"
    SUM = "sum"
    MAX = "max"
    MIN = "min"


class EventPattern(str, Enum):
    """Predefined event patterns."""
    BRUTE_FORCE = "brute_force"
    DATA_EXFILTRATION = "data_exfiltration"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    APT_BEHAVIOR = "apt_behavior"
    INSIDER_THREAT = "insider_threat"
    ANOMALOUS_ACCESS = "anomalous_access"
    COMPLIANCE_VIOLATION = "compliance_violation"


@dataclass
class EventCondition:
    """Event condition for CEP rules."""
    field: str
    operator: str
    value: Any
    case_sensitive: bool = True
    
    def matches(self, event: SecurityEvent) -> bool:
        """Check if event matches this condition."""
        event_value = getattr(event, self.field, None)
        if event_value is None:
            return False
        
        # Handle case sensitivity for string comparisons
        if isinstance(event_value, str) and isinstance(self.value, str) and not self.case_sensitive:
            event_value = event_value.lower()
            compare_value = self.value.lower()
        else:
            compare_value = self.value
        
        # Apply operator
        if self.operator == "equals":
            return event_value == compare_value
        elif self.operator == "not_equals":
            return event_value != compare_value
        elif self.operator == "contains":
            return str(compare_value) in str(event_value)
        elif self.operator == "regex":
            return bool(re.search(compare_value, str(event_value)))
        elif self.operator == "greater_than":
            return event_value > compare_value
        elif self.operator == "less_than":
            return event_value < compare_value
        elif self.operator == "in":
            return event_value in compare_value
        elif self.operator == "not_in":
            return event_value not in compare_value
        else:
            return False


@dataclass
class CEPRule:
    """Complex Event Processing rule."""
    rule_id: str
    name: str
    description: str
    pattern: EventPattern
    conditions: List[EventCondition]
    operator: RuleOperator
    time_window: Optional[timedelta] = None
    threshold: Optional[int] = None
    group_by: List[str] = field(default_factory=list)
    actions: List[str] = field(default_factory=list)
    severity: str = "medium"
    enabled: bool = True
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    
    def evaluate(self, events: List[SecurityEvent]) -> bool:
        """Evaluate rule against a list of events."""
        if not self.enabled or not events:
            return False
        
        # Apply time window filter if specified
        if self.time_window:
            cutoff_time = datetime.now(timezone.utc) - self.time_window
            events = [e for e in events if e.timestamp >= cutoff_time]
        
        # Group events if specified
        if self.group_by:
            grouped_events = self._group_events(events)
            return any(self._evaluate_group(group) for group in grouped_events.values())
        else:
            return self._evaluate_group(events)
    
    def _group_events(self, events: List[SecurityEvent]) -> Dict[str, List[SecurityEvent]]:
        """Group events by specified fields."""
        groups = defaultdict(list)
        for event in events:
            group_key = "|".join(str(getattr(event, field, "")) for field in self.group_by)
            groups[group_key].append(event)
        return groups
    
    def _evaluate_group(self, events: List[SecurityEvent]) -> bool:
        """Evaluate rule against a group of events."""
        if self.operator == RuleOperator.AND:
            return self._evaluate_and(events)
        elif self.operator == RuleOperator.OR:
            return self._evaluate_or(events)
        elif self.operator == RuleOperator.SEQUENCE:
            return self._evaluate_sequence(events)
        elif self.operator == RuleOperator.COUNT:
            return self._evaluate_count(events)
        elif self.operator == RuleOperator.WITHIN:
            return self._evaluate_within(events)
        else:
            return False
    
    def _evaluate_and(self, events: List[SecurityEvent]) -> bool:
        """Evaluate AND condition."""
        for condition in self.conditions:
            if not any(condition.matches(event) for event in events):
                return False
        return True
    
    def _evaluate_or(self, events: List[SecurityEvent]) -> bool:
        """Evaluate OR condition."""
        for condition in self.conditions:
            if any(condition.matches(event) for event in events):
                return True
        return False
    
    def _evaluate_sequence(self, events: List[SecurityEvent]) -> bool:
        """Evaluate sequence condition."""
        events_sorted = sorted(events, key=lambda e: e.timestamp)
        condition_index = 0
        
        for event in events_sorted:
            if condition_index < len(self.conditions):
                if self.conditions[condition_index].matches(event):
                    condition_index += 1
        
        return condition_index == len(self.conditions)
    
    def _evaluate_count(self, events: List[SecurityEvent]) -> bool:
        """Evaluate count condition."""
        matching_events = []
        for event in events:
            if any(condition.matches(event) for condition in self.conditions):
                matching_events.append(event)
        
        return len(matching_events) >= (self.threshold or 1)
    
    def _evaluate_within(self, events: List[SecurityEvent]) -> bool:
        """Evaluate within time window condition."""
        if not self.time_window:
            return False
        
        # Find events that match conditions within time window
        now = datetime.now(timezone.utc)
        recent_events = [e for e in events if (now - e.timestamp) <= self.time_window]
        
        return self._evaluate_count(recent_events)


@dataclass
class CEPAlert:
    """Complex event processing alert."""
    alert_id: str
    rule_id: str
    rule_name: str
    pattern: EventPattern
    severity: str
    message: str
    events: List[SecurityEvent]
    timestamp: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    resolved: bool = False
    resolved_at: Optional[datetime] = None


class EventWindow:
    """Sliding window for event processing."""
    
    def __init__(self, size: int, time_window: Optional[timedelta] = None):
        self.size = size
        self.time_window = time_window
        self.events: deque = deque(maxlen=size)
        self.event_times: deque = deque(maxlen=size)
    
    def add_event(self, event: SecurityEvent):
        """Add event to window."""
        now = datetime.now(timezone.utc)
        self.events.append(event)
        self.event_times.append(now)
        
        # Remove events outside time window
        if self.time_window:
            cutoff_time = now - self.time_window
            while self.event_times and self.event_times[0] < cutoff_time:
                self.events.popleft()
                self.event_times.popleft()
    
    def get_events(self) -> List[SecurityEvent]:
        """Get all events in window."""
        return list(self.events)
    
    def clear(self):
        """Clear window."""
        self.events.clear()
        self.event_times.clear()


class ComplexEventProcessor:
    """
    Complex Event Processing engine for real-time security event analysis.
    
    Features:
    - Pattern detection and matching
    - Temporal event correlation
    - Statistical analysis and aggregation
    - Real-time alerting
    - Rule-based event processing
    - Machine learning-enhanced detection
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.rules: Dict[str, CEPRule] = {}
        self.windows: Dict[str, EventWindow] = {}
        self.pattern_detectors: Dict[EventPattern, Callable] = {}
        self.event_buffer: deque = deque(maxlen=10000)
        self.alert_handlers: List[Callable] = []
        self.statistics: Dict[str, Any] = defaultdict(int)
        
        # Event bus for publishing alerts
        self.event_bus: Optional[EventBus] = None
        
        # Processing settings
        self.max_window_size = self.config.get("max_window_size", 1000)
        self.default_time_window = timedelta(minutes=self.config.get("default_time_window_minutes", 15))
        self.processing_interval = self.config.get("processing_interval_seconds", 1.0)
        
        # Initialize pattern detectors
        self._initialize_pattern_detectors()
        
        # Load predefined rules
        self._load_predefined_rules()
        
        logger.info("Complex Event Processor initialized")
    
    async def initialize(self) -> bool:
        """Initialize the CEP service."""
        try:
            # Initialize event bus connection
            self.event_bus = EventBus()
            await self.event_bus.initialize()
            
            # Start event processing loop
            asyncio.create_task(self._processing_loop())
            
            logger.info("CEP service initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize CEP service: {e}")
            return False
    
    async def cleanup(self) -> bool:
        """Cleanup CEP service."""
        try:
            if self.event_bus:
                await self.event_bus.cleanup()
            
            logger.info("CEP service cleaned up successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to cleanup CEP service: {e}")
            return False
    
    @traced("cep_process_event")
    async def process_event(self, event: SecurityEvent) -> List[CEPAlert]:
        """Process a single security event."""
        alerts = []
        
        try:
            # Add event to buffer
            self.event_buffer.append(event)
            
            # Update statistics
            self.statistics["events_processed"] += 1
            
            # Add event to all windows
            for window in self.windows.values():
                window.add_event(event)
            
            # Evaluate all rules
            for rule in self.rules.values():
                if rule.enabled:
                    # Get relevant events for rule evaluation
                    if rule.group_by:
                        # Use appropriate window or recent events
                        recent_events = self._get_recent_events(rule.time_window or self.default_time_window)
                    else:
                        recent_events = list(self.event_buffer)
                    
                    if rule.evaluate(recent_events):
                        alert = await self._create_alert(rule, recent_events, event)
                        alerts.append(alert)
                        
                        # Publish alert
                        if self.event_bus:
                            await self.event_bus.publish("cep.alert", alert)
                        
                        # Call alert handlers
                        for handler in self.alert_handlers:
                            try:
                                await handler(alert)
                            except Exception as e:
                                logger.warning(f"Alert handler failed: {e}")
            
            # Run pattern detectors
            pattern_alerts = await self._run_pattern_detectors(event)
            alerts.extend(pattern_alerts)
            
            logger.debug(f"Processed event {event.event_id}, generated {len(alerts)} alerts")
            return alerts
            
        except Exception as e:
            logger.error(f"Failed to process event: {e}")
            return []
    
    def add_rule(self, rule: CEPRule) -> bool:
        """Add a CEP rule."""
        try:
            if rule.rule_id in self.rules:
                logger.warning(f"Rule {rule.rule_id} already exists, updating")
            
            self.rules[rule.rule_id] = rule
            
            # Create window for rule if needed
            if rule.time_window:
                window_id = f"rule_{rule.rule_id}"
                self.windows[window_id] = EventWindow(
                    size=self.max_window_size,
                    time_window=rule.time_window
                )
            
            logger.info(f"Added CEP rule: {rule.rule_id}")
            metrics.cep_rules_added.inc()
            return True
            
        except Exception as e:
            logger.error(f"Failed to add rule {rule.rule_id}: {e}")
            return False
    
    def remove_rule(self, rule_id: str) -> bool:
        """Remove a CEP rule."""
        try:
            if rule_id in self.rules:
                del self.rules[rule_id]
                
                # Remove associated window
                window_id = f"rule_{rule_id}"
                if window_id in self.windows:
                    del self.windows[window_id]
                
                logger.info(f"Removed CEP rule: {rule_id}")
                metrics.cep_rules_removed.inc()
                return True
            else:
                logger.warning(f"Rule {rule_id} not found")
                return False
                
        except Exception as e:
            logger.error(f"Failed to remove rule {rule_id}: {e}")
            return False
    
    def get_rule(self, rule_id: str) -> Optional[CEPRule]:
        """Get a CEP rule."""
        return self.rules.get(rule_id)
    
    def list_rules(self) -> List[CEPRule]:
        """List all CEP rules."""
        return list(self.rules.values())
    
    def add_alert_handler(self, handler: Callable[[CEPAlert], None]):
        """Add alert handler callback."""
        self.alert_handlers.append(handler)
    
    def remove_alert_handler(self, handler: Callable[[CEPAlert], None]):
        """Remove alert handler callback."""
        if handler in self.alert_handlers:
            self.alert_handlers.remove(handler)
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get CEP statistics."""
        return {
            "events_processed": self.statistics["events_processed"],
            "alerts_generated": self.statistics["alerts_generated"],
            "rules_count": len(self.rules),
            "active_rules": len([r for r in self.rules.values() if r.enabled]),
            "windows_count": len(self.windows),
            "buffer_size": len(self.event_buffer),
            "patterns_detected": self.statistics["patterns_detected"]
        }
    
    def _initialize_pattern_detectors(self):
        """Initialize built-in pattern detectors."""
        self.pattern_detectors = {
            EventPattern.BRUTE_FORCE: self._detect_brute_force,
            EventPattern.DATA_EXFILTRATION: self._detect_data_exfiltration,
            EventPattern.PRIVILEGE_ESCALATION: self._detect_privilege_escalation,
            EventPattern.LATERAL_MOVEMENT: self._detect_lateral_movement,
            EventPattern.APT_BEHAVIOR: self._detect_apt_behavior,
            EventPattern.INSIDER_THREAT: self._detect_insider_threat,
            EventPattern.ANOMALOUS_ACCESS: self._detect_anomalous_access,
            EventPattern.COMPLIANCE_VIOLATION: self._detect_compliance_violation
        }
    
    def _load_predefined_rules(self):
        """Load predefined CEP rules."""
        # Brute force detection rule
        brute_force_rule = CEPRule(
            rule_id="brute_force_detection",
            name="Brute Force Attack Detection",
            description="Detect multiple failed login attempts from same source",
            pattern=EventPattern.BRUTE_FORCE,
            conditions=[
                EventCondition("event_type", "equals", "authentication"),
                EventCondition("status", "equals", "failed"),
            ],
            operator=RuleOperator.COUNT,
            time_window=timedelta(minutes=5),
            threshold=5,
            group_by=["source_ip"],
            actions=["alert", "block_ip"],
            severity="high"
        )
        self.add_rule(brute_force_rule)
        
        # Data exfiltration detection rule
        exfiltration_rule = CEPRule(
            rule_id="data_exfiltration_detection",
            name="Data Exfiltration Detection",
            description="Detect large data transfers outside business hours",
            pattern=EventPattern.DATA_EXFILTRATION,
            conditions=[
                EventCondition("event_type", "equals", "data_transfer"),
                EventCondition("bytes_transferred", "greater_than", 100000000),  # 100MB
            ],
            operator=RuleOperator.AND,
            time_window=timedelta(hours=1),
            actions=["alert", "investigate"],
            severity="critical"
        )
        self.add_rule(exfiltration_rule)
        
        # Privilege escalation detection rule
        privilege_escalation_rule = CEPRule(
            rule_id="privilege_escalation_detection",
            name="Privilege Escalation Detection",
            description="Detect privilege escalation attempts",
            pattern=EventPattern.PRIVILEGE_ESCALATION,
            conditions=[
                EventCondition("event_type", "equals", "privilege_change"),
                EventCondition("new_privileges", "contains", "admin"),
            ],
            operator=RuleOperator.AND,
            actions=["alert", "investigate"],
            severity="high"
        )
        self.add_rule(privilege_escalation_rule)
    
    async def _processing_loop(self):
        """Main event processing loop."""
        while True:
            try:
                await asyncio.sleep(self.processing_interval)
                
                # Periodic cleanup and maintenance
                await self._cleanup_old_events()
                
            except Exception as e:
                logger.error(f"Error in CEP processing loop: {e}")
    
    async def _cleanup_old_events(self):
        """Clean up old events from buffers."""
        cutoff_time = datetime.now(timezone.utc) - timedelta(hours=24)
        
        # Clean event buffer
        while self.event_buffer and self.event_buffer[0].timestamp < cutoff_time:
            self.event_buffer.popleft()
    
    def _get_recent_events(self, time_window: timedelta) -> List[SecurityEvent]:
        """Get recent events within time window."""
        cutoff_time = datetime.now(timezone.utc) - time_window
        return [e for e in self.event_buffer if e.timestamp >= cutoff_time]
    
    async def _create_alert(self, rule: CEPRule, events: List[SecurityEvent], trigger_event: SecurityEvent) -> CEPAlert:
        """Create CEP alert from rule and events."""
        alert_id = f"cep_{rule.rule_id}_{int(datetime.now(timezone.utc).timestamp())}"
        
        # Filter events that actually match the rule conditions
        matching_events = []
        for event in events:
            if any(condition.matches(event) for condition in rule.conditions):
                matching_events.append(event)
        
        # Include trigger event if not already in matching events
        if trigger_event not in matching_events:
            matching_events.append(trigger_event)
        
        alert = CEPAlert(
            alert_id=alert_id,
            rule_id=rule.rule_id,
            rule_name=rule.name,
            pattern=rule.pattern,
            severity=rule.severity,
            message=f"CEP Rule '{rule.name}' triggered: {rule.description}",
            events=matching_events[:10],  # Limit to last 10 events
            timestamp=datetime.now(timezone.utc),
            metadata={
                "event_count": len(matching_events),
                "time_window": str(rule.time_window) if rule.time_window else None,
                "threshold": rule.threshold,
                "group_by": rule.group_by,
                "actions": rule.actions
            }
        )
        
        self.statistics["alerts_generated"] += 1
        logger.info(f"Generated CEP alert: {alert_id}")
        
        return alert
    
    async def _run_pattern_detectors(self, event: SecurityEvent) -> List[CEPAlert]:
        """Run pattern detection algorithms."""
        alerts = []
        
        for pattern, detector in self.pattern_detectors.items():
            try:
                if await detector(event):
                    # Create pattern-based alert
                    alert = await self._create_pattern_alert(pattern, event)
                    alerts.append(alert)
                    self.statistics["patterns_detected"] += 1
            except Exception as e:
                logger.warning(f"Pattern detector {pattern} failed: {e}")
        
        return alerts
    
    async def _create_pattern_alert(self, pattern: EventPattern, event: SecurityEvent) -> CEPAlert:
        """Create alert for detected pattern."""
        alert_id = f"pattern_{pattern.value}_{int(datetime.now(timezone.utc).timestamp())}"
        
        return CEPAlert(
            alert_id=alert_id,
            rule_id=f"pattern_{pattern.value}",
            rule_name=f"{pattern.value.replace('_', ' ').title()} Pattern Detection",
            pattern=pattern,
            severity="medium",
            message=f"Detected {pattern.value.replace('_', ' ')} pattern",
            events=[event],
            timestamp=datetime.now(timezone.utc),
            metadata={"pattern_type": pattern.value}
        )
    
    # Pattern detection methods
    async def _detect_brute_force(self, event: SecurityEvent) -> bool:
        """Detect brute force attack patterns."""
        if event.event_type != "authentication" or event.severity != "failed":
            return False
        
        # Check for multiple failures from same source
        recent_events = self._get_recent_events(timedelta(minutes=5))
        failures = [e for e in recent_events 
                   if e.event_type == "authentication" 
                   and e.severity == "failed" 
                   and getattr(e, 'source_ip', None) == getattr(event, 'source_ip', None)]
        
        return len(failures) >= 5
    
    async def _detect_data_exfiltration(self, event: SecurityEvent) -> bool:
        """Detect data exfiltration patterns."""
        if event.event_type != "data_transfer":
            return False
        
        # Check for large transfers or unusual destinations
        bytes_transferred = getattr(event, 'bytes_transferred', 0)
        destination = getattr(event, 'destination', '')
        
        # Large transfer threshold (100MB)
        if bytes_transferred > 100000000:
            return True
        
        # Unusual destination (external domains)
        if destination and not any(domain in destination for domain in ['internal.com', 'company.local']):
            return True
        
        return False
    
    async def _detect_privilege_escalation(self, event: SecurityEvent) -> bool:
        """Detect privilege escalation patterns."""
        return (event.event_type == "privilege_change" and 
                "admin" in str(getattr(event, 'new_privileges', '')).lower())
    
    async def _detect_lateral_movement(self, event: SecurityEvent) -> bool:
        """Detect lateral movement patterns."""
        if event.event_type != "network_connection":
            return False
        
        # Check for connections to multiple internal systems
        recent_events = self._get_recent_events(timedelta(hours=1))
        connections = [e for e in recent_events 
                      if e.event_type == "network_connection" 
                      and getattr(e, 'source_ip', None) == getattr(event, 'source_ip', None)]
        
        unique_destinations = set(getattr(e, 'destination_ip', '') for e in connections)
        return len(unique_destinations) > 10
    
    async def _detect_apt_behavior(self, event: SecurityEvent) -> bool:
        """Detect Advanced Persistent Threat patterns."""
        # Look for combination of reconnaissance, persistence, and exfiltration
        recent_events = self._get_recent_events(timedelta(hours=24))
        
        has_recon = any(e.event_type == "network_scan" for e in recent_events)
        has_persistence = any(e.event_type == "file_creation" and "startup" in str(getattr(e, 'file_path', '')) for e in recent_events)
        has_exfiltration = any(e.event_type == "data_transfer" and getattr(e, 'bytes_transferred', 0) > 10000000 for e in recent_events)
        
        return has_recon and has_persistence and has_exfiltration
    
    async def _detect_insider_threat(self, event: SecurityEvent) -> bool:
        """Detect insider threat patterns."""
        if not hasattr(event, 'user_id'):
            return False
        
        # Check for access to sensitive resources outside normal hours
        hour = event.timestamp.hour
        is_after_hours = hour < 7 or hour > 19
        
        is_sensitive_access = any(keyword in str(getattr(event, 'resource', '')).lower() 
                                 for keyword in ['confidential', 'restricted', 'secret'])
        
        return is_after_hours and is_sensitive_access
    
    async def _detect_anomalous_access(self, event: SecurityEvent) -> bool:
        """Detect anomalous access patterns."""
        if event.event_type != "file_access":
            return False
        
        # Check for access to unusual number of files
        recent_events = self._get_recent_events(timedelta(hours=1))
        user_accesses = [e for e in recent_events 
                        if e.event_type == "file_access" 
                        and getattr(e, 'user_id', None) == getattr(event, 'user_id', None)]
        
        return len(user_accesses) > 100
    
    async def _detect_compliance_violation(self, event: SecurityEvent) -> bool:
        """Detect compliance violation patterns."""
        # Check for access to regulated data without proper authorization
        if event.event_type == "data_access":
            data_classification = getattr(event, 'data_classification', '')
            user_clearance = getattr(event, 'user_clearance', '')
            
            if data_classification in ['confidential', 'restricted'] and user_clearance not in ['high', 'admin']:
                return True
        
        return False