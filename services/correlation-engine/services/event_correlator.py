"""
Event Correlator - Core Correlation Logic

This service implements the core correlation logic that combines
pattern matching with rule evaluation to generate correlation results.
"""

import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from uuid import UUID

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

from ..models.correlation import (
    CorrelationRule, CorrelationEvent, CorrelationState, 
    CorrelationEventStatus, get_db
)
from .rule_engine import RuleEngine, ParsedRule
from .pattern_matcher import PatternMatcher, PatternMatch

logger = get_logger(__name__)
metrics = get_metrics()


class EventCorrelator:
    """
    Event correlator that combines pattern matching with rule evaluation.
    
    This service:
    1. Evaluates correlation rules against events
    2. Applies pattern matching to detect complex patterns
    3. Maintains correlation state across time windows
    4. Generates correlation results when conditions are met
    """
    
    def __init__(self, pattern_matcher: PatternMatcher, rule_engine: RuleEngine):
        self.pattern_matcher = pattern_matcher
        self.rule_engine = rule_engine
        
        # Correlation state management
        self.active_correlations: Dict[str, Dict[str, Any]] = {}
        
        logger.info("Event correlator initialized")
    
    @traced("event_correlator_correlate")
    async def correlate(
        self,
        rule: CorrelationRule,
        event: CorrelationEvent,
        state: CorrelationState
    ) -> Optional[Dict[str, Any]]:
        """
        Correlate an event against a rule and return correlation result if conditions are met.
        
        Args:
            rule: The correlation rule to evaluate
            event: The incoming event
            state: Current correlation state
            
        Returns:
            Correlation result dict if correlation is found, None otherwise
        """
        start_time = time.time()
        
        try:
            # Parse the rule if not already parsed
            parsed_rule = self.rule_engine.parse_rule(rule)
            
            # Update correlation state with new event
            await self._update_correlation_state(state, event, parsed_rule)
            
            # Evaluate rule conditions
            conditions_met = self.rule_engine.evaluate_conditions(parsed_rule, event, state)
            
            if not conditions_met:
                logger.debug(f"Rule conditions not met for rule {rule.name}")
                return None
            
            # Get all events for this correlation
            correlation_events = await self._get_correlation_events(rule.id, state.correlation_key)
            
            # Apply pattern matching
            pattern_matches = self.pattern_matcher.detect_patterns(
                correlation_events, 
                state.correlation_key
            )
            
            # Check if correlation conditions are satisfied
            correlation_result = await self._evaluate_correlation_conditions(
                parsed_rule, 
                correlation_events, 
                pattern_matches, 
                state
            )
            
            if correlation_result:
                # Mark event as correlated
                await self._mark_event_correlated(event)
                
                # Update metrics
                processing_time = time.time() - start_time
                metrics.event_correlator_processing_time.observe(processing_time)
                metrics.event_correlator_correlations_found.inc()
                
                logger.info(f"Correlation found for rule {rule.name}")
                
                return correlation_result
            
            return None
            
        except Exception as e:
            logger.error(f"Error correlating event for rule {rule.name}: {e}")
            metrics.event_correlator_errors.inc()
            return None
    
    async def _update_correlation_state(
        self,
        state: CorrelationState,
        event: CorrelationEvent,
        parsed_rule: ParsedRule
    ):
        """Update correlation state with new event."""
        # Update state data based on rule type
        if parsed_rule.rule_type.value == "sequence":
            await self._update_sequence_state(state, event, parsed_rule)
        elif parsed_rule.rule_type.value == "threshold":
            await self._update_threshold_state(state, event, parsed_rule)
        elif parsed_rule.rule_type.value == "pattern":
            await self._update_pattern_state(state, event, parsed_rule)
        elif parsed_rule.rule_type.value == "statistical":
            await self._update_statistical_state(state, event, parsed_rule)
        elif parsed_rule.rule_type.value == "temporal":
            await self._update_temporal_state(state, event, parsed_rule)
        
        # Update common state fields
        state.event_count += 1
        state.last_updated = datetime.now()
        
        # Save state to database
        with get_db() as db:
            db.merge(state)
            db.commit()
    
    async def _update_sequence_state(
        self,
        state: CorrelationState,
        event: CorrelationEvent,
        parsed_rule: ParsedRule
    ):
        """Update state for sequence-based correlation."""
        if "sequence_events" not in state.state_data:
            state.state_data["sequence_events"] = []
        
        # Add event to sequence
        state.state_data["sequence_events"].append({
            "event_id": event.event_id,
            "event_type": event.event_type,
            "timestamp": event.event_timestamp.isoformat(),
            "sequence_number": event.sequence_number
        })
        
        # Keep only events within time window
        cutoff_time = datetime.now() - timedelta(seconds=parsed_rule.time_window)
        state.state_data["sequence_events"] = [
            e for e in state.state_data["sequence_events"]
            if datetime.fromisoformat(e["timestamp"]) >= cutoff_time
        ]
    
    async def _update_threshold_state(
        self,
        state: CorrelationState,
        event: CorrelationEvent,
        parsed_rule: ParsedRule
    ):
        """Update state for threshold-based correlation."""
        if "event_counts" not in state.state_data:
            state.state_data["event_counts"] = {}
        
        event_type = event.event_type
        if event_type not in state.state_data["event_counts"]:
            state.state_data["event_counts"][event_type] = 0
        
        state.state_data["event_counts"][event_type] += 1
        
        # Store recent events for threshold checking
        if "recent_events" not in state.state_data:
            state.state_data["recent_events"] = []
        
        state.state_data["recent_events"].append({
            "event_id": event.event_id,
            "event_type": event.event_type,
            "timestamp": event.event_timestamp.isoformat()
        })
        
        # Keep only events within time window
        cutoff_time = datetime.now() - timedelta(seconds=parsed_rule.time_window)
        state.state_data["recent_events"] = [
            e for e in state.state_data["recent_events"]
            if datetime.fromisoformat(e["timestamp"]) >= cutoff_time
        ]
        
        # Update counts based on recent events
        event_counts = {}
        for e in state.state_data["recent_events"]:
            event_type = e["event_type"]
            event_counts[event_type] = event_counts.get(event_type, 0) + 1
        
        state.state_data["event_counts"] = event_counts
    
    async def _update_pattern_state(
        self,
        state: CorrelationState,
        event: CorrelationEvent,
        parsed_rule: ParsedRule
    ):
        """Update state for pattern-based correlation."""
        if "pattern_events" not in state.state_data:
            state.state_data["pattern_events"] = []
        
        # Add event to pattern tracking
        state.state_data["pattern_events"].append({
            "event_id": event.event_id,
            "event_type": event.event_type,
            "timestamp": event.event_timestamp.isoformat(),
            "event_data": event.event_data
        })
        
        # Keep only events within time window
        cutoff_time = datetime.now() - timedelta(seconds=parsed_rule.time_window)
        state.state_data["pattern_events"] = [
            e for e in state.state_data["pattern_events"]
            if datetime.fromisoformat(e["timestamp"]) >= cutoff_time
        ]
    
    async def _update_statistical_state(
        self,
        state: CorrelationState,
        event: CorrelationEvent,
        parsed_rule: ParsedRule
    ):
        """Update state for statistical correlation."""
        if "statistical_data" not in state.state_data:
            state.state_data["statistical_data"] = {
                "event_counts": {},
                "field_values": {},
                "timestamps": []
            }
        
        # Update event counts
        event_type = event.event_type
        stats = state.state_data["statistical_data"]
        
        if event_type not in stats["event_counts"]:
            stats["event_counts"][event_type] = 0
        stats["event_counts"][event_type] += 1
        
        # Track field values for statistical analysis
        for field, value in event.event_data.items():
            if field not in stats["field_values"]:
                stats["field_values"][field] = []
            stats["field_values"][field].append(value)
        
        # Track timestamps for temporal analysis
        stats["timestamps"].append(event.event_timestamp.isoformat())
        
        # Keep only recent data
        cutoff_time = datetime.now() - timedelta(seconds=parsed_rule.time_window)
        stats["timestamps"] = [
            ts for ts in stats["timestamps"]
            if datetime.fromisoformat(ts) >= cutoff_time
        ]
    
    async def _update_temporal_state(
        self,
        state: CorrelationState,
        event: CorrelationEvent,
        parsed_rule: ParsedRule
    ):
        """Update state for temporal correlation."""
        if "temporal_data" not in state.state_data:
            state.state_data["temporal_data"] = {
                "event_timeline": [],
                "time_intervals": []
            }
        
        temporal_data = state.state_data["temporal_data"]
        
        # Add event to timeline
        temporal_data["event_timeline"].append({
            "event_id": event.event_id,
            "event_type": event.event_type,
            "timestamp": event.event_timestamp.isoformat()
        })
        
        # Calculate time intervals
        if len(temporal_data["event_timeline"]) > 1:
            prev_time = datetime.fromisoformat(temporal_data["event_timeline"][-2]["timestamp"])
            curr_time = event.event_timestamp
            interval = (curr_time - prev_time).total_seconds()
            temporal_data["time_intervals"].append(interval)
        
        # Keep only events within time window
        cutoff_time = datetime.now() - timedelta(seconds=parsed_rule.time_window)
        temporal_data["event_timeline"] = [
            e for e in temporal_data["event_timeline"]
            if datetime.fromisoformat(e["timestamp"]) >= cutoff_time
        ]
    
    async def _get_correlation_events(
        self,
        rule_id: UUID,
        correlation_key: str
    ) -> List[CorrelationEvent]:
        """Get all events for a correlation."""
        with get_db() as db:
            events = db.query(CorrelationEvent).filter(
                CorrelationEvent.rule_id == rule_id,
                CorrelationEvent.correlation_key == correlation_key,
                CorrelationEvent.status != CorrelationEventStatus.ERROR
            ).order_by(CorrelationEvent.event_timestamp).all()
            
            return events
    
    async def _evaluate_correlation_conditions(
        self,
        parsed_rule: ParsedRule,
        events: List[CorrelationEvent],
        pattern_matches: List[PatternMatch],
        state: CorrelationState
    ) -> Optional[Dict[str, Any]]:
        """Evaluate if correlation conditions are met."""
        
        # Check rule-specific conditions
        if parsed_rule.rule_type.value == "sequence":
            return await self._evaluate_sequence_conditions(
                parsed_rule, events, pattern_matches, state
            )
        elif parsed_rule.rule_type.value == "threshold":
            return await self._evaluate_threshold_conditions(
                parsed_rule, events, pattern_matches, state
            )
        elif parsed_rule.rule_type.value == "pattern":
            return await self._evaluate_pattern_conditions(
                parsed_rule, events, pattern_matches, state
            )
        elif parsed_rule.rule_type.value == "statistical":
            return await self._evaluate_statistical_conditions(
                parsed_rule, events, pattern_matches, state
            )
        elif parsed_rule.rule_type.value == "temporal":
            return await self._evaluate_temporal_conditions(
                parsed_rule, events, pattern_matches, state
            )
        
        return None
    
    async def _evaluate_sequence_conditions(
        self,
        parsed_rule: ParsedRule,
        events: List[CorrelationEvent],
        pattern_matches: List[PatternMatch],
        state: CorrelationState
    ) -> Optional[Dict[str, Any]]:
        """Evaluate sequence correlation conditions."""
        sequence_order = parsed_rule.sequence_order
        
        if not sequence_order:
            return None
        
        # Check if we have the complete sequence
        if len(events) < len(sequence_order):
            return None
        
        # Find sequence matches in pattern matches
        sequence_matches = [
            match for match in pattern_matches
            if match.pattern_type.value == "sequence"
        ]
        
        if not sequence_matches:
            return None
        
        # Take the highest confidence match
        best_match = max(sequence_matches, key=lambda x: x.confidence)
        
        return {
            "title": f"Sequence Pattern Detected: {parsed_rule.name}",
            "description": f"Detected sequence pattern with {len(events)} events",
            "severity": "medium",
            "confidence": int(best_match.confidence * 100),
            "risk_score": int(best_match.confidence * 70),
            "event_ids": [event.event_id for event in events],
            "first_event_at": events[0].event_timestamp,
            "last_event_at": events[-1].event_timestamp,
            "metadata": {
                "rule_type": "sequence",
                "sequence_length": len(events),
                "pattern_confidence": best_match.confidence,
                "pattern_metadata": best_match.metadata
            },
            "tags": ["sequence", "pattern", "automated"]
        }
    
    async def _evaluate_threshold_conditions(
        self,
        parsed_rule: ParsedRule,
        events: List[CorrelationEvent],
        pattern_matches: List[PatternMatch],
        state: CorrelationState
    ) -> Optional[Dict[str, Any]]:
        """Evaluate threshold correlation conditions."""
        threshold = parsed_rule.threshold
        
        if not threshold:
            return None
        
        # Check event count threshold
        if len(events) < threshold:
            return None
        
        # Calculate severity based on threshold exceeded
        severity_map = {
            (1, 5): "low",
            (5, 15): "medium",
            (15, 50): "high",
            (50, float('inf')): "critical"
        }
        
        severity = "low"
        for (min_val, max_val), sev in severity_map.items():
            if min_val <= len(events) < max_val:
                severity = sev
                break
        
        # Calculate confidence based on how much threshold is exceeded
        confidence = min(100, int((len(events) / threshold) * 50) + 50)
        
        return {
            "title": f"Threshold Exceeded: {parsed_rule.name}",
            "description": f"Event count ({len(events)}) exceeded threshold ({threshold})",
            "severity": severity,
            "confidence": confidence,
            "risk_score": min(100, int((len(events) / threshold) * 60)),
            "event_ids": [event.event_id for event in events],
            "first_event_at": events[0].event_timestamp,
            "last_event_at": events[-1].event_timestamp,
            "metadata": {
                "rule_type": "threshold",
                "event_count": len(events),
                "threshold": threshold,
                "threshold_ratio": len(events) / threshold,
                "time_window": parsed_rule.time_window
            },
            "tags": ["threshold", "frequency", "automated"]
        }
    
    async def _evaluate_pattern_conditions(
        self,
        parsed_rule: ParsedRule,
        events: List[CorrelationEvent],
        pattern_matches: List[PatternMatch],
        state: CorrelationState
    ) -> Optional[Dict[str, Any]]:
        """Evaluate pattern correlation conditions."""
        if not pattern_matches:
            return None
        
        # Take the highest confidence pattern match
        best_match = max(pattern_matches, key=lambda x: x.confidence)
        
        # Calculate overall confidence
        confidence = int(best_match.confidence * 100)
        
        # Determine severity based on pattern type and confidence
        severity_map = {
            "brute_force": "high",
            "privilege_escalation": "critical",
            "data_exfiltration": "high",
            "lateral_movement": "medium",
            "port_scan": "medium"
        }
        
        severity = "medium"
        for pattern_key, sev in severity_map.items():
            if pattern_key in best_match.pattern_name.lower():
                severity = sev
                break
        
        return {
            "title": f"Pattern Detected: {best_match.pattern_name}",
            "description": f"Detected security pattern with {confidence}% confidence",
            "severity": severity,
            "confidence": confidence,
            "risk_score": int(best_match.confidence * 80),
            "event_ids": [event.event_id for event in best_match.events],
            "first_event_at": best_match.events[0].event_timestamp,
            "last_event_at": best_match.events[-1].event_timestamp,
            "metadata": {
                "rule_type": "pattern",
                "pattern_name": best_match.pattern_name,
                "pattern_type": best_match.pattern_type.value,
                "pattern_confidence": best_match.confidence,
                "pattern_metadata": best_match.metadata
            },
            "tags": ["pattern", "security", "automated"]
        }
    
    async def _evaluate_statistical_conditions(
        self,
        parsed_rule: ParsedRule,
        events: List[CorrelationEvent],
        pattern_matches: List[PatternMatch],
        state: CorrelationState
    ) -> Optional[Dict[str, Any]]:
        """Evaluate statistical correlation conditions."""
        # Find statistical pattern matches
        statistical_matches = [
            match for match in pattern_matches
            if match.pattern_type.value == "statistical"
        ]
        
        if not statistical_matches:
            return None
        
        best_match = max(statistical_matches, key=lambda x: x.confidence)
        
        return {
            "title": f"Statistical Anomaly: {parsed_rule.name}",
            "description": f"Statistical anomaly detected with {int(best_match.confidence * 100)}% confidence",
            "severity": "medium",
            "confidence": int(best_match.confidence * 100),
            "risk_score": int(best_match.confidence * 65),
            "event_ids": [event.event_id for event in events],
            "first_event_at": events[0].event_timestamp,
            "last_event_at": events[-1].event_timestamp,
            "metadata": {
                "rule_type": "statistical",
                "statistical_analysis": best_match.metadata,
                "event_count": len(events)
            },
            "tags": ["statistical", "anomaly", "automated"]
        }
    
    async def _evaluate_temporal_conditions(
        self,
        parsed_rule: ParsedRule,
        events: List[CorrelationEvent],
        pattern_matches: List[PatternMatch],
        state: CorrelationState
    ) -> Optional[Dict[str, Any]]:
        """Evaluate temporal correlation conditions."""
        # Find temporal pattern matches
        temporal_matches = [
            match for match in pattern_matches
            if match.pattern_type.value == "temporal"
        ]
        
        if not temporal_matches:
            return None
        
        best_match = max(temporal_matches, key=lambda x: x.confidence)
        
        return {
            "title": f"Temporal Pattern: {parsed_rule.name}",
            "description": f"Temporal pattern detected with {int(best_match.confidence * 100)}% confidence",
            "severity": "medium",
            "confidence": int(best_match.confidence * 100),
            "risk_score": int(best_match.confidence * 60),
            "event_ids": [event.event_id for event in events],
            "first_event_at": events[0].event_timestamp,
            "last_event_at": events[-1].event_timestamp,
            "metadata": {
                "rule_type": "temporal",
                "temporal_analysis": best_match.metadata,
                "event_count": len(events)
            },
            "tags": ["temporal", "pattern", "automated"]
        }
    
    async def _mark_event_correlated(self, event: CorrelationEvent):
        """Mark an event as correlated."""
        with get_db() as db:
            db_event = db.query(CorrelationEvent).filter(
                CorrelationEvent.id == event.id
            ).first()
            
            if db_event:
                db_event.status = CorrelationEventStatus.CORRELATED
                db.commit()
    
    def get_stats(self) -> Dict[str, Any]:
        """Get correlator statistics."""
        return {
            "active_correlations": len(self.active_correlations),
            "pattern_matcher_stats": {
                "patterns_count": len(self.pattern_matcher.patterns),
                "history_keys": len(self.pattern_matcher.event_history)
            },
            "rule_engine_stats": {
                "compiled_rules": len(self.rule_engine.compiled_rules)
            }
        }