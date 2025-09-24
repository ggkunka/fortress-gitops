"""Event patterns and routing for the event bus."""

import re
import fnmatch
from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass, field
from enum import Enum

import structlog

from .base import EventMessage, EventHandler


class PatternType(Enum):
    """Event pattern types."""
    EXACT = "exact"
    WILDCARD = "wildcard"
    REGEX = "regex"
    PREFIX = "prefix"
    SUFFIX = "suffix"


@dataclass
class EventPattern:
    """Event pattern for matching events."""
    
    pattern: str
    pattern_type: PatternType = PatternType.EXACT
    description: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def matches(self, event_type: str) -> bool:
        """Check if an event type matches this pattern."""
        if self.pattern_type == PatternType.EXACT:
            return event_type == self.pattern
        elif self.pattern_type == PatternType.WILDCARD:
            return fnmatch.fnmatch(event_type, self.pattern)
        elif self.pattern_type == PatternType.REGEX:
            return bool(re.match(self.pattern, event_type))
        elif self.pattern_type == PatternType.PREFIX:
            return event_type.startswith(self.pattern)
        elif self.pattern_type == PatternType.SUFFIX:
            return event_type.endswith(self.pattern)
        else:
            return False
    
    def __str__(self) -> str:
        return f"EventPattern({self.pattern_type.value}: {self.pattern})"


class EventRouter:
    """Router for directing events to appropriate handlers."""
    
    def __init__(self, service_name: str):
        self.service_name = service_name
        self.routes: Dict[str, List[EventHandler]] = {}
        self.patterns: Dict[str, EventPattern] = {}
        self.logger = structlog.get_logger().bind(
            service=service_name,
            component="event_router"
        )
    
    def add_route(
        self,
        pattern: str,
        handler: Callable,
        pattern_type: PatternType = PatternType.EXACT,
        description: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Add a route for events matching a pattern."""
        # Create event pattern
        event_pattern = EventPattern(
            pattern=pattern,
            pattern_type=pattern_type,
            description=description,
            metadata=metadata or {},
        )
        
        # Create event handler
        event_handler = EventHandler(
            handler=handler,
            event_pattern=pattern,
            service_name=self.service_name,
        )
        
        # Store pattern and handler
        self.patterns[event_handler.handler_id] = event_pattern
        
        if pattern not in self.routes:
            self.routes[pattern] = []
        self.routes[pattern].append(event_handler)
        
        self.logger.info(
            "Route added",
            pattern=pattern,
            pattern_type=pattern_type.value,
            handler_id=event_handler.handler_id,
            description=description,
        )
        
        return event_handler.handler_id
    
    def remove_route(self, handler_id: str) -> bool:
        """Remove a route by handler ID."""
        if handler_id not in self.patterns:
            return False
        
        pattern = self.patterns[handler_id].pattern
        
        # Remove handler from routes
        if pattern in self.routes:
            self.routes[pattern] = [
                h for h in self.routes[pattern]
                if h.handler_id != handler_id
            ]
            
            # Remove pattern if no more handlers
            if not self.routes[pattern]:
                del self.routes[pattern]
        
        # Remove pattern
        del self.patterns[handler_id]
        
        self.logger.info(
            "Route removed",
            pattern=pattern,
            handler_id=handler_id,
        )
        
        return True
    
    def route_event(self, event: EventMessage) -> List[EventHandler]:
        """Route an event to appropriate handlers."""
        matching_handlers = []
        
        for handler_id, pattern in self.patterns.items():
            if pattern.matches(event.event_type):
                # Find the handler
                for handlers in self.routes.values():
                    for handler in handlers:
                        if handler.handler_id == handler_id:
                            matching_handlers.append(handler)
                            break
        
        self.logger.debug(
            "Event routed",
            event_type=event.event_type,
            event_id=event.event_id,
            matching_handlers=len(matching_handlers),
        )
        
        return matching_handlers
    
    def get_routes(self) -> Dict[str, List[Dict[str, Any]]]:
        """Get all routes with their patterns and handlers."""
        routes_info = {}
        
        for pattern, handlers in self.routes.items():
            routes_info[pattern] = []
            
            for handler in handlers:
                pattern_info = self.patterns[handler.handler_id]
                routes_info[pattern].append({
                    "handler_id": handler.handler_id,
                    "pattern": pattern_info.pattern,
                    "pattern_type": pattern_info.pattern_type.value,
                    "description": pattern_info.description,
                    "metadata": pattern_info.metadata,
                })
        
        return routes_info
    
    def get_stats(self) -> Dict[str, Any]:
        """Get router statistics."""
        total_handlers = sum(len(handlers) for handlers in self.routes.values())
        
        pattern_types = {}
        for pattern in self.patterns.values():
            pattern_type = pattern.pattern_type.value
            pattern_types[pattern_type] = pattern_types.get(pattern_type, 0) + 1
        
        return {
            "service_name": self.service_name,
            "total_patterns": len(self.patterns),
            "total_handlers": total_handlers,
            "pattern_types": pattern_types,
            "routes": list(self.routes.keys()),
        }


class EventFilter:
    """Filter for selecting events based on criteria."""
    
    def __init__(self, name: str):
        self.name = name
        self.criteria: List[Dict[str, Any]] = []
        self.logger = structlog.get_logger().bind(component="event_filter")
    
    def add_criteria(
        self,
        field: str,
        operator: str,
        value: Any,
        description: Optional[str] = None,
    ) -> None:
        """Add filtering criteria."""
        criterion = {
            "field": field,
            "operator": operator,
            "value": value,
            "description": description,
        }
        self.criteria.append(criterion)
        
        self.logger.debug(
            "Filter criteria added",
            filter_name=self.name,
            field=field,
            operator=operator,
            value=value,
        )
    
    def matches(self, event: EventMessage) -> bool:
        """Check if an event matches all criteria."""
        for criterion in self.criteria:
            if not self._evaluate_criterion(event, criterion):
                return False
        return True
    
    def _evaluate_criterion(
        self,
        event: EventMessage,
        criterion: Dict[str, Any]
    ) -> bool:
        """Evaluate a single criterion against an event."""
        field = criterion["field"]
        operator = criterion["operator"]
        expected_value = criterion["value"]
        
        # Get actual value from event
        if field.startswith("metadata."):
            actual_value = event.metadata.get(field[9:])
        elif field.startswith("data."):
            actual_value = event.data.get(field[5:])
        else:
            actual_value = getattr(event, field, None)
        
        # Evaluate based on operator
        if operator == "eq":
            return actual_value == expected_value
        elif operator == "ne":
            return actual_value != expected_value
        elif operator == "gt":
            return actual_value is not None and actual_value > expected_value
        elif operator == "gte":
            return actual_value is not None and actual_value >= expected_value
        elif operator == "lt":
            return actual_value is not None and actual_value < expected_value
        elif operator == "lte":
            return actual_value is not None and actual_value <= expected_value
        elif operator == "in":
            return actual_value in expected_value
        elif operator == "not_in":
            return actual_value not in expected_value
        elif operator == "contains":
            return (
                actual_value is not None and
                isinstance(actual_value, str) and
                expected_value in actual_value
            )
        elif operator == "starts_with":
            return (
                actual_value is not None and
                isinstance(actual_value, str) and
                actual_value.startswith(expected_value)
            )
        elif operator == "ends_with":
            return (
                actual_value is not None and
                isinstance(actual_value, str) and
                actual_value.endswith(expected_value)
            )
        elif operator == "regex":
            return (
                actual_value is not None and
                isinstance(actual_value, str) and
                bool(re.match(expected_value, actual_value))
            )
        elif operator == "exists":
            return actual_value is not None
        elif operator == "not_exists":
            return actual_value is None
        else:
            self.logger.warning(
                "Unknown operator",
                operator=operator,
                field=field,
            )
            return False


class EventAggregator:
    """Aggregator for collecting and processing groups of events."""
    
    def __init__(self, name: str, window_size: int = 60):
        self.name = name
        self.window_size = window_size  # seconds
        self.events: List[EventMessage] = []
        self.aggregation_rules: List[Dict[str, Any]] = []
        self.logger = structlog.get_logger().bind(component="event_aggregator")
    
    def add_event(self, event: EventMessage) -> None:
        """Add an event to the aggregator."""
        self.events.append(event)
        self._cleanup_old_events()
    
    def add_aggregation_rule(
        self,
        rule_type: str,
        field: str,
        condition: Optional[Dict[str, Any]] = None,
        description: Optional[str] = None,
    ) -> None:
        """Add an aggregation rule."""
        rule = {
            "type": rule_type,
            "field": field,
            "condition": condition or {},
            "description": description,
        }
        self.aggregation_rules.append(rule)
        
        self.logger.debug(
            "Aggregation rule added",
            aggregator_name=self.name,
            rule_type=rule_type,
            field=field,
        )
    
    def aggregate(self) -> Dict[str, Any]:
        """Perform aggregation on collected events."""
        results = {}
        
        for rule in self.aggregation_rules:
            rule_type = rule["type"]
            field = rule["field"]
            
            # Filter events based on condition
            filtered_events = self._filter_events(rule.get("condition", {}))
            
            # Perform aggregation
            if rule_type == "count":
                results[f"count_{field}"] = len(filtered_events)
            elif rule_type == "sum":
                values = [self._get_field_value(event, field) for event in filtered_events]
                numeric_values = [v for v in values if isinstance(v, (int, float))]
                results[f"sum_{field}"] = sum(numeric_values)
            elif rule_type == "avg":
                values = [self._get_field_value(event, field) for event in filtered_events]
                numeric_values = [v for v in values if isinstance(v, (int, float))]
                results[f"avg_{field}"] = (
                    sum(numeric_values) / len(numeric_values)
                    if numeric_values else 0
                )
            elif rule_type == "max":
                values = [self._get_field_value(event, field) for event in filtered_events]
                numeric_values = [v for v in values if isinstance(v, (int, float))]
                results[f"max_{field}"] = max(numeric_values) if numeric_values else None
            elif rule_type == "min":
                values = [self._get_field_value(event, field) for event in filtered_events]
                numeric_values = [v for v in values if isinstance(v, (int, float))]
                results[f"min_{field}"] = min(numeric_values) if numeric_values else None
            elif rule_type == "distinct":
                values = [self._get_field_value(event, field) for event in filtered_events]
                results[f"distinct_{field}"] = list(set(values))
            elif rule_type == "group_by":
                groups = {}
                for event in filtered_events:
                    group_value = self._get_field_value(event, field)
                    if group_value not in groups:
                        groups[group_value] = []
                    groups[group_value].append(event.event_id)
                results[f"group_by_{field}"] = groups
        
        return results
    
    def _filter_events(self, condition: Dict[str, Any]) -> List[EventMessage]:
        """Filter events based on condition."""
        if not condition:
            return self.events
        
        filtered = []
        for event in self.events:
            if self._matches_condition(event, condition):
                filtered.append(event)
        
        return filtered
    
    def _matches_condition(
        self,
        event: EventMessage,
        condition: Dict[str, Any]
    ) -> bool:
        """Check if an event matches a condition."""
        for field, expected_value in condition.items():
            actual_value = self._get_field_value(event, field)
            if actual_value != expected_value:
                return False
        return True
    
    def _get_field_value(self, event: EventMessage, field: str) -> Any:
        """Get field value from an event."""
        if field.startswith("metadata."):
            return event.metadata.get(field[9:])
        elif field.startswith("data."):
            return event.data.get(field[5:])
        else:
            return getattr(event, field, None)
    
    def _cleanup_old_events(self) -> None:
        """Remove events older than the window size."""
        import time
        current_time = time.time()
        
        self.events = [
            event for event in self.events
            if (current_time - event.timestamp.timestamp()) <= self.window_size
        ]
    
    def get_stats(self) -> Dict[str, Any]:
        """Get aggregator statistics."""
        return {
            "name": self.name,
            "window_size": self.window_size,
            "events_count": len(self.events),
            "rules_count": len(self.aggregation_rules),
        }