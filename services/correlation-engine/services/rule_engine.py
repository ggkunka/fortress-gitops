"""
Rule Engine - Correlation Rule Management

This service handles correlation rule parsing, validation, and execution.
It supports a domain-specific language (DSL) for defining correlation rules.
"""

import re
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

from ..models.correlation import CorrelationRule, CorrelationEvent, CorrelationState

logger = get_logger(__name__)
metrics = get_metrics()


class RuleOperator(str, Enum):
    """Rule operators."""
    AND = "and"
    OR = "or"
    NOT = "not"
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    NOT_CONTAINS = "not_contains"
    MATCHES = "matches"
    GT = "gt"
    LT = "lt"
    GTE = "gte"
    LTE = "lte"
    IN = "in"
    NOT_IN = "not_in"


class RuleType(str, Enum):
    """Rule types."""
    SEQUENCE = "sequence"
    THRESHOLD = "threshold"
    PATTERN = "pattern"
    STATISTICAL = "statistical"
    TEMPORAL = "temporal"


@dataclass
class RuleCondition:
    """Rule condition."""
    field: str
    operator: RuleOperator
    value: Any
    negate: bool = False


@dataclass
class RuleAction:
    """Rule action."""
    type: str
    parameters: Dict[str, Any]


@dataclass
class ParsedRule:
    """Parsed correlation rule."""
    rule_id: str
    name: str
    rule_type: RuleType
    conditions: List[RuleCondition]
    actions: List[RuleAction]
    time_window: int
    threshold: Optional[int] = None
    sequence_order: Optional[List[str]] = None
    metadata: Optional[Dict[str, Any]] = None


class RuleEngine:
    """
    Rule engine for parsing and executing correlation rules.
    
    Supports a DSL for defining correlation rules with conditions,
    actions, and temporal constraints.
    """
    
    def __init__(self):
        self.compiled_rules: Dict[str, ParsedRule] = {}
        logger.info("Rule engine initialized")
    
    @traced("rule_engine_parse_rule")
    def parse_rule(self, rule: CorrelationRule) -> ParsedRule:
        """Parse a correlation rule DSL into a structured format."""
        try:
            rule_id = str(rule.id)
            
            # Check if rule is already compiled
            if rule_id in self.compiled_rules:
                cached_rule = self.compiled_rules[rule_id]
                # Simple cache invalidation check
                if cached_rule.name == rule.name:
                    return cached_rule
            
            # Parse the rule DSL
            parsed_rule = self._parse_rule_dsl(rule)
            
            # Cache the parsed rule
            self.compiled_rules[rule_id] = parsed_rule
            
            logger.debug(f"Parsed rule {rule.name} successfully")
            metrics.rule_engine_rules_parsed.inc()
            
            return parsed_rule
            
        except Exception as e:
            logger.error(f"Error parsing rule {rule.name}: {e}")
            metrics.rule_engine_parse_errors.inc()
            raise
    
    def _parse_rule_dsl(self, rule: CorrelationRule) -> ParsedRule:
        """Parse the rule DSL string."""
        dsl = rule.rule_dsl
        
        # This is a simplified parser - in practice, you'd use a proper parser
        # like ANTLR or pyparsing for a more robust DSL
        
        try:
            # Try to parse as JSON first (for simple rules)
            rule_data = json.loads(dsl)
            return self._parse_json_rule(rule, rule_data)
        except json.JSONDecodeError:
            # Parse as custom DSL
            return self._parse_custom_dsl(rule, dsl)
    
    def _parse_json_rule(self, rule: CorrelationRule, rule_data: Dict[str, Any]) -> ParsedRule:
        """Parse JSON format rule."""
        conditions = []
        actions = []
        
        # Parse conditions
        for condition_data in rule_data.get('conditions', []):
            condition = RuleCondition(
                field=condition_data['field'],
                operator=RuleOperator(condition_data['operator']),
                value=condition_data['value'],
                negate=condition_data.get('negate', False)
            )
            conditions.append(condition)
        
        # Parse actions
        for action_data in rule_data.get('actions', []):
            action = RuleAction(
                type=action_data['type'],
                parameters=action_data.get('parameters', {})
            )
            actions.append(action)
        
        return ParsedRule(
            rule_id=str(rule.id),
            name=rule.name,
            rule_type=RuleType(rule.rule_type),
            conditions=conditions,
            actions=actions,
            time_window=rule.time_window,
            threshold=rule_data.get('threshold'),
            sequence_order=rule_data.get('sequence_order'),
            metadata=rule_data.get('metadata', {})
        )
    
    def _parse_custom_dsl(self, rule: CorrelationRule, dsl: str) -> ParsedRule:
        """Parse custom DSL format."""
        # This is a simplified DSL parser
        # Example DSL:
        # """
        # WHEN event_type = "login_failed" AND source_ip = "192.168.1.100"
        # COUNT >= 5 WITHIN 300 seconds
        # THEN alert severity = "high"
        # """
        
        conditions = []
        actions = []
        threshold = None
        
        lines = dsl.strip().split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if line.startswith('WHEN'):
                current_section = 'conditions'
                condition_text = line[4:].strip()
                conditions.extend(self._parse_condition_text(condition_text))
            
            elif line.startswith('COUNT'):
                # Parse threshold condition
                match = re.match(r'COUNT\s*([><=]+)\s*(\d+)', line)
                if match:
                    operator = match.group(1)
                    value = int(match.group(2))
                    if operator in ['>=', '>']:
                        threshold = value
            
            elif line.startswith('THEN'):
                current_section = 'actions'
                action_text = line[4:].strip()
                actions.extend(self._parse_action_text(action_text))
            
            elif current_section == 'conditions':
                conditions.extend(self._parse_condition_text(line))
            
            elif current_section == 'actions':
                actions.extend(self._parse_action_text(line))
        
        return ParsedRule(
            rule_id=str(rule.id),
            name=rule.name,
            rule_type=RuleType(rule.rule_type),
            conditions=conditions,
            actions=actions,
            time_window=rule.time_window,
            threshold=threshold
        )
    
    def _parse_condition_text(self, text: str) -> List[RuleCondition]:
        """Parse condition text into RuleCondition objects."""
        conditions = []
        
        # Split by AND/OR
        parts = re.split(r'\s+(AND|OR)\s+', text, flags=re.IGNORECASE)
        
        for part in parts:
            if part.upper() in ['AND', 'OR']:
                continue
            
            # Parse individual condition
            # Example: event_type = "login_failed"
            match = re.match(r'(\w+)\s*([><=!]+|CONTAINS|MATCHES)\s*"?([^"]+)"?', part.strip())
            if match:
                field = match.group(1)
                operator_str = match.group(2).lower()
                value = match.group(3)
                
                # Map operator string to enum
                operator_map = {
                    '=': RuleOperator.EQUALS,
                    '==': RuleOperator.EQUALS,
                    '!=': RuleOperator.NOT_EQUALS,
                    '>': RuleOperator.GT,
                    '<': RuleOperator.LT,
                    '>=': RuleOperator.GTE,
                    '<=': RuleOperator.LTE,
                    'contains': RuleOperator.CONTAINS,
                    'matches': RuleOperator.MATCHES
                }
                
                operator = operator_map.get(operator_str, RuleOperator.EQUALS)
                
                condition = RuleCondition(
                    field=field,
                    operator=operator,
                    value=value
                )
                conditions.append(condition)
        
        return conditions
    
    def _parse_action_text(self, text: str) -> List[RuleAction]:
        """Parse action text into RuleAction objects."""
        actions = []
        
        # Example: alert severity = "high"
        if text.startswith('alert'):
            params = {}
            param_text = text[5:].strip()
            
            # Parse parameters
            param_matches = re.findall(r'(\w+)\s*=\s*"?([^"]+)"?', param_text)
            for param_match in param_matches:
                params[param_match[0]] = param_match[1]
            
            action = RuleAction(
                type='alert',
                parameters=params
            )
            actions.append(action)
        
        return actions
    
    @traced("rule_engine_evaluate_conditions")
    def evaluate_conditions(
        self, 
        parsed_rule: ParsedRule, 
        event: CorrelationEvent,
        state: CorrelationState
    ) -> bool:
        """Evaluate rule conditions against an event."""
        try:
            # Evaluate each condition
            for condition in parsed_rule.conditions:
                if not self._evaluate_condition(condition, event, state):
                    return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error evaluating conditions for rule {parsed_rule.rule_id}: {e}")
            metrics.rule_engine_evaluation_errors.inc()
            return False
    
    def _evaluate_condition(
        self, 
        condition: RuleCondition, 
        event: CorrelationEvent,
        state: CorrelationState
    ) -> bool:
        """Evaluate a single condition."""
        # Get the field value from event data
        field_value = self._get_field_value(condition.field, event, state)
        
        if field_value is None:
            return False
        
        # Evaluate based on operator
        result = self._apply_operator(condition.operator, field_value, condition.value)
        
        # Apply negation if specified
        if condition.negate:
            result = not result
        
        return result
    
    def _get_field_value(self, field: str, event: CorrelationEvent, state: CorrelationState) -> Any:
        """Get field value from event or state data."""
        # Check event data first
        if field in event.event_data:
            return event.event_data[field]
        
        # Check event attributes
        if hasattr(event, field):
            return getattr(event, field)
        
        # Check state data
        if field in state.state_data:
            return state.state_data[field]
        
        # Handle nested fields (e.g., "data.user.id")
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
    
    def _apply_operator(self, operator: RuleOperator, field_value: Any, condition_value: Any) -> bool:
        """Apply operator to compare field value with condition value."""
        try:
            if operator == RuleOperator.EQUALS:
                return field_value == condition_value
            
            elif operator == RuleOperator.NOT_EQUALS:
                return field_value != condition_value
            
            elif operator == RuleOperator.CONTAINS:
                return str(condition_value) in str(field_value)
            
            elif operator == RuleOperator.NOT_CONTAINS:
                return str(condition_value) not in str(field_value)
            
            elif operator == RuleOperator.MATCHES:
                return re.search(str(condition_value), str(field_value)) is not None
            
            elif operator == RuleOperator.GT:
                return float(field_value) > float(condition_value)
            
            elif operator == RuleOperator.LT:
                return float(field_value) < float(condition_value)
            
            elif operator == RuleOperator.GTE:
                return float(field_value) >= float(condition_value)
            
            elif operator == RuleOperator.LTE:
                return float(field_value) <= float(condition_value)
            
            elif operator == RuleOperator.IN:
                if isinstance(condition_value, (list, tuple)):
                    return field_value in condition_value
                else:
                    return field_value in str(condition_value).split(',')
            
            elif operator == RuleOperator.NOT_IN:
                if isinstance(condition_value, (list, tuple)):
                    return field_value not in condition_value
                else:
                    return field_value not in str(condition_value).split(',')
            
            return False
            
        except (ValueError, TypeError) as e:
            logger.warning(f"Error applying operator {operator}: {e}")
            return False
    
    def validate_rule(self, rule_dsl: str) -> Dict[str, Any]:
        """Validate a rule DSL without executing it."""
        try:
            # Create a temporary rule for validation
            temp_rule = CorrelationRule(
                name="temp_validation",
                rule_dsl=rule_dsl,
                rule_type="pattern",
                time_window=300
            )
            
            # Try to parse the rule
            parsed_rule = self._parse_rule_dsl(temp_rule)
            
            return {
                'valid': True,
                'parsed_rule': {
                    'name': parsed_rule.name,
                    'rule_type': parsed_rule.rule_type.value,
                    'conditions_count': len(parsed_rule.conditions),
                    'actions_count': len(parsed_rule.actions),
                    'time_window': parsed_rule.time_window
                }
            }
            
        except Exception as e:
            return {
                'valid': False,
                'error': str(e)
            }
    
    def get_rule_metrics(self, rule_id: str) -> Dict[str, Any]:
        """Get metrics for a specific rule."""
        # This would typically query the database for rule performance metrics
        return {
            'rule_id': rule_id,
            'executions': 0,
            'matches': 0,
            'errors': 0,
            'avg_execution_time': 0.0,
            'last_execution': None
        }
    
    def clear_cache(self):
        """Clear the compiled rules cache."""
        self.compiled_rules.clear()
        logger.info("Rule engine cache cleared")
    
    def get_compiled_rules(self) -> Dict[str, ParsedRule]:
        """Get all compiled rules."""
        return self.compiled_rules.copy()