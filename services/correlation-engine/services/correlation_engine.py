"""
Correlation Engine - Main Service

This service orchestrates the entire correlation process including
event ingestion, pattern matching, rule evaluation, and result generation.
"""

import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from uuid import UUID

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.events.event_bus import EventBus
from shared.config.settings import get_settings

from ..models.correlation import (
    CorrelationRule, CorrelationEvent, CorrelationResult, 
    CorrelationState, CorrelationEventStatus, CorrelationResultStatus,
    get_db, create_correlation_event, create_correlation_result
)
from .event_correlator import EventCorrelator
from .rule_engine import RuleEngine
from .pattern_matcher import PatternMatcher

logger = get_logger(__name__)
metrics = get_metrics()
settings = get_settings()


class CorrelationEngine:
    """
    Main correlation engine that orchestrates event correlation.
    
    This service:
    1. Listens for events from the event bus
    2. Applies correlation rules to incoming events
    3. Maintains correlation state across time windows
    4. Generates correlation results when patterns are matched
    5. Publishes results to downstream services
    """
    
    def __init__(
        self,
        event_correlator: EventCorrelator,
        event_bus: EventBus,
        max_concurrent_correlations: int = 1000,
        cleanup_interval: int = 300  # 5 minutes
    ):
        self.event_correlator = event_correlator
        self.event_bus = event_bus
        self.max_concurrent_correlations = max_concurrent_correlations
        self.cleanup_interval = cleanup_interval
        
        # Runtime state
        self.is_running = False
        self.active_correlations: Dict[str, CorrelationState] = {}
        self.processing_tasks: Set[asyncio.Task] = set()
        self.cleanup_task: Optional[asyncio.Task] = None
        
        # Performance tracking
        self.stats = {
            'events_processed': 0,
            'correlations_found': 0,
            'processing_errors': 0,
            'active_correlations': 0,
            'avg_processing_time': 0.0
        }
        
        logger.info("Correlation engine initialized")
    
    async def start(self):
        """Start the correlation engine."""
        if self.is_running:
            logger.warning("Correlation engine is already running")
            return
        
        logger.info("Starting correlation engine...")
        
        try:
            # Subscribe to events
            await self.event_bus.subscribe(
                "security.events.*",
                self._handle_event
            )
            
            await self.event_bus.subscribe(
                "ingestion.events.*",
                self._handle_event
            )
            
            await self.event_bus.subscribe(
                "enrichment.events.*",
                self._handle_event
            )
            
            # Start cleanup task
            self.cleanup_task = asyncio.create_task(self._cleanup_expired_correlations())
            
            self.is_running = True
            logger.info("Correlation engine started successfully")
            metrics.correlation_engine_status.set(1)
            
        except Exception as e:
            logger.error(f"Failed to start correlation engine: {e}")
            metrics.correlation_engine_errors.inc()
            raise
    
    async def stop(self):
        """Stop the correlation engine."""
        if not self.is_running:
            return
        
        logger.info("Stopping correlation engine...")
        
        self.is_running = False
        
        # Cancel cleanup task
        if self.cleanup_task:
            self.cleanup_task.cancel()
            try:
                await self.cleanup_task
            except asyncio.CancelledError:
                pass
        
        # Cancel all processing tasks
        for task in self.processing_tasks:
            task.cancel()
        
        if self.processing_tasks:
            await asyncio.gather(*self.processing_tasks, return_exceptions=True)
        
        # Unsubscribe from events
        await self.event_bus.unsubscribe("security.events.*")
        await self.event_bus.unsubscribe("ingestion.events.*")
        await self.event_bus.unsubscribe("enrichment.events.*")
        
        logger.info("Correlation engine stopped")
        metrics.correlation_engine_status.set(0)
    
    @traced("correlation_engine_handle_event")
    async def _handle_event(self, event: Dict[str, Any]):
        """Handle incoming events."""
        start_time = time.time()
        
        try:
            # Validate event structure
            if not self._validate_event(event):
                logger.warning(f"Invalid event structure: {event}")
                metrics.correlation_engine_invalid_events.inc()
                return
            
            # Create processing task
            task = asyncio.create_task(self._process_event(event))
            self.processing_tasks.add(task)
            
            # Clean up completed tasks
            task.add_done_callback(self.processing_tasks.discard)
            
            # Update stats
            self.stats['events_processed'] += 1
            processing_time = time.time() - start_time
            self.stats['avg_processing_time'] = (
                (self.stats['avg_processing_time'] * (self.stats['events_processed'] - 1) + 
                 processing_time) / self.stats['events_processed']
            )
            
            metrics.correlation_engine_events_processed.inc()
            metrics.correlation_engine_processing_time.observe(processing_time)
            
        except Exception as e:
            logger.error(f"Error handling event: {e}")
            metrics.correlation_engine_errors.inc()
            self.stats['processing_errors'] += 1
    
    @traced("correlation_engine_process_event")
    async def _process_event(self, event: Dict[str, Any]):
        """Process a single event through correlation rules."""
        event_id = event.get('id')
        event_type = event.get('type')
        
        logger.debug(f"Processing event {event_id} of type {event_type}")
        
        try:
            # Get applicable rules for this event
            rules = await self._get_applicable_rules(event)
            
            for rule in rules:
                try:
                    await self._apply_rule_to_event(rule, event)
                except Exception as e:
                    logger.error(f"Error applying rule {rule.id} to event {event_id}: {e}")
                    metrics.correlation_engine_rule_errors.inc()
                    continue
                    
        except Exception as e:
            logger.error(f"Error processing event {event_id}: {e}")
            metrics.correlation_engine_errors.inc()
            raise
    
    async def _get_applicable_rules(self, event: Dict[str, Any]) -> List[CorrelationRule]:
        """Get correlation rules applicable to this event."""
        event_type = event.get('type')
        
        with get_db() as db:
            # Get active rules that match the event type
            rules = db.query(CorrelationRule).filter(
                CorrelationRule.status == 'active'
            ).all()
            
            # Filter rules based on event type and other criteria
            applicable_rules = []
            for rule in rules:
                if await self._rule_matches_event(rule, event):
                    applicable_rules.append(rule)
            
            return applicable_rules
    
    async def _rule_matches_event(self, rule: CorrelationRule, event: Dict[str, Any]) -> bool:
        """Check if a rule matches an event."""
        # This is a simplified version - in practice, this would use
        # the rule DSL to determine if the event matches
        event_type = event.get('type', '')
        
        # Basic type matching
        if rule.rule_type == 'sequence':
            return True  # Sequence rules can match any event
        elif rule.rule_type == 'threshold':
            return True  # Threshold rules can match any event
        elif rule.rule_type == 'pattern':
            # Pattern rules would have more complex matching logic
            return True
        
        return False
    
    @traced("correlation_engine_apply_rule")
    async def _apply_rule_to_event(self, rule: CorrelationRule, event: Dict[str, Any]):
        """Apply a correlation rule to an event."""
        correlation_key = self._generate_correlation_key(rule, event)
        
        # Get or create correlation state
        state = await self._get_or_create_correlation_state(rule, correlation_key)
        
        # Create correlation event
        correlation_event = create_correlation_event(
            rule_id=rule.id,
            event_id=event.get('id'),
            event_type=event.get('type'),
            event_data=event,
            correlation_key=correlation_key,
            event_timestamp=datetime.fromisoformat(event.get('timestamp')),
            sequence_number=state.event_count + 1
        )
        
        # Save correlation event
        with get_db() as db:
            db.add(correlation_event)
            db.commit()
        
        # Update correlation state
        state.event_count += 1
        state.last_updated = datetime.now()
        
        # Check if correlation conditions are met
        correlation_result = await self.event_correlator.correlate(
            rule, correlation_event, state
        )
        
        if correlation_result:
            await self._handle_correlation_result(rule, correlation_result, state)
    
    def _generate_correlation_key(self, rule: CorrelationRule, event: Dict[str, Any]) -> str:
        """Generate a correlation key for grouping related events."""
        # This is a simplified version - in practice, this would use
        # the rule configuration to determine how to group events
        
        # Example: group by source IP for network events
        if event.get('type', '').startswith('network'):
            return f"network_{event.get('source_ip', 'unknown')}"
        
        # Example: group by user ID for authentication events
        if event.get('type', '').startswith('auth'):
            return f"auth_{event.get('user_id', 'unknown')}"
        
        # Default: group by event type
        return f"default_{event.get('type', 'unknown')}"
    
    async def _get_or_create_correlation_state(
        self, 
        rule: CorrelationRule, 
        correlation_key: str
    ) -> CorrelationState:
        """Get or create correlation state for a rule and key."""
        state_key = f"{rule.id}_{correlation_key}"
        
        # Check in-memory cache first
        if state_key in self.active_correlations:
            state = self.active_correlations[state_key]
            if state.expires_at > datetime.now():
                return state
            else:
                # Remove expired state
                del self.active_correlations[state_key]
        
        # Check database
        with get_db() as db:
            state = db.query(CorrelationState).filter(
                CorrelationState.rule_id == rule.id,
                CorrelationState.correlation_key == correlation_key,
                CorrelationState.is_active == True,
                CorrelationState.expires_at > datetime.now()
            ).first()
            
            if not state:
                # Create new state
                state = CorrelationState(
                    rule_id=rule.id,
                    correlation_key=correlation_key,
                    state_data={},
                    expires_at=datetime.now() + timedelta(seconds=rule.time_window)
                )
                db.add(state)
                db.commit()
                db.refresh(state)
            
            # Cache state
            self.active_correlations[state_key] = state
            return state
    
    @traced("correlation_engine_handle_result")
    async def _handle_correlation_result(
        self, 
        rule: CorrelationRule, 
        correlation_result: Dict[str, Any], 
        state: CorrelationState
    ):
        """Handle a correlation result."""
        logger.info(f"Correlation found for rule {rule.name}: {correlation_result}")
        
        # Create correlation result record
        result = create_correlation_result(
            rule_id=rule.id,
            correlation_key=state.correlation_key,
            title=correlation_result.get('title', f"Correlation: {rule.name}"),
            description=correlation_result.get('description', ''),
            severity=correlation_result.get('severity', 'medium'),
            confidence=correlation_result.get('confidence', 80),
            risk_score=correlation_result.get('risk_score', 50),
            event_count=state.event_count,
            event_ids=correlation_result.get('event_ids', []),
            first_event_at=correlation_result.get('first_event_at', datetime.now()),
            last_event_at=correlation_result.get('last_event_at', datetime.now()),
            correlation_window=rule.time_window,
            metadata=correlation_result.get('metadata', {}),
            tags=correlation_result.get('tags', [])
        )
        
        # Save result
        with get_db() as db:
            db.add(result)
            db.commit()
            db.refresh(result)
        
        # Publish result to event bus
        await self._publish_correlation_result(result)
        
        # Update stats
        self.stats['correlations_found'] += 1
        metrics.correlation_engine_correlations_found.inc()
        
        # Mark state as inactive
        state.is_active = False
        
        # Remove from active correlations
        state_key = f"{rule.id}_{state.correlation_key}"
        if state_key in self.active_correlations:
            del self.active_correlations[state_key]
    
    async def _publish_correlation_result(self, result: CorrelationResult):
        """Publish correlation result to event bus."""
        event = {
            'id': str(result.id),
            'type': 'correlation.result',
            'timestamp': result.created_at.isoformat(),
            'source': 'correlation-engine',
            'data': {
                'rule_id': str(result.rule_id),
                'correlation_key': result.correlation_key,
                'title': result.title,
                'description': result.description,
                'severity': result.severity,
                'confidence': result.confidence,
                'risk_score': result.risk_score,
                'event_count': result.event_count,
                'event_ids': result.event_ids,
                'first_event_at': result.first_event_at.isoformat(),
                'last_event_at': result.last_event_at.isoformat(),
                'metadata': result.metadata,
                'tags': result.tags
            }
        }
        
        await self.event_bus.publish('correlation.results', event)
        logger.info(f"Published correlation result: {result.id}")
    
    async def _cleanup_expired_correlations(self):
        """Cleanup expired correlation states."""
        while self.is_running:
            try:
                await asyncio.sleep(self.cleanup_interval)
                
                current_time = datetime.now()
                expired_keys = []
                
                # Clean up in-memory cache
                for key, state in self.active_correlations.items():
                    if state.expires_at <= current_time:
                        expired_keys.append(key)
                
                for key in expired_keys:
                    del self.active_correlations[key]
                
                # Clean up database
                with get_db() as db:
                    expired_states = db.query(CorrelationState).filter(
                        CorrelationState.expires_at <= current_time,
                        CorrelationState.is_active == True
                    ).all()
                    
                    for state in expired_states:
                        state.is_active = False
                    
                    db.commit()
                
                # Update stats
                self.stats['active_correlations'] = len(self.active_correlations)
                metrics.correlation_engine_active_correlations.set(self.stats['active_correlations'])
                
                if expired_keys:
                    logger.info(f"Cleaned up {len(expired_keys)} expired correlation states")
                    
            except Exception as e:
                logger.error(f"Error in cleanup task: {e}")
                metrics.correlation_engine_cleanup_errors.inc()
    
    def _validate_event(self, event: Dict[str, Any]) -> bool:
        """Validate event structure."""
        required_fields = ['id', 'type', 'timestamp']
        
        for field in required_fields:
            if field not in event:
                return False
        
        # Validate timestamp format
        try:
            datetime.fromisoformat(event['timestamp'])
        except ValueError:
            return False
        
        return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Get correlation engine statistics."""
        return {
            **self.stats,
            'is_running': self.is_running,
            'active_processing_tasks': len(self.processing_tasks)
        }