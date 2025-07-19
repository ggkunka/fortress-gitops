"""
Response Orchestrator - Core Incident Response Orchestration Engine

This service orchestrates automated incident response workflows,
including playbook execution, escalation, and integration management.
"""

import asyncio
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from uuid import UUID
from dataclasses import dataclass

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.events.event_bus import EventBus

from ..models.response import (
    Incident, ResponseAction, ResponsePlaybook, EscalationRule,
    IncidentStatus, IncidentSeverity, ResponseActionType, ResponseActionStatus,
    create_incident, create_response_action, get_db
)
from .playbook_engine import PlaybookEngine
from .action_executor import ActionExecutor
from .notification_manager import NotificationManager
from .integration_manager import IntegrationManager

logger = get_logger(__name__)
metrics = get_metrics()


@dataclass
class ResponseRequest:
    """Response request model."""
    correlation_result_id: UUID
    risk_assessment_id: Optional[UUID]
    incident_type: str
    severity: IncidentSeverity
    title: str
    description: str
    impact_score: float
    affected_systems: List[str]
    context: Dict[str, Any]
    requested_by: str = "system"


@dataclass
class ResponseContext:
    """Response context for incident handling."""
    incident: Incident
    playbook: Optional[ResponsePlaybook]
    environment: Dict[str, Any]
    integrations: Dict[str, Any]
    stakeholders: List[str]


class ResponseOrchestrator:
    """
    Core response orchestrator that manages the complete incident response lifecycle.
    
    This orchestrator:
    1. Receives incident triggers from correlation/risk assessment
    2. Selects appropriate response playbooks
    3. Orchestrates playbook execution
    4. Manages escalation workflows
    5. Coordinates with external systems
    6. Tracks response metrics
    """
    
    def __init__(
        self,
        playbook_engine: PlaybookEngine,
        action_executor: ActionExecutor,
        notification_manager: NotificationManager,
        integration_manager: IntegrationManager,
        event_bus: EventBus
    ):
        self.playbook_engine = playbook_engine
        self.action_executor = action_executor
        self.notification_manager = notification_manager
        self.integration_manager = integration_manager
        self.event_bus = event_bus
        
        # Response orchestration state
        self.active_responses: Dict[UUID, ResponseContext] = {}
        self.processing_queue = asyncio.Queue()
        self.processing_tasks: Set[asyncio.Task] = set()
        
        # Escalation monitoring
        self.escalation_monitor_task = None
        self.escalation_check_interval = 60  # seconds
        
        logger.info("Response orchestrator initialized")
    
    async def start(self):
        """Start the response orchestrator."""
        # Start response processor
        processor_task = asyncio.create_task(self._process_responses())
        self.processing_tasks.add(processor_task)
        
        # Start escalation monitor
        self.escalation_monitor_task = asyncio.create_task(self._monitor_escalations())
        
        # Subscribe to events
        await self.event_bus.subscribe("correlation.result.created", self._handle_correlation_event)
        await self.event_bus.subscribe("risk_assessment.completed", self._handle_risk_assessment_event)
        await self.event_bus.subscribe("incident.manual_trigger", self._handle_manual_incident)
        
        logger.info("Response orchestrator started")
    
    async def stop(self):
        """Stop the response orchestrator."""
        # Cancel processing tasks
        for task in self.processing_tasks:
            task.cancel()
        
        if self.escalation_monitor_task:
            self.escalation_monitor_task.cancel()
        
        await asyncio.gather(*self.processing_tasks, return_exceptions=True)
        
        logger.info("Response orchestrator stopped")
    
    @traced("response_orchestrator_initiate_response")
    async def initiate_response(self, request: ResponseRequest) -> Incident:
        """Initiate incident response workflow."""
        start_time = time.time()
        
        try:
            logger.info(f"Initiating response for {request.incident_type} - {request.title}")
            
            # Step 1: Create incident record
            incident = await self._create_incident(request)
            
            # Step 2: Select response playbook
            playbook = await self._select_playbook(incident, request.context)
            
            # Step 3: Create response context
            context = await self._create_response_context(incident, playbook, request.context)
            
            # Step 4: Store active response
            self.active_responses[incident.id] = context
            
            # Step 5: Queue for processing
            await self.processing_queue.put(incident.id)
            
            # Step 6: Send initial notifications
            await self._send_initial_notifications(incident, context)
            
            # Step 7: Create external ticket if configured
            await self._create_external_ticket(incident, context)
            
            processing_time = time.time() - start_time
            metrics.response_orchestrator_initiation_time.observe(processing_time)
            metrics.response_orchestrator_incidents.inc()
            
            logger.info(f"Response initiated for incident {incident.id}")
            
            return incident
            
        except Exception as e:
            logger.error(f"Error initiating response: {e}")
            metrics.response_orchestrator_errors.inc()
            raise
    
    async def _process_responses(self):
        """Process response queue."""
        while True:
            try:
                # Get incident ID from queue
                incident_id = await self.processing_queue.get()
                
                # Process incident response
                task = asyncio.create_task(self._execute_response_workflow(incident_id))
                self.processing_tasks.add(task)
                task.add_done_callback(self.processing_tasks.discard)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing response: {e}")
                await asyncio.sleep(1)
    
    @traced("response_orchestrator_execute_workflow")
    async def _execute_response_workflow(self, incident_id: UUID):
        """Execute complete response workflow for an incident."""
        try:
            context = self.active_responses.get(incident_id)
            if not context:
                logger.warning(f"No active response context for incident {incident_id}")
                return
            
            incident = context.incident
            playbook = context.playbook
            
            logger.info(f"Executing response workflow for incident {incident_id}")
            
            # Update incident status
            await self._update_incident_status(incident, IncidentStatus.INVESTIGATING)
            
            if playbook:
                # Execute playbook
                await self._execute_playbook(incident, playbook, context)
            else:
                # Execute default response actions
                await self._execute_default_response(incident, context)
            
            # Check for escalation
            await self._check_escalation(incident, context)
            
            # Update metrics
            await self._update_response_metrics(incident, context)
            
        except Exception as e:
            logger.error(f"Error executing response workflow: {e}")
            
            # Update incident with error
            if incident_id in self.active_responses:
                incident = self.active_responses[incident_id].incident
                await self._handle_response_failure(incident, str(e))
    
    async def _execute_playbook(
        self,
        incident: Incident,
        playbook: ResponsePlaybook,
        context: ResponseContext
    ):
        """Execute response playbook."""
        try:
            logger.info(f"Executing playbook {playbook.name} for incident {incident.id}")
            
            # Generate actions from playbook
            actions = await self.playbook_engine.generate_actions(playbook, incident, context)
            
            # Create action records
            for order, action_spec in enumerate(actions):
                action = create_response_action(
                    incident_id=incident.id,
                    action_name=action_spec["name"],
                    action_type=ResponseActionType(action_spec["type"]),
                    order_index=order,
                    executor=action_spec.get("executor", "system"),
                    execution_method=action_spec.get("execution_method", "automated"),
                    description=action_spec.get("description", ""),
                    command=action_spec.get("command", ""),
                    parameters=action_spec.get("parameters", {}),
                    requires_approval=action_spec.get("requires_approval", False)
                )
                
                # Save action
                with get_db() as db:
                    db.add(action)
                    db.commit()
                    db.refresh(action)
                
                # Execute action
                await self._execute_action(action, context)
            
            # Update playbook metrics
            await self._update_playbook_metrics(playbook, True)
            
        except Exception as e:
            logger.error(f"Error executing playbook: {e}")
            await self._update_playbook_metrics(playbook, False)
            raise
    
    async def _execute_default_response(self, incident: Incident, context: ResponseContext):
        """Execute default response actions when no playbook is available."""
        try:
            logger.info(f"Executing default response for incident {incident.id}")
            
            # Default investigation actions
            default_actions = [
                {
                    "name": "Initial Investigation",
                    "type": ResponseActionType.INVESTIGATION,
                    "description": "Gather initial incident information",
                    "executor": "analyst",
                    "execution_method": "manual",
                    "order": 0
                },
                {
                    "name": "Stakeholder Notification",
                    "type": ResponseActionType.NOTIFICATION,
                    "description": "Notify relevant stakeholders",
                    "executor": "system",
                    "execution_method": "automated",
                    "order": 1
                },
                {
                    "name": "Evidence Collection",
                    "type": ResponseActionType.INVESTIGATION,
                    "description": "Collect relevant evidence and logs",
                    "executor": "analyst",
                    "execution_method": "manual",
                    "order": 2
                }
            ]
            
            # Create and execute actions
            for action_spec in default_actions:
                action = create_response_action(
                    incident_id=incident.id,
                    action_name=action_spec["name"],
                    action_type=action_spec["type"],
                    order_index=action_spec["order"],
                    executor=action_spec["executor"],
                    execution_method=action_spec["execution_method"],
                    description=action_spec["description"]
                )
                
                with get_db() as db:
                    db.add(action)
                    db.commit()
                    db.refresh(action)
                
                await self._execute_action(action, context)
            
        except Exception as e:
            logger.error(f"Error executing default response: {e}")
            raise
    
    async def _execute_action(self, action: ResponseAction, context: ResponseContext):
        """Execute individual response action."""
        try:
            logger.info(f"Executing action {action.action_name} for incident {action.incident_id}")
            
            # Check if action requires approval
            if action.requires_approval and not action.approved_by:
                logger.info(f"Action {action.id} requires approval, skipping for now")
                return
            
            # Update action status
            await self._update_action_status(action, ResponseActionStatus.IN_PROGRESS)
            
            # Execute action based on execution method
            if action.execution_method == "automated":
                result = await self.action_executor.execute_automated_action(action, context)
            elif action.execution_method == "api":
                result = await self.action_executor.execute_api_action(action, context)
            elif action.execution_method == "script":
                result = await self.action_executor.execute_script_action(action, context)
            else:
                # Manual action - just mark as pending user action
                result = {"status": "pending_manual", "message": "Waiting for manual execution"}
            
            # Update action with result
            await self._update_action_result(action, result)
            
            # Update incident status based on action type
            await self._update_incident_based_on_action(context.incident, action)
            
        except Exception as e:
            logger.error(f"Error executing action {action.id}: {e}")
            await self._update_action_status(action, ResponseActionStatus.FAILED, str(e))
    
    async def _monitor_escalations(self):
        """Monitor incidents for escalation conditions."""
        while True:
            try:
                await asyncio.sleep(self.escalation_check_interval)
                
                # Check all active incidents for escalation
                for incident_id, context in self.active_responses.items():
                    await self._check_escalation(context.incident, context)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error monitoring escalations: {e}")
                await asyncio.sleep(5)
    
    async def _check_escalation(self, incident: Incident, context: ResponseContext):
        """Check if incident needs escalation."""
        try:
            with get_db() as db:
                # Get escalation rules
                escalation_rules = db.query(EscalationRule).filter(
                    EscalationRule.is_active == True
                ).all()
                
                for rule in escalation_rules:
                    if await self._should_escalate(incident, rule):
                        await self._escalate_incident(incident, rule, context)
                
        except Exception as e:
            logger.error(f"Error checking escalation: {e}")
    
    async def _should_escalate(self, incident: Incident, rule: EscalationRule) -> bool:
        """Check if incident meets escalation criteria."""
        try:
            # Check severity threshold
            if rule.severity_threshold:
                severity_levels = {
                    IncidentSeverity.INFORMATIONAL: 1,
                    IncidentSeverity.LOW: 2,
                    IncidentSeverity.MEDIUM: 3,
                    IncidentSeverity.HIGH: 4,
                    IncidentSeverity.CRITICAL: 5
                }
                
                if severity_levels.get(incident.severity, 0) < severity_levels.get(rule.severity_threshold, 0):
                    return False
            
            # Check time threshold
            if rule.time_threshold:
                time_since_detection = (datetime.now() - incident.detected_at).total_seconds() / 60
                if time_since_detection < rule.time_threshold:
                    return False
            
            # Check status conditions
            if rule.status_conditions:
                if incident.status not in rule.status_conditions:
                    return False
            
            # Check if already escalated to this level
            if incident.escalation_level >= rule.escalation_level:
                return False
            
            return True
            
        except Exception as e:
            logger.error(f"Error checking escalation criteria: {e}")
            return False
    
    async def _escalate_incident(
        self,
        incident: Incident,
        rule: EscalationRule,
        context: ResponseContext
    ):
        """Escalate incident according to escalation rule."""
        try:
            logger.info(f"Escalating incident {incident.id} to level {rule.escalation_level}")
            
            # Update incident escalation level
            incident.escalation_level = rule.escalation_level
            
            # Execute escalation actions
            for action in rule.escalation_actions:
                if action["type"] == "notification":
                    await self.notification_manager.send_escalation_notification(
                        incident, action["targets"], action.get("template", "escalation_default")
                    )
                elif action["type"] == "assignment":
                    incident.assigned_to = action["assignee"]
                    incident.assigned_team = action.get("team")
                elif action["type"] == "external_ticket":
                    await self._create_external_ticket(incident, context)
            
            # Save incident changes
            with get_db() as db:
                db.merge(incident)
                db.commit()
            
            # Publish escalation event
            await self.event_bus.publish("incident.escalated", {
                "incident_id": str(incident.id),
                "escalation_level": rule.escalation_level,
                "rule_name": rule.name
            })
            
            metrics.response_orchestrator_escalations.inc()
            
        except Exception as e:
            logger.error(f"Error escalating incident: {e}")
    
    # Event handlers
    async def _handle_correlation_event(self, event_data: Dict[str, Any]):
        """Handle correlation result event."""
        try:
            # Check if this correlation requires immediate response
            severity = event_data.get("severity", "medium").lower()
            risk_score = event_data.get("risk_score", 0)
            
            # Only auto-respond to high-severity or high-risk correlations
            if severity in ["high", "critical"] or risk_score > 70:
                request = ResponseRequest(
                    correlation_result_id=UUID(event_data["correlation_id"]),
                    incident_type=event_data.get("title", "Security Incident"),
                    severity=IncidentSeverity(severity),
                    title=event_data.get("title", "Automated Security Response"),
                    description=event_data.get("description", ""),
                    impact_score=risk_score,
                    affected_systems=event_data.get("affected_systems", []),
                    context=event_data,
                    requested_by="correlation_engine"
                )
                
                await self.initiate_response(request)
            
        except Exception as e:
            logger.error(f"Error handling correlation event: {e}")
    
    async def _handle_risk_assessment_event(self, event_data: Dict[str, Any]):
        """Handle risk assessment completion event."""
        try:
            # Check if risk assessment indicates need for response
            risk_level = event_data.get("risk_level", "medium").lower()
            risk_score = event_data.get("risk_score", 0)
            
            if risk_level in ["high", "critical"] or risk_score > 80:
                request = ResponseRequest(
                    correlation_result_id=UUID(event_data["correlation_result_id"]),
                    risk_assessment_id=UUID(event_data["assessment_id"]),
                    incident_type="High-Risk Security Event",
                    severity=IncidentSeverity(risk_level),
                    title=f"High-Risk Event Response - {event_data.get('title', 'Unknown')}",
                    description=event_data.get("description", ""),
                    impact_score=risk_score,
                    affected_systems=[],
                    context=event_data,
                    requested_by="risk_assessment"
                )
                
                await self.initiate_response(request)
            
        except Exception as e:
            logger.error(f"Error handling risk assessment event: {e}")
    
    async def _handle_manual_incident(self, event_data: Dict[str, Any]):
        """Handle manual incident trigger."""
        try:
            request = ResponseRequest(
                correlation_result_id=UUID(event_data["correlation_result_id"]),
                incident_type=event_data["incident_type"],
                severity=IncidentSeverity(event_data["severity"]),
                title=event_data["title"],
                description=event_data.get("description", ""),
                impact_score=event_data.get("impact_score", 50),
                affected_systems=event_data.get("affected_systems", []),
                context=event_data,
                requested_by=event_data.get("requested_by", "manual")
            )
            
            await self.initiate_response(request)
            
        except Exception as e:
            logger.error(f"Error handling manual incident: {e}")
    
    # Helper methods
    async def _create_incident(self, request: ResponseRequest) -> Incident:
        """Create incident record."""
        incident = create_incident(
            title=request.title,
            correlation_result_id=request.correlation_result_id,
            severity=request.severity,
            incident_type=request.incident_type,
            impact_score=request.impact_score,
            created_by=request.requested_by,
            description=request.description,
            risk_assessment_id=request.risk_assessment_id,
            affected_systems=request.affected_systems,
            business_impact=request.context.get("business_impact", ""),
            metadata=request.context
        )
        
        with get_db() as db:
            db.add(incident)
            db.commit()
            db.refresh(incident)
        
        return incident
    
    async def _select_playbook(self, incident: Incident, context: Dict[str, Any]) -> Optional[ResponsePlaybook]:
        """Select appropriate response playbook."""
        return await self.playbook_engine.select_playbook(incident, context)
    
    async def _create_response_context(
        self,
        incident: Incident,
        playbook: Optional[ResponsePlaybook],
        context: Dict[str, Any]
    ) -> ResponseContext:
        """Create response context."""
        return ResponseContext(
            incident=incident,
            playbook=playbook,
            environment=context.get("environment", {}),
            integrations=await self.integration_manager.get_available_integrations(),
            stakeholders=context.get("stakeholders", [])
        )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get orchestrator statistics."""
        return {
            "active_responses": len(self.active_responses),
            "processing_queue_size": self.processing_queue.qsize(),
            "processing_tasks": len(self.processing_tasks),
            "escalation_check_interval": self.escalation_check_interval
        }
    
    # Placeholder methods (would be implemented with actual logic)
    async def _send_initial_notifications(self, incident: Incident, context: ResponseContext):
        """Send initial incident notifications."""
        pass
    
    async def _create_external_ticket(self, incident: Incident, context: ResponseContext):
        """Create external ticket in ITSM system."""
        pass
    
    async def _update_incident_status(self, incident: Incident, status: IncidentStatus):
        """Update incident status."""
        pass
    
    async def _update_action_status(self, action: ResponseAction, status: ResponseActionStatus, error: str = None):
        """Update action status."""
        pass
    
    async def _update_action_result(self, action: ResponseAction, result: Dict[str, Any]):
        """Update action result."""
        pass
    
    async def _update_incident_based_on_action(self, incident: Incident, action: ResponseAction):
        """Update incident status based on action completion."""
        pass
    
    async def _update_playbook_metrics(self, playbook: ResponsePlaybook, success: bool):
        """Update playbook execution metrics."""
        pass
    
    async def _update_response_metrics(self, incident: Incident, context: ResponseContext):
        """Update response metrics."""
        pass
    
    async def _handle_response_failure(self, incident: Incident, error: str):
        """Handle response failure."""
        pass