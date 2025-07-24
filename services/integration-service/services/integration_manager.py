"""
Integration Manager - Central coordinator for external system integrations

This service manages the lifecycle of integrations with external systems,
handles connection monitoring, data synchronization, and event routing.
"""

import asyncio
import json
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from uuid import UUID
import hashlib

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.events.event_bus import EventBus
from shared.security.sanitization import sanitize_input

from ..models.integration import (
    Integration, IntegrationConnectionLog, IntegrationSyncLog,
    IntegrationType, IntegrationStatus, ConnectionStatus, DataSyncStatus,
    get_db
)

logger = get_logger(__name__)
metrics = get_metrics()


class IntegrationManager:
    """
    Central integration manager that coordinates all external system integrations.
    
    This manager:
    1. Manages integration lifecycle
    2. Monitors connection health
    3. Coordinates data synchronization
    4. Routes events between systems
    5. Handles error recovery and retries
    """
    
    def __init__(
        self,
        event_bus: EventBus,
        siem_connector=None,
        cloud_connector=None,
        threat_feed_connector=None,
        vulnerability_feed_connector=None,
        ticketing_connector=None
    ):
        self.event_bus = event_bus
        
        # Connector instances
        self.connectors = {
            IntegrationType.SIEM: siem_connector,
            IntegrationType.CLOUD: cloud_connector,
            IntegrationType.THREAT_FEED: threat_feed_connector,
            IntegrationType.VULNERABILITY_FEED: vulnerability_feed_connector,
            IntegrationType.TICKETING: ticketing_connector
        }
        
        # Active integrations
        self.active_integrations: Dict[UUID, Integration] = {}
        self.integration_tasks: Set[asyncio.Task] = set()
        
        # Health monitoring
        self.health_check_task = None
        self.health_check_interval = 60  # seconds
        
        # Data sync coordination
        self.sync_scheduler_task = None
        self.sync_queue = asyncio.Queue()
        
        # Event routing
        self.event_routing_task = None
        
        logger.info("Integration manager initialized")
    
    async def start(self):
        """Start the integration manager."""
        try:
            # Load active integrations
            await self._load_active_integrations()
            
            # Start health monitoring
            self.health_check_task = asyncio.create_task(self._health_check_loop())
            
            # Start sync scheduler
            self.sync_scheduler_task = asyncio.create_task(self._sync_scheduler_loop())
            
            # Start event routing
            self.event_routing_task = asyncio.create_task(self._event_routing_loop())
            
            # Subscribe to integration events
            await self.event_bus.subscribe("integration.created", self._handle_integration_created)
            await self.event_bus.subscribe("integration.updated", self._handle_integration_updated)
            await self.event_bus.subscribe("integration.deleted", self._handle_integration_deleted)
            await self.event_bus.subscribe("integration.sync_requested", self._handle_sync_requested)
            
            # Subscribe to external events for routing
            await self.event_bus.subscribe("security.incident", self._route_security_event)
            await self.event_bus.subscribe("vulnerability.detected", self._route_vulnerability_event)
            await self.event_bus.subscribe("threat.detected", self._route_threat_event)
            
            logger.info("Integration manager started")
            
        except Exception as e:
            logger.error(f"Error starting integration manager: {e}")
            raise
    
    async def stop(self):
        """Stop the integration manager."""
        try:
            # Cancel all tasks
            tasks_to_cancel = [
                self.health_check_task,
                self.sync_scheduler_task,
                self.event_routing_task
            ]
            
            for task in tasks_to_cancel:
                if task and not task.done():
                    task.cancel()
            
            # Cancel integration tasks
            for task in self.integration_tasks:
                if not task.done():
                    task.cancel()
            
            # Wait for cancellation
            if tasks_to_cancel:
                await asyncio.gather(*[t for t in tasks_to_cancel if t], return_exceptions=True)
            
            if self.integration_tasks:
                await asyncio.gather(*self.integration_tasks, return_exceptions=True)
            
            # Disconnect integrations
            for integration_id, integration in self.active_integrations.items():
                await self._disconnect_integration(integration_id)
            
            logger.info("Integration manager stopped")
            
        except Exception as e:
            logger.error(f"Error stopping integration manager: {e}")
    
    async def _load_active_integrations(self):
        """Load active integrations from database."""
        try:
            with get_db() as db:
                integrations = db.query(Integration).filter(
                    Integration.is_enabled == True,
                    Integration.status.in_([IntegrationStatus.ACTIVE, IntegrationStatus.PENDING])
                ).all()
                
                for integration in integrations:
                    self.active_integrations[integration.id] = integration
                    
                    # Initialize connection if needed
                    if integration.status == IntegrationStatus.PENDING:
                        task = asyncio.create_task(self._initialize_integration(integration.id))
                        self.integration_tasks.add(task)
                        task.add_done_callback(self.integration_tasks.discard)
                
                logger.info(f"Loaded {len(integrations)} active integrations")
                
        except Exception as e:
            logger.error(f"Error loading active integrations: {e}")
    
    @traced("integration_manager_health_check_loop")
    async def _health_check_loop(self):
        """Health check loop for all integrations."""
        while True:
            try:
                current_time = datetime.utcnow()
                
                for integration_id, integration in self.active_integrations.items():
                    # Check if health check is due
                    if (not integration.last_health_check or 
                        current_time - integration.last_health_check >= 
                        timedelta(seconds=integration.health_check_interval)):
                        
                        # Schedule health check
                        task = asyncio.create_task(self._perform_health_check(integration_id))
                        self.integration_tasks.add(task)
                        task.add_done_callback(self.integration_tasks.discard)
                
                await asyncio.sleep(self.health_check_interval)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in health check loop: {e}")
                await asyncio.sleep(60)  # Wait before retrying
    
    @traced("integration_manager_sync_scheduler_loop")
    async def _sync_scheduler_loop(self):
        """Data synchronization scheduler loop."""
        while True:
            try:
                # Get sync request from queue
                sync_request = await self.sync_queue.get()
                
                # Process sync request
                await self._process_sync_request(sync_request)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error in sync scheduler loop: {e}")
                await asyncio.sleep(1)
    
    async def _event_routing_loop(self):
        """Event routing loop for external system notifications."""
        # This will be implemented based on specific routing requirements
        pass
    
    @traced("integration_manager_initialize_integration")
    async def _initialize_integration(self, integration_id: UUID):
        """Initialize a specific integration."""
        try:
            integration = self.active_integrations.get(integration_id)
            if not integration:
                return
            
            connector = self.connectors.get(IntegrationType(integration.integration_type))
            if not connector:
                logger.error(f"No connector available for type: {integration.integration_type}")
                await self._update_integration_status(integration_id, IntegrationStatus.ERROR)
                return
            
            # Attempt connection
            connection_result = await connector.connect(integration)
            
            if connection_result.get("success", False):
                await self._update_integration_status(integration_id, IntegrationStatus.ACTIVE)
                await self._log_connection_attempt(integration_id, ConnectionStatus.CONNECTED, connection_result)
                
                # Schedule initial sync if supported
                if integration.is_bidirectional or connection_result.get("supports_pull", False):
                    await self.sync_queue.put({
                        "integration_id": integration_id,
                        "sync_type": "initial",
                        "priority": "high"
                    })
                
                logger.info(f"Integration initialized successfully: {integration.name}")
                metrics.integration_manager_connections_successful.inc()
                
            else:
                await self._update_integration_status(integration_id, IntegrationStatus.ERROR)
                await self._log_connection_attempt(
                    integration_id, 
                    ConnectionStatus.FAILED, 
                    connection_result
                )
                
                logger.error(f"Integration initialization failed: {integration.name}")
                metrics.integration_manager_connections_failed.inc()
                
        except Exception as e:
            logger.error(f"Error initializing integration {integration_id}: {e}")
            await self._update_integration_status(integration_id, IntegrationStatus.ERROR)
            metrics.integration_manager_errors.inc()
    
    @traced("integration_manager_perform_health_check")
    async def _perform_health_check(self, integration_id: UUID):
        """Perform health check for a specific integration."""
        try:
            integration = self.active_integrations.get(integration_id)
            if not integration:
                return
            
            connector = self.connectors.get(IntegrationType(integration.integration_type))
            if not connector:
                return
            
            # Perform health check
            health_result = await connector.health_check(integration)
            
            # Update status based on result
            if health_result.get("healthy", False):
                connection_status = ConnectionStatus.CONNECTED
                await self._update_integration_connection_status(integration_id, connection_status)
            else:
                connection_status = ConnectionStatus.FAILED
                await self._update_integration_connection_status(integration_id, connection_status)
                
                # If health check fails repeatedly, mark integration as error
                if integration.retry_count >= integration.max_retries:
                    await self._update_integration_status(integration_id, IntegrationStatus.ERROR)
            
            # Log health check result
            await self._log_connection_attempt(integration_id, connection_status, health_result)
            
            # Update last health check time
            with get_db() as db:
                db_integration = db.query(Integration).filter(
                    Integration.id == integration_id
                ).first()
                if db_integration:
                    db_integration.last_health_check = datetime.utcnow()
                    db.commit()
            
            metrics.integration_manager_health_checks.inc()
            
        except Exception as e:
            logger.error(f"Error performing health check for {integration_id}: {e}")
            await self._update_integration_connection_status(integration_id, ConnectionStatus.FAILED)
    
    async def _process_sync_request(self, sync_request: Dict[str, Any]):
        """Process a data synchronization request."""
        try:
            integration_id = UUID(sync_request["integration_id"])
            sync_type = sync_request.get("sync_type", "pull")
            
            integration = self.active_integrations.get(integration_id)
            if not integration:
                return
            
            connector = self.connectors.get(IntegrationType(integration.integration_type))
            if not connector:
                return
            
            # Create sync log entry
            sync_log = IntegrationSyncLog(
                integration_id=integration_id,
                sync_type=sync_type,
                started_at=datetime.utcnow(),
                status=DataSyncStatus.SYNCING
            )
            
            with get_db() as db:
                db.add(sync_log)
                db.commit()
                db.refresh(sync_log)
            
            try:
                # Perform synchronization
                if sync_type in ["pull", "initial"]:
                    sync_result = await connector.pull_data(integration)
                elif sync_type == "push":
                    sync_result = await connector.push_data(integration, sync_request.get("data"))
                else:
                    raise ValueError(f"Unknown sync type: {sync_type}")
                
                # Update sync log with results
                sync_log.completed_at = datetime.utcnow()
                sync_log.duration = (sync_log.completed_at - sync_log.started_at).total_seconds()
                sync_log.status = DataSyncStatus.SYNCHRONIZED
                sync_log.records_processed = sync_result.get("records_processed", 0)
                sync_log.records_successful = sync_result.get("records_successful", 0)
                sync_log.records_failed = sync_result.get("records_failed", 0)
                sync_log.records_skipped = sync_result.get("records_skipped", 0)
                sync_log.sync_metadata = sync_result.get("metadata", {})
                
                # Calculate data checksum
                if sync_result.get("data"):
                    data_str = json.dumps(sync_result["data"], sort_keys=True)
                    sync_log.data_checksum = hashlib.sha256(data_str.encode()).hexdigest()
                
                # Update integration sync status
                await self._update_integration_sync_status(integration_id, DataSyncStatus.SYNCHRONIZED)
                
                logger.info(f"Sync completed for integration {integration.name}: {sync_log.records_processed} records")
                metrics.integration_manager_syncs_successful.inc()
                
            except Exception as sync_error:
                # Update sync log with error
                sync_log.completed_at = datetime.utcnow()
                sync_log.duration = (sync_log.completed_at - sync_log.started_at).total_seconds()
                sync_log.status = DataSyncStatus.SYNC_FAILED
                sync_log.error_message = str(sync_error)
                sync_log.error_details = {"error_type": type(sync_error).__name__}
                
                # Update integration sync status
                await self._update_integration_sync_status(integration_id, DataSyncStatus.SYNC_FAILED)
                
                logger.error(f"Sync failed for integration {integration.name}: {sync_error}")
                metrics.integration_manager_syncs_failed.inc()
                
                raise
            
            finally:
                # Save sync log
                with get_db() as db:
                    db.merge(sync_log)
                    db.commit()
                
        except Exception as e:
            logger.error(f"Error processing sync request: {e}")
            metrics.integration_manager_errors.inc()
    
    # Status update methods
    async def _update_integration_status(self, integration_id: UUID, status: IntegrationStatus):
        """Update integration status."""
        try:
            with get_db() as db:
                integration = db.query(Integration).filter(
                    Integration.id == integration_id
                ).first()
                if integration:
                    integration.status = status
                    integration.updated_at = datetime.utcnow()
                    db.commit()
                    
                    # Update local cache
                    if integration_id in self.active_integrations:
                        self.active_integrations[integration_id] = integration
        except Exception as e:
            logger.error(f"Error updating integration status: {e}")
    
    async def _update_integration_connection_status(self, integration_id: UUID, status: ConnectionStatus):
        """Update integration connection status."""
        try:
            with get_db() as db:
                integration = db.query(Integration).filter(
                    Integration.id == integration_id
                ).first()
                if integration:
                    integration.connection_status = status
                    integration.updated_at = datetime.utcnow()
                    
                    # Update retry count
                    if status == ConnectionStatus.FAILED:
                        integration.retry_count += 1
                    else:
                        integration.retry_count = 0
                    
                    db.commit()
                    
                    # Update local cache
                    if integration_id in self.active_integrations:
                        self.active_integrations[integration_id] = integration
        except Exception as e:
            logger.error(f"Error updating connection status: {e}")
    
    async def _update_integration_sync_status(self, integration_id: UUID, status: DataSyncStatus):
        """Update integration sync status."""
        try:
            with get_db() as db:
                integration = db.query(Integration).filter(
                    Integration.id == integration_id
                ).first()
                if integration:
                    integration.data_sync_status = status
                    integration.last_sync_at = datetime.utcnow()
                    integration.updated_at = datetime.utcnow()
                    db.commit()
                    
                    # Update local cache
                    if integration_id in self.active_integrations:
                        self.active_integrations[integration_id] = integration
        except Exception as e:
            logger.error(f"Error updating sync status: {e}")
    
    async def _log_connection_attempt(
        self, 
        integration_id: UUID, 
        status: ConnectionStatus, 
        result: Dict[str, Any]
    ):
        """Log a connection attempt."""
        try:
            log_entry = IntegrationConnectionLog(
                integration_id=integration_id,
                connection_status=status,
                response_time=result.get("response_time"),
                error_message=result.get("error_message"),
                error_details=result.get("error_details"),
                health_data=result.get("health_data"),
                capabilities_detected=result.get("capabilities"),
                version_detected=result.get("version")
            )
            
            with get_db() as db:
                db.add(log_entry)
                db.commit()
                
        except Exception as e:
            logger.error(f"Error logging connection attempt: {e}")
    
    async def _disconnect_integration(self, integration_id: UUID):
        """Disconnect a specific integration."""
        try:
            integration = self.active_integrations.get(integration_id)
            if not integration:
                return
            
            connector = self.connectors.get(IntegrationType(integration.integration_type))
            if connector:
                await connector.disconnect(integration)
            
            # Update status
            await self._update_integration_connection_status(integration_id, ConnectionStatus.DISCONNECTED)
            
        except Exception as e:
            logger.error(f"Error disconnecting integration {integration_id}: {e}")
    
    # Event handlers
    async def _handle_integration_created(self, event_data: Dict[str, Any]):
        """Handle integration created event."""
        try:
            integration_id = UUID(event_data["integration_id"])
            
            # Reload integration from database
            with get_db() as db:
                integration = db.query(Integration).filter(
                    Integration.id == integration_id
                ).first()
                
                if integration and integration.is_enabled:
                    self.active_integrations[integration_id] = integration
                    
                    # Initialize the integration
                    task = asyncio.create_task(self._initialize_integration(integration_id))
                    self.integration_tasks.add(task)
                    task.add_done_callback(self.integration_tasks.discard)
                    
        except Exception as e:
            logger.error(f"Error handling integration created event: {e}")
    
    async def _handle_integration_updated(self, event_data: Dict[str, Any]):
        """Handle integration updated event."""
        try:
            integration_id = UUID(event_data["integration_id"])
            
            # Reload integration from database
            with get_db() as db:
                integration = db.query(Integration).filter(
                    Integration.id == integration_id
                ).first()
                
                if integration:
                    if integration.is_enabled:
                        self.active_integrations[integration_id] = integration
                        
                        # Re-initialize if needed
                        if integration.status == IntegrationStatus.PENDING:
                            task = asyncio.create_task(self._initialize_integration(integration_id))
                            self.integration_tasks.add(task)
                            task.add_done_callback(self.integration_tasks.discard)
                    else:
                        # Remove from active integrations
                        if integration_id in self.active_integrations:
                            await self._disconnect_integration(integration_id)
                            del self.active_integrations[integration_id]
                            
        except Exception as e:
            logger.error(f"Error handling integration updated event: {e}")
    
    async def _handle_integration_deleted(self, event_data: Dict[str, Any]):
        """Handle integration deleted event."""
        try:
            integration_id = UUID(event_data["integration_id"])
            
            if integration_id in self.active_integrations:
                await self._disconnect_integration(integration_id)
                del self.active_integrations[integration_id]
                
        except Exception as e:
            logger.error(f"Error handling integration deleted event: {e}")
    
    async def _handle_sync_requested(self, event_data: Dict[str, Any]):
        """Handle sync requested event."""
        try:
            sync_request = {
                "integration_id": event_data["integration_id"],
                "sync_type": event_data.get("sync_type", "pull"),
                "priority": event_data.get("priority", "normal"),
                "data": event_data.get("data")
            }
            
            await self.sync_queue.put(sync_request)
            
        except Exception as e:
            logger.error(f"Error handling sync requested event: {e}")
    
    # Event routing methods
    async def _route_security_event(self, event_data: Dict[str, Any]):
        """Route security events to external systems."""
        try:
            # Route to SIEM systems
            siem_integrations = [
                integration for integration in self.active_integrations.values()
                if integration.integration_type == IntegrationType.SIEM and 
                integration.status == IntegrationStatus.ACTIVE
            ]
            
            for integration in siem_integrations:
                connector = self.connectors[IntegrationType.SIEM]
                if connector:
                    await connector.send_event(integration, "security_incident", event_data)
            
            # Route to ticketing systems if configured
            await self._route_to_ticketing("security_incident", event_data)
            
        except Exception as e:
            logger.error(f"Error routing security event: {e}")
    
    async def _route_vulnerability_event(self, event_data: Dict[str, Any]):
        """Route vulnerability events to external systems."""
        try:
            # Route to vulnerability management systems
            vuln_integrations = [
                integration for integration in self.active_integrations.values()
                if integration.integration_type == IntegrationType.VULNERABILITY_FEED and 
                integration.status == IntegrationStatus.ACTIVE
            ]
            
            for integration in vuln_integrations:
                connector = self.connectors[IntegrationType.VULNERABILITY_FEED]
                if connector:
                    await connector.send_event(integration, "vulnerability_detected", event_data)
            
        except Exception as e:
            logger.error(f"Error routing vulnerability event: {e}")
    
    async def _route_threat_event(self, event_data: Dict[str, Any]):
        """Route threat events to external systems."""
        try:
            # Route to threat intelligence platforms
            threat_integrations = [
                integration for integration in self.active_integrations.values()
                if integration.integration_type == IntegrationType.THREAT_FEED and 
                integration.status == IntegrationStatus.ACTIVE
            ]
            
            for integration in threat_integrations:
                connector = self.connectors[IntegrationType.THREAT_FEED]
                if connector:
                    await connector.send_event(integration, "threat_detected", event_data)
            
        except Exception as e:
            logger.error(f"Error routing threat event: {e}")
    
    async def _route_to_ticketing(self, event_type: str, event_data: Dict[str, Any]):
        """Route events to ticketing systems."""
        try:
            ticketing_integrations = [
                integration for integration in self.active_integrations.values()
                if integration.integration_type == IntegrationType.TICKETING and 
                integration.status == IntegrationStatus.ACTIVE
            ]
            
            for integration in ticketing_integrations:
                # Check if this integration is configured to handle this event type
                if event_type in integration.settings.get("auto_ticket_events", []):
                    connector = self.connectors[IntegrationType.TICKETING]
                    if connector:
                        await connector.create_ticket(integration, event_type, event_data)
            
        except Exception as e:
            logger.error(f"Error routing to ticketing systems: {e}")
    
    # Public interface methods
    async def request_sync(self, integration_id: UUID, sync_type: str = "pull", data: Optional[Dict[str, Any]] = None):
        """Request data synchronization for an integration."""
        sync_request = {
            "integration_id": str(integration_id),
            "sync_type": sync_type,
            "priority": "normal",
            "data": data
        }
        
        await self.sync_queue.put(sync_request)
    
    async def test_integration(self, integration_id: UUID) -> Dict[str, Any]:
        """Test an integration connection."""
        try:
            integration = self.active_integrations.get(integration_id)
            if not integration:
                return {"success": False, "error": "Integration not found"}
            
            connector = self.connectors.get(IntegrationType(integration.integration_type))
            if not connector:
                return {"success": False, "error": "Connector not available"}
            
            # Perform test connection
            test_result = await connector.test_connection(integration)
            
            # Log the test attempt
            await self._log_connection_attempt(
                integration_id,
                ConnectionStatus.CONNECTED if test_result.get("success") else ConnectionStatus.FAILED,
                test_result
            )
            
            return test_result
            
        except Exception as e:
            logger.error(f"Error testing integration {integration_id}: {e}")
            return {"success": False, "error": str(e)}
    
    def get_stats(self) -> Dict[str, Any]:
        """Get integration manager statistics."""
        return {
            "active_integrations": len(self.active_integrations),
            "integration_tasks": len(self.integration_tasks),
            "sync_queue_size": self.sync_queue.qsize(),
            "health_check_interval": self.health_check_interval,
            "integrations_by_type": {
                integration_type.value: len([
                    i for i in self.active_integrations.values()
                    if i.integration_type == integration_type
                ])
                for integration_type in IntegrationType
            },
            "integrations_by_status": {
                status.value: len([
                    i for i in self.active_integrations.values()
                    if i.status == status
                ])
                for status in IntegrationStatus
            }
        }