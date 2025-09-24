"""
Risk Assessment Engine - Core Risk Assessment Orchestrator

This service orchestrates the complete risk assessment process,
integrating correlation results, LLM analysis, and risk calculation.
"""

import time
import asyncio
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from uuid import UUID
from dataclasses import dataclass

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.events.event_bus import EventBus

from ..models.risk_assessment import (
    RiskAssessment, RiskFactor, RiskMitigation, RiskProfile, RiskContext,
    RiskLevel, RiskCategory, RiskAssessmentStatus, create_risk_assessment, get_db
)
from .llm_client import LLMManager, RiskAssessmentPrompt
from .risk_calculator import RiskCalculator, RiskVector, RiskCalculationMethod

logger = get_logger(__name__)
metrics = get_metrics()


@dataclass
class AssessmentRequest:
    """Risk assessment request."""
    correlation_result_id: UUID
    correlation_data: Dict[str, Any]
    assessment_type: str
    priority: int = 5
    requested_by: str = "system"
    context: Optional[Dict[str, Any]] = None


@dataclass
class AssessmentContext:
    """Assessment context data."""
    organization_profile: Dict[str, Any]
    threat_landscape: Dict[str, Any]
    compliance_requirements: List[str]
    asset_information: Dict[str, Any]
    historical_data: Dict[str, Any]
    risk_tolerance: Dict[str, Any]


class RiskAssessmentEngine:
    """
    Core risk assessment engine that orchestrates the complete assessment process.
    
    This engine:
    1. Processes correlation results
    2. Gathers contextual information
    3. Performs LLM-enhanced analysis
    4. Calculates risk scores
    5. Generates recommendations
    6. Updates risk profiles
    """
    
    def __init__(
        self,
        llm_manager: LLMManager,
        risk_calculator: RiskCalculator,
        event_bus: EventBus
    ):
        self.llm_manager = llm_manager
        self.risk_calculator = risk_calculator
        self.event_bus = event_bus
        
        # Assessment queue for processing
        self.assessment_queue = asyncio.Queue()
        self.processing_tasks = set()
        
        # Context cache for performance
        self.context_cache = {}
        self.cache_ttl = 3600  # 1 hour
        
        logger.info("Risk assessment engine initialized")
    
    async def start(self):
        """Start the risk assessment engine."""
        # Start assessment processor
        processor_task = asyncio.create_task(self._process_assessments())
        self.processing_tasks.add(processor_task)
        
        # Subscribe to correlation events
        await self.event_bus.subscribe(
            "correlation.result.created",
            self._handle_correlation_result
        )
        
        logger.info("Risk assessment engine started")
    
    async def stop(self):
        """Stop the risk assessment engine."""
        # Cancel processing tasks
        for task in self.processing_tasks:
            task.cancel()
        
        await asyncio.gather(*self.processing_tasks, return_exceptions=True)
        
        logger.info("Risk assessment engine stopped")
    
    @traced("risk_assessment_engine_assess")
    async def assess_risk(self, request: AssessmentRequest) -> RiskAssessment:
        """Perform comprehensive risk assessment."""
        start_time = time.time()
        
        try:
            logger.info(f"Starting risk assessment for correlation {request.correlation_result_id}")
            
            # Step 1: Gather assessment context
            context = await self._gather_assessment_context(request)
            
            # Step 2: Perform LLM analysis
            llm_analysis = await self._perform_llm_analysis(request, context)
            
            # Step 3: Calculate risk scores
            risk_calculation = await self._calculate_risk_scores(request, context, llm_analysis)
            
            # Step 4: Generate risk factors
            risk_factors = await self._generate_risk_factors(request, context, llm_analysis)
            
            # Step 5: Create risk assessment
            assessment = await self._create_risk_assessment(
                request, context, llm_analysis, risk_calculation, risk_factors
            )
            
            # Step 6: Generate recommendations
            recommendations = await self._generate_recommendations(assessment, context)
            
            # Step 7: Update risk profiles
            await self._update_risk_profiles(assessment, context)
            
            # Step 8: Publish assessment event
            await self._publish_assessment_event(assessment)
            
            processing_time = time.time() - start_time
            metrics.risk_assessment_engine_processing_time.observe(processing_time)
            metrics.risk_assessment_engine_assessments.inc()
            
            logger.info(f"Risk assessment completed: {assessment.risk_level} ({assessment.risk_score})")
            
            return assessment
            
        except Exception as e:
            logger.error(f"Error in risk assessment: {e}")
            metrics.risk_assessment_engine_errors.inc()
            raise
    
    async def _handle_correlation_result(self, event_data: Dict[str, Any]):
        """Handle correlation result event."""
        try:
            correlation_id = event_data.get("correlation_id")
            if not correlation_id:
                return
            
            # Create assessment request
            request = AssessmentRequest(
                correlation_result_id=UUID(correlation_id),
                correlation_data=event_data.get("correlation_data", {}),
                assessment_type="automated",
                priority=self._calculate_priority(event_data),
                requested_by="correlation_engine",
                context=event_data.get("context", {})
            )
            
            # Queue for processing
            await self.assessment_queue.put(request)
            
        except Exception as e:
            logger.error(f"Error handling correlation result: {e}")
    
    async def _process_assessments(self):
        """Process assessment queue."""
        while True:
            try:
                # Get assessment request
                request = await self.assessment_queue.get()
                
                # Process assessment
                task = asyncio.create_task(self.assess_risk(request))
                self.processing_tasks.add(task)
                task.add_done_callback(self.processing_tasks.discard)
                
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.error(f"Error processing assessment: {e}")
                await asyncio.sleep(1)
    
    async def _gather_assessment_context(self, request: AssessmentRequest) -> AssessmentContext:
        """Gather contextual information for assessment."""
        try:
            # Check cache first
            cache_key = f"context_{request.correlation_result_id}"
            cached_context = self.context_cache.get(cache_key)
            
            if cached_context and cached_context["expires_at"] > datetime.now():
                return cached_context["context"]
            
            # Gather context from various sources
            with get_db() as db:
                # Get organization profile
                org_profile = await self._get_organization_profile(db)
                
                # Get threat landscape
                threat_landscape = await self._get_threat_landscape(db)
                
                # Get compliance requirements
                compliance_reqs = await self._get_compliance_requirements(db)
                
                # Get asset information
                asset_info = await self._get_asset_information(db, request.correlation_data)
                
                # Get historical data
                historical_data = await self._get_historical_data(db, request.correlation_result_id)
                
                # Get risk tolerance
                risk_tolerance = await self._get_risk_tolerance(db)
                
                context = AssessmentContext(
                    organization_profile=org_profile,
                    threat_landscape=threat_landscape,
                    compliance_requirements=compliance_reqs,
                    asset_information=asset_info,
                    historical_data=historical_data,
                    risk_tolerance=risk_tolerance
                )
                
                # Cache context
                self.context_cache[cache_key] = {
                    "context": context,
                    "expires_at": datetime.now() + timedelta(seconds=self.cache_ttl)
                }
                
                return context
                
        except Exception as e:
            logger.error(f"Error gathering assessment context: {e}")
            # Return minimal context
            return AssessmentContext(
                organization_profile={},
                threat_landscape={},
                compliance_requirements=[],
                asset_information={},
                historical_data={},
                risk_tolerance={}
            )
    
    async def _perform_llm_analysis(
        self,
        request: AssessmentRequest,
        context: AssessmentContext
    ) -> Dict[str, Any]:
        """Perform LLM-enhanced risk analysis."""
        try:
            # Create LLM prompt
            prompt = RiskAssessmentPrompt(
                correlation_data=request.correlation_data,
                context_data={
                    "organization_profile": context.organization_profile,
                    "threat_landscape": context.threat_landscape,
                    "compliance_requirements": context.compliance_requirements,
                    "asset_information": context.asset_information
                },
                assessment_type=request.assessment_type,
                risk_framework="nist",
                organization_profile=context.organization_profile
            )
            
            # Get LLM analysis
            llm_response = await self.llm_manager.assess_risk(prompt)
            
            # Parse LLM response
            import json
            llm_analysis = json.loads(llm_response.content)
            
            # Add LLM metadata
            llm_analysis["llm_metadata"] = {
                "provider": llm_response.provider,
                "model": llm_response.model,
                "confidence": llm_response.confidence,
                "reasoning": llm_response.reasoning,
                "response_time": llm_response.response_time,
                "usage": llm_response.usage
            }
            
            return llm_analysis
            
        except Exception as e:
            logger.error(f"Error in LLM analysis: {e}")
            # Return basic analysis
            return {
                "risk_level": "medium",
                "risk_score": 50,
                "confidence": 0.5,
                "reasoning": "Analysis failed, using default values",
                "llm_metadata": {"error": str(e)}
            }
    
    async def _calculate_risk_scores(
        self,
        request: AssessmentRequest,
        context: AssessmentContext,
        llm_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Calculate comprehensive risk scores."""
        try:
            # Extract risk factors from correlation data and LLM analysis
            impact_score = self._extract_impact_score(request.correlation_data, llm_analysis)
            likelihood_score = self._extract_likelihood_score(request.correlation_data, llm_analysis)
            vulnerability_score = self._extract_vulnerability_score(request.correlation_data, llm_analysis)
            threat_score = self._extract_threat_score(request.correlation_data, llm_analysis)
            asset_value = self._extract_asset_value(context.asset_information)
            control_effectiveness = self._extract_control_effectiveness(context.organization_profile)
            
            # Create risk vector
            risk_vector = RiskVector(
                impact=impact_score,
                likelihood=likelihood_score,
                vulnerability=vulnerability_score,
                threat=threat_score,
                asset_value=asset_value,
                control_effectiveness=control_effectiveness
            )
            
            # Calculate risk using multiple methods
            methods = [
                RiskCalculationMethod.SEMI_QUANTITATIVE,
                RiskCalculationMethod.QUALITATIVE,
                RiskCalculationMethod.QUANTITATIVE
            ]
            
            calculations = {}
            for method in methods:
                try:
                    result = self.risk_calculator.calculate_risk(
                        risk_vector,
                        method,
                        {
                            "correlation_data": request.correlation_data,
                            "organization_profile": context.organization_profile,
                            "threat_landscape": context.threat_landscape
                        }
                    )
                    calculations[method.value] = result
                except Exception as e:
                    logger.warning(f"Error calculating risk with {method}: {e}")
            
            # Use semi-quantitative as primary, with fallback
            primary_calculation = calculations.get(
                RiskCalculationMethod.SEMI_QUANTITATIVE.value,
                calculations.get(RiskCalculationMethod.QUALITATIVE.value)
            )
            
            if not primary_calculation:
                raise Exception("No risk calculation method succeeded")
            
            return {
                "primary_calculation": primary_calculation,
                "all_calculations": calculations,
                "risk_vector": risk_vector
            }
            
        except Exception as e:
            logger.error(f"Error calculating risk scores: {e}")
            raise
    
    async def _generate_risk_factors(
        self,
        request: AssessmentRequest,
        context: AssessmentContext,
        llm_analysis: Dict[str, Any]
    ) -> List[RiskFactor]:
        """Generate detailed risk factors."""
        factors = []
        
        try:
            # Extract risk factors from LLM analysis
            llm_factors = llm_analysis.get("risk_factors", [])
            
            for factor_data in llm_factors:
                factor = RiskFactor(
                    factor_name=factor_data.get("factor", "Unknown"),
                    factor_type="llm_identified",
                    factor_description=factor_data.get("description", ""),
                    weight=factor_data.get("weight", 0.5),
                    impact=factor_data.get("impact", 50),
                    likelihood=factor_data.get("likelihood", 50),
                    factor_data=factor_data,
                    evidence={"source": "llm_analysis"}
                )
                factors.append(factor)
            
            # Add technical factors from correlation data
            correlation_factors = self._extract_correlation_factors(request.correlation_data)
            factors.extend(correlation_factors)
            
            # Add contextual factors
            context_factors = self._extract_context_factors(context)
            factors.extend(context_factors)
            
            return factors
            
        except Exception as e:
            logger.error(f"Error generating risk factors: {e}")
            return []
    
    async def _create_risk_assessment(
        self,
        request: AssessmentRequest,
        context: AssessmentContext,
        llm_analysis: Dict[str, Any],
        risk_calculation: Dict[str, Any],
        risk_factors: List[RiskFactor]
    ) -> RiskAssessment:
        """Create risk assessment record."""
        try:
            primary_calc = risk_calculation["primary_calculation"]
            
            # Extract title and description
            title = llm_analysis.get("title", f"Risk Assessment for {request.correlation_result_id}")
            description = llm_analysis.get("description", "Automated risk assessment")
            
            # Create assessment
            assessment = create_risk_assessment(
                title=title,
                correlation_result_id=request.correlation_result_id,
                risk_level=primary_calc.risk_level,
                risk_score=primary_calc.overall_risk_score,
                confidence_score=primary_calc.confidence_score,
                risk_category=primary_calc.risk_category,
                impact_score=risk_calculation["risk_vector"].impact,
                likelihood_score=risk_calculation["risk_vector"].likelihood,
                created_by=request.requested_by,
                description=description,
                vulnerability_score=risk_calculation["risk_vector"].vulnerability,
                threat_score=risk_calculation["risk_vector"].threat,
                context_data={
                    "organization_profile": context.organization_profile,
                    "threat_landscape": context.threat_landscape,
                    "compliance_requirements": context.compliance_requirements
                },
                analysis_data=primary_calc.metadata,
                llm_analysis=llm_analysis,
                llm_confidence=llm_analysis.get("confidence", 0.0),
                llm_reasoning=llm_analysis.get("reasoning", ""),
                status=RiskAssessmentStatus.COMPLETED,
                completed_at=datetime.now(),
                metadata={
                    "calculation_methods": list(risk_calculation["all_calculations"].keys()),
                    "risk_factors_count": len(risk_factors),
                    "assessment_type": request.assessment_type
                }
            )
            
            # Save to database
            with get_db() as db:
                db.add(assessment)
                db.flush()  # Get ID
                
                # Add risk factors
                for factor in risk_factors:
                    factor.assessment_id = assessment.id
                    db.add(factor)
                
                db.commit()
                db.refresh(assessment)
            
            return assessment
            
        except Exception as e:
            logger.error(f"Error creating risk assessment: {e}")
            raise
    
    async def _generate_recommendations(
        self,
        assessment: RiskAssessment,
        context: AssessmentContext
    ) -> List[RiskMitigation]:
        """Generate risk mitigation recommendations."""
        try:
            # Use LLM to generate recommendations
            recommendations_response = await self.llm_manager.generate_recommendations({
                "assessment": {
                    "risk_level": assessment.risk_level,
                    "risk_score": assessment.risk_score,
                    "risk_category": assessment.risk_category,
                    "analysis_data": assessment.analysis_data,
                    "context_data": assessment.context_data
                },
                "organization_profile": context.organization_profile,
                "compliance_requirements": context.compliance_requirements
            })
            
            # Parse recommendations
            import json
            recommendations_data = json.loads(recommendations_response.content)
            
            mitigations = []
            for rec in recommendations_data.get("recommendations", []):
                mitigation = RiskMitigation(
                    assessment_id=assessment.id,
                    mitigation_name=rec.get("title", "Recommendation"),
                    mitigation_type=rec.get("type", "corrective"),
                    description=rec.get("description", ""),
                    effectiveness_score=rec.get("effectiveness", 70),
                    implementation_cost=self._map_cost_to_score(rec.get("implementation_cost", "medium")),
                    implementation_time=self._map_time_to_days(rec.get("implementation_time", "medium")),
                    priority=rec.get("priority", 5),
                    implementation_plan=rec.get("implementation_plan", {}),
                    status="recommended"
                )
                mitigations.append(mitigation)
            
            # Save recommendations
            with get_db() as db:
                for mitigation in mitigations:
                    db.add(mitigation)
                db.commit()
            
            return mitigations
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            return []
    
    async def _update_risk_profiles(
        self,
        assessment: RiskAssessment,
        context: AssessmentContext
    ):
        """Update risk profiles based on assessment."""
        try:
            # Extract entities from correlation data
            entities = self._extract_entities(assessment.context_data)
            
            with get_db() as db:
                for entity_type, entity_id in entities:
                    # Get or create risk profile
                    profile = db.query(RiskProfile).filter(
                        RiskProfile.entity_type == entity_type,
                        RiskProfile.entity_id == entity_id
                    ).first()
                    
                    if not profile:
                        profile = RiskProfile(
                            entity_type=entity_type,
                            entity_id=entity_id,
                            entity_name=entity_id,
                            overall_risk_score=assessment.risk_score,
                            risk_level=assessment.risk_level,
                            score_history=[],
                            incident_count=1,
                            last_incident_date=datetime.now(),
                            last_assessed_at=datetime.now()
                        )
                        db.add(profile)
                    else:
                        # Update existing profile
                        profile.overall_risk_score = self._calculate_updated_risk_score(
                            profile.overall_risk_score,
                            assessment.risk_score
                        )
                        profile.risk_level = self._score_to_risk_level(profile.overall_risk_score)
                        profile.incident_count += 1
                        profile.last_incident_date = datetime.now()
                        profile.last_assessed_at = datetime.now()
                        
                        # Update score history
                        if not profile.score_history:
                            profile.score_history = []
                        profile.score_history.append({
                            "date": datetime.now().isoformat(),
                            "score": assessment.risk_score,
                            "assessment_id": str(assessment.id)
                        })
                        
                        # Keep only last 100 entries
                        if len(profile.score_history) > 100:
                            profile.score_history = profile.score_history[-100:]
                
                db.commit()
                
        except Exception as e:
            logger.error(f"Error updating risk profiles: {e}")
    
    async def _publish_assessment_event(self, assessment: RiskAssessment):
        """Publish risk assessment event."""
        try:
            event_data = {
                "assessment_id": str(assessment.id),
                "correlation_result_id": str(assessment.correlation_result_id),
                "risk_level": assessment.risk_level,
                "risk_score": assessment.risk_score,
                "risk_category": assessment.risk_category,
                "confidence_score": assessment.confidence_score,
                "created_at": assessment.created_at.isoformat(),
                "created_by": assessment.created_by
            }
            
            await self.event_bus.publish("risk_assessment.completed", event_data)
            
        except Exception as e:
            logger.error(f"Error publishing assessment event: {e}")
    
    # Helper methods
    def _calculate_priority(self, event_data: Dict[str, Any]) -> int:
        """Calculate assessment priority."""
        severity = event_data.get("severity", "medium").lower()
        confidence = event_data.get("confidence", 50)
        
        if severity == "critical":
            return 10
        elif severity == "high":
            return 8
        elif severity == "medium":
            return 5
        else:
            return 3
    
    def _extract_impact_score(self, correlation_data: Dict[str, Any], llm_analysis: Dict[str, Any]) -> float:
        """Extract impact score from data."""
        # Prefer LLM analysis
        if "impact_score" in llm_analysis:
            return llm_analysis["impact_score"]
        
        # Fall back to correlation data
        risk_score = correlation_data.get("risk_score", 50)
        return min(100, risk_score * 1.2)  # Slight boost for impact
    
    def _extract_likelihood_score(self, correlation_data: Dict[str, Any], llm_analysis: Dict[str, Any]) -> float:
        """Extract likelihood score from data."""
        if "likelihood_score" in llm_analysis:
            return llm_analysis["likelihood_score"]
        
        confidence = correlation_data.get("confidence", 50)
        return confidence
    
    def _extract_vulnerability_score(self, correlation_data: Dict[str, Any], llm_analysis: Dict[str, Any]) -> float:
        """Extract vulnerability score from data."""
        if "vulnerability_score" in llm_analysis:
            return llm_analysis["vulnerability_score"]
        
        # Estimate based on pattern type
        metadata = correlation_data.get("metadata", {})
        pattern_type = metadata.get("pattern_type", "unknown")
        
        vulnerability_map = {
            "brute_force": 80,
            "privilege_escalation": 90,
            "data_exfiltration": 85,
            "lateral_movement": 75,
            "port_scan": 60
        }
        
        return vulnerability_map.get(pattern_type, 50)
    
    def _extract_threat_score(self, correlation_data: Dict[str, Any], llm_analysis: Dict[str, Any]) -> float:
        """Extract threat score from data."""
        if "threat_score" in llm_analysis:
            return llm_analysis["threat_score"]
        
        # Estimate based on severity
        severity = correlation_data.get("severity", "medium").lower()
        severity_map = {
            "critical": 95,
            "high": 80,
            "medium": 60,
            "low": 30,
            "informational": 10
        }
        
        return severity_map.get(severity, 50)
    
    def _extract_asset_value(self, asset_info: Dict[str, Any]) -> float:
        """Extract asset value from asset information."""
        return asset_info.get("value_score", 70)
    
    def _extract_control_effectiveness(self, org_profile: Dict[str, Any]) -> float:
        """Extract control effectiveness from organization profile."""
        security_maturity = org_profile.get("security_maturity", 60)
        return security_maturity
    
    def _map_cost_to_score(self, cost: str) -> float:
        """Map cost string to numeric score."""
        cost_map = {
            "low": 20,
            "medium": 50,
            "high": 80
        }
        return cost_map.get(cost.lower(), 50)
    
    def _map_time_to_days(self, time_str: str) -> int:
        """Map time string to days."""
        time_map = {
            "immediate": 1,
            "short": 7,
            "medium": 30,
            "long": 90
        }
        return time_map.get(time_str.lower(), 30)
    
    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert score to risk level."""
        if score >= 85:
            return RiskLevel.CRITICAL
        elif score >= 70:
            return RiskLevel.HIGH
        elif score >= 40:
            return RiskLevel.MEDIUM
        elif score >= 15:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFORMATIONAL
    
    def get_stats(self) -> Dict[str, Any]:
        """Get engine statistics."""
        return {
            "queue_size": self.assessment_queue.qsize(),
            "active_tasks": len(self.processing_tasks),
            "cache_entries": len(self.context_cache),
            "cache_ttl": self.cache_ttl
        }
    
    # Placeholder methods (would be implemented based on specific data sources)
    async def _get_organization_profile(self, db) -> Dict[str, Any]:
        """Get organization profile from database."""
        return {"security_maturity": 70, "industry": "technology"}
    
    async def _get_threat_landscape(self, db) -> Dict[str, Any]:
        """Get threat landscape data."""
        return {"threat_level": "medium", "active_campaigns": []}
    
    async def _get_compliance_requirements(self, db) -> List[str]:
        """Get compliance requirements."""
        return ["SOC2", "ISO27001", "GDPR"]
    
    async def _get_asset_information(self, db, correlation_data: Dict[str, Any]) -> Dict[str, Any]:
        """Get asset information."""
        return {"value_score": 75, "criticality": "high"}
    
    async def _get_historical_data(self, db, correlation_id: UUID) -> Dict[str, Any]:
        """Get historical data."""
        return {"similar_incidents": 0, "trend": "stable"}
    
    async def _get_risk_tolerance(self, db) -> Dict[str, Any]:
        """Get risk tolerance settings."""
        return {"risk_appetite": "moderate", "tolerance_thresholds": {}}
    
    def _extract_correlation_factors(self, correlation_data: Dict[str, Any]) -> List[RiskFactor]:
        """Extract risk factors from correlation data."""
        return []
    
    def _extract_context_factors(self, context: AssessmentContext) -> List[RiskFactor]:
        """Extract risk factors from context."""
        return []
    
    def _extract_entities(self, context_data: Dict[str, Any]) -> List[Tuple[str, str]]:
        """Extract entities from context data."""
        return []
    
    def _calculate_updated_risk_score(self, current_score: float, new_score: float) -> float:
        """Calculate updated risk score."""
        # Weighted average with emphasis on recent score
        return (current_score * 0.7) + (new_score * 0.3)