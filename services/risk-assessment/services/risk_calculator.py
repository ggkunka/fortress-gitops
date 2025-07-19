"""
Risk Calculator - Advanced Risk Scoring and Analysis Engine

This service implements sophisticated risk calculation algorithms,
including quantitative risk analysis, threat modeling, and impact assessment.
"""

import math
import statistics
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict

import numpy as np
from scipy import stats

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced

from ..models.risk_assessment import RiskLevel, RiskCategory, RiskAssessment, RiskFactor

logger = get_logger(__name__)
metrics = get_metrics()


class RiskCalculationMethod(str, Enum):
    """Risk calculation methods."""
    QUALITATIVE = "qualitative"
    QUANTITATIVE = "quantitative"
    SEMI_QUANTITATIVE = "semi_quantitative"
    MONTE_CARLO = "monte_carlo"
    FUZZY_LOGIC = "fuzzy_logic"


@dataclass
class RiskVector:
    """Risk vector for multidimensional risk analysis."""
    impact: float  # 0-100
    likelihood: float  # 0-100
    vulnerability: float  # 0-100
    threat: float  # 0-100
    asset_value: float  # 0-100
    control_effectiveness: float  # 0-100


@dataclass
class RiskCalculationResult:
    """Risk calculation result."""
    overall_risk_score: float
    risk_level: RiskLevel
    risk_category: RiskCategory
    confidence_score: float
    calculation_method: RiskCalculationMethod
    risk_factors: List[Dict[str, Any]]
    impact_breakdown: Dict[str, float]
    mitigation_impact: float
    residual_risk: float
    metadata: Dict[str, Any]


class RiskCalculator:
    """
    Advanced risk calculator with multiple calculation methods.
    
    Supports various risk assessment methodologies including:
    - Qualitative risk assessment
    - Quantitative risk analysis (QRA)
    - Semi-quantitative approaches
    - Monte Carlo simulation
    - Fuzzy logic risk assessment
    """
    
    def __init__(self):
        # Risk calculation weights and parameters
        self.impact_weights = {
            "financial": 0.3,
            "operational": 0.25,
            "reputational": 0.2,
            "compliance": 0.15,
            "technical": 0.1
        }
        
        self.likelihood_factors = {
            "threat_capability": 0.3,
            "vulnerability_exploitability": 0.25,
            "control_effectiveness": 0.2,
            "threat_motivation": 0.15,
            "attack_surface": 0.1
        }
        
        # Risk level thresholds
        self.risk_thresholds = {
            RiskLevel.CRITICAL: 85,
            RiskLevel.HIGH: 70,
            RiskLevel.MEDIUM: 40,
            RiskLevel.LOW: 15,
            RiskLevel.INFORMATIONAL: 0
        }
        
        logger.info("Risk calculator initialized")
    
    @traced("risk_calculator_calculate_risk")
    def calculate_risk(
        self,
        risk_vector: RiskVector,
        method: RiskCalculationMethod = RiskCalculationMethod.SEMI_QUANTITATIVE,
        context: Optional[Dict[str, Any]] = None
    ) -> RiskCalculationResult:
        """Calculate risk score using specified method."""
        try:
            context = context or {}
            
            if method == RiskCalculationMethod.QUALITATIVE:
                result = self._calculate_qualitative_risk(risk_vector, context)
            elif method == RiskCalculationMethod.QUANTITATIVE:
                result = self._calculate_quantitative_risk(risk_vector, context)
            elif method == RiskCalculationMethod.SEMI_QUANTITATIVE:
                result = self._calculate_semi_quantitative_risk(risk_vector, context)
            elif method == RiskCalculationMethod.MONTE_CARLO:
                result = self._calculate_monte_carlo_risk(risk_vector, context)
            elif method == RiskCalculationMethod.FUZZY_LOGIC:
                result = self._calculate_fuzzy_logic_risk(risk_vector, context)
            else:
                raise ValueError(f"Unsupported calculation method: {method}")
            
            metrics.risk_calculator_calculations.inc()
            logger.debug(f"Risk calculated: {result.overall_risk_score} ({result.risk_level})")
            
            return result
            
        except Exception as e:
            logger.error(f"Error calculating risk: {e}")
            metrics.risk_calculator_errors.inc()
            raise
    
    def _calculate_qualitative_risk(
        self,
        risk_vector: RiskVector,
        context: Dict[str, Any]
    ) -> RiskCalculationResult:
        """Calculate qualitative risk assessment."""
        # Convert quantitative values to qualitative categories
        impact_category = self._quantitative_to_qualitative(risk_vector.impact)
        likelihood_category = self._quantitative_to_qualitative(risk_vector.likelihood)
        
        # Qualitative risk matrix
        risk_matrix = {
            ("very_low", "very_low"): 5,
            ("very_low", "low"): 10,
            ("very_low", "medium"): 15,
            ("very_low", "high"): 20,
            ("very_low", "very_high"): 25,
            ("low", "very_low"): 10,
            ("low", "low"): 20,
            ("low", "medium"): 30,
            ("low", "high"): 40,
            ("low", "very_high"): 50,
            ("medium", "very_low"): 15,
            ("medium", "low"): 30,
            ("medium", "medium"): 50,
            ("medium", "high"): 70,
            ("medium", "very_high"): 85,
            ("high", "very_low"): 20,
            ("high", "low"): 40,
            ("high", "medium"): 70,
            ("high", "high"): 90,
            ("high", "very_high"): 95,
            ("very_high", "very_low"): 25,
            ("very_high", "low"): 50,
            ("very_high", "medium"): 85,
            ("very_high", "high"): 95,
            ("very_high", "very_high"): 100
        }
        
        overall_risk_score = risk_matrix.get(
            (impact_category, likelihood_category), 50
        )
        
        # Adjust for other factors
        if risk_vector.vulnerability > 80:
            overall_risk_score = min(100, overall_risk_score * 1.2)
        if risk_vector.control_effectiveness < 30:
            overall_risk_score = min(100, overall_risk_score * 1.15)
        
        return RiskCalculationResult(
            overall_risk_score=overall_risk_score,
            risk_level=self._score_to_risk_level(overall_risk_score),
            risk_category=self._determine_risk_category(context),
            confidence_score=0.7,  # Qualitative assessments have moderate confidence
            calculation_method=RiskCalculationMethod.QUALITATIVE,
            risk_factors=[
                {"factor": "impact", "weight": 0.5, "value": risk_vector.impact},
                {"factor": "likelihood", "weight": 0.5, "value": risk_vector.likelihood}
            ],
            impact_breakdown=self._calculate_impact_breakdown(risk_vector, context),
            mitigation_impact=0.0,
            residual_risk=overall_risk_score,
            metadata={
                "impact_category": impact_category,
                "likelihood_category": likelihood_category,
                "calculation_date": datetime.now().isoformat()
            }
        )
    
    def _calculate_quantitative_risk(
        self,
        risk_vector: RiskVector,
        context: Dict[str, Any]
    ) -> RiskCalculationResult:
        """Calculate quantitative risk analysis."""
        # Single Loss Expectancy (SLE) = Asset Value × Exposure Factor
        asset_value = risk_vector.asset_value
        exposure_factor = risk_vector.vulnerability / 100
        sle = asset_value * exposure_factor
        
        # Annualized Rate of Occurrence (ARO) based on likelihood
        aro = self._likelihood_to_aro(risk_vector.likelihood)
        
        # Annualized Loss Expectancy (ALE) = SLE × ARO
        ale = sle * aro
        
        # Convert ALE to risk score (0-100)
        max_ale = asset_value * aro  # Maximum possible loss
        risk_score = min(100, (ale / max_ale) * 100) if max_ale > 0 else 0
        
        # Adjust for threat level
        threat_multiplier = 1 + (risk_vector.threat / 100)
        risk_score = min(100, risk_score * threat_multiplier)
        
        # Adjust for control effectiveness
        control_reduction = risk_vector.control_effectiveness / 100
        residual_risk = risk_score * (1 - control_reduction)
        
        return RiskCalculationResult(
            overall_risk_score=residual_risk,
            risk_level=self._score_to_risk_level(residual_risk),
            risk_category=self._determine_risk_category(context),
            confidence_score=0.9,  # Quantitative assessments have high confidence
            calculation_method=RiskCalculationMethod.QUANTITATIVE,
            risk_factors=[
                {"factor": "sle", "weight": 0.4, "value": sle},
                {"factor": "aro", "weight": 0.3, "value": aro},
                {"factor": "control_effectiveness", "weight": 0.3, "value": risk_vector.control_effectiveness}
            ],
            impact_breakdown=self._calculate_impact_breakdown(risk_vector, context),
            mitigation_impact=risk_score - residual_risk,
            residual_risk=residual_risk,
            metadata={
                "sle": sle,
                "aro": aro,
                "ale": ale,
                "asset_value": asset_value,
                "exposure_factor": exposure_factor,
                "calculation_date": datetime.now().isoformat()
            }
        )
    
    def _calculate_semi_quantitative_risk(
        self,
        risk_vector: RiskVector,
        context: Dict[str, Any]
    ) -> RiskCalculationResult:
        """Calculate semi-quantitative risk assessment."""
        # Weighted risk calculation
        risk_components = {
            "impact": risk_vector.impact * 0.35,
            "likelihood": risk_vector.likelihood * 0.25,
            "vulnerability": risk_vector.vulnerability * 0.2,
            "threat": risk_vector.threat * 0.15,
            "asset_value": risk_vector.asset_value * 0.05
        }
        
        # Calculate base risk score
        base_risk = sum(risk_components.values())
        
        # Apply control effectiveness
        control_reduction = risk_vector.control_effectiveness / 100
        adjusted_risk = base_risk * (1 - control_reduction)
        
        # Apply contextual modifiers
        context_multiplier = self._calculate_context_multiplier(context)
        final_risk = min(100, adjusted_risk * context_multiplier)
        
        # Calculate confidence based on data quality
        confidence = self._calculate_confidence_score(risk_vector, context)
        
        return RiskCalculationResult(
            overall_risk_score=final_risk,
            risk_level=self._score_to_risk_level(final_risk),
            risk_category=self._determine_risk_category(context),
            confidence_score=confidence,
            calculation_method=RiskCalculationMethod.SEMI_QUANTITATIVE,
            risk_factors=[
                {"factor": name, "weight": weight/100, "value": value}
                for name, value in risk_components.items()
            ],
            impact_breakdown=self._calculate_impact_breakdown(risk_vector, context),
            mitigation_impact=base_risk - final_risk,
            residual_risk=final_risk,
            metadata={
                "base_risk": base_risk,
                "control_reduction": control_reduction,
                "context_multiplier": context_multiplier,
                "calculation_date": datetime.now().isoformat()
            }
        )
    
    def _calculate_monte_carlo_risk(
        self,
        risk_vector: RiskVector,
        context: Dict[str, Any]
    ) -> RiskCalculationResult:
        """Calculate risk using Monte Carlo simulation."""
        # Number of simulations
        num_simulations = context.get("monte_carlo_iterations", 10000)
        
        # Define probability distributions for each factor
        impact_dist = np.random.normal(risk_vector.impact, 10, num_simulations)
        likelihood_dist = np.random.normal(risk_vector.likelihood, 8, num_simulations)
        vulnerability_dist = np.random.normal(risk_vector.vulnerability, 12, num_simulations)
        threat_dist = np.random.normal(risk_vector.threat, 15, num_simulations)
        
        # Ensure values stay within bounds
        impact_dist = np.clip(impact_dist, 0, 100)
        likelihood_dist = np.clip(likelihood_dist, 0, 100)
        vulnerability_dist = np.clip(vulnerability_dist, 0, 100)
        threat_dist = np.clip(threat_dist, 0, 100)
        
        # Calculate risk for each simulation
        risk_scores = []
        for i in range(num_simulations):
            sim_risk = self._calculate_simulation_risk(
                impact_dist[i],
                likelihood_dist[i],
                vulnerability_dist[i],
                threat_dist[i],
                risk_vector.control_effectiveness
            )
            risk_scores.append(sim_risk)
        
        # Calculate statistics
        mean_risk = np.mean(risk_scores)
        std_risk = np.std(risk_scores)
        percentiles = np.percentile(risk_scores, [5, 25, 50, 75, 95])
        
        # Confidence based on standard deviation
        confidence = max(0.5, 1 - (std_risk / 100))
        
        return RiskCalculationResult(
            overall_risk_score=mean_risk,
            risk_level=self._score_to_risk_level(mean_risk),
            risk_category=self._determine_risk_category(context),
            confidence_score=confidence,
            calculation_method=RiskCalculationMethod.MONTE_CARLO,
            risk_factors=[
                {"factor": "impact", "weight": 0.3, "value": np.mean(impact_dist)},
                {"factor": "likelihood", "weight": 0.25, "value": np.mean(likelihood_dist)},
                {"factor": "vulnerability", "weight": 0.25, "value": np.mean(vulnerability_dist)},
                {"factor": "threat", "weight": 0.2, "value": np.mean(threat_dist)}
            ],
            impact_breakdown=self._calculate_impact_breakdown(risk_vector, context),
            mitigation_impact=0.0,
            residual_risk=mean_risk,
            metadata={
                "num_simulations": num_simulations,
                "mean_risk": mean_risk,
                "std_risk": std_risk,
                "percentiles": {
                    "p5": percentiles[0],
                    "p25": percentiles[1],
                    "p50": percentiles[2],
                    "p75": percentiles[3],
                    "p95": percentiles[4]
                },
                "calculation_date": datetime.now().isoformat()
            }
        )
    
    def _calculate_fuzzy_logic_risk(
        self,
        risk_vector: RiskVector,
        context: Dict[str, Any]
    ) -> RiskCalculationResult:
        """Calculate risk using fuzzy logic."""
        # Define fuzzy membership functions
        impact_fuzzy = self._calculate_fuzzy_membership(risk_vector.impact)
        likelihood_fuzzy = self._calculate_fuzzy_membership(risk_vector.likelihood)
        vulnerability_fuzzy = self._calculate_fuzzy_membership(risk_vector.vulnerability)
        threat_fuzzy = self._calculate_fuzzy_membership(risk_vector.threat)
        
        # Fuzzy rule evaluation
        risk_rules = [
            # High impact + High likelihood = Critical risk
            min(impact_fuzzy["high"], likelihood_fuzzy["high"]) * 95,
            # High impact + Medium likelihood = High risk
            min(impact_fuzzy["high"], likelihood_fuzzy["medium"]) * 80,
            # Medium impact + High likelihood = High risk
            min(impact_fuzzy["medium"], likelihood_fuzzy["high"]) * 75,
            # Medium impact + Medium likelihood = Medium risk
            min(impact_fuzzy["medium"], likelihood_fuzzy["medium"]) * 50,
            # Low impact + High likelihood = Medium risk
            min(impact_fuzzy["low"], likelihood_fuzzy["high"]) * 40,
            # Low impact + Medium likelihood = Low risk
            min(impact_fuzzy["low"], likelihood_fuzzy["medium"]) * 25,
            # Low impact + Low likelihood = Low risk
            min(impact_fuzzy["low"], likelihood_fuzzy["low"]) * 15
        ]
        
        # Aggregate rules using weighted average
        rule_weights = [rule for rule in risk_rules if rule > 0]
        if rule_weights:
            fuzzy_risk = sum(rule_weights) / len(rule_weights)
        else:
            fuzzy_risk = 0
        
        # Apply vulnerability and threat modifiers
        vuln_modifier = 1 + (vulnerability_fuzzy["high"] * 0.2)
        threat_modifier = 1 + (threat_fuzzy["high"] * 0.15)
        
        final_risk = min(100, fuzzy_risk * vuln_modifier * threat_modifier)
        
        return RiskCalculationResult(
            overall_risk_score=final_risk,
            risk_level=self._score_to_risk_level(final_risk),
            risk_category=self._determine_risk_category(context),
            confidence_score=0.8,  # Fuzzy logic has good confidence
            calculation_method=RiskCalculationMethod.FUZZY_LOGIC,
            risk_factors=[
                {"factor": "impact_fuzzy", "weight": 0.35, "value": impact_fuzzy},
                {"factor": "likelihood_fuzzy", "weight": 0.25, "value": likelihood_fuzzy},
                {"factor": "vulnerability_fuzzy", "weight": 0.2, "value": vulnerability_fuzzy},
                {"factor": "threat_fuzzy", "weight": 0.2, "value": threat_fuzzy}
            ],
            impact_breakdown=self._calculate_impact_breakdown(risk_vector, context),
            mitigation_impact=0.0,
            residual_risk=final_risk,
            metadata={
                "fuzzy_risk": fuzzy_risk,
                "vuln_modifier": vuln_modifier,
                "threat_modifier": threat_modifier,
                "active_rules": len(rule_weights),
                "calculation_date": datetime.now().isoformat()
            }
        )
    
    def _quantitative_to_qualitative(self, value: float) -> str:
        """Convert quantitative value to qualitative category."""
        if value >= 80:
            return "very_high"
        elif value >= 60:
            return "high"
        elif value >= 40:
            return "medium"
        elif value >= 20:
            return "low"
        else:
            return "very_low"
    
    def _likelihood_to_aro(self, likelihood: float) -> float:
        """Convert likelihood score to Annualized Rate of Occurrence."""
        # Map likelihood (0-100) to ARO (0-1)
        if likelihood >= 90:
            return 1.0  # Once per year
        elif likelihood >= 70:
            return 0.5  # Once every 2 years
        elif likelihood >= 50:
            return 0.2  # Once every 5 years
        elif likelihood >= 30:
            return 0.1  # Once every 10 years
        elif likelihood >= 10:
            return 0.05  # Once every 20 years
        else:
            return 0.01  # Once every 100 years
    
    def _calculate_simulation_risk(
        self,
        impact: float,
        likelihood: float,
        vulnerability: float,
        threat: float,
        control_effectiveness: float
    ) -> float:
        """Calculate risk for a single simulation."""
        base_risk = (impact * 0.4) + (likelihood * 0.3) + (vulnerability * 0.2) + (threat * 0.1)
        control_reduction = control_effectiveness / 100
        return base_risk * (1 - control_reduction)
    
    def _calculate_fuzzy_membership(self, value: float) -> Dict[str, float]:
        """Calculate fuzzy membership functions."""
        # Triangular membership functions
        low_membership = max(0, min(1, (40 - value) / 40))
        medium_membership = max(0, min((value - 20) / 30, (80 - value) / 30))
        high_membership = max(0, min(1, (value - 60) / 40))
        
        return {
            "low": low_membership,
            "medium": medium_membership,
            "high": high_membership
        }
    
    def _calculate_context_multiplier(self, context: Dict[str, Any]) -> float:
        """Calculate context-based risk multiplier."""
        multiplier = 1.0
        
        # Industry risk factors
        industry = context.get("industry", "").lower()
        if industry in ["finance", "healthcare", "government"]:
            multiplier *= 1.2
        elif industry in ["retail", "education"]:
            multiplier *= 1.1
        
        # Geographic risk factors
        region = context.get("region", "").lower()
        if region in ["high_risk_region"]:
            multiplier *= 1.15
        
        # Regulatory environment
        if context.get("highly_regulated", False):
            multiplier *= 1.1
        
        # Recent incidents
        if context.get("recent_incidents", 0) > 0:
            multiplier *= 1.05 + (context["recent_incidents"] * 0.02)
        
        return min(1.5, multiplier)  # Cap at 1.5x
    
    def _calculate_confidence_score(
        self,
        risk_vector: RiskVector,
        context: Dict[str, Any]
    ) -> float:
        """Calculate confidence score based on data quality."""
        base_confidence = 0.7
        
        # Data completeness
        vector_fields = [
            risk_vector.impact,
            risk_vector.likelihood,
            risk_vector.vulnerability,
            risk_vector.threat,
            risk_vector.asset_value,
            risk_vector.control_effectiveness
        ]
        
        complete_fields = sum(1 for field in vector_fields if field > 0)
        completeness_score = complete_fields / len(vector_fields)
        
        # Data freshness
        data_age = context.get("data_age_days", 0)
        freshness_score = max(0.5, 1 - (data_age / 365))
        
        # Source reliability
        source_reliability = context.get("source_reliability", 0.8)
        
        confidence = base_confidence * completeness_score * freshness_score * source_reliability
        
        return min(1.0, confidence)
    
    def _calculate_impact_breakdown(
        self,
        risk_vector: RiskVector,
        context: Dict[str, Any]
    ) -> Dict[str, float]:
        """Calculate detailed impact breakdown."""
        base_impact = risk_vector.impact
        
        return {
            "financial": base_impact * self.impact_weights["financial"],
            "operational": base_impact * self.impact_weights["operational"],
            "reputational": base_impact * self.impact_weights["reputational"],
            "compliance": base_impact * self.impact_weights["compliance"],
            "technical": base_impact * self.impact_weights["technical"]
        }
    
    def _score_to_risk_level(self, score: float) -> RiskLevel:
        """Convert risk score to risk level."""
        if score >= self.risk_thresholds[RiskLevel.CRITICAL]:
            return RiskLevel.CRITICAL
        elif score >= self.risk_thresholds[RiskLevel.HIGH]:
            return RiskLevel.HIGH
        elif score >= self.risk_thresholds[RiskLevel.MEDIUM]:
            return RiskLevel.MEDIUM
        elif score >= self.risk_thresholds[RiskLevel.LOW]:
            return RiskLevel.LOW
        else:
            return RiskLevel.INFORMATIONAL
    
    def _determine_risk_category(self, context: Dict[str, Any]) -> RiskCategory:
        """Determine risk category based on context."""
        # This is a simplified implementation
        # In practice, this would use more sophisticated categorization logic
        
        event_type = context.get("event_type", "").lower()
        
        if any(keyword in event_type for keyword in ["auth", "login", "access"]):
            return RiskCategory.SECURITY
        elif any(keyword in event_type for keyword in ["compliance", "audit", "policy"]):
            return RiskCategory.COMPLIANCE
        elif any(keyword in event_type for keyword in ["system", "service", "infrastructure"]):
            return RiskCategory.OPERATIONAL
        elif any(keyword in event_type for keyword in ["data", "privacy", "breach"]):
            return RiskCategory.REPUTATIONAL
        else:
            return RiskCategory.TECHNICAL
    
    def calculate_risk_trend(
        self,
        historical_scores: List[Tuple[datetime, float]],
        window_days: int = 30
    ) -> Dict[str, Any]:
        """Calculate risk trend analysis."""
        if len(historical_scores) < 2:
            return {"trend": "stable", "confidence": 0.0}
        
        # Filter recent data
        cutoff_date = datetime.now() - timedelta(days=window_days)
        recent_scores = [
            (date, score) for date, score in historical_scores
            if date >= cutoff_date
        ]
        
        if len(recent_scores) < 2:
            return {"trend": "stable", "confidence": 0.0}
        
        # Calculate trend using linear regression
        dates = [(date - recent_scores[0][0]).total_seconds() for date, _ in recent_scores]
        scores = [score for _, score in recent_scores]
        
        slope, intercept, r_value, p_value, std_err = stats.linregress(dates, scores)
        
        # Determine trend
        if slope > 1:
            trend = "increasing"
        elif slope < -1:
            trend = "decreasing"
        else:
            trend = "stable"
        
        return {
            "trend": trend,
            "slope": slope,
            "confidence": abs(r_value),
            "p_value": p_value,
            "std_error": std_err,
            "recent_scores": len(recent_scores),
            "analysis_window": window_days
        }
    
    def get_risk_metrics(self) -> Dict[str, Any]:
        """Get risk calculator metrics."""
        return {
            "calculation_methods": [method.value for method in RiskCalculationMethod],
            "risk_levels": [level.value for level in RiskLevel],
            "risk_categories": [category.value for category in RiskCategory],
            "impact_weights": self.impact_weights,
            "likelihood_factors": self.likelihood_factors,
            "risk_thresholds": {level.value: threshold for level, threshold in self.risk_thresholds.items()}
        }