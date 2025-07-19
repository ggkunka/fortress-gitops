"""
LLM Client - Integration with Large Language Models for Risk Assessment

This service provides integration with various LLM providers for
enhanced risk assessment capabilities.
"""

import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass
from enum import Enum
from abc import ABC, abstractmethod

import openai
import httpx
from pydantic import BaseModel, Field

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.config.settings import get_settings

logger = get_logger(__name__)
metrics = get_metrics()


class LLMProvider(str, Enum):
    """LLM providers."""
    OPENAI = "openai"
    ANTHROPIC = "anthropic"
    AZURE_OPENAI = "azure_openai"
    HUGGINGFACE = "huggingface"
    LOCAL = "local"


@dataclass
class LLMResponse:
    """LLM response model."""
    content: str
    confidence: float
    reasoning: str
    metadata: Dict[str, Any]
    provider: LLMProvider
    model: str
    usage: Dict[str, Any]
    response_time: float


class RiskAssessmentPrompt(BaseModel):
    """Risk assessment prompt model."""
    correlation_data: Dict[str, Any] = Field(..., description="Correlation result data")
    context_data: Dict[str, Any] = Field(default_factory=dict, description="Additional context")
    assessment_type: str = Field(..., description="Type of assessment requested")
    risk_framework: str = Field(default="nist", description="Risk framework to use")
    organization_profile: Dict[str, Any] = Field(default_factory=dict, description="Organization profile")


class LLMClient(ABC):
    """Abstract base class for LLM clients."""
    
    @abstractmethod
    async def assess_risk(self, prompt: RiskAssessmentPrompt) -> LLMResponse:
        """Assess risk using LLM."""
        pass
    
    @abstractmethod
    async def generate_recommendations(self, assessment_data: Dict[str, Any]) -> LLMResponse:
        """Generate risk mitigation recommendations."""
        pass
    
    @abstractmethod
    async def analyze_threat_intelligence(self, threat_data: Dict[str, Any]) -> LLMResponse:
        """Analyze threat intelligence data."""
        pass


class OpenAIClient(LLMClient):
    """OpenAI client for risk assessment."""
    
    def __init__(self, api_key: str, model: str = "gpt-4"):
        self.client = openai.AsyncOpenAI(api_key=api_key)
        self.model = model
        self.provider = LLMProvider.OPENAI
        logger.info(f"OpenAI client initialized with model {model}")
    
    @traced("llm_client_assess_risk")
    async def assess_risk(self, prompt: RiskAssessmentPrompt) -> LLMResponse:
        """Assess risk using OpenAI."""
        start_time = time.time()
        
        try:
            system_prompt = self._build_risk_assessment_system_prompt(prompt.risk_framework)
            user_prompt = self._build_risk_assessment_user_prompt(prompt)
            
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.3,
                max_tokens=2000,
                response_format={"type": "json_object"}
            )
            
            response_time = time.time() - start_time
            
            # Parse response
            content = response.choices[0].message.content
            parsed_response = json.loads(content)
            
            llm_response = LLMResponse(
                content=content,
                confidence=parsed_response.get("confidence", 0.0),
                reasoning=parsed_response.get("reasoning", ""),
                metadata=parsed_response.get("metadata", {}),
                provider=self.provider,
                model=self.model,
                usage=response.usage.model_dump() if response.usage else {},
                response_time=response_time
            )
            
            metrics.llm_client_requests.inc()
            metrics.llm_client_response_time.observe(response_time)
            
            return llm_response
            
        except Exception as e:
            logger.error(f"Error in OpenAI risk assessment: {e}")
            metrics.llm_client_errors.inc()
            raise
    
    @traced("llm_client_generate_recommendations")
    async def generate_recommendations(self, assessment_data: Dict[str, Any]) -> LLMResponse:
        """Generate risk mitigation recommendations."""
        start_time = time.time()
        
        try:
            system_prompt = self._build_recommendations_system_prompt()
            user_prompt = self._build_recommendations_user_prompt(assessment_data)
            
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.4,
                max_tokens=1500,
                response_format={"type": "json_object"}
            )
            
            response_time = time.time() - start_time
            
            content = response.choices[0].message.content
            parsed_response = json.loads(content)
            
            llm_response = LLMResponse(
                content=content,
                confidence=parsed_response.get("confidence", 0.0),
                reasoning=parsed_response.get("reasoning", ""),
                metadata=parsed_response.get("metadata", {}),
                provider=self.provider,
                model=self.model,
                usage=response.usage.model_dump() if response.usage else {},
                response_time=response_time
            )
            
            metrics.llm_client_requests.inc()
            metrics.llm_client_response_time.observe(response_time)
            
            return llm_response
            
        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            metrics.llm_client_errors.inc()
            raise
    
    @traced("llm_client_analyze_threat_intelligence")
    async def analyze_threat_intelligence(self, threat_data: Dict[str, Any]) -> LLMResponse:
        """Analyze threat intelligence data."""
        start_time = time.time()
        
        try:
            system_prompt = self._build_threat_analysis_system_prompt()
            user_prompt = self._build_threat_analysis_user_prompt(threat_data)
            
            response = await self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=0.2,
                max_tokens=1500,
                response_format={"type": "json_object"}
            )
            
            response_time = time.time() - start_time
            
            content = response.choices[0].message.content
            parsed_response = json.loads(content)
            
            llm_response = LLMResponse(
                content=content,
                confidence=parsed_response.get("confidence", 0.0),
                reasoning=parsed_response.get("reasoning", ""),
                metadata=parsed_response.get("metadata", {}),
                provider=self.provider,
                model=self.model,
                usage=response.usage.model_dump() if response.usage else {},
                response_time=response_time
            )
            
            metrics.llm_client_requests.inc()
            metrics.llm_client_response_time.observe(response_time)
            
            return llm_response
            
        except Exception as e:
            logger.error(f"Error analyzing threat intelligence: {e}")
            metrics.llm_client_errors.inc()
            raise
    
    def _build_risk_assessment_system_prompt(self, framework: str) -> str:
        """Build system prompt for risk assessment."""
        return f"""You are a cybersecurity risk assessment expert specializing in the {framework.upper()} framework.

Your task is to analyze security correlation results and provide comprehensive risk assessments.

Key responsibilities:
1. Analyze security events and correlation patterns
2. Assess threat severity and likelihood
3. Evaluate business impact
4. Provide risk scores and classifications
5. Consider organizational context and threat landscape

Response format (JSON):
{{
    "risk_level": "critical|high|medium|low|informational",
    "risk_score": 0-100,
    "confidence": 0.0-1.0,
    "impact_score": 0-100,
    "likelihood_score": 0-100,
    "risk_category": "security|compliance|operational|financial|reputational",
    "risk_factors": [
        {{
            "factor": "factor_name",
            "weight": 0.0-1.0,
            "description": "factor_description"
        }}
    ],
    "business_impact": {{
        "financial": 0-100,
        "operational": 0-100,
        "reputational": 0-100,
        "compliance": 0-100
    }},
    "reasoning": "detailed_reasoning",
    "metadata": {{
        "framework": "{framework}",
        "assessment_date": "ISO_timestamp",
        "key_indicators": ["indicator1", "indicator2"]
    }}
}}

Use evidence-based analysis and provide clear reasoning for all assessments."""
    
    def _build_risk_assessment_user_prompt(self, prompt: RiskAssessmentPrompt) -> str:
        """Build user prompt for risk assessment."""
        return f"""Please assess the risk for the following security correlation:

CORRELATION DATA:
{json.dumps(prompt.correlation_data, indent=2)}

CONTEXT DATA:
{json.dumps(prompt.context_data, indent=2)}

ASSESSMENT TYPE: {prompt.assessment_type}

ORGANIZATION PROFILE:
{json.dumps(prompt.organization_profile, indent=2)}

Please provide a comprehensive risk assessment including:
1. Overall risk level and score
2. Impact and likelihood analysis
3. Key risk factors
4. Business impact assessment
5. Detailed reasoning

Focus on actionable insights and evidence-based analysis."""
    
    def _build_recommendations_system_prompt(self) -> str:
        """Build system prompt for recommendations."""
        return """You are a cybersecurity expert specializing in risk mitigation and incident response.

Your task is to generate actionable recommendations for risk mitigation based on security risk assessments.

Key responsibilities:
1. Analyze risk assessment results
2. Generate specific, actionable recommendations
3. Prioritize recommendations by impact and feasibility
4. Consider implementation costs and timelines
5. Provide both immediate and long-term solutions

Response format (JSON):
{
    "recommendations": [
        {
            "title": "recommendation_title",
            "description": "detailed_description",
            "type": "preventive|detective|corrective|recovery",
            "priority": 1-10,
            "implementation_cost": "low|medium|high",
            "implementation_time": "immediate|short|medium|long",
            "effectiveness": 0-100,
            "categories": ["category1", "category2"]
        }
    ],
    "immediate_actions": [
        {
            "action": "action_description",
            "urgency": "critical|high|medium|low",
            "owner": "suggested_owner"
        }
    ],
    "long_term_strategy": {
        "objectives": ["objective1", "objective2"],
        "timeline": "timeline_description",
        "resources_needed": ["resource1", "resource2"]
    },
    "confidence": 0.0-1.0,
    "reasoning": "detailed_reasoning",
    "metadata": {
        "recommendation_date": "ISO_timestamp",
        "total_recommendations": 0,
        "critical_actions": 0
    }
}

Focus on practical, implementable solutions with clear business value."""
    
    def _build_recommendations_user_prompt(self, assessment_data: Dict[str, Any]) -> str:
        """Build user prompt for recommendations."""
        return f"""Please generate risk mitigation recommendations for the following risk assessment:

RISK ASSESSMENT DATA:
{json.dumps(assessment_data, indent=2)}

Please provide:
1. Prioritized list of recommendations
2. Immediate actions required
3. Long-term strategic recommendations
4. Implementation guidance
5. Resource requirements

Focus on practical, cost-effective solutions that address the root causes of risk."""
    
    def _build_threat_analysis_system_prompt(self) -> str:
        """Build system prompt for threat analysis."""
        return """You are a threat intelligence analyst specializing in cybersecurity threat assessment.

Your task is to analyze threat intelligence data and provide actionable insights.

Key responsibilities:
1. Analyze threat indicators and patterns
2. Assess threat actor capabilities and motivations
3. Evaluate threat relevance to the organization
4. Provide threat context and attribution
5. Generate threat-specific recommendations

Response format (JSON):
{
    "threat_level": "critical|high|medium|low",
    "threat_score": 0-100,
    "relevance_score": 0-100,
    "threat_actors": [
        {
            "name": "actor_name",
            "type": "nation_state|cybercriminal|insider|hacktivist",
            "capability": "advanced|intermediate|basic",
            "motivation": "financial|political|espionage|disruption"
        }
    ],
    "attack_vectors": [
        {
            "vector": "vector_name",
            "likelihood": 0-100,
            "impact": 0-100
        }
    ],
    "indicators": {
        "iocs": ["ioc1", "ioc2"],
        "ttps": ["ttp1", "ttp2"],
        "signatures": ["sig1", "sig2"]
    },
    "context": {
        "campaign": "campaign_name",
        "timeline": "timeline_description",
        "targets": ["target_type1", "target_type2"]
    },
    "confidence": 0.0-1.0,
    "reasoning": "detailed_reasoning",
    "metadata": {
        "analysis_date": "ISO_timestamp",
        "sources": ["source1", "source2"],
        "quality_score": 0-100
    }
}

Provide evidence-based analysis with clear threat attribution when possible."""
    
    def _build_threat_analysis_user_prompt(self, threat_data: Dict[str, Any]) -> str:
        """Build user prompt for threat analysis."""
        return f"""Please analyze the following threat intelligence data:

THREAT DATA:
{json.dumps(threat_data, indent=2)}

Please provide:
1. Threat level assessment
2. Threat actor analysis
3. Attack vector evaluation
4. Indicator extraction
5. Contextual analysis
6. Relevance assessment

Focus on actionable intelligence that can inform defensive strategies."""


class AnthropicClient(LLMClient):
    """Anthropic (Claude) client for risk assessment."""
    
    def __init__(self, api_key: str, model: str = "claude-3-sonnet-20240229"):
        self.api_key = api_key
        self.model = model
        self.provider = LLMProvider.ANTHROPIC
        self.base_url = "https://api.anthropic.com"
        logger.info(f"Anthropic client initialized with model {model}")
    
    async def assess_risk(self, prompt: RiskAssessmentPrompt) -> LLMResponse:
        """Assess risk using Anthropic Claude."""
        start_time = time.time()
        
        try:
            system_prompt = self._build_risk_assessment_system_prompt(prompt.risk_framework)
            user_prompt = self._build_risk_assessment_user_prompt(prompt)
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self.base_url}/v1/messages",
                    headers={
                        "Content-Type": "application/json",
                        "x-api-key": self.api_key,
                        "anthropic-version": "2023-06-01"
                    },
                    json={
                        "model": self.model,
                        "max_tokens": 2000,
                        "temperature": 0.3,
                        "system": system_prompt,
                        "messages": [
                            {"role": "user", "content": user_prompt}
                        ]
                    }
                )
                
                response.raise_for_status()
                data = response.json()
                
                response_time = time.time() - start_time
                
                content = data["content"][0]["text"]
                parsed_response = json.loads(content)
                
                llm_response = LLMResponse(
                    content=content,
                    confidence=parsed_response.get("confidence", 0.0),
                    reasoning=parsed_response.get("reasoning", ""),
                    metadata=parsed_response.get("metadata", {}),
                    provider=self.provider,
                    model=self.model,
                    usage=data.get("usage", {}),
                    response_time=response_time
                )
                
                metrics.llm_client_requests.inc()
                metrics.llm_client_response_time.observe(response_time)
                
                return llm_response
                
        except Exception as e:
            logger.error(f"Error in Anthropic risk assessment: {e}")
            metrics.llm_client_errors.inc()
            raise
    
    async def generate_recommendations(self, assessment_data: Dict[str, Any]) -> LLMResponse:
        """Generate recommendations using Anthropic Claude."""
        # Implementation similar to assess_risk but with recommendations prompts
        # ... (implementation details)
        pass
    
    async def analyze_threat_intelligence(self, threat_data: Dict[str, Any]) -> LLMResponse:
        """Analyze threat intelligence using Anthropic Claude."""
        # Implementation similar to assess_risk but with threat analysis prompts
        # ... (implementation details)
        pass


class LLMClientFactory:
    """Factory for creating LLM clients."""
    
    @staticmethod
    def create_client(provider: LLMProvider, **kwargs) -> LLMClient:
        """Create LLM client based on provider."""
        if provider == LLMProvider.OPENAI:
            return OpenAIClient(**kwargs)
        elif provider == LLMProvider.ANTHROPIC:
            return AnthropicClient(**kwargs)
        else:
            raise ValueError(f"Unsupported LLM provider: {provider}")


class LLMManager:
    """Manager for LLM operations with fallback and load balancing."""
    
    def __init__(self):
        self.clients: Dict[LLMProvider, LLMClient] = {}
        self.primary_provider = None
        self.fallback_providers = []
        
        # Initialize clients from configuration
        self._initialize_clients()
        
        logger.info("LLM manager initialized")
    
    def _initialize_clients(self):
        """Initialize LLM clients from configuration."""
        settings = get_settings()
        
        # OpenAI client
        if hasattr(settings, 'openai_api_key') and settings.openai_api_key:
            self.clients[LLMProvider.OPENAI] = OpenAIClient(
                api_key=settings.openai_api_key,
                model=getattr(settings, 'openai_model', 'gpt-4')
            )
            if not self.primary_provider:
                self.primary_provider = LLMProvider.OPENAI
        
        # Anthropic client
        if hasattr(settings, 'anthropic_api_key') and settings.anthropic_api_key:
            self.clients[LLMProvider.ANTHROPIC] = AnthropicClient(
                api_key=settings.anthropic_api_key,
                model=getattr(settings, 'anthropic_model', 'claude-3-sonnet-20240229')
            )
            if not self.primary_provider:
                self.primary_provider = LLMProvider.ANTHROPIC
        
        # Set fallback providers
        self.fallback_providers = [
            provider for provider in self.clients.keys()
            if provider != self.primary_provider
        ]
    
    @traced("llm_manager_assess_risk")
    async def assess_risk(self, prompt: RiskAssessmentPrompt) -> LLMResponse:
        """Assess risk with fallback support."""
        providers_to_try = [self.primary_provider] + self.fallback_providers
        
        for provider in providers_to_try:
            if provider in self.clients:
                try:
                    return await self.clients[provider].assess_risk(prompt)
                except Exception as e:
                    logger.warning(f"Error with {provider}: {e}")
                    continue
        
        raise Exception("All LLM providers failed")
    
    @traced("llm_manager_generate_recommendations")
    async def generate_recommendations(self, assessment_data: Dict[str, Any]) -> LLMResponse:
        """Generate recommendations with fallback support."""
        providers_to_try = [self.primary_provider] + self.fallback_providers
        
        for provider in providers_to_try:
            if provider in self.clients:
                try:
                    return await self.clients[provider].generate_recommendations(assessment_data)
                except Exception as e:
                    logger.warning(f"Error with {provider}: {e}")
                    continue
        
        raise Exception("All LLM providers failed")
    
    @traced("llm_manager_analyze_threat_intelligence")
    async def analyze_threat_intelligence(self, threat_data: Dict[str, Any]) -> LLMResponse:
        """Analyze threat intelligence with fallback support."""
        providers_to_try = [self.primary_provider] + self.fallback_providers
        
        for provider in providers_to_try:
            if provider in self.clients:
                try:
                    return await self.clients[provider].analyze_threat_intelligence(threat_data)
                except Exception as e:
                    logger.warning(f"Error with {provider}: {e}")
                    continue
        
        raise Exception("All LLM providers failed")
    
    def get_available_providers(self) -> List[LLMProvider]:
        """Get list of available providers."""
        return list(self.clients.keys())
    
    def get_client_stats(self) -> Dict[str, Any]:
        """Get statistics for all clients."""
        return {
            "primary_provider": self.primary_provider,
            "available_providers": self.get_available_providers(),
            "fallback_providers": self.fallback_providers,
            "total_clients": len(self.clients)
        }