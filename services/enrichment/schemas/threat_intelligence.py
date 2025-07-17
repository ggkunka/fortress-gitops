"""Threat intelligence schemas."""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from enum import Enum

from pydantic import BaseModel, Field, validator


class ThreatLevel(str, Enum):
    """Threat level enumeration."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    UNKNOWN = "unknown"


class IndicatorType(str, Enum):
    """Indicator of Compromise (IoC) type enumeration."""
    DOMAIN = "domain"
    IP_ADDRESS = "ip_address"
    URL = "url"
    FILE_HASH = "file_hash"
    EMAIL = "email"
    REGISTRY_KEY = "registry_key"
    MUTEX = "mutex"
    USER_AGENT = "user_agent"
    CERTIFICATE = "certificate"
    PROCESS = "process"
    COMMAND_LINE = "command_line"
    NETWORK_TRAFFIC = "network_traffic"


class MalwareFamily(str, Enum):
    """Malware family enumeration."""
    TROJAN = "trojan"
    RANSOMWARE = "ransomware"
    SPYWARE = "spyware"
    ADWARE = "adware"
    ROOTKIT = "rootkit"
    KEYLOGGER = "keylogger"
    BACKDOOR = "backdoor"
    BOTNET = "botnet"
    WORM = "worm"
    VIRUS = "virus"
    EXPLOIT_KIT = "exploit_kit"
    REMOTE_ACCESS_TOOL = "remote_access_tool"
    CRYPTOMINER = "cryptominer"
    UNKNOWN = "unknown"


class ThreatActorType(str, Enum):
    """Threat actor type enumeration."""
    NATION_STATE = "nation_state"
    CYBERCRIMINAL = "cybercriminal"
    HACKTIVIST = "hacktivist"
    INSIDER = "insider"
    SCRIPT_KIDDIE = "script_kiddie"
    UNKNOWN = "unknown"


class IoC(BaseModel):
    """Indicator of Compromise schema."""
    
    indicator_id: str = Field(..., description="Unique indicator identifier")
    indicator_type: IndicatorType = Field(..., description="Type of indicator")
    value: str = Field(..., description="Indicator value")
    threat_level: ThreatLevel = Field(..., description="Threat level")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score")
    first_seen: datetime = Field(..., description="First seen timestamp")
    last_seen: datetime = Field(..., description="Last seen timestamp")
    sources: List[str] = Field(default_factory=list, description="Intelligence sources")
    tags: List[str] = Field(default_factory=list, description="Associated tags")
    malware_families: List[MalwareFamily] = Field(
        default_factory=list,
        description="Associated malware families"
    )
    threat_actors: List[str] = Field(
        default_factory=list,
        description="Associated threat actors"
    )
    campaigns: List[str] = Field(
        default_factory=list,
        description="Associated campaigns"
    )
    kill_chain_phases: List[str] = Field(
        default_factory=list,
        description="Kill chain phases"
    )
    ttps: List[str] = Field(
        default_factory=list,
        description="Tactics, Techniques, and Procedures"
    )
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context"
    )
    
    @validator('last_seen')
    def validate_last_seen(cls, v, values):
        """Validate last seen timestamp."""
        if 'first_seen' in values and v < values['first_seen']:
            raise ValueError('Last seen must be after first seen')
        return v
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "indicator_id": "ioc_123",
                "indicator_type": "domain",
                "value": "malicious.example.com",
                "threat_level": "high",
                "confidence": 0.85,
                "first_seen": "2023-01-01T10:00:00Z",
                "last_seen": "2023-01-01T12:00:00Z",
                "sources": ["misp", "virustotal"],
                "tags": ["malware", "c2"],
                "malware_families": ["trojan"],
                "threat_actors": ["apt28"],
                "campaigns": ["operation_example"],
                "kill_chain_phases": ["command_and_control"],
                "ttps": ["T1071", "T1043"]
            }
        }


class ThreatActor(BaseModel):
    """Threat actor schema."""
    
    actor_id: str = Field(..., description="Unique actor identifier")
    name: str = Field(..., description="Actor name")
    aliases: List[str] = Field(default_factory=list, description="Known aliases")
    actor_type: ThreatActorType = Field(..., description="Type of threat actor")
    sophistication: str = Field(..., description="Sophistication level")
    motivation: List[str] = Field(default_factory=list, description="Motivations")
    countries: List[str] = Field(default_factory=list, description="Associated countries")
    first_seen: datetime = Field(..., description="First seen timestamp")
    last_seen: datetime = Field(..., description="Last seen timestamp")
    active: bool = Field(default=True, description="Whether actor is currently active")
    targets: List[str] = Field(default_factory=list, description="Target sectors/regions")
    tools: List[str] = Field(default_factory=list, description="Known tools")
    malware: List[str] = Field(default_factory=list, description="Associated malware")
    campaigns: List[str] = Field(default_factory=list, description="Associated campaigns")
    ttps: List[str] = Field(default_factory=list, description="Tactics, Techniques, and Procedures")
    sources: List[str] = Field(default_factory=list, description="Intelligence sources")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score")
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "actor_id": "actor_123",
                "name": "APT28",
                "aliases": ["Fancy Bear", "Sofacy"],
                "actor_type": "nation_state",
                "sophistication": "high",
                "motivation": ["espionage", "political"],
                "countries": ["RU"],
                "first_seen": "2008-01-01T00:00:00Z",
                "last_seen": "2023-01-01T12:00:00Z",
                "active": True,
                "targets": ["government", "military"],
                "tools": ["X-Agent", "Zebrocy"],
                "malware": ["sofacy_malware"],
                "campaigns": ["operation_pawn_storm"],
                "ttps": ["T1566", "T1193"],
                "sources": ["crowdstrike", "fireeye"],
                "confidence": 0.95
            }
        }


class Malware(BaseModel):
    """Malware schema."""
    
    malware_id: str = Field(..., description="Unique malware identifier")
    name: str = Field(..., description="Malware name")
    aliases: List[str] = Field(default_factory=list, description="Known aliases")
    family: MalwareFamily = Field(..., description="Malware family")
    first_seen: datetime = Field(..., description="First seen timestamp")
    last_seen: datetime = Field(..., description="Last seen timestamp")
    active: bool = Field(default=True, description="Whether malware is currently active")
    platforms: List[str] = Field(default_factory=list, description="Target platforms")
    capabilities: List[str] = Field(default_factory=list, description="Malware capabilities")
    file_hashes: List[str] = Field(default_factory=list, description="Associated file hashes")
    c2_servers: List[str] = Field(default_factory=list, description="Command and control servers")
    threat_actors: List[str] = Field(
        default_factory=list,
        description="Associated threat actors"
    )
    campaigns: List[str] = Field(default_factory=list, description="Associated campaigns")
    ttps: List[str] = Field(default_factory=list, description="Tactics, Techniques, and Procedures")
    yara_rules: List[str] = Field(default_factory=list, description="YARA rules")
    sources: List[str] = Field(default_factory=list, description="Intelligence sources")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score")
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "malware_id": "malware_123",
                "name": "Emotet",
                "aliases": ["Heodo", "Geodo"],
                "family": "trojan",
                "first_seen": "2014-01-01T00:00:00Z",
                "last_seen": "2023-01-01T12:00:00Z",
                "active": False,
                "platforms": ["Windows"],
                "capabilities": ["credential_theft", "lateral_movement"],
                "file_hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
                "c2_servers": ["c2.example.com"],
                "threat_actors": ["ta505"],
                "campaigns": ["emotet_campaign_2023"],
                "ttps": ["T1566", "T1204"],
                "yara_rules": ["emotet_detection"],
                "sources": ["misp", "virustotal"],
                "confidence": 0.90
            }
        }


class Campaign(BaseModel):
    """Campaign schema."""
    
    campaign_id: str = Field(..., description="Unique campaign identifier")
    name: str = Field(..., description="Campaign name")
    aliases: List[str] = Field(default_factory=list, description="Known aliases")
    first_seen: datetime = Field(..., description="First seen timestamp")
    last_seen: datetime = Field(..., description="Last seen timestamp")
    active: bool = Field(default=True, description="Whether campaign is currently active")
    objectives: List[str] = Field(default_factory=list, description="Campaign objectives")
    targets: List[str] = Field(default_factory=list, description="Target sectors/regions")
    threat_actors: List[str] = Field(
        default_factory=list,
        description="Associated threat actors"
    )
    malware: List[str] = Field(default_factory=list, description="Associated malware")
    tools: List[str] = Field(default_factory=list, description="Tools used")
    ttps: List[str] = Field(default_factory=list, description="Tactics, Techniques, and Procedures")
    indicators: List[str] = Field(default_factory=list, description="Associated indicators")
    sources: List[str] = Field(default_factory=list, description="Intelligence sources")
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score")
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "campaign_id": "campaign_123",
                "name": "Operation Pawn Storm",
                "aliases": ["APT28 Campaign"],
                "first_seen": "2020-01-01T00:00:00Z",
                "last_seen": "2023-01-01T12:00:00Z",
                "active": True,
                "objectives": ["espionage", "intelligence_gathering"],
                "targets": ["government", "military"],
                "threat_actors": ["apt28"],
                "malware": ["x_agent", "zebrocy"],
                "tools": ["powershell", "cobalt_strike"],
                "ttps": ["T1566", "T1193"],
                "indicators": ["ioc_123", "ioc_456"],
                "sources": ["crowdstrike", "fireeye"],
                "confidence": 0.90
            }
        }


class ThreatIntelligence(BaseModel):
    """Comprehensive threat intelligence schema."""
    
    intelligence_id: str = Field(..., description="Unique intelligence identifier")
    data_type: str = Field(..., description="Type of data being enriched")
    enrichment_timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="Enrichment timestamp"
    )
    threat_level: ThreatLevel = Field(..., description="Overall threat level")
    confidence: float = Field(ge=0.0, le=1.0, description="Overall confidence score")
    sources: List[str] = Field(default_factory=list, description="Intelligence sources")
    
    # IoCs
    indicators: List[IoC] = Field(default_factory=list, description="Indicators of compromise")
    
    # Threat actors
    threat_actors: List[ThreatActor] = Field(
        default_factory=list,
        description="Associated threat actors"
    )
    
    # Malware
    malware: List[Malware] = Field(default_factory=list, description="Associated malware")
    
    # Campaigns
    campaigns: List[Campaign] = Field(default_factory=list, description="Associated campaigns")
    
    # Kill chain mapping
    kill_chain_phases: List[str] = Field(
        default_factory=list,
        description="Kill chain phases"
    )
    
    # TTPs
    ttps: List[str] = Field(default_factory=list, description="Tactics, Techniques, and Procedures")
    
    # Contextual information
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context")
    
    # Recommendations
    recommendations: List[str] = Field(
        default_factory=list,
        description="Security recommendations"
    )
    
    # Risk assessment
    risk_score: float = Field(ge=0.0, le=10.0, description="Risk score (0-10)")
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "intelligence_id": "ti_123",
                "data_type": "sbom",
                "enrichment_timestamp": "2023-01-01T12:00:00Z",
                "threat_level": "high",
                "confidence": 0.85,
                "sources": ["misp", "virustotal", "otx"],
                "indicators": [
                    {
                        "indicator_id": "ioc_123",
                        "indicator_type": "domain",
                        "value": "malicious.example.com",
                        "threat_level": "high",
                        "confidence": 0.85
                    }
                ],
                "threat_actors": [
                    {
                        "actor_id": "actor_123",
                        "name": "APT28",
                        "actor_type": "nation_state",
                        "sophistication": "high"
                    }
                ],
                "malware": [
                    {
                        "malware_id": "malware_123",
                        "name": "Emotet",
                        "family": "trojan"
                    }
                ],
                "campaigns": [
                    {
                        "campaign_id": "campaign_123",
                        "name": "Operation Pawn Storm"
                    }
                ],
                "kill_chain_phases": ["delivery", "exploitation"],
                "ttps": ["T1566", "T1193"],
                "context": {
                    "geographic_focus": ["US", "EU"],
                    "industry_focus": ["government", "financial"]
                },
                "recommendations": [
                    "Block malicious domains",
                    "Update security controls",
                    "Monitor for indicators"
                ],
                "risk_score": 8.5
            }
        }