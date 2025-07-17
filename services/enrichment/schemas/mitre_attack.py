"""MITRE ATT&CK mapping schemas."""

from datetime import datetime
from typing import Any, Dict, List, Optional, Union
from enum import Enum

from pydantic import BaseModel, Field, validator


class TacticType(str, Enum):
    """MITRE ATT&CK tactic enumeration."""
    INITIAL_ACCESS = "initial_access"
    EXECUTION = "execution"
    PERSISTENCE = "persistence"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DEFENSE_EVASION = "defense_evasion"
    CREDENTIAL_ACCESS = "credential_access"
    DISCOVERY = "discovery"
    LATERAL_MOVEMENT = "lateral_movement"
    COLLECTION = "collection"
    COMMAND_AND_CONTROL = "command_and_control"
    EXFILTRATION = "exfiltration"
    IMPACT = "impact"
    RECONNAISSANCE = "reconnaissance"
    RESOURCE_DEVELOPMENT = "resource_development"


class PlatformType(str, Enum):
    """Platform type enumeration."""
    WINDOWS = "windows"
    LINUX = "linux"
    MACOS = "macos"
    ANDROID = "android"
    IOS = "ios"
    NETWORK = "network"
    CONTAINERS = "containers"
    CLOUD = "cloud"
    SAAS = "saas"
    IAAS = "iaas"
    OFFICE_365 = "office_365"
    AZURE_AD = "azure_ad"
    GOOGLE_WORKSPACE = "google_workspace"


class DetectionLevel(str, Enum):
    """Detection level enumeration."""
    NONE = "none"
    MINIMAL = "minimal"
    PARTIAL = "partial"
    MODERATE = "moderate"
    SIGNIFICANT = "significant"
    HIGH = "high"


class MitigationLevel(str, Enum):
    """Mitigation level enumeration."""
    NONE = "none"
    MINIMAL = "minimal"
    PARTIAL = "partial"
    MODERATE = "moderate"
    SIGNIFICANT = "significant"
    HIGH = "high"


class Tactic(BaseModel):
    """MITRE ATT&CK tactic schema."""
    
    tactic_id: str = Field(..., description="MITRE ATT&CK tactic ID")
    name: str = Field(..., description="Tactic name")
    description: str = Field(..., description="Tactic description")
    short_name: str = Field(..., description="Short name")
    external_references: List[str] = Field(
        default_factory=list,
        description="External references"
    )
    techniques: List[str] = Field(
        default_factory=list,
        description="Associated technique IDs"
    )
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "tactic_id": "TA0001",
                "name": "Initial Access",
                "description": "The adversary is trying to get into your network.",
                "short_name": "initial-access",
                "external_references": [
                    "https://attack.mitre.org/tactics/TA0001/"
                ],
                "techniques": ["T1566", "T1190", "T1133"]
            }
        }


class Technique(BaseModel):
    """MITRE ATT&CK technique schema."""
    
    technique_id: str = Field(..., description="MITRE ATT&CK technique ID")
    name: str = Field(..., description="Technique name")
    description: str = Field(..., description="Technique description")
    tactics: List[TacticType] = Field(
        default_factory=list,
        description="Associated tactics"
    )
    platforms: List[PlatformType] = Field(
        default_factory=list,
        description="Applicable platforms"
    )
    data_sources: List[str] = Field(
        default_factory=list,
        description="Data sources for detection"
    )
    detection_level: DetectionLevel = Field(
        default=DetectionLevel.MODERATE,
        description="Detection difficulty level"
    )
    mitigation_level: MitigationLevel = Field(
        default=MitigationLevel.MODERATE,
        description="Mitigation effectiveness level"
    )
    sub_techniques: List[str] = Field(
        default_factory=list,
        description="Sub-technique IDs"
    )
    mitigations: List[str] = Field(
        default_factory=list,
        description="Applicable mitigation IDs"
    )
    external_references: List[str] = Field(
        default_factory=list,
        description="External references"
    )
    version: str = Field(default="1.0", description="Technique version")
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "technique_id": "T1566",
                "name": "Phishing",
                "description": "Adversaries may send phishing messages to gain access to victim systems.",
                "tactics": ["initial_access"],
                "platforms": ["windows", "linux", "macos"],
                "data_sources": ["email_gateway", "network_traffic"],
                "detection_level": "moderate",
                "mitigation_level": "moderate",
                "sub_techniques": ["T1566.001", "T1566.002"],
                "mitigations": ["M1017", "M1021"],
                "external_references": [
                    "https://attack.mitre.org/techniques/T1566/"
                ],
                "version": "2.1"
            }
        }


class SubTechnique(BaseModel):
    """MITRE ATT&CK sub-technique schema."""
    
    sub_technique_id: str = Field(..., description="MITRE ATT&CK sub-technique ID")
    parent_technique_id: str = Field(..., description="Parent technique ID")
    name: str = Field(..., description="Sub-technique name")
    description: str = Field(..., description="Sub-technique description")
    platforms: List[PlatformType] = Field(
        default_factory=list,
        description="Applicable platforms"
    )
    data_sources: List[str] = Field(
        default_factory=list,
        description="Data sources for detection"
    )
    detection_level: DetectionLevel = Field(
        default=DetectionLevel.MODERATE,
        description="Detection difficulty level"
    )
    mitigation_level: MitigationLevel = Field(
        default=MitigationLevel.MODERATE,
        description="Mitigation effectiveness level"
    )
    mitigations: List[str] = Field(
        default_factory=list,
        description="Applicable mitigation IDs"
    )
    external_references: List[str] = Field(
        default_factory=list,
        description="External references"
    )
    version: str = Field(default="1.0", description="Sub-technique version")
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "sub_technique_id": "T1566.001",
                "parent_technique_id": "T1566",
                "name": "Spearphishing Attachment",
                "description": "Adversaries may send spearphishing emails with a malicious attachment.",
                "platforms": ["windows", "linux", "macos"],
                "data_sources": ["email_gateway", "file_monitoring"],
                "detection_level": "moderate",
                "mitigation_level": "moderate",
                "mitigations": ["M1017", "M1021"],
                "external_references": [
                    "https://attack.mitre.org/techniques/T1566/001/"
                ],
                "version": "2.1"
            }
        }


class Mitigation(BaseModel):
    """MITRE ATT&CK mitigation schema."""
    
    mitigation_id: str = Field(..., description="MITRE ATT&CK mitigation ID")
    name: str = Field(..., description="Mitigation name")
    description: str = Field(..., description="Mitigation description")
    techniques: List[str] = Field(
        default_factory=list,
        description="Mitigated technique IDs"
    )
    effectiveness: MitigationLevel = Field(
        default=MitigationLevel.MODERATE,
        description="Mitigation effectiveness level"
    )
    implementation_complexity: str = Field(
        default="medium",
        description="Implementation complexity"
    )
    external_references: List[str] = Field(
        default_factory=list,
        description="External references"
    )
    version: str = Field(default="1.0", description="Mitigation version")
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "mitigation_id": "M1017",
                "name": "User Training",
                "description": "Train users to identify and report suspicious phishing emails.",
                "techniques": ["T1566", "T1204"],
                "effectiveness": "moderate",
                "implementation_complexity": "low",
                "external_references": [
                    "https://attack.mitre.org/mitigations/M1017/"
                ],
                "version": "1.0"
            }
        }


class DataSource(BaseModel):
    """MITRE ATT&CK data source schema."""
    
    data_source_id: str = Field(..., description="Data source ID")
    name: str = Field(..., description="Data source name")
    description: str = Field(..., description="Data source description")
    platforms: List[PlatformType] = Field(
        default_factory=list,
        description="Applicable platforms"
    )
    data_components: List[str] = Field(
        default_factory=list,
        description="Data components"
    )
    techniques: List[str] = Field(
        default_factory=list,
        description="Associated technique IDs"
    )
    external_references: List[str] = Field(
        default_factory=list,
        description="External references"
    )
    version: str = Field(default="1.0", description="Data source version")
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "data_source_id": "DS0015",
                "name": "Application Log",
                "description": "Events collected by third-party services.",
                "platforms": ["windows", "linux", "macos"],
                "data_components": ["Application Log Content"],
                "techniques": ["T1566", "T1204"],
                "external_references": [
                    "https://attack.mitre.org/datasources/DS0015/"
                ],
                "version": "1.0"
            }
        }


class AttackPattern(BaseModel):
    """Attack pattern mapping schema."""
    
    pattern_id: str = Field(..., description="Unique pattern identifier")
    name: str = Field(..., description="Pattern name")
    description: str = Field(..., description="Pattern description")
    techniques: List[str] = Field(
        default_factory=list,
        description="Associated technique IDs"
    )
    sub_techniques: List[str] = Field(
        default_factory=list,
        description="Associated sub-technique IDs"
    )
    tactics: List[TacticType] = Field(
        default_factory=list,
        description="Associated tactics"
    )
    confidence: float = Field(ge=0.0, le=1.0, description="Confidence score")
    evidence: List[str] = Field(
        default_factory=list,
        description="Evidence for the mapping"
    )
    context: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context"
    )
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "pattern_id": "pattern_123",
                "name": "Email-based Initial Access",
                "description": "Attack pattern involving phishing emails",
                "techniques": ["T1566"],
                "sub_techniques": ["T1566.001"],
                "tactics": ["initial_access"],
                "confidence": 0.85,
                "evidence": ["malicious_attachment", "phishing_email"],
                "context": {
                    "target_sector": "finance",
                    "campaign": "operation_example"
                }
            }
        }


class MitreAttack(BaseModel):
    """Comprehensive MITRE ATT&CK mapping schema."""
    
    mapping_id: str = Field(..., description="Unique mapping identifier")
    data_type: str = Field(..., description="Type of data being mapped")
    enrichment_timestamp: datetime = Field(
        default_factory=datetime.utcnow,
        description="Mapping timestamp"
    )
    framework_version: str = Field(
        default="v13.1",
        description="MITRE ATT&CK framework version"
    )
    confidence: float = Field(ge=0.0, le=1.0, description="Overall confidence score")
    
    # Mapped tactics
    tactics: List[Tactic] = Field(default_factory=list, description="Mapped tactics")
    
    # Mapped techniques
    techniques: List[Technique] = Field(default_factory=list, description="Mapped techniques")
    
    # Mapped sub-techniques
    sub_techniques: List[SubTechnique] = Field(
        default_factory=list,
        description="Mapped sub-techniques"
    )
    
    # Applicable mitigations
    mitigations: List[Mitigation] = Field(
        default_factory=list,
        description="Applicable mitigations"
    )
    
    # Data sources
    data_sources: List[DataSource] = Field(
        default_factory=list,
        description="Relevant data sources"
    )
    
    # Attack patterns
    attack_patterns: List[AttackPattern] = Field(
        default_factory=list,
        description="Identified attack patterns"
    )
    
    # Kill chain phases
    kill_chain_phases: List[str] = Field(
        default_factory=list,
        description="Kill chain phases"
    )
    
    # Platform coverage
    platforms: List[PlatformType] = Field(
        default_factory=list,
        description="Applicable platforms"
    )
    
    # Detection recommendations
    detection_recommendations: List[str] = Field(
        default_factory=list,
        description="Detection recommendations"
    )
    
    # Mitigation recommendations
    mitigation_recommendations: List[str] = Field(
        default_factory=list,
        description="Mitigation recommendations"
    )
    
    # Risk assessment
    risk_score: float = Field(ge=0.0, le=10.0, description="Risk score based on MITRE mapping")
    
    # Additional context
    context: Dict[str, Any] = Field(default_factory=dict, description="Additional context")
    
    class Config:
        """Pydantic configuration."""
        schema_extra = {
            "example": {
                "mapping_id": "mitre_123",
                "data_type": "cve",
                "enrichment_timestamp": "2023-01-01T12:00:00Z",
                "framework_version": "v13.1",
                "confidence": 0.85,
                "tactics": [
                    {
                        "tactic_id": "TA0001",
                        "name": "Initial Access",
                        "description": "The adversary is trying to get into your network.",
                        "short_name": "initial-access"
                    }
                ],
                "techniques": [
                    {
                        "technique_id": "T1566",
                        "name": "Phishing",
                        "description": "Adversaries may send phishing messages.",
                        "tactics": ["initial_access"],
                        "platforms": ["windows", "linux", "macos"]
                    }
                ],
                "sub_techniques": [
                    {
                        "sub_technique_id": "T1566.001",
                        "parent_technique_id": "T1566",
                        "name": "Spearphishing Attachment",
                        "description": "Adversaries may send spearphishing emails with a malicious attachment."
                    }
                ],
                "mitigations": [
                    {
                        "mitigation_id": "M1017",
                        "name": "User Training",
                        "description": "Train users to identify and report suspicious phishing emails.",
                        "techniques": ["T1566"]
                    }
                ],
                "data_sources": [
                    {
                        "data_source_id": "DS0015",
                        "name": "Application Log",
                        "description": "Events collected by third-party services."
                    }
                ],
                "attack_patterns": [
                    {
                        "pattern_id": "pattern_123",
                        "name": "Email-based Initial Access",
                        "techniques": ["T1566"],
                        "confidence": 0.85
                    }
                ],
                "kill_chain_phases": ["delivery", "exploitation"],
                "platforms": ["windows", "linux", "macos"],
                "detection_recommendations": [
                    "Monitor email gateway logs",
                    "Implement email security controls"
                ],
                "mitigation_recommendations": [
                    "Implement user training programs",
                    "Deploy email security solutions"
                ],
                "risk_score": 7.5,
                "context": {
                    "vulnerability_type": "remote_code_execution",
                    "exploit_availability": "public"
                }
            }
        }