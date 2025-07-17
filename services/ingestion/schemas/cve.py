"""CVE (Common Vulnerabilities and Exposures) schema definitions."""

from datetime import datetime
from typing import Any, Dict, List, Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, validator


class CVEReference(BaseModel):
    """CVE reference model."""
    
    url: str = Field(..., description="Reference URL")
    source: Optional[str] = Field(None, description="Reference source")
    tags: Optional[List[str]] = Field(None, description="Reference tags")
    name: Optional[str] = Field(None, description="Reference name")
    
    @validator('url')
    def validate_url(cls, v):
        """Validate URL format."""
        import re
        url_pattern = re.compile(
            r'^https?://'  # http:// or https://
            r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain...
            r'localhost|'  # localhost...
            r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ip
            r'(?::\d+)?'  # optional port
            r'(?:/?|[/?]\S+)$', re.IGNORECASE)
        if not url_pattern.match(v):
            raise ValueError('Invalid URL format')
        return v


class CVEMetadata(BaseModel):
    """CVE metadata model."""
    
    assigner: Optional[str] = Field(None, description="CVE assigner")
    state: Optional[str] = Field(None, description="CVE state")
    date_reserved: Optional[datetime] = Field(None, description="Date reserved")
    date_published: Optional[datetime] = Field(None, description="Date published")
    date_updated: Optional[datetime] = Field(None, description="Date updated")
    date_rejected: Optional[datetime] = Field(None, description="Date rejected")
    
    @validator('state')
    def validate_state(cls, v):
        """Validate CVE state."""
        if v:
            valid_states = ['PUBLISHED', 'RESERVED', 'REJECTED', 'DISPUTED']
            if v not in valid_states:
                raise ValueError(f'Invalid CVE state: {v}. Valid states: {valid_states}')
        return v


class CVEImpact(BaseModel):
    """CVE impact model."""
    
    cvss_v2: Optional[Dict[str, Any]] = Field(None, description="CVSS v2 metrics")
    cvss_v3: Optional[Dict[str, Any]] = Field(None, description="CVSS v3 metrics")
    cvss_v4: Optional[Dict[str, Any]] = Field(None, description="CVSS v4 metrics")
    
    @validator('cvss_v2')
    def validate_cvss_v2(cls, v):
        """Validate CVSS v2 format."""
        if v:
            required_fields = ['version', 'vectorString', 'baseScore']
            for field in required_fields:
                if field not in v:
                    raise ValueError(f'CVSS v2 missing required field: {field}')
            
            # Validate base score range
            base_score = v.get('baseScore')
            if not isinstance(base_score, (int, float)) or not (0 <= base_score <= 10):
                raise ValueError('CVSS v2 baseScore must be between 0 and 10')
        return v
    
    @validator('cvss_v3')
    def validate_cvss_v3(cls, v):
        """Validate CVSS v3 format."""
        if v:
            required_fields = ['version', 'vectorString', 'baseScore', 'baseSeverity']
            for field in required_fields:
                if field not in v:
                    raise ValueError(f'CVSS v3 missing required field: {field}')
            
            # Validate base score range
            base_score = v.get('baseScore')
            if not isinstance(base_score, (int, float)) or not (0 <= base_score <= 10):
                raise ValueError('CVSS v3 baseScore must be between 0 and 10')
            
            # Validate severity
            severity = v.get('baseSeverity')
            valid_severities = ['NONE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
            if severity not in valid_severities:
                raise ValueError(f'Invalid CVSS v3 severity: {severity}. Valid severities: {valid_severities}')
        return v
    
    @validator('cvss_v4')
    def validate_cvss_v4(cls, v):
        """Validate CVSS v4 format."""
        if v:
            required_fields = ['version', 'vectorString', 'baseScore', 'baseSeverity']
            for field in required_fields:
                if field not in v:
                    raise ValueError(f'CVSS v4 missing required field: {field}')
            
            # Validate base score range
            base_score = v.get('baseScore')
            if not isinstance(base_score, (int, float)) or not (0 <= base_score <= 10):
                raise ValueError('CVSS v4 baseScore must be between 0 and 10')
        return v


class CVEWeakness(BaseModel):
    """CVE weakness model."""
    
    cwe_id: str = Field(..., description="CWE identifier")
    description: Optional[str] = Field(None, description="Weakness description")
    source: Optional[str] = Field(None, description="Weakness source")
    
    @validator('cwe_id')
    def validate_cwe_id(cls, v):
        """Validate CWE ID format."""
        import re
        if not re.match(r'^CWE-\d+$', v):
            raise ValueError('CWE ID must be in format CWE-XXX')
        return v


class CVEConfiguration(BaseModel):
    """CVE configuration model."""
    
    nodes: List[Dict[str, Any]] = Field(..., description="Configuration nodes")
    
    @validator('nodes')
    def validate_nodes(cls, v):
        """Validate configuration nodes."""
        if not v:
            raise ValueError('Configuration must contain at least one node')
        
        for node in v:
            if not isinstance(node, dict):
                raise ValueError('Configuration node must be a dictionary')
            if 'operator' not in node:
                raise ValueError('Configuration node must contain an operator')
            
            operator = node.get('operator')
            valid_operators = ['AND', 'OR']
            if operator not in valid_operators:
                raise ValueError(f'Invalid operator: {operator}. Valid operators: {valid_operators}')
        
        return v


class CVESchema(BaseModel):
    """Main CVE schema."""
    
    # Required fields
    cve_id: str = Field(..., description="CVE identifier")
    source_identifier: str = Field(..., description="Source identifier")
    published: datetime = Field(..., description="Publication date")
    last_modified: datetime = Field(..., description="Last modification date")
    
    # Vulnerability status
    vuln_status: str = Field(..., description="Vulnerability status")
    
    # Descriptions
    descriptions: List[Dict[str, str]] = Field(..., description="CVE descriptions")
    
    # References
    references: List[CVEReference] = Field(..., description="CVE references")
    
    # Metadata
    metadata: Optional[CVEMetadata] = Field(None, description="CVE metadata")
    
    # Impact metrics
    metrics: Optional[CVEImpact] = Field(None, description="CVE impact metrics")
    
    # Weaknesses
    weaknesses: Optional[List[CVEWeakness]] = Field(None, description="Associated weaknesses")
    
    # Configurations
    configurations: Optional[List[CVEConfiguration]] = Field(None, description="Vulnerable configurations")
    
    # Vendor comments
    vendor_comments: Optional[List[Dict[str, str]]] = Field(None, description="Vendor comments")
    
    # Additional properties
    properties: Optional[Dict[str, Any]] = Field(None, description="Additional properties")
    
    # Ingestion metadata
    ingestion_id: UUID = Field(default_factory=uuid4, description="Ingestion unique identifier")
    ingestion_timestamp: datetime = Field(default_factory=datetime.utcnow, description="Ingestion timestamp")
    source_system: Optional[str] = Field(None, description="Source system identifier")
    source_environment: Optional[str] = Field(None, description="Source environment")
    
    @validator('cve_id')
    def validate_cve_id(cls, v):
        """Validate CVE ID format."""
        import re
        if not re.match(r'^CVE-\d{4}-\d{4,}$', v):
            raise ValueError('CVE ID must be in format CVE-YYYY-NNNN')
        return v
    
    @validator('vuln_status')
    def validate_vuln_status(cls, v):
        """Validate vulnerability status."""
        valid_statuses = [
            'PUBLISHED', 'RESERVED', 'REJECTED', 'DISPUTED',
            'AWAITING_ANALYSIS', 'UNDERGOING_ANALYSIS', 'ANALYZED'
        ]
        if v not in valid_statuses:
            raise ValueError(f'Invalid vulnerability status: {v}. Valid statuses: {valid_statuses}')
        return v
    
    @validator('descriptions')
    def validate_descriptions(cls, v):
        """Validate descriptions format."""
        if not v:
            raise ValueError('CVE must contain at least one description')
        
        for desc in v:
            if not isinstance(desc, dict):
                raise ValueError('Description must be a dictionary')
            if 'lang' not in desc or 'value' not in desc:
                raise ValueError('Description must contain "lang" and "value" fields')
        
        return v
    
    @validator('references')
    def validate_references(cls, v):
        """Validate references format."""
        if not v:
            raise ValueError('CVE must contain at least one reference')
        return v
    
    class Config:
        """Pydantic configuration."""
        
        json_encoders = {
            datetime: lambda v: v.isoformat(),
            UUID: lambda v: str(v),
        }
        
        schema_extra = {
            "example": {
                "cve_id": "CVE-2023-1234",
                "source_identifier": "cve@mitre.org",
                "published": "2023-01-01T00:00:00Z",
                "last_modified": "2023-01-01T00:00:00Z",
                "vuln_status": "PUBLISHED",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A vulnerability in example software allows remote attackers to execute arbitrary code."
                    }
                ],
                "references": [
                    {
                        "url": "https://example.com/advisory",
                        "source": "example.com",
                        "tags": ["Vendor Advisory"]
                    }
                ],
                "metrics": {
                    "cvss_v3": {
                        "version": "3.1",
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "baseScore": 9.8,
                        "baseSeverity": "CRITICAL"
                    }
                },
                "weaknesses": [
                    {
                        "cwe_id": "CWE-79",
                        "description": "Cross-site Scripting (XSS)",
                        "source": "NVD"
                    }
                ]
            }
        }