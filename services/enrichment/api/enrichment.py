"""Enrichment API endpoints."""

from typing import Dict, Any, List, Optional
from datetime import datetime

import structlog
from fastapi import APIRouter, HTTPException, Query, Depends

from ..schemas.enrichment import (
    EnrichmentRequest, EnrichmentResponse, EnrichmentTask,
    EnrichmentStatus, DataType, EnrichmentType
)

logger = structlog.get_logger()
router = APIRouter()


@router.get("/enrichment/types")
async def get_enrichment_types() -> Dict[str, Any]:
    """Get available enrichment types."""
    return {
        "enrichment_types": [
            {
                "type": "threat_intelligence",
                "description": "Enrich data with threat intelligence from multiple sources",
                "supported_data_types": ["sbom", "cve", "runtime"]
            },
            {
                "type": "mitre_attack",
                "description": "Map data to MITRE ATT&CK techniques and tactics",
                "supported_data_types": ["sbom", "cve", "runtime"]
            },
            {
                "type": "vulnerability_analysis",
                "description": "Perform detailed vulnerability analysis and risk assessment",
                "supported_data_types": ["sbom", "cve"]
            },
            {
                "type": "behavioral_analysis",
                "description": "Analyze runtime behavior patterns and anomalies",
                "supported_data_types": ["runtime"]
            },
            {
                "type": "contextual_analysis",
                "description": "Perform contextual analysis and risk indicator identification",
                "supported_data_types": ["sbom", "cve", "runtime"]
            },
            {
                "type": "risk_assessment",
                "description": "Calculate overall risk scores and recommendations",
                "supported_data_types": ["sbom", "cve", "runtime"]
            }
        ]
    }


@router.get("/enrichment/data-types")
async def get_data_types() -> Dict[str, Any]:
    """Get supported data types."""
    return {
        "data_types": [
            {
                "type": "sbom",
                "description": "Software Bill of Materials data",
                "schema": "SPDX/CycloneDX compatible format"
            },
            {
                "type": "cve",
                "description": "Common Vulnerabilities and Exposures data",
                "schema": "CVE JSON format compatible"
            },
            {
                "type": "runtime",
                "description": "Runtime behavior and telemetry data",
                "schema": "Custom runtime behavior format"
            }
        ]
    }


@router.post("/enrichment/validate")
async def validate_enrichment_request(request: EnrichmentRequest) -> Dict[str, Any]:
    """Validate an enrichment request without processing it."""
    try:
        # Perform validation
        validation_result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "request_id": request.request_id,
            "data_type": request.data_type.value,
            "enrichment_types": [et.value for et in request.enrichment_types],
        }
        
        # Check data type compatibility
        for enrichment_type in request.enrichment_types:
            if not _is_compatible(request.data_type, enrichment_type):
                validation_result["warnings"].append(
                    f"Enrichment type '{enrichment_type.value}' may not be fully compatible with data type '{request.data_type.value}'"
                )
        
        # Check data structure
        if not isinstance(request.data, dict):
            validation_result["valid"] = False
            validation_result["errors"].append("Data must be a valid JSON object")
        
        # Check required fields based on data type
        required_fields = _get_required_fields(request.data_type)
        missing_fields = []
        for field in required_fields:
            if field not in request.data:
                missing_fields.append(field)
        
        if missing_fields:
            validation_result["warnings"].append(
                f"Missing recommended fields for {request.data_type.value}: {', '.join(missing_fields)}"
            )
        
        return validation_result
        
    except Exception as e:
        logger.error("Error validating enrichment request", error=str(e))
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/enrichment/examples")
async def get_request_examples() -> Dict[str, Any]:
    """Get example enrichment requests for different data types."""
    return {
        "examples": {
            "sbom": {
                "request_id": "sbom_example_001",
                "data_type": "sbom",
                "data": {
                    "bomFormat": "CycloneDX",
                    "specVersion": "1.4",
                    "version": 1,
                    "components": [
                        {
                            "type": "library",
                            "name": "express",
                            "version": "4.18.0",
                            "purl": "pkg:npm/express@4.18.0",
                            "hashes": [
                                {
                                    "alg": "SHA-256",
                                    "content": "sha256:abcd1234..."
                                }
                            ]
                        }
                    ]
                },
                "enrichment_types": ["threat_intelligence", "vulnerability_analysis"],
                "priority": 5,
                "timeout_seconds": 300
            },
            "cve": {
                "request_id": "cve_example_001",
                "data_type": "cve",
                "data": {
                    "cve_id": "CVE-2021-44228",
                    "description": "Apache Log4j2 JNDI features...",
                    "metrics": {
                        "cvss_v3": {
                            "baseScore": 10.0,
                            "baseSeverity": "CRITICAL"
                        }
                    }
                },
                "enrichment_types": ["threat_intelligence", "mitre_attack"],
                "priority": 9,
                "timeout_seconds": 300
            },
            "runtime": {
                "request_id": "runtime_example_001",
                "data_type": "runtime",
                "data": {
                    "events": [
                        {
                            "event_type": "process_start",
                            "timestamp": "2024-01-01T12:00:00Z",
                            "data": {
                                "process_name": "suspicious.exe",
                                "command_line": "suspicious.exe --download-payload"
                            }
                        }
                    ],
                    "anomalies": [
                        {
                            "type": "suspicious_process",
                            "severity": "high",
                            "confidence": 0.9
                        }
                    ]
                },
                "enrichment_types": ["behavioral_analysis", "mitre_attack"],
                "priority": 8,
                "timeout_seconds": 300
            }
        }
    }


def _is_compatible(data_type: DataType, enrichment_type: EnrichmentType) -> bool:
    """Check if data type is compatible with enrichment type."""
    compatibility_matrix = {
        DataType.SBOM: [
            EnrichmentType.THREAT_INTELLIGENCE,
            EnrichmentType.MITRE_ATTACK,
            EnrichmentType.VULNERABILITY_ANALYSIS,
            EnrichmentType.CONTEXTUAL_ANALYSIS,
            EnrichmentType.RISK_ASSESSMENT,
        ],
        DataType.CVE: [
            EnrichmentType.THREAT_INTELLIGENCE,
            EnrichmentType.MITRE_ATTACK,
            EnrichmentType.VULNERABILITY_ANALYSIS,
            EnrichmentType.CONTEXTUAL_ANALYSIS,
            EnrichmentType.RISK_ASSESSMENT,
        ],
        DataType.RUNTIME: [
            EnrichmentType.THREAT_INTELLIGENCE,
            EnrichmentType.MITRE_ATTACK,
            EnrichmentType.BEHAVIORAL_ANALYSIS,
            EnrichmentType.CONTEXTUAL_ANALYSIS,
            EnrichmentType.RISK_ASSESSMENT,
        ],
    }
    
    return enrichment_type in compatibility_matrix.get(data_type, [])


def _get_required_fields(data_type: DataType) -> List[str]:
    """Get required fields for a data type."""
    required_fields = {
        DataType.SBOM: ["bomFormat", "specVersion", "components"],
        DataType.CVE: ["cve_id", "description"],
        DataType.RUNTIME: ["events"],
    }
    
    return required_fields.get(data_type, [])