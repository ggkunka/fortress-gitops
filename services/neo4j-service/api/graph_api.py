"""
Graph API - REST endpoints for dependency graph operations

This service provides comprehensive dependency graph storage and analysis
capabilities using Neo4j for supply chain security.
"""

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Set
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from pydantic import BaseModel, Field
from fastapi.responses import JSONResponse

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.security.sanitization import sanitize_input

from ..models.graph import (
    ComponentNode, DependencyRelationship, VulnerabilityNode, 
    LicenseNode, SupplyChainRisk, GraphQuery, GraphPath,
    RiskLevel, ComponentType, RelationshipType,
    create_component_node, create_dependency_relationship
)
from ..services.graph_repository import GraphRepository
from ..services.graph_analyzer import GraphAnalyzer

logger = get_logger(__name__)
metrics = get_metrics()

router = APIRouter()

# Global instances (would be injected in real implementation)
graph_repository = None
graph_analyzer = None


class CreateComponentRequest(BaseModel):
    """Request model for creating component nodes."""
    name: str = Field(..., min_length=1, max_length=255)
    version: str = Field(..., min_length=1, max_length=100)
    component_type: ComponentType = Field(...)
    namespace: Optional[str] = Field(None, max_length=255)
    language: Optional[str] = Field(None, max_length=50)
    ecosystem: Optional[str] = Field(None, max_length=50)
    purl: Optional[str] = Field(None, max_length=500)
    cpe: Optional[str] = Field(None, max_length=500)
    supplier: Optional[str] = Field(None, max_length=255)
    author: Optional[str] = Field(None, max_length=255)
    homepage: Optional[str] = Field(None, max_length=500)
    repository_url: Optional[str] = Field(None, max_length=500)
    description: Optional[str] = Field(None, max_length=1000)
    license_declared: Optional[str] = Field(None, max_length=255)
    license_concluded: Optional[str] = Field(None, max_length=255)
    copyright: Optional[str] = Field(None, max_length=500)
    checksum_sha1: Optional[str] = Field(None, max_length=40)
    checksum_sha256: Optional[str] = Field(None, max_length=64)
    checksum_md5: Optional[str] = Field(None, max_length=32)
    download_url: Optional[str] = Field(None, max_length=500)
    files_analyzed: bool = Field(default=False)
    verification_code: Optional[str] = Field(None, max_length=255)
    risk_score: float = Field(0.0, ge=0.0, le=10.0)
    confidence_score: float = Field(1.0, ge=0.0, le=1.0)
    popularity_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    maintenance_score: Optional[float] = Field(None, ge=0.0, le=1.0)
    properties: Optional[Dict[str, Any]] = Field(default_factory=dict)
    labels: Optional[List[str]] = Field(default_factory=list)


class CreateDependencyRequest(BaseModel):
    """Request model for creating dependency relationships."""
    from_component_id: str = Field(..., min_length=1)
    to_component_id: str = Field(..., min_length=1)
    relationship_type: RelationshipType = Field(...)
    scope: Optional[str] = Field(None, max_length=50)
    version_constraint: Optional[str] = Field(None, max_length=100)
    is_optional: bool = Field(default=False)
    is_direct: bool = Field(default=True)
    depth: int = Field(default=1, ge=1)
    introduced_by: Optional[str] = Field(None, max_length=255)
    confidence_score: float = Field(1.0, ge=0.0, le=1.0)
    last_verified: Optional[datetime] = None
    properties: Optional[Dict[str, Any]] = Field(default_factory=dict)


class CreateVulnerabilityRequest(BaseModel):
    """Request model for creating vulnerability nodes."""
    vulnerability_id: str = Field(..., min_length=1, max_length=255)
    cve_id: Optional[str] = Field(None, max_length=50)
    title: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = Field(None, max_length=2000)
    severity: RiskLevel = Field(...)
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0)
    cvss_vector: Optional[str] = Field(None, max_length=255)
    cwe_id: Optional[str] = Field(None, max_length=50)
    published_date: datetime = Field(...)
    modified_date: Optional[datetime] = None
    source: str = Field(..., min_length=1, max_length=255)
    source_url: Optional[str] = Field(None, max_length=500)
    exploitability: Optional[str] = Field(None, max_length=50)
    impact: Optional[str] = Field(None, max_length=50)
    exploit_available: bool = Field(default=False)
    exploit_in_wild: bool = Field(default=False)
    patch_available: bool = Field(default=False)
    patch_date: Optional[datetime] = None
    affected_versions: Optional[List[str]] = Field(default_factory=list)
    fixed_versions: Optional[List[str]] = Field(default_factory=list)
    properties: Optional[Dict[str, Any]] = Field(default_factory=dict)


class GraphQueryRequest(BaseModel):
    """Request model for graph queries."""
    query_type: str = Field(..., min_length=1, max_length=50)
    start_node_id: Optional[str] = Field(None, max_length=255)
    node_types: Optional[List[str]] = Field(default_factory=list)
    relationship_types: Optional[List[str]] = Field(default_factory=list)
    filters: Optional[Dict[str, Any]] = Field(default_factory=dict)
    max_depth: int = Field(5, ge=1, le=10)
    limit: int = Field(1000, ge=1, le=10000)
    include_properties: bool = Field(default=True)


def get_graph_repository() -> GraphRepository:
    """Get graph repository instance."""
    global graph_repository
    if graph_repository is None:
        raise RuntimeError("Graph repository not initialized")
    return graph_repository


def get_graph_analyzer() -> GraphAnalyzer:
    """Get graph analyzer instance."""
    global graph_analyzer
    if graph_analyzer is None:
        raise RuntimeError("Graph analyzer not initialized")
    return graph_analyzer


@router.post("/components", response_model=Dict[str, Any])
@traced("graph_api_create_component")
async def create_component(
    request: CreateComponentRequest,
    repository: GraphRepository = Depends(get_graph_repository)
):
    """Create a component node in the dependency graph."""
    try:
        # Sanitize inputs
        name = sanitize_input(request.name, max_length=255)
        version = sanitize_input(request.version, max_length=100)
        
        # Create component node
        component = create_component_node(
            name=name,
            version=version,
            component_type=request.component_type,
            namespace=request.namespace,
            language=request.language,
            ecosystem=request.ecosystem,
            purl=request.purl,
            cpe=request.cpe,
            supplier=request.supplier,
            author=request.author,
            homepage=request.homepage,
            repository_url=request.repository_url,
            description=request.description,
            license_declared=request.license_declared,
            license_concluded=request.license_concluded,
            copyright=request.copyright,
            checksum_sha1=request.checksum_sha1,
            checksum_sha256=request.checksum_sha256,
            checksum_md5=request.checksum_md5,
            download_url=request.download_url,
            files_analyzed=request.files_analyzed,
            verification_code=request.verification_code,
            risk_score=request.risk_score,
            confidence_score=request.confidence_score,
            popularity_score=request.popularity_score,
            maintenance_score=request.maintenance_score,
            properties=request.properties or {},
            labels=request.labels or []
        )
        
        # Store in graph
        node_id = await repository.create_component_node(component)
        
        logger.info(f"Component node created: {node_id}")
        metrics.graph_api_components_created.inc()
        
        return {
            "message": "Component created successfully",
            "node_id": node_id,
            "name": request.name,
            "version": request.version,
            "component_type": request.component_type,
            "timestamp": component.created_at.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating component: {e}")
        metrics.graph_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/dependencies", response_model=Dict[str, Any])
@traced("graph_api_create_dependency")
async def create_dependency(
    request: CreateDependencyRequest,
    repository: GraphRepository = Depends(get_graph_repository)
):
    """Create a dependency relationship in the graph."""
    try:
        # Create dependency relationship
        dependency = create_dependency_relationship(
            from_component_id=request.from_component_id,
            to_component_id=request.to_component_id,
            relationship_type=request.relationship_type,
            scope=request.scope,
            version_constraint=request.version_constraint,
            is_optional=request.is_optional,
            is_direct=request.is_direct,
            depth=request.depth,
            introduced_by=request.introduced_by,
            confidence_score=request.confidence_score,
            last_verified=request.last_verified,
            properties=request.properties or {}
        )
        
        # Store in graph
        relationship_id = await repository.create_dependency_relationship(dependency)
        
        logger.info(f"Dependency relationship created: {relationship_id}")
        metrics.graph_api_dependencies_created.inc()
        
        return {
            "message": "Dependency created successfully",
            "relationship_id": relationship_id,
            "from_component": request.from_component_id,
            "to_component": request.to_component_id,
            "relationship_type": request.relationship_type,
            "timestamp": dependency.created_at.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating dependency: {e}")
        metrics.graph_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/vulnerabilities", response_model=Dict[str, Any])
@traced("graph_api_create_vulnerability")
async def create_vulnerability(
    request: CreateVulnerabilityRequest,
    repository: GraphRepository = Depends(get_graph_repository)
):
    """Create a vulnerability node in the graph."""
    try:
        # Sanitize inputs
        vulnerability_id = sanitize_input(request.vulnerability_id, max_length=255)
        title = sanitize_input(request.title, max_length=255)
        
        # Create vulnerability node
        vulnerability = VulnerabilityNode(
            vulnerability_id=vulnerability_id,
            cve_id=request.cve_id,
            title=title,
            description=request.description,
            severity=request.severity,
            cvss_score=request.cvss_score,
            cvss_vector=request.cvss_vector,
            cwe_id=request.cwe_id,
            published_date=request.published_date,
            modified_date=request.modified_date,
            source=request.source,
            source_url=request.source_url,
            exploitability=request.exploitability,
            impact=request.impact,
            exploit_available=request.exploit_available,
            exploit_in_wild=request.exploit_in_wild,
            patch_available=request.patch_available,
            patch_date=request.patch_date,
            affected_versions=request.affected_versions or [],
            fixed_versions=request.fixed_versions or [],
            properties=request.properties or {}
        )
        
        # Store in graph
        node_id = await repository.create_vulnerability_node(vulnerability)
        
        logger.info(f"Vulnerability node created: {node_id}")
        metrics.graph_api_vulnerabilities_created.inc()
        
        return {
            "message": "Vulnerability created successfully",
            "node_id": node_id,
            "vulnerability_id": request.vulnerability_id,
            "title": request.title,
            "severity": request.severity,
            "timestamp": vulnerability.created_at.isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error creating vulnerability: {e}")
        metrics.graph_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.post("/query", response_model=Dict[str, Any])
@traced("graph_api_execute_query")
async def execute_graph_query(
    request: GraphQueryRequest,
    repository: GraphRepository = Depends(get_graph_repository)
):
    """Execute a graph query."""
    try:
        # Create query object
        query = GraphQuery(
            query_type=request.query_type,
            start_node_id=request.start_node_id,
            node_types=request.node_types,
            relationship_types=request.relationship_types,
            filters=request.filters,
            max_depth=request.max_depth,
            limit=request.limit,
            include_properties=request.include_properties
        )
        
        # Execute query
        result = await repository.execute_query(query)
        
        return {
            "query_type": request.query_type,
            "nodes": result.nodes,
            "relationships": result.relationships,
            "total_nodes": result.total_nodes,
            "total_relationships": result.total_relationships,
            "execution_time": result.execution_time,
            "metadata": result.metadata
        }
        
    except Exception as e:
        logger.error(f"Error executing graph query: {e}")
        metrics.graph_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/components/{component_id}", response_model=Dict[str, Any])
@traced("graph_api_get_component")
async def get_component(
    component_id: str,
    include_dependencies: bool = Query(False),
    include_vulnerabilities: bool = Query(False),
    repository: GraphRepository = Depends(get_graph_repository)
):
    """Get a component by ID with optional related data."""
    try:
        component = await repository.get_component_by_id(component_id)
        
        if not component:
            raise HTTPException(status_code=404, detail="Component not found")
        
        result = component.dict()
        
        if include_dependencies:
            dependencies = await repository.get_component_dependencies(component_id)
            result["dependencies"] = dependencies
        
        if include_vulnerabilities:
            vulnerabilities = await repository.get_component_vulnerabilities(component_id)
            result["vulnerabilities"] = vulnerabilities
        
        return result
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error getting component: {e}")
        metrics.graph_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/analysis/supply-chain-risk", response_model=Dict[str, Any])
@traced("graph_api_supply_chain_risk_analysis")
async def analyze_supply_chain_risk(
    component_id: str = Query(...),
    max_depth: int = Query(5, ge=1, le=10),
    analyzer: GraphAnalyzer = Depends(get_graph_analyzer)
):
    """Analyze supply chain risk for a component."""
    try:
        analysis = await analyzer.analyze_supply_chain_risk(
            component_id=component_id,
            max_depth=max_depth
        )
        
        return {
            "component_id": component_id,
            "risk_analysis": analysis,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error analyzing supply chain risk: {e}")
        metrics.graph_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/analysis/dependency-path", response_model=Dict[str, Any])
@traced("graph_api_dependency_path_analysis")
async def find_dependency_path(
    from_component_id: str = Query(...),
    to_component_id: str = Query(...),
    max_depth: int = Query(10, ge=1, le=20),
    analyzer: GraphAnalyzer = Depends(get_graph_analyzer)
):
    """Find dependency paths between two components."""
    try:
        paths = await analyzer.find_dependency_paths(
            from_component_id=from_component_id,
            to_component_id=to_component_id,
            max_depth=max_depth
        )
        
        return {
            "from_component": from_component_id,
            "to_component": to_component_id,
            "paths": [path.dict() for path in paths],
            "total_paths": len(paths),
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error finding dependency path: {e}")
        metrics.graph_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/analysis/vulnerability-impact", response_model=Dict[str, Any])
@traced("graph_api_vulnerability_impact_analysis")
async def analyze_vulnerability_impact(
    vulnerability_id: str = Query(...),
    analyzer: GraphAnalyzer = Depends(get_graph_analyzer)
):
    """Analyze the impact of a vulnerability across the dependency graph."""
    try:
        impact = await analyzer.analyze_vulnerability_impact(vulnerability_id)
        
        return {
            "vulnerability_id": vulnerability_id,
            "impact_analysis": impact,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error analyzing vulnerability impact: {e}")
        metrics.graph_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/analysis/license-compliance", response_model=Dict[str, Any])
@traced("graph_api_license_compliance_analysis")
async def analyze_license_compliance(
    component_id: str = Query(...),
    policy_name: Optional[str] = Query(None),
    analyzer: GraphAnalyzer = Depends(get_graph_analyzer)
):
    """Analyze license compliance for a component and its dependencies."""
    try:
        compliance = await analyzer.analyze_license_compliance(
            component_id=component_id,
            policy_name=policy_name
        )
        
        return {
            "component_id": component_id,
            "policy_name": policy_name,
            "compliance_analysis": compliance,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error analyzing license compliance: {e}")
        metrics.graph_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.get("/statistics", response_model=Dict[str, Any])
@traced("graph_api_get_statistics")
async def get_statistics(
    repository: GraphRepository = Depends(get_graph_repository),
    analyzer: GraphAnalyzer = Depends(get_graph_analyzer)
):
    """Get comprehensive graph statistics."""
    try:
        repository_stats = repository.get_stats()
        analyzer_stats = analyzer.get_stats()
        
        return {
            "service": "neo4j-service",
            "repository": repository_stats,
            "analyzer": analyzer_stats,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except Exception as e:
        logger.error(f"Error getting statistics: {e}")
        metrics.graph_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")


@router.delete("/components/{component_id}", response_model=Dict[str, Any])
@traced("graph_api_delete_component")
async def delete_component(
    component_id: str,
    cascade: bool = Query(False, description="Delete related relationships"),
    repository: GraphRepository = Depends(get_graph_repository)
):
    """Delete a component node from the graph."""
    try:
        success = await repository.delete_component(component_id, cascade=cascade)
        
        if not success:
            raise HTTPException(status_code=404, detail="Component not found")
        
        logger.info(f"Component deleted: {component_id}")
        
        return {
            "message": "Component deleted successfully",
            "component_id": component_id,
            "cascade": cascade,
            "timestamp": datetime.utcnow().isoformat()
        }
        
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error deleting component: {e}")
        metrics.graph_api_errors.inc()
        raise HTTPException(status_code=500, detail="Internal server error")