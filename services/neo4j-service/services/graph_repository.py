"""
Graph Repository Service - Neo4j-based dependency graph storage

This service provides comprehensive graph storage and query capabilities
for dependency analysis and supply chain security.
"""

import asyncio
import json
from datetime import datetime, timezone, timedelta
from typing import Dict, List, Optional, Any, Set, Tuple
from neo4j import AsyncGraphDatabase, AsyncSession, AsyncDriver
from neo4j.exceptions import Neo4jError
import uuid

from shared.observability.logging import get_logger
from shared.observability.metrics import get_metrics
from shared.observability.tracing import traced
from shared.config.settings import get_settings

from ..models.graph import (
    ComponentNode, DependencyRelationship, VulnerabilityNode, LicenseNode,
    GraphQuery, GraphResult, GraphPath, BaseGraphModel,
    ComponentType, RelationshipType, RiskLevel
)

logger = get_logger(__name__)
metrics = get_metrics()


class GraphRepository:
    """
    Neo4j-based graph repository for dependency analysis.
    
    This repository provides:
    1. Component node management
    2. Dependency relationship management
    3. Vulnerability tracking
    4. License management
    5. Graph querying and analysis
    6. Path finding algorithms
    """
    
    def __init__(self):
        self.driver: Optional[AsyncDriver] = None
        self.settings = get_settings()
        
        # Neo4j connection settings
        self.uri = getattr(self.settings, 'neo4j_uri', 'bolt://localhost:7687')
        self.username = getattr(self.settings, 'neo4j_username', 'neo4j')
        self.password = getattr(self.settings, 'neo4j_password', 'password')
        self.database = getattr(self.settings, 'neo4j_database', 'neo4j')
        
        # Performance settings
        self.max_connection_pool_size = 50
        self.connection_timeout = 30
        self.max_transaction_retry_time = 15
        
        logger.info("Graph repository initialized")
    
    async def initialize(self):
        """Initialize repository with Neo4j connection."""
        try:
            # Create Neo4j driver
            self.driver = AsyncGraphDatabase.driver(
                self.uri,
                auth=(self.username, self.password),
                max_connection_pool_size=self.max_connection_pool_size,
                connection_timeout=self.connection_timeout,
                max_transaction_retry_time=self.max_transaction_retry_time
            )
            
            # Test connection
            await self._test_connection()
            
            # Create constraints and indexes
            await self._create_constraints()
            await self._create_indexes()
            
            logger.info("Graph repository connected to Neo4j")
            
        except Exception as e:
            logger.error(f"Failed to initialize graph repository: {e}")
            raise
    
    async def close(self):
        """Close Neo4j connection."""
        if self.driver:
            await self.driver.close()
            logger.info("Graph repository connection closed")
    
    @traced("graph_repository_create_component_node")
    async def create_component_node(self, component: ComponentNode) -> str:
        """Create a component node in the graph."""
        try:
            async with self.driver.session(database=self.database) as session:
                result = await session.run(
                    """
                    CREATE (c:Component {
                        id: $id,
                        name: $name,
                        version: $version,
                        component_type: $component_type,
                        namespace: $namespace,
                        language: $language,
                        ecosystem: $ecosystem,
                        purl: $purl,
                        cpe: $cpe,
                        supplier: $supplier,
                        author: $author,
                        homepage: $homepage,
                        repository_url: $repository_url,
                        description: $description,
                        license_declared: $license_declared,
                        license_concluded: $license_concluded,
                        copyright: $copyright,
                        checksum_sha1: $checksum_sha1,
                        checksum_sha256: $checksum_sha256,
                        checksum_md5: $checksum_md5,
                        download_url: $download_url,
                        files_analyzed: $files_analyzed,
                        verification_code: $verification_code,
                        risk_score: $risk_score,
                        confidence_score: $confidence_score,
                        popularity_score: $popularity_score,
                        maintenance_score: $maintenance_score,
                        created_at: $created_at,
                        updated_at: $updated_at,
                        properties: $properties,
                        labels: $labels
                    })
                    RETURN c.id as id
                    """,
                    **component.dict()
                )
                
                record = await result.single()
                node_id = record["id"]
                
                logger.debug(f"Component node created: {node_id}")
                metrics.neo4j_component_nodes_created.inc()
                
                return node_id
                
        except Exception as e:
            logger.error(f"Error creating component node: {e}")
            metrics.neo4j_write_errors.inc()
            raise
    
    @traced("graph_repository_create_dependency_relationship")
    async def create_dependency_relationship(self, dependency: DependencyRelationship) -> str:
        """Create a dependency relationship in the graph."""
        try:
            async with self.driver.session(database=self.database) as session:
                result = await session.run(
                    """
                    MATCH (from:Component {id: $from_component_id})
                    MATCH (to:Component {id: $to_component_id})
                    CREATE (from)-[r:DEPENDS_ON {
                        id: $id,
                        relationship_type: $relationship_type,
                        scope: $scope,
                        version_constraint: $version_constraint,
                        is_optional: $is_optional,
                        is_direct: $is_direct,
                        depth: $depth,
                        introduced_by: $introduced_by,
                        confidence_score: $confidence_score,
                        last_verified: $last_verified,
                        created_at: $created_at,
                        updated_at: $updated_at,
                        properties: $properties
                    }]->(to)
                    RETURN r.id as id
                    """,
                    **dependency.dict()
                )
                
                record = await result.single()
                if not record:
                    raise ValueError("Failed to create dependency relationship")
                
                relationship_id = record["id"]
                
                logger.debug(f"Dependency relationship created: {relationship_id}")
                metrics.neo4j_dependency_relationships_created.inc()
                
                return relationship_id
                
        except Exception as e:
            logger.error(f"Error creating dependency relationship: {e}")
            metrics.neo4j_write_errors.inc()
            raise
    
    @traced("graph_repository_create_vulnerability_node")
    async def create_vulnerability_node(self, vulnerability: VulnerabilityNode) -> str:
        """Create a vulnerability node in the graph."""
        try:
            async with self.driver.session(database=self.database) as session:
                result = await session.run(
                    """
                    CREATE (v:Vulnerability {
                        id: $id,
                        vulnerability_id: $vulnerability_id,
                        cve_id: $cve_id,
                        title: $title,
                        description: $description,
                        severity: $severity,
                        cvss_score: $cvss_score,
                        cvss_vector: $cvss_vector,
                        cwe_id: $cwe_id,
                        published_date: $published_date,
                        modified_date: $modified_date,
                        source: $source,
                        source_url: $source_url,
                        exploitability: $exploitability,
                        impact: $impact,
                        exploit_available: $exploit_available,
                        exploit_in_wild: $exploit_in_wild,
                        patch_available: $patch_available,
                        patch_date: $patch_date,
                        affected_versions: $affected_versions,
                        fixed_versions: $fixed_versions,
                        created_at: $created_at,
                        updated_at: $updated_at,
                        properties: $properties
                    })
                    RETURN v.id as id
                    """,
                    **vulnerability.dict()
                )
                
                record = await result.single()
                node_id = record["id"]
                
                logger.debug(f"Vulnerability node created: {node_id}")
                metrics.neo4j_vulnerability_nodes_created.inc()
                
                return node_id
                
        except Exception as e:
            logger.error(f"Error creating vulnerability node: {e}")
            metrics.neo4j_write_errors.inc()
            raise
    
    @traced("graph_repository_link_component_vulnerability")
    async def link_component_vulnerability(
        self, 
        component_id: str, 
        vulnerability_id: str,
        affected_versions: List[str] = None,
        fixed_versions: List[str] = None
    ) -> str:
        """Link a component to a vulnerability."""
        try:
            async with self.driver.session(database=self.database) as session:
                result = await session.run(
                    """
                    MATCH (c:Component {id: $component_id})
                    MATCH (v:Vulnerability {id: $vulnerability_id})
                    CREATE (c)-[r:HAS_VULNERABILITY {
                        id: $link_id,
                        affected_versions: $affected_versions,
                        fixed_versions: $fixed_versions,
                        created_at: $created_at
                    }]->(v)
                    RETURN r.id as id
                    """,
                    component_id=component_id,
                    vulnerability_id=vulnerability_id,
                    link_id=str(uuid.uuid4()),
                    affected_versions=affected_versions or [],
                    fixed_versions=fixed_versions or [],
                    created_at=datetime.now(timezone.utc).isoformat()
                )
                
                record = await result.single()
                if not record:
                    raise ValueError("Failed to link component to vulnerability")
                
                link_id = record["id"]
                
                logger.debug(f"Component-vulnerability link created: {link_id}")
                metrics.neo4j_vulnerability_links_created.inc()
                
                return link_id
                
        except Exception as e:
            logger.error(f"Error linking component to vulnerability: {e}")
            metrics.neo4j_write_errors.inc()
            raise
    
    @traced("graph_repository_execute_query")
    async def execute_query(self, query: GraphQuery) -> GraphResult:
        """Execute a graph query."""
        try:
            start_time = datetime.now()
            
            # Build Cypher query based on query type
            cypher_query, parameters = self._build_cypher_query(query)
            
            async with self.driver.session(database=self.database) as session:
                result = await session.run(cypher_query, parameters)
                records = await result.data()
            
            # Process results
            nodes = []
            relationships = []
            
            for record in records:
                if 'nodes' in record:
                    nodes.extend(record['nodes'])
                if 'relationships' in record:
                    relationships.extend(record['relationships'])
                if 'n' in record:  # Single node result
                    nodes.append(record['n'])
                if 'r' in record:  # Single relationship result
                    relationships.append(record['r'])
            
            # Calculate execution time
            execution_time = (datetime.now() - start_time).total_seconds()
            
            graph_result = GraphResult(
                query=query,
                nodes=nodes,
                relationships=relationships,
                total_nodes=len(nodes),
                total_relationships=len(relationships),
                execution_time=execution_time,
                metadata={
                    "cypher_query": cypher_query,
                    "parameters": parameters
                }
            )
            
            logger.debug(f"Graph query executed: {len(nodes)} nodes, {len(relationships)} relationships")
            metrics.neo4j_queries_executed.inc()
            
            return graph_result
            
        except Exception as e:
            logger.error(f"Error executing graph query: {e}")
            metrics.neo4j_query_errors.inc()
            raise
    
    @traced("graph_repository_get_component_by_id")
    async def get_component_by_id(self, component_id: str) -> Optional[ComponentNode]:
        """Get a component by ID."""
        try:
            async with self.driver.session(database=self.database) as session:
                result = await session.run(
                    "MATCH (c:Component {id: $component_id}) RETURN c",
                    component_id=component_id
                )
                
                record = await result.single()
                if not record:
                    return None
                
                component_data = dict(record["c"])
                return ComponentNode(**component_data)
                
        except Exception as e:
            logger.error(f"Error getting component by ID: {e}")
            metrics.neo4j_read_errors.inc()
            raise
    
    @traced("graph_repository_get_component_dependencies")
    async def get_component_dependencies(
        self, 
        component_id: str, 
        max_depth: int = 5
    ) -> List[Dict[str, Any]]:
        """Get dependencies for a component."""
        try:
            async with self.driver.session(database=self.database) as session:
                result = await session.run(
                    """
                    MATCH (c:Component {id: $component_id})-[r:DEPENDS_ON*1..$max_depth]->(dep:Component)
                    RETURN dep, r, length(r) as depth
                    ORDER BY depth, dep.name
                    """,
                    component_id=component_id,
                    max_depth=max_depth
                )
                
                dependencies = []
                async for record in result:
                    dep_data = dict(record["dep"])
                    dep_data["depth"] = record["depth"]
                    dep_data["relationships"] = [dict(rel) for rel in record["r"]]
                    dependencies.append(dep_data)
                
                return dependencies
                
        except Exception as e:
            logger.error(f"Error getting component dependencies: {e}")
            metrics.neo4j_read_errors.inc()
            raise
    
    @traced("graph_repository_get_component_vulnerabilities")
    async def get_component_vulnerabilities(self, component_id: str) -> List[Dict[str, Any]]:
        """Get vulnerabilities for a component."""
        try:
            async with self.driver.session(database=self.database) as session:
                result = await session.run(
                    """
                    MATCH (c:Component {id: $component_id})-[r:HAS_VULNERABILITY]->(v:Vulnerability)
                    RETURN v, r
                    """,
                    component_id=component_id
                )
                
                vulnerabilities = []
                async for record in result:
                    vuln_data = dict(record["v"])
                    vuln_data["link"] = dict(record["r"])
                    vulnerabilities.append(vuln_data)
                
                return vulnerabilities
                
        except Exception as e:
            logger.error(f"Error getting component vulnerabilities: {e}")
            metrics.neo4j_read_errors.inc()
            raise
    
    @traced("graph_repository_find_dependency_paths")
    async def find_dependency_paths(
        self, 
        from_component_id: str, 
        to_component_id: str,
        max_depth: int = 10
    ) -> List[GraphPath]:
        """Find dependency paths between two components."""
        try:
            async with self.driver.session(database=self.database) as session:
                result = await session.run(
                    """
                    MATCH path = (from:Component {id: $from_id})-[r:DEPENDS_ON*1..$max_depth]->(to:Component {id: $to_id})
                    RETURN path, length(path) as depth
                    ORDER BY depth
                    LIMIT 100
                    """,
                    from_id=from_component_id,
                    to_id=to_component_id,
                    max_depth=max_depth
                )
                
                paths = []
                async for record in result:
                    path_data = record["path"]
                    depth = record["depth"]
                    
                    # Extract nodes and relationships from path
                    nodes = [dict(node) for node in path_data.nodes]
                    relationships = [dict(rel) for rel in path_data.relationships]
                    
                    graph_path = GraphPath(
                        nodes=nodes,
                        relationships=relationships,
                        depth=depth,
                        risk_score=self._calculate_path_risk_score(nodes, relationships)
                    )
                    paths.append(graph_path)
                
                return paths
                
        except Exception as e:
            logger.error(f"Error finding dependency paths: {e}")
            metrics.neo4j_read_errors.inc()
            raise
    
    @traced("graph_repository_delete_component")
    async def delete_component(self, component_id: str, cascade: bool = False) -> bool:
        """Delete a component node from the graph."""
        try:
            async with self.driver.session(database=self.database) as session:
                if cascade:
                    # Delete component and all its relationships
                    result = await session.run(
                        """
                        MATCH (c:Component {id: $component_id})
                        DETACH DELETE c
                        RETURN count(c) as deleted_count
                        """,
                        component_id=component_id
                    )
                else:
                    # Only delete if no relationships exist
                    result = await session.run(
                        """
                        MATCH (c:Component {id: $component_id})
                        WHERE NOT (c)-[]-()
                        DELETE c
                        RETURN count(c) as deleted_count
                        """,
                        component_id=component_id
                    )
                
                record = await result.single()
                deleted_count = record["deleted_count"]
                
                logger.debug(f"Component deleted: {component_id}, cascade: {cascade}")
                metrics.neo4j_components_deleted.inc()
                
                return deleted_count > 0
                
        except Exception as e:
            logger.error(f"Error deleting component: {e}")
            metrics.neo4j_write_errors.inc()
            raise
    
    async def _test_connection(self):
        """Test Neo4j connection."""
        try:
            async with self.driver.session(database=self.database) as session:
                result = await session.run("RETURN 1 as test")
                await result.single()
            logger.info("Neo4j connection test passed")
        except Exception as e:
            logger.error(f"Neo4j connection test failed: {e}")
            raise
    
    async def _create_constraints(self):
        """Create database constraints."""
        try:
            async with self.driver.session(database=self.database) as session:
                constraints = [
                    "CREATE CONSTRAINT component_id_unique IF NOT EXISTS FOR (c:Component) REQUIRE c.id IS UNIQUE",
                    "CREATE CONSTRAINT vulnerability_id_unique IF NOT EXISTS FOR (v:Vulnerability) REQUIRE v.id IS UNIQUE",
                    "CREATE CONSTRAINT license_id_unique IF NOT EXISTS FOR (l:License) REQUIRE l.id IS UNIQUE"
                ]
                
                for constraint in constraints:
                    await session.run(constraint)
                
            logger.info("Database constraints created")
        except Exception as e:
            logger.error(f"Error creating constraints: {e}")
    
    async def _create_indexes(self):
        """Create database indexes."""
        try:
            async with self.driver.session(database=self.database) as session:
                indexes = [
                    "CREATE INDEX component_name_version IF NOT EXISTS FOR (c:Component) ON (c.name, c.version)",
                    "CREATE INDEX component_type IF NOT EXISTS FOR (c:Component) ON (c.component_type)",
                    "CREATE INDEX component_ecosystem IF NOT EXISTS FOR (c:Component) ON (c.ecosystem)",
                    "CREATE INDEX vulnerability_cve IF NOT EXISTS FOR (v:Vulnerability) ON (v.cve_id)",
                    "CREATE INDEX vulnerability_severity IF NOT EXISTS FOR (v:Vulnerability) ON (v.severity)",
                    "CREATE INDEX dependency_type IF NOT EXISTS FOR ()-[r:DEPENDS_ON]-() ON (r.relationship_type)"
                ]
                
                for index in indexes:
                    await session.run(index)
                
            logger.info("Database indexes created")
        except Exception as e:
            logger.error(f"Error creating indexes: {e}")
    
    def _build_cypher_query(self, query: GraphQuery) -> Tuple[str, Dict[str, Any]]:
        """Build Cypher query from GraphQuery."""
        cypher_parts = []
        parameters = {}
        
        # Build MATCH clause
        if query.query_type == "find_dependencies":
            if query.start_node_id:
                cypher_parts.append("MATCH (start:Component {id: $start_id})-[r:DEPENDS_ON*1..$max_depth]->(dep:Component)")
                parameters["start_id"] = query.start_node_id
                parameters["max_depth"] = query.max_depth
            else:
                cypher_parts.append("MATCH (c:Component)-[r:DEPENDS_ON]->(dep:Component)")
        
        elif query.query_type == "find_vulnerabilities":
            cypher_parts.append("MATCH (c:Component)-[r:HAS_VULNERABILITY]->(v:Vulnerability)")
        
        elif query.query_type == "find_components":
            cypher_parts.append("MATCH (c:Component)")
        
        else:
            # Generic query
            node_labels = ":".join(query.node_types) if query.node_types else ""
            cypher_parts.append(f"MATCH (n{node_labels})")
        
        # Build WHERE clause
        where_conditions = []
        
        # Add filters
        for field, value in query.filters.items():
            param_name = f"filter_{field}"
            if isinstance(value, list):
                where_conditions.append(f"n.{field} IN ${param_name}")
            else:
                where_conditions.append(f"n.{field} = ${param_name}")
            parameters[param_name] = value
        
        if where_conditions:
            cypher_parts.append("WHERE " + " AND ".join(where_conditions))
        
        # Build RETURN clause
        if query.include_properties:
            cypher_parts.append("RETURN n, r")
        else:
            cypher_parts.append("RETURN n.id, n.name, n.version")
        
        # Add LIMIT
        if query.limit:
            cypher_parts.append(f"LIMIT {query.limit}")
        
        cypher_query = " ".join(cypher_parts)
        return cypher_query, parameters
    
    def _calculate_path_risk_score(
        self, 
        nodes: List[Dict[str, Any]], 
        relationships: List[Dict[str, Any]]
    ) -> float:
        """Calculate risk score for a dependency path."""
        total_risk = 0.0
        node_count = len(nodes)
        
        if node_count == 0:
            return 0.0
        
        # Sum up individual node risk scores
        for node in nodes:
            risk_score = node.get("risk_score", 0.0)
            total_risk += risk_score
        
        # Factor in path depth (longer paths are riskier)
        depth_penalty = min(node_count * 0.1, 1.0)
        
        # Factor in relationship characteristics
        indirect_penalty = sum(
            0.1 for rel in relationships 
            if not rel.get("is_direct", True)
        )
        
        # Calculate average with penalties
        avg_risk = total_risk / node_count
        final_risk = min(avg_risk + depth_penalty + indirect_penalty, 10.0)
        
        return round(final_risk, 2)
    
    def get_stats(self) -> Dict[str, Any]:
        """Get repository statistics."""
        return {
            "connection_status": "connected" if self.driver else "disconnected",
            "database": self.database,
            "uri": self.uri,
            "max_connection_pool_size": self.max_connection_pool_size,
            "operations": [
                "create_component_node", "create_dependency_relationship",
                "create_vulnerability_node", "link_component_vulnerability",
                "execute_query", "get_component_by_id", "get_component_dependencies",
                "get_component_vulnerabilities", "find_dependency_paths",
                "delete_component"
            ]
        }