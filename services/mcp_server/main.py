"""
MCP Security Platform Server - Main Entry Point

Implements Anthropic's Model Context Protocol (MCP) specification
for security scanning and vulnerability analysis.
"""

import asyncio
import json
import logging
import sys
from typing import Any, Dict, List, Optional, Sequence

import structlog
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import (
    CallToolRequestParams,
    GetResourceRequestParams,
    ListResourcesRequestParams,
    ListToolsRequestParams,
    Resource,
    TextContent,
    Tool,
)

from services.mcp_server.tools.security_scanner import SecurityScannerTool
from services.mcp_server.tools.vulnerability_analyzer import VulnerabilityAnalyzerTool
from services.mcp_server.tools.risk_assessor import RiskAssessorTool
from services.mcp_server.resources.security_data import SecurityDataResource
from services.mcp_server.schemas.security_types import ScanRequest, ScanResult

logger = structlog.get_logger(__name__)


class MCPSecurityServer:
    """
    MCP Server for Security Platform
    
    Provides security scanning, vulnerability analysis, and risk assessment
    capabilities through the Model Context Protocol.
    """
    
    def __init__(self):
        """Initialize the MCP Security Server."""
        self.server = Server("mcp-security-platform")
        self.security_scanner = SecurityScannerTool()
        self.vulnerability_analyzer = VulnerabilityAnalyzerTool()
        self.risk_assessor = RiskAssessorTool()
        self.security_data = SecurityDataResource()
        
        # Register handlers
        self._register_handlers()
        
    def _register_handlers(self):
        """Register MCP protocol handlers."""
        
        @self.server.list_tools()
        async def list_tools() -> List[Tool]:
            """List available security tools."""
            return [
                Tool(
                    name="scan_container_vulnerabilities",
                    description="Scan container images for security vulnerabilities using Grype, Trivy, or Syft",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "image": {
                                "type": "string",
                                "description": "Container image to scan (e.g., 'nginx:latest', 'redis:8.0.3')"
                            },
                            "scanner": {
                                "type": "string",
                                "enum": ["grype", "trivy", "syft"],
                                "default": "grype",
                                "description": "Scanner to use for vulnerability detection"
                            },
                            "format": {
                                "type": "string",
                                "enum": ["json", "table", "sarif"],
                                "default": "json",
                                "description": "Output format for scan results"
                            }
                        },
                        "required": ["image"]
                    }
                ),
                Tool(
                    name="generate_sbom",
                    description="Generate Software Bill of Materials (SBOM) for container images or filesystems",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "Target to analyze (container image, directory, or file)"
                            },
                            "format": {
                                "type": "string",
                                "enum": ["spdx", "cyclonedx", "syft"],
                                "default": "spdx",
                                "description": "SBOM format to generate"
                            },
                            "output": {
                                "type": "string",
                                "enum": ["json", "xml", "yaml"],
                                "default": "json",
                                "description": "Output format for SBOM"
                            }
                        },
                        "required": ["target"]
                    }
                ),
                Tool(
                    name="assess_security_risk",
                    description="Perform AI-powered security risk assessment of vulnerabilities",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "vulnerabilities": {
                                "type": "array",
                                "items": {
                                    "type": "object",
                                    "properties": {
                                        "cve_id": {"type": "string"},
                                        "severity": {"type": "string"},
                                        "description": {"type": "string"},
                                        "package": {"type": "string"}
                                    }
                                },
                                "description": "List of vulnerabilities to assess"
                            },
                            "context": {
                                "type": "string",
                                "description": "Additional context for risk assessment (environment, usage, etc.)"
                            },
                            "criteria": {
                                "type": "array",
                                "items": {"type": "string"},
                                "description": "Specific assessment criteria (exploitability, business impact, etc.)"
                            }
                        },
                        "required": ["vulnerabilities"]
                    }
                ),
                Tool(
                    name="analyze_compliance",
                    description="Analyze security compliance against frameworks (CIS, NIST, SOC2)",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "target": {
                                "type": "string",
                                "description": "Target to analyze (container, cluster, configuration)"
                            },
                            "framework": {
                                "type": "string",
                                "enum": ["cis", "nist", "soc2", "pci-dss", "iso27001"],
                                "description": "Compliance framework to evaluate against"
                            },
                            "profile": {
                                "type": "string",
                                "description": "Specific profile or benchmark version"
                            }
                        },
                        "required": ["target", "framework"]
                    }
                )
            ]
        
        @self.server.call_tool()
        async def call_tool(name: str, arguments: Dict[str, Any]) -> Sequence[TextContent]:
            """Handle tool execution requests."""
            try:
                if name == "scan_container_vulnerabilities":
                    result = await self.security_scanner.scan_vulnerabilities(**arguments)
                elif name == "generate_sbom":
                    result = await self.security_scanner.generate_sbom(**arguments)
                elif name == "assess_security_risk":
                    result = await self.risk_assessor.assess_risk(**arguments)
                elif name == "analyze_compliance":
                    result = await self.vulnerability_analyzer.analyze_compliance(**arguments)
                else:
                    raise ValueError(f"Unknown tool: {name}")
                
                return [TextContent(type="text", text=json.dumps(result, indent=2))]
                
            except Exception as e:
                logger.error("Tool execution failed", tool=name, error=str(e))
                return [TextContent(
                    type="text", 
                    text=json.dumps({
                        "error": f"Tool execution failed: {str(e)}",
                        "tool": name,
                        "arguments": arguments
                    }, indent=2)
                )]
        
        @self.server.list_resources()
        async def list_resources() -> List[Resource]:
            """List available security data resources."""
            return [
                Resource(
                    uri="security://scans/recent",
                    name="Recent Security Scans",
                    description="Recent vulnerability scan results and metadata",
                    mimeType="application/json"
                ),
                Resource(
                    uri="security://vulnerabilities/critical",
                    name="Critical Vulnerabilities",
                    description="Critical severity vulnerabilities across all scans",
                    mimeType="application/json"
                ),
                Resource(
                    uri="security://sboms/latest",
                    name="Latest SBOM Data",
                    description="Software Bill of Materials for recent scans",
                    mimeType="application/json"
                ),
                Resource(
                    uri="security://compliance/status",
                    name="Compliance Status",
                    description="Current compliance status across frameworks",
                    mimeType="application/json"
                ),
                Resource(
                    uri="security://metrics/dashboard",
                    name="Security Metrics",
                    description="Security metrics and KPIs for monitoring",
                    mimeType="application/json"
                )
            ]
        
        @self.server.read_resource()
        async def read_resource(uri: str) -> str:
            """Read security data resources."""
            try:
                if uri.startswith("security://scans/"):
                    return await self.security_data.get_scan_data(uri)
                elif uri.startswith("security://vulnerabilities/"):
                    return await self.security_data.get_vulnerability_data(uri)
                elif uri.startswith("security://sboms/"):
                    return await self.security_data.get_sbom_data(uri)
                elif uri.startswith("security://compliance/"):
                    return await self.security_data.get_compliance_data(uri)
                elif uri.startswith("security://metrics/"):
                    return await self.security_data.get_metrics_data(uri)
                else:
                    raise ValueError(f"Unknown resource URI: {uri}")
                    
            except Exception as e:
                logger.error("Resource read failed", uri=uri, error=str(e))
                return json.dumps({
                    "error": f"Failed to read resource: {str(e)}",
                    "uri": uri
                })


async def main():
    """Main entry point for the MCP Security Server."""
    logging.basicConfig(level=logging.INFO)
    logger.info("Starting MCP Security Platform Server")
    
    # Initialize server
    security_server = MCPSecurityServer()
    
    try:
        # Run with stdio transport (for CLI tools and IDE integration)
        async with stdio_server() as (read_stream, write_stream):
            logger.info("MCP Security Server running on stdio transport")
            await security_server.server.run(
                read_stream, 
                write_stream,
                security_server.server.create_initialization_options()
            )
    except KeyboardInterrupt:
        logger.info("Server shutdown requested")
    except Exception as e:
        logger.error("Server error", error=str(e))
        sys.exit(1)
    finally:
        logger.info("MCP Security Server stopped")


if __name__ == "__main__":
    asyncio.run(main())