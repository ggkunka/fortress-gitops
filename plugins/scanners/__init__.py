"""
Scanner Plugins Package

This package contains vulnerability and security scanner plugins for the MCP Security Platform.
Each scanner plugin provides a standardized interface for different security scanning tools.

Available Scanner Plugins:
- Trivy: Comprehensive vulnerability scanner for containers and infrastructure
- Syft: Software Bill of Materials (SBOM) generator
- Grype: Vulnerability scanner using Anchore's vulnerability database
- OSV: Open Source Vulnerability scanner using Google's OSV database

Usage:
    from plugins.scanners.trivy.trivy_plugin import TrivyPlugin, TrivyConfig
    from plugins.scanners.syft.syft_plugin import SyftPlugin, SyftConfig
    from plugins.scanners.grype.grype_plugin import GrypePlugin, GrypeConfig
    from plugins.scanners.osv.osv_plugin import OSVPlugin, OSVConfig
    
    # Initialize scanner
    trivy_config = TrivyConfig()
    trivy = TrivyPlugin(trivy_config)
    await trivy.initialize()
    
    # Perform scan
    result = await trivy.scan_image("nginx:latest")
"""

from .trivy.trivy_plugin import TrivyPlugin, TrivyConfig
from .syft.syft_plugin import SyftPlugin, SyftConfig
from .grype.grype_plugin import GrypePlugin, GrypeConfig
from .osv.osv_plugin import OSVPlugin, OSVConfig

__all__ = [
    "TrivyPlugin",
    "TrivyConfig", 
    "SyftPlugin",
    "SyftConfig",
    "GrypePlugin",
    "GrypeConfig",
    "OSVPlugin",
    "OSVConfig"
]