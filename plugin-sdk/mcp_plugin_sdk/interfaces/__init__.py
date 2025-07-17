"""
Plugin interfaces for the MCP Security Platform.
"""

from .base import BasePlugin, PluginMetadata, PluginCapabilities, PluginContext, PluginType, PluginStatus
from .analyzer import AnalyzerPlugin, VulnerabilityResult, AnalysisRequest, AnalysisResponse
from .enricher import EnricherPlugin, EnrichmentResult, EnrichmentRequest, EnrichmentResponse
from .scanner import ScannerPlugin, ScanResult, ScanRequest, ScanResponse
from .notifier import NotifierPlugin, NotificationResult, NotificationRequest, NotificationResponse

__all__ = [
    # Base interface
    "BasePlugin",
    "PluginMetadata",
    "PluginCapabilities", 
    "PluginContext",
    "PluginType",
    "PluginStatus",
    
    # Analyzer interface
    "AnalyzerPlugin",
    "VulnerabilityResult",
    "AnalysisRequest",
    "AnalysisResponse",
    
    # Enricher interface
    "EnricherPlugin",
    "EnrichmentResult",
    "EnrichmentRequest",
    "EnrichmentResponse",
    
    # Scanner interface
    "ScannerPlugin",
    "ScanResult",
    "ScanRequest",
    "ScanResponse",
    
    # Notifier interface
    "NotifierPlugin",
    "NotificationResult",
    "NotificationRequest",
    "NotificationResponse",
]