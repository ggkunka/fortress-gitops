# MCP Security Platform Plugin SDK

The MCP Security Platform Plugin SDK provides a comprehensive framework for developing security analysis plugins. This SDK enables developers to create custom analyzers, enrichers, scanners, and notifiers that integrate seamlessly with the MCP Security Platform.

## Features

- **Multiple Plugin Types**: Support for analyzers, enrichers, scanners, notifiers, and custom processors
- **Event-Driven Architecture**: Asynchronous event bus for plugin communication
- **Configuration Management**: Dynamic configuration with hot-reloading
- **WebAssembly Support**: Secure plugin execution in WASM sandboxes
- **Resource Management**: CPU, memory, and execution time limits
- **Security Model**: Capability-based permissions and sandboxing
- **Lifecycle Management**: Comprehensive plugin lifecycle hooks
- **Monitoring & Metrics**: Built-in health checks and performance metrics

## Quick Start

### Installation

```bash
pip install mcp-plugin-sdk
```

For WebAssembly support:
```bash
pip install mcp-plugin-sdk[wasm]
```

For development:
```bash
pip install mcp-plugin-sdk[dev]
```

### Creating Your First Plugin

```python
from mcp_plugin_sdk import AnalyzerPlugin, AnalysisRequest, AnalysisResponse

class MyAnalyzerPlugin(AnalyzerPlugin):
    async def initialize(self) -> None:
        self.logger.info("Plugin initialized")
    
    async def analyze(self, request: AnalysisRequest) -> AnalysisResponse:
        # Your analysis logic here
        return AnalysisResponse(
            request_id=request.request_id,
            status="success",
            vulnerabilities=[],
            analysis_duration=0.1
        )
    
    def get_supported_types(self) -> List[str]:
        return ["source_code"]
    
    def get_rules_info(self) -> Dict[str, Any]:
        return {"total_rules": 0}
```

## Plugin Types

### Analyzer Plugins

Analyzer plugins perform vulnerability analysis and threat detection:

```python
from mcp_plugin_sdk import AnalyzerPlugin, VulnerabilityResult, Severity

class VulnerabilityAnalyzer(AnalyzerPlugin):
    async def analyze(self, request: AnalysisRequest) -> AnalysisResponse:
        vulnerabilities = []
        
        # Analyze source code for vulnerabilities
        for pattern in self.get_patterns():
            matches = pattern.finditer(request.target_data.get('content', ''))
            for match in matches:
                vuln = VulnerabilityResult(
                    vulnerability_id=f"vuln_{match.start()}",
                    title="Security Issue Detected",
                    severity=Severity.HIGH,
                    vulnerability_type="code_injection",
                    # ... other fields
                )
                vulnerabilities.append(vuln)
        
        return AnalysisResponse(
            request_id=request.request_id,
            status="success",
            vulnerabilities=vulnerabilities
        )
```

### Enricher Plugins

Enricher plugins add threat intelligence and contextual information:

```python
from mcp_plugin_sdk import EnricherPlugin, EnrichmentResult

class ThreatIntelEnricher(EnricherPlugin):
    async def enrich(self, request: EnrichmentRequest) -> EnrichmentResponse:
        enrichments = []
        
        if request.data_type == "ip":
            # Look up IP reputation
            reputation = await self.lookup_ip_reputation(request.data_value)
            
            enrichment = EnrichmentResult(
                source_type="ip",
                source_value=request.data_value,
                enrichment_type="reputation",
                enriched_data=reputation,
                confidence="high",
                source_name="threat-intel-db"
            )
            enrichments.append(enrichment)
        
        return EnrichmentResponse(
            request_id=request.request_id,
            status="success",
            enrichments=enrichments
        )
```

### Scanner Plugins

Scanner plugins perform active security scanning:

```python
from mcp_plugin_sdk import ScannerPlugin, ScanResult

class WebAppScanner(ScannerPlugin):
    async def start_scan(self, request: ScanRequest) -> ScanResponse:
        scan_id = str(uuid.uuid4())
        
        # Start background scan
        asyncio.create_task(self._perform_scan(scan_id, request))
        
        return ScanResponse(
            request_id=request.request_id,
            scan_id=scan_id,
            status="running",
            progress=0.0
        )
    
    async def _perform_scan(self, scan_id: str, request: ScanRequest):
        # Perform actual scanning
        findings = await self.scan_target(request.target)
        
        result = ScanResult(
            scan_id=scan_id,
            target=request.target,
            scan_type="web_application",
            status="completed",
            findings=findings
        )
        
        # Update scan status
        self._scan_results[scan_id] = result
```

### Notifier Plugins

Notifier plugins handle alert delivery:

```python
from mcp_plugin_sdk import NotifierPlugin, NotificationResult

class SlackNotifier(NotifierPlugin):
    async def send_notification(self, request: NotificationRequest) -> NotificationResponse:
        results = []
        
        for channel in request.channels:
            if channel == "slack":
                success = await self._send_slack_message(
                    request.title,
                    request.message,
                    request.recipients.get("slack", [])
                )
                
                result = NotificationResult(
                    notification_id=str(uuid.uuid4()),
                    channel=channel,
                    success=success,
                    delivered_at=datetime.now() if success else None
                )
                results.append(result)
        
        return NotificationResponse(
            request_id=request.request_id,
            notification_id=str(uuid.uuid4()),
            status="success" if all(r.success for r in results) else "partial",
            results=results
        )
```

## Configuration Management

### Plugin Configuration

Create a `plugin.json` manifest file:

```json
{
  "name": "my-analyzer",
  "version": "1.0.0",
  "description": "Custom vulnerability analyzer",
  "plugin_type": "analyzer",
  "config_schema": {
    "type": "object",
    "properties": {
      "patterns": {
        "type": "array",
        "items": {"type": "string"}
      },
      "severity_threshold": {
        "type": "string",
        "enum": ["low", "medium", "high", "critical"]
      }
    }
  },
  "default_config": {
    "patterns": ["eval\\(", "exec\\("],
    "severity_threshold": "medium"
  },
  "entry_point": "my_analyzer:MyAnalyzerPlugin"
}
```

### Dynamic Configuration

Access configuration in your plugin:

```python
class MyPlugin(AnalyzerPlugin):
    async def initialize(self):
        patterns = self.config.get('patterns', [])
        threshold = self.config.get('severity_threshold', 'medium')
        
        # Configuration is automatically reloaded when changed
        
    async def _on_config_changed(self, new_config: Dict[str, Any]):
        # Handle configuration updates
        self.logger.info("Configuration updated")
        await self.reload_patterns(new_config.get('patterns', []))
```

## Event System

### Subscribing to Events

```python
from mcp_plugin_sdk import SecurityEvent, EventFilter

class EventProcessor(BasePlugin):
    async def initialize(self):
        # Subscribe to vulnerability events
        await self.event_bus.subscribe(
            subscriber_id=self.plugin_id,
            callback=self.handle_vulnerability_event,
            filters=EventFilter(
                event_types=["security.vulnerability_detected"],
                min_priority="high"
            )
        )
    
    async def handle_vulnerability_event(self, event: SecurityEvent):
        self.logger.info(f"Received vulnerability: {event.data}")
        
        # Process the event
        if event.data.get('severity') == 'critical':
            await self.escalate_vulnerability(event)
```

### Publishing Events

```python
async def publish_finding(self, vulnerability):
    event = SecurityEvent(
        event_type="security.vulnerability_detected",
        source=self.plugin_id,
        data={
            'vulnerability_id': vulnerability.vulnerability_id,
            'severity': vulnerability.severity,
            'component': vulnerability.affected_component
        },
        priority=vulnerability.severity,
        tags=['static-analysis', 'code-injection']
    )
    
    await self.event_bus.publish(event)
```

## WebAssembly Plugins

### Creating WASM Plugins

Compile your plugin to WebAssembly for enhanced security:

```c
// plugin.c
#include <stdio.h>

// Host function declarations
extern void log_info(int level, const char* message, int length);

// Plugin functions
void plugin_init() {
    const char* msg = "WASM Plugin initialized";
    log_info(1, msg, strlen(msg));
}

int analyze_data(const char* data, int length) {
    // Analysis logic
    return 0;  // Number of vulnerabilities found
}

void plugin_shutdown() {
    const char* msg = "WASM Plugin shutting down";
    log_info(1, msg, strlen(msg));
}
```

Compile with Emscripten:
```bash
emcc plugin.c -o plugin.wasm -s WASM=1 -s EXPORTED_FUNCTIONS='["_plugin_init","_analyze_data","_plugin_shutdown"]'
```

### Loading WASM Plugins

```python
from mcp_plugin_sdk.runtime.wasm import WasmPluginLoader, WasmResourceLimits

loader = WasmPluginLoader()

# Set resource limits
limits = WasmResourceLimits(
    max_memory_bytes=32 * 1024 * 1024,  # 32MB
    max_execution_time_ms=10000,  # 10 seconds
    max_fuel=500000  # Computation limit
)

# Load WASM plugin
plugin = await loader.load_plugin(
    wasm_file=Path("plugin.wasm"),
    context=plugin_context,
    limits=limits
)

# Call WASM functions
result = await plugin.call_wasm_function("analyze_data", ["input data"])
```

## Security Model

### Capability-Based Security

Plugins declare required permissions:

```json
{
  "capabilities": {
    "required_permissions": [
      "file_system_access",
      "network_access"
    ],
    "network_access": true,
    "file_system_access": true,
    "database_access": false
  }
}
```

### Sandboxing

Plugins run in isolated environments:

```python
# Registry configuration
config = PluginRegistryConfig(
    sandbox_plugins=True,
    allowed_permissions={"file_system_access", "network_access"},
    max_plugin_memory_mb=256,
    max_plugin_cpu_percent=25
)
```

## Error Handling

### Plugin Exceptions

```python
from mcp_plugin_sdk.utils.exceptions import PluginError, ConfigurationError

class MyPlugin(AnalyzerPlugin):
    async def analyze(self, request):
        try:
            # Analysis logic
            pass
        except ValueError as e:
            raise PluginError(f"Invalid input: {e}")
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            raise PluginError("Analysis failed")
```

### Error Recovery

```python
async def initialize(self):
    try:
        await self.load_models()
    except Exception as e:
        self.logger.warning(f"Failed to load models: {e}")
        # Fallback to basic analysis
        self.use_basic_analysis = True
```

## Testing Plugins

### Unit Testing

```python
import pytest
from mcp_plugin_sdk import PluginContext, AnalysisRequest

@pytest.mark.asyncio
async def test_analyzer_plugin():
    # Create test context
    context = PluginContext(
        plugin_id="test-plugin",
        config={"patterns": ["test_pattern"]},
        # ... other required fields
    )
    
    # Create plugin instance
    plugin = MyAnalyzerPlugin(context)
    await plugin.initialize()
    
    # Test analysis
    request = AnalysisRequest(
        request_id="test-123",
        target_type="source_code",
        target_data={"content": "test code"}
    )
    
    response = await plugin.analyze(request)
    
    assert response.status == "success"
    assert len(response.vulnerabilities) >= 0
```

### Integration Testing

```python
@pytest.mark.asyncio
async def test_plugin_with_registry():
    # Start plugin registry
    registry = PluginRegistry(config)
    await registry.start()
    
    # Load plugin
    await registry.load_plugin("my-analyzer")
    
    # Test plugin functionality
    plugin = registry.get_plugin("my-analyzer")
    assert plugin is not None
    
    # Test analysis through registry
    # ...
    
    await registry.stop()
```

## Deployment

### Plugin Package Structure

```
my-analyzer-plugin/
├── plugin.json           # Plugin manifest
├── src/
│   ├── __init__.py
│   └── analyzer.py       # Plugin implementation
├── tests/
│   └── test_analyzer.py
├── config/
│   └── default.yaml      # Default configuration
├── docs/
│   └── README.md
└── requirements.txt      # Dependencies
```

### Installation

1. Package your plugin:
```bash
python setup.py sdist bdist_wheel
```

2. Install in plugin directory:
```bash
pip install my-analyzer-plugin -t /opt/mcp/plugins/
```

3. Register with plugin registry:
```bash
curl -X POST http://registry:8090/api/v1/discovery \
  -d '{"directories": ["/opt/mcp/plugins"]}'
```

### Docker Deployment

```dockerfile
FROM python:3.11-slim

# Install plugin SDK
RUN pip install mcp-plugin-sdk

# Copy plugin
COPY my-analyzer-plugin/ /opt/mcp/plugins/my-analyzer/

# Set working directory
WORKDIR /opt/mcp/plugins

# Run plugin registry
CMD ["python", "-m", "mcp_plugin_sdk.registry"]
```

## Best Practices

### Performance

1. **Async Operations**: Use async/await for I/O operations
2. **Resource Limits**: Set appropriate memory and CPU limits
3. **Caching**: Cache expensive computations and external API calls
4. **Batching**: Process multiple items together when possible

```python
class EfficientAnalyzer(AnalyzerPlugin):
    def __init__(self, context):
        super().__init__(context)
        self._cache = {}
    
    async def analyze(self, request):
        # Check cache first
        cache_key = self._generate_cache_key(request)
        if cache_key in self._cache:
            return self._cache[cache_key]
        
        # Perform analysis
        result = await self._perform_analysis(request)
        
        # Cache result
        self._cache[cache_key] = result
        return result
```

### Security

1. **Input Validation**: Always validate input data
2. **Sandboxing**: Use WASM for untrusted plugins
3. **Permissions**: Request minimal required permissions
4. **Secrets**: Never hardcode credentials

```python
class SecureAnalyzer(AnalyzerPlugin):
    async def analyze(self, request):
        # Validate input
        if not self.validate_request(request):
            raise PluginError("Invalid request")
        
        # Sanitize file paths
        file_path = self._sanitize_path(request.target_data.get('file_path'))
        
        # Check permissions
        if not self._has_permission('file_system_access'):
            raise SecurityError("File system access not permitted")
```

### Error Handling

1. **Graceful Degradation**: Continue operation when possible
2. **Detailed Logging**: Log errors with context
3. **Recovery**: Implement retry logic for transient failures

```python
async def robust_analysis(self, request):
    max_retries = 3
    for attempt in range(max_retries):
        try:
            return await self._perform_analysis(request)
        except TransientError as e:
            if attempt < max_retries - 1:
                self.logger.warning(f"Analysis failed (attempt {attempt + 1}): {e}")
                await asyncio.sleep(2 ** attempt)  # Exponential backoff
            else:
                raise PluginError(f"Analysis failed after {max_retries} attempts")
```

## API Reference

See the [API documentation](./docs/api.md) for detailed interface specifications.

## Examples

Check the [examples directory](./examples/) for complete plugin implementations:

- [Static Code Analyzer](./examples/static-analyzer/)
- [Network Scanner](./examples/network-scanner/)
- [Threat Intel Enricher](./examples/threat-intel/)
- [Slack Notifier](./examples/slack-notifier/)
- [WASM Security Scanner](./examples/wasm-scanner/)

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Run the test suite: `pytest`
5. Submit a pull request

## License

Apache License 2.0 - see [LICENSE](LICENSE) for details.

## Support

- Documentation: https://docs.mcp-security.com/plugins/
- Issues: https://github.com/mcp-security/platform/issues
- Discussions: https://github.com/mcp-security/platform/discussions
- Email: platform@mcp-security.com