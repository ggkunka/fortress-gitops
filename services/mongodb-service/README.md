# MongoDB Service

The MongoDB Service provides comprehensive SBOM (Software Bill of Materials) document storage and management capabilities for the MCP Security Platform.

## Features

### Core Functionality
- **SBOM Document Storage**: Complete SBOM document lifecycle management
- **Multi-Format Support**: SPDX, CycloneDX, Syft in JSON, XML, YAML formats
- **Component Analysis**: Detailed component tracking and analysis
- **Vulnerability Management**: Integration with vulnerability databases
- **License Compliance**: License risk analysis and compliance tracking

### Advanced Capabilities
- **Real-time Processing**: Asynchronous SBOM processing and enrichment
- **Search & Filtering**: Advanced search capabilities with full-text search
- **Security Analytics**: Comprehensive security metrics and statistics
- **Relationship Mapping**: Parent-child SBOM relationships
- **Compliance Tracking**: Policy violation detection and reporting

## Architecture

### Components

#### Models (`models/sbom.py`)
- **SBOMDocument**: Primary SBOM document model
- **ComponentModel**: Individual component representation
- **VulnerabilityModel**: Vulnerability information
- **LicenseModel**: License details and compliance data
- **Query Models**: Search and filtering capabilities

#### Services
- **SBOMRepository** (`services/sbom_repository.py`): Core data access layer
- **SBOMProcessor** (`services/sbom_processor.py`): Document parsing and enrichment

#### API (`api/sbom_api.py`)
- RESTful endpoints for SBOM operations
- File upload capabilities
- Advanced search and filtering
- Statistics and analytics endpoints

### Database Schema

#### Collections
- `sbom_documents`: Primary SBOM storage
- `components`: Component analysis cache
- `vulnerabilities`: Vulnerability intelligence cache

#### Indexes
- Performance-optimized indexes for all search operations
- Full-text search capabilities
- Compound indexes for complex queries

## API Endpoints

### SBOM Management
- `POST /api/v1/sbom/sboms` - Create new SBOM document
- `POST /api/v1/sbom/sboms/{id}/upload` - Upload SBOM content
- `GET /api/v1/sbom/sboms/{id}` - Get SBOM document
- `PUT /api/v1/sbom/sboms/{id}` - Update SBOM document
- `DELETE /api/v1/sbom/sboms/{id}` - Delete SBOM document

### Search & Analysis
- `POST /api/v1/sbom/sboms/search` - Search SBOM documents
- `GET /api/v1/sbom/sboms/{id}/components` - Get components
- `GET /api/v1/sbom/sboms/{id}/vulnerabilities` - Get vulnerabilities
- `GET /api/v1/sbom/sboms/{id}/licenses` - Get licenses

### Processing
- `POST /api/v1/sbom/sboms/{id}/reprocess` - Reprocess SBOM document

### Analytics
- `GET /api/v1/sbom/statistics` - Get comprehensive statistics

## Supported SBOM Formats

### SPDX (Software Package Data Exchange)
- **JSON**: `spdx-json`
- **XML**: `spdx-xml`
- **YAML**: `spdx-yaml`
- **Tag-Value**: `spdx-tag-value`

### CycloneDX
- **JSON**: `cyclonedx-json`
- **XML**: `cyclonedx-xml`
- **YAML**: `cyclonedx-yaml`

### Syft
- **JSON**: `syft-json`

## Component Types

- Application
- Container
- Device
- File
- Firmware
- Framework
- Library
- Operating System
- Platform
- Other

## Security Features

### Vulnerability Integration
- Automatic vulnerability enrichment
- Multiple severity levels (Low, Medium, High, Critical)
- CVE integration
- CVSS scoring

### License Compliance
- License risk analysis
- OSI approval tracking
- Copyleft detection
- Compliance reporting

### Data Security
- Input sanitization
- Secure file handling
- Audit logging
- Access controls

## Deployment

### Docker Compose
```bash
cd services/mongodb-service
docker-compose up -d
```

### Environment Variables
- `MONGODB_URL`: MongoDB connection string
- `MONGODB_DATABASE`: Database name
- `REDIS_URL`: Redis connection string
- `LOG_LEVEL`: Logging level
- `SECRET_KEY`: Application secret key

### Services
- **MongoDB**: Document database (port 27017)
- **Mongo Express**: Web-based admin interface (port 8081)
- **MongoDB Service**: Main application (port 8010)
- **Redis**: Cache and message broker (port 6379)

## Usage Examples

### Create SBOM Document
```bash
curl -X POST "http://localhost:8010/api/v1/sbom/sboms" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Application",
    "version": "1.0.0",
    "format": "spdx-json",
    "spec_version": "2.3",
    "source": "build-system",
    "category": "web-application",
    "environment": "production",
    "tags": ["web", "nodejs"]
  }'
```

### Upload SBOM Content
```bash
curl -X POST "http://localhost:8010/api/v1/sbom/sboms/{id}/upload" \
  -F "file=@sbom.spdx.json"
```

### Search SBOM Documents
```bash
curl -X POST "http://localhost:8010/api/v1/sbom/sboms/search" \
  -H "Content-Type: application/json" \
  -d '{
    "has_vulnerabilities": true,
    "environment": "production",
    "limit": 10
  }'
```

### Get Statistics
```bash
curl "http://localhost:8010/api/v1/sbom/statistics?time_range=24h"
```

## Development

### Prerequisites
- Python 3.11+
- MongoDB 7.0+
- Redis 7.0+

### Setup
```bash
# Install dependencies
pip install -r requirements.txt

# Run development server
uvicorn main:app --reload --port 8010
```

### Testing
```bash
# Run tests
pytest tests/

# Run with coverage
pytest --cov=services/mongodb-service tests/
```

## Monitoring

### Health Check
```bash
curl http://localhost:8010/health
```

### Metrics
```bash
curl http://localhost:8010/metrics
```

### Observability
- OpenTelemetry tracing
- Prometheus metrics
- Structured logging
- Performance monitoring

## Integration

### Event Bus
- Publishes SBOM processing events
- Subscribes to vulnerability updates
- Integrates with correlation engine

### Shared Components
- Observability infrastructure
- Security middleware
- Configuration management
- Event bus integration

## Performance

### Optimizations
- MongoDB indexes for fast queries
- Async processing pipeline
- Connection pooling
- Caching strategies

### Scalability
- Horizontal scaling support
- Sharding capabilities
- Load balancing
- Performance monitoring

## Security Considerations

### Data Protection
- Encryption at rest and in transit
- Access control and authentication
- Input validation and sanitization
- Audit logging

### Compliance
- License risk assessment
- Vulnerability tracking
- Policy enforcement
- Compliance reporting

## Troubleshooting

### Common Issues
1. **MongoDB Connection**: Check connection string and credentials
2. **Processing Failures**: Review error logs and SBOM format
3. **Performance Issues**: Monitor indexes and query patterns
4. **Memory Usage**: Adjust processing batch sizes

### Logs
```bash
# View service logs
docker-compose logs -f mongodb-service

# View MongoDB logs
docker-compose logs -f mongodb
```

## Contributing

1. Follow the existing code structure
2. Add comprehensive tests
3. Update documentation
4. Ensure security best practices
5. Add observability instrumentation