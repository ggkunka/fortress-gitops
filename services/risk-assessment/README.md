# Risk Assessment Service

The Risk Assessment Service provides comprehensive risk assessment capabilities with LLM integration for enhanced security analysis. It processes correlation results from the Correlation Engine and generates detailed risk assessments using advanced AI models.

## Features

### Core Capabilities
- **LLM-Enhanced Analysis**: Integration with OpenAI, Anthropic, and other LLM providers
- **Multi-Method Risk Calculation**: Qualitative, quantitative, semi-quantitative, Monte Carlo, and fuzzy logic
- **Comprehensive Risk Modeling**: Impact, likelihood, vulnerability, and threat assessment
- **Automated Recommendations**: AI-generated risk mitigation strategies
- **Risk Profiling**: Entity-based risk tracking and trending
- **Real-time Processing**: Event-driven assessment pipeline

### Advanced Features
- **Multiple Risk Frameworks**: NIST, ISO 27001, and custom frameworks
- **Contextual Analysis**: Organization profile and threat landscape integration
- **Risk Trending**: Historical analysis and predictive modeling
- **Mitigation Tracking**: Implementation planning and progress monitoring
- **Compliance Mapping**: Regulatory requirement integration

## Architecture

### Core Components

#### 1. Risk Assessment Engine
- **Purpose**: Orchestrates the complete risk assessment process
- **Features**:
  - Correlation result processing
  - Context gathering and caching
  - LLM analysis orchestration
  - Risk calculation coordination
  - Recommendation generation
  - Risk profile updates

#### 2. LLM Client Manager
- **Purpose**: Manages integration with multiple LLM providers
- **Features**:
  - Provider abstraction layer
  - Fallback and load balancing
  - Response parsing and validation
  - Usage tracking and optimization
  - Custom prompt engineering

#### 3. Risk Calculator
- **Purpose**: Implements various risk calculation methodologies
- **Features**:
  - Multiple calculation methods
  - Risk vector analysis
  - Confidence scoring
  - Trend analysis
  - Statistical modeling

### Data Models

#### Risk Assessment
```python
class RiskAssessment:
    - id: UUID
    - correlation_result_id: UUID
    - title: str
    - risk_level: RiskLevel
    - risk_score: float (0-100)
    - confidence_score: float (0-100)
    - risk_category: RiskCategory
    - impact_score: float
    - likelihood_score: float
    - llm_analysis: Dict
    - recommendations: List
    - status: RiskAssessmentStatus
```

#### Risk Factor
```python
class RiskFactor:
    - id: UUID
    - assessment_id: UUID
    - factor_name: str
    - factor_type: str
    - weight: float (0-1)
    - impact: float (0-100)
    - likelihood: float (0-100)
    - evidence: Dict
```

#### Risk Mitigation
```python
class RiskMitigation:
    - id: UUID
    - assessment_id: UUID
    - mitigation_name: str
    - mitigation_type: str
    - effectiveness_score: float (0-100)
    - implementation_cost: float (0-100)
    - priority: int (1-10)
    - status: str
```

## API Documentation

### Risk Assessment Operations

#### Create Assessment
```http
POST /api/v1/risk-assessment/assessments
Content-Type: application/json

{
    "correlation_result_id": "uuid",
    "assessment_type": "automated",
    "priority": 5,
    "context": {},
    "requested_by": "user_id"
}
```

#### Get Assessment
```http
GET /api/v1/risk-assessment/assessments/{assessment_id}
```

#### Update Assessment
```http
PUT /api/v1/risk-assessment/assessments/{assessment_id}
Content-Type: application/json

{
    "status": "reviewed",
    "risk_level": "high",
    "updated_by": "user_id"
}
```

#### List Assessments
```http
GET /api/v1/risk-assessment/assessments?status=completed&risk_level=high&limit=50
```

### Risk Profile Operations

#### Get Risk Profiles
```http
GET /api/v1/risk-assessment/profiles?entity_type=user&risk_level=high
```

### Statistics and Reporting

#### Get Risk Statistics
```http
GET /api/v1/risk-assessment/statistics?time_range=24h
```

Response:
```json
{
    "total_assessments": 150,
    "risk_level_breakdown": {
        "critical": 5,
        "high": 25,
        "medium": 80,
        "low": 35,
        "informational": 5
    },
    "average_risk_score": 45.2,
    "total_mitigations": 75
}
```

## Configuration

### Environment Variables

#### LLM Configuration
```bash
# OpenAI
OPENAI_API_KEY=your_openai_key
OPENAI_MODEL=gpt-4

# Anthropic
ANTHROPIC_API_KEY=your_anthropic_key
ANTHROPIC_MODEL=claude-3-sonnet-20240229

# Azure OpenAI
AZURE_OPENAI_ENDPOINT=your_endpoint
AZURE_OPENAI_API_KEY=your_key
AZURE_OPENAI_API_VERSION=2023-12-01-preview
```

#### Database Configuration
```bash
DATABASE_URL=postgresql://user:pass@localhost/riskassessment
```

#### Redis Configuration
```bash
REDIS_URL=redis://localhost:6379
```

### Risk Calculation Parameters

#### Risk Thresholds
```python
RISK_THRESHOLDS = {
    "critical": 85,
    "high": 70,
    "medium": 40,
    "low": 15,
    "informational": 0
}
```

#### Impact Weights
```python
IMPACT_WEIGHTS = {
    "financial": 0.3,
    "operational": 0.25,
    "reputational": 0.2,
    "compliance": 0.15,
    "technical": 0.1
}
```

## LLM Integration

### Supported Providers
- **OpenAI**: GPT-4, GPT-3.5 Turbo
- **Anthropic**: Claude-3 Sonnet, Claude-3 Haiku
- **Azure OpenAI**: Enterprise-grade OpenAI models
- **Custom**: Extensible for additional providers

### Prompt Engineering

#### Risk Assessment Prompt
```python
system_prompt = """You are a cybersecurity risk assessment expert.
Analyze security correlation results and provide comprehensive risk assessments.

Response format (JSON):
{
    "risk_level": "critical|high|medium|low|informational",
    "risk_score": 0-100,
    "confidence": 0.0-1.0,
    "impact_score": 0-100,
    "likelihood_score": 0-100,
    "risk_factors": [...],
    "reasoning": "detailed_reasoning"
}
"""
```

#### Recommendation Generation
```python
system_prompt = """You are a cybersecurity expert specializing in risk mitigation.
Generate actionable recommendations for risk mitigation.

Response format (JSON):
{
    "recommendations": [
        {
            "title": "recommendation_title",
            "description": "detailed_description",
            "type": "preventive|detective|corrective",
            "priority": 1-10,
            "effectiveness": 0-100
        }
    ]
}
"""
```

## Risk Calculation Methods

### 1. Qualitative Risk Assessment
- **Purpose**: Traditional risk matrix approach
- **Features**: Impact/likelihood mapping, categorical scoring
- **Use Case**: Quick assessments, limited data scenarios

### 2. Quantitative Risk Analysis (QRA)
- **Purpose**: Numerical risk calculation
- **Features**: SLE/ALE calculations, statistical modeling
- **Use Case**: Financial impact analysis, ROI calculations

### 3. Semi-Quantitative Assessment
- **Purpose**: Hybrid approach combining qualitative and quantitative
- **Features**: Weighted scoring, contextual adjustments
- **Use Case**: General-purpose risk assessment

### 4. Monte Carlo Simulation
- **Purpose**: Probabilistic risk modeling
- **Features**: Statistical distributions, uncertainty quantification
- **Use Case**: Complex scenarios, uncertainty analysis

### 5. Fuzzy Logic Assessment
- **Purpose**: Handles imprecise and uncertain data
- **Features**: Membership functions, rule-based inference
- **Use Case**: Ambiguous scenarios, expert knowledge integration

## Deployment

### Docker Deployment
```bash
# Build image
docker build -t mcp-risk-assessment .

# Run container
docker run -p 8002:8002 \
    -e DATABASE_URL=postgresql://user:pass@db/riskassessment \
    -e REDIS_URL=redis://redis:6379 \
    -e OPENAI_API_KEY=your_key \
    mcp-risk-assessment
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: risk-assessment
spec:
  replicas: 3
  selector:
    matchLabels:
      app: risk-assessment
  template:
    metadata:
      labels:
        app: risk-assessment
    spec:
      containers:
      - name: risk-assessment
        image: mcp-risk-assessment:latest
        ports:
        - containerPort: 8002
        env:
        - name: DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: risk-assessment-secrets
              key: database-url
        - name: OPENAI_API_KEY
          valueFrom:
            secretKeyRef:
              name: risk-assessment-secrets
              key: openai-api-key
```

## Monitoring and Observability

### Metrics
- `risk_assessment_engine_assessments_total`: Total assessments processed
- `risk_assessment_engine_processing_time`: Assessment processing time
- `llm_client_requests_total`: LLM API requests
- `llm_client_response_time`: LLM response time
- `risk_calculator_calculations_total`: Risk calculations performed

### Logging
- Structured logging with correlation IDs
- Assessment lifecycle tracking
- Error tracking and debugging
- Performance monitoring

### Tracing
- End-to-end request tracing
- LLM call tracing
- Database operation tracing
- Event processing tracing

## Security Considerations

### Data Protection
- Sensitive data encryption at rest and in transit
- PII handling and anonymization
- Audit logging for compliance
- Access control and authentication

### LLM Security
- API key management and rotation
- Rate limiting and quota management
- Response validation and sanitization
- Fallback mechanisms for availability

### Network Security
- TLS/SSL encryption
- Network segmentation
- API gateway integration
- DDoS protection

## Testing

### Unit Tests
```bash
# Run unit tests
pytest tests/unit/

# Run with coverage
pytest --cov=services/risk_assessment tests/unit/
```

### Integration Tests
```bash
# Run integration tests
pytest tests/integration/

# Run with database
pytest tests/integration/ --db-url=postgresql://test:test@localhost/test
```

### Load Testing
```bash
# Run load tests
locust -f tests/load/locustfile.py --host=http://localhost:8002
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Implement changes with tests
4. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.