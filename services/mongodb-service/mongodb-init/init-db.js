// MongoDB initialization script for MCP Security Platform

// Switch to the MCP Security database
db = db.getSiblingDB('mcp_security');

// Create collections with validation
db.createCollection('sbom_documents', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['id', 'name', 'version', 'format', 'spec_version', 'created_by', 'source'],
      properties: {
        id: {
          bsonType: 'string',
          description: 'Unique identifier for the SBOM document'
        },
        name: {
          bsonType: 'string',
          description: 'Name of the SBOM document'
        },
        version: {
          bsonType: 'string',
          description: 'Version of the SBOM document'
        },
        format: {
          bsonType: 'string',
          enum: ['spdx-json', 'cyclonedx-json', 'spdx-xml', 'cyclonedx-xml', 'spdx-yaml', 'cyclonedx-yaml', 'spdx-tag-value', 'syft-json'],
          description: 'Format of the SBOM document'
        },
        spec_version: {
          bsonType: 'string',
          description: 'Specification version'
        },
        status: {
          bsonType: 'string',
          enum: ['pending', 'processing', 'completed', 'failed', 'archived'],
          description: 'Processing status'
        },
        created_by: {
          bsonType: 'string',
          description: 'User who created the document'
        },
        source: {
          bsonType: 'string',
          description: 'Source of the SBOM document'
        }
      }
    }
  }
});

db.createCollection('components', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['id', 'name', 'type'],
      properties: {
        id: {
          bsonType: 'string',
          description: 'Unique identifier for the component'
        },
        name: {
          bsonType: 'string',
          description: 'Name of the component'
        },
        type: {
          bsonType: 'string',
          enum: ['application', 'container', 'device', 'file', 'firmware', 'framework', 'library', 'operating-system', 'platform', 'other'],
          description: 'Type of component'
        }
      }
    }
  }
});

db.createCollection('vulnerabilities', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['id', 'severity'],
      properties: {
        id: {
          bsonType: 'string',
          description: 'Unique identifier for the vulnerability'
        },
        severity: {
          bsonType: 'string',
          enum: ['low', 'medium', 'high', 'critical'],
          description: 'Severity level of the vulnerability'
        }
      }
    }
  }
});

// Create indexes for performance
print('Creating indexes...');

// SBOM documents indexes
db.sbom_documents.createIndex({ 'id': 1 }, { unique: true });
db.sbom_documents.createIndex({ 'name': 1 });
db.sbom_documents.createIndex({ 'version': 1 });
db.sbom_documents.createIndex({ 'format': 1 });
db.sbom_documents.createIndex({ 'status': 1 });
db.sbom_documents.createIndex({ 'created_by': 1 });
db.sbom_documents.createIndex({ 'source': 1 });
db.sbom_documents.createIndex({ 'created_at': -1 });
db.sbom_documents.createIndex({ 'updated_at': -1 });

// Compound indexes
db.sbom_documents.createIndex({ 'name': 1, 'version': 1 });
db.sbom_documents.createIndex({ 'status': 1, 'created_at': -1 });
db.sbom_documents.createIndex({ 'source': 1, 'created_at': -1 });

// Security-related indexes
db.sbom_documents.createIndex({ 'vulnerable_components': 1 });
db.sbom_documents.createIndex({ 'high_severity_vulnerabilities': 1 });
db.sbom_documents.createIndex({ 'tags': 1 });
db.sbom_documents.createIndex({ 'category': 1 });
db.sbom_documents.createIndex({ 'environment': 1 });

// Component-related indexes
db.sbom_documents.createIndex({ 'components.name': 1 });
db.sbom_documents.createIndex({ 'components.version': 1 });
db.sbom_documents.createIndex({ 'components.type': 1 });
db.sbom_documents.createIndex({ 'components.package_url': 1 });

// Text search index
db.sbom_documents.createIndex({
  'name': 'text',
  'description': 'text',
  'components.name': 'text',
  'components.description': 'text'
});

// Components collection indexes
db.components.createIndex({ 'id': 1 }, { unique: true });
db.components.createIndex({ 'name': 1 });
db.components.createIndex({ 'version': 1 });
db.components.createIndex({ 'type': 1 });
db.components.createIndex({ 'package_url': 1 });
db.components.createIndex({ 'created_at': -1 });

// Vulnerabilities collection indexes
db.vulnerabilities.createIndex({ 'id': 1 }, { unique: true });
db.vulnerabilities.createIndex({ 'cve_id': 1 });
db.vulnerabilities.createIndex({ 'severity': 1 });
db.vulnerabilities.createIndex({ 'published_date': -1 });

// Create user for the application
db.createUser({
  user: 'mcp_app',
  pwd: 'mcp_app_password',
  roles: [
    {
      role: 'readWrite',
      db: 'mcp_security'
    }
  ]
});

// Insert sample data for testing
print('Inserting sample data...');

// Sample SBOM document
db.sbom_documents.insertOne({
  id: 'sbom-sample-001',
  name: 'Sample Web Application',
  version: '1.0.0',
  format: 'spdx-json',
  spec_version: '2.3',
  data_license: 'CC0-1.0',
  document_namespace: 'https://example.com/sbom/sample-web-app-1.0.0',
  status: 'completed',
  raw_content: '{"spdxVersion": "SPDX-2.3", "name": "Sample Web Application", "packages": []}',
  parsed_content: {
    spdxVersion: 'SPDX-2.3',
    name: 'Sample Web Application',
    packages: []
  },
  components: [
    {
      id: 'comp-001',
      name: 'express',
      version: '4.18.2',
      type: 'library',
      package_url: 'pkg:npm/express@4.18.2',
      licenses: [
        {
          name: 'MIT',
          is_osi_approved: true
        }
      ],
      vulnerabilities: [],
      created_at: new Date(),
      updated_at: new Date()
    }
  ],
  total_components: 1,
  vulnerable_components: 0,
  high_severity_vulnerabilities: 0,
  medium_severity_vulnerabilities: 0,
  low_severity_vulnerabilities: 0,
  license_risks: [],
  created_at: new Date(),
  updated_at: new Date(),
  created_by: 'system',
  source: 'sample-data',
  source_reference: 'init-script',
  category: 'web-application',
  environment: 'development',
  tags: ['sample', 'web', 'nodejs']
});

// Sample component
db.components.insertOne({
  id: 'comp-001',
  name: 'express',
  version: '4.18.2',
  type: 'library',
  supplier: 'npm',
  description: 'Fast, unopinionated, minimalist web framework',
  homepage: 'https://expressjs.com',
  package_url: 'pkg:npm/express@4.18.2',
  licenses: [
    {
      name: 'MIT',
      is_osi_approved: true
    }
  ],
  vulnerabilities: [],
  created_at: new Date(),
  updated_at: new Date()
});

// Sample vulnerability
db.vulnerabilities.insertOne({
  id: 'vuln-001',
  cve_id: 'CVE-2023-26136',
  severity: 'medium',
  score: 5.3,
  description: 'Sample vulnerability description',
  published_date: new Date('2023-06-15'),
  modified_date: new Date('2023-06-20'),
  references: [
    'https://nvd.nist.gov/vuln/detail/CVE-2023-26136'
  ],
  affected_versions: ['< 4.18.2'],
  fixed_versions: ['4.18.2']
});

print('MongoDB initialization completed successfully!');
print('Database: mcp_security');
print('Collections created: sbom_documents, components, vulnerabilities');
print('Indexes created for optimal performance');
print('Sample data inserted for testing');
print('Application user created: mcp_app');