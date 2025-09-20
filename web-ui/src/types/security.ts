// Enhanced Security Dashboard Types

// Role-based Access Control
export type UserRole = 'admin' | 'user' | 'viewer' | 'security-analyst' | 'compliance-officer';

export interface RolePermissions {
  role: UserRole;
  permissions: {
    clusters: {
      view: boolean;
      create: boolean;
      edit: boolean;
      delete: boolean;
      deploy: boolean;
    };
    repositories: {
      view: boolean;
      create: boolean;
      edit: boolean;
      delete: boolean;
      scan: boolean;
      push: boolean;
    };
    agents: {
      view: boolean;
      create: boolean;
      edit: boolean;
      delete: boolean;
      deploy: boolean;
      configure: boolean;
    };
    vulnerabilities: {
      view: boolean;
      patch: boolean;
      ignore: boolean;
      export: boolean;
    };
    dashboard: {
      view: boolean;
      customize: boolean;
      export: boolean;
    };
    users: {
      view: boolean;
      create: boolean;
      edit: boolean;
      delete: boolean;
      manage_roles: boolean;
    };
    system: {
      configure: boolean;
      backup: boolean;
      restore: boolean;
      audit: boolean;
    };
  };
}

// Security Dashboard Data Types
export interface SecurityMetrics {
  timestamp: Date;
  totalClusters: number;
  healthyClusters: number;
  totalVulnerabilities: number;
  criticalVulnerabilities: number;
  highVulnerabilities: number;
  mediumVulnerabilities: number;
  lowVulnerabilities: number;
  patchedVulnerabilities: number;
  newVulnerabilities: number;
  riskScore: number; // 0-100
  complianceScore: number; // 0-100
  securityPosture: 'excellent' | 'good' | 'fair' | 'poor' | 'critical';
}

// CVE Relationship Graph Types
export interface CVENode {
  id: string;
  type: 'cve' | 'cluster' | 'namespace' | 'pod' | 'container' | 'process' | 'syscall' | 'file' | 'network';
  label: string;
  severity?: 'critical' | 'high' | 'medium' | 'low';
  cvssScore?: number;
  description?: string;
  affectedComponents?: string[];
  patchAvailable?: boolean;
  exploitAvailable?: boolean;
  metadata: {
    [key: string]: any;
  };
  position?: {
    x: number;
    y: number;
  };
  size?: number;
  color?: string;
}

export interface CVEEdge {
  id: string;
  source: string;
  target: string;
  type: 'affects' | 'contains' | 'runs' | 'calls' | 'accesses' | 'communicates' | 'depends';
  weight?: number;
  label?: string;
  metadata?: {
    [key: string]: any;
  };
}

export interface SecurityGraph {
  nodes: CVENode[];
  edges: CVEEdge[];
  layout: 'force' | 'hierarchical' | 'circular' | 'grid';
  filters: {
    severity: string[];
    nodeTypes: string[];
    timeRange: string;
  };
}

// Patch Management Types
export interface PatchInfo {
  id: string;
  cveId: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  affectedImages: string[];
  patchVersion: string;
  releaseDate: Date;
  testingStatus: 'pending' | 'testing' | 'tested' | 'approved' | 'rejected';
  deploymentStatus: 'pending' | 'building' | 'built' | 'deploying' | 'deployed' | 'failed';
  rollbackAvailable: boolean;
  impactAssessment: {
    riskLevel: 'low' | 'medium' | 'high' | 'critical';
    affectedServices: string[];
    downtime: string;
    rollbackTime: string;
  };
  approvals: {
    securityTeam: boolean;
    devOpsTeam: boolean;
    businessOwner: boolean;
  };
  metadata: {
    [key: string]: any;
  };
}

export interface PatchBuild {
  id: string;
  patchId: string;
  baseImage: string;
  patchedImage: string;
  buildStatus: 'queued' | 'building' | 'built' | 'failed' | 'testing' | 'ready';
  buildLogs: string[];
  testResults: {
    securityScan: {
      passed: boolean;
      vulnerabilities: number;
      report: string;
    };
    functionalTest: {
      passed: boolean;
      results: string;
    };
    performanceTest: {
      passed: boolean;
      metrics: {
        cpuUsage: number;
        memoryUsage: number;
        responseTime: number;
      };
    };
  };
  createdAt: Date;
  completedAt?: Date;
  size: number; // in bytes
  layers: string[];
}

export interface PatchDeployment {
  id: string;
  patchId: string;
  clusterId: string;
  namespace: string;
  targetWorkloads: string[];
  strategy: 'rolling' | 'blue-green' | 'canary';
  status: 'pending' | 'deploying' | 'deployed' | 'failed' | 'rolled-back';
  progress: number; // 0-100
  startedAt: Date;
  completedAt?: Date;
  rollbackPlan: {
    available: boolean;
    previousVersion: string;
    estimatedTime: string;
  };
  healthChecks: {
    name: string;
    status: 'pending' | 'running' | 'passed' | 'failed';
    message: string;
  }[];
}

// Real-time Security Events
export interface SecurityEvent {
  id: string;
  timestamp: Date;
  type: 'vulnerability_detected' | 'patch_available' | 'security_breach' | 'compliance_violation' | 'anomaly_detected';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  source: {
    type: 'cluster' | 'container' | 'process' | 'network' | 'file';
    id: string;
    name: string;
  };
  affectedResources: {
    type: string;
    id: string;
    name: string;
  }[];
  recommendations: string[];
  automatedResponse?: {
    available: boolean;
    actions: string[];
    riskLevel: 'low' | 'medium' | 'high';
  };
  status: 'open' | 'investigating' | 'mitigating' | 'resolved' | 'false_positive';
  assignedTo?: string;
  tags: string[];
  metadata: {
    [key: string]: any;
  };
}

// Dashboard Widget Types
export interface DashboardWidget {
  id: string;
  type: 'metric' | 'chart' | 'graph' | 'table' | 'map' | 'timeline' | 'heatmap' | 'gauge';
  title: string;
  description?: string;
  position: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
  config: {
    dataSource: string;
    refreshInterval: number; // seconds
    filters?: {
      [key: string]: any;
    };
    visualization: {
      [key: string]: any;
    };
  };
  permissions: {
    view: UserRole[];
    edit: UserRole[];
  };
  isVisible: boolean;
  isResizable: boolean;
  isDraggable: boolean;
}

export interface DashboardLayout {
  id: string;
  name: string;
  description?: string;
  widgets: DashboardWidget[];
  theme: 'light' | 'dark' | 'security';
  layout: 'grid' | 'masonry' | 'flex';
  isDefault: boolean;
  isPublic: boolean;
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
  permissions: {
    view: UserRole[];
    edit: UserRole[];
    clone: UserRole[];
  };
}

// Threat Intelligence Types
export interface ThreatIntelligence {
  id: string;
  type: 'ioc' | 'ttp' | 'campaign' | 'actor' | 'malware';
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  confidence: number; // 0-100
  source: string;
  tags: string[];
  indicators: {
    type: 'ip' | 'domain' | 'hash' | 'url' | 'email';
    value: string;
    context: string;
  }[];
  relatedCVEs: string[];
  affectedSystems: string[];
  mitigations: string[];
  references: string[];
  firstSeen: Date;
  lastSeen: Date;
  isActive: boolean;
}

// Compliance and Audit Types
export interface ComplianceFramework {
  id: string;
  name: string;
  version: string;
  description: string;
  controls: ComplianceControl[];
  applicableTo: string[]; // cluster types, industries, etc.
}

export interface ComplianceControl {
  id: string;
  frameworkId: string;
  controlId: string;
  title: string;
  description: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  automatedCheck: boolean;
  checkScript?: string;
  remediation: string;
  references: string[];
}

export interface ComplianceAssessment {
  id: string;
  frameworkId: string;
  clusterId: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  overallScore: number; // 0-100
  results: {
    controlId: string;
    status: 'pass' | 'fail' | 'not_applicable' | 'manual_review';
    score: number;
    findings: string[];
    evidence: string[];
    remediation: string[];
  }[];
  startedAt: Date;
  completedAt?: Date;
  nextAssessment?: Date;
  reportUrl?: string;
}

// Advanced Analytics Types
export interface SecurityTrend {
  metric: string;
  timeframe: 'hour' | 'day' | 'week' | 'month' | 'quarter' | 'year';
  data: {
    timestamp: Date;
    value: number;
    change?: number; // percentage change from previous period
  }[];
  prediction?: {
    timestamp: Date;
    value: number;
    confidence: number;
  }[];
}

export interface RiskAssessment {
  id: string;
  clusterId: string;
  overallRisk: number; // 0-100
  riskFactors: {
    category: string;
    score: number;
    weight: number;
    description: string;
    mitigations: string[];
  }[];
  recommendations: {
    priority: 'critical' | 'high' | 'medium' | 'low';
    action: string;
    impact: string;
    effort: 'low' | 'medium' | 'high';
    timeline: string;
  }[];
  lastAssessed: Date;
  nextAssessment: Date;
  trend: 'improving' | 'stable' | 'degrading';
}

// Visualization Configuration Types
export interface VisualizationConfig {
  type: 'line' | 'bar' | 'pie' | 'scatter' | 'heatmap' | 'network' | 'sankey' | 'treemap';
  theme: 'light' | 'dark' | 'security';
  colors: {
    primary: string;
    secondary: string;
    success: string;
    warning: string;
    error: string;
    info: string;
    critical: string;
    high: string;
    medium: string;
    low: string;
  };
  animations: {
    enabled: boolean;
    duration: number;
    easing: string;
  };
  interactions: {
    zoom: boolean;
    pan: boolean;
    select: boolean;
    hover: boolean;
    tooltip: boolean;
  };
}

// Export types for API responses
export interface SecurityDashboardData {
  metrics: SecurityMetrics;
  events: SecurityEvent[];
  trends: SecurityTrend[];
  threats: ThreatIntelligence[];
  compliance: ComplianceAssessment[];
  patches: PatchInfo[];
  graph: SecurityGraph;
  riskAssessment: RiskAssessment;
}

// Real-time update types
export interface RealTimeSecurityUpdate {
  type: 'metrics' | 'event' | 'threat' | 'compliance' | 'patch' | 'graph';
  data: any;
  timestamp: Date;
  priority: 'low' | 'medium' | 'high' | 'critical';
}
