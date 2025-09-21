// Enhanced MCP Security Platform Types

// User Management & Authentication Types
export interface User {
  id: string;
  username: string;
  email: string;
  firstName: string;
  lastName: string;
  roles: UserRole[];
  groups: string[];
  isActive: boolean;
  lastLogin?: Date;
  createdAt: Date;
  updatedAt: Date;
  preferences: UserPreferences;
}

export interface UserRole {
  id: string;
  name: string;
  permissions: Permission[];
  description: string;
  isSystemRole: boolean;
}

export interface Permission {
  resource: string; // 'clusters', 'repositories', 'scans', 'agents', 'users'
  actions: string[]; // 'read', 'write', 'delete', 'deploy', 'manage'
  conditions?: string[]; // Optional conditions like resource filters
}

export interface UserPreferences {
  theme: 'light' | 'dark' | 'auto';
  language: string;
  timezone: string;
  dashboardLayout: DashboardLayout;
  notifications: NotificationSettings;
}

export interface NotificationSettings {
  email: boolean;
  browser: boolean;
  slack: boolean;
  teams: boolean;
  severity: 'low' | 'medium' | 'high' | 'critical';
}

// Authentication Types
export interface AuthConfig {
  type: 'local' | 'ldap' | 'saml' | 'oidc' | 'azure-ad';
  config: LDAPConfig | SAMLConfig | OIDCConfig | AzureADConfig;
}

export interface LDAPConfig {
  url: string;
  bindDN: string;
  bindCredentials: string;
  searchBase: string;
  searchFilter: string;
  groupSearchBase?: string;
  groupSearchFilter?: string;
  tlsOptions?: {
    rejectUnauthorized: boolean;
    ca?: string;
  };
}

export interface SAMLConfig {
  entryPoint: string;
  issuer: string;
  cert: string;
  privateKey?: string;
  signatureAlgorithm?: string;
}

export interface OIDCConfig {
  issuer: string;
  clientId: string;
  clientSecret: string;
  redirectUri: string;
  scope: string[];
}

export interface AzureADConfig {
  tenantId: string;
  clientId: string;
  clientSecret?: string;
  redirectUri: string;
}

// Kubernetes Cluster Management Types
export interface ClusterConfig {
  id: string;
  name: string;
  description: string;
  endpoint: string;
  authentication: ClusterAuthentication;
  namespace?: string;
  tags: string[];
  status: 'connected' | 'disconnected' | 'error' | 'connecting';
  lastConnected?: Date;
  version?: string;
  nodeCount?: number;
  region?: string;
  provider?: 'aws' | 'gcp' | 'azure' | 'on-premise' | 'other';
  metadata: ClusterMetadata;
}

export interface ClusterAuthentication {
  type: 'certificate' | 'token' | 'serviceAccount' | 'kubeconfig';
  certificate?: string;
  privateKey?: string;
  token?: string;
  caCertificate?: string;
  kubeconfig?: string;
}

export interface ClusterMetadata {
  createdAt: Date;
  updatedAt: Date;
  createdBy: string;
  labels: Record<string, string>;
  annotations: Record<string, string>;
}

export interface ClusterStatus {
  clusterId: string;
  isHealthy: boolean;
  nodes: NodeStatus[];
  namespaces: string[];
  resources: ResourceUsage;
  agents: AgentStatus[];
  lastChecked: Date;
}

export interface NodeStatus {
  name: string;
  status: 'Ready' | 'NotReady' | 'Unknown';
  roles: string[];
  version: string;
  os: string;
  architecture: string;
  resources: {
    cpu: ResourceMetric;
    memory: ResourceMetric;
    storage: ResourceMetric;
  };
}

export interface ResourceMetric {
  used: string;
  available: string;
  percentage: number;
}

export interface ResourceUsage {
  cpu: ResourceMetric;
  memory: ResourceMetric;
  storage: ResourceMetric;
  pods: {
    used: number;
    available: number;
  };
}

// Repository Management Types
export interface ImageRepository {
  id: string;
  name: string;
  type: 'docker' | 'harbor' | 'ecr' | 'gcr' | 'acr' | 'quay';
  url: string;
  authentication: RepositoryAuthentication;
  scanOnPush: boolean;
  autoScan: boolean;
  scanSchedule?: string;
  retentionPolicy?: RetentionPolicy;
  isActive: boolean;
  lastSync?: Date;
  imageCount?: number;
  vulnerabilityStats?: VulnerabilityStats;
}

export interface ChartRepository {
  id: string;
  name: string;
  url: string;
  type: 'helm' | 'oci';
  authentication?: RepositoryAuthentication;
  syncSchedule?: string;
  lastSync?: Date;
  chartCount?: number;
  isActive: boolean;
}

export interface RepositoryAuthentication {
  type: 'none' | 'basic' | 'token' | 'aws' | 'gcp' | 'azure';
  username?: string;
  password?: string;
  token?: string;
  awsCredentials?: AWSCredentials;
  gcpCredentials?: GCPCredentials;
  azureCredentials?: AzureCredentials;
}

export interface AWSCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  region: string;
  sessionToken?: string;
}

export interface GCPCredentials {
  projectId: string;
  keyFile: string;
}

export interface AzureCredentials {
  tenantId: string;
  clientId: string;
  clientSecret: string;
}

export interface RetentionPolicy {
  maxImages: number;
  maxAge: number; // days
  keepLatest: number;
  tagPattern?: string;
}

// Security Agent Types
export interface SecurityAgent {
  id: string;
  name: string;
  type:
    | 'vulnerability-scanner'
    | 'compliance-checker'
    | 'runtime-security'
    | 'network-policy'
    | 'admission-controller';
  description: string;
  helmChart: HelmChart;
  configuration: AgentConfiguration;
  targetClusters: string[];
  deploymentStatus: AgentDeploymentStatus[];
  isActive: boolean;
  version: string;
  capabilities: string[];
}

export interface HelmChart {
  repository: string;
  chart: string;
  version: string;
  values: Record<string, any>;
  customValues?: string; // YAML string
}

export interface AgentConfiguration {
  resources: {
    requests: {
      cpu: string;
      memory: string;
    };
    limits: {
      cpu: string;
      memory: string;
    };
  };
  nodeSelector?: Record<string, string>;
  tolerations?: any[];
  affinity?: any;
  securityContext?: any;
  serviceAccount?: string;
  rbac: {
    create: boolean;
    rules?: any[];
  };
  config: Record<string, any>;
}

export interface AgentDeploymentStatus {
  clusterId: string;
  clusterName: string;
  status: 'pending' | 'deploying' | 'deployed' | 'failed' | 'updating' | 'uninstalling';
  version: string;
  lastUpdated: Date;
  healthStatus: 'healthy' | 'unhealthy' | 'unknown';
  message?: string;
  pods: PodStatus[];
}

export interface AgentStatus {
  agentId: string;
  clusterId: string;
  status: AgentDeploymentStatus;
  metrics: AgentMetrics;
  logs: LogEntry[];
}

export interface AgentMetrics {
  cpu: number;
  memory: number;
  scansCompleted: number;
  vulnerabilitiesFound: number;
  lastScanTime?: Date;
}

export interface PodStatus {
  name: string;
  namespace: string;
  status: 'Running' | 'Pending' | 'Failed' | 'Succeeded' | 'Unknown';
  ready: boolean;
  restarts: number;
  age: string;
}

// Scanning & Vulnerability Types
export interface ScanResult {
  id: string;
  type: 'image' | 'cluster' | 'chart';
  target: string;
  status: 'pending' | 'running' | 'completed' | 'failed';
  startedAt: Date;
  completedAt?: Date;
  duration?: number;
  vulnerabilities: Vulnerability[];
  summary: ScanSummary;
  metadata: ScanMetadata;
}

export interface Vulnerability {
  id: string;
  cveId?: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  cvssScore?: number;
  title: string;
  description: string;
  affectedPackage: string;
  installedVersion: string;
  fixedVersion?: string;
  publishedDate?: Date;
  lastModifiedDate?: Date;
  references: string[];
  status: 'open' | 'fixed' | 'ignored' | 'false-positive';
}

export interface ScanSummary {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  fixed: number;
  ignored: number;
}

export interface ScanMetadata {
  scanner: string;
  scannerVersion: string;
  policies: string[];
  clusterId?: string;
  repositoryId?: string;
  tags: string[];
}

export interface VulnerabilityStats {
  total: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  trend: 'increasing' | 'decreasing' | 'stable';
}

// Dashboard & UI Types
export interface DashboardLayout {
  widgets: DashboardWidget[];
  columns: number;
  autoRefresh: boolean;
  refreshInterval: number; // seconds
}

export interface DashboardWidget {
  id: string;
  type: 'metrics' | 'chart' | 'table' | 'status' | 'alerts';
  title: string;
  position: {
    x: number;
    y: number;
    width: number;
    height: number;
  };
  config: Record<string, any>;
  dataSource: string;
}

export interface Alert {
  id: string;
  type: 'vulnerability' | 'compliance' | 'security' | 'system';
  severity: 'low' | 'medium' | 'high' | 'critical';
  title: string;
  message: string;
  source: string;
  clusterId?: string;
  agentId?: string;
  timestamp: Date;
  status: 'open' | 'acknowledged' | 'resolved';
  assignedTo?: string;
  tags: string[];
}

// API Response Types
export interface ApiResponse<T> {
  success: boolean;
  data?: T;
  error?: string;
  message?: string;
  timestamp: Date;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  pageSize: number;
  totalPages: number;
}

// WebSocket Types
export interface WebSocketMessage {
  type: string;
  payload: any;
  timestamp: Date;
}

export interface RealTimeUpdate {
  type: 'cluster-status' | 'scan-progress' | 'agent-status' | 'alert' | 'metrics';
  data: any;
}

// Log Entry Types
export interface LogEntry {
  timestamp: Date;
  level: 'debug' | 'info' | 'warn' | 'error';
  message: string;
  source: string;
  metadata?: Record<string, any>;
}

// Audit Types
export interface AuditLog {
  id: string;
  userId: string;
  username: string;
  action: string;
  resource: string;
  resourceId?: string;
  timestamp: Date;
  ipAddress: string;
  userAgent: string;
  success: boolean;
  details?: Record<string, any>;
}

// Configuration Types
export interface SystemConfig {
  authentication: AuthConfig;
  security: SecurityConfig;
  notifications: NotificationConfig;
  scanning: ScanningConfig;
  retention: RetentionConfig;
}

export interface SecurityConfig {
  sessionTimeout: number; // minutes
  maxLoginAttempts: number;
  passwordPolicy: PasswordPolicy;
  mfaRequired: boolean;
  allowedIpRanges?: string[];
}

export interface PasswordPolicy {
  minLength: number;
  requireUppercase: boolean;
  requireLowercase: boolean;
  requireNumbers: boolean;
  requireSpecialChars: boolean;
  maxAge: number; // days
}

export interface NotificationConfig {
  email: EmailConfig;
  slack: SlackConfig;
  teams: TeamsConfig;
  webhook: WebhookConfig;
}

export interface EmailConfig {
  enabled: boolean;
  smtpHost: string;
  smtpPort: number;
  username: string;
  password: string;
  fromAddress: string;
  tls: boolean;
}

export interface SlackConfig {
  enabled: boolean;
  webhookUrl: string;
  channel: string;
  username: string;
}

export interface TeamsConfig {
  enabled: boolean;
  webhookUrl: string;
}

export interface WebhookConfig {
  enabled: boolean;
  url: string;
  secret?: string;
  headers?: Record<string, string>;
}

export interface ScanningConfig {
  defaultSchedule: string;
  maxConcurrentScans: number;
  scanTimeout: number; // minutes
  retryAttempts: number;
  enabledScanners: string[];
}

export interface RetentionConfig {
  scanResults: number; // days
  auditLogs: number; // days
  alerts: number; // days
  metrics: number; // days
}
