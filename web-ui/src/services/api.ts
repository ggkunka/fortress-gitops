import axios, { AxiosInstance, AxiosResponse } from 'axios';
import { io, Socket } from 'socket.io-client';

// API Configuration - Using internal Kubernetes service DNS names
const API_CONFIG = {
  AUTH_SERVICE: 'http://auth-service.mcp-security.svc.cluster.local:8080',
  GATEWAY_SERVICE: 'http://gateway-service.mcp-security.svc.cluster.local:8081',
  SCANNER_MANAGER: 'http://scanner-manager.mcp-security.svc.cluster.local:8082',
  VULNERABILITY_ANALYZER: 'http://vulnerability-analyzer.mcp-security.svc.cluster.local:8083',
  REPORT_GENERATOR: 'http://report-generator.mcp-security.svc.cluster.local:8084',
  NOTIFICATION_SERVICE: 'http://notification-service.mcp-security.svc.cluster.local:8085',
  PLUGIN_MANAGER: 'http://plugin-manager.mcp-security.svc.cluster.local:8086',
  GRAPHQL_GATEWAY: 'http://graphql-gateway.mcp-security.svc.cluster.local:8087',
  WEBSOCKET_GATEWAY: 'http://websocket-gateway.mcp-security.svc.cluster.local:8088',
  CICD_INTEGRATION: 'http://cicd-integration.mcp-security.svc.cluster.local:8089',
  SIEM_INTEGRATION: 'http://siem-integration.mcp-security.svc.cluster.local:8090',
  ZERO_TRUST_SECURITY: 'http://zero-trust-security.mcp-security.svc.cluster.local:8091',
  ML_ENGINE: 'http://ml-engine.mcp-security.svc.cluster.local:8092',
  ELASTICSEARCH: 'http://elasticsearch.mcp-security.svc.cluster.local:9200',
  PROMETHEUS: 'http://prometheus.mcp-security.svc.cluster.local:9090',
  GRAFANA: 'http://grafana.mcp-security.svc.cluster.local:3000',
};

// For development, use localhost proxy when running outside cluster
const isDevelopment =
  (window as any).location?.hostname === 'localhost' ||
  (typeof process !== 'undefined' && process.env?.NODE_ENV === 'development');
const API_BASE = isDevelopment ? 'http://localhost:30080/api' : '/api';

class ApiService {
  private axiosInstance: AxiosInstance;
  private wsSocket: Socket | null = null;

  constructor() {
    this.axiosInstance = axios.create({
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Add request interceptor for authentication
    this.axiosInstance.interceptors.request.use(
      (config) => {
        const token = localStorage.getItem('fortress_token');
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    // Add response interceptor for error handling
    this.axiosInstance.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          localStorage.removeItem('fortress_token');
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  // WebSocket Connection
  connectWebSocket(): Socket {
    if (!this.wsSocket) {
      const wsUrl = isDevelopment ? 'ws://localhost:30080' : API_CONFIG.WEBSOCKET_GATEWAY;

      this.wsSocket = io(wsUrl, {
        transports: ['websocket'],
        auth: {
          token: localStorage.getItem('fortress_token'),
        },
      });
    }
    return this.wsSocket;
  }

  disconnectWebSocket(): void {
    if (this.wsSocket) {
      this.wsSocket.disconnect();
      this.wsSocket = null;
    }
  }

  // Authentication APIs
  async login(credentials: { username: string; password: string }) {
    const response = await this.axiosInstance.post(`${API_BASE}/auth/login`, credentials);
    return response.data;
  }

  async logout() {
    const response = await this.axiosInstance.post(`${API_BASE}/auth/logout`);
    localStorage.removeItem('fortress_token');
    return response.data;
  }

  async getCurrentUser() {
    const response = await this.axiosInstance.get(`${API_BASE}/auth/me`);
    return response.data;
  }

  // Security Dashboard APIs
  getSecurityOverview = async () => {
    const response = await this.axiosInstance.get(`${API_BASE}/dashboard/overview`);
    return response.data;
  };

  getSecurityMetrics = async () => {
    const response = await this.axiosInstance.get(`${API_BASE}/dashboard/metrics`);
    return response.data;
  };

  getThreatDetectionData = async () => {
    const response = await this.axiosInstance.get(`${API_BASE}/threats/detection`);
    return response.data;
  };

  // Cluster Management APIs
  getClusters = async () => {
    const response = await this.axiosInstance.get(`${API_BASE}/clusters`);
    return response.data;
  };

  async getClusterDetails(clusterId: string) {
    const response = await this.axiosInstance.get(`${API_BASE}/clusters/${clusterId}`);
    return response.data;
  }

  getPods = async (clusterId?: string) => {
    const url = clusterId ? `${API_BASE}/clusters/${clusterId}/pods` : `${API_BASE}/pods`;
    const response = await this.axiosInstance.get(url);
    return response.data;
  };

  getServices = async (clusterId?: string) => {
    const url = clusterId ? `${API_BASE}/clusters/${clusterId}/services` : `${API_BASE}/services`;
    const response = await this.axiosInstance.get(url);
    return response.data;
  };

  async createPod(clusterId: string, podSpec: any) {
    const response = await this.axiosInstance.post(
      `${API_BASE}/clusters/${clusterId}/pods`,
      podSpec
    );
    return response.data;
  }

  async deletePod(clusterId: string, podName: string, namespace: string) {
    const response = await this.axiosInstance.delete(
      `${API_BASE}/clusters/${clusterId}/pods/${podName}?namespace=${namespace}`
    );
    return response.data;
  }

  // Vulnerability Management APIs
  getVulnerabilities = async () => {
    const response = await this.axiosInstance.get(`${API_BASE}/vulnerabilities`);
    return response.data;
  };

  async getVulnerabilityDetails(cveId: string) {
    const response = await this.axiosInstance.get(`${API_BASE}/vulnerabilities/${cveId}`);
    return response.data;
  }

  scanCluster = async (clusterId: string) => {
    const response = await this.axiosInstance.post(`${API_BASE}/scan/cluster/${clusterId}`);
    return response.data;
  };

  async getScanResults(scanId: string) {
    const response = await this.axiosInstance.get(`${API_BASE}/scan/results/${scanId}`);
    return response.data;
  }

  // Compliance APIs
  async getComplianceStatus() {
    const response = await this.axiosInstance.get(`${API_BASE}/compliance/status`);
    return response.data;
  }

  async getComplianceFrameworks() {
    const response = await this.axiosInstance.get(`${API_BASE}/compliance/frameworks`);
    return response.data;
  }

  async runComplianceAssessment(frameworkId: string) {
    const response = await this.axiosInstance.post(`${API_BASE}/compliance/assess/${frameworkId}`);
    return response.data;
  }

  // Reports APIs
  async getReports() {
    const response = await this.axiosInstance.get(`${API_BASE}/reports`);
    return response.data;
  }

  async generateReport(reportConfig: any) {
    const response = await this.axiosInstance.post(`${API_BASE}/reports/generate`, reportConfig);
    return response.data;
  }

  async downloadReport(reportId: string, format: string) {
    const response = await this.axiosInstance.get(
      `${API_BASE}/reports/${reportId}/download?format=${format}`,
      { responseType: 'blob' }
    );
    return response.data;
  }

  // Integration Management APIs
  async getIntegrations() {
    const response = await this.axiosInstance.get(`${API_BASE}/integrations`);
    return response.data;
  }

  async getIntegrationStatus(integrationId: string) {
    const response = await this.axiosInstance.get(
      `${API_BASE}/integrations/${integrationId}/status`
    );
    return response.data;
  }

  async testIntegration(integrationId: string) {
    const response = await this.axiosInstance.post(
      `${API_BASE}/integrations/${integrationId}/test`
    );
    return response.data;
  }

  async configureIntegration(integrationId: string, config: any) {
    const response = await this.axiosInstance.put(
      `${API_BASE}/integrations/${integrationId}/config`,
      config
    );
    return response.data;
  }

  // User Management APIs
  async getUsers() {
    const response = await this.axiosInstance.get(`${API_BASE}/users`);
    return response.data;
  }

  async createUser(userData: any) {
    const response = await this.axiosInstance.post(`${API_BASE}/users`, userData);
    return response.data;
  }

  async updateUser(userId: string, userData: any) {
    const response = await this.axiosInstance.put(`${API_BASE}/users/${userId}`, userData);
    return response.data;
  }

  async deleteUser(userId: string) {
    const response = await this.axiosInstance.delete(`${API_BASE}/users/${userId}`);
    return response.data;
  }

  async getRoles() {
    const response = await this.axiosInstance.get(`${API_BASE}/roles`);
    return response.data;
  }

  // ML Engine APIs
  async getAnomalyDetection() {
    const response = await this.axiosInstance.get(`${API_BASE}/ml/anomalies`);
    return response.data;
  }

  async getThreatIntelligence() {
    const response = await this.axiosInstance.get(`${API_BASE}/ml/threat-intel`);
    return response.data;
  }

  async getRiskAssessment() {
    const response = await this.axiosInstance.get(`${API_BASE}/ml/risk-assessment`);
    return response.data;
  }

  // SIEM Integration APIs
  async getSiemEvents() {
    const response = await this.axiosInstance.get(`${API_BASE}/siem/events`);
    return response.data;
  }

  async forwardEventToSiem(event: any) {
    const response = await this.axiosInstance.post(`${API_BASE}/siem/forward`, event);
    return response.data;
  }

  // GraphQL Query
  async graphqlQuery(query: string, variables?: any) {
    const response = await this.axiosInstance.post(`${API_BASE}/graphql`, {
      query,
      variables,
    });
    return response.data;
  }

  // Health Check
  async healthCheck() {
    try {
      const response = await this.axiosInstance.get(`${API_BASE}/health`);
      return response.data;
    } catch (error) {
      return { status: 'error', message: 'Service unavailable' };
    }
  }
}

export const apiService = new ApiService();
export default apiService;
