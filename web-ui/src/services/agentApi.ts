import { apiClient } from './apiClient';
import {
  SecurityAgent,
  AgentDeploymentStatus,
  AgentStatus,
  HelmChart,
  AgentConfiguration,
  ApiResponse,
  PaginatedResponse,
} from '../types';

export class AgentApi {
  private baseUrl = '/api/v1/agents';

  // Agent Management
  async getAgents(): Promise<SecurityAgent[]> {
    const response = await apiClient.get<ApiResponse<SecurityAgent[]>>(this.baseUrl);
    return response.data || [];
  }

  async getAgent(id: string): Promise<SecurityAgent> {
    const response = await apiClient.get<ApiResponse<SecurityAgent>>(`${this.baseUrl}/${id}`);
    if (!response.data) {
      throw new Error('Agent not found');
    }
    return response.data;
  }

  async createAgent(
    agent: Omit<SecurityAgent, 'id' | 'deploymentStatus' | 'version'>
  ): Promise<SecurityAgent> {
    const response = await apiClient.post<ApiResponse<SecurityAgent>>(this.baseUrl, agent);
    if (!response.data) {
      throw new Error('Failed to create agent');
    }
    return response.data;
  }

  async updateAgent(id: string, agent: Partial<SecurityAgent>): Promise<SecurityAgent> {
    const response = await apiClient.put<ApiResponse<SecurityAgent>>(
      `${this.baseUrl}/${id}`,
      agent
    );
    if (!response.data) {
      throw new Error('Failed to update agent');
    }
    return response.data;
  }

  async deleteAgent(id: string): Promise<void> {
    await apiClient.delete(`${this.baseUrl}/${id}`);
  }

  // Agent Deployment
  async deployAgent(
    agentId: string,
    clusterIds: string[]
  ): Promise<{ deploymentId: string; status: string }> {
    const response = await apiClient.post<ApiResponse<{ deploymentId: string; status: string }>>(
      `${this.baseUrl}/${agentId}/deploy`,
      { clusterIds }
    );
    return response.data || { deploymentId: '', status: 'failed' };
  }

  async undeployAgent(
    agentId: string,
    clusterIds: string[]
  ): Promise<{ success: boolean; results: any[] }> {
    const response = await apiClient.post<ApiResponse<{ success: boolean; results: any[] }>>(
      `${this.baseUrl}/${agentId}/undeploy`,
      { clusterIds }
    );
    return response.data || { success: false, results: [] };
  }

  async updateAgentDeployment(
    agentId: string,
    clusterIds: string[]
  ): Promise<{ success: boolean; results: any[] }> {
    const response = await apiClient.post<ApiResponse<{ success: boolean; results: any[] }>>(
      `${this.baseUrl}/${agentId}/update`,
      { clusterIds }
    );
    return response.data || { success: false, results: [] };
  }

  // Agent Status and Monitoring
  async getAgentStatus(agentId: string, clusterId?: string): Promise<AgentStatus[]> {
    const params = clusterId ? { clusterId } : {};
    const response = await apiClient.get<ApiResponse<AgentStatus[]>>(
      `${this.baseUrl}/${agentId}/status`,
      { params }
    );
    return response.data || [];
  }

  async getAgentStatuses(): Promise<AgentStatus[]> {
    const response = await apiClient.get<ApiResponse<AgentStatus[]>>(`${this.baseUrl}/status`);
    return response.data || [];
  }

  async getAgentDeploymentStatus(agentId: string): Promise<AgentDeploymentStatus[]> {
    const response = await apiClient.get<ApiResponse<AgentDeploymentStatus[]>>(
      `${this.baseUrl}/${agentId}/deployment-status`
    );
    return response.data || [];
  }

  // Agent Logs
  async getAgentLogs(
    agentId: string,
    clusterId: string,
    options?: {
      lines?: number;
      since?: string;
      follow?: boolean;
      podName?: string;
    }
  ): Promise<{ logs: string[]; podName: string }> {
    const response = await apiClient.get<ApiResponse<{ logs: string[]; podName: string }>>(
      `${this.baseUrl}/${agentId}/logs/${clusterId}`,
      { params: options }
    );
    return response.data || { logs: [], podName: '' };
  }

  async streamAgentLogs(
    agentId: string,
    clusterId: string,
    onLog: (log: string) => void,
    onError: (error: string) => void
  ): Promise<() => void> {
    // This would typically use WebSocket or Server-Sent Events
    // For now, we'll implement polling
    let isStreaming = true;
    let lastTimestamp = new Date().toISOString();

    const poll = async () => {
      if (!isStreaming) return;

      try {
        const logs = await this.getAgentLogs(agentId, clusterId, {
          since: lastTimestamp,
          lines: 100,
        });

        logs.logs.forEach(onLog);
        lastTimestamp = new Date().toISOString();
      } catch (error: any) {
        onError(error.message || 'Failed to fetch logs');
      }

      if (isStreaming) {
        setTimeout(poll, 2000); // Poll every 2 seconds
      }
    };

    poll();

    return () => {
      isStreaming = false;
    };
  }

  // Helm Chart Operations
  async getAvailableCharts(): Promise<HelmChart[]> {
    const response = await apiClient.get<ApiResponse<HelmChart[]>>(`${this.baseUrl}/charts`);
    return response.data || [];
  }

  async getChartVersions(repository: string, chart: string): Promise<string[]> {
    const response = await apiClient.get<ApiResponse<string[]>>(`${this.baseUrl}/charts/versions`, {
      params: { repository, chart },
    });
    return response.data || [];
  }

  async getChartValues(
    repository: string,
    chart: string,
    version: string
  ): Promise<Record<string, any>> {
    const response = await apiClient.get<ApiResponse<Record<string, any>>>(
      `${this.baseUrl}/charts/values`,
      { params: { repository, chart, version } }
    );
    return response.data || {};
  }

  async validateChartValues(
    repository: string,
    chart: string,
    version: string,
    values: Record<string, any>
  ): Promise<{ valid: boolean; errors: string[] }> {
    const response = await apiClient.post<ApiResponse<{ valid: boolean; errors: string[] }>>(
      `${this.baseUrl}/charts/validate`,
      { repository, chart, version, values }
    );
    return response.data || { valid: false, errors: [] };
  }

  // Agent Configuration
  async getAgentConfiguration(agentId: string): Promise<AgentConfiguration> {
    const response = await apiClient.get<ApiResponse<AgentConfiguration>>(
      `${this.baseUrl}/${agentId}/configuration`
    );
    return response.data || ({} as AgentConfiguration);
  }

  async updateAgentConfiguration(
    agentId: string,
    configuration: Partial<AgentConfiguration>
  ): Promise<AgentConfiguration> {
    const response = await apiClient.put<ApiResponse<AgentConfiguration>>(
      `${this.baseUrl}/${agentId}/configuration`,
      configuration
    );
    if (!response.data) {
      throw new Error('Failed to update agent configuration');
    }
    return response.data;
  }

  async getDefaultConfiguration(agentType: string): Promise<AgentConfiguration> {
    const response = await apiClient.get<ApiResponse<AgentConfiguration>>(
      `${this.baseUrl}/default-configuration/${agentType}`
    );
    return response.data || ({} as AgentConfiguration);
  }

  // Agent Templates
  async getAgentTemplates(): Promise<SecurityAgent[]> {
    const response = await apiClient.get<ApiResponse<SecurityAgent[]>>(`${this.baseUrl}/templates`);
    return response.data || [];
  }

  async createAgentFromTemplate(
    templateId: string,
    customization: Partial<SecurityAgent>
  ): Promise<SecurityAgent> {
    const response = await apiClient.post<ApiResponse<SecurityAgent>>(
      `${this.baseUrl}/templates/${templateId}/create`,
      customization
    );
    if (!response.data) {
      throw new Error('Failed to create agent from template');
    }
    return response.data;
  }

  // Agent Health Checks
  async performHealthCheck(
    agentId: string,
    clusterId: string
  ): Promise<{
    healthy: boolean;
    checks: { name: string; status: 'pass' | 'fail'; message: string }[];
  }> {
    const response = await apiClient.post<
      ApiResponse<{
        healthy: boolean;
        checks: { name: string; status: 'pass' | 'fail'; message: string }[];
      }>
    >(`${this.baseUrl}/${agentId}/health-check/${clusterId}`);
    return response.data || { healthy: false, checks: [] };
  }

  // Agent Metrics
  async getAgentMetrics(
    agentId: string,
    clusterId: string,
    timeRange = '1h'
  ): Promise<{
    cpu: { timestamp: string; value: number }[];
    memory: { timestamp: string; value: number }[];
    scans: { timestamp: string; value: number }[];
    vulnerabilities: { timestamp: string; value: number }[];
  }> {
    const response = await apiClient.get<
      ApiResponse<{
        cpu: { timestamp: string; value: number }[];
        memory: { timestamp: string; value: number }[];
        scans: { timestamp: string; value: number }[];
        vulnerabilities: { timestamp: string; value: number }[];
      }>
    >(`${this.baseUrl}/${agentId}/metrics/${clusterId}`, {
      params: { timeRange },
    });
    return response.data || { cpu: [], memory: [], scans: [], vulnerabilities: [] };
  }

  // Bulk Operations
  async bulkDeploy(
    agentIds: string[],
    clusterIds: string[]
  ): Promise<{
    success: boolean;
    results: { agentId: string; clusterId: string; success: boolean; message: string }[];
  }> {
    const response = await apiClient.post<
      ApiResponse<{
        success: boolean;
        results: { agentId: string; clusterId: string; success: boolean; message: string }[];
      }>
    >(`${this.baseUrl}/bulk-deploy`, { agentIds, clusterIds });
    return response.data || { success: false, results: [] };
  }

  async bulkUndeploy(
    agentIds: string[],
    clusterIds: string[]
  ): Promise<{
    success: boolean;
    results: { agentId: string; clusterId: string; success: boolean; message: string }[];
  }> {
    const response = await apiClient.post<
      ApiResponse<{
        success: boolean;
        results: { agentId: string; clusterId: string; success: boolean; message: string }[];
      }>
    >(`${this.baseUrl}/bulk-undeploy`, { agentIds, clusterIds });
    return response.data || { success: false, results: [] };
  }

  async bulkUpdate(
    agentIds: string[],
    clusterIds: string[]
  ): Promise<{
    success: boolean;
    results: { agentId: string; clusterId: string; success: boolean; message: string }[];
  }> {
    const response = await apiClient.post<
      ApiResponse<{
        success: boolean;
        results: { agentId: string; clusterId: string; success: boolean; message: string }[];
      }>
    >(`${this.baseUrl}/bulk-update`, { agentIds, clusterIds });
    return response.data || { success: false, results: [] };
  }

  // Agent Statistics
  async getAgentStats(): Promise<{
    totalAgents: number;
    deployedAgents: number;
    healthyAgents: number;
    totalDeployments: number;
    failedDeployments: number;
  }> {
    const response = await apiClient.get<
      ApiResponse<{
        totalAgents: number;
        deployedAgents: number;
        healthyAgents: number;
        totalDeployments: number;
        failedDeployments: number;
      }>
    >(`${this.baseUrl}/stats`);
    return (
      response.data || {
        totalAgents: 0,
        deployedAgents: 0,
        healthyAgents: 0,
        totalDeployments: 0,
        failedDeployments: 0,
      }
    );
  }
}

export const agentApi = new AgentApi();
