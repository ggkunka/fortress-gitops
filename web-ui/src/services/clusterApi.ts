import { apiClient } from './apiClient';
import {
  ClusterConfig,
  ClusterStatus,
  ClusterAuthentication,
  ApiResponse,
  PaginatedResponse,
} from '../types';

export class ClusterApi {
  private baseUrl = '/api/v1/clusters';

  // Cluster Management
  async getClusters(): Promise<ClusterConfig[]> {
    const response = await apiClient.get<ApiResponse<ClusterConfig[]>>(this.baseUrl);
    return response.data.data || [];
  }

  async getCluster(id: string): Promise<ClusterConfig> {
    const response = await apiClient.get<ApiResponse<ClusterConfig>>(`${this.baseUrl}/${id}`);
    if (!response.data.data) {
      throw new Error('Cluster not found');
    }
    return response.data.data;
  }

  async createCluster(cluster: Omit<ClusterConfig, 'id' | 'status' | 'lastConnected' | 'metadata'>): Promise<ClusterConfig> {
    const response = await apiClient.post<ApiResponse<ClusterConfig>>(this.baseUrl, cluster);
    if (!response.data.data) {
      throw new Error('Failed to create cluster');
    }
    return response.data.data;
  }

  async updateCluster(id: string, cluster: Partial<ClusterConfig>): Promise<ClusterConfig> {
    const response = await apiClient.put<ApiResponse<ClusterConfig>>(`${this.baseUrl}/${id}`, cluster);
    if (!response.data.data) {
      throw new Error('Failed to update cluster');
    }
    return response.data.data;
  }

  async deleteCluster(id: string): Promise<void> {
    await apiClient.delete(`${this.baseUrl}/${id}`);
  }

  // Cluster Connectivity
  async testConnection(id: string): Promise<{ success: boolean; message: string; details?: any }> {
    const response = await apiClient.post<ApiResponse<{ success: boolean; message: string; details?: any }>>(
      `${this.baseUrl}/${id}/test-connection`
    );
    return response.data.data || { success: false, message: 'Unknown error' };
  }

  async testConnectionConfig(config: ClusterAuthentication & { endpoint: string }): Promise<{ success: boolean; message: string; details?: any }> {
    const response = await apiClient.post<ApiResponse<{ success: boolean; message: string; details?: any }>>(
      `${this.baseUrl}/test-connection`,
      config
    );
    return response.data.data || { success: false, message: 'Unknown error' };
  }

  // Cluster Status and Monitoring
  async getClusterStatus(id: string): Promise<ClusterStatus> {
    const response = await apiClient.get<ApiResponse<ClusterStatus>>(`${this.baseUrl}/${id}/status`);
    if (!response.data.data) {
      throw new Error('Failed to get cluster status');
    }
    return response.data.data;
  }

  async getClusterStatuses(): Promise<ClusterStatus[]> {
    const response = await apiClient.get<ApiResponse<ClusterStatus[]>>(`${this.baseUrl}/status`);
    return response.data.data || [];
  }

  // Namespace Operations
  async getNamespaces(id: string): Promise<string[]> {
    const response = await apiClient.get<ApiResponse<string[]>>(`${this.baseUrl}/${id}/namespaces`);
    return response.data.data || [];
  }

  async createNamespace(id: string, namespace: string): Promise<void> {
    await apiClient.post(`${this.baseUrl}/${id}/namespaces`, { name: namespace });
  }

  async deleteNamespace(id: string, namespace: string): Promise<void> {
    await apiClient.delete(`${this.baseUrl}/${id}/namespaces/${namespace}`);
  }

  // Resource Operations
  async getResources(id: string, namespace?: string): Promise<any[]> {
    const params = namespace ? { namespace } : {};
    const response = await apiClient.get<ApiResponse<any[]>>(`${this.baseUrl}/${id}/resources`, { params });
    return response.data.data || [];
  }

  async getResource(id: string, resourceType: string, resourceName: string, namespace?: string): Promise<any> {
    const params = namespace ? { namespace } : {};
    const response = await apiClient.get<ApiResponse<any>>(
      `${this.baseUrl}/${id}/resources/${resourceType}/${resourceName}`,
      { params }
    );
    return response.data.data;
  }

  // Kubeconfig Operations
  async generateKubeconfig(id: string): Promise<string> {
    const response = await apiClient.get<ApiResponse<{ kubeconfig: string }>>(`${this.baseUrl}/${id}/kubeconfig`);
    return response.data.data?.kubeconfig || '';
  }

  async validateKubeconfig(kubeconfig: string): Promise<{ valid: boolean; message: string; clusters?: string[] }> {
    const response = await apiClient.post<ApiResponse<{ valid: boolean; message: string; clusters?: string[] }>>(
      `${this.baseUrl}/validate-kubeconfig`,
      { kubeconfig }
    );
    return response.data.data || { valid: false, message: 'Unknown error' };
  }

  // Bulk Operations
  async bulkOperation(clusterIds: string[], operation: string, params?: any): Promise<{ [clusterId: string]: { success: boolean; message: string } }> {
    const response = await apiClient.post<ApiResponse<{ [clusterId: string]: { success: boolean; message: string } }>>(
      `${this.baseUrl}/bulk-operation`,
      { clusterIds, operation, params }
    );
    return response.data.data || {};
  }

  // Cluster Events
  async getClusterEvents(id: string, limit = 100): Promise<any[]> {
    const response = await apiClient.get<ApiResponse<any[]>>(`${this.baseUrl}/${id}/events`, {
      params: { limit }
    });
    return response.data.data || [];
  }

  // Cluster Metrics
  async getClusterMetrics(id: string, timeRange = '1h'): Promise<any> {
    const response = await apiClient.get<ApiResponse<any>>(`${this.baseUrl}/${id}/metrics`, {
      params: { timeRange }
    });
    return response.data.data;
  }

  // Security Scanning
  async scanCluster(id: string, scanType: string = 'security'): Promise<{ scanId: string }> {
    const response = await apiClient.post<ApiResponse<{ scanId: string }>>(
      `${this.baseUrl}/${id}/scan`,
      { scanType }
    );
    return response.data.data || { scanId: '' };
  }

  async getClusterScanResults(id: string, limit = 50): Promise<any[]> {
    const response = await apiClient.get<ApiResponse<any[]>>(`${this.baseUrl}/${id}/scan-results`, {
      params: { limit }
    });
    return response.data.data || [];
  }
}

export const clusterApi = new ClusterApi();
