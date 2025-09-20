import { apiClient } from './apiClient';
import {
  ImageRepository,
  ChartRepository,
  RepositoryAuthentication,
  ScanResult,
  VulnerabilityStats,
  ApiResponse,
  PaginatedResponse,
} from '../types';

export class RepositoryApi {
  private baseUrl = '/api/v1/repositories';

  // Image Repository Management
  async getImageRepositories(): Promise<ImageRepository[]> {
    const response = await apiClient.get<ApiResponse<ImageRepository[]>>(`${this.baseUrl}/images`);
    return response.data.data || [];
  }

  async getImageRepository(id: string): Promise<ImageRepository> {
    const response = await apiClient.get<ApiResponse<ImageRepository>>(`${this.baseUrl}/images/${id}`);
    if (!response.data.data) {
      throw new Error('Image repository not found');
    }
    return response.data.data;
  }

  async createImageRepository(repository: Omit<ImageRepository, 'id' | 'lastSync' | 'imageCount' | 'vulnerabilityStats'>): Promise<ImageRepository> {
    const response = await apiClient.post<ApiResponse<ImageRepository>>(`${this.baseUrl}/images`, repository);
    if (!response.data.data) {
      throw new Error('Failed to create image repository');
    }
    return response.data.data;
  }

  async updateImageRepository(id: string, repository: Partial<ImageRepository>): Promise<ImageRepository> {
    const response = await apiClient.put<ApiResponse<ImageRepository>>(`${this.baseUrl}/images/${id}`, repository);
    if (!response.data.data) {
      throw new Error('Failed to update image repository');
    }
    return response.data.data;
  }

  async deleteImageRepository(id: string): Promise<void> {
    await apiClient.delete(`${this.baseUrl}/images/${id}`);
  }

  // Chart Repository Management
  async getChartRepositories(): Promise<ChartRepository[]> {
    const response = await apiClient.get<ApiResponse<ChartRepository[]>>(`${this.baseUrl}/charts`);
    return response.data.data || [];
  }

  async getChartRepository(id: string): Promise<ChartRepository> {
    const response = await apiClient.get<ApiResponse<ChartRepository>>(`${this.baseUrl}/charts/${id}`);
    if (!response.data.data) {
      throw new Error('Chart repository not found');
    }
    return response.data.data;
  }

  async createChartRepository(repository: Omit<ChartRepository, 'id' | 'lastSync' | 'chartCount'>): Promise<ChartRepository> {
    const response = await apiClient.post<ApiResponse<ChartRepository>>(`${this.baseUrl}/charts`, repository);
    if (!response.data.data) {
      throw new Error('Failed to create chart repository');
    }
    return response.data.data;
  }

  async updateChartRepository(id: string, repository: Partial<ChartRepository>): Promise<ChartRepository> {
    const response = await apiClient.put<ApiResponse<ChartRepository>>(`${this.baseUrl}/charts/${id}`, repository);
    if (!response.data.data) {
      throw new Error('Failed to update chart repository');
    }
    return response.data.data;
  }

  async deleteChartRepository(id: string): Promise<void> {
    await apiClient.delete(`${this.baseUrl}/charts/${id}`);
  }

  // Repository Testing and Validation
  async testImageRepositoryConnection(config: {
    type: string;
    url: string;
    authentication: RepositoryAuthentication;
  }): Promise<{ success: boolean; message: string; details?: any }> {
    const response = await apiClient.post<ApiResponse<{ success: boolean; message: string; details?: any }>>(
      `${this.baseUrl}/images/test-connection`,
      config
    );
    return response.data.data || { success: false, message: 'Unknown error' };
  }

  async testChartRepositoryConnection(config: {
    url: string;
    type: string;
    authentication?: RepositoryAuthentication;
  }): Promise<{ success: boolean; message: string; details?: any }> {
    const response = await apiClient.post<ApiResponse<{ success: boolean; message: string; details?: any }>>(
      `${this.baseUrl}/charts/test-connection`,
      config
    );
    return response.data.data || { success: false, message: 'Unknown error' };
  }

  // Image Operations
  async getImages(repositoryId: string, page = 1, pageSize = 50, search?: string): Promise<PaginatedResponse<any>> {
    const params: any = { page, pageSize };
    if (search) params.search = search;
    
    const response = await apiClient.get<ApiResponse<PaginatedResponse<any>>>(
      `${this.baseUrl}/images/${repositoryId}/images`,
      { params }
    );
    return response.data.data || { items: [], total: 0, page: 1, pageSize: 50, totalPages: 0 };
  }

  async getImage(repositoryId: string, imageName: string, tag?: string): Promise<any> {
    const params = tag ? { tag } : {};
    const response = await apiClient.get<ApiResponse<any>>(
      `${this.baseUrl}/images/${repositoryId}/images/${encodeURIComponent(imageName)}`,
      { params }
    );
    return response.data.data;
  }

  async getImageTags(repositoryId: string, imageName: string): Promise<string[]> {
    const response = await apiClient.get<ApiResponse<string[]>>(
      `${this.baseUrl}/images/${repositoryId}/images/${encodeURIComponent(imageName)}/tags`
    );
    return response.data.data || [];
  }

  async deleteImage(repositoryId: string, imageName: string, tag?: string): Promise<void> {
    const params = tag ? { tag } : {};
    await apiClient.delete(
      `${this.baseUrl}/images/${repositoryId}/images/${encodeURIComponent(imageName)}`,
      { params }
    );
  }

  // Chart Operations
  async getCharts(repositoryId: string, page = 1, pageSize = 50, search?: string): Promise<PaginatedResponse<any>> {
    const params: any = { page, pageSize };
    if (search) params.search = search;
    
    const response = await apiClient.get<ApiResponse<PaginatedResponse<any>>>(
      `${this.baseUrl}/charts/${repositoryId}/charts`,
      { params }
    );
    return response.data.data || { items: [], total: 0, page: 1, pageSize: 50, totalPages: 0 };
  }

  async getChart(repositoryId: string, chartName: string, version?: string): Promise<any> {
    const params = version ? { version } : {};
    const response = await apiClient.get<ApiResponse<any>>(
      `${this.baseUrl}/charts/${repositoryId}/charts/${encodeURIComponent(chartName)}`,
      { params }
    );
    return response.data.data;
  }

  async getChartVersions(repositoryId: string, chartName: string): Promise<string[]> {
    const response = await apiClient.get<ApiResponse<string[]>>(
      `${this.baseUrl}/charts/${repositoryId}/charts/${encodeURIComponent(chartName)}/versions`
    );
    return response.data.data || [];
  }

  // Scanning Operations
  async scanImage(repositoryId: string, imageName: string, tag: string): Promise<{ scanId: string }> {
    const response = await apiClient.post<ApiResponse<{ scanId: string }>>(
      `${this.baseUrl}/images/${repositoryId}/scan`,
      { imageName, tag }
    );
    return response.data.data || { scanId: '' };
  }

  async scanChart(repositoryId: string, chartName: string, version: string): Promise<{ scanId: string }> {
    const response = await apiClient.post<ApiResponse<{ scanId: string }>>(
      `${this.baseUrl}/charts/${repositoryId}/scan`,
      { chartName, version }
    );
    return response.data.data || { scanId: '' };
  }

  async getScanResults(repositoryId: string, type: 'image' | 'chart', page = 1, pageSize = 50): Promise<PaginatedResponse<ScanResult>> {
    const response = await apiClient.get<ApiResponse<PaginatedResponse<ScanResult>>>(
      `${this.baseUrl}/${type}s/${repositoryId}/scan-results`,
      { params: { page, pageSize } }
    );
    return response.data.data || { items: [], total: 0, page: 1, pageSize: 50, totalPages: 0 };
  }

  async getScanResult(scanId: string): Promise<ScanResult> {
    const response = await apiClient.get<ApiResponse<ScanResult>>(`${this.baseUrl}/scan-results/${scanId}`);
    if (!response.data.data) {
      throw new Error('Scan result not found');
    }
    return response.data.data;
  }

  // Repository Synchronization
  async syncImageRepository(id: string): Promise<{ success: boolean; message: string }> {
    const response = await apiClient.post<ApiResponse<{ success: boolean; message: string }>>(
      `${this.baseUrl}/images/${id}/sync`
    );
    return response.data.data || { success: false, message: 'Unknown error' };
  }

  async syncChartRepository(id: string): Promise<{ success: boolean; message: string }> {
    const response = await apiClient.post<ApiResponse<{ success: boolean; message: string }>>(
      `${this.baseUrl}/charts/${id}/sync`
    );
    return response.data.data || { success: false, message: 'Unknown error' };
  }

  // Image Push Operations
  async pushImage(repositoryId: string, imageName: string, tag: string, sourceImage: string): Promise<{ success: boolean; message: string }> {
    const response = await apiClient.post<ApiResponse<{ success: boolean; message: string }>>(
      `${this.baseUrl}/images/${repositoryId}/push`,
      { imageName, tag, sourceImage }
    );
    return response.data.data || { success: false, message: 'Unknown error' };
  }

  async promoteImage(
    sourceRepositoryId: string,
    targetRepositoryId: string,
    imageName: string,
    sourceTag: string,
    targetTag: string
  ): Promise<{ success: boolean; message: string }> {
    const response = await apiClient.post<ApiResponse<{ success: boolean; message: string }>>(
      `${this.baseUrl}/images/promote`,
      { sourceRepositoryId, targetRepositoryId, imageName, sourceTag, targetTag }
    );
    return response.data.data || { success: false, message: 'Unknown error' };
  }

  // Vulnerability Statistics
  async getVulnerabilityStats(repositoryId: string, type: 'image' | 'chart'): Promise<VulnerabilityStats> {
    const response = await apiClient.get<ApiResponse<VulnerabilityStats>>(
      `${this.baseUrl}/${type}s/${repositoryId}/vulnerability-stats`
    );
    return response.data.data || { total: 0, critical: 0, high: 0, medium: 0, low: 0, trend: 'stable' };
  }

  async getRepositoryStats(): Promise<{
    totalRepositories: number;
    totalImages: number;
    totalCharts: number;
    totalVulnerabilities: number;
    criticalVulnerabilities: number;
  }> {
    const response = await apiClient.get<ApiResponse<{
      totalRepositories: number;
      totalImages: number;
      totalCharts: number;
      totalVulnerabilities: number;
      criticalVulnerabilities: number;
    }>>(`${this.baseUrl}/stats`);
    return response.data.data || {
      totalRepositories: 0,
      totalImages: 0,
      totalCharts: 0,
      totalVulnerabilities: 0,
      criticalVulnerabilities: 0,
    };
  }

  // Bulk Operations
  async bulkScanImages(repositoryId: string, images: { name: string; tag: string }[]): Promise<{ scanIds: string[] }> {
    const response = await apiClient.post<ApiResponse<{ scanIds: string[] }>>(
      `${this.baseUrl}/images/${repositoryId}/bulk-scan`,
      { images }
    );
    return response.data.data || { scanIds: [] };
  }

  async bulkDeleteImages(repositoryId: string, images: { name: string; tag: string }[]): Promise<{ success: boolean; results: any[] }> {
    const response = await apiClient.post<ApiResponse<{ success: boolean; results: any[] }>>(
      `${this.baseUrl}/images/${repositoryId}/bulk-delete`,
      { images }
    );
    return response.data.data || { success: false, results: [] };
  }
}

export const repositoryApi = new RepositoryApi();
