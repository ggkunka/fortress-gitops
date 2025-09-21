import { apiClient } from './apiClient';

export interface Scan {
  id: string;
  name: string;
  type: 'network' | 'web' | 'infrastructure' | 'compliance';
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  target: string;
  progress: number;
  vulnerabilities_found: number;
  severity_counts: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  started_at?: string;
  completed_at?: string;
  duration?: number;
  created_by: string;
  created_at: string;
  updated_at: string;
  organization_id: string;
  scan_config?: {
    ports?: string;
    exclude_hosts?: string[];
    scan_techniques?: string[];
    timing_template?: string;
    max_scan_time?: number;
  };
  results_summary?: {
    hosts_discovered: number;
    services_detected: number;
    vulnerabilities_found: number;
    compliance_issues: number;
  };
}

export interface CreateScanRequest {
  name: string;
  type: 'network' | 'web' | 'infrastructure' | 'compliance';
  target: string;
  description?: string;
  scan_config?: {
    ports?: string;
    exclude_hosts?: string[];
    scan_techniques?: string[];
    timing_template?: string;
    max_scan_time?: number;
  };
  schedule?: {
    frequency?: 'once' | 'daily' | 'weekly' | 'monthly';
    start_time?: string;
    timezone?: string;
  };
}

export interface ScanFilters {
  search?: string;
  status?: string;
  type?: string;
  created_by?: string;
  date_from?: string;
  date_to?: string;
  page?: number;
  limit?: number;
}

export interface ScanListResponse {
  scans: Scan[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
}

class ScansAPI {
  /**
   * Get list of scans with optional filters
   */
  public async getScans(filters?: ScanFilters): Promise<ScanListResponse> {
    return apiClient.get<ScanListResponse>('/scans', filters);
  }

  /**
   * Get scan by ID
   */
  public async getScan(scanId: string): Promise<Scan> {
    return apiClient.get<Scan>(`/scans/${scanId}`);
  }

  /**
   * Create new scan
   */
  public async createScan(scanData: CreateScanRequest): Promise<Scan> {
    return apiClient.post<Scan>('/scans', scanData);
  }

  /**
   * Update scan
   */
  public async updateScan(scanId: string, updates: Partial<Scan>): Promise<Scan> {
    return apiClient.patch<Scan>(`/scans/${scanId}`, updates);
  }

  /**
   * Delete scan
   */
  public async deleteScan(scanId: string): Promise<void> {
    return apiClient.delete<void>(`/scans/${scanId}`);
  }

  /**
   * Start scan
   */
  public async startScan(scanId: string): Promise<Scan> {
    return apiClient.post<Scan>(`/scans/${scanId}/start`);
  }

  /**
   * Stop scan
   */
  public async stopScan(scanId: string): Promise<Scan> {
    return apiClient.post<Scan>(`/scans/${scanId}/stop`);
  }

  /**
   * Get scan results
   */
  public async getScanResults(scanId: string): Promise<any> {
    return apiClient.get<any>(`/scans/${scanId}/results`);
  }

  /**
   * Download scan report
   */
  public async downloadScanReport(scanId: string, format: string = 'pdf'): Promise<Blob> {
    const response = await apiClient.getClient().get(`/scans/${scanId}/report`, {
      params: { format },
      responseType: 'blob',
    });
    return response.data;
  }

  /**
   * Get scan statistics
   */
  public async getScanStats(): Promise<{
    total: number;
    running: number;
    completed: number;
    failed: number;
    pending: number;
  }> {
    return apiClient.get<any>('/scans/stats');
  }

  /**
   * Get available scan types and configurations
   */
  public async getScanTypes(): Promise<
    {
      type: string;
      name: string;
      description: string;
      required_fields: string[];
      optional_fields: string[];
    }[]
  > {
    return apiClient.get<any>('/scans/types');
  }
}

// Create and export singleton instance
export const scansApi = new ScansAPI();

// Export class for testing
export { ScansAPI };
