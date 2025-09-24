import { apiClient } from './apiClient';

export interface Vulnerability {
  id: string;
  title: string;
  description: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvss_score: number;
  cvss_vector?: string;
  cve_id?: string;
  cwe_id?: string;
  asset: string;
  port?: number;
  service?: string;
  protocol?: string;
  status: 'open' | 'in_progress' | 'resolved' | 'false_positive' | 'accepted_risk';
  first_detected: string;
  last_seen: string;
  scan_id: string;
  scan_name: string;
  remediation?: string;
  references: string[];
  tags: string[];
  assigned_to?: string;
  resolution_notes?: string;
  risk_score: number;
  created_at: string;
  updated_at: string;
  organization_id: string;
  evidence?: {
    request?: string;
    response?: string;
    proof_of_concept?: string;
    screenshots?: string[];
  };
  exploit_info?: {
    exploitability: 'not_defined' | 'unproven' | 'proof_of_concept' | 'functional' | 'high';
    exploit_available: boolean;
    public_exploit: boolean;
  };
}

export interface VulnerabilityFilters {
  search?: string;
  severity?: string[];
  status?: string[];
  asset?: string;
  cve_id?: string;
  assigned_to?: string;
  date_from?: string;
  date_to?: string;
  scan_id?: string;
  page?: number;
  limit?: number;
  sort_by?: 'created_at' | 'cvss_score' | 'risk_score' | 'severity';
  sort_order?: 'asc' | 'desc';
}

export interface VulnerabilityListResponse {
  vulnerabilities: Vulnerability[];
  total: number;
  page: number;
  limit: number;
  total_pages: number;
  filters_applied: VulnerabilityFilters;
}

export interface VulnerabilityStats {
  total: number;
  by_severity: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  by_status: {
    open: number;
    in_progress: number;
    resolved: number;
    false_positive: number;
    accepted_risk: number;
  };
  trend: {
    period: string;
    new_vulnerabilities: number;
    resolved_vulnerabilities: number;
  }[];
}

export interface UpdateVulnerabilityRequest {
  status?: 'open' | 'in_progress' | 'resolved' | 'false_positive' | 'accepted_risk';
  assigned_to?: string;
  resolution_notes?: string;
  tags?: string[];
}

class VulnerabilitiesAPI {
  /**
   * Get list of vulnerabilities with optional filters
   */
  public async getVulnerabilities(
    filters?: VulnerabilityFilters
  ): Promise<VulnerabilityListResponse> {
    return apiClient.get<VulnerabilityListResponse>('/vulnerabilities', filters);
  }

  /**
   * Get vulnerability by ID
   */
  public async getVulnerability(vulnerabilityId: string): Promise<Vulnerability> {
    return apiClient.get<Vulnerability>(`/vulnerabilities/${vulnerabilityId}`);
  }

  /**
   * Update vulnerability
   */
  public async updateVulnerability(
    vulnerabilityId: string,
    updates: UpdateVulnerabilityRequest
  ): Promise<Vulnerability> {
    return apiClient.patch<Vulnerability>(`/vulnerabilities/${vulnerabilityId}`, updates);
  }

  /**
   * Bulk update vulnerabilities
   */
  public async bulkUpdateVulnerabilities(
    vulnerabilityIds: string[],
    updates: UpdateVulnerabilityRequest
  ): Promise<{ updated_count: number; vulnerabilities: Vulnerability[] }> {
    return apiClient.patch<any>('/vulnerabilities/bulk', {
      vulnerability_ids: vulnerabilityIds,
      updates,
    });
  }

  /**
   * Delete vulnerability
   */
  public async deleteVulnerability(vulnerabilityId: string): Promise<void> {
    return apiClient.delete<void>(`/vulnerabilities/${vulnerabilityId}`);
  }

  /**
   * Get vulnerability statistics
   */
  public async getVulnerabilityStats(): Promise<VulnerabilityStats> {
    return apiClient.get<VulnerabilityStats>('/vulnerabilities/stats');
  }

  /**
   * Export vulnerabilities to various formats
   */
  public async exportVulnerabilities(
    filters?: VulnerabilityFilters,
    format: 'csv' | 'json' | 'xlsx' = 'csv'
  ): Promise<Blob> {
    const response = await apiClient.getClient().get('/vulnerabilities/export', {
      params: { ...filters, format },
      responseType: 'blob',
    });
    return response.data;
  }

  /**
   * Get vulnerability by CVE ID
   */
  public async getVulnerabilityByCVE(cveId: string): Promise<Vulnerability[]> {
    return apiClient.get<Vulnerability[]>(`/vulnerabilities/cve/${cveId}`);
  }

  /**
   * Get vulnerabilities for specific asset
   */
  public async getAssetVulnerabilities(asset: string): Promise<Vulnerability[]> {
    return apiClient.get<Vulnerability[]>(`/vulnerabilities/asset`, { asset });
  }

  /**
   * Get similar vulnerabilities
   */
  public async getSimilarVulnerabilities(vulnerabilityId: string): Promise<Vulnerability[]> {
    return apiClient.get<Vulnerability[]>(`/vulnerabilities/${vulnerabilityId}/similar`);
  }

  /**
   * Create manual vulnerability
   */
  public async createVulnerability(
    vulnerabilityData: Partial<Vulnerability>
  ): Promise<Vulnerability> {
    return apiClient.post<Vulnerability>('/vulnerabilities', vulnerabilityData);
  }

  /**
   * Get vulnerability remediation guidance
   */
  public async getRemediationGuidance(vulnerabilityId: string): Promise<{
    remediation_steps: string[];
    estimated_effort: string;
    priority: string;
    resources: { title: string; url: string; type: string }[];
  }> {
    return apiClient.get<any>(`/vulnerabilities/${vulnerabilityId}/remediation`);
  }

  /**
   * Mark vulnerability as false positive
   */
  public async markFalsePositive(vulnerabilityId: string, reason: string): Promise<Vulnerability> {
    return apiClient.post<Vulnerability>(`/vulnerabilities/${vulnerabilityId}/false-positive`, {
      reason,
    });
  }

  /**
   * Accept vulnerability risk
   */
  public async acceptRisk(
    vulnerabilityId: string,
    justification: string,
    expiry_date?: string
  ): Promise<Vulnerability> {
    return apiClient.post<Vulnerability>(`/vulnerabilities/${vulnerabilityId}/accept-risk`, {
      justification,
      expiry_date,
    });
  }
}

// Create and export singleton instance
export const vulnerabilitiesApi = new VulnerabilitiesAPI();

// Export class for testing
export { VulnerabilitiesAPI };
