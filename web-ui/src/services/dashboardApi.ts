import { apiClient } from './apiClient';

export interface DashboardStats {
  total_scans: number;
  active_scans: number;
  total_vulnerabilities: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  total_assets: number;
  protected_assets: number;
  total_integrations: number;
  active_integrations: number;
  last_scan_time?: string;
  security_score: number;
  compliance_score: number;
}

export interface VulnerabilityTrend {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  total: number;
}

export interface ScanActivity {
  date: string;
  scans_completed: number;
  scans_failed: number;
  vulnerabilities_found: number;
  assets_scanned: number;
}

export interface TopVulnerabilities {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  cvss_score: number;
  affected_assets: number;
  first_detected: string;
  cve_id?: string;
}

export interface AssetRisk {
  asset: string;
  ip_address?: string;
  hostname?: string;
  risk_score: number;
  vulnerability_count: number;
  critical_vulnerabilities: number;
  high_vulnerabilities: number;
  last_scan: string;
  scan_status: 'completed' | 'in_progress' | 'failed' | 'pending';
}

export interface RecentScan {
  id: string;
  name: string;
  type: 'network' | 'web' | 'infrastructure' | 'compliance';
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  target: string;
  started_at: string;
  completed_at?: string;
  vulnerabilities_found: number;
  progress: number;
}

export interface SecurityMetrics {
  mean_time_to_detection: number; // hours
  mean_time_to_remediation: number; // hours
  vulnerability_discovery_rate: number; // per day
  false_positive_rate: number; // percentage
  scan_success_rate: number; // percentage
  asset_coverage: number; // percentage
}

export interface ComplianceStatus {
  framework: string;
  status: 'compliant' | 'non_compliant' | 'partially_compliant' | 'unknown';
  score: number;
  controls_passed: number;
  controls_failed: number;
  controls_total: number;
  last_assessment: string;
}

export interface AlertSummary {
  total_alerts: number;
  critical_alerts: number;
  unacknowledged_alerts: number;
  recent_alerts: {
    id: string;
    title: string;
    severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
    timestamp: string;
    source: string;
    acknowledged: boolean;
  }[];
}

class DashboardAPI {
  /**
   * Get dashboard overview statistics
   */
  public async getDashboardStats(): Promise<DashboardStats> {
    return apiClient.get<DashboardStats>('/dashboard/stats');
  }

  /**
   * Get vulnerability trends over time
   */
  public async getVulnerabilityTrends(
    timeRange: '7d' | '30d' | '90d' | '1y' = '30d'
  ): Promise<VulnerabilityTrend[]> {
    return apiClient.get<VulnerabilityTrend[]>('/dashboard/vulnerability-trends', {
      time_range: timeRange,
    });
  }

  /**
   * Get scan activity over time
   */
  public async getScanActivity(
    timeRange: '7d' | '30d' | '90d' | '1y' = '30d'
  ): Promise<ScanActivity[]> {
    return apiClient.get<ScanActivity[]>('/dashboard/scan-activity', {
      time_range: timeRange,
    });
  }

  /**
   * Get top vulnerabilities by impact
   */
  public async getTopVulnerabilities(limit: number = 10): Promise<TopVulnerabilities[]> {
    return apiClient.get<TopVulnerabilities[]>('/dashboard/top-vulnerabilities', { limit });
  }

  /**
   * Get assets by risk level
   */
  public async getAssetsByRisk(limit: number = 10): Promise<AssetRisk[]> {
    return apiClient.get<AssetRisk[]>('/dashboard/assets-by-risk', { limit });
  }

  /**
   * Get recent scan activity
   */
  public async getRecentScans(limit: number = 10): Promise<RecentScan[]> {
    return apiClient.get<RecentScan[]>('/dashboard/recent-scans', { limit });
  }

  /**
   * Get security metrics and KPIs
   */
  public async getSecurityMetrics(): Promise<SecurityMetrics> {
    return apiClient.get<SecurityMetrics>('/dashboard/security-metrics');
  }

  /**
   * Get compliance status across frameworks
   */
  public async getComplianceStatus(): Promise<ComplianceStatus[]> {
    return apiClient.get<ComplianceStatus[]>('/dashboard/compliance-status');
  }

  /**
   * Get alert summary and recent alerts
   */
  public async getAlertSummary(): Promise<AlertSummary> {
    return apiClient.get<AlertSummary>('/dashboard/alerts');
  }

  /**
   * Get vulnerability distribution by severity
   */
  public async getVulnerabilityDistribution(): Promise<{
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  }> {
    return apiClient.get<any>('/dashboard/vulnerability-distribution');
  }

  /**
   * Get scan status distribution
   */
  public async getScanStatusDistribution(): Promise<{
    completed: number;
    running: number;
    failed: number;
    pending: number;
    cancelled: number;
  }> {
    return apiClient.get<any>('/dashboard/scan-status-distribution');
  }

  /**
   * Get integration health summary
   */
  public async getIntegrationHealth(): Promise<{
    total_integrations: number;
    healthy_integrations: number;
    warning_integrations: number;
    error_integrations: number;
    integrations: {
      id: string;
      name: string;
      type: string;
      status: 'healthy' | 'warning' | 'error';
      last_check: string;
    }[];
  }> {
    return apiClient.get<any>('/dashboard/integration-health');
  }

  /**
   * Get system resource usage
   */
  public async getSystemResources(): Promise<{
    cpu_usage: number;
    memory_usage: number;
    disk_usage: number;
    network_usage: {
      bytes_in: number;
      bytes_out: number;
    };
    active_processes: number;
    scan_queue_size: number;
  }> {
    return apiClient.get<any>('/dashboard/system-resources');
  }

  /**
   * Get threat intelligence summary
   */
  public async getThreatIntelligence(): Promise<{
    total_indicators: number;
    recent_indicators: number;
    threat_feeds: {
      name: string;
      status: 'active' | 'inactive' | 'error';
      last_update: string;
      indicator_count: number;
    }[];
    top_threats: {
      indicator: string;
      type: 'ip' | 'domain' | 'hash' | 'url';
      threat_type: string;
      confidence: number;
      first_seen: string;
    }[];
  }> {
    return apiClient.get<any>('/dashboard/threat-intelligence');
  }

  /**
   * Get custom dashboard widgets configuration
   */
  public async getDashboardWidgets(): Promise<
    {
      id: string;
      type: string;
      title: string;
      position: { x: number; y: number; w: number; h: number };
      config: any;
      enabled: boolean;
    }[]
  > {
    return apiClient.get<any>('/dashboard/widgets');
  }

  /**
   * Update dashboard widgets configuration
   */
  public async updateDashboardWidgets(
    widgets: {
      id: string;
      type: string;
      title: string;
      position: { x: number; y: number; w: number; h: number };
      config: any;
      enabled: boolean;
    }[]
  ): Promise<void> {
    return apiClient.put<void>('/dashboard/widgets', { widgets });
  }

  /**
   * Export dashboard data
   */
  public async exportDashboardData(
    format: 'pdf' | 'png' | 'csv' = 'pdf',
    widgets?: string[]
  ): Promise<Blob> {
    const response = await apiClient.getClient().get('/dashboard/export', {
      params: { format, widgets: widgets?.join(',') },
      responseType: 'blob',
    });
    return response.data;
  }

  /**
   * Get real-time dashboard updates
   */
  public async getDashboardUpdates(lastUpdate?: string): Promise<{
    timestamp: string;
    updates: {
      type: 'scan_completed' | 'vulnerability_found' | 'integration_error' | 'system_alert';
      data: any;
    }[];
  }> {
    return apiClient.get<any>('/dashboard/updates', { last_update: lastUpdate });
  }
}

// Create and export singleton instance
export const dashboardApi = new DashboardAPI();

// Export class for testing
export { DashboardAPI };
