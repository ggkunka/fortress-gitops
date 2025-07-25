import { apiClient } from './apiClient';

export interface Integration {
  id: string;
  name: string;
  type: 'siem' | 'cloud_security' | 'threat_intelligence' | 'vulnerability_management' | 'ticketing';
  provider: string;
  status: 'connected' | 'disconnected' | 'error' | 'testing';
  enabled: boolean;
  last_sync?: string;
  sync_frequency: number; // minutes
  config: {
    endpoint?: string;
    api_key?: string;
    username?: string;
    password?: string;
    region?: string;
    account_id?: string;
    project_id?: string;
    workspace_id?: string;
    [key: string]: any;
  };
  health: {
    status: 'healthy' | 'warning' | 'error';
    last_check: string;
    message?: string;
    response_time?: number;
  };
  metrics: {
    events_ingested: number;
    data_exported: number;
    last_activity?: string;
    sync_errors: number;
    uptime_percentage: number;
  };
  created_at: string;
  updated_at: string;
  created_by: string;
  organization_id: string;
  tags?: string[];
  description?: string;
}

export interface CreateIntegrationRequest {
  name: string;
  type: 'siem' | 'cloud_security' | 'threat_intelligence' | 'vulnerability_management' | 'ticketing';
  provider: string;
  config: {
    endpoint?: string;
    api_key?: string;
    username?: string;
    password?: string;
    region?: string;
    account_id?: string;
    project_id?: string;
    workspace_id?: string;
    [key: string]: any;
  };
  sync_frequency?: number;
  enabled?: boolean;
  description?: string;
  tags?: string[];
}

export interface IntegrationProvider {
  id: string;
  name: string;
  type: string;
  description: string;
  logo_url?: string;
  documentation_url?: string;
  required_fields: {
    name: string;
    type: 'text' | 'password' | 'url' | 'select';
    label: string;
    description?: string;
    required: boolean;
    options?: { value: string; label: string }[];
  }[];
  optional_fields: {
    name: string;
    type: 'text' | 'password' | 'url' | 'select' | 'number';
    label: string;
    description?: string;
    default_value?: any;
    options?: { value: string; label: string }[];
  }[];
  supported_features: string[];
}

export interface IntegrationLog {
  id: string;
  integration_id: string;
  timestamp: string;
  level: 'info' | 'warning' | 'error';
  message: string;
  details?: any;
  sync_id?: string;
}

export interface SyncResult {
  id: string;
  integration_id: string;
  started_at: string;
  completed_at?: string;
  status: 'running' | 'completed' | 'failed';
  records_processed: number;
  records_success: number;
  records_failed: number;
  error_message?: string;
  duration?: number;
}

class IntegrationsAPI {
  /**
   * Get list of integrations
   */
  public async getIntegrations(filters?: {
    type?: string;
    provider?: string;
    status?: string;
    enabled?: boolean;
    page?: number;
    limit?: number;
  }): Promise<{
    integrations: Integration[];
    total: number;
    page: number;
    limit: number;
    total_pages: number;
  }> {
    return apiClient.get<any>('/integrations', filters);
  }

  /**
   * Get integration by ID
   */
  public async getIntegration(integrationId: string): Promise<Integration> {
    return apiClient.get<Integration>(`/integrations/${integrationId}`);
  }

  /**
   * Create new integration
   */
  public async createIntegration(integrationData: CreateIntegrationRequest): Promise<Integration> {
    return apiClient.post<Integration>('/integrations', integrationData);
  }

  /**
   * Update integration
   */
  public async updateIntegration(
    integrationId: string, 
    updates: Partial<Integration>
  ): Promise<Integration> {
    return apiClient.patch<Integration>(`/integrations/${integrationId}`, updates);
  }

  /**
   * Delete integration
   */
  public async deleteIntegration(integrationId: string): Promise<void> {
    return apiClient.delete<void>(`/integrations/${integrationId}`);
  }

  /**
   * Test integration connection
   */
  public async testIntegration(integrationId: string): Promise<{
    success: boolean;
    message: string;
    response_time: number;
    details?: any;
  }> {
    return apiClient.post<any>(`/integrations/${integrationId}/test`);
  }

  /**
   * Test integration configuration before creating
   */
  public async testIntegrationConfig(config: CreateIntegrationRequest): Promise<{
    success: boolean;
    message: string;
    response_time: number;
    details?: any;
  }> {
    return apiClient.post<any>('/integrations/test-config', config);
  }

  /**
   * Enable/disable integration
   */
  public async toggleIntegration(integrationId: string, enabled: boolean): Promise<Integration> {
    return apiClient.patch<Integration>(`/integrations/${integrationId}`, { enabled });
  }

  /**
   * Sync integration now
   */
  public async syncIntegration(integrationId: string): Promise<SyncResult> {
    return apiClient.post<SyncResult>(`/integrations/${integrationId}/sync`);
  }

  /**
   * Get integration health status
   */
  public async getIntegrationHealth(integrationId: string): Promise<{
    status: 'healthy' | 'warning' | 'error';
    checks: {
      name: string;
      status: 'pass' | 'fail' | 'warning';
      message: string;
      response_time?: number;
    }[];
    last_check: string;
  }> {
    return apiClient.get<any>(`/integrations/${integrationId}/health`);
  }

  /**
   * Get integration logs
   */
  public async getIntegrationLogs(
    integrationId: string,
    filters?: {
      level?: string;
      date_from?: string;
      date_to?: string;
      page?: number;
      limit?: number;
    }
  ): Promise<{
    logs: IntegrationLog[];
    total: number;
    page: number;
    limit: number;
    total_pages: number;
  }> {
    return apiClient.get<any>(`/integrations/${integrationId}/logs`, filters);
  }

  /**
   * Get integration sync history
   */
  public async getSyncHistory(
    integrationId: string,
    filters?: {
      status?: string;
      date_from?: string;
      date_to?: string;
      page?: number;
      limit?: number;
    }
  ): Promise<{
    syncs: SyncResult[];
    total: number;
    page: number;
    limit: number;
    total_pages: number;
  }> {
    return apiClient.get<any>(`/integrations/${integrationId}/sync-history`, filters);
  }

  /**
   * Get available integration providers
   */
  public async getIntegrationProviders(): Promise<IntegrationProvider[]> {
    return apiClient.get<IntegrationProvider[]>('/integrations/providers');
  }

  /**
   * Get integration provider by ID
   */
  public async getIntegrationProvider(providerId: string): Promise<IntegrationProvider> {
    return apiClient.get<IntegrationProvider>(`/integrations/providers/${providerId}`);
  }

  /**
   * Get integration statistics
   */
  public async getIntegrationStats(): Promise<{
    total_integrations: number;
    connected_integrations: number;
    enabled_integrations: number;
    failed_integrations: number;
    by_type: Record<string, number>;
    by_provider: Record<string, number>;
    sync_stats: {
      total_syncs: number;
      successful_syncs: number;
      failed_syncs: number;
      average_sync_time: number;
    };
  }> {
    return apiClient.get<any>('/integrations/stats');
  }

  /**
   * Get integration metrics
   */
  public async getIntegrationMetrics(
    integrationId: string,
    timeRange: '1h' | '24h' | '7d' | '30d' = '24h'
  ): Promise<{
    events_ingested: { timestamp: string; value: number }[];
    data_exported: { timestamp: string; value: number }[];
    response_times: { timestamp: string; value: number }[];
    error_rate: { timestamp: string; value: number }[];
  }> {
    return apiClient.get<any>(`/integrations/${integrationId}/metrics`, { time_range: timeRange });
  }

  /**
   * Export integration configuration
   */
  public async exportIntegrationConfig(integrationId: string): Promise<Blob> {
    const response = await apiClient.getClient().get(`/integrations/${integrationId}/export`, {
      responseType: 'blob',
    });
    return response.data;
  }

  /**
   * Import integration configuration
   */
  public async importIntegrationConfig(configFile: File): Promise<Integration> {
    const formData = new FormData();
    formData.append('config_file', configFile);
    
    const response = await apiClient.getClient().post('/integrations/import', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  }
}

// Create and export singleton instance
export const integrationsApi = new IntegrationsAPI();

// Export class for testing
export { IntegrationsAPI };