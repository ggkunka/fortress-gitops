import { apiClient } from './apiClient';

export interface Report {
  id: string;
  name: string;
  type: 'security' | 'compliance' | 'executive' | 'technical' | 'vulnerability';
  format: 'pdf' | 'html' | 'csv' | 'json' | 'xlsx';
  status: 'generating' | 'completed' | 'failed' | 'scheduled';
  created_at: string;
  completed_at?: string;
  size?: number;
  download_url?: string;
  schedule?: {
    frequency: 'daily' | 'weekly' | 'monthly';
    day_of_week?: number;
    day_of_month?: number;
    time: string;
    timezone?: string;
    enabled: boolean;
  };
  filters: {
    date_range?: string;
    severity?: string[];
    assets?: string[];
    scan_types?: string[];
    organization_id?: string;
  };
  created_by: string;
  recipients?: string[];
  organization_id: string;
  template_id?: string;
  error_message?: string;
  generation_time?: number;
}

export interface CreateReportRequest {
  name: string;
  type: 'security' | 'compliance' | 'executive' | 'technical' | 'vulnerability';
  format: 'pdf' | 'html' | 'csv' | 'json' | 'xlsx';
  filters: {
    date_range?: string;
    severity?: string[];
    assets?: string[];
    scan_types?: string[];
  };
  schedule?: {
    frequency?: 'daily' | 'weekly' | 'monthly';
    day_of_week?: number;
    day_of_month?: number;
    time?: string;
    timezone?: string;
    enabled?: boolean;
  };
  recipients?: string[];
  template_id?: string;
  description?: string;
}

export interface ReportTemplate {
  id: string;
  name: string;
  description: string;
  type: 'security' | 'compliance' | 'executive' | 'technical' | 'vulnerability';
  sections: {
    id: string;
    name: string;
    type: string;
    enabled: boolean;
    config: any;
  }[];
  created_by: string;
  is_default: boolean;
  organization_id: string;
}

export interface ReportStats {
  total_reports: number;
  completed_reports: number;
  scheduled_reports: number;
  failed_reports: number;
  total_size: number;
  average_generation_time: number;
}

class ReportsAPI {
  /**
   * Get list of reports
   */
  public async getReports(filters?: {
    type?: string;
    status?: string;
    created_by?: string;
    page?: number;
    limit?: number;
  }): Promise<{
    reports: Report[];
    total: number;
    page: number;
    limit: number;
    total_pages: number;
  }> {
    return apiClient.get<any>('/reports', filters);
  }

  /**
   * Get report by ID
   */
  public async getReport(reportId: string): Promise<Report> {
    return apiClient.get<Report>(`/reports/${reportId}`);
  }

  /**
   * Create new report
   */
  public async createReport(reportData: CreateReportRequest): Promise<Report> {
    return apiClient.post<Report>('/reports', reportData);
  }

  /**
   * Update report
   */
  public async updateReport(reportId: string, updates: Partial<Report>): Promise<Report> {
    return apiClient.patch<Report>(`/reports/${reportId}`, updates);
  }

  /**
   * Delete report
   */
  public async deleteReport(reportId: string): Promise<void> {
    return apiClient.delete<void>(`/reports/${reportId}`);
  }

  /**
   * Download report
   */
  public async downloadReport(reportId: string): Promise<Blob> {
    const response = await apiClient.getClient().get(`/reports/${reportId}/download`, {
      responseType: 'blob',
    });
    return response.data;
  }

  /**
   * Generate report immediately
   */
  public async generateReport(reportId: string): Promise<Report> {
    return apiClient.post<Report>(`/reports/${reportId}/generate`);
  }

  /**
   * Get report statistics
   */
  public async getReportStats(): Promise<ReportStats> {
    return apiClient.get<ReportStats>('/reports/stats');
  }

  /**
   * Get report templates
   */
  public async getReportTemplates(): Promise<ReportTemplate[]> {
    return apiClient.get<ReportTemplate[]>('/reports/templates');
  }

  /**
   * Create report template
   */
  public async createReportTemplate(templateData: Partial<ReportTemplate>): Promise<ReportTemplate> {
    return apiClient.post<ReportTemplate>('/reports/templates', templateData);
  }

  /**
   * Update report template
   */
  public async updateReportTemplate(
    templateId: string, 
    updates: Partial<ReportTemplate>
  ): Promise<ReportTemplate> {
    return apiClient.patch<ReportTemplate>(`/reports/templates/${templateId}`, updates);
  }

  /**
   * Delete report template
   */
  public async deleteReportTemplate(templateId: string): Promise<void> {
    return apiClient.delete<void>(`/reports/templates/${templateId}`);
  }

  /**
   * Schedule report
   */
  public async scheduleReport(reportId: string, schedule: Report['schedule']): Promise<Report> {
    return apiClient.post<Report>(`/reports/${reportId}/schedule`, { schedule });
  }

  /**
   * Unschedule report
   */
  public async unscheduleReport(reportId: string): Promise<Report> {
    return apiClient.delete<Report>(`/reports/${reportId}/schedule`);
  }

  /**
   * Get scheduled reports
   */
  public async getScheduledReports(): Promise<Report[]> {
    return apiClient.get<Report[]>('/reports/scheduled');
  }

  /**
   * Send report via email
   */
  public async sendReport(reportId: string, recipients: string[], message?: string): Promise<void> {
    return apiClient.post<void>(`/reports/${reportId}/send`, {
      recipients,
      message,
    });
  }

  /**
   * Get report generation history
   */
  public async getReportHistory(reportId: string): Promise<{
    executions: {
      id: string;
      started_at: string;
      completed_at?: string;
      status: string;
      error_message?: string;
      size?: number;
      generation_time?: number;
    }[];
  }> {
    return apiClient.get<any>(`/reports/${reportId}/history`);
  }

  /**
   * Preview report content
   */
  public async previewReport(reportData: CreateReportRequest): Promise<{
    preview_url: string;
    expires_at: string;
  }> {
    return apiClient.post<any>('/reports/preview', reportData);
  }
}

// Create and export singleton instance
export const reportsApi = new ReportsAPI();

// Export class for testing
export { ReportsAPI };