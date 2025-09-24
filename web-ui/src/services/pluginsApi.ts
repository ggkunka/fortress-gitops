import { apiClient } from './apiClient';

export interface Plugin {
  id: string;
  name: string;
  description: string;
  category: 'scanner' | 'integration' | 'reporting' | 'analysis' | 'automation';
  version: string;
  author: string;
  author_verified: boolean;
  downloads: number;
  rating: number;
  reviews_count: number;
  tags: string[];
  price: number; // 0 for free
  official: boolean;
  status: 'available' | 'installed' | 'updating' | 'deprecated';
  requirements: {
    min_platform_version: string;
    dependencies: string[];
    permissions: string[];
    system_requirements?: {
      min_memory?: string;
      min_disk_space?: string;
      supported_os?: string[];
    };
  };
  screenshots: string[];
  documentation_url?: string;
  source_url?: string;
  created_at: string;
  updated_at: string;
  changelog?: string;
  installation_size?: number;
  license?: string;
  support_email?: string;
  organization_id?: string;
}

export interface PluginReview {
  id: string;
  plugin_id: string;
  user_id: string;
  username: string;
  rating: number;
  comment: string;
  created_at: string;
  updated_at: string;
  helpful_count: number;
  verified_purchase: boolean;
}

export interface InstalledPlugin {
  plugin_id: string;
  plugin: Plugin;
  installed_version: string;
  latest_version: string;
  installed_at: string;
  last_updated?: string;
  status: 'active' | 'inactive' | 'error' | 'updating';
  config?: Record<string, any>;
  enabled: boolean;
  update_available: boolean;
  error_message?: string;
}

export interface PluginFilters {
  search?: string;
  category?: string;
  price?: 'free' | 'paid' | 'all';
  official?: boolean;
  sort_by?: 'popular' | 'rating' | 'newest' | 'price_low' | 'price_high';
  tags?: string[];
  page?: number;
  limit?: number;
}

export interface PluginInstallationResult {
  success: boolean;
  plugin_id: string;
  message: string;
  installation_log?: string[];
  error_details?: string;
}

class PluginsAPI {
  /**
   * Get list of available plugins
   */
  public async getPlugins(filters?: PluginFilters): Promise<{
    plugins: Plugin[];
    total: number;
    page: number;
    limit: number;
    total_pages: number;
  }> {
    return apiClient.get<any>('/plugins', filters);
  }

  /**
   * Get plugin by ID
   */
  public async getPlugin(pluginId: string): Promise<Plugin> {
    return apiClient.get<Plugin>(`/plugins/${pluginId}`);
  }

  /**
   * Install plugin
   */
  public async installPlugin(
    pluginId: string,
    config?: Record<string, any>
  ): Promise<PluginInstallationResult> {
    return apiClient.post<PluginInstallationResult>(`/plugins/${pluginId}/install`, { config });
  }

  /**
   * Uninstall plugin
   */
  public async uninstallPlugin(pluginId: string): Promise<{
    success: boolean;
    message: string;
    uninstallation_log?: string[];
  }> {
    return apiClient.post<any>(`/plugins/${pluginId}/uninstall`);
  }

  /**
   * Update plugin
   */
  public async updatePlugin(pluginId: string): Promise<PluginInstallationResult> {
    return apiClient.post<PluginInstallationResult>(`/plugins/${pluginId}/update`);
  }

  /**
   * Get installed plugins
   */
  public async getInstalledPlugins(): Promise<InstalledPlugin[]> {
    return apiClient.get<InstalledPlugin[]>('/plugins/installed');
  }

  /**
   * Enable/disable installed plugin
   */
  public async togglePlugin(pluginId: string, enabled: boolean): Promise<InstalledPlugin> {
    return apiClient.patch<InstalledPlugin>(`/plugins/installed/${pluginId}`, { enabled });
  }

  /**
   * Configure installed plugin
   */
  public async configurePlugin(
    pluginId: string,
    config: Record<string, any>
  ): Promise<InstalledPlugin> {
    return apiClient.patch<InstalledPlugin>(`/plugins/installed/${pluginId}/config`, { config });
  }

  /**
   * Get plugin configuration schema
   */
  public async getPluginConfigSchema(pluginId: string): Promise<{
    schema: any;
    ui_schema?: any;
    default_values?: Record<string, any>;
  }> {
    return apiClient.get<any>(`/plugins/${pluginId}/config-schema`);
  }

  /**
   * Get plugin reviews
   */
  public async getPluginReviews(
    pluginId: string,
    filters?: {
      rating?: number;
      page?: number;
      limit?: number;
    }
  ): Promise<{
    reviews: PluginReview[];
    total: number;
    page: number;
    limit: number;
    total_pages: number;
    rating_distribution: Record<number, number>;
  }> {
    return apiClient.get<any>(`/plugins/${pluginId}/reviews`, filters);
  }

  /**
   * Submit plugin review
   */
  public async submitPluginReview(
    pluginId: string,
    review: {
      rating: number;
      comment: string;
    }
  ): Promise<PluginReview> {
    return apiClient.post<PluginReview>(`/plugins/${pluginId}/reviews`, review);
  }

  /**
   * Update plugin review
   */
  public async updatePluginReview(
    pluginId: string,
    reviewId: string,
    review: {
      rating?: number;
      comment?: string;
    }
  ): Promise<PluginReview> {
    return apiClient.patch<PluginReview>(`/plugins/${pluginId}/reviews/${reviewId}`, review);
  }

  /**
   * Delete plugin review
   */
  public async deletePluginReview(pluginId: string, reviewId: string): Promise<void> {
    return apiClient.delete<void>(`/plugins/${pluginId}/reviews/${reviewId}`);
  }

  /**
   * Mark review as helpful
   */
  public async markReviewHelpful(
    pluginId: string,
    reviewId: string
  ): Promise<{
    helpful_count: number;
  }> {
    return apiClient.post<any>(`/plugins/${pluginId}/reviews/${reviewId}/helpful`);
  }

  /**
   * Get plugin categories
   */
  public async getPluginCategories(): Promise<
    {
      id: string;
      name: string;
      description: string;
      icon?: string;
      plugin_count: number;
    }[]
  > {
    return apiClient.get<any>('/plugins/categories');
  }

  /**
   * Get popular plugins
   */
  public async getPopularPlugins(limit: number = 10): Promise<Plugin[]> {
    return apiClient.get<Plugin[]>('/plugins/popular', { limit });
  }

  /**
   * Get featured plugins
   */
  public async getFeaturedPlugins(): Promise<Plugin[]> {
    return apiClient.get<Plugin[]>('/plugins/featured');
  }

  /**
   * Get plugin updates available
   */
  public async getPluginUpdates(): Promise<
    {
      plugin_id: string;
      current_version: string;
      latest_version: string;
      changelog: string;
      update_available: boolean;
    }[]
  > {
    return apiClient.get<any>('/plugins/updates');
  }

  /**
   * Check plugin compatibility
   */
  public async checkPluginCompatibility(pluginId: string): Promise<{
    compatible: boolean;
    issues: {
      type: 'dependency' | 'permission' | 'version' | 'system';
      message: string;
      severity: 'error' | 'warning';
    }[];
    recommendations?: string[];
  }> {
    return apiClient.get<any>(`/plugins/${pluginId}/compatibility`);
  }

  /**
   * Get plugin statistics
   */
  public async getPluginStats(): Promise<{
    total_plugins: number;
    installed_plugins: number;
    active_plugins: number;
    updates_available: number;
    by_category: Record<string, number>;
    storage_used: number;
  }> {
    return apiClient.get<any>('/plugins/stats');
  }

  /**
   * Download plugin
   */
  public async downloadPlugin(pluginId: string): Promise<Blob> {
    const response = await apiClient.getClient().get(`/plugins/${pluginId}/download`, {
      responseType: 'blob',
    });
    return response.data;
  }

  /**
   * Upload custom plugin
   */
  public async uploadPlugin(pluginFile: File, metadata?: Record<string, any>): Promise<Plugin> {
    const formData = new FormData();
    formData.append('plugin_file', pluginFile);
    if (metadata) {
      formData.append('metadata', JSON.stringify(metadata));
    }

    const response = await apiClient.getClient().post('/plugins/upload', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    return response.data;
  }

  /**
   * Get plugin logs
   */
  public async getPluginLogs(
    pluginId: string,
    filters?: {
      level?: 'debug' | 'info' | 'warning' | 'error';
      date_from?: string;
      date_to?: string;
      page?: number;
      limit?: number;
    }
  ): Promise<{
    logs: {
      timestamp: string;
      level: string;
      message: string;
      details?: any;
    }[];
    total: number;
    page: number;
    limit: number;
    total_pages: number;
  }> {
    return apiClient.get<any>(`/plugins/installed/${pluginId}/logs`, filters);
  }

  /**
   * Restart plugin
   */
  public async restartPlugin(pluginId: string): Promise<{
    success: boolean;
    message: string;
  }> {
    return apiClient.post<any>(`/plugins/installed/${pluginId}/restart`);
  }
}

// Create and export singleton instance
export const pluginsApi = new PluginsAPI();

// Export class for testing
export { PluginsAPI };
