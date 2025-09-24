import { apiClient } from './apiClient';
import {
  User,
  UserRole,
  Permission,
  AuthConfig,
  AuditLog,
  ApiResponse,
  PaginatedResponse,
} from '../types';

export class UserApi {
  private baseUrl = '/api/v1/users';

  // User Management
  async getUsers(page = 1, pageSize = 50, search?: string): Promise<PaginatedResponse<User>> {
    const params: any = { page, pageSize };
    if (search) params.search = search;

    const response = await apiClient.get<ApiResponse<PaginatedResponse<User>>>(this.baseUrl, {
      params,
    });
    return response.data || { items: [], total: 0, page: 1, pageSize: 50, totalPages: 0 };
  }

  async getUser(id: string): Promise<User> {
    const response = await apiClient.get<ApiResponse<User>>(`${this.baseUrl}/${id}`);
    if (!response.data) {
      throw new Error('User not found');
    }
    return response.data;
  }

  async getCurrentUser(): Promise<User> {
    const response = await apiClient.get<ApiResponse<User>>(`${this.baseUrl}/me`);
    if (!response.data) {
      throw new Error('User not found');
    }
    return response.data;
  }

  async createUser(
    user: Omit<User, 'id' | 'createdAt' | 'updatedAt' | 'lastLogin'>
  ): Promise<User> {
    const response = await apiClient.post<ApiResponse<User>>(this.baseUrl, user);
    if (!response.data) {
      throw new Error('Failed to create user');
    }
    return response.data;
  }

  async updateUser(id: string, user: Partial<User>): Promise<User> {
    const response = await apiClient.put<ApiResponse<User>>(`${this.baseUrl}/${id}`, user);
    if (!response.data) {
      throw new Error('Failed to update user');
    }
    return response.data;
  }

  async deleteUser(id: string): Promise<void> {
    await apiClient.delete(`${this.baseUrl}/${id}`);
  }

  async activateUser(id: string): Promise<User> {
    const response = await apiClient.post<ApiResponse<User>>(`${this.baseUrl}/${id}/activate`);
    if (!response.data) {
      throw new Error('Failed to activate user');
    }
    return response.data;
  }

  async deactivateUser(id: string): Promise<User> {
    const response = await apiClient.post<ApiResponse<User>>(`${this.baseUrl}/${id}/deactivate`);
    if (!response.data) {
      throw new Error('Failed to deactivate user');
    }
    return response.data;
  }

  // Role Management
  async getRoles(): Promise<UserRole[]> {
    const response = await apiClient.get<ApiResponse<UserRole[]>>(`${this.baseUrl}/roles`);
    return response.data || [];
  }

  async getRole(id: string): Promise<UserRole> {
    const response = await apiClient.get<ApiResponse<UserRole>>(`${this.baseUrl}/roles/${id}`);
    if (!response.data) {
      throw new Error('Role not found');
    }
    return response.data;
  }

  async createRole(role: Omit<UserRole, 'id'>): Promise<UserRole> {
    const response = await apiClient.post<ApiResponse<UserRole>>(`${this.baseUrl}/roles`, role);
    if (!response.data) {
      throw new Error('Failed to create role');
    }
    return response.data;
  }

  async updateRole(id: string, role: Partial<UserRole>): Promise<UserRole> {
    const response = await apiClient.put<ApiResponse<UserRole>>(
      `${this.baseUrl}/roles/${id}`,
      role
    );
    if (!response.data) {
      throw new Error('Failed to update role');
    }
    return response.data;
  }

  async deleteRole(id: string): Promise<void> {
    await apiClient.delete(`${this.baseUrl}/roles/${id}`);
  }

  async assignRole(userId: string, roleId: string): Promise<User> {
    const response = await apiClient.post<ApiResponse<User>>(
      `${this.baseUrl}/${userId}/roles/${roleId}`
    );
    if (!response.data) {
      throw new Error('Failed to assign role');
    }
    return response.data;
  }

  async unassignRole(userId: string, roleId: string): Promise<User> {
    const response = await apiClient.delete<ApiResponse<User>>(
      `${this.baseUrl}/${userId}/roles/${roleId}`
    );
    if (!response.data) {
      throw new Error('Failed to unassign role');
    }
    return response.data;
  }

  // Permission Management
  async getPermissions(): Promise<Permission[]> {
    const response = await apiClient.get<ApiResponse<Permission[]>>(`${this.baseUrl}/permissions`);
    return response.data || [];
  }

  async getUserPermissions(userId: string): Promise<Permission[]> {
    const response = await apiClient.get<ApiResponse<Permission[]>>(
      `${this.baseUrl}/${userId}/permissions`
    );
    return response.data || [];
  }

  async checkPermission(userId: string, resource: string, action: string): Promise<boolean> {
    const response = await apiClient.post<ApiResponse<{ allowed: boolean }>>(
      `${this.baseUrl}/${userId}/check-permission`,
      { resource, action }
    );
    return response.data?.allowed || false;
  }

  // Authentication Configuration
  async getAuthConfig(): Promise<AuthConfig> {
    const response = await apiClient.get<ApiResponse<AuthConfig>>('/api/v1/auth/config');
    if (!response.data) {
      throw new Error('Auth config not found');
    }
    return response.data;
  }

  async updateAuthConfig(config: AuthConfig): Promise<AuthConfig> {
    const response = await apiClient.put<ApiResponse<AuthConfig>>('/api/v1/auth/config', config);
    if (!response.data) {
      throw new Error('Failed to update auth config');
    }
    return response.data;
  }

  async testAuthConfig(
    config: AuthConfig
  ): Promise<{ success: boolean; message: string; details?: any }> {
    const response = await apiClient.post<
      ApiResponse<{ success: boolean; message: string; details?: any }>
    >('/api/v1/auth/test-config', config);
    return response.data || { success: false, message: 'Unknown error' };
  }

  // LDAP/AD Integration
  async testLdapConnection(
    config: any
  ): Promise<{ success: boolean; message: string; users?: any[] }> {
    const response = await apiClient.post<
      ApiResponse<{ success: boolean; message: string; users?: any[] }>
    >('/api/v1/auth/test-ldap', config);
    return response.data || { success: false, message: 'Unknown error' };
  }

  async syncLdapUsers(): Promise<{ success: boolean; message: string; syncedUsers: number }> {
    const response = await apiClient.post<
      ApiResponse<{ success: boolean; message: string; syncedUsers: number }>
    >('/api/v1/auth/sync-ldap-users');
    return response.data || { success: false, message: 'Unknown error', syncedUsers: 0 };
  }

  async getLdapGroups(): Promise<string[]> {
    const response = await apiClient.get<ApiResponse<string[]>>('/api/v1/auth/ldap-groups');
    return response.data || [];
  }

  async mapLdapGroup(
    ldapGroup: string,
    roleId: string
  ): Promise<{ success: boolean; message: string }> {
    const response = await apiClient.post<ApiResponse<{ success: boolean; message: string }>>(
      '/api/v1/auth/map-ldap-group',
      { ldapGroup, roleId }
    );
    return response.data || { success: false, message: 'Unknown error' };
  }

  // SSO Integration
  async getSsoProviders(): Promise<{ id: string; name: string; type: string; enabled: boolean }[]> {
    const response = await apiClient.get<
      ApiResponse<{ id: string; name: string; type: string; enabled: boolean }[]>
    >('/api/v1/auth/sso-providers');
    return response.data || [];
  }

  async configureSsoProvider(provider: {
    type: 'saml' | 'oidc' | 'azure-ad';
    name: string;
    config: any;
  }): Promise<{ success: boolean; message: string; providerId?: string }> {
    const response = await apiClient.post<
      ApiResponse<{ success: boolean; message: string; providerId?: string }>
    >('/api/v1/auth/configure-sso', provider);
    return response.data || { success: false, message: 'Unknown error' };
  }

  async testSsoProvider(
    providerId: string
  ): Promise<{ success: boolean; message: string; loginUrl?: string }> {
    const response = await apiClient.post<
      ApiResponse<{ success: boolean; message: string; loginUrl?: string }>
    >(`/api/v1/auth/test-sso/${providerId}`);
    return response.data || { success: false, message: 'Unknown error' };
  }

  // User Sessions
  async getUserSessions(userId: string): Promise<
    {
      id: string;
      userId: string;
      ipAddress: string;
      userAgent: string;
      createdAt: Date;
      lastActivity: Date;
      isActive: boolean;
    }[]
  > {
    const response = await apiClient.get<
      ApiResponse<
        {
          id: string;
          userId: string;
          ipAddress: string;
          userAgent: string;
          createdAt: Date;
          lastActivity: Date;
          isActive: boolean;
        }[]
      >
    >(`${this.baseUrl}/${userId}/sessions`);
    return response.data || [];
  }

  async revokeUserSession(userId: string, sessionId: string): Promise<void> {
    await apiClient.delete(`${this.baseUrl}/${userId}/sessions/${sessionId}`);
  }

  async revokeAllUserSessions(userId: string): Promise<void> {
    await apiClient.delete(`${this.baseUrl}/${userId}/sessions`);
  }

  // Audit Logs
  async getAuditLogs(
    page = 1,
    pageSize = 50,
    filters?: {
      userId?: string;
      action?: string;
      resource?: string;
      startDate?: Date;
      endDate?: Date;
    }
  ): Promise<PaginatedResponse<AuditLog>> {
    const params: any = { page, pageSize };
    if (filters) {
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined) {
          params[key] = value instanceof Date ? value.toISOString() : value;
        }
      });
    }

    const response = await apiClient.get<ApiResponse<PaginatedResponse<AuditLog>>>(
      '/api/v1/audit-logs',
      { params }
    );
    return response.data || { items: [], total: 0, page: 1, pageSize: 50, totalPages: 0 };
  }

  async exportAuditLogs(
    format: 'csv' | 'json' | 'pdf',
    filters?: {
      userId?: string;
      action?: string;
      resource?: string;
      startDate?: Date;
      endDate?: Date;
    }
  ): Promise<Blob> {
    const params: any = { format };
    if (filters) {
      Object.entries(filters).forEach(([key, value]) => {
        if (value !== undefined) {
          params[key] = value instanceof Date ? value.toISOString() : value;
        }
      });
    }

    const response = await apiClient.get<any>('/api/v1/audit-logs/export', {
      params,
      responseType: 'blob',
    });
    return response.data as Blob;
  }

  // User Statistics
  async getUserStats(): Promise<{
    totalUsers: number;
    activeUsers: number;
    inactiveUsers: number;
    totalRoles: number;
    totalPermissions: number;
    recentLogins: number;
  }> {
    const response = await apiClient.get<
      ApiResponse<{
        totalUsers: number;
        activeUsers: number;
        inactiveUsers: number;
        totalRoles: number;
        totalPermissions: number;
        recentLogins: number;
      }>
    >(`${this.baseUrl}/stats`);
    return (
      response.data || {
        totalUsers: 0,
        activeUsers: 0,
        inactiveUsers: 0,
        totalRoles: 0,
        totalPermissions: 0,
        recentLogins: 0,
      }
    );
  }

  // Password Management
  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string
  ): Promise<{ success: boolean; message: string }> {
    const response = await apiClient.post<ApiResponse<{ success: boolean; message: string }>>(
      `${this.baseUrl}/${userId}/change-password`,
      { currentPassword, newPassword }
    );
    return response.data || { success: false, message: 'Unknown error' };
  }

  async resetPassword(
    userId: string
  ): Promise<{ success: boolean; message: string; temporaryPassword?: string }> {
    const response = await apiClient.post<
      ApiResponse<{ success: boolean; message: string; temporaryPassword?: string }>
    >(`${this.baseUrl}/${userId}/reset-password`);
    return response.data || { success: false, message: 'Unknown error' };
  }

  async forcePasswordChange(userId: string): Promise<{ success: boolean; message: string }> {
    const response = await apiClient.post<ApiResponse<{ success: boolean; message: string }>>(
      `${this.baseUrl}/${userId}/force-password-change`
    );
    return response.data || { success: false, message: 'Unknown error' };
  }

  // Bulk Operations
  async bulkCreateUsers(
    users: Omit<User, 'id' | 'createdAt' | 'updatedAt' | 'lastLogin'>[]
  ): Promise<{
    success: boolean;
    results: { user: User | null; error?: string }[];
  }> {
    const response = await apiClient.post<
      ApiResponse<{
        success: boolean;
        results: { user: User | null; error?: string }[];
      }>
    >(`${this.baseUrl}/bulk-create`, { users });
    return response.data || { success: false, results: [] };
  }

  async bulkUpdateUsers(updates: { id: string; data: Partial<User> }[]): Promise<{
    success: boolean;
    results: { user: User | null; error?: string }[];
  }> {
    const response = await apiClient.post<
      ApiResponse<{
        success: boolean;
        results: { user: User | null; error?: string }[];
      }>
    >(`${this.baseUrl}/bulk-update`, { updates });
    return response.data || { success: false, results: [] };
  }

  async bulkAssignRoles(
    userIds: string[],
    roleIds: string[]
  ): Promise<{
    success: boolean;
    results: { userId: string; success: boolean; message: string }[];
  }> {
    const response = await apiClient.post<
      ApiResponse<{
        success: boolean;
        results: { userId: string; success: boolean; message: string }[];
      }>
    >(`${this.baseUrl}/bulk-assign-roles`, { userIds, roleIds });
    return response.data || { success: false, results: [] };
  }
}

export const userApi = new UserApi();
