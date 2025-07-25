import axios, { AxiosInstance, AxiosResponse } from 'axios';

export interface User {
  id: string;
  username: string;
  email: string;
  first_name: string;
  last_name: string;
  organization: {
    id: string;
    name: string;
  };
  roles: string[];
  permissions: string[];
  is_active: boolean;
  is_verified: boolean;
  last_login?: string;
  created_at: string;
}

export interface LoginRequest {
  username: string;
  password: string;
}

export interface AuthResponse {
  access_token: string;
  refresh_token: string;
  token_type: 'bearer';
  expires_in: number;
  user: User;
}

export interface RefreshTokenRequest {
  refresh_token: string;
}

class AuthAPI {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: process.env.REACT_APP_API_URL || 'http://localhost:8000/v1',
      timeout: 10000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    // Request interceptor to add auth token
    this.client.interceptors.request.use(
      (config) => {
        const token = this.getStoredToken();
        if (token) {
          config.headers.Authorization = `Bearer ${token}`;
        }
        return config;
      },
      (error) => {
        return Promise.reject(error);
      }
    );

    // Response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          // Token expired or invalid
          this.clearAuthToken();
          window.location.href = '/login';
        }
        return Promise.reject(error);
      }
    );
  }

  private getStoredToken(): string | null {
    return localStorage.getItem('auth_token');
  }

  public setAuthToken(token: string | null): void {
    if (token) {
      localStorage.setItem('auth_token', token);
      this.client.defaults.headers.common.Authorization = `Bearer ${token}`;
    } else {
      this.clearAuthToken();
    }
  }

  public clearAuthToken(): void {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('auth_user');
    delete this.client.defaults.headers.common.Authorization;
  }

  /**
   * Login user with username and password
   */
  public async login(username: string, password: string): Promise<AuthResponse> {
    const response: AxiosResponse<AuthResponse> = await this.client.post('/auth/login', {
      username,
      password,
    });
    return response.data;
  }

  /**
   * Refresh authentication token
   */
  public async refreshToken(refreshToken: string): Promise<AuthResponse> {
    const response: AxiosResponse<AuthResponse> = await this.client.post('/auth/refresh', {
      refresh_token: refreshToken,
    });
    return response.data;
  }

  /**
   * Logout user (optional endpoint call)
   */
  public async logout(): Promise<void> {
    try {
      await this.client.post('/auth/logout');
    } catch (error) {
      // Ignore logout errors
      console.warn('Logout API call failed:', error);
    }
  }

  /**
   * Get current user profile
   */
  public async getCurrentUser(): Promise<User> {
    const response: AxiosResponse<User> = await this.client.get('/auth/me');
    return response.data;
  }

  /**
   * Update user profile
   */
  public async updateProfile(data: Partial<User>): Promise<User> {
    const response: AxiosResponse<User> = await this.client.put('/auth/me', data);
    return response.data;
  }

  /**
   * Change user password
   */
  public async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await this.client.post('/auth/change-password', {
      current_password: currentPassword,
      new_password: newPassword,
    });
  }

  /**
   * Request password reset
   */
  public async requestPasswordReset(email: string): Promise<void> {
    await this.client.post('/auth/forgot-password', { email });
  }

  /**
   * Reset password with token
   */
  public async resetPassword(token: string, newPassword: string): Promise<void> {
    await this.client.post('/auth/reset-password', {
      token,
      new_password: newPassword,
    });
  }

  /**
   * Verify email address
   */
  public async verifyEmail(token: string): Promise<void> {
    await this.client.post('/auth/verify-email', { token });
  }

  /**
   * Resend email verification
   */
  public async resendEmailVerification(): Promise<void> {
    await this.client.post('/auth/resend-verification');
  }

  /**
   * Get user permissions
   */
  public async getUserPermissions(): Promise<string[]> {
    const response: AxiosResponse<{ permissions: string[] }> = await this.client.get('/auth/permissions');
    return response.data.permissions;
  }

  /**
   * Check if user has specific permission
   */
  public async hasPermission(permission: string): Promise<boolean> {
    try {
      const response: AxiosResponse<{ has_permission: boolean }> = await this.client.get(
        `/auth/permissions/${permission}`
      );
      return response.data.has_permission;
    } catch (error) {
      return false;
    }
  }

  /**
   * Get user sessions
   */
  public async getUserSessions(): Promise<any[]> {
    const response: AxiosResponse<{ sessions: any[] }> = await this.client.get('/auth/sessions');
    return response.data.sessions;
  }

  /**
   * Revoke user session
   */
  public async revokeSession(sessionId: string): Promise<void> {
    await this.client.delete(`/auth/sessions/${sessionId}`);
  }

  /**
   * Get API client instance for making authenticated requests
   */
  public getClient(): AxiosInstance {
    return this.client;
  }
}

// Create and export singleton instance
export const authApi = new AuthAPI();

// Export class for testing or multiple instances
export { AuthAPI };