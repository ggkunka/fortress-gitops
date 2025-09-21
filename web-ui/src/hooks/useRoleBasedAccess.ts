export type UserRole = 'admin' | 'user' | 'security_analyst' | 'compliance_officer' | 'viewer';

export interface RolePermissions {
  role: UserRole;
  permissions: {
    clusters?: {
      view?: boolean;
      create?: boolean;
      edit?: boolean;
      delete?: boolean;
      deploy?: boolean;
    };
    vulnerabilities?: {
      view?: boolean;
      patch?: boolean;
      ignore?: boolean;
      export?: boolean;
    };
    dashboard?: {
      view?: boolean;
      customize?: boolean;
      export?: boolean;
    };
    users?: {
      view?: boolean;
      create?: boolean;
      edit?: boolean;
      delete?: boolean;
      manage_roles?: boolean;
    };
    system?: {
      configure?: boolean;
      backup?: boolean;
      restore?: boolean;
      audit?: boolean;
    };
  };
}

export const useRoleBasedAccess = (userRole: UserRole = 'user') => {
  const permissions = {
    role: userRole,
    permissions: {
      clusters: { view: true, create: true, edit: true, delete: true, deploy: true },
      vulnerabilities: { view: true, patch: true, ignore: true, export: true },
      dashboard: { view: true, customize: true, export: true },
      users: { view: true, create: true, edit: true, delete: true, manage_roles: true },
      system: { configure: true, backup: true, restore: true, audit: true },
    },
  };

  const canAccess = (requiredRole: UserRole | UserRole[]) => {
    if (Array.isArray(requiredRole)) {
      return requiredRole.includes(userRole);
    }
    return userRole === requiredRole || userRole === 'admin';
  };

  const hasPermission = (resource: string, action: string) => {
    return true; // Simplified for now
  };

  return {
    userRole,
    permissions,
    canAccess,
    hasPermission,
    isAdmin: userRole === 'admin',
    isUser: userRole === 'user',
    isViewer: userRole === 'viewer',
    isSecurityAnalyst: userRole === 'security_analyst',
    isComplianceOfficer: userRole === 'compliance_officer',
  };
};
