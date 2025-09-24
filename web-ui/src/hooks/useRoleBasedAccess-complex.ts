import * as React from 'react';

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

// Define role permissions
const ROLE_PERMISSIONS: Record<UserRole, RolePermissions> = {
  admin: {
    role: 'admin',
    permissions: {
      clusters: { view: true, create: true, edit: true, delete: true, deploy: true },
      vulnerabilities: { view: true, patch: true, ignore: true, export: true },
      dashboard: { view: true, customize: true, export: true },
      users: { view: true, create: true, edit: true, delete: true, manage_roles: true },
      system: { configure: true, backup: true, restore: true, audit: true },
    },
  },
  security_analyst: {
    role: 'security_analyst',
    permissions: {
      clusters: { view: true, edit: false, delete: false, deploy: false },
      vulnerabilities: { view: true, patch: true, ignore: true, export: true },
      dashboard: { view: true, customize: false, export: true },
      users: { view: true, create: false, edit: false, delete: false, manage_roles: false },
      system: { configure: false, backup: false, restore: false, audit: true },
    },
  },
  compliance_officer: {
    role: 'compliance_officer',
    permissions: {
      clusters: { view: true, create: false, edit: false, delete: false, deploy: false },
      vulnerabilities: { view: true, patch: false, ignore: false, export: true },
      dashboard: { view: true, customize: false, export: true },
      users: { view: true, create: false, edit: false, delete: false, manage_roles: false },
      system: { configure: false, backup: false, restore: false, audit: true },
    },
  },
  user: {
    role: 'user',
    permissions: {
      clusters: { view: true, create: false, edit: false, delete: false, deploy: false },
      vulnerabilities: { view: true, patch: false, ignore: false, export: false },
      dashboard: { view: true, customize: false, export: false },
      users: { view: false, create: false, edit: false, delete: false, manage_roles: false },
      system: { configure: false, backup: false, restore: false, audit: false },
    },
  },
  viewer: {
    role: 'viewer',
    permissions: {
      clusters: { view: true, create: false, edit: false, delete: false, deploy: false },
      vulnerabilities: { view: true, patch: false, ignore: false, export: false },
      dashboard: { view: true, customize: false, export: false },
      users: { view: false, create: false, edit: false, delete: false, manage_roles: false },
      system: { configure: false, backup: false, restore: false, audit: false },
    },
  },
};

export const useRoleBasedAccess = (userRole: UserRole = 'user') => {
  const permissions = React.useMemo(() => {
    return ROLE_PERMISSIONS[userRole] || ROLE_PERMISSIONS.user;
  }, [userRole]);

  const canAccess = React.useMemo(() => {
    return (requiredRole: UserRole | UserRole[]) => {
      if (Array.isArray(requiredRole)) {
        return requiredRole.includes(userRole);
      }
      return userRole === requiredRole || userRole === 'admin';
    };
  }, [userRole]);

  const hasPermission = React.useMemo(() => {
    return (resource: string, action: string) => {
      const resourcePermissions = (permissions.permissions as any)[resource];
      if (!resourcePermissions) return false;
      return resourcePermissions[action] === true;
    };
  }, [permissions]);

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
