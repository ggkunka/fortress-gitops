import { useMemo } from 'react';
import { UserRole, RolePermissions } from '../types/security';
import { useAuth } from '../contexts/AuthContext';

// Define role permissions
const ROLE_PERMISSIONS: Record<UserRole, RolePermissions> = {
  admin: {
    role: 'admin',
    permissions: {
      clusters: {
        view: true,
        create: true,
        edit: true,
        delete: true,
        deploy: true,
      },
      repositories: {
        view: true,
        create: true,
        edit: true,
        delete: true,
        scan: true,
        push: true,
      },
      agents: {
        view: true,
        create: true,
        edit: true,
        delete: true,
        deploy: true,
        configure: true,
      },
      vulnerabilities: {
        view: true,
        patch: true,
        ignore: true,
        export: true,
      },
      dashboard: {
        view: true,
        customize: true,
        export: true,
      },
      users: {
        view: true,
        create: true,
        edit: true,
        delete: true,
        manage_roles: true,
      },
      system: {
        configure: true,
        backup: true,
        restore: true,
        audit: true,
      },
    },
  },
  user: {
    role: 'user',
    permissions: {
      clusters: {
        view: true,
        create: false,
        edit: false,
        delete: false,
        deploy: false,
      },
      repositories: {
        view: true,
        create: false,
        edit: false,
        delete: false,
        scan: false,
        push: false,
      },
      agents: {
        view: true,
        create: false,
        edit: false,
        delete: false,
        deploy: false,
        configure: false,
      },
      vulnerabilities: {
        view: true,
        patch: false,
        ignore: false,
        export: true,
      },
      dashboard: {
        view: true,
        customize: false,
        export: true,
      },
      users: {
        view: false,
        create: false,
        edit: false,
        delete: false,
        manage_roles: false,
      },
      system: {
        configure: false,
        backup: false,
        restore: false,
        audit: false,
      },
    },
  },
  viewer: {
    role: 'viewer',
    permissions: {
      clusters: {
        view: true,
        create: false,
        edit: false,
        delete: false,
        deploy: false,
      },
      repositories: {
        view: true,
        create: false,
        edit: false,
        delete: false,
        scan: false,
        push: false,
      },
      agents: {
        view: true,
        create: false,
        edit: false,
        delete: false,
        deploy: false,
        configure: false,
      },
      vulnerabilities: {
        view: true,
        patch: false,
        ignore: false,
        export: false,
      },
      dashboard: {
        view: true,
        customize: false,
        export: false,
      },
      users: {
        view: false,
        create: false,
        edit: false,
        delete: false,
        manage_roles: false,
      },
      system: {
        configure: false,
        backup: false,
        restore: false,
        audit: false,
      },
    },
  },
  'security-analyst': {
    role: 'security-analyst',
    permissions: {
      clusters: {
        view: true,
        create: false,
        edit: false,
        delete: false,
        deploy: false,
      },
      repositories: {
        view: true,
        create: false,
        edit: false,
        delete: false,
        scan: true,
        push: false,
      },
      agents: {
        view: true,
        create: false,
        edit: false,
        delete: false,
        deploy: false,
        configure: false,
      },
      vulnerabilities: {
        view: true,
        patch: true,
        ignore: true,
        export: true,
      },
      dashboard: {
        view: true,
        customize: true,
        export: true,
      },
      users: {
        view: false,
        create: false,
        edit: false,
        delete: false,
        manage_roles: false,
      },
      system: {
        configure: false,
        backup: false,
        restore: false,
        audit: true,
      },
    },
  },
  'compliance-officer': {
    role: 'compliance-officer',
    permissions: {
      clusters: {
        view: true,
        create: false,
        edit: false,
        delete: false,
        deploy: false,
      },
      repositories: {
        view: true,
        create: false,
        edit: false,
        delete: false,
        scan: false,
        push: false,
      },
      agents: {
        view: true,
        create: false,
        edit: false,
        delete: false,
        deploy: false,
        configure: false,
      },
      vulnerabilities: {
        view: true,
        patch: false,
        ignore: false,
        export: true,
      },
      dashboard: {
        view: true,
        customize: false,
        export: true,
      },
      users: {
        view: false,
        create: false,
        edit: false,
        delete: false,
        manage_roles: false,
      },
      system: {
        configure: false,
        backup: false,
        restore: false,
        audit: true,
      },
    },
  },
};

export interface UseRoleBasedAccessReturn {
  userRole: UserRole;
  permissions: RolePermissions;
  hasPermission: (resource: string, action: string) => boolean;
  canAccess: (requiredRole: UserRole | UserRole[]) => boolean;
  isAdmin: boolean;
  isUser: boolean;
  isViewer: boolean;
  isSecurityAnalyst: boolean;
  isComplianceOfficer: boolean;
}

export const useRoleBasedAccess = (): UseRoleBasedAccessReturn => {
  const { user } = useAuth();

  // Get user role from user object or default to 'viewer'
  const userRole: UserRole = useMemo(() => {
    if (!user || !user.roles || user.roles.length === 0) {
      return 'viewer';
    }
    
    // If user has multiple roles, prioritize admin > security-analyst > compliance-officer > user > viewer
    const rolePriority: UserRole[] = ['admin', 'security-analyst', 'compliance-officer', 'user', 'viewer'];
    
    for (const role of rolePriority) {
      if (user.roles.some(userRole => userRole.name === role)) {
        return role;
      }
    }
    
    return 'viewer';
  }, [user]);

  // Get permissions for the user's role
  const permissions = useMemo(() => {
    return ROLE_PERMISSIONS[userRole] || ROLE_PERMISSIONS.viewer;
  }, [userRole]);

  // Check if user has specific permission
  const hasPermission = useMemo(() => {
    return (resource: string, action: string): boolean => {
      const resourcePermissions = (permissions.permissions as any)[resource];
      if (!resourcePermissions) {
        return false;
      }
      return resourcePermissions[action] === true;
    };
  }, [permissions]);

  // Check if user can access based on required role(s)
  const canAccess = useMemo(() => {
    return (requiredRole: UserRole | UserRole[]): boolean => {
      const requiredRoles = Array.isArray(requiredRole) ? requiredRole : [requiredRole];
      return requiredRoles.includes(userRole);
    };
  }, [userRole]);

  // Role checks
  const isAdmin = userRole === 'admin';
  const isUser = userRole === 'user';
  const isViewer = userRole === 'viewer';
  const isSecurityAnalyst = userRole === 'security-analyst';
  const isComplianceOfficer = userRole === 'compliance-officer';

  return {
    userRole,
    permissions,
    hasPermission,
    canAccess,
    isAdmin,
    isUser,
    isViewer,
    isSecurityAnalyst,
    isComplianceOfficer,
  };
};

// Higher-order component for role-based access control
export const withRoleBasedAccess = <P extends object>(
  Component: React.ComponentType<P>,
  requiredRole: UserRole | UserRole[],
  fallbackComponent?: React.ComponentType<P>
) => {
  return (props: P) => {
    const { canAccess } = useRoleBasedAccess();
    
    if (!canAccess(requiredRole)) {
      if (fallbackComponent) {
        const FallbackComponent = fallbackComponent;
        return <FallbackComponent {...props} />;
      }
      return (
        <div style={{ padding: '20px', textAlign: 'center' }}>
          <h3>Access Denied</h3>
          <p>You don't have permission to access this resource.</p>
        </div>
      );
    }
    
    return <Component {...props} />;
  };
};

// Hook for conditional rendering based on permissions
export const usePermissionCheck = () => {
  const { hasPermission, canAccess } = useRoleBasedAccess();

  const canViewClusters = hasPermission('clusters', 'view');
  const canManageClusters = hasPermission('clusters', 'create') && hasPermission('clusters', 'edit');
  const canDeleteClusters = hasPermission('clusters', 'delete');
  const canDeployClusters = hasPermission('clusters', 'deploy');

  const canViewRepositories = hasPermission('repositories', 'view');
  const canManageRepositories = hasPermission('repositories', 'create') && hasPermission('repositories', 'edit');
  const canScanRepositories = hasPermission('repositories', 'scan');
  const canPushToRepositories = hasPermission('repositories', 'push');

  const canViewAgents = hasPermission('agents', 'view');
  const canManageAgents = hasPermission('agents', 'create') && hasPermission('agents', 'edit');
  const canDeployAgents = hasPermission('agents', 'deploy');
  const canConfigureAgents = hasPermission('agents', 'configure');

  const canViewVulnerabilities = hasPermission('vulnerabilities', 'view');
  const canPatchVulnerabilities = hasPermission('vulnerabilities', 'patch');
  const canIgnoreVulnerabilities = hasPermission('vulnerabilities', 'ignore');
  const canExportVulnerabilities = hasPermission('vulnerabilities', 'export');

  const canViewDashboard = hasPermission('dashboard', 'view');
  const canCustomizeDashboard = hasPermission('dashboard', 'customize');
  const canExportDashboard = hasPermission('dashboard', 'export');

  const canViewUsers = hasPermission('users', 'view');
  const canManageUsers = hasPermission('users', 'create') && hasPermission('users', 'edit');
  const canManageRoles = hasPermission('users', 'manage_roles');

  const canConfigureSystem = hasPermission('system', 'configure');
  const canBackupSystem = hasPermission('system', 'backup');
  const canAuditSystem = hasPermission('system', 'audit');

  return {
    // Cluster permissions
    canViewClusters,
    canManageClusters,
    canDeleteClusters,
    canDeployClusters,

    // Repository permissions
    canViewRepositories,
    canManageRepositories,
    canScanRepositories,
    canPushToRepositories,

    // Agent permissions
    canViewAgents,
    canManageAgents,
    canDeployAgents,
    canConfigureAgents,

    // Vulnerability permissions
    canViewVulnerabilities,
    canPatchVulnerabilities,
    canIgnoreVulnerabilities,
    canExportVulnerabilities,

    // Dashboard permissions
    canViewDashboard,
    canCustomizeDashboard,
    canExportDashboard,

    // User permissions
    canViewUsers,
    canManageUsers,
    canManageRoles,

    // System permissions
    canConfigureSystem,
    canBackupSystem,
    canAuditSystem,

    // Role checks
    canAccess,
    hasPermission,
  };
};
