import React from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { CssBaseline, Box } from '@mui/material';
import { QueryClient, QueryClientProvider } from 'react-query';
import { ReactQueryDevtools } from 'react-query/devtools';

// Components
import { AppLayout } from './components/layout/AppLayout';
import { AuthProvider, useAuth } from './contexts/AuthContext';

// Pages
import { LoginPage } from './pages/auth/LoginPage';
import { DashboardPage } from './pages/dashboard/DashboardPage';
import { ScansPage } from './pages/scans/ScansPage';
import { VulnerabilitiesPage } from './pages/vulnerabilities/VulnerabilitiesPage';
import { ReportsPage } from './pages/reports/ReportsPage';
import { IntegrationsPage } from './pages/integrations/IntegrationsPage';
import { MarketplacePage } from './pages/marketplace/MarketplacePage';
import ClustersPage from './pages/clusters/ClustersPage';
import RepositoriesPage from './pages/repositories/RepositoriesPage';
import SecurityDashboard from './components/SecurityDashboard';

// Create theme
const theme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#1976d2',
      light: '#42a5f5',
      dark: '#1565c0',
    },
    secondary: {
      main: '#dc004e',
      light: '#ff5983',
      dark: '#9a0036',
    },
    error: {
      main: '#f44336',
    },
    warning: {
      main: '#ff9800',
    },
    info: {
      main: '#2196f3',
    },
    success: {
      main: '#4caf50',
    },
    background: {
      default: '#f5f5f5',
      paper: '#ffffff',
    },
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
    h1: {
      fontSize: '2.5rem',
      fontWeight: 500,
    },
    h2: {
      fontSize: '2rem',
      fontWeight: 500,
    },
    h3: {
      fontSize: '1.75rem',
      fontWeight: 500,
    },
    h4: {
      fontSize: '1.5rem',
      fontWeight: 500,
    },
    h5: {
      fontSize: '1.25rem',
      fontWeight: 500,
    },
    h6: {
      fontSize: '1rem',
      fontWeight: 500,
    },
  },
  shape: {
    borderRadius: 8,
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
          fontWeight: 500,
        },
      },
    },
    MuiCard: {
      styleOverrides: {
        root: {
          boxShadow: '0 2px 8px rgba(0,0,0,0.1)',
        },
      },
    },
    MuiAppBar: {
      styleOverrides: {
        root: {
          boxShadow: '0 1px 3px rgba(0,0,0,0.12)',
        },
      },
    },
  },
});

// Create React Query client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
      staleTime: 5 * 60 * 1000, // 5 minutes
    },
  },
});

// Protected Route Component
const ProtectedRoute: React.FC<{ children: React.ReactNode }> = ({ children }) => {
  const { isAuthenticated, isLoading } = useAuth();

  if (isLoading) {
    return <Box display="flex" justifyContent="center" alignItems="center" minHeight="100vh">Loading...</Box>;
  }

  if (!isAuthenticated) {
    return <Navigate to="/login" replace />;
  }

  return <>{children}</>;
};

// App Component
const App: React.FC = () => {
  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider theme={theme}>
        <CssBaseline />
        <AuthProvider>
          <Router>
            <Routes>
              {/* Public Routes */}
              <Route path="/login" element={<LoginPage />} />

              {/* Protected Routes */}
              <Route
                path="/*"
                element={
                  <ProtectedRoute>
                    <AppLayout>
                      <Routes>
                        <Route path="/" element={<Navigate to="/security-dashboard" replace />} />
                        <Route path="/security-dashboard" element={<SecurityDashboard userRole="admin" permissions={{
                          role: 'admin',
                          permissions: {
                            clusters: { view: true, create: true, edit: true, delete: true, deploy: true },
                            repositories: { view: true, create: true, edit: true, delete: true, scan: true, push: true },
                            agents: { view: true, create: true, edit: true, delete: true, deploy: true, configure: true },
                            vulnerabilities: { view: true, patch: true, ignore: true, export: true },
                            dashboard: { view: true, customize: true, export: true },
                            users: { view: true, create: true, edit: true, delete: true, manage_roles: true },
                            system: { configure: true, backup: true, restore: true, audit: true }
                          }
                        }} />} />
                        <Route path="/dashboard" element={<DashboardPage />} />
                        <Route path="/clusters" element={<ClustersPage />} />
                        <Route path="/repositories" element={<RepositoriesPage />} />
                        <Route path="/scans" element={<ScansPage />} />
                        <Route path="/vulnerabilities" element={<VulnerabilitiesPage />} />
                        <Route path="/reports" element={<ReportsPage />} />
                        <Route path="/integrations" element={<IntegrationsPage />} />
                        <Route path="/marketplace" element={<MarketplacePage />} />
                        <Route path="*" element={<Navigate to="/security-dashboard" replace />} />
                      </Routes>
                    </AppLayout>
                  </ProtectedRoute>
                }
              />
            </Routes>
          </Router>
        </AuthProvider>
      </ThemeProvider>
      <ReactQueryDevtools initialIsOpen={false} />
    </QueryClientProvider>
  );
};

export default App;