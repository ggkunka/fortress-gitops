import React, { useState, useEffect } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import { CssBaseline, Box } from '@mui/material';
import { QueryClient, QueryClientProvider } from 'react-query';
import { SnackbarProvider } from 'notistack';

// Services
import apiService from './services/api';

// Components
import FunctionalLogin from './components/FunctionalLogin';
import FunctionalDashboard from './components/FunctionalDashboard';

// Theme
const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#00d4ff',
    },
    secondary: {
      main: '#7c3aed',
    },
    background: {
      default: '#0a0e27',
      paper: '#1a1d3a',
    },
  },
  typography: {
    fontFamily: 'Inter, sans-serif',
  },
});

// React Query Client
const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 3,
      staleTime: 5 * 60 * 1000, // 5 minutes
      refetchOnWindowFocus: false,
    },
  },
});

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [currentUser, setCurrentUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const initializeApp = async () => {
      const token = localStorage.getItem('fortress_token');
      if (token) {
        try {
          // For demo purposes, create a mock user
          const mockUser = {
            id: '1',
            username: 'admin',
            role: 'admin',
            permissions: {
              clusters: { view: true, create: true, edit: true, delete: true },
              vulnerabilities: { view: true, patch: true },
              dashboard: { view: true, customize: true },
            },
          };
          setCurrentUser(mockUser);
          setIsAuthenticated(true);
        } catch (error) {
          console.error('Failed to get current user:', error);
          localStorage.removeItem('fortress_token');
        }
      }
      setLoading(false);
    };

    initializeApp();
  }, []);

  const handleLogin = async (credentials: { username: string; password: string }) => {
    try {
      // For demo purposes, accept any credentials
      const mockResponse = {
        token: 'demo-jwt-token-' + Date.now(),
        user: {
          id: '1',
          username: credentials.username,
          role: credentials.username === 'admin' ? 'admin' : 'user',
          permissions: {
            clusters: { view: true, create: true, edit: true, delete: true },
            vulnerabilities: { view: true, patch: true },
            dashboard: { view: true, customize: true },
          },
        },
      };

      localStorage.setItem('fortress_token', mockResponse.token);
      setCurrentUser(mockResponse.user);
      setIsAuthenticated(true);
      return { success: true };
    } catch (error: any) {
      return {
        success: false,
        error: error.response?.data?.message || 'Login failed',
      };
    }
  };

  const handleLogout = async () => {
    try {
      await apiService.logout();
    } catch (error) {
      console.error('Logout error:', error);
    } finally {
      localStorage.removeItem('fortress_token');
      setIsAuthenticated(false);
      setCurrentUser(null);
      apiService.disconnectWebSocket();
    }
  };

  if (loading) {
    return (
      <ThemeProvider theme={darkTheme}>
        <CssBaseline />
        <Box
          sx={{
            display: 'flex',
            justifyContent: 'center',
            alignItems: 'center',
            minHeight: '100vh',
            background: 'linear-gradient(135deg, #0a0e27 0%, #1a1d3a 50%, #2d1b69 100%)',
          }}
        >
          <Box sx={{ textAlign: 'center', color: 'white' }}>
            <h1>🏰 Fortress Security Platform</h1>
            <p>Connecting to backend services...</p>
          </Box>
        </Box>
      </ThemeProvider>
    );
  }

  if (!isAuthenticated) {
    return (
      <ThemeProvider theme={darkTheme}>
        <CssBaseline />
        <FunctionalLogin onLogin={handleLogin} />
      </ThemeProvider>
    );
  }

  return (
    <QueryClientProvider client={queryClient}>
      <ThemeProvider theme={darkTheme}>
        <CssBaseline />
        <SnackbarProvider maxSnack={3}>
          <Router>
            <Box sx={{ display: 'flex', minHeight: '100vh' }}>
              <Box sx={{ flexGrow: 1, display: 'flex', flexDirection: 'column' }}>
                <Box component="main" sx={{ flexGrow: 1, backgroundColor: '#0a0e27' }}>
                  <Routes>
                    <Route path="/" element={<Navigate to="/dashboard" replace />} />
                    <Route
                      path="/dashboard"
                      element={
                        <FunctionalDashboard
                          userRole={currentUser?.role || 'admin'}
                          permissions={currentUser?.permissions || {}}
                        />
                      }
                    />
                    <Route path="*" element={<Navigate to="/dashboard" replace />} />
                  </Routes>
                </Box>
              </Box>
            </Box>
          </Router>
        </SnackbarProvider>
      </ThemeProvider>
    </QueryClientProvider>
  );
}

export default App;
