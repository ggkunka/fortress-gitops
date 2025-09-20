import React, { useState } from 'react';
import {
  Box,
  Card,
  CardContent,
  TextField,
  Button,
  Typography,
  Alert,
  CircularProgress,
  InputAdornment,
  IconButton,
  Divider,
  Chip,
} from '@mui/material';
import {
  Visibility,
  VisibilityOff,
  Security,
  Person,
  Lock,
  Login as LoginIcon,
} from '@mui/icons-material';
import { useForm } from 'react-hook-form';
import apiService from '../services/api';

interface LoginProps {
  onLogin: (credentials: {
    username: string;
    password: string;
  }) => Promise<{ success: boolean; error?: string }>;
}

interface LoginFormData {
  username: string;
  password: string;
}

const FunctionalLogin: React.FC<LoginProps> = ({ onLogin }) => {
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string>('');
  const [connectionStatus, setConnectionStatus] = useState<'checking' | 'connected' | 'error'>(
    'checking'
  );

  const {
    register,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormData>();

  // Check backend connectivity on component mount
  React.useEffect(() => {
    const checkConnection = async () => {
      try {
        await apiService.healthCheck();
        setConnectionStatus('connected');
      } catch (error) {
        setConnectionStatus('error');
      }
    };
    checkConnection();
  }, []);

  const onSubmit = async (data: LoginFormData) => {
    setIsLoading(true);
    setError('');

    try {
      const result = await onLogin(data);
      if (!result.success) {
        setError(result.error || 'Login failed');
      }
    } catch (err: any) {
      setError(err.message || 'An unexpected error occurred');
    } finally {
      setIsLoading(false);
    }
  };

  const handleDemoLogin = async (role: 'admin' | 'user' | 'analyst') => {
    const demoCredentials = {
      admin: { username: 'admin', password: 'admin123' },
      user: { username: 'user', password: 'user123' },
      analyst: { username: 'analyst', password: 'analyst123' },
    };

    await onSubmit(demoCredentials[role]);
  };

  return (
    <Box
      sx={{
        minHeight: '100vh',
        background: 'linear-gradient(135deg, #0a0e27 0%, #1a1d3a 50%, #2d1b69 100%)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        p: 2,
      }}
    >
      <Card
        sx={{
          maxWidth: 450,
          width: '100%',
          backdropFilter: 'blur(20px)',
          background: 'rgba(255, 255, 255, 0.05)',
          border: '1px solid rgba(255, 255, 255, 0.1)',
        }}
      >
        <CardContent sx={{ p: 4 }}>
          {/* Header */}
          <Box textAlign="center" mb={4}>
            <Security sx={{ fontSize: 60, color: '#00d4ff', mb: 2 }} />
            <Typography
              variant="h4"
              sx={{
                fontWeight: 'bold',
                background: 'linear-gradient(135deg, #00d4ff, #7c3aed)',
                backgroundClip: 'text',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
                mb: 1,
              }}
            >
              🏰 Fortress Security
            </Typography>
            <Typography variant="subtitle1" color="rgba(255, 255, 255, 0.7)">
              Enterprise Cloud Native Application Protection Platform
            </Typography>
          </Box>

          {/* Connection Status */}
          <Box mb={3}>
            <Chip
              label={
                connectionStatus === 'checking'
                  ? 'Checking connection...'
                  : connectionStatus === 'connected'
                    ? 'Connected to backend services'
                    : 'Backend connection error'
              }
              color={
                connectionStatus === 'checking'
                  ? 'default'
                  : connectionStatus === 'connected'
                    ? 'success'
                    : 'error'
              }
              icon={
                connectionStatus === 'checking' ? (
                  <CircularProgress size={16} />
                ) : connectionStatus === 'connected' ? (
                  <Security />
                ) : (
                  <Security />
                )
              }
              sx={{ width: '100%' }}
            />
          </Box>

          {/* Error Alert */}
          {error && (
            <Alert severity="error" sx={{ mb: 3 }}>
              {error}
            </Alert>
          )}

          {/* Login Form */}
          <Box component="form" onSubmit={handleSubmit(onSubmit)}>
            <TextField
              fullWidth
              label="Username"
              variant="outlined"
              margin="normal"
              {...register('username', { required: 'Username is required' })}
              error={!!errors.username}
              helperText={errors.username?.message}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Person sx={{ color: 'rgba(255, 255, 255, 0.5)' }} />
                  </InputAdornment>
                ),
                sx: {
                  color: 'white',
                  '& .MuiOutlinedInput-notchedOutline': {
                    borderColor: 'rgba(255, 255, 255, 0.3)',
                  },
                  '&:hover .MuiOutlinedInput-notchedOutline': {
                    borderColor: 'rgba(255, 255, 255, 0.5)',
                  },
                  '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
                    borderColor: '#00d4ff',
                  },
                },
              }}
              InputLabelProps={{
                sx: { color: 'rgba(255, 255, 255, 0.7)' },
              }}
            />

            <TextField
              fullWidth
              label="Password"
              type={showPassword ? 'text' : 'password'}
              variant="outlined"
              margin="normal"
              {...register('password', { required: 'Password is required' })}
              error={!!errors.password}
              helperText={errors.password?.message}
              InputProps={{
                startAdornment: (
                  <InputAdornment position="start">
                    <Lock sx={{ color: 'rgba(255, 255, 255, 0.5)' }} />
                  </InputAdornment>
                ),
                endAdornment: (
                  <InputAdornment position="end">
                    <IconButton
                      onClick={() => setShowPassword(!showPassword)}
                      edge="end"
                      sx={{ color: 'rgba(255, 255, 255, 0.5)' }}
                    >
                      {showPassword ? <VisibilityOff /> : <Visibility />}
                    </IconButton>
                  </InputAdornment>
                ),
                sx: {
                  color: 'white',
                  '& .MuiOutlinedInput-notchedOutline': {
                    borderColor: 'rgba(255, 255, 255, 0.3)',
                  },
                  '&:hover .MuiOutlinedInput-notchedOutline': {
                    borderColor: 'rgba(255, 255, 255, 0.5)',
                  },
                  '&.Mui-focused .MuiOutlinedInput-notchedOutline': {
                    borderColor: '#00d4ff',
                  },
                },
              }}
              InputLabelProps={{
                sx: { color: 'rgba(255, 255, 255, 0.7)' },
              }}
            />

            <Button
              type="submit"
              fullWidth
              variant="contained"
              size="large"
              disabled={isLoading || connectionStatus === 'error'}
              startIcon={isLoading ? <CircularProgress size={20} /> : <LoginIcon />}
              sx={{
                mt: 3,
                mb: 2,
                background: 'linear-gradient(135deg, #00d4ff, #7c3aed)',
                '&:hover': {
                  background: 'linear-gradient(135deg, #0099cc, #6b2db8)',
                },
                '&:disabled': {
                  background: 'rgba(255, 255, 255, 0.1)',
                },
              }}
            >
              {isLoading ? 'Signing In...' : 'Sign In'}
            </Button>
          </Box>

          <Divider sx={{ my: 3, borderColor: 'rgba(255, 255, 255, 0.1)' }}>
            <Typography variant="body2" color="rgba(255, 255, 255, 0.5)">
              Demo Accounts
            </Typography>
          </Divider>

          {/* Demo Login Buttons */}
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
            <Button
              variant="outlined"
              size="small"
              onClick={() => handleDemoLogin('admin')}
              disabled={isLoading || connectionStatus === 'error'}
              sx={{
                borderColor: 'rgba(239, 68, 68, 0.5)',
                color: '#ef4444',
                '&:hover': {
                  borderColor: '#ef4444',
                  backgroundColor: 'rgba(239, 68, 68, 0.1)',
                },
              }}
            >
              Admin Demo (admin/admin123)
            </Button>
            <Button
              variant="outlined"
              size="small"
              onClick={() => handleDemoLogin('analyst')}
              disabled={isLoading || connectionStatus === 'error'}
              sx={{
                borderColor: 'rgba(245, 158, 11, 0.5)',
                color: '#f59e0b',
                '&:hover': {
                  borderColor: '#f59e0b',
                  backgroundColor: 'rgba(245, 158, 11, 0.1)',
                },
              }}
            >
              Security Analyst Demo (analyst/analyst123)
            </Button>
            <Button
              variant="outlined"
              size="small"
              onClick={() => handleDemoLogin('user')}
              disabled={isLoading || connectionStatus === 'error'}
              sx={{
                borderColor: 'rgba(16, 185, 129, 0.5)',
                color: '#10b981',
                '&:hover': {
                  borderColor: '#10b981',
                  backgroundColor: 'rgba(16, 185, 129, 0.1)',
                },
              }}
            >
              User Demo (user/user123)
            </Button>
          </Box>

          {/* Footer */}
          <Box textAlign="center" mt={4}>
            <Typography variant="caption" color="rgba(255, 255, 255, 0.5)">
              Connected to live backend services
              <br />
              GraphQL • WebSocket • SIEM • ML Engine • Zero Trust
            </Typography>
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
};

export default FunctionalLogin;
