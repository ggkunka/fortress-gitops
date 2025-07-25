import React, { useState } from 'react';
import { useNavigate, Navigate } from 'react-router-dom';
import {
  Box,
  Card,
  CardContent,
  TextField,
  Button,
  Typography,
  Alert,
  Container,
  Link,
  Divider,
  CircularProgress,
} from '@mui/material';
import { Security as SecurityIcon } from '@mui/icons-material';
import { useForm, Controller } from 'react-hook-form';

import { useAuth } from '../../contexts/AuthContext';

interface LoginFormData {
  username: string;
  password: string;
}

export const LoginPage: React.FC = () => {
  const navigate = useNavigate();
  const { login, isAuthenticated, isLoading, error, clearError } = useAuth();
  const [isSubmitting, setIsSubmitting] = useState(false);

  const {
    control,
    handleSubmit,
    formState: { errors },
  } = useForm<LoginFormData>({
    defaultValues: {
      username: '',
      password: '',
    },
  });

  // Redirect if already authenticated
  if (isAuthenticated) {
    return <Navigate to="/dashboard" replace />;
  }

  const onSubmit = async (data: LoginFormData) => {
    setIsSubmitting(true);
    clearError();

    try {
      await login(data.username, data.password);
      navigate('/dashboard');
    } catch (error) {
      // Error is handled by the AuthContext
    } finally {
      setIsSubmitting(false);
    }
  };

  if (isLoading) {
    return (
      <Box
        display="flex"
        justifyContent="center"
        alignItems="center"
        minHeight="100vh"
        bgcolor="background.default"
      >
        <CircularProgress />
      </Box>
    );
  }

  return (
    <Box
      sx={{
        minHeight: '100vh',
        bgcolor: 'primary.main',
        background: 'linear-gradient(135deg, #1976d2 0%, #1565c0 100%)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'center',
        py: 3,
      }}
    >
      <Container maxWidth="sm">
        <Card elevation={8} sx={{ borderRadius: 2 }}>
          <CardContent sx={{ p: 4 }}>
            {/* Header */}
            <Box textAlign="center" mb={4}>
              <SecurityIcon sx={{ fontSize: 48, color: 'primary.main', mb: 2 }} />
              <Typography variant="h4" component="h1" gutterBottom fontWeight="bold">
                MCP Security Platform
              </Typography>
              <Typography variant="body1" color="textSecondary">
                Sign in to access your security dashboard
              </Typography>
            </Box>

            {/* Error Alert */}
            {error && (
              <Alert severity="error" sx={{ mb: 3 }} onClose={clearError}>
                {error}
              </Alert>
            )}

            {/* Login Form */}
            <form onSubmit={handleSubmit(onSubmit)}>
              <Box mb={3}>
                <Controller
                  name="username"
                  control={control}
                  rules={{
                    required: 'Username is required',
                    minLength: {
                      value: 3,
                      message: 'Username must be at least 3 characters',
                    },
                  }}
                  render={({ field }) => (
                    <TextField
                      {...field}
                      fullWidth
                      label="Username"
                      variant="outlined"
                      error={!!errors.username}
                      helperText={errors.username?.message}
                      disabled={isSubmitting}
                      autoComplete="username"
                      autoFocus
                    />
                  )}
                />
              </Box>

              <Box mb={3}>
                <Controller
                  name="password"
                  control={control}
                  rules={{
                    required: 'Password is required',
                    minLength: {
                      value: 6,
                      message: 'Password must be at least 6 characters',
                    },
                  }}
                  render={({ field }) => (
                    <TextField
                      {...field}
                      fullWidth
                      label="Password"
                      type="password"
                      variant="outlined"
                      error={!!errors.password}
                      helperText={errors.password?.message}
                      disabled={isSubmitting}
                      autoComplete="current-password"
                    />
                  )}
                />
              </Box>

              <Button
                type="submit"
                fullWidth
                variant="contained"
                size="large"
                disabled={isSubmitting}
                sx={{ py: 1.5, mb: 2 }}
              >
                {isSubmitting ? (
                  <>
                    <CircularProgress size={20} sx={{ mr: 1 }} />
                    Signing in...
                  </>
                ) : (
                  'Sign In'
                )}
              </Button>
            </form>

            <Divider sx={{ my: 3 }} />

            {/* Footer Links */}
            <Box textAlign="center">
              <Link
                href="#"
                variant="body2"
                color="primary"
                sx={{ textDecoration: 'none', mr: 2 }}
              >
                Forgot password?
              </Link>
              <Link
                href="#"
                variant="body2"
                color="primary"
                sx={{ textDecoration: 'none' }}
              >
                Need help?
              </Link>
            </Box>

            {/* Demo Credentials */}
            <Box mt={3} p={2} bgcolor="grey.50" borderRadius={1}>
              <Typography variant="caption" color="textSecondary" display="block" gutterBottom>
                Demo Credentials:
              </Typography>
              <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
                Username: admin
                <br />
                Password: admin123
              </Typography>
            </Box>
          </CardContent>
        </Card>

        {/* Footer */}
        <Box textAlign="center" mt={3}>
          <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.8)' }}>
            © 2024 MCP Security Platform. All rights reserved.
          </Typography>
        </Box>
      </Container>
    </Box>
  );
};