import React, { useState } from 'react';
import {
  Card,
  CardContent,
  Typography,
  Grid,
  Box,
  Chip,
  LinearProgress,
  IconButton,
  Tooltip,
  Avatar,
  useTheme,
  alpha,
} from '@mui/material';
import {
  Cloud as CloudIcon,
  Storage as StorageIcon,
  AccountTree as ClusterIcon,
  Memory as WorkloadIcon,
  CloudQueue as ContainerIcon,
  Api as ApiIcon,
  Visibility as VisibilityIcon,
  Security as SecurityIcon,
  Warning as WarningIcon,
  CheckCircle as CheckIcon,
} from '@mui/icons-material';
import { motion } from 'framer-motion';

const CloudAssetsOverview: React.FC = () => {
  const theme = useTheme();
  
  const assetsData = {
    total: 2847,
    protected: 2744,
    unprotected: 103,
    clusters: 24,
    workloads: 1456,
    containers: 8934,
    apis: 234,
    cloudProviders: [
      { name: 'AWS', assets: 1245, color: '#ff9900', protected: 95 },
      { name: 'Azure', assets: 892, color: '#0078d4', protected: 97 },
      { name: 'GCP', assets: 710, color: '#4285f4', protected: 94 }
    ],
    riskDistribution: {
      critical: 3,
      high: 12,
      medium: 45,
      low: 43
    }
  };

  const protectionPercentage = Math.round((assetsData.protected / assetsData.total) * 100);

  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.5, delay: 0.1 }}
    >
      <Card sx={{ 
        background: 'linear-gradient(135deg, #1e293b, #334155)', 
        border: '1px solid rgba(255,255,255,0.1)',
        height: '100%'
      }}>
        <CardContent>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 3 }}>
            <Typography variant="h6" sx={{ display: 'flex', alignItems: 'center' }}>
              <CloudIcon sx={{ mr: 1, color: '#3b82f6' }} />
              Cloud Assets Overview
            </Typography>
            <Chip 
              label={`${protectionPercentage}% Protected`}
              size="small"
              sx={{ 
                backgroundColor: alpha('#10b981', 0.2),
                color: '#10b981'
              }}
            />
          </Box>

          {/* Asset Statistics */}
          <Grid container spacing={3} sx={{ mb: 3 }}>
            <Grid item xs={6} sm={3}>
              <Box sx={{ textAlign: 'center' }}>
                <Avatar sx={{ 
                  width: 48, 
                  height: 48, 
                  mx: 'auto', 
                  mb: 1, 
                  backgroundColor: '#3b82f6' 
                }}>
                  <StorageIcon />
                </Avatar>
                <Typography variant="h5" sx={{ fontWeight: 700, color: '#3b82f6' }}>
                  {assetsData.total.toLocaleString()}
                </Typography>
                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                  Total Assets
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Box sx={{ textAlign: 'center' }}>
                <Avatar sx={{ 
                  width: 48, 
                  height: 48, 
                  mx: 'auto', 
                  mb: 1, 
                  backgroundColor: '#8b5cf6' 
                }}>
                  <ClusterIcon />
                </Avatar>
                <Typography variant="h5" sx={{ fontWeight: 700, color: '#8b5cf6' }}>
                  {assetsData.clusters}
                </Typography>
                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                  K8s Clusters
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Box sx={{ textAlign: 'center' }}>
                <Avatar sx={{ 
                  width: 48, 
                  height: 48, 
                  mx: 'auto', 
                  mb: 1, 
                  backgroundColor: '#10b981' 
                }}>
                  <WorkloadIcon />
                </Avatar>
                <Typography variant="h5" sx={{ fontWeight: 700, color: '#10b981' }}>
                  {assetsData.workloads.toLocaleString()}
                </Typography>
                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                  Workloads
                </Typography>
              </Box>
            </Grid>
            <Grid item xs={6} sm={3}>
              <Box sx={{ textAlign: 'center' }}>
                <Avatar sx={{ 
                  width: 48, 
                  height: 48, 
                  mx: 'auto', 
                  mb: 1, 
                  backgroundColor: '#f59e0b' 
                }}>
                  <ContainerIcon />
                </Avatar>
                <Typography variant="h5" sx={{ fontWeight: 700, color: '#f59e0b' }}>
                  {assetsData.containers.toLocaleString()}
                </Typography>
                <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                  Containers
                </Typography>
              </Box>
            </Grid>
          </Grid>

          {/* Protection Coverage */}
          <Box sx={{ mb: 3 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
              <Typography variant="body2" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                Protection Coverage
              </Typography>
              <Typography variant="body2" sx={{ color: '#10b981', fontWeight: 600 }}>
                {assetsData.protected.toLocaleString()} / {assetsData.total.toLocaleString()}
              </Typography>
            </Box>
            <LinearProgress 
              variant="determinate" 
              value={protectionPercentage}
              sx={{ 
                height: 8, 
                borderRadius: 4,
                backgroundColor: 'rgba(255,255,255,0.1)',
                '& .MuiLinearProgress-bar': {
                  backgroundColor: '#10b981',
                  borderRadius: 4
                }
              }}
            />
          </Box>

          {/* Cloud Providers */}
          <Box sx={{ mb: 3 }}>
            <Typography variant="subtitle2" sx={{ mb: 2, color: 'rgba(255,255,255,0.8)' }}>
              Cloud Providers
            </Typography>
            <Grid container spacing={2}>
              {assetsData.cloudProviders.map((provider) => (
                <Grid item xs={12} sm={4} key={provider.name}>
                  <Box sx={{ 
                    p: 2, 
                    backgroundColor: 'rgba(0,0,0,0.2)', 
                    borderRadius: 2,
                    border: `1px solid ${alpha(provider.color, 0.3)}`
                  }}>
                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 1 }}>
                      <Typography variant="subtitle2" sx={{ fontWeight: 600, color: provider.color }}>
                        {provider.name}
                      </Typography>
                      <Chip 
                        label={`${provider.protected}%`}
                        size="small"
                        sx={{ 
                          backgroundColor: alpha('#10b981', 0.2),
                          color: '#10b981',
                          fontSize: '0.7rem'
                        }}
                      />
                    </Box>
                    <Typography variant="h6" sx={{ fontWeight: 700, color: 'white' }}>
                      {provider.assets.toLocaleString()}
                    </Typography>
                    <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.6)' }}>
                      Assets
                    </Typography>
                  </Box>
                </Grid>
              ))}
            </Grid>
          </Box>

          {/* Risk Distribution */}
          <Box>
            <Typography variant="subtitle2" sx={{ mb: 2, color: 'rgba(255,255,255,0.8)' }}>
              Risk Distribution
            </Typography>
            <Grid container spacing={2}>
              <Grid item xs={3}>
                <Box sx={{ textAlign: 'center' }}>
                  <Typography variant="h6" sx={{ color: '#ef4444', fontWeight: 700 }}>
                    {assetsData.riskDistribution.critical}
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                    Critical
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={3}>
                <Box sx={{ textAlign: 'center' }}>
                  <Typography variant="h6" sx={{ color: '#f97316', fontWeight: 700 }}>
                    {assetsData.riskDistribution.high}
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                    High
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={3}>
                <Box sx={{ textAlign: 'center' }}>
                  <Typography variant="h6" sx={{ color: '#eab308', fontWeight: 700 }}>
                    {assetsData.riskDistribution.medium}
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                    Medium
                  </Typography>
                </Box>
              </Grid>
              <Grid item xs={3}>
                <Box sx={{ textAlign: 'center' }}>
                  <Typography variant="h6" sx={{ color: '#06b6d4', fontWeight: 700 }}>
                    {assetsData.riskDistribution.low}
                  </Typography>
                  <Typography variant="caption" sx={{ color: 'rgba(255,255,255,0.7)' }}>
                    Low
                  </Typography>
                </Box>
              </Grid>
            </Grid>
          </Box>
        </CardContent>
      </Card>
    </motion.div>
  );
};

export default CloudAssetsOverview;
